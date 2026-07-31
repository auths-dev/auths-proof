use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use auths_lifecycle::StoreError;
use auths_radicle::{
    OpenPatchActionV1,
    lifecycle::{
        RadicleLifecycleRegistry, RadicleLifecycleStore, RadicleRecoveryRecordV1,
        reservation_scope_digests,
    },
};

const MAX_RECORDS: usize = 2_048;

struct DemoRadicleLifecycleStore {
    inner: auths_stores::PersistentLifecycleStore,
}

impl auths_lifecycle::LifecycleStore for DemoRadicleLifecycleStore {
    fn transact(
        &self,
        transaction: &auths_lifecycle::StoreTransactionV1,
    ) -> Result<auths_lifecycle::StoredTransitionV1, StoreError> {
        self.inner.transact(transaction)
    }
}

impl RadicleLifecycleStore for DemoRadicleLifecycleStore {
    fn load_radicle_lifecycle(
        &self,
        workflow: &auths_lifecycle::WorkflowId,
    ) -> Result<Option<auths_lifecycle::LifecycleRecordV1>, StoreError> {
        self.inner.load(workflow)
    }
}

pub(crate) struct DemoRadicleLifecycleRegistry {
    directory: PathBuf,
    stores: Mutex<HashMap<String, Arc<DemoRadicleLifecycleStore>>>,
    domain_lock: Mutex<()>,
}

impl DemoRadicleLifecycleRegistry {
    pub(crate) fn open(directory: PathBuf, obsolete_state: &Path) -> Result<Self, StoreError> {
        if obsolete_state.exists() {
            return Err(StoreError::Corrupt);
        }
        fs::create_dir_all(directory.join("recovery")).map_err(|_| StoreError::Unavailable)?;
        fs::create_dir_all(directory.join("publications")).map_err(|_| StoreError::Unavailable)?;
        Ok(Self {
            directory,
            stores: Mutex::new(HashMap::new()),
            domain_lock: Mutex::new(()),
        })
    }

    fn workflow_key(workflow_id: &auths_radicle::WorkflowId) -> String {
        auths_radicle::canonical::sha256(workflow_id.as_str().as_bytes())
            .as_str()
            .into()
    }

    fn recovery_path(&self, workflow_id: &auths_radicle::WorkflowId) -> PathBuf {
        self.directory
            .join("recovery")
            .join(format!("{}.json", Self::workflow_key(workflow_id)))
    }

    fn publication_path(&self, workflow_id: &auths_radicle::WorkflowId) -> PathBuf {
        self.directory
            .join("publications")
            .join(format!("{}.json", Self::workflow_key(workflow_id)))
    }
}

impl RadicleLifecycleRegistry for DemoRadicleLifecycleRegistry {
    fn for_action(
        &self,
        action: &OpenPatchActionV1,
    ) -> Result<Arc<dyn RadicleLifecycleStore>, StoreError> {
        let scopes = reservation_scope_digests(action).map_err(|_| StoreError::Corrupt)?;
        let scope_key = hex::encode(scopes[0].as_bytes());
        let mut stores = self.stores.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(store) = stores.get(&scope_key) {
            let concrete = Arc::clone(store);
            let store: Arc<dyn RadicleLifecycleStore> = concrete;
            return Ok(store);
        }
        let rules = scopes
            .into_iter()
            .map(
                |scope_digest| auths_stores::LifecycleCapacityRuleV1::Exclusive {
                    scope_digest,
                    window_digest: None,
                    retain_after_commit: true,
                },
            )
            .collect();
        let store = Arc::new(DemoRadicleLifecycleStore {
            inner: auths_stores::PersistentLifecycleStore::open(
                self.directory.join(format!("{scope_key}.lifecycle")),
                rules,
                MAX_RECORDS,
            )
            .map_err(|_| StoreError::Corrupt)?,
        });
        stores.insert(scope_key, Arc::clone(&store));
        Ok(store)
    }

    fn persist_recovery(&self, record: &RadicleRecoveryRecordV1) -> Result<(), StoreError> {
        record.validate().map_err(|_| StoreError::Corrupt)?;
        let _guard = self
            .domain_lock
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        persist_exact(&self.recovery_path(&record.workflow_id), record)
    }

    fn load_recovery(
        &self,
        workflow_id: &auths_radicle::WorkflowId,
    ) -> Result<Option<RadicleRecoveryRecordV1>, StoreError> {
        let _guard = self
            .domain_lock
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        let Some(record): Option<RadicleRecoveryRecordV1> =
            load_exact(&self.recovery_path(workflow_id))?
        else {
            return Ok(None);
        };
        record.validate().map_err(|_| StoreError::Corrupt)?;
        Ok(Some(record))
    }

    fn persist_publication(
        &self,
        workflow_id: &auths_radicle::WorkflowId,
        publication: &auths_radicle::executor::LocalPublication,
    ) -> Result<(), StoreError> {
        let _guard = self
            .domain_lock
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        persist_exact(&self.publication_path(workflow_id), publication)
    }

    fn load_publication(
        &self,
        workflow_id: &auths_radicle::WorkflowId,
    ) -> Result<Option<auths_radicle::executor::LocalPublication>, StoreError> {
        let _guard = self
            .domain_lock
            .lock()
            .map_err(|_| StoreError::Unavailable)?;
        load_exact(&self.publication_path(workflow_id))
    }
}

fn persist_exact<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), StoreError> {
    let bytes = serde_json::to_vec(value).map_err(|_| StoreError::Corrupt)?;
    if path.exists() {
        let existing = fs::read(path).map_err(|_| StoreError::Unavailable)?;
        return if existing == bytes {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        };
    }
    let temporary = path.with_extension("json.tmp");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| StoreError::Unavailable)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| StoreError::Unavailable)?;
    fs::rename(&temporary, path).map_err(|_| StoreError::Unavailable)?;
    let parent = path.parent().ok_or(StoreError::Unavailable)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| StoreError::Unavailable)
}

fn load_exact<T>(path: &Path) -> Result<Option<T>, StoreError>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path).map_err(|_| StoreError::Unavailable)?;
    let value: T = serde_json::from_slice(&bytes).map_err(|_| StoreError::Corrupt)?;
    if serde_json::to_vec(&value).map_err(|_| StoreError::Corrupt)? != bytes {
        return Err(StoreError::Corrupt);
    }
    Ok(Some(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn obsolete_prelaunch_workflow_state_is_rejected_not_migrated() {
        let directory = tempfile::tempdir().unwrap();
        let lifecycle = directory.path().join("lifecycle");
        let obsolete = directory.path().join("workflow-store.json");
        fs::write(&obsolete, b"{\"legacy\":true}").unwrap();

        assert!(matches!(
            DemoRadicleLifecycleRegistry::open(lifecycle.clone(), &obsolete),
            Err(StoreError::Corrupt)
        ));
        assert!(!lifecycle.exists());
        assert_eq!(fs::read(obsolete).unwrap(), b"{\"legacy\":true}");
    }
}
