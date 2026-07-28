//! Durable, at-most-once Radicle workflow claims and stage transitions.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::Write as _,
    path::{Path, PathBuf},
    sync::Mutex,
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{
    canonical::{canonical_json, sha256},
    types::{CobId, DigestHex, GitOid, WorkflowId},
};

/// Monotonic workflow stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowStage {
    /// Execution was durably claimed.
    Claimed,
    /// A patch/revision was stored locally by Radicle.
    Stored,
    /// The executor announced the stored revision.
    Announced,
    /// An independent observer found the revision.
    Replicated,
}

/// Durable public workflow state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowRecord {
    workflow_id: WorkflowId,
    action_digest: DigestHex,
    lease_digest: DigestHex,
    stage: WorkflowStage,
    patch_id: Option<CobId>,
    revision_id: Option<GitOid>,
    updated_at: u64,
}

impl WorkflowRecord {
    /// Returns the workflow.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the claimed action digest.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Returns the current monotonic stage.
    #[must_use]
    pub const fn stage(&self) -> WorkflowStage {
        self.stage
    }

    /// Returns the patch identifier once stored.
    #[must_use]
    pub const fn patch_id(&self) -> Option<&CobId> {
        self.patch_id.as_ref()
    }

    /// Returns the initial revision identifier once stored.
    #[must_use]
    pub const fn revision_id(&self) -> Option<&GitOid> {
        self.revision_id.as_ref()
    }
}

/// Opaque proof that an execution was claimed durably.
#[derive(Debug)]
pub struct ExecutionLease {
    workflow_id: WorkflowId,
    action_digest: DigestHex,
    lease_digest: DigestHex,
}

impl ExecutionLease {
    /// Returns the workflow identifier.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.workflow_id
    }

    /// Returns the exact claimed action.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Returns the stable lease commitment.
    #[must_use]
    pub const fn lease_digest(&self) -> &DigestHex {
        &self.lease_digest
    }
}

/// Result of attempting the at-most-once claim.
#[derive(Debug)]
pub enum ClaimResult {
    /// The caller owns the only execution lease.
    Claimed(ExecutionLease),
    /// This workflow was already claimed for this exact action.
    Replay(WorkflowRecord),
    /// The workflow identifier is already bound to different action bytes.
    Conflict(WorkflowRecord),
    /// Durable state was unavailable.
    Unavailable,
}

/// Minimal persistence contract used by the workflow service.
pub trait WorkflowStore: Send + Sync {
    /// Claims an exact action at most once.
    fn claim(&self, workflow_id: &WorkflowId, action_digest: &DigestHex, now: u64) -> ClaimResult;

    /// Records a successful local Radicle write.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for unavailable state or a conflicting lease.
    fn record_stored(
        &self,
        lease: &ExecutionLease,
        patch_id: &CobId,
        revision_id: &GitOid,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError>;

    /// Advances a stored workflow after announce or independent observation.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for an invalid transition or unavailable state.
    fn advance(
        &self,
        lease: &ExecutionLease,
        stage: WorkflowStage,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError>;

    /// Reads public workflow state.
    ///
    /// # Errors
    ///
    /// Returns a closed failure when durable state is unavailable.
    fn get(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowRecord>, WorkflowStoreError>;
}

/// Process-safe in-memory store used by deterministic tests.
#[derive(Default)]
pub struct InMemoryWorkflowStore {
    records: Mutex<BTreeMap<WorkflowId, WorkflowRecord>>,
}

impl WorkflowStore for InMemoryWorkflowStore {
    fn claim(&self, workflow_id: &WorkflowId, action_digest: &DigestHex, now: u64) -> ClaimResult {
        let Ok(mut records) = self.records.lock() else {
            return ClaimResult::Unavailable;
        };
        claim_in(&mut records, workflow_id, action_digest, now)
    }

    fn record_stored(
        &self,
        lease: &ExecutionLease,
        patch_id: &CobId,
        revision_id: &GitOid,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        record_stored_in(&mut records, lease, patch_id, revision_id, now)
    }

    fn advance(
        &self,
        lease: &ExecutionLease,
        stage: WorkflowStage,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        advance_in(&mut records, lease, stage, now)
    }

    fn get(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowRecord>, WorkflowStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| WorkflowStoreError::Unavailable)
    }
}

/// Crash-persistent single-writer workflow store.
///
/// Every state mutation is serialized canonically, synced to disk, and
/// atomically renamed before it becomes visible in memory. A deployment must
/// run one writer process per state file.
pub struct PersistentWorkflowStore {
    path: PathBuf,
    records: Mutex<BTreeMap<WorkflowId, WorkflowRecord>>,
}

impl PersistentWorkflowStore {
    /// Opens or creates one bounded workflow state file.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, or excessively large persisted state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, WorkflowStoreError> {
        let path = path.into();
        let records = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| WorkflowStoreError::Unavailable)?;
            if bytes.len() > 16 * 1024 * 1024 {
                return Err(WorkflowStoreError::Corrupt);
            }
            let records: BTreeMap<WorkflowId, WorkflowRecord> =
                serde_json::from_slice(&bytes).map_err(|_| WorkflowStoreError::Corrupt)?;
            if canonical_json(&records).map_err(|_| WorkflowStoreError::Corrupt)? != bytes {
                return Err(WorkflowStoreError::Corrupt);
            }
            records
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            path,
            records: Mutex::new(records),
        })
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(
            &mut BTreeMap<WorkflowId, WorkflowRecord>,
        ) -> Result<T, WorkflowStoreError>,
    ) -> Result<T, WorkflowStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| WorkflowStoreError::Unavailable)?;
        let mut next = records.clone();
        let result = operation(&mut next)?;
        persist(&self.path, &next)?;
        *records = next;
        Ok(result)
    }
}

impl WorkflowStore for PersistentWorkflowStore {
    fn claim(&self, workflow_id: &WorkflowId, action_digest: &DigestHex, now: u64) -> ClaimResult {
        let result = self.mutate(|records| {
            Ok(match claim_in(records, workflow_id, action_digest, now) {
                ClaimResult::Unavailable => return Err(WorkflowStoreError::Unavailable),
                result => result,
            })
        });
        result.unwrap_or(ClaimResult::Unavailable)
    }

    fn record_stored(
        &self,
        lease: &ExecutionLease,
        patch_id: &CobId,
        revision_id: &GitOid,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError> {
        self.mutate(|records| record_stored_in(records, lease, patch_id, revision_id, now))
    }

    fn advance(
        &self,
        lease: &ExecutionLease,
        stage: WorkflowStage,
        now: u64,
    ) -> Result<WorkflowRecord, WorkflowStoreError> {
        self.mutate(|records| advance_in(records, lease, stage, now))
    }

    fn get(&self, workflow_id: &WorkflowId) -> Result<Option<WorkflowRecord>, WorkflowStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| WorkflowStoreError::Unavailable)
    }
}

fn claim_in(
    records: &mut BTreeMap<WorkflowId, WorkflowRecord>,
    workflow_id: &WorkflowId,
    action_digest: &DigestHex,
    now: u64,
) -> ClaimResult {
    if let Some(existing) = records.get(workflow_id) {
        return if existing.action_digest == *action_digest {
            ClaimResult::Replay(existing.clone())
        } else {
            ClaimResult::Conflict(existing.clone())
        };
    }
    let lease_digest =
        sha256(format!("auths-radicle-lease-v1\0{workflow_id}\0{action_digest}").as_bytes());
    let record = WorkflowRecord {
        workflow_id: workflow_id.clone(),
        action_digest: action_digest.clone(),
        lease_digest: lease_digest.clone(),
        stage: WorkflowStage::Claimed,
        patch_id: None,
        revision_id: None,
        updated_at: now,
    };
    records.insert(workflow_id.clone(), record);
    ClaimResult::Claimed(ExecutionLease {
        workflow_id: workflow_id.clone(),
        action_digest: action_digest.clone(),
        lease_digest,
    })
}

fn record_stored_in(
    records: &mut BTreeMap<WorkflowId, WorkflowRecord>,
    lease: &ExecutionLease,
    patch_id: &CobId,
    revision_id: &GitOid,
    now: u64,
) -> Result<WorkflowRecord, WorkflowStoreError> {
    let record = matching_record_mut(records, lease)?;
    if record.stage > WorkflowStage::Stored {
        if record.patch_id.as_ref() == Some(patch_id)
            && record.revision_id.as_ref() == Some(revision_id)
        {
            return Ok(record.clone());
        }
        return Err(WorkflowStoreError::Conflict);
    }
    if record.stage == WorkflowStage::Stored
        && (record.patch_id.as_ref() != Some(patch_id)
            || record.revision_id.as_ref() != Some(revision_id))
    {
        return Err(WorkflowStoreError::Conflict);
    }
    record.stage = WorkflowStage::Stored;
    record.patch_id = Some(patch_id.clone());
    record.revision_id = Some(revision_id.clone());
    record.updated_at = now;
    Ok(record.clone())
}

fn advance_in(
    records: &mut BTreeMap<WorkflowId, WorkflowRecord>,
    lease: &ExecutionLease,
    stage: WorkflowStage,
    now: u64,
) -> Result<WorkflowRecord, WorkflowStoreError> {
    let record = matching_record_mut(records, lease)?;
    if stage < WorkflowStage::Announced
        || stage < record.stage
        || record.patch_id.is_none()
        || record.revision_id.is_none()
        || (stage == WorkflowStage::Replicated && record.stage < WorkflowStage::Announced)
    {
        return Err(WorkflowStoreError::InvalidTransition);
    }
    record.stage = stage;
    record.updated_at = now;
    Ok(record.clone())
}

fn matching_record_mut<'a>(
    records: &'a mut BTreeMap<WorkflowId, WorkflowRecord>,
    lease: &ExecutionLease,
) -> Result<&'a mut WorkflowRecord, WorkflowStoreError> {
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(WorkflowStoreError::Missing)?;
    if record.action_digest != lease.action_digest || record.lease_digest != lease.lease_digest {
        return Err(WorkflowStoreError::Conflict);
    }
    Ok(record)
}

fn persist(
    path: &Path,
    records: &BTreeMap<WorkflowId, WorkflowRecord>,
) -> Result<(), WorkflowStoreError> {
    let parent = path.parent().ok_or(WorkflowStoreError::Unavailable)?;
    fs::create_dir_all(parent).map_err(|_| WorkflowStoreError::Unavailable)?;
    let bytes = canonical_json(records).map_err(|_| WorkflowStoreError::Corrupt)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| WorkflowStoreError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| WorkflowStoreError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| WorkflowStoreError::Unavailable)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| WorkflowStoreError::Unavailable)
}

/// Closed durable workflow-store failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WorkflowStoreError {
    /// State could not be read or committed.
    #[error("workflow state is unavailable")]
    Unavailable,
    /// Persisted state is malformed or non-canonical.
    #[error("workflow state is corrupt")]
    Corrupt,
    /// No record exists for an execution lease.
    #[error("workflow execution lease is missing")]
    Missing,
    /// The workflow is bound to different exact bytes.
    #[error("workflow execution lease conflicts with durable state")]
    Conflict,
    /// A stage transition would skip or reverse a mandatory boundary.
    #[error("invalid workflow stage transition")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::test_support::{digest, oid};

    #[test]
    fn concurrent_duplicate_claims_execute_exactly_once() {
        let store = Arc::new(InMemoryWorkflowStore::default());
        let barrier = Arc::new(Barrier::new(16));
        let workflow = WorkflowId::parse("workflow-race").unwrap();
        let action = digest('a');
        let handles = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let workflow = workflow.clone();
                let action = action.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.claim(&workflow, &action, 1)
                })
            })
            .collect::<Vec<_>>();
        let results = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimResult::Claimed(_)))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, ClaimResult::Replay(_)))
                .count(),
            15
        );
    }

    #[test]
    fn persistent_claim_survives_reopen_and_preserves_monotonic_stages() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("workflows.json");
        let workflow = WorkflowId::parse("workflow-persistent").unwrap();
        let action = digest('b');
        let store = PersistentWorkflowStore::open(&path).unwrap();
        let ClaimResult::Claimed(lease) = store.claim(&workflow, &action, 1) else {
            panic!("first execution must own the lease");
        };
        store
            .record_stored(&lease, &CobId::parse("c".repeat(40)).unwrap(), &oid('c'), 2)
            .unwrap();
        store.advance(&lease, WorkflowStage::Announced, 3).unwrap();
        drop(store);

        let reopened = PersistentWorkflowStore::open(&path).unwrap();
        let ClaimResult::Replay(record) = reopened.claim(&workflow, &action, 4) else {
            panic!("reopened store must reject replay");
        };
        assert_eq!(record.stage(), WorkflowStage::Announced);
        assert_eq!(record.patch_id().unwrap().as_str(), "c".repeat(40));
    }
}
