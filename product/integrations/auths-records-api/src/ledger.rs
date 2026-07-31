//! Durable, atomic records, replay, capacity, and receipt state.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{
    CustomerRecordV1, EffectReceipt, ReadField, ReceiptBundle, RecordIdentifier, RecordsError,
    SealedCreateRecordCommand, SealedReadRecordCommand,
    canonical::{canonical_digest, canonical_json, sha256},
};

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const LEDGER_STATE_SCHEMA: &str = "auths.records-ledger-state/2";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRecord {
    pub namespace_id: RecordIdentifier,
    pub record_id: RecordIdentifier,
    pub customer: CustomerRecordV1,
    pub created_at: u64,
    pub updated_at: u64,
    pub version: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordProjection {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customer: Option<CustomerRecordV1>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub create_units: u32,
    pub read_units: u32,
    pub created_bytes: u64,
    pub disclosed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletedRecordsAction {
    pub effect: EffectReceipt,
    pub projection: Option<RecordProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LedgerState {
    schema: String,
    records: BTreeMap<String, StoredRecord>,
    usage_by_policy: BTreeMap<String, Usage>,
    completed_actions: BTreeMap<String, CompletedRecordsAction>,
    receipts: BTreeMap<String, ReceiptBundle>,
}

impl LedgerState {
    fn empty() -> Self {
        Self {
            schema: LEDGER_STATE_SCHEMA.into(),
            records: BTreeMap::new(),
            usage_by_policy: BTreeMap::new(),
            completed_actions: BTreeMap::new(),
            receipts: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateTransition {
    Executed(EffectReceipt),
    Replay(EffectReceipt),
    Denied(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadTransition {
    Disclosed {
        receipt: EffectReceipt,
        projection: RecordProjection,
    },
    Replay {
        receipt: EffectReceipt,
        projection: RecordProjection,
    },
    Denied(&'static str),
}

pub trait RecordsLedger: Send + Sync {
    fn create(&self, command: SealedCreateRecordCommand) -> Result<CreateTransition, RecordsError>;

    fn read(&self, command: SealedReadRecordCommand) -> Result<ReadTransition, RecordsError>;

    fn completed(
        &self,
        action_digest: &str,
    ) -> Result<Option<CompletedRecordsAction>, RecordsError>;
    fn append_receipt(&self, receipt: ReceiptBundle) -> Result<(), RecordsError>;
    fn receipt(&self, receipt_id: &str) -> Result<Option<ReceiptBundle>, RecordsError>;
    fn usage(&self, policy_digest: &str) -> Result<Usage, RecordsError>;
    fn state_commitment(&self) -> Result<String, RecordsError>;
}

impl<T: RecordsLedger + ?Sized> RecordsLedger for Arc<T> {
    fn create(&self, command: SealedCreateRecordCommand) -> Result<CreateTransition, RecordsError> {
        (**self).create(command)
    }

    fn read(&self, command: SealedReadRecordCommand) -> Result<ReadTransition, RecordsError> {
        (**self).read(command)
    }

    fn completed(
        &self,
        action_digest: &str,
    ) -> Result<Option<CompletedRecordsAction>, RecordsError> {
        (**self).completed(action_digest)
    }

    fn append_receipt(&self, receipt: ReceiptBundle) -> Result<(), RecordsError> {
        (**self).append_receipt(receipt)
    }

    fn receipt(&self, receipt_id: &str) -> Result<Option<ReceiptBundle>, RecordsError> {
        (**self).receipt(receipt_id)
    }

    fn usage(&self, policy_digest: &str) -> Result<Usage, RecordsError> {
        (**self).usage(policy_digest)
    }

    fn state_commitment(&self) -> Result<String, RecordsError> {
        (**self).state_commitment()
    }
}

#[derive(Clone)]
pub struct MemoryRecordsLedger {
    state: Arc<Mutex<LedgerState>>,
}

impl Default for MemoryRecordsLedger {
    fn default() -> Self {
        Self {
            state: Arc::new(Mutex::new(LedgerState::empty())),
        }
    }
}

impl RecordsLedger for MemoryRecordsLedger {
    fn create(&self, command: SealedCreateRecordCommand) -> Result<CreateTransition, RecordsError> {
        if !command.lifecycle_authorization_matches() {
            return Err(RecordsError::MeaningMismatch);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?;
        create_in(&mut state, &command)
    }

    fn read(&self, command: SealedReadRecordCommand) -> Result<ReadTransition, RecordsError> {
        if !command.lifecycle_authorization_matches() {
            return Err(RecordsError::MeaningMismatch);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?;
        read_in(&mut state, &command)
    }

    fn completed(
        &self,
        action_digest: &str,
    ) -> Result<Option<CompletedRecordsAction>, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .completed_actions
            .get(action_digest)
            .cloned())
    }

    fn append_receipt(&self, receipt: ReceiptBundle) -> Result<(), RecordsError> {
        let id = receipt.decision.receipt_id.clone();
        self.state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .receipts
            .insert(id, receipt);
        Ok(())
    }

    fn receipt(&self, receipt_id: &str) -> Result<Option<ReceiptBundle>, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .receipts
            .get(receipt_id)
            .cloned())
    }

    fn usage(&self, policy_digest: &str) -> Result<Usage, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .usage_by_policy
            .get(policy_digest)
            .cloned()
            .unwrap_or_default())
    }

    fn state_commitment(&self) -> Result<String, RecordsError> {
        canonical_digest(
            &*self
                .state
                .lock()
                .map_err(|_| RecordsError::StateUnavailable)?,
        )
    }
}

pub struct PersistentRecordsLedger {
    path: PathBuf,
    state: Mutex<LedgerState>,
}

impl PersistentRecordsLedger {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RecordsError> {
        let path = path.into();
        let state = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| RecordsError::StateUnavailable)?;
            if bytes.len() > MAX_STATE_BYTES {
                return Err(RecordsError::LimitExceeded);
            }
            let state: LedgerState =
                serde_json::from_slice(&bytes).map_err(|_| RecordsError::StateUnavailable)?;
            if state.schema != LEDGER_STATE_SCHEMA || canonical_json(&state)? != bytes {
                return Err(RecordsError::NonCanonical);
            }
            state
        } else {
            LedgerState::empty()
        };
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn mutate<T>(
        &self,
        operation: impl FnOnce(&mut LedgerState) -> Result<T, RecordsError>,
    ) -> Result<T, RecordsError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?;
        let mut candidate = state.clone();
        let result = operation(&mut candidate)?;
        let bytes = canonical_json(&candidate)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(RecordsError::LimitExceeded);
        }
        let parent = self.path.parent().ok_or(RecordsError::StateUnavailable)?;
        fs::create_dir_all(parent).map_err(|_| RecordsError::StateUnavailable)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|_| RecordsError::StateUnavailable)?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| RecordsError::StateUnavailable)?;
        temporary
            .persist(&self.path)
            .map_err(|_| RecordsError::StateUnavailable)?;
        *state = candidate;
        Ok(result)
    }
}

impl RecordsLedger for PersistentRecordsLedger {
    fn create(&self, command: SealedCreateRecordCommand) -> Result<CreateTransition, RecordsError> {
        if !command.lifecycle_authorization_matches() {
            return Err(RecordsError::MeaningMismatch);
        }
        self.mutate(|state| create_in(state, &command))
    }

    fn read(&self, command: SealedReadRecordCommand) -> Result<ReadTransition, RecordsError> {
        if !command.lifecycle_authorization_matches() {
            return Err(RecordsError::MeaningMismatch);
        }
        self.mutate(|state| read_in(state, &command))
    }

    fn completed(
        &self,
        action_digest: &str,
    ) -> Result<Option<CompletedRecordsAction>, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .completed_actions
            .get(action_digest)
            .cloned())
    }

    fn append_receipt(&self, receipt: ReceiptBundle) -> Result<(), RecordsError> {
        self.mutate(|state| {
            state
                .receipts
                .insert(receipt.decision.receipt_id.clone(), receipt);
            Ok(())
        })
    }

    fn receipt(&self, receipt_id: &str) -> Result<Option<ReceiptBundle>, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .receipts
            .get(receipt_id)
            .cloned())
    }

    fn usage(&self, policy_digest: &str) -> Result<Usage, RecordsError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?
            .usage_by_policy
            .get(policy_digest)
            .cloned()
            .unwrap_or_default())
    }

    fn state_commitment(&self) -> Result<String, RecordsError> {
        canonical_digest(
            &*self
                .state
                .lock()
                .map_err(|_| RecordsError::StateUnavailable)?,
        )
    }
}

fn create_in(
    state: &mut LedgerState,
    command: &SealedCreateRecordCommand,
) -> Result<CreateTransition, RecordsError> {
    let action = command.action();
    let action_digest = action.digest()?;
    if let Some(completed) = state.completed_actions.get(&action_digest) {
        return Ok(CreateTransition::Replay(completed.effect.clone()));
    }
    let key = record_key(&action.namespace_id, &action.record_id);
    if state.records.contains_key(&key) {
        return Ok(CreateTransition::Denied("record-already-exists"));
    }
    let usage = state
        .usage_by_policy
        .entry(action.policy_digest.clone())
        .or_default();
    let value_bytes = u64::try_from(canonical_json(&action.customer)?.len())
        .map_err(|_| RecordsError::LimitExceeded)?;
    let before = usage.clone();
    usage.create_units = usage
        .create_units
        .checked_add(1)
        .ok_or(RecordsError::StateUnavailable)?;
    usage.created_bytes = usage
        .created_bytes
        .checked_add(value_bytes)
        .ok_or(RecordsError::StateUnavailable)?;
    let record = StoredRecord {
        namespace_id: action.namespace_id.clone(),
        record_id: action.record_id.clone(),
        customer: action.customer.clone(),
        created_at: command.executed_at(),
        updated_at: command.executed_at(),
        version: 1,
    };
    state.records.insert(key, record);
    let effect = EffectReceipt::Create {
        receipt_id: format!("effect-{}", &action_digest[..24]),
        decision_digest: command.decision_digest().into(),
        action_digest: action_digest.clone(),
        namespace_commitment: sha256(action.namespace_id.as_str().as_bytes()),
        record_commitment: sha256(action.record_id.as_str().as_bytes()),
        value_commitment: canonical_digest(&action.customer)?,
        record_version: 1,
        create_units_before: before.create_units,
        create_units_after: usage.create_units,
        created_bytes_before: before.created_bytes,
        created_bytes_after: usage.created_bytes,
        executed_at: command.executed_at(),
    };
    state.completed_actions.insert(
        action_digest,
        CompletedRecordsAction {
            effect: effect.clone(),
            projection: None,
        },
    );
    Ok(CreateTransition::Executed(effect))
}

fn read_in(
    state: &mut LedgerState,
    command: &SealedReadRecordCommand,
) -> Result<ReadTransition, RecordsError> {
    let action = command.action();
    let policy = command.policy();
    let action_digest = action.digest()?;
    if let Some(completed) = state.completed_actions.get(&action_digest) {
        if let Some(projection) = &completed.projection {
            return Ok(ReadTransition::Replay {
                receipt: completed.effect.clone(),
                projection: projection.clone(),
            });
        }
        return Err(RecordsError::StateUnavailable);
    }
    let key = record_key(&action.namespace_id, &action.record_id);
    let Some(record) = state.records.get(&key) else {
        return Ok(ReadTransition::Denied("record-not-found"));
    };
    if record.version != action.expected_record_version {
        return Ok(ReadTransition::Denied("record-version-mismatch"));
    }
    let projection = project(record, &action.allowed_fields);
    let response = canonical_json(&projection)?;
    let response_bytes = u64::try_from(response.len()).map_err(|_| RecordsError::LimitExceeded)?;
    if response_bytes > u64::from(action.maximum_response_bytes) {
        return Ok(ReadTransition::Denied("response-limit-exceeded"));
    }
    let usage = state
        .usage_by_policy
        .entry(action.policy_digest.clone())
        .or_default();
    if usage.disclosed_bytes.saturating_add(response_bytes) > policy.maximum_disclosed_bytes {
        return Ok(ReadTransition::Denied("disclosure-budget-exhausted"));
    }
    let before = usage.clone();
    usage.read_units = usage
        .read_units
        .checked_add(1)
        .ok_or(RecordsError::StateUnavailable)?;
    usage.disclosed_bytes = usage
        .disclosed_bytes
        .checked_add(response_bytes)
        .ok_or(RecordsError::StateUnavailable)?;
    let effect = EffectReceipt::Read {
        receipt_id: format!("effect-{}", &action_digest[..24]),
        decision_digest: command.decision_digest().into(),
        action_digest: action_digest.clone(),
        namespace_commitment: sha256(action.namespace_id.as_str().as_bytes()),
        record_commitment: sha256(action.record_id.as_str().as_bytes()),
        fields_commitment: canonical_digest(&action.allowed_fields)?,
        response_commitment: sha256(&response),
        response_bytes,
        read_units_before: before.read_units,
        read_units_after: usage.read_units,
        disclosed_bytes_before: before.disclosed_bytes,
        disclosed_bytes_after: usage.disclosed_bytes,
        disclosed_at: command.disclosed_at(),
    };
    state.completed_actions.insert(
        action_digest,
        CompletedRecordsAction {
            effect: effect.clone(),
            projection: Some(projection.clone()),
        },
    );
    Ok(ReadTransition::Disclosed {
        receipt: effect,
        projection,
    })
}

fn project(record: &StoredRecord, fields: &[ReadField]) -> RecordProjection {
    RecordProjection {
        record_id: fields
            .contains(&ReadField::RecordId)
            .then(|| record.record_id.as_str().to_string()),
        customer: fields
            .contains(&ReadField::Customer)
            .then(|| record.customer.clone()),
        created_at: fields
            .contains(&ReadField::CreatedAt)
            .then_some(record.created_at),
        updated_at: fields
            .contains(&ReadField::UpdatedAt)
            .then_some(record.updated_at),
        version: fields
            .contains(&ReadField::Version)
            .then_some(record.version),
    }
}

fn record_key(namespace: &RecordIdentifier, record: &RecordIdentifier) -> String {
    format!("{}/{}", namespace.as_str(), record.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_v2_state_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records-ledger.json");
        let first = PersistentRecordsLedger::open(&path).unwrap();
        let commitment = first.state_commitment().unwrap();
        first.mutate(|_| Ok(())).unwrap();
        drop(first);

        let reopened = PersistentRecordsLedger::open(&path).unwrap();
        assert_eq!(reopened.state_commitment().unwrap(), commitment);
        assert!(reopened.completed(&"a".repeat(64)).unwrap().is_none());
    }

    #[test]
    fn obsolete_v1_state_is_rejected_without_rewrite() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records-ledger.json");
        let obsolete =
            br#"{"completed_actions":{},"receipts":{},"records":{},"usage_by_policy":{}}"#;
        fs::write(&path, obsolete).unwrap();

        assert!(PersistentRecordsLedger::open(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), obsolete);
    }
}
