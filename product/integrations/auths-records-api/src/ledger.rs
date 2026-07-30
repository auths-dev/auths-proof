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
    BoundedRecordApiPolicyV1, CreateRecordV1, CustomerRecordV1, EffectReceipt, ReadField,
    ReadRecordV1, ReceiptBundle, RecordIdentifier, RecordsError,
    canonical::{canonical_digest, canonical_json, sha256},
};

const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;

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
struct CompletedAction {
    effect: EffectReceipt,
    projection: Option<RecordProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct LedgerState {
    records: BTreeMap<String, StoredRecord>,
    usage_by_policy: BTreeMap<String, Usage>,
    completed_actions: BTreeMap<String, CompletedAction>,
    receipts: BTreeMap<String, ReceiptBundle>,
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
    fn create(
        &self,
        action: &CreateRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<CreateTransition, RecordsError>;

    fn read(
        &self,
        action: &ReadRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<ReadTransition, RecordsError>;

    fn append_receipt(&self, receipt: ReceiptBundle) -> Result<(), RecordsError>;
    fn receipt(&self, receipt_id: &str) -> Result<Option<ReceiptBundle>, RecordsError>;
    fn usage(&self, policy_digest: &str) -> Result<Usage, RecordsError>;
    fn state_commitment(&self) -> Result<String, RecordsError>;
}

impl<T: RecordsLedger + ?Sized> RecordsLedger for Arc<T> {
    fn create(
        &self,
        action: &CreateRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<CreateTransition, RecordsError> {
        (**self).create(action, policy, decision_digest, now)
    }

    fn read(
        &self,
        action: &ReadRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<ReadTransition, RecordsError> {
        (**self).read(action, policy, decision_digest, now)
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

#[derive(Clone, Default)]
pub struct MemoryRecordsLedger {
    state: Arc<Mutex<LedgerState>>,
}

impl RecordsLedger for MemoryRecordsLedger {
    fn create(
        &self,
        action: &CreateRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<CreateTransition, RecordsError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?;
        create_in(&mut state, action, policy, decision_digest, now)
    }

    fn read(
        &self,
        action: &ReadRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<ReadTransition, RecordsError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RecordsError::StateUnavailable)?;
        read_in(&mut state, action, policy, decision_digest, now)
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
            if canonical_json(&state)? != bytes {
                return Err(RecordsError::NonCanonical);
            }
            state
        } else {
            LedgerState::default()
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
    fn create(
        &self,
        action: &CreateRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<CreateTransition, RecordsError> {
        self.mutate(|state| create_in(state, action, policy, decision_digest, now))
    }

    fn read(
        &self,
        action: &ReadRecordV1,
        policy: &BoundedRecordApiPolicyV1,
        decision_digest: &str,
        now: u64,
    ) -> Result<ReadTransition, RecordsError> {
        self.mutate(|state| read_in(state, action, policy, decision_digest, now))
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
    action: &CreateRecordV1,
    policy: &BoundedRecordApiPolicyV1,
    decision_digest: &str,
    now: u64,
) -> Result<CreateTransition, RecordsError> {
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
    if usage.create_units >= policy.maximum_creates {
        return Ok(CreateTransition::Denied("create-budget-exhausted"));
    }
    if usage.created_bytes.saturating_add(value_bytes) > policy.maximum_created_bytes {
        return Ok(CreateTransition::Denied("created-bytes-budget-exhausted"));
    }
    let before = usage.clone();
    usage.create_units = usage.create_units.saturating_add(1);
    usage.created_bytes = usage.created_bytes.saturating_add(value_bytes);
    let record = StoredRecord {
        namespace_id: action.namespace_id.clone(),
        record_id: action.record_id.clone(),
        customer: action.customer.clone(),
        created_at: now,
        updated_at: now,
        version: 1,
    };
    state.records.insert(key, record);
    let effect = EffectReceipt::Create {
        receipt_id: format!("effect-{}", &action_digest[..24]),
        decision_digest: decision_digest.into(),
        action_digest: action_digest.clone(),
        namespace_commitment: sha256(action.namespace_id.as_str().as_bytes()),
        record_commitment: sha256(action.record_id.as_str().as_bytes()),
        value_commitment: canonical_digest(&action.customer)?,
        record_version: 1,
        create_units_before: before.create_units,
        create_units_after: usage.create_units,
        created_bytes_before: before.created_bytes,
        created_bytes_after: usage.created_bytes,
        executed_at: now,
    };
    state.completed_actions.insert(
        action_digest,
        CompletedAction {
            effect: effect.clone(),
            projection: None,
        },
    );
    Ok(CreateTransition::Executed(effect))
}

fn read_in(
    state: &mut LedgerState,
    action: &ReadRecordV1,
    policy: &BoundedRecordApiPolicyV1,
    decision_digest: &str,
    now: u64,
) -> Result<ReadTransition, RecordsError> {
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
    if usage.read_units >= policy.maximum_reads {
        return Ok(ReadTransition::Denied("read-budget-exhausted"));
    }
    if usage.disclosed_bytes.saturating_add(response_bytes) > policy.maximum_disclosed_bytes {
        return Ok(ReadTransition::Denied("disclosure-budget-exhausted"));
    }
    let before = usage.clone();
    usage.read_units = usage.read_units.saturating_add(1);
    usage.disclosed_bytes = usage.disclosed_bytes.saturating_add(response_bytes);
    let effect = EffectReceipt::Read {
        receipt_id: format!("effect-{}", &action_digest[..24]),
        decision_digest: decision_digest.into(),
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
        disclosed_at: now,
    };
    state.completed_actions.insert(
        action_digest,
        CompletedAction {
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
    use crate::{CREATE_OPERATION, READ_OPERATION};

    fn fixture() -> (CreateRecordV1, BoundedRecordApiPolicyV1) {
        let policy = BoundedRecordApiPolicyV1 {
            policy_type: "auths.demo.bounded-record-api-policy".into(),
            policy_version: 1,
            policy_id: "p".into(),
            namespace_id: RecordIdentifier::parse("visitor").unwrap(),
            presenter_principal: "key:demo".into(),
            allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
            allowed_record_ids: Vec::new(),
            allowed_record_id_prefixes: vec!["demo-".into()],
            maximum_value_bytes: 100,
            maximum_response_bytes: 4096,
            allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId],
            maximum_creates: 1,
            maximum_reads: 1,
            maximum_created_bytes: 100,
            maximum_disclosed_bytes: 4096,
            fixed_and_rolling_budgets: Vec::new(),
            valid_from: 0,
            expires_at: 100,
            maximum_action_lifetime_seconds: 100,
            maximum_presentation_lifetime_seconds: 100,
            maximum_evidence_age_seconds: 100,
            executor_audience: "https://records".into(),
        };
        let action = CreateRecordV1 {
            profile: "auths.demo.records.create/1".into(),
            namespace_id: policy.namespace_id.clone(),
            record_id: RecordIdentifier::parse("demo-1").unwrap(),
            customer: CustomerRecordV1 {
                age: 25,
                name: "Bob".into(),
                notes: "Demo customer".into(),
                occupation: "Sales".into(),
            },
            value_encoding: "auths.demo.customer-record/1".into(),
            expected_absent: true,
            policy_digest: policy.digest().unwrap(),
            required_evaluator: "auths.records.create-evaluator/1".into(),
            required_configuration_digest: "a".repeat(64),
            executor_audience: policy.executor_audience.clone(),
            expires_at: 50,
            nonce: "0123456789abcdef".into(),
        };
        (action, policy)
    }

    #[test]
    fn concurrent_final_unit_is_consumed_once() {
        let ledger = Arc::new(MemoryRecordsLedger::default());
        let (action, policy) = fixture();
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let ledger = Arc::clone(&ledger);
                let action = action.clone();
                let policy = policy.clone();
                std::thread::spawn(move || ledger.create(&action, &policy, "decision", 1).unwrap())
            })
            .collect();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, CreateTransition::Executed(_)))
                .count(),
            1
        );
        assert_eq!(ledger.usage(&action.policy_digest).unwrap().create_units, 1);
    }

    #[test]
    fn committed_action_and_budget_survive_process_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("records-ledger.json");
        let (action, policy) = fixture();

        {
            let ledger = PersistentRecordsLedger::open(&path).unwrap();
            let first = ledger.create(&action, &policy, "decision-1", 1).unwrap();
            assert!(matches!(first, CreateTransition::Executed(_)));
            assert_eq!(ledger.usage(&action.policy_digest).unwrap().create_units, 1);
        }

        let reopened = PersistentRecordsLedger::open(&path).unwrap();
        let replay = reopened.create(&action, &policy, "decision-2", 2).unwrap();
        assert!(matches!(replay, CreateTransition::Replay(_)));
        assert_eq!(
            reopened.usage(&action.policy_digest).unwrap().create_units,
            1
        );
    }
}
