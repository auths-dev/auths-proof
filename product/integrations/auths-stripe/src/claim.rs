//! Durable at-most-once claims for exact Stripe refunds.

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
    canonical::{canonical_json, sha256},
    types::{DigestHex, RefundId},
};

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

/// Monotonic execution stage.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    /// Exact action is reserved.
    Claimed,
    /// Stripe returned a refund object.
    ProviderAccepted,
    /// A later provider read or webhook was recorded.
    Observed,
    /// Request delivery may have reached Stripe and requires reconciliation.
    OutcomeUnknown,
    /// A known provider failure occurred before creation.
    Failed,
}

/// Durable public claim state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    workflow_id: String,
    action_digest: DigestHex,
    lease_digest: DigestHex,
    stage: ClaimStage,
    refund_id: Option<RefundId>,
    result_digest: Option<DigestHex>,
    updated_at: u64,
}

impl ClaimRecord {
    /// Workflow.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Exact claimed action.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Current stage.
    #[must_use]
    pub const fn stage(&self) -> ClaimStage {
        self.stage
    }

    /// Provider refund, when known.
    #[must_use]
    pub const fn refund_id(&self) -> Option<&RefundId> {
        self.refund_id.as_ref()
    }
}

/// Opaque proof that the exact action was claimed.
#[derive(Debug)]
pub struct ClaimLease {
    workflow_id: String,
    action_digest: DigestHex,
    lease_digest: DigestHex,
}

impl ClaimLease {
    /// Workflow.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Exact action digest.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }
}

/// Claim attempt outcome.
#[derive(Debug)]
pub enum ClaimResult {
    /// This caller owns the one execution lease.
    Claimed(ClaimLease),
    /// The same exact action was previously claimed.
    Replay(ClaimRecord),
    /// The workflow ID is bound to different action bytes.
    Conflict(ClaimRecord),
    /// Durable storage was unavailable.
    Unavailable,
}

/// Minimal durable claim contract.
pub trait ClaimStore: Send + Sync {
    /// Claims one exact action.
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult;

    /// Records a provider result.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for a missing or conflicting lease.
    fn record_provider_result(
        &self,
        lease: &ClaimLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError>;

    /// Records a known terminal or reconciliation stage.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for a missing or conflicting lease.
    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError>;

    /// Reads claim state.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence failure.
    fn get(&self, workflow_id: &str) -> Result<Option<ClaimRecord>, ClaimStoreError>;
}

impl<T: ClaimStore + ?Sized> ClaimStore for Arc<T> {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        (**self).claim(workflow_id, action_digest, now)
    }

    fn record_provider_result(
        &self,
        lease: &ClaimLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        (**self).record_provider_result(lease, refund_id, result_digest, now)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        (**self).record_stage(lease, stage, now)
    }

    fn get(&self, workflow_id: &str) -> Result<Option<ClaimRecord>, ClaimStoreError> {
        (**self).get(workflow_id)
    }
}

/// Process-safe in-memory claim store.
#[derive(Default)]
pub struct InMemoryClaimStore {
    records: Mutex<BTreeMap<String, ClaimRecord>>,
}

impl ClaimStore for InMemoryClaimStore {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        let Ok(mut records) = self.records.lock() else {
            return ClaimResult::Unavailable;
        };
        claim_in(&mut records, workflow_id, action_digest, now)
    }

    fn record_provider_result(
        &self,
        lease: &ClaimLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ClaimStoreError::Unavailable)?;
        record_provider_result_in(&mut records, lease, refund_id, result_digest, now)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ClaimStoreError::Unavailable)?;
        record_stage_in(&mut records, lease, stage, now)
    }

    fn get(&self, workflow_id: &str) -> Result<Option<ClaimRecord>, ClaimStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| ClaimStoreError::Unavailable)
    }
}

/// Crash-persistent single-writer claim store.
pub struct PersistentClaimStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, ClaimRecord>>,
}

impl PersistentClaimStore {
    /// Opens one canonical bounded state file.
    ///
    /// # Errors
    ///
    /// Rejects malformed, non-canonical, or oversized state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ClaimStoreError> {
        let path = path.into();
        let records = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| ClaimStoreError::Unavailable)?;
            if bytes.len() > MAX_STATE_BYTES {
                return Err(ClaimStoreError::Corrupt);
            }
            let records: BTreeMap<String, ClaimRecord> =
                serde_json::from_slice(&bytes).map_err(|_| ClaimStoreError::Corrupt)?;
            if canonical_json(&records).map_err(|_| ClaimStoreError::Corrupt)? != bytes {
                return Err(ClaimStoreError::Corrupt);
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
        operation: impl FnOnce(&mut BTreeMap<String, ClaimRecord>) -> Result<T, ClaimStoreError>,
    ) -> Result<T, ClaimStoreError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ClaimStoreError::Unavailable)?;
        let output = operation(&mut records)?;
        let bytes = canonical_json(&*records).map_err(|_| ClaimStoreError::Corrupt)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ClaimStoreError::Unavailable);
        }
        let parent = self.path.parent().ok_or(ClaimStoreError::Unavailable)?;
        fs::create_dir_all(parent).map_err(|_| ClaimStoreError::Unavailable)?;
        let mut temporary =
            NamedTempFile::new_in(parent).map_err(|_| ClaimStoreError::Unavailable)?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| ClaimStoreError::Unavailable)?;
        temporary
            .persist(&self.path)
            .map_err(|_| ClaimStoreError::Unavailable)?;
        Ok(output)
    }
}

impl ClaimStore for PersistentClaimStore {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        self.mutate(|records| Ok(claim_in(records, workflow_id, action_digest, now)))
            .unwrap_or(ClaimResult::Unavailable)
    }

    fn record_provider_result(
        &self,
        lease: &ClaimLease,
        refund_id: &RefundId,
        result_digest: &DigestHex,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        self.mutate(|records| {
            record_provider_result_in(records, lease, refund_id, result_digest, now)
        })
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimStoreError> {
        self.mutate(|records| record_stage_in(records, lease, stage, now))
    }

    fn get(&self, workflow_id: &str) -> Result<Option<ClaimRecord>, ClaimStoreError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| ClaimStoreError::Unavailable)
    }
}

fn claim_in(
    records: &mut BTreeMap<String, ClaimRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    now: u64,
) -> ClaimResult {
    if !valid_workflow_id(workflow_id) {
        return ClaimResult::Unavailable;
    }
    if let Some(record) = records.get(workflow_id) {
        return if record.action_digest == *action_digest {
            ClaimResult::Replay(record.clone())
        } else {
            ClaimResult::Conflict(record.clone())
        };
    }
    let lease_digest = sha256(
        format!(
            "auths.stripe.claim/1\0{workflow_id}\0{}\0{now}",
            action_digest.as_str()
        )
        .as_bytes(),
    );
    records.insert(
        workflow_id.to_owned(),
        ClaimRecord {
            workflow_id: workflow_id.to_owned(),
            action_digest: action_digest.clone(),
            lease_digest: lease_digest.clone(),
            stage: ClaimStage::Claimed,
            refund_id: None,
            result_digest: None,
            updated_at: now,
        },
    );
    ClaimResult::Claimed(ClaimLease {
        workflow_id: workflow_id.to_owned(),
        action_digest: action_digest.clone(),
        lease_digest,
    })
}

fn record_provider_result_in(
    records: &mut BTreeMap<String, ClaimRecord>,
    lease: &ClaimLease,
    refund_id: &RefundId,
    result_digest: &DigestHex,
    now: u64,
) -> Result<ClaimRecord, ClaimStoreError> {
    let record = record_for_lease(records, lease)?;
    if record.stage != ClaimStage::Claimed && record.stage != ClaimStage::OutcomeUnknown {
        return Err(ClaimStoreError::InvalidTransition);
    }
    record.stage = ClaimStage::ProviderAccepted;
    record.refund_id = Some(refund_id.clone());
    record.result_digest = Some(result_digest.clone());
    record.updated_at = now;
    Ok(record.clone())
}

fn record_stage_in(
    records: &mut BTreeMap<String, ClaimRecord>,
    lease: &ClaimLease,
    stage: ClaimStage,
    now: u64,
) -> Result<ClaimRecord, ClaimStoreError> {
    let record = record_for_lease(records, lease)?;
    let valid = match stage {
        ClaimStage::Claimed | ClaimStage::ProviderAccepted => false,
        ClaimStage::Observed => record.stage == ClaimStage::ProviderAccepted,
        ClaimStage::OutcomeUnknown | ClaimStage::Failed => record.stage == ClaimStage::Claimed,
    };
    if !valid {
        return Err(ClaimStoreError::InvalidTransition);
    }
    record.stage = stage;
    record.updated_at = now;
    Ok(record.clone())
}

fn record_for_lease<'a>(
    records: &'a mut BTreeMap<String, ClaimRecord>,
    lease: &ClaimLease,
) -> Result<&'a mut ClaimRecord, ClaimStoreError> {
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(ClaimStoreError::Missing)?;
    if record.action_digest != lease.action_digest || record.lease_digest != lease.lease_digest {
        return Err(ClaimStoreError::Conflict);
    }
    Ok(record)
}

fn valid_workflow_id(value: &str) -> bool {
    (8..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

/// Closed claim-store error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimStoreError {
    /// State is unavailable.
    #[error("claim state is unavailable")]
    Unavailable,
    /// State file is malformed or non-canonical.
    #[error("claim state is corrupt")]
    Corrupt,
    /// Claim is missing.
    #[error("claim is missing")]
    Missing,
    /// Lease does not match.
    #[error("claim lease conflicts")]
    Conflict,
    /// Stage transition is invalid.
    #[error("invalid claim transition")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn concurrent_claims_execute_once() {
        let store = Arc::new(InMemoryClaimStore::default());
        let digest = sha256(b"one exact refund");
        let handles = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let digest = digest.clone();
                std::thread::spawn(move || store.claim("refund-workflow-1", &digest, 100))
            })
            .collect::<Vec<_>>();
        let claimed = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|result| matches!(result, ClaimResult::Claimed(_)))
            .count();
        assert_eq!(claimed, 1);
    }
}
