//! Durable at-most-once claim state before credential acquisition.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{canonical::canonical_json, schema::DigestHex};

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

/// Durable workflow stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    Claimed,
    CredentialAcquired,
    TransactionStarted,
    LedgerReserved,
    RowsLocked,
    MutationCommitted,
    Observed,
    Reconciled,
    OutcomeUnknown,
    Failed,
}

/// Receipt-safe claim record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub action_digest: DigestHex,
    pub claim_id: String,
    pub stage: ClaimStage,
    pub claimed_at: u64,
    pub updated_at: u64,
}

/// Capability held only by the successful claimant.
#[derive(Clone, Debug)]
pub struct ClaimLease {
    pub(crate) action_digest: DigestHex,
    pub(crate) claim_id: String,
}

/// Atomic claim result.
#[derive(Clone, Debug)]
pub enum ClaimResult {
    Claimed(ClaimLease),
    Replay(ClaimRecord),
    Conflict(ClaimRecord),
    Unavailable,
}

/// Durable claim boundary.
pub trait ClaimStore: Send + Sync {
    fn claim(&self, action_digest: &DigestHex, now: u64) -> ClaimResult;
    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError>;
    fn get(&self, action_digest: &DigestHex) -> Result<Option<ClaimRecord>, ClaimError>;
}

impl<T: ClaimStore + ?Sized> ClaimStore for Arc<T> {
    fn claim(&self, action_digest: &DigestHex, now: u64) -> ClaimResult {
        (**self).claim(action_digest, now)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError> {
        (**self).record_stage(lease, stage, now)
    }

    fn get(&self, action_digest: &DigestHex) -> Result<Option<ClaimRecord>, ClaimError> {
        (**self).get(action_digest)
    }
}

/// Thread-safe deterministic store.
#[derive(Clone, Default)]
pub struct MemoryClaimStore {
    records: Arc<Mutex<BTreeMap<DigestHex, ClaimRecord>>>,
}

impl ClaimStore for MemoryClaimStore {
    fn claim(&self, action_digest: &DigestHex, now: u64) -> ClaimResult {
        let Ok(mut records) = self.records.lock() else {
            return ClaimResult::Unavailable;
        };
        claim_in(&mut records, action_digest, now)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError> {
        let mut records = self.records.lock().map_err(|_| ClaimError::Unavailable)?;
        record_stage_in(&mut records, lease, stage, now)
    }

    fn get(&self, action_digest: &DigestHex) -> Result<Option<ClaimRecord>, ClaimError> {
        self.records
            .lock()
            .map(|records| records.get(action_digest).cloned())
            .map_err(|_| ClaimError::Unavailable)
    }
}

/// Crash-persistent store using canonical JSON and atomic replacement.
pub struct PersistentClaimStore {
    path: PathBuf,
    records: Mutex<BTreeMap<DigestHex, ClaimRecord>>,
}

impl PersistentClaimStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ClaimError> {
        let path = path.into();
        let records = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| ClaimError::Unavailable)?;
            if bytes.len() > MAX_STATE_BYTES {
                return Err(ClaimError::Corrupt);
            }
            let records: BTreeMap<DigestHex, ClaimRecord> =
                serde_json::from_slice(&bytes).map_err(|_| ClaimError::Corrupt)?;
            if canonical_json(&records).map_err(|_| ClaimError::Corrupt)? != bytes {
                return Err(ClaimError::Corrupt);
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
        operation: impl FnOnce(&mut BTreeMap<DigestHex, ClaimRecord>) -> Result<T, ClaimError>,
    ) -> Result<T, ClaimError> {
        let mut records = self.records.lock().map_err(|_| ClaimError::Unavailable)?;
        let mut candidate = records.clone();
        let result = operation(&mut candidate)?;
        let bytes = canonical_json(&candidate).map_err(|_| ClaimError::Corrupt)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(ClaimError::Unavailable);
        }
        let parent = self.path.parent().ok_or(ClaimError::Unavailable)?;
        fs::create_dir_all(parent).map_err(|_| ClaimError::Unavailable)?;
        let mut temporary = NamedTempFile::new_in(parent).map_err(|_| ClaimError::Unavailable)?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| ClaimError::Unavailable)?;
        temporary
            .persist(&self.path)
            .map_err(|_| ClaimError::Unavailable)?;
        *records = candidate;
        Ok(result)
    }
}

impl ClaimStore for PersistentClaimStore {
    fn claim(&self, action_digest: &DigestHex, now: u64) -> ClaimResult {
        self.mutate(|records| Ok(claim_in(records, action_digest, now)))
            .unwrap_or(ClaimResult::Unavailable)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError> {
        self.mutate(|records| record_stage_in(records, lease, stage, now))
    }

    fn get(&self, action_digest: &DigestHex) -> Result<Option<ClaimRecord>, ClaimError> {
        self.records
            .lock()
            .map(|records| records.get(action_digest).cloned())
            .map_err(|_| ClaimError::Unavailable)
    }
}

fn claim_in(
    records: &mut BTreeMap<DigestHex, ClaimRecord>,
    action_digest: &DigestHex,
    now: u64,
) -> ClaimResult {
    if let Some(record) = records.get(action_digest) {
        return if matches!(
            record.stage,
            ClaimStage::MutationCommitted | ClaimStage::Observed | ClaimStage::Reconciled
        ) {
            ClaimResult::Replay(record.clone())
        } else {
            ClaimResult::Conflict(record.clone())
        };
    }
    let claim_id = format!("claim-{}", &action_digest.as_str()[..24]);
    records.insert(
        action_digest.clone(),
        ClaimRecord {
            action_digest: action_digest.clone(),
            claim_id: claim_id.clone(),
            stage: ClaimStage::Claimed,
            claimed_at: now,
            updated_at: now,
        },
    );
    ClaimResult::Claimed(ClaimLease {
        action_digest: action_digest.clone(),
        claim_id,
    })
}

fn record_stage_in(
    records: &mut BTreeMap<DigestHex, ClaimRecord>,
    lease: &ClaimLease,
    stage: ClaimStage,
    now: u64,
) -> Result<ClaimRecord, ClaimError> {
    let record = records
        .get_mut(&lease.action_digest)
        .ok_or(ClaimError::LeaseMismatch)?;
    if record.claim_id != lease.claim_id {
        return Err(ClaimError::LeaseMismatch);
    }
    record.stage = stage;
    record.updated_at = now;
    Ok(record.clone())
}

/// Closed claim persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimError {
    #[error("claim store unavailable")]
    Unavailable,
    #[error("claim store corrupt")]
    Corrupt,
    #[error("claim lease mismatch")]
    LeaseMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::sha256;

    #[test]
    fn only_one_claim_wins() {
        let store = MemoryClaimStore::default();
        let digest = sha256(b"action");
        assert!(matches!(store.claim(&digest, 1), ClaimResult::Claimed(_)));
        assert!(matches!(store.claim(&digest, 2), ClaimResult::Conflict(_)));
    }

    #[test]
    fn committed_claim_is_replay() {
        let store = MemoryClaimStore::default();
        let digest = sha256(b"action");
        let ClaimResult::Claimed(lease) = store.claim(&digest, 1) else {
            panic!("first claimant must win")
        };
        store
            .record_stage(&lease, ClaimStage::MutationCommitted, 2)
            .unwrap();
        assert!(matches!(store.claim(&digest, 3), ClaimResult::Replay(_)));
    }
}
