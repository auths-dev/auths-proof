//! Atomic at-most-once claim state for saved-plan application.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{canonical::canonical_json, types::DigestHex};

const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

/// Durable workflow stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    Claimed,
    ArtifactVerified,
    CredentialAcquired,
    StateRechecked,
    ApplyStarted,
    StateCommitted,
    PostconditionsObserved,
    Converged,
    OutcomeUnknown,
    Failed,
}

/// Receipt-safe claim record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub action_digest: DigestHex,
    pub stage: ClaimStage,
    pub claimed_at: u64,
    pub updated_at: u64,
}

/// Capability held only by the claim winner.
#[derive(Clone, Debug)]
pub struct ClaimLease {
    pub(crate) action_digest: DigestHex,
}

/// Atomic claim result.
#[derive(Clone, Debug)]
pub enum ClaimResult {
    Claimed(ClaimLease),
    /// A prior apply reached an ambiguous outcome and must be observed, never
    /// blindly applied again.
    Resume(ClaimLease),
    Replay(ClaimRecord),
    Conflict(ClaimRecord),
    Unavailable,
}

/// Durable claim-store boundary.
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

/// Crash-persistent single-process store using atomic replacement.
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
        return if record.stage == ClaimStage::OutcomeUnknown {
            ClaimResult::Resume(ClaimLease {
                action_digest: action_digest.clone(),
            })
        } else if matches!(
            record.stage,
            ClaimStage::Converged | ClaimStage::StateCommitted | ClaimStage::PostconditionsObserved
        ) {
            ClaimResult::Replay(record.clone())
        } else {
            ClaimResult::Conflict(record.clone())
        };
    }
    let record = ClaimRecord {
        action_digest: action_digest.clone(),
        stage: ClaimStage::Claimed,
        claimed_at: now,
        updated_at: now,
    };
    records.insert(action_digest.clone(), record);
    ClaimResult::Claimed(ClaimLease {
        action_digest: action_digest.clone(),
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
    if now < record.updated_at || !transition_allowed(record.stage, stage) {
        return Err(ClaimError::InvalidTransition);
    }
    record.stage = stage;
    record.updated_at = now;
    Ok(record.clone())
}

const fn transition_allowed(current: ClaimStage, next: ClaimStage) -> bool {
    current as u8 == next as u8
        || matches!(
            (current, next),
            (
                ClaimStage::Claimed,
                ClaimStage::ArtifactVerified | ClaimStage::Failed
            ) | (
                ClaimStage::ArtifactVerified,
                ClaimStage::CredentialAcquired | ClaimStage::Failed
            ) | (
                ClaimStage::CredentialAcquired,
                ClaimStage::StateRechecked | ClaimStage::Failed
            ) | (
                ClaimStage::StateRechecked,
                ClaimStage::ApplyStarted | ClaimStage::Failed
            ) | (
                ClaimStage::ApplyStarted,
                ClaimStage::StateCommitted | ClaimStage::OutcomeUnknown | ClaimStage::Failed
            ) | (
                ClaimStage::OutcomeUnknown,
                ClaimStage::StateCommitted | ClaimStage::Failed
            ) | (
                ClaimStage::StateCommitted,
                ClaimStage::PostconditionsObserved
            ) | (ClaimStage::PostconditionsObserved, ClaimStage::Converged)
        )
}

/// Closed claim-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimError {
    #[error("claim store is unavailable")]
    Unavailable,
    #[error("claim store is corrupt")]
    Corrupt,
    #[error("claim lease does not match durable state")]
    LeaseMismatch,
    #[error("claim stage transition is not monotonic")]
    InvalidTransition,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let store = Arc::new(MemoryClaimStore::default());
        let digest = crate::canonical::sha256(b"one-plan");
        let barrier = Arc::new(Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let store = Arc::clone(&store);
                let digest = digest.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.claim(&digest, 100)
                })
            })
            .collect();
        let winners = handles
            .into_iter()
            .map(|handle| matches!(handle.join().unwrap(), ClaimResult::Claimed(_)))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn outcome_unknown_resumes_only_for_reconciliation() {
        let store = MemoryClaimStore::default();
        let digest = crate::canonical::sha256(b"ambiguous-plan");
        let ClaimResult::Claimed(lease) = store.claim(&digest, 100) else {
            panic!("first claim must win")
        };
        for (stage, now) in [
            (ClaimStage::ArtifactVerified, 101),
            (ClaimStage::CredentialAcquired, 102),
            (ClaimStage::StateRechecked, 103),
            (ClaimStage::ApplyStarted, 104),
        ] {
            store.record_stage(&lease, stage, now).unwrap();
        }
        store
            .record_stage(&lease, ClaimStage::OutcomeUnknown, 105)
            .unwrap();
        assert!(matches!(store.claim(&digest, 106), ClaimResult::Resume(_)));
        assert_eq!(
            store.record_stage(&lease, ClaimStage::ArtifactVerified, 107),
            Err(ClaimError::InvalidTransition)
        );
        assert!(matches!(store.claim(&digest, 108), ClaimResult::Resume(_)));
    }
}
