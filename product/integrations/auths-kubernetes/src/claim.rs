//! Atomic at-most-once claim state for irreversible rollouts.

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

/// Durable claim stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimStage {
    Claimed,
    CredentialAcquired,
    ApiAccepted,
    PersistedVerified,
    RolloutConverged,
    OutcomeUnknown,
    Failed,
}

/// Claim record safe for receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimRecord {
    pub workflow_id: String,
    pub action_digest: DigestHex,
    pub stage: ClaimStage,
    pub claimed_at: u64,
    pub updated_at: u64,
}

/// Capability held only by the winning claimant.
#[derive(Clone, Debug)]
pub struct ClaimLease {
    pub(crate) workflow_id: String,
    pub(crate) action_digest: DigestHex,
}

/// Atomic claim outcome.
pub enum ClaimResult {
    Claimed(ClaimLease),
    Replay(ClaimRecord),
    Conflict(ClaimRecord),
    Unavailable,
}

/// Durable claim store boundary.
pub trait ClaimStore: Send + Sync {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult;

    /// Advances a lease held by the unique winning claimant.
    ///
    /// # Errors
    ///
    /// Returns [`ClaimError`] when durable state is unavailable, the lease no
    /// longer matches, or the requested transition would move backward.
    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError>;
}

impl<T: ClaimStore + ?Sized> ClaimStore for Arc<T> {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        (**self).claim(workflow_id, action_digest, now)
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError> {
        (**self).record_stage(lease, stage, now)
    }
}

/// Thread-safe deterministic claim store used by tests and demo adapters.
#[derive(Clone, Default)]
pub struct MemoryClaimStore {
    records: Arc<Mutex<BTreeMap<String, ClaimRecord>>>,
}

impl ClaimStore for MemoryClaimStore {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        let Ok(mut records) = self.records.lock() else {
            return ClaimResult::Unavailable;
        };
        if let Some(record) = records.get(workflow_id) {
            return if &record.action_digest == action_digest {
                ClaimResult::Replay(record.clone())
            } else {
                ClaimResult::Conflict(record.clone())
            };
        }
        records.insert(
            workflow_id.into(),
            ClaimRecord {
                workflow_id: workflow_id.into(),
                action_digest: action_digest.clone(),
                stage: ClaimStage::Claimed,
                claimed_at: now,
                updated_at: now,
            },
        );
        ClaimResult::Claimed(ClaimLease {
            workflow_id: workflow_id.into(),
            action_digest: action_digest.clone(),
        })
    }

    fn record_stage(
        &self,
        lease: &ClaimLease,
        stage: ClaimStage,
        now: u64,
    ) -> Result<ClaimRecord, ClaimError> {
        let mut records = self.records.lock().map_err(|_| ClaimError::Unavailable)?;
        let record = records
            .get_mut(&lease.workflow_id)
            .ok_or(ClaimError::LeaseMismatch)?;
        if record.action_digest != lease.action_digest {
            return Err(ClaimError::LeaseMismatch);
        }
        record.stage = stage;
        record.updated_at = now;
        Ok(record.clone())
    }
}

/// Crash-persistent single-process claim store.
///
/// The complete bounded map is written to a temporary file, synced, and
/// atomically renamed before the in-memory view advances.
pub struct PersistentClaimStore {
    path: PathBuf,
    records: Mutex<BTreeMap<String, ClaimRecord>>,
}

impl PersistentClaimStore {
    /// Opens a canonical claim file or creates an empty store.
    ///
    /// # Errors
    ///
    /// Rejects unreadable, malformed, non-canonical, or oversized state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, ClaimError> {
        let path = path.into();
        let records = if path.exists() {
            let bytes = fs::read(&path).map_err(|_| ClaimError::Unavailable)?;
            if bytes.len() > MAX_STATE_BYTES {
                return Err(ClaimError::Corrupt);
            }
            let records: BTreeMap<String, ClaimRecord> =
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
        operation: impl FnOnce(&mut BTreeMap<String, ClaimRecord>) -> Result<T, ClaimError>,
    ) -> Result<T, ClaimError> {
        let mut records = self.records.lock().map_err(|_| ClaimError::Unavailable)?;
        let mut candidate = records.clone();
        let output = operation(&mut candidate)?;
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
        Ok(output)
    }
}

impl ClaimStore for PersistentClaimStore {
    fn claim(&self, workflow_id: &str, action_digest: &DigestHex, now: u64) -> ClaimResult {
        self.mutate(|records| Ok(claim_in(records, workflow_id, action_digest, now)))
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
}

fn claim_in(
    records: &mut BTreeMap<String, ClaimRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    now: u64,
) -> ClaimResult {
    if workflow_id.is_empty() || workflow_id.len() > 256 {
        return ClaimResult::Unavailable;
    }
    if let Some(record) = records.get(workflow_id) {
        return if &record.action_digest == action_digest {
            ClaimResult::Replay(record.clone())
        } else {
            ClaimResult::Conflict(record.clone())
        };
    }
    records.insert(
        workflow_id.into(),
        ClaimRecord {
            workflow_id: workflow_id.into(),
            action_digest: action_digest.clone(),
            stage: ClaimStage::Claimed,
            claimed_at: now,
            updated_at: now,
        },
    );
    ClaimResult::Claimed(ClaimLease {
        workflow_id: workflow_id.into(),
        action_digest: action_digest.clone(),
    })
}

fn record_stage_in(
    records: &mut BTreeMap<String, ClaimRecord>,
    lease: &ClaimLease,
    stage: ClaimStage,
    now: u64,
) -> Result<ClaimRecord, ClaimError> {
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(ClaimError::LeaseMismatch)?;
    if record.action_digest != lease.action_digest || now < record.updated_at {
        return Err(ClaimError::LeaseMismatch);
    }
    record.stage = stage;
    record.updated_at = now;
    Ok(record.clone())
}

/// Closed claim failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ClaimError {
    #[error("Kubernetes claim store is unavailable")]
    Unavailable,
    #[error("Kubernetes claim lease does not match durable state")]
    LeaseMismatch,
    #[error("Kubernetes claim state is corrupt")]
    Corrupt,
}

#[cfg(test)]
mod tests {
    use std::{sync::Barrier, thread};

    use super::*;
    use crate::canonical::sha256;

    #[test]
    fn concurrent_claims_have_exactly_one_winner() {
        let store = MemoryClaimStore::default();
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let store = store.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                matches!(
                    store.claim("workflow", &sha256(b"action"), 10),
                    ClaimResult::Claimed(_)
                )
            }));
        }
        barrier.wait();
        let winners = handles
            .into_iter()
            .filter_map(|handle| handle.join().ok())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
    }

    #[test]
    fn persistent_claim_survives_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("claims.json");
        let digest = sha256(b"action");
        let ClaimResult::Claimed(lease) = PersistentClaimStore::open(&path)
            .unwrap()
            .claim("workflow", &digest, 10)
        else {
            panic!("first claimant must win");
        };
        let store = PersistentClaimStore::open(&path).unwrap();
        assert!(matches!(
            store.claim("workflow", &digest, 11),
            ClaimResult::Replay(_)
        ));
        assert_eq!(
            store
                .record_stage(&lease, ClaimStage::ApiAccepted, 12)
                .unwrap()
                .stage,
            ClaimStage::ApiAccepted
        );
    }
}
