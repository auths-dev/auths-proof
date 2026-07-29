//! Reusable in-memory adapters and the Auths SDK bridge.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_sdk::{RequestContext, Verifier, VerifyResult};
use tempfile::NamedTempFile;

use crate::{
    errors::PortError,
    ports::{
        Clock, PlanArtifactStore, ProofDecision, ProofVerifier, ReceiptSink, SavedPlanArtifact,
    },
    profile::OpenTofuSavedPlanProfile,
    receipts::OpenTofuReceipt,
    types::PlanHandle,
};

/// Auths SDK adapter fixed to the saved-plan profile.
pub struct SdkProofVerifier {
    verifier: Verifier,
}

impl SdkProofVerifier {
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl ProofVerifier for SdkProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &OpenTofuSavedPlanProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => Ok(ProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => Ok(ProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => Ok(ProofDecision::Indeterminate {
                code: explanation.code().into(),
            }),
        }
    }
}

/// Trusted system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| PortError::InvalidConfiguration)
    }
}

/// Fixed trusted clock for deterministic tests.
#[derive(Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now(&self) -> Result<u64, PortError> {
        Ok(self.0)
    }
}

/// Bounded process-local protected plan store.
#[derive(Clone, Default)]
pub struct MemoryPlanArtifactStore {
    artifacts: Arc<Mutex<BTreeMap<PlanHandle, Vec<u8>>>>,
}

impl PlanArtifactStore for MemoryPlanArtifactStore {
    fn put(&self, artifact: SavedPlanArtifact) -> Result<PlanHandle, PortError> {
        let digest = crate::canonical::sha256(artifact.bytes());
        let handle = PlanHandle::parse(digest.as_str()[..32].to_owned())
            .map_err(|_| PortError::Persistence)?;
        let mut artifacts = self.artifacts.lock().map_err(|_| PortError::Persistence)?;
        if let Some(existing) = artifacts.get(&handle) {
            if existing != artifact.bytes() {
                return Err(PortError::Persistence);
            }
        } else {
            artifacts.insert(handle.clone(), artifact.bytes().to_vec());
        }
        Ok(handle)
    }

    fn resolve(&self, handle: &PlanHandle) -> Result<SavedPlanArtifact, PortError> {
        let bytes = self
            .artifacts
            .lock()
            .map_err(|_| PortError::Persistence)?
            .get(handle)
            .cloned()
            .ok_or(PortError::ArtifactUnavailable)?;
        SavedPlanArtifact::new(bytes)
    }
}

/// Crash-persistent protected plan store using content-derived opaque handles.
pub struct PersistentPlanArtifactStore {
    directory: PathBuf,
    lock: Mutex<()>,
}

impl PersistentPlanArtifactStore {
    pub fn open(directory: impl Into<PathBuf>) -> Result<Self, PortError> {
        let directory = directory.into();
        fs::create_dir_all(&directory).map_err(|_| PortError::Persistence)?;
        if !directory.is_dir() {
            return Err(PortError::Persistence);
        }
        Ok(Self {
            directory,
            lock: Mutex::new(()),
        })
    }

    fn path(&self, handle: &PlanHandle) -> Result<PathBuf, PortError> {
        let path = self.directory.join(handle.as_str());
        if path.parent() != Some(self.directory.as_path()) {
            return Err(PortError::Persistence);
        }
        Ok(path)
    }
}

impl PlanArtifactStore for PersistentPlanArtifactStore {
    fn put(&self, artifact: SavedPlanArtifact) -> Result<PlanHandle, PortError> {
        let digest = crate::canonical::sha256(artifact.bytes());
        let handle = PlanHandle::parse(digest.as_str()[..32].to_owned())
            .map_err(|_| PortError::Persistence)?;
        let path = self.path(&handle)?;
        let _guard = self.lock.lock().map_err(|_| PortError::Persistence)?;
        if path.exists() {
            let existing = read_artifact(&path)?;
            if existing != artifact.bytes() {
                return Err(PortError::Persistence);
            }
            return Ok(handle);
        }
        let mut temporary =
            NamedTempFile::new_in(&self.directory).map_err(|_| PortError::Persistence)?;
        temporary
            .write_all(artifact.bytes())
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| PortError::Persistence)?;
        temporary
            .persist(&path)
            .map_err(|_| PortError::Persistence)?;
        Ok(handle)
    }

    fn resolve(&self, handle: &PlanHandle) -> Result<SavedPlanArtifact, PortError> {
        let bytes = read_artifact(&self.path(handle)?)?;
        let digest = crate::canonical::sha256(&bytes);
        if &digest.as_str()[..32] != handle.as_str() {
            return Err(PortError::ArtifactMismatch);
        }
        SavedPlanArtifact::new(bytes)
    }
}

fn read_artifact(path: &Path) -> Result<Vec<u8>, PortError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| PortError::ArtifactUnavailable)?;
    if !metadata.file_type().is_file() || metadata.len() > 256 * 1024 * 1024 {
        return Err(PortError::ArtifactUnavailable);
    }
    fs::read(path).map_err(|_| PortError::ArtifactUnavailable)
}

/// Append-only memory receipt sink.
#[derive(Clone, Default)]
pub struct MemoryReceiptSink {
    receipts: Arc<Mutex<Vec<OpenTofuReceipt>>>,
}

impl MemoryReceiptSink {
    #[must_use]
    pub fn receipts(&self) -> Vec<OpenTofuReceipt> {
        self.receipts
            .lock()
            .map_or_else(|_| Vec::new(), |receipts| receipts.clone())
    }
}

impl ReceiptSink for MemoryReceiptSink {
    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), PortError> {
        self.receipts
            .lock()
            .map_err(|_| PortError::Persistence)?
            .push(receipt.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_plan_store_rejects_tampered_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let store = PersistentPlanArtifactStore::open(directory.path()).unwrap();
        let handle = store
            .put(SavedPlanArtifact::new(b"authorized-plan".to_vec()).unwrap())
            .unwrap();
        assert_eq!(store.resolve(&handle).unwrap().bytes(), b"authorized-plan");

        fs::write(directory.path().join(handle.as_str()), b"substituted").unwrap();
        assert!(matches!(
            store.resolve(&handle),
            Err(PortError::ArtifactMismatch)
        ));
    }
}
