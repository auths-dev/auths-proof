//! Single-host durable one-use claims. This store does not infer provider effect.

use crate::{ClosedProviderRequest, LogicalOperationId, OperatorNamespace};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
};
use tempfile::NamedTempFile;
use thiserror::Error;

const SCHEMA: &str = "auths.gateway-attempt/1";
const MAX_RECORD_BYTES: usize = 2_048;

/// Conservative gateway attempt stages; a response is not effect evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayAttemptStage {
    /// Transport entry was durably excluded after a claim.
    NotEntered,
    /// Transport may have started; restart projects this to `Unknown`.
    Attempting,
    /// A complete bounded HTTP response was durably recorded.
    ResponseRecorded,
    /// Entry or effect is ambiguous; no automatic retry.
    Unknown,
    /// A separate read-only comparison completed; match is not causation.
    Observed,
}

/// Secret-free persisted evidence for one logical operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayAttemptSnapshot {
    namespace: OperatorNamespace,
    operation_id: LogicalOperationId,
    action_commitment: [u8; 32],
    recipe_digest: [u8; 32],
    stage: GatewayAttemptStage,
    response_status: Option<u16>,
    observation_match: Option<bool>,
}

impl GatewayAttemptSnapshot {
    /// Returns the operator namespace.
    #[must_use]
    pub const fn namespace(&self) -> &OperatorNamespace {
        &self.namespace
    }
    /// Returns the stable operation ID.
    #[must_use]
    pub const fn operation_id(&self) -> &LogicalOperationId {
        &self.operation_id
    }
    /// Returns the exact action commitment.
    #[must_use]
    pub const fn action_commitment(&self) -> &[u8; 32] {
        &self.action_commitment
    }
    /// Returns the installed recipe digest.
    #[must_use]
    pub const fn recipe_digest(&self) -> &[u8; 32] {
        &self.recipe_digest
    }
    /// Returns the conservative stage.
    #[must_use]
    pub const fn stage(&self) -> GatewayAttemptStage {
        self.stage
    }
    /// Returns the HTTP status only after a complete response.
    #[must_use]
    pub const fn response_status(&self) -> Option<u16> {
        self.response_status
    }
    /// Returns read-back equality, never exclusive causation.
    #[must_use]
    pub const fn observation_match(&self) -> Option<bool> {
        self.observation_match
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    schema: String,
    namespace: String,
    operation_id: String,
    action_commitment: String,
    recipe_digest: String,
    nonce: String,
    stage: GatewayAttemptStage,
    response_status: Option<u16>,
    response_digest: Option<String>,
    observation_match: Option<bool>,
}

impl Record {
    fn snapshot(&self, recovered: bool) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        if self.schema != SCHEMA
            || self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        let namespace =
            OperatorNamespace::parse(&self.namespace).map_err(|_| GatewayAttemptError::Corrupt)?;
        let operation_id = LogicalOperationId::parse(&self.operation_id)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        let action_commitment = digest_bytes(&self.action_commitment)?;
        let recipe_digest = digest_bytes(&self.recipe_digest)?;
        let has_response = self.response_status.is_some() && self.response_digest.is_some();
        if self.response_status.is_some() != self.response_digest.is_some()
            || has_response
                != matches!(
                    self.stage,
                    GatewayAttemptStage::ResponseRecorded | GatewayAttemptStage::Observed
                )
            || (self.stage == GatewayAttemptStage::Observed) != self.observation_match.is_some()
            || self
                .response_digest
                .as_deref()
                .is_some_and(|value| digest_bytes(value).is_err())
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(GatewayAttemptSnapshot {
            namespace,
            operation_id,
            action_commitment,
            recipe_digest,
            stage: if recovered && self.stage == GatewayAttemptStage::Attempting {
                GatewayAttemptStage::Unknown
            } else {
                self.stage
            },
            response_status: self.response_status,
            observation_match: self.observation_match,
        })
    }
}

fn digest_bytes(value: &str) -> Result<[u8; 32], GatewayAttemptError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GatewayAttemptError::Corrupt);
    }
    let mut bytes = [0_u8; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    Ok(bytes)
}

/// Closed durable claim errors. A replay never licenses another provider entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayAttemptError {
    /// A logical ID was already claimed, regardless of proof challenge or body.
    #[error("logical operation already claimed")]
    Replay,
    /// The state directory is not a private, normalized local directory.
    #[error("unsafe attempt directory")]
    UnsafeDirectory,
    /// Existing state is incomplete or contradictory; fail closed.
    #[error("corrupt attempt record")]
    Corrupt,
    /// Storage or synchronization failed; an in-flight effect may be unknown.
    #[error("attempt store unavailable")]
    Unavailable,
    /// A claimed attempt attempted an invalid transition.
    #[error("invalid attempt transition")]
    InvalidTransition,
}

/// Atomic file claim store for one host. This is not a multi-host claim store
/// and does not establish credential isolation by itself.
pub struct FileGatewayAttemptStore {
    root: PathBuf,
}

impl FileGatewayAttemptStore {
    /// Opens or creates an owner-private directory, retaining all prior claims.
    ///
    /// # Errors
    /// Rejects symlinks, broad permissions, foreign ownership, and I/O errors.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, GatewayAttemptError> {
        let root = root.into();
        if !root.is_absolute()
            || root
                .components()
                .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
        {
            return Err(GatewayAttemptError::UnsafeDirectory);
        }
        if !root.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&root)
                    .map_err(|_| GatewayAttemptError::Unavailable)?;
            }
            #[cfg(not(unix))]
            return Err(GatewayAttemptError::UnsafeDirectory);
        }
        let metadata = fs::symlink_metadata(&root).map_err(|_| GatewayAttemptError::Unavailable)?;
        if !metadata.file_type().is_dir()
            || fs::canonicalize(&root).map_err(|_| GatewayAttemptError::Unavailable)? != root
        {
            return Err(GatewayAttemptError::UnsafeDirectory);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
            if metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != rustix::process::geteuid().as_raw()
            {
                return Err(GatewayAttemptError::UnsafeDirectory);
            }
        }
        Ok(Self { root })
    }

    /// Claims one logical ID before credential access or transport entry.
    ///
    /// # Errors
    /// An existing file, including a partial crashed claim, is `Replay`.
    pub fn claim(
        &self,
        request: &ClosedProviderRequest,
        action_commitment: [u8; 32],
        recipe_digest: [u8; 32],
    ) -> Result<ClaimedGatewayAttempt, GatewayAttemptError> {
        let path = self.path_for(request.namespace(), request.operation_id());
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| GatewayAttemptError::Unavailable)?;
        let record = Record {
            schema: SCHEMA.to_owned(),
            namespace: request.namespace().as_str().to_owned(),
            operation_id: request.operation_id().as_str().to_owned(),
            action_commitment: hex::encode(action_commitment),
            recipe_digest: hex::encode(recipe_digest),
            nonce: hex::encode(nonce),
            stage: GatewayAttemptStage::Attempting,
            response_status: None,
            response_digest: None,
            observation_match: None,
        };
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(GatewayAttemptError::Replay);
            }
            Err(_) => return Err(GatewayAttemptError::Unavailable),
        };
        file.write_all(&encode(&record)?)
            .and_then(|()| file.sync_all())
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)?;
        Ok(ClaimedGatewayAttempt {
            root: self.root.clone(),
            path,
            record,
        })
    }

    /// Reads a secret-free durable snapshot. A prior `attempting` stage is
    /// conservatively projected as `unknown` after restart.
    ///
    /// # Errors
    /// Malformed state is a hard failure, not an unclaimed slot.
    pub fn read(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Option<GatewayAttemptSnapshot>, GatewayAttemptError> {
        let path = self.path_for(namespace, operation_id);
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GatewayAttemptError::Unavailable),
        };
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        let record: Record =
            serde_json::from_slice(&bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
        if record.namespace != namespace.as_str() || record.operation_id != operation_id.as_str() {
            return Err(GatewayAttemptError::Corrupt);
        }
        record.snapshot(true).map(Some)
    }

    fn path_for(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> PathBuf {
        let mut hash = Sha256::new();
        hash.update(b"auths.gateway-logical-operation/1\0");
        hash.update(namespace.as_str().as_bytes());
        hash.update([0]);
        hash.update(operation_id.as_str().as_bytes());
        self.root
            .join(format!("claim-{}.json", hex::encode(hash.finalize())))
    }
}

/// A durable claim token; dropping it without a result leaves `unknown` on
/// restart and never permits another automatic write.
pub struct ClaimedGatewayAttempt {
    root: PathBuf,
    path: PathBuf,
    record: Record,
}

impl ClaimedGatewayAttempt {
    /// Records definite pre-entry exclusion while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub fn record_not_entered(mut self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.record.stage = GatewayAttemptStage::NotEntered;
        replace(&self.root, &self.path, &self.record)?;
        self.record.snapshot(false)
    }

    /// Records an ambiguous outcome while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub fn record_unknown(mut self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.record.stage = GatewayAttemptStage::Unknown;
        replace(&self.root, &self.path, &self.record)?;
        self.record.snapshot(false)
    }

    /// Records a complete bounded HTTP response, never effect success.
    ///
    /// # Errors
    /// Rejects invalid status and persistence failure.
    pub fn record_response(
        mut self,
        status: u16,
        digest: [u8; 32],
    ) -> Result<ResponseRecordedGatewayAttempt, GatewayAttemptError> {
        if !(100..=599).contains(&status) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        self.record.stage = GatewayAttemptStage::ResponseRecorded;
        self.record.response_status = Some(status);
        self.record.response_digest = Some(hex::encode(digest));
        replace(&self.root, &self.path, &self.record)?;
        Ok(ResponseRecordedGatewayAttempt {
            root: self.root,
            path: self.path,
            record: self.record,
        })
    }
}

/// Complete response token that may be promoted only by a separate read-back.
pub struct ResponseRecordedGatewayAttempt {
    root: PathBuf,
    path: PathBuf,
    record: Record,
}

impl ResponseRecordedGatewayAttempt {
    /// Returns response evidence without asserting effect.
    ///
    /// # Errors
    /// Rejects contradictory state.
    pub fn snapshot(&self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.record.snapshot(false)
    }

    /// Records read-back equality; a match does not prove this write caused it.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    pub fn record_observation(
        mut self,
        matched: bool,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.record.stage = GatewayAttemptStage::Observed;
        self.record.observation_match = Some(matched);
        replace(&self.root, &self.path, &self.record)?;
        self.record.snapshot(false)
    }
}

fn encode(record: &Record) -> Result<Vec<u8>, GatewayAttemptError> {
    let bytes = serde_json::to_vec(record).map_err(|_| GatewayAttemptError::Corrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(bytes)
}

fn replace(root: &Path, path: &Path, record: &Record) -> Result<(), GatewayAttemptError> {
    let bytes = fs::read(path).map_err(|_| GatewayAttemptError::Unavailable)?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    let old: Record = serde_json::from_slice(&bytes).map_err(|_| GatewayAttemptError::Corrupt)?;
    if old.nonce != record.nonce
        || old.namespace != record.namespace
        || old.operation_id != record.operation_id
        || old.action_commitment != record.action_commitment
        || old.recipe_digest != record.recipe_digest
        || !matches!(
            (old.stage, record.stage),
            (
                GatewayAttemptStage::Attempting,
                GatewayAttemptStage::NotEntered
            ) | (
                GatewayAttemptStage::Attempting,
                GatewayAttemptStage::Unknown
            ) | (
                GatewayAttemptStage::Attempting,
                GatewayAttemptStage::ResponseRecorded
            ) | (
                GatewayAttemptStage::ResponseRecorded,
                GatewayAttemptStage::Observed
            )
        )
    {
        return Err(GatewayAttemptError::InvalidTransition);
    }
    let mut pending = NamedTempFile::new_in(root).map_err(|_| GatewayAttemptError::Unavailable)?;
    pending
        .write_all(&encode(record)?)
        .and_then(|()| pending.as_file().sync_all())
        .map_err(|_| GatewayAttemptError::Unavailable)?;
    pending
        .persist(path)
        .map_err(|_| GatewayAttemptError::Unavailable)?;
    sync_directory(root)
}

fn sync_directory(root: &Path) -> Result<(), GatewayAttemptError> {
    #[cfg(unix)]
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| GatewayAttemptError::Unavailable)?;
    #[cfg(not(unix))]
    let _ = root;
    Ok(())
}
