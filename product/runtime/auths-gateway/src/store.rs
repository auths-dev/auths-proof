//! Durable one-use gateway attempt claims. This store does not infer provider
//! effect.
//!
//! [`GatewayAttempts`] owns the record format, its stages, and which stage
//! changes are valid. It persists through a [`GatewayAttemptStore`], which is
//! only an insert-once and compare-and-swap mechanism over opaque bounded
//! bytes: [`FileGatewayAttemptStore`] for one host, and the qualified
//! multi-host `PostgresLifecycleStore`.

use crate::{ClosedProviderRequest, LogicalOperationId, OperatorNamespace, echo_token};
use auths_lifecycle::StoreError;
use auths_stores::{GatewayAttemptInsert, PostgresLifecycleStore};
use base64ct::{Base64, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use tempfile::NamedTempFile;
use thiserror::Error;

const SCHEMA: &str = "auths.gateway-attempt/2";
const MAX_RECORD_BYTES: usize = auths_stores::MAX_GATEWAY_ATTEMPT_BYTES;
const MAX_EVIDENCE_BYTES: usize = 65_536;
const MAX_LOCATOR_BYTES: usize = 9_216;
const MAX_EXPECTED_BYTES: usize = 8_192;

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
    /// A read-back returned exactly this attempt's echo token and the verified
    /// value. The link to the authorization holds only while no other party
    /// with write access to that provider field wrote the same token.
    ObservedByProvider,
}

/// Additional secret-free fact recorded with an `observed` stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayObservationFact {
    /// The echo field held a token other than this attempt's. Another writer
    /// changed it, or this write never applied; the gateway does not guess.
    EchoMismatch,
}

/// How provider-held evidence was obtained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GatewayEvidenceChannel {
    /// A bounded read-only GET over the pinned origin with the gateway credential.
    ReadBack,
}

/// Secret-free provider evidence kept for every `observed-by-provider` stage.
/// The bytes inherit the provider data's sensitivity and must not be logged;
/// `Debug` reports only their length.
#[derive(Clone, Eq, PartialEq)]
pub struct GatewayProviderEvidence {
    channel: GatewayEvidenceChannel,
    locator: String,
    echo: String,
    evidence_digest: [u8; 32],
    evidence: Vec<u8>,
    observed_at: u64,
}

impl GatewayProviderEvidence {
    /// Returns the evidence channel.
    #[must_use]
    pub const fn channel(&self) -> GatewayEvidenceChannel {
        self.channel
    }
    /// Returns the observation URL, built only from verified fields.
    #[must_use]
    pub fn locator(&self) -> &str {
        &self.locator
    }
    /// Returns the echo token found in the provider record.
    #[must_use]
    pub fn echo(&self) -> &str {
        &self.echo
    }
    /// Returns SHA-256 of the exact observation response bytes.
    #[must_use]
    pub const fn evidence_digest(&self) -> &[u8; 32] {
        &self.evidence_digest
    }
    /// Returns the bounded observation response bytes.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }
    /// Returns gateway wall-clock seconds; this time is not authenticated.
    #[must_use]
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }
}

impl std::fmt::Debug for GatewayProviderEvidence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayProviderEvidence")
            .field("channel", &self.channel)
            .field("locator", &self.locator)
            .field("echo", &self.echo)
            .field("evidence_digest", &hex::encode(self.evidence_digest))
            .field("evidence_bytes", &self.evidence.len())
            .field("observed_at", &self.observed_at)
            .finish()
    }
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
    observation_fact: Option<GatewayObservationFact>,
    provider_evidence: Option<GatewayProviderEvidence>,
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
    /// Returns an additional fact recorded with the observation.
    #[must_use]
    pub const fn observation_fact(&self) -> Option<GatewayObservationFact> {
        self.observation_fact
    }
    /// Returns provider-held evidence for `observed-by-provider` only.
    #[must_use]
    pub const fn provider_evidence(&self) -> Option<&GatewayProviderEvidence> {
        self.provider_evidence.as_ref()
    }
}

/// Observation target fixed at claim time from verified fields, so a later
/// read-back never depends on a different submission's fields.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ObservationPlan {
    locator: String,
    expected: String,
    echo: bool,
}

impl ObservationPlan {
    fn from_request(request: &ClosedProviderRequest) -> Result<Option<Self>, GatewayAttemptError> {
        request
            .observation()
            .map(|observation| {
                Ok(Self {
                    locator: observation.url().to_owned(),
                    expected: canonical_expected(observation.expected())?,
                    echo: observation.echo_pointer().is_some() && request.echo_token().is_some(),
                })
            })
            .transpose()
    }

    fn valid(&self) -> bool {
        !self.locator.is_empty()
            && self.locator.len() <= MAX_LOCATOR_BYTES
            && !self.expected.is_empty()
            && self.expected.len() <= MAX_EXPECTED_BYTES
    }
}

fn canonical_expected(value: &serde_json::Value) -> Result<String, GatewayAttemptError> {
    let bytes =
        serde_json_canonicalizer::to_vec(value).map_err(|_| GatewayAttemptError::Corrupt)?;
    String::from_utf8(bytes).map_err(|_| GatewayAttemptError::Corrupt)
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceWire {
    channel: GatewayEvidenceChannel,
    locator: String,
    echo: String,
    evidence_digest: String,
    evidence_b64: String,
    observed_at: u64,
}

impl EvidenceWire {
    fn decode(
        &self,
        plan: &ObservationPlan,
        expected_echo: &str,
    ) -> Result<GatewayProviderEvidence, GatewayAttemptError> {
        let evidence_digest = digest_bytes(&self.evidence_digest)?;
        let evidence =
            Base64::decode_vec(&self.evidence_b64).map_err(|_| GatewayAttemptError::Corrupt)?;
        if self.locator != plan.locator
            || self.echo != expected_echo
            || evidence.is_empty()
            || evidence.len() > MAX_EVIDENCE_BYTES
            || <[u8; 32]>::from(Sha256::digest(&evidence)) != evidence_digest
        {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(GatewayProviderEvidence {
            channel: self.channel,
            locator: self.locator.clone(),
            echo: self.echo.clone(),
            evidence_digest,
            evidence,
            observed_at: self.observed_at,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
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
    observation_plan: Option<ObservationPlan>,
    observation_fact: Option<GatewayObservationFact>,
    provider_evidence: Option<EvidenceWire>,
}

impl Record {
    fn echo_token(&self) -> Result<String, GatewayAttemptError> {
        let namespace =
            OperatorNamespace::parse(&self.namespace).map_err(|_| GatewayAttemptError::Corrupt)?;
        let operation_id = LogicalOperationId::parse(&self.operation_id)
            .map_err(|_| GatewayAttemptError::Corrupt)?;
        Ok(echo_token(
            &namespace,
            &operation_id,
            &digest_bytes(&self.action_commitment)?,
        ))
    }

    fn stage_fields_consistent(&self) -> bool {
        let has_response = self.response_status.is_some();
        let requires_response = matches!(
            self.stage,
            GatewayAttemptStage::ResponseRecorded | GatewayAttemptStage::Observed
        );
        let by_provider = self.stage == GatewayAttemptStage::ObservedByProvider;
        has_response == self.response_digest.is_some()
            && (!requires_response || has_response)
            && (!has_response || requires_response || by_provider)
            && (self.stage == GatewayAttemptStage::Observed) == self.observation_match.is_some()
            && (self.observation_fact.is_none() || self.observation_match == Some(false))
            && by_provider == self.provider_evidence.is_some()
            && (!by_provider || self.observation_plan.as_ref().is_some_and(|plan| plan.echo))
            && self
                .observation_plan
                .as_ref()
                .is_none_or(ObservationPlan::valid)
            && self
                .response_digest
                .as_deref()
                .is_none_or(|value| digest_bytes(value).is_ok())
    }

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
        if !self.stage_fields_consistent() {
            return Err(GatewayAttemptError::Corrupt);
        }
        let provider_evidence = match (&self.provider_evidence, &self.observation_plan) {
            (Some(wire), Some(plan)) => Some(wire.decode(plan, &self.echo_token()?)?),
            (Some(_), None) => return Err(GatewayAttemptError::Corrupt),
            (None, _) => None,
        };
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
            observation_fact: self.observation_fact,
            provider_evidence,
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
    /// Another gateway process advanced this attempt first; nothing was
    /// recorded by this caller.
    #[error("attempt advanced concurrently")]
    Conflict,
}

/// Storage key of one logical operation in one operator namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayAttemptKey([u8; 32]);

impl GatewayAttemptKey {
    /// Derives the key of `operation_id` in `namespace`.
    #[must_use]
    pub fn for_operation(namespace: &OperatorNamespace, operation_id: &LogicalOperationId) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"auths.gateway-logical-operation/1\0");
        hash.update(namespace.as_str().as_bytes());
        hash.update([0]);
        hash.update(operation_id.as_str().as_bytes());
        Self(hash.finalize().into())
    }

    /// Returns the key bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Durable insert-once and compare-and-swap storage of opaque attempt
/// records. Implementations never interpret the bytes.
///
/// Every implementation must pass the same conformance suite: one winner per
/// key across processes, no lost replacement, and fail-closed reads.
pub trait GatewayAttemptStore: Send + Sync {
    /// Stores `record` under `key` only when the key has never been stored.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Replay`] when the key already exists,
    /// including a record left by a crashed claim.
    fn insert(&self, key: &GatewayAttemptKey, record: &[u8]) -> Result<(), GatewayAttemptError>;

    /// Loads the record stored under `key`.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Corrupt`] for unreadable or oversized
    /// state; it is never reported as an unclaimed key.
    fn load(&self, key: &GatewayAttemptKey) -> Result<Option<Vec<u8>>, GatewayAttemptError>;

    /// Replaces the record under `key` with `next` only while it still
    /// holds exactly `current`.
    ///
    /// # Errors
    /// Returns [`GatewayAttemptError::Conflict`] when another writer replaced
    /// it first.
    fn replace(
        &self,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError>;
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

    fn path_for(&self, key: &GatewayAttemptKey) -> PathBuf {
        self.root
            .join(format!("claim-{}.json", hex::encode(key.as_bytes())))
    }

    fn read_path(path: &Path) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(GatewayAttemptError::Unavailable),
        };
        if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(Some(bytes))
    }

    fn pending(&self, record: &[u8]) -> Result<NamedTempFile, GatewayAttemptError> {
        let mut pending =
            NamedTempFile::new_in(&self.root).map_err(|_| GatewayAttemptError::Unavailable)?;
        pending
            .write_all(record)
            .and_then(|()| pending.as_file().sync_all())
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        Ok(pending)
    }

    /// Serializes replacements across every process on this host.
    fn exclusive(&self) -> Result<File, GatewayAttemptError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let lock = options
            .open(self.root.join(".replace.lock"))
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        Ok(lock)
    }
}

impl GatewayAttemptStore for FileGatewayAttemptStore {
    fn insert(&self, key: &GatewayAttemptKey, record: &[u8]) -> Result<(), GatewayAttemptError> {
        if record.is_empty() || record.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        match self.pending(record)?.persist_noclobber(self.path_for(key)) {
            Ok(_) => sync_directory(&self.root),
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(GatewayAttemptError::Replay)
            }
            Err(_) => Err(GatewayAttemptError::Unavailable),
        }
    }

    fn load(&self, key: &GatewayAttemptKey) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        Self::read_path(&self.path_for(key))
    }

    fn replace(
        &self,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        if next.is_empty() || next.len() > MAX_RECORD_BYTES {
            return Err(GatewayAttemptError::Corrupt);
        }
        let path = self.path_for(key);
        let _lock = self.exclusive()?;
        if Self::read_path(&path)?.as_deref() != Some(current) {
            return Err(GatewayAttemptError::Conflict);
        }
        self.pending(next)?
            .persist(&path)
            .map_err(|_| GatewayAttemptError::Unavailable)?;
        sync_directory(&self.root)
    }
}

/// The qualified multi-host store: attempts live in the lifecycle database
/// under the same TLS, pooling, and schema contract as lifecycle records.
///
/// The pooled client blocks on its own runtime, so it is connected, used,
/// and dropped only off the async executor.
pub struct PostgresGatewayAttemptStore {
    store: Option<Arc<PostgresLifecycleStore>>,
}

impl PostgresGatewayAttemptStore {
    /// Uses an already connected lifecycle store, which may be shared with
    /// lifecycle work in the same process.
    #[must_use]
    pub const fn new(store: Arc<PostgresLifecycleStore>) -> Self {
        Self { store: Some(store) }
    }

    fn store(&self) -> Result<&PostgresLifecycleStore, GatewayAttemptError> {
        self.store
            .as_deref()
            .ok_or(GatewayAttemptError::Unavailable)
    }
}

impl Drop for PostgresGatewayAttemptStore {
    fn drop(&mut self) {
        if let Some(store) = self.store.take() {
            let _ = std::thread::spawn(move || drop(store)).join();
        }
    }
}

impl GatewayAttemptStore for PostgresGatewayAttemptStore {
    fn insert(&self, key: &GatewayAttemptKey, record: &[u8]) -> Result<(), GatewayAttemptError> {
        match self.store()?.insert_gateway_attempt(key.as_bytes(), record) {
            Ok(GatewayAttemptInsert::Inserted) => Ok(()),
            Ok(GatewayAttemptInsert::Exists) => Err(GatewayAttemptError::Replay),
            Err(error) => Err(postgres_error(error)),
        }
    }

    fn load(&self, key: &GatewayAttemptKey) -> Result<Option<Vec<u8>>, GatewayAttemptError> {
        self.store()?
            .load_gateway_attempt(key.as_bytes())
            .map_err(postgres_error)
    }

    fn replace(
        &self,
        key: &GatewayAttemptKey,
        current: &[u8],
        next: &[u8],
    ) -> Result<(), GatewayAttemptError> {
        self.store()?
            .replace_gateway_attempt(key.as_bytes(), current, next)
            .map_err(postgres_error)
    }
}

const fn postgres_error(error: StoreError) -> GatewayAttemptError {
    match error {
        StoreError::Conflict => GatewayAttemptError::Conflict,
        StoreError::Corrupt
        | StoreError::LimitExceeded
        | StoreError::SchemaMismatch
        | StoreError::InvalidAcknowledgement
        | StoreError::Rejected(_) => GatewayAttemptError::Corrupt,
        StoreError::Unavailable | StoreError::PoolExhausted | StoreError::Timeout => {
            GatewayAttemptError::Unavailable
        }
    }
}

/// Runs one blocking store operation off the async executor. The pooled
/// `PostgreSQL` client must never block an executor thread.
async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, GatewayAttemptError> + Send + 'static,
) -> Result<T, GatewayAttemptError> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|_| GatewayAttemptError::Unavailable)?
}

/// Gateway attempt semantics over one durable [`GatewayAttemptStore`].
#[derive(Clone)]
pub struct GatewayAttempts {
    store: Arc<dyn GatewayAttemptStore>,
}

impl GatewayAttempts {
    /// Uses `store` for every claim and stage change.
    #[must_use]
    pub fn new(store: Arc<dyn GatewayAttemptStore>) -> Self {
        Self { store }
    }

    /// Claims one logical ID before credential access or transport entry. The
    /// record keeps the request's verified action commitment and observation
    /// target; a later echo token is always derived from this record.
    ///
    /// # Errors
    /// An existing record, including a crashed claim, is `Replay`.
    pub async fn claim(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
    ) -> Result<ClaimedGatewayAttempt, GatewayAttemptError> {
        let key = GatewayAttemptKey::for_operation(request.namespace(), request.operation_id());
        let mut nonce = [0_u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| GatewayAttemptError::Unavailable)?;
        let record = Record {
            schema: SCHEMA.to_owned(),
            namespace: request.namespace().as_str().to_owned(),
            operation_id: request.operation_id().as_str().to_owned(),
            action_commitment: hex::encode(request.action_commitment()),
            recipe_digest: hex::encode(recipe_digest),
            nonce: hex::encode(nonce),
            stage: GatewayAttemptStage::Attempting,
            response_status: None,
            response_digest: None,
            observation_match: None,
            observation_plan: ObservationPlan::from_request(request)?,
            observation_fact: None,
            provider_evidence: None,
        };
        let stored = encode(&record)?;
        let store = Arc::clone(&self.store);
        let bytes = stored.clone();
        blocking(move || store.insert(&key, &bytes)).await?;
        Ok(ClaimedGatewayAttempt {
            attempt: Attempt {
                store: Arc::clone(&self.store),
                key,
                stored,
                record,
            },
        })
    }

    /// Reads a secret-free durable snapshot. An `attempting` stage is
    /// conservatively projected as `unknown`: another process may hold it, or
    /// it may have crashed.
    ///
    /// # Errors
    /// Malformed state is a hard failure, not an unclaimed slot.
    pub async fn read(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Option<GatewayAttemptSnapshot>, GatewayAttemptError> {
        self.load(namespace, operation_id)
            .await?
            .map(|(_, record)| record.snapshot(true))
            .transpose()
    }

    /// Reopens a persisted `unknown` or `response-recorded` attempt for one
    /// more read-only observation. It returns `None` unless the recipe declared
    /// an echo, the recipe digest is unchanged, and the new verified request
    /// names the same observation target and expected value stored at claim.
    /// An `attempting` record is not reopened: it cannot be told apart from
    /// an attempt still in flight in another process.
    ///
    /// # Errors
    /// Malformed state is a hard failure.
    pub async fn resume_observable(
        &self,
        request: &ClosedProviderRequest,
        recipe_digest: [u8; 32],
    ) -> Result<Option<ObservableGatewayAttempt>, GatewayAttemptError> {
        let Some((stored, record)) = self
            .load(request.namespace(), request.operation_id())
            .await?
        else {
            return Ok(None);
        };
        record.snapshot(false)?;
        let current = ObservationPlan::from_request(request)?;
        let resumable = matches!(
            record.stage,
            GatewayAttemptStage::Unknown | GatewayAttemptStage::ResponseRecorded
        ) && record.recipe_digest == hex::encode(recipe_digest)
            && record
                .observation_plan
                .as_ref()
                .is_some_and(|plan| plan.echo)
            && record.observation_plan == current;
        Ok(resumable.then(|| ObservableGatewayAttempt {
            attempt: Attempt {
                store: Arc::clone(&self.store),
                key: GatewayAttemptKey::for_operation(request.namespace(), request.operation_id()),
                stored,
                record,
            },
        }))
    }

    async fn load(
        &self,
        namespace: &OperatorNamespace,
        operation_id: &LogicalOperationId,
    ) -> Result<Option<(Vec<u8>, Record)>, GatewayAttemptError> {
        let key = GatewayAttemptKey::for_operation(namespace, operation_id);
        let store = Arc::clone(&self.store);
        let Some(bytes) = blocking(move || store.load(&key)).await? else {
            return Ok(None);
        };
        let record = decode(&bytes)?;
        if record.namespace != namespace.as_str() || record.operation_id != operation_id.as_str() {
            return Err(GatewayAttemptError::Corrupt);
        }
        Ok(Some((bytes, record)))
    }
}

/// One loaded or claimed attempt and the exact bytes it was read as.
struct Attempt {
    store: Arc<dyn GatewayAttemptStore>,
    key: GatewayAttemptKey,
    stored: Vec<u8>,
    record: Record,
}

impl Attempt {
    /// Persists `next` only as a valid stage change from the exact stored
    /// record; a concurrent change by another process is a conflict.
    async fn advance(mut self, next: Record) -> Result<Self, GatewayAttemptError> {
        if !valid_transition(&self.record, &next) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let bytes = encode(&next)?;
        let store = Arc::clone(&self.store);
        let key = self.key;
        let current = std::mem::take(&mut self.stored);
        let replacement = bytes.clone();
        blocking(move || store.replace(&key, &current, &replacement)).await?;
        self.stored = bytes;
        self.record = next;
        Ok(self)
    }
}

/// A durable claim token; dropping it without a result leaves `unknown` on
/// restart and never permits another automatic write.
pub struct ClaimedGatewayAttempt {
    attempt: Attempt,
}

impl ClaimedGatewayAttempt {
    /// Records definite pre-entry exclusion while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub async fn record_not_entered(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::NotEntered;
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records an ambiguous outcome while retaining replay history.
    ///
    /// # Errors
    /// Persistence failure does not permit a retry.
    pub async fn record_unknown(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Unknown;
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records a complete bounded HTTP response, never effect success.
    ///
    /// # Errors
    /// Rejects invalid status and persistence failure.
    pub async fn record_response(
        self,
        status: u16,
        digest: [u8; 32],
    ) -> Result<ObservableGatewayAttempt, GatewayAttemptError> {
        if !(100..=599).contains(&status) {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::ResponseRecorded;
        next.response_status = Some(status);
        next.response_digest = Some(hex::encode(digest));
        Ok(ObservableGatewayAttempt {
            attempt: self.attempt.advance(next).await?,
        })
    }
}

/// A `response-recorded` or `unknown` attempt that may be advanced only by a
/// separate read-only observation, never by another write.
pub struct ObservableGatewayAttempt {
    attempt: Attempt,
}

impl ObservableGatewayAttempt {
    /// Returns response evidence without asserting effect.
    ///
    /// # Errors
    /// Rejects contradictory state.
    pub fn snapshot(&self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        self.attempt.record.snapshot(false)
    }

    /// Returns this attempt's echo token, derived from the stored verified
    /// commitment, when the recipe declared an echo field.
    #[must_use]
    pub fn echo_token(&self) -> Option<String> {
        self.attempt
            .record
            .observation_plan
            .as_ref()
            .filter(|plan| plan.echo)
            .and_then(|_| self.attempt.record.echo_token().ok())
    }

    /// Records read-back equality; a match does not prove this write caused it.
    /// Only a `response-recorded` attempt can take this transition.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    pub async fn record_observation(
        self,
        matched: bool,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Observed;
        next.observation_match = Some(matched);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records `observed` with `matched: false` and the `echo-mismatch` fact.
    /// Only a `response-recorded` attempt can take this transition.
    ///
    /// # Errors
    /// Persistence failure retains only the recorded response.
    pub async fn record_echo_mismatch(self) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let mut next = self.attempt.record.clone();
        next.stage = GatewayAttemptStage::Observed;
        next.observation_match = Some(false);
        next.observation_fact = Some(GatewayObservationFact::EchoMismatch);
        self.attempt.advance(next).await?.record.snapshot(false)
    }

    /// Records terminal `observed-by-provider` with the exact response bytes.
    /// The caller must already have found this attempt's token in them; the
    /// stored token is re-derived from this record, never taken from input.
    ///
    /// # Errors
    /// Rejects a recipe without echo, empty or oversized evidence, and
    /// persistence failure.
    pub async fn record_provider_evidence(
        self,
        evidence: &[u8],
        observed_at: u64,
    ) -> Result<GatewayAttemptSnapshot, GatewayAttemptError> {
        let record = &self.attempt.record;
        let plan = record
            .observation_plan
            .as_ref()
            .filter(|plan| plan.echo)
            .ok_or(GatewayAttemptError::InvalidTransition)?;
        if evidence.is_empty() || evidence.len() > MAX_EVIDENCE_BYTES {
            return Err(GatewayAttemptError::InvalidTransition);
        }
        let mut next = record.clone();
        next.provider_evidence = Some(EvidenceWire {
            channel: GatewayEvidenceChannel::ReadBack,
            locator: plan.locator.clone(),
            echo: record.echo_token()?,
            evidence_digest: hex::encode(Sha256::digest(evidence)),
            evidence_b64: Base64::encode_string(evidence),
            observed_at,
        });
        next.stage = GatewayAttemptStage::ObservedByProvider;
        self.attempt.advance(next).await?.record.snapshot(false)
    }
}

fn encode(record: &Record) -> Result<Vec<u8>, GatewayAttemptError> {
    let bytes = serde_json::to_vec(record).map_err(|_| GatewayAttemptError::Corrupt)?;
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    Ok(bytes)
}

fn decode(bytes: &[u8]) -> Result<Record, GatewayAttemptError> {
    if bytes.is_empty() || bytes.len() > MAX_RECORD_BYTES {
        return Err(GatewayAttemptError::Corrupt);
    }
    serde_json::from_slice(bytes).map_err(|_| GatewayAttemptError::Corrupt)
}

fn valid_transition(old: &Record, new: &Record) -> bool {
    old.nonce == new.nonce
        && old.namespace == new.namespace
        && old.operation_id == new.operation_id
        && old.action_commitment == new.action_commitment
        && old.recipe_digest == new.recipe_digest
        && old.observation_plan == new.observation_plan
        && matches!(
            (old.stage, new.stage),
            (
                GatewayAttemptStage::Attempting,
                GatewayAttemptStage::NotEntered
                    | GatewayAttemptStage::Unknown
                    | GatewayAttemptStage::ResponseRecorded
            ) | (
                GatewayAttemptStage::ResponseRecorded,
                GatewayAttemptStage::Observed | GatewayAttemptStage::ObservedByProvider
            ) | (
                GatewayAttemptStage::Unknown,
                GatewayAttemptStage::ObservedByProvider
            )
        )
        && new.snapshot(false).is_ok()
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
