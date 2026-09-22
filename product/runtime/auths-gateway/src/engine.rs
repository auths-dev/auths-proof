//! Native-verified, digest-bound single-host execution coordinator.

// Explicit matches keep each verification and transport failure mapped to its
// distinct public stage; `let...else` would obscure those boundary decisions.
#![allow(clippy::manual_let_else)]

use crate::recipe::ReadBack;
use crate::transport::{
    GatewayHttpTransport, LeasedTransport, ProviderPort, WriteTransportOutcome,
};
use crate::{
    ClaimedGatewayAttempt, ClosedProviderRequest, CompiledRecipe, FileGatewayAttemptStore,
    GatewayAttemptError, GatewayConnectionDescriptor, GatewayEvidenceChannel,
    GatewayProviderEvidence, ObservableGatewayAttempt,
};
use auths_connections::{
    ConnectionAlias, ConnectionBinding, ConnectionCredentialStore, ConnectionProfile,
    ConnectionState, PersistentCredentialStore, ProviderKind, SecretBytes, StoredSecretLease,
};
use auths_model::VerificationDecision;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::McpProfile;
use auths_stores::PersistentConnectionStore;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;

/// Installation failure before an application socket can be served.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum GatewayEngineConfigurationError {
    /// Independently installed trust is missing or unbounded.
    #[error("gateway trusted context is missing or unbounded")]
    InvalidTrust,
    /// The installed recipe differs from the operator-approved digest.
    #[error("gateway recipe approval digest mismatch")]
    UnapprovedRecipe,
}

/// Closed, secret-free application result. A recorded response or matching
/// read-back does not prove provider effect or exclusive causation.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum GatewaySubmitResult {
    /// Native proof verification denied the action.
    Denied { code: String },
    /// Native proof verification could not reach an authorized conclusion.
    Indeterminate { code: String },
    /// Proof was authorized but this operation did not enter write transport.
    NotEntered { code: String },
    /// Write entry/effect is ambiguous; no automatic retry is permitted.
    Unknown,
    /// A complete bounded HTTP response exists, but no read-back was recorded.
    ResponseRecorded { status: u16 },
    /// A separately completed read-back compared exact state; not causation.
    Observed { status: u16, matched: bool },
    /// A read-back over the pinned origin returned exactly this attempt's echo
    /// token and the verified value. `status` is absent when the write itself
    /// was `unknown`. The link holds only while no other party with write
    /// access to that provider field wrote the same token.
    ObservedByProvider {
        status: Option<u16>,
        evidence: GatewayEvidenceSummary,
    },
}

/// Secret-free summary of stored provider evidence. The response bytes and
/// the observation locator stay in the operator's attempt store.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayEvidenceSummary {
    /// Evidence channel; `read-back` in this version.
    pub channel: GatewayEvidenceChannel,
    /// The echo token found in the provider record.
    pub echo: String,
    /// Lowercase hexadecimal SHA-256 of the exact observation response bytes.
    pub evidence_digest: String,
    /// Gateway wall-clock seconds; not authenticated.
    pub observed_at: u64,
}

impl From<&GatewayProviderEvidence> for GatewayEvidenceSummary {
    fn from(evidence: &GatewayProviderEvidence) -> Self {
        Self {
            channel: evidence.channel(),
            echo: evidence.echo().to_owned(),
            evidence_digest: hex::encode(evidence.evidence_digest()),
            observed_at: evidence.observed_at(),
        }
    }
}

/// One immutable installed operation and independently provisioned trust.
/// Connection state and generation are rechecked on every submission.
pub struct GatewayEngine {
    recipe: CompiledRecipe,
    trusted_context_cbor: Vec<u8>,
    provider: ProviderKind,
    alias: ConnectionAlias,
    workload_id: String,
    profile: ConnectionProfile,
    connections: PersistentConnectionStore,
    credentials: PersistentCredentialStore,
    attempts: FileGatewayAttemptStore,
    administrative_gate: RwLock<()>,
}

impl GatewayEngine {
    /// Constructs an engine only for an exact operator-approved recipe digest.
    /// The caller must be the separately deployed gateway, never the app.
    ///
    /// # Errors
    /// Refuses missing trust or a changed recipe.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipe: CompiledRecipe,
        approved_digest: [u8; 32],
        trusted_context_cbor: Vec<u8>,
        provider: ProviderKind,
        alias: ConnectionAlias,
        workload_id: String,
        profile: ConnectionProfile,
        connections: PersistentConnectionStore,
        credentials: PersistentCredentialStore,
        attempts: FileGatewayAttemptStore,
    ) -> Result<Self, GatewayEngineConfigurationError> {
        if trusted_context_cbor.is_empty()
            || trusted_context_cbor.len() > MAX_CONTEXT_BYTES
            || auths_codec::decode_verifier_context(&trusted_context_cbor).is_err()
        {
            return Err(GatewayEngineConfigurationError::InvalidTrust);
        }
        if *recipe.digest() != approved_digest {
            return Err(GatewayEngineConfigurationError::UnapprovedRecipe);
        }
        Ok(Self {
            recipe,
            trusted_context_cbor,
            provider,
            alias,
            workload_id,
            profile,
            connections,
            credentials,
            attempts,
            administrative_gate: RwLock::new(()),
        })
    }

    /// Disables new submissions after all already-entered submissions finish.
    /// The operator-only service channel must be the sole caller.
    ///
    /// # Errors
    /// A failed durable transition never reports disabled.
    pub async fn disable_connection(&self) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Active {
            return Err("gateway.admin.connection-not-active");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .advance_generation(current.connection_id(), current.generation(), next)
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        self.connections
            .transition_state(
                &self.provider,
                &self.alias,
                current.generation(),
                ConnectionState::Disabled,
                *commitment.as_bytes(),
                now,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        Ok(())
    }

    /// Rotates the operator-held secret to a new generation, retaining the
    /// previous generation for unresolved attempts. The admin channel must be
    /// unavailable to the application identity.
    ///
    /// # Errors
    /// A failed durable transition never reports rotation complete.
    pub async fn rotate_connection(&self, secret: SecretBytes) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Active {
            return Err("gateway.admin.connection-not-active");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .replace(current.connection_id(), current.generation(), next, secret)
            .await
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        let replacement = current
            .rotated(
                current.descriptor().to_vec(),
                *current.account_commitment(),
                *commitment.as_bytes(),
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.connections
            .replace(current.generation(), replacement)
            .map_err(|_| "gateway.admin.transition-unavailable")
    }

    /// Revokes new entry after in-flight submissions complete, retaining a
    /// terminal record and withholding every new credential lease.
    ///
    /// # Errors
    /// A failed durable transition never reports revocation complete.
    pub async fn revoke_connection(&self) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-revoked");
        }
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        let commitment = self
            .credentials
            .advance_generation(current.connection_id(), current.generation(), next)
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        self.connections
            .transition_state(
                &self.provider,
                &self.alias,
                current.generation(),
                ConnectionState::Revoked,
                *commitment.as_bytes(),
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        let _ = self
            .credentials
            .revoke(current.connection_id(), current.generation())
            .await;
        let _ = self.credentials.revoke(current.connection_id(), next).await;
        Ok(())
    }

    /// Verifies and attempts one exact action. Only proof and action bytes are
    /// accepted from the application; trust, recipe, connection, and credential
    /// come from the operator's installation. A replay never writes again; for
    /// an echo recipe it may perform one more read-only observation.
    pub async fn submit(&self, proof_cbor: &[u8], action_cbor: &[u8]) -> GatewaySubmitResult {
        let request = match self.verify_and_close(proof_cbor, action_cbor) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let _guard = self.administrative_gate.read().await;
        let (binding, transport) = match self.prepare_entry() {
            Ok(value) => value,
            Err(result) => return result,
        };
        let claim = match self.attempts.claim(&request, *self.recipe.digest()) {
            Ok(value) => value,
            Err(GatewayAttemptError::Replay) => {
                return self
                    .observe_after_replay(&request, &binding, &transport)
                    .await;
            }
            Err(_) => return not_entered("gateway.attempt.unavailable"),
        };
        let lease = match self.lease(&binding).await {
            Ok(value) => value,
            Err(()) => return checkpoint_not_entered(claim),
        };
        let port = LeasedTransport {
            transport: &transport,
            lease: &lease,
        };
        execute_claimed(claim, &request, &port).await
    }

    fn prepare_entry(
        &self,
    ) -> Result<(ConnectionBinding, GatewayHttpTransport), GatewaySubmitResult> {
        let binding = match self.connections.resolve(
            &self.provider,
            Some(&self.alias),
            &self.workload_id,
            &self.profile,
        ) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.connection.unavailable")),
        };
        let descriptor = match GatewayConnectionDescriptor::from_binding(&binding, &self.recipe) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.connection.recipe-mismatch")),
        };
        if self
            .connections
            .reread_before_lease(&binding, &self.workload_id, &self.profile)
            .is_err()
        {
            return Err(not_entered("gateway.connection.changed"));
        }
        match GatewayHttpTransport::prepare(&self.recipe, descriptor.credential()) {
            Ok(transport) => Ok((binding, transport)),
            Err(_) => Err(not_entered("gateway.transport.preparation")),
        }
    }

    async fn lease(&self, binding: &ConnectionBinding) -> Result<StoredSecretLease, ()> {
        self.credentials
            .lease_secret(binding, Instant::now() + Duration::from_secs(30))
            .await
            .map_err(|_| ())
    }

    async fn observe_after_replay(
        &self,
        request: &ClosedProviderRequest,
        binding: &ConnectionBinding,
        transport: &GatewayHttpTransport,
    ) -> GatewaySubmitResult {
        let attempt = match self
            .attempts
            .resume_observable(request, *self.recipe.digest())
        {
            Ok(Some(value)) => value,
            Ok(None) | Err(_) => return replay_refused(),
        };
        let lease = match self.lease(binding).await {
            Ok(value) => value,
            Err(()) => return replay_refused(),
        };
        let port = LeasedTransport {
            transport,
            lease: &lease,
        };
        reobserve(attempt, request, &port).await
    }

    fn verify_and_close(
        &self,
        proof_cbor: &[u8],
        action_cbor: &[u8],
    ) -> Result<ClosedProviderRequest, GatewaySubmitResult> {
        if proof_cbor.is_empty()
            || proof_cbor.len() > MAX_PROOF_BYTES
            || action_cbor.is_empty()
            || action_cbor.len() > MAX_ACTION_BYTES
        {
            return Err(GatewaySubmitResult::Indeterminate {
                code: "gateway.submit.invalid-size".to_owned(),
            });
        }
        let raw_key = match auths_raw_key::RawKeyMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let did_key = match auths_did_key::DidKeyMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let did_keri = match auths_did_keri::DidKeriMethod::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let ed25519 = match auths_signature::Ed25519Suite::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let p256 = match auths_signature::P256Sha256Suite::new() {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
        let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
        let registries = match auths_registries::ImmutableRegistries::new(&methods, &suites) {
            Ok(value) => value,
            Err(_) => return Err(indeterminate_registry()),
        };
        let sealed = match auths_verifier::verify_v1_sealed(
            proof_cbor,
            action_cbor,
            &self.trusted_context_cbor,
            &registries,
        ) {
            Ok(value) => value,
            Err(_) => {
                return Err(GatewaySubmitResult::Indeterminate {
                    code: "gateway.verify.invalid-input".to_owned(),
                });
            }
        };
        let Some(action) = sealed.action() else {
            let code = sealed.portable().code().code().to_owned();
            return Err(match sealed.portable().decision() {
                VerificationDecision::Denied => GatewaySubmitResult::Denied { code },
                VerificationDecision::Authorized | VerificationDecision::Indeterminate => {
                    GatewaySubmitResult::Indeterminate { code }
                }
            });
        };
        let command = match McpProfile.decode_verified(action) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.action.projection")),
        };
        let canonical = match auths_codec::encode_canonical_action(action.canonical_action()) {
            Ok(value) => value,
            Err(_) => return Err(not_entered("gateway.action.commitment")),
        };
        let action_commitment =
            match auths_codec::domain_commitment("auths.canonical-action.v1", &canonical) {
                Ok(value) => *value.as_bytes(),
                Err(_) => return Err(not_entered("gateway.action.commitment")),
            };
        self.recipe
            .closed_request(&command, action_commitment)
            .map_err(|error| not_entered(error.code()))
    }
}

fn indeterminate_registry() -> GatewaySubmitResult {
    GatewaySubmitResult::Indeterminate {
        code: "gateway.verify.registry-unavailable".to_owned(),
    }
}

fn not_entered(code: &'static str) -> GatewaySubmitResult {
    GatewaySubmitResult::NotEntered {
        code: code.to_owned(),
    }
}

fn replay_refused() -> GatewaySubmitResult {
    not_entered("gateway.attempt.replay")
}

fn checkpoint_not_entered(claim: ClaimedGatewayAttempt) -> GatewaySubmitResult {
    match claim.record_not_entered() {
        Ok(_) => not_entered("gateway.credential.unavailable"),
        Err(_) => GatewaySubmitResult::Unknown,
    }
}

fn wall_clock_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Enters the provider once for a freshly claimed attempt, records the
/// response class, then performs at most one read-only observation.
async fn execute_claimed(
    claim: ClaimedGatewayAttempt,
    request: &ClosedProviderRequest,
    port: &impl ProviderPort,
) -> GatewaySubmitResult {
    let write = match port.write(request).await {
        Ok(value) => value,
        Err(_) => return checkpoint_not_entered(claim),
    };
    match write {
        WriteTransportOutcome::Unknown => {
            let _ = claim.record_unknown();
            GatewaySubmitResult::Unknown
        }
        WriteTransportOutcome::ResponseRecorded { status, digest } => {
            let recorded = match claim.record_response(status, digest) {
                Ok(value) => value,
                Err(_) => return GatewaySubmitResult::Unknown,
            };
            record_read_back(recorded, request, port)
                .await
                .unwrap_or(GatewaySubmitResult::ResponseRecorded { status })
        }
    }
}

/// Performs one more read-only observation of a resumed attempt. Anything
/// short of a recorded transition is reported as the replay refusal it is.
async fn reobserve(
    attempt: ObservableGatewayAttempt,
    request: &ClosedProviderRequest,
    port: &impl ProviderPort,
) -> GatewaySubmitResult {
    record_read_back(attempt, request, port)
        .await
        .unwrap_or_else(replay_refused)
}

/// Returns `None` when nothing was durably recorded. The echo token comes
/// from the stored attempt, never from the current submission, so a fresh
/// challenge for the same logical operation checks the original token.
async fn record_read_back(
    attempt: ObservableGatewayAttempt,
    request: &ClosedProviderRequest,
    port: &impl ProviderPort,
) -> Option<GatewaySubmitResult> {
    let observation = request.observation()?;
    let bytes = port.read_back(observation).await?;
    let token = attempt.echo_token();
    let reading = observation.read_back(token.as_deref(), &bytes)?;
    let status = attempt.snapshot().ok()?.response_status();
    match reading {
        ReadBack::EchoMatched => {
            let snapshot = attempt
                .record_provider_evidence(&bytes, wall_clock_seconds()?)
                .ok()?;
            Some(GatewaySubmitResult::ObservedByProvider {
                status,
                evidence: snapshot.provider_evidence()?.into(),
            })
        }
        ReadBack::Value { matched } => {
            let status = status?;
            attempt.record_observation(matched).ok()?;
            Some(GatewaySubmitResult::Observed { status, matched })
        }
        ReadBack::EchoMismatch => {
            let status = status?;
            attempt.record_echo_mismatch().ok()?;
            Some(GatewaySubmitResult::Observed {
                status,
                matched: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::GatewayTransportError;
    use crate::{
        ClosedObservationRequest, GatewayAttemptSnapshot, GatewayAttemptStage,
        GatewayObservationFact, LogicalOperationId, echo_token,
    };
    use serde_json::{Map, Value, json};
    use sha2::{Digest as _, Sha256};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const ORIGINAL: [u8; 32] = [0x11; 32];
    const FRESH: [u8; 32] = [0x22; 32];
    const RECORD: &str = "recTEST0000000001";
    const FOREIGN: &str =
        "auths-e1-0000000000000000000000000000000000000000000000000000000000000000";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Delivery {
        Respond,
        RespondWithoutApplying,
        TimeoutAfterApplying,
        LostBeforeApplying,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Reading {
        Faithful,
        Unavailable,
        ForeignEcho,
        EchoStripped,
        ValueChanged,
    }

    /// Synthetic provider that counts every write entry and read-back.
    struct CountingProvider {
        delivery: Delivery,
        reading: Reading,
        writes: AtomicUsize,
        reads: AtomicUsize,
        fields: Mutex<Map<String, Value>>,
        last_read: Mutex<Vec<u8>>,
    }

    impl CountingProvider {
        fn new(delivery: Delivery, reading: Reading) -> Self {
            let mut fields = Map::new();
            fields.insert("DemoStatus".into(), json!("Pending"));
            Self {
                delivery,
                reading,
                writes: AtomicUsize::new(0),
                reads: AtomicUsize::new(0),
                fields: Mutex::new(fields),
                last_read: Mutex::new(Vec::new()),
            }
        }

        fn writes(&self) -> usize {
            self.writes.load(Ordering::SeqCst)
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    impl ProviderPort for CountingProvider {
        async fn write(
            &self,
            request: &ClosedProviderRequest,
        ) -> Result<WriteTransportOutcome, GatewayTransportError> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            if matches!(
                self.delivery,
                Delivery::Respond | Delivery::TimeoutAfterApplying
            ) {
                let body: Value = serde_json::from_slice(request.body())
                    .map_err(|_| GatewayTransportError::NotEntered)?;
                if let Some(update) = body.get("fields").and_then(Value::as_object) {
                    self.fields.lock().expect("fields").extend(update.clone());
                }
            }
            Ok(match self.delivery {
                Delivery::Respond | Delivery::RespondWithoutApplying => {
                    WriteTransportOutcome::ResponseRecorded {
                        status: 200,
                        digest: [4; 32],
                    }
                }
                Delivery::TimeoutAfterApplying | Delivery::LostBeforeApplying => {
                    WriteTransportOutcome::Unknown
                }
            })
        }

        async fn read_back(&self, _: &ClosedObservationRequest) -> Option<Vec<u8>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let mut fields = self.fields.lock().expect("fields").clone();
            match self.reading {
                Reading::Faithful => {}
                Reading::Unavailable => return None,
                Reading::ForeignEcho => {
                    fields.insert("auths_echo".into(), json!(FOREIGN));
                }
                Reading::EchoStripped => {
                    fields.remove("auths_echo");
                }
                Reading::ValueChanged => {
                    fields.insert("DemoStatus".into(), json!("Pending"));
                }
            }
            let bytes = serde_json::to_vec(&json!({"id": RECORD, "fields": fields})).ok()?;
            *self.last_read.lock().expect("last read") = bytes.clone();
            Some(bytes)
        }
    }

    struct Harness {
        recipe: CompiledRecipe,
        store: FileGatewayAttemptStore,
        root: std::path::PathBuf,
        _temp: tempfile::TempDir,
    }

    impl Harness {
        fn open(name: &str) -> Self {
            let (source, lock): (&[u8], &[u8]) = match name {
                "airtable" => (
                    include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
                    include_bytes!(
                        "../../../../bindings/fixtures/gateway/airtable/profile.lock.json"
                    ),
                ),
                "github" => (
                    include_bytes!("../../../../bindings/fixtures/gateway/github/recipe.json"),
                    include_bytes!(
                        "../../../../bindings/fixtures/gateway/github/profile.lock.json"
                    ),
                ),
                _ => panic!("unknown test-only fixture"),
            };
            let recipe = CompiledRecipe::compile(source, lock).expect("fixture compiles");
            let temp = tempfile::tempdir().expect("temp directory");
            let root = std::fs::canonicalize(temp.path())
                .expect("canonical temp")
                .join("attempts");
            let store = FileGatewayAttemptStore::open(&root).expect("store");
            Self {
                recipe,
                store,
                root,
                _temp: temp,
            }
        }

        fn restart(&mut self) {
            self.store = FileGatewayAttemptStore::open(&self.root).expect("restarted store");
        }

        fn request(&self, commitment: [u8; 32], values: &Value) -> ClosedProviderRequest {
            let mut arguments = values.as_object().expect("object").clone();
            arguments.insert(
                "operator_namespace".into(),
                json!(self.recipe.namespace().as_str()),
            );
            arguments.insert("recipe_digest".into(), json!(self.recipe.digest_hex()));
            self.recipe
                .closed_request_from_arguments(&arguments, commitment)
                .expect("closed request")
        }

        fn airtable(&self, commitment: [u8; 32], replacement: &str) -> ClosedProviderRequest {
            self.request(
                commitment,
                &json!({"operation_id": "run-1", "record_id": RECORD, "replacement": replacement}),
            )
        }

        fn github(&self) -> ClosedProviderRequest {
            self.request(
                ORIGINAL,
                &json!({"operation_id": "issue-1", "title": "Exact", "body": "One issue"}),
            )
        }

        /// Mirrors the engine's post-verification dispatch with a fake port.
        async fn submit(
            &self,
            request: &ClosedProviderRequest,
            provider: &CountingProvider,
        ) -> GatewaySubmitResult {
            match self.store.claim(request, *self.recipe.digest()) {
                Ok(claim) => execute_claimed(claim, request, provider).await,
                Err(GatewayAttemptError::Replay) => {
                    match self.store.resume_observable(request, *self.recipe.digest()) {
                        Ok(Some(attempt)) => reobserve(attempt, request, provider).await,
                        _ => replay_refused(),
                    }
                }
                Err(_) => not_entered("gateway.attempt.unavailable"),
            }
        }

        fn snapshot(&self, request: &ClosedProviderRequest) -> GatewayAttemptSnapshot {
            self.store
                .read(request.namespace(), request.operation_id())
                .expect("read")
                .expect("retained claim")
        }

        fn describe(&self, request: &ClosedProviderRequest) -> String {
            let snapshot = self.snapshot(request);
            let stage = serde_json::to_value(snapshot.stage())
                .expect("stage")
                .as_str()
                .expect("kebab stage")
                .to_owned();
            match (snapshot.observation_match(), snapshot.observation_fact()) {
                (Some(true), _) => format!("{stage}-match"),
                (Some(false), Some(GatewayObservationFact::EchoMismatch)) => {
                    format!("{stage}-mismatch-echo-mismatch")
                }
                (Some(false), None) => format!("{stage}-mismatch"),
                (None, _) => stage,
            }
        }
    }

    fn original_token() -> String {
        echo_token(
            &crate::OperatorNamespace::parse("airtable-demo").expect("namespace"),
            &LogicalOperationId::parse("run-1").expect("operation"),
            &ORIGINAL,
        )
    }

    async fn run_claim_case(id: &str) -> (String, usize) {
        let mut harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        drop(
            harness
                .store
                .claim(&original, *harness.recipe.digest())
                .expect("first claim"),
        );
        let transition = match id {
            "first-claim" => "unclaimed->attempting".to_owned(),
            "same-id-fresh-challenge" | "changed-action-same-id" => {
                let replacement = if id == "same-id-fresh-challenge" {
                    "Approved"
                } else {
                    "Pending"
                };
                let second = harness.airtable(FRESH, replacement);
                assert_eq!(harness.submit(&second, &provider).await, replay_refused());
                "attempting->replay-refused".to_owned()
            }
            "crash-after-claim" => {
                harness.restart();
                format!("attempting->{}-on-restart", harness.describe(&original))
            }
            _ => panic!("unhandled claim scenario {id}"),
        };
        assert_eq!(provider.reads(), 0, "{id}");
        (transition, provider.writes())
    }

    async fn run_first_attempt_case(id: &str) -> (String, usize) {
        let (delivery, reading) = match id {
            "complete-http-response" | "echo-read-back" => (Delivery::Respond, Reading::Faithful),
            "ambiguous-transport" => (Delivery::LostBeforeApplying, Reading::Faithful),
            "matching-read-back" => (Delivery::Respond, Reading::EchoStripped),
            "mismatching-read-back" => (Delivery::RespondWithoutApplying, Reading::Faithful),
            "observation-unavailable" => (Delivery::Respond, Reading::Unavailable),
            "echo-overwritten-by-provider" => (Delivery::Respond, Reading::ForeignEcho),
            "echo-present-value-changed" => (Delivery::Respond, Reading::ValueChanged),
            _ => panic!("unhandled first-attempt scenario {id}"),
        };
        let harness = Harness::open(
            if matches!(id, "complete-http-response" | "ambiguous-transport") {
                "github"
            } else {
                "airtable"
            },
        );
        let provider = CountingProvider::new(delivery, reading);
        let request = if harness.recipe.review().has_observation() {
            harness.airtable(ORIGINAL, "Approved")
        } else {
            harness.github()
        };
        let result = harness.submit(&request, &provider).await;
        let from = if matches!(result, GatewaySubmitResult::Unknown)
            || !harness.recipe.review().has_observation()
        {
            "attempting"
        } else {
            "response-recorded"
        };
        (
            format!("{from}->{}", harness.describe(&request)),
            provider.writes(),
        )
    }

    async fn run_resolution_case(id: &str) -> (String, usize) {
        let (delivery, reading) = match id {
            "lost-write-echo-absent" => (Delivery::LostBeforeApplying, Reading::Faithful),
            "unknown-echo-overwritten" => (Delivery::TimeoutAfterApplying, Reading::ForeignEcho),
            "fresh-challenge-after-observed-by-provider" => (Delivery::Respond, Reading::Faithful),
            _ => (Delivery::TimeoutAfterApplying, Reading::Faithful),
        };
        let mut harness = Harness::open("airtable");
        let provider = CountingProvider::new(delivery, reading);
        let original = harness.airtable(ORIGINAL, "Approved");
        let first = harness.submit(&original, &provider).await;
        let before = harness.describe(&original);
        if id == "restart-during-unknown" {
            harness.restart();
        }
        let replacement = if id == "changed-action-during-unknown" {
            "Pending"
        } else {
            "Approved"
        };
        let replay = harness
            .submit(&harness.airtable(FRESH, replacement), &provider)
            .await;
        if matches!(
            harness.snapshot(&original).stage(),
            GatewayAttemptStage::ObservedByProvider
        ) && before != "observed-by-provider"
        {
            assert!(matches!(
                replay,
                GatewaySubmitResult::ObservedByProvider { status: None, .. }
            ));
        } else {
            assert_eq!(replay, replay_refused(), "{id}: first {first:?}");
        }
        (
            format!("{before}->{}", harness.describe(&original)),
            provider.writes(),
        )
    }

    async fn run_crash_after_entry_case() -> (String, usize) {
        let mut harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        let claim = harness
            .store
            .claim(&original, *harness.recipe.digest())
            .expect("claim");
        provider.write(&original).await.expect("entered");
        drop(claim);
        harness.restart();
        let replay = harness
            .submit(&harness.airtable(FRESH, "Approved"), &provider)
            .await;
        assert_eq!(replay, replay_refused());
        assert_eq!(provider.reads(), 0);
        (
            format!("attempting->{}-on-restart", harness.describe(&original)),
            provider.writes(),
        )
    }

    #[tokio::test]
    async fn attempt_scenario_corpus_drives_the_counting_provider() {
        let corpus: Value = serde_json::from_slice(include_bytes!(
            "../../../../bindings/fixtures/gateway/attempt-scenarios.json"
        ))
        .expect("state corpus");
        assert_eq!(corpus["schema"], "auths.gateway-attempt-scenarios/1");
        for case in corpus["cases"].as_array().expect("cases") {
            let id = case["id"].as_str().expect("id");
            let (transition, writes) = match id {
                "first-claim"
                | "same-id-fresh-challenge"
                | "changed-action-same-id"
                | "crash-after-claim" => run_claim_case(id).await,
                "crash-after-entry-not-reobserved" => run_crash_after_entry_case().await,
                "timeout-after-delivery-read-back"
                | "lost-write-echo-absent"
                | "unknown-echo-overwritten"
                | "restart-during-unknown"
                | "changed-action-during-unknown"
                | "fresh-challenge-after-observed-by-provider" => run_resolution_case(id).await,
                _ => run_first_attempt_case(id).await,
            };
            assert_eq!(transition, case["transition"], "{id}");
            assert_eq!(
                u64::try_from(writes).expect("count"),
                case["provider_entries"].as_u64().expect("entries"),
                "{id}"
            );
        }
    }

    #[tokio::test]
    async fn normal_write_reaches_observed_by_provider_with_secret_free_evidence() {
        let harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let request = harness.airtable(ORIGINAL, "Approved");
        let result = harness.submit(&request, &provider).await;
        let snapshot = harness.snapshot(&request);
        let evidence = snapshot.provider_evidence().expect("evidence");
        let bytes = provider.last_read.lock().expect("last read").clone();
        assert_eq!(snapshot.stage(), GatewayAttemptStage::ObservedByProvider);
        assert_eq!(evidence.channel(), GatewayEvidenceChannel::ReadBack);
        assert_eq!(
            evidence.locator(),
            request.observation().expect("obs").url()
        );
        assert_eq!(evidence.echo(), original_token());
        assert_eq!(evidence.evidence(), bytes.as_slice());
        assert_eq!(
            evidence.evidence_digest(),
            &<[u8; 32]>::from(Sha256::digest(&bytes))
        );
        assert!(!format!("{evidence:?}").contains("DemoStatus"));
        assert_eq!(
            result,
            GatewaySubmitResult::ObservedByProvider {
                status: Some(200),
                evidence: evidence.into(),
            }
        );
        let wire = serde_json::to_value(&result).expect("wire");
        assert_eq!(wire["outcome"], "observed-by-provider");
        assert_eq!(wire["evidence"]["channel"], "read-back");
        assert_eq!(wire["evidence"]["echo"], original_token());
        assert_eq!(
            wire["evidence"].as_object().expect("object").len(),
            4,
            "no bytes or locator reach the application"
        );
        assert_eq!((provider.writes(), provider.reads()), (1, 1));
    }

    #[tokio::test]
    async fn timeout_after_delivery_resolves_on_next_observation_without_second_write() {
        let mut harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::TimeoutAfterApplying, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        assert_eq!(
            harness.submit(&original, &provider).await,
            GatewaySubmitResult::Unknown
        );
        assert_eq!(
            provider.reads(),
            0,
            "an unknown write is not read back in-line"
        );
        harness.restart();
        let fresh = harness.airtable(FRESH, "Approved");
        let GatewaySubmitResult::ObservedByProvider { status, evidence } =
            harness.submit(&fresh, &provider).await
        else {
            panic!("expected observed-by-provider");
        };
        assert_eq!(status, None);
        assert_eq!(evidence.echo, original_token());
        assert_ne!(Some(evidence.echo.as_str()), fresh.echo_token());
        assert_eq!(
            harness.submit(&fresh, &provider).await,
            replay_refused(),
            "terminal stage is not re-read"
        );
        assert_eq!((provider.writes(), provider.reads()), (1, 1));
    }

    #[tokio::test]
    async fn provider_side_overwrite_records_echo_mismatch() {
        let harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::Respond, Reading::ForeignEcho);
        let request = harness.airtable(ORIGINAL, "Approved");
        assert_eq!(
            harness.submit(&request, &provider).await,
            GatewaySubmitResult::Observed {
                status: 200,
                matched: false
            }
        );
        let snapshot = harness.snapshot(&request);
        assert_eq!(snapshot.stage(), GatewayAttemptStage::Observed);
        assert_eq!(
            snapshot.observation_fact(),
            Some(GatewayObservationFact::EchoMismatch)
        );
        assert!(snapshot.provider_evidence().is_none());
        assert_eq!(provider.writes(), 1);
    }

    #[tokio::test]
    async fn replay_or_fresh_challenge_makes_no_second_provider_entry() {
        let harness = Harness::open("airtable");
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        let first = harness.submit(&original, &provider).await;
        assert!(matches!(
            first,
            GatewaySubmitResult::ObservedByProvider { .. }
        ));
        for request in [
            harness.airtable(ORIGINAL, "Approved"),
            harness.airtable(FRESH, "Approved"),
            harness.airtable(FRESH, "Pending"),
        ] {
            assert_eq!(harness.submit(&request, &provider).await, replay_refused());
        }
        assert_eq!((provider.writes(), provider.reads()), (1, 1));
    }

    #[test]
    fn application_result_parses_closed_observed_by_provider_shape() {
        let wire = json!({
            "outcome": "observed-by-provider",
            "status": null,
            "evidence": {
                "channel": "read-back",
                "echo": original_token(),
                "evidence_digest": "00".repeat(32),
                "observed_at": 1
            }
        });
        assert!(serde_json::from_value::<GatewaySubmitResult>(wire.clone()).is_ok());
        let mut extra = wire;
        extra["evidence"]["evidence_b64"] = json!("e30");
        assert!(serde_json::from_value::<GatewaySubmitResult>(extra).is_err());
    }
}
