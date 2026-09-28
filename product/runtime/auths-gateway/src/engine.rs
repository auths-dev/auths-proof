//! Native-verified, digest-bound execution coordinator. Attempts persist in
//! the single-host file store or the multi-host `PostgreSQL` store; connection
//! state is per process.

// Explicit matches keep each verification and transport failure mapped to its
// distinct public stage; `let...else` would obscure those boundary decisions.
#![allow(clippy::manual_let_else)]

use crate::bounds::{BoundAdmission, admit_bounds};
use crate::observer::{
    GatewayObserver, GatewaySignedObservation, OUTCOME_SCHEMA, READ_BACK_SCHEMA, operation_subject,
    outcome_facts, read_back_facts,
};
use crate::recipe::{ENTRY_DEADLINE_SECONDS, GuardChecks};
use crate::submit::{self, SubmitContext, SubmitIo};
use crate::transport::{
    GatewayHttpTransport, GatewayTransportError, LeasedTransport, ProviderPort, ProviderResponse,
    WriteTransportOutcome,
};
use crate::{
    ClosedCredentialRead, ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe,
    GatewayAttempts, GatewayConnectionDescriptor, GatewayEvidenceChannel, GatewayProviderEvidence,
    RequestHeader,
};
use auths_connections::{
    ConnectionAlias, ConnectionBinding, ConnectionCredentialStore, ConnectionProfile,
    ConnectionRecord, ConnectionState, PersistentCredentialStore, ProviderKind, SecretBytes,
    StoredSecretLease,
};
use auths_model::{
    CanonicalAction, ObservationRequirement, ResourceId, Timestamp, TrustedContext,
    VerificationDecision, VerifierConfigurationId,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, with_mcp_arguments_registries};
use auths_registries::ImmutableRegistries;
use auths_stores::PersistentConnectionStore;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;

const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
/// How often `serve` sweeps expired count and sum slots.
pub const SLOT_SWEEP_INTERVAL_SECONDS: u64 = 60;
/// The most expired slots one sweep deletes.
pub const SLOT_SWEEP_LIMIT: usize = 1_024;

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

/// Closed, read-only application request for one gateway-signed observation.
/// It carries no URL, method, header, body, schema, subject, or time: the
/// gateway derives each from its installation and its own clock.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GatewayObserveRequest {
    /// Read the recipe's observed field now and sign what was read.
    /// `arguments` names exactly the observation path's fields.
    ReadBack { arguments: Map<String, Value> },
    /// Sign the stored stage and commitment of one logical operation in this
    /// installation's namespace. No provider is contacted.
    Outcome { operation_id: String },
}

/// Closed application result of an observation request. A signed
/// observation asserts only what the gateway saw at `observed_at`.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case", deny_unknown_fields)]
pub enum GatewayObserveResult {
    /// A canonical signed observation to attach to the next action with
    /// `media_type` as its attachment media type.
    Signed {
        schema: String,
        subject: String,
        observed_at: u64,
        media_type: String,
        observation_b64: String,
    },
    /// Nothing was signed.
    Refused { code: String },
}

impl From<GatewaySignedObservation> for GatewayObserveResult {
    fn from(signed: GatewaySignedObservation) -> Self {
        Self::Signed {
            schema: signed.schema().to_owned(),
            subject: signed.subject().to_owned(),
            observed_at: signed.observed_at(),
            media_type: crate::observer::OBSERVATION_MEDIA_TYPE.to_owned(),
            observation_b64: Base64UrlUnpadded::encode_string(signed.bytes()),
        }
    }
}

fn refused(code: &'static str) -> GatewayObserveResult {
    GatewayObserveResult::Refused {
        code: code.to_owned(),
    }
}

/// One immutable installed operation and independently provisioned trust.
/// Connection state and generation are rechecked on every submission against
/// this process's own copy: a disable, rotate, or revoke made through another
/// gateway process does not reach it, and processes must not share a state
/// directory.
pub struct GatewayEngine {
    recipe: CompiledRecipe,
    trusted_context: TrustedContext,
    observer: Option<GatewayObserver>,
    provider: ProviderKind,
    alias: ConnectionAlias,
    workload_id: String,
    profile: ConnectionProfile,
    connections: PersistentConnectionStore,
    credentials: PersistentCredentialStore,
    attempts: GatewayAttempts,
    administrative_gate: RwLock<()>,
    #[cfg(feature = "loopback-provider")]
    loopback_port: Option<u16>,
}

impl GatewayEngine {
    /// Constructs an engine only for an exact operator-approved recipe digest.
    /// The caller must be the separately deployed gateway, never the app.
    ///
    /// # Errors
    /// Refuses missing trust, a changed recipe, or a recipe that declares a
    /// capability whose runtime step this gateway does not perform.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        recipe: CompiledRecipe,
        approved_digest: [u8; 32],
        trusted_context_cbor: &[u8],
        provider: ProviderKind,
        alias: ConnectionAlias,
        workload_id: String,
        profile: ConnectionProfile,
        connections: PersistentConnectionStore,
        credentials: PersistentCredentialStore,
        attempts: GatewayAttempts,
    ) -> Result<Self, GatewayEngineConfigurationError> {
        if trusted_context_cbor.is_empty() || trusted_context_cbor.len() > MAX_CONTEXT_BYTES {
            return Err(GatewayEngineConfigurationError::InvalidTrust);
        }
        let trusted_context = auths_codec::decode_verifier_context(trusted_context_cbor)
            .map_err(|_| GatewayEngineConfigurationError::InvalidTrust)?;
        if *recipe.digest() != approved_digest {
            return Err(GatewayEngineConfigurationError::UnapprovedRecipe);
        }
        Ok(Self {
            recipe,
            trusted_context,
            observer: None,
            provider,
            alias,
            workload_id,
            profile,
            connections,
            credentials,
            attempts,
            administrative_gate: RwLock::new(()),
            #[cfg(feature = "loopback-provider")]
            loopback_port: None,
        })
    }

    /// Development builds only: sends provider requests to a plain-HTTP
    /// provider double on `127.0.0.1:port` instead of the approved origin.
    #[cfg(feature = "loopback-provider")]
    #[must_use]
    pub fn with_loopback_provider(mut self, port: u16) -> Self {
        self.loopback_port = Some(port);
        self
    }

    /// Installs the operator-provisioned observer key. Without one, every
    /// observation request is refused.
    #[must_use]
    pub fn with_observer(mut self, observer: GatewayObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Refuses an installation whose operator principal is also a root or an
    /// observer of the installed trust, or whose observer key is a root or
    /// is not anchored in it.
    ///
    /// # Errors
    /// Returns the first overlap with its stable code.
    pub fn check_principal_separation(
        &self,
        operator: &auths_model::PrincipalId,
    ) -> Result<(), crate::PrincipalSeparationError> {
        crate::check_principal_separation(
            &self.trusted_context,
            operator,
            self.observer.as_ref().map(GatewayObserver::principal),
        )
    }

    /// Disables new submissions after all already-entered submissions finish,
    /// then deletes every credential generation older than the current one.
    /// Disabling stores no credential, so it needs no free credential-store
    /// capacity. The operator-only service channel must be the sole caller.
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
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        let disabled = self
            .connections
            .transition_state(
                &self.provider,
                &self.alias,
                current.generation(),
                ConnectionState::Disabled,
                now,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.delete_superseded_credentials(&disabled);
        Ok(())
    }

    /// Rotates the operator-held secret to a new generation and deletes every
    /// older generation. The candidate secret must first pass every declared
    /// credential check: the prefix, the probe, the account read against the
    /// record's commitment, and the denied reads. A rotation that fails after
    /// storing the successor deletes it, leaving the connection on its
    /// current secret. The admin channel must be unavailable to the
    /// application identity.
    ///
    /// # Errors
    /// A refused candidate or a failed durable transition never reports
    /// rotation complete.
    pub async fn rotate_connection(
        &self,
        candidate: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<(), &'static str> {
        // The candidate is checked before the gate is taken, so no
        // submission waits on the provider reads. A rotation keeps the
        // account commitment, so the record reloaded under the gate is
        // checked against the same account.
        let account = *self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?
            .account_commitment();
        crate::onboarding::check_candidate_credential(
            &self.recipe,
            self.recipe.review().credential(),
            &candidate,
            crate::onboarding::OnboardingAccount::Commitment(account),
        )
        .await
        .map_err(crate::onboarding::OnboardingFailure::admin_code)?;
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Active {
            return Err("gateway.admin.connection-not-active");
        }
        if *current.account_commitment() != account {
            return Err("gateway.admin.credential-account");
        }
        let mut candidate = candidate;
        let secret = SecretBytes::new(std::mem::take(&mut *candidate))
            .map_err(|_| "gateway.admin.invalid-credential")?;
        let next = current
            .generation()
            .get()
            .checked_add(1)
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        // Nothing can name a generation the record has not reached, so a
        // successor left by an earlier failed rotation is discarded, not reused.
        let _ = self.credentials.revoke(current.connection_id(), next).await;
        let commitment = self
            .credentials
            .replace(current.connection_id(), current.generation(), next, secret)
            .await
            .map_err(|_| "gateway.admin.credential-unavailable")?;
        match self.publish_rotation(&current, *commitment.as_bytes()) {
            Ok(rotated) => {
                self.delete_superseded_credentials(&rotated);
                Ok(())
            }
            Err(code) => {
                // The record still names its previous secret. If this deletion
                // fails too, the unpublished successor still cannot be leased:
                // it fails the credential-reference check at any generation it
                // would serve, and the next rotation supersedes it.
                let _ = self.credentials.revoke(current.connection_id(), next).await;
                Err(code)
            }
        }
    }

    fn publish_rotation(
        &self,
        current: &ConnectionRecord,
        commitment: [u8; 32],
    ) -> Result<ConnectionRecord, &'static str> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| "gateway.admin.clock-unavailable")?
            .as_secs();
        let replacement = current
            .rotated(
                current.descriptor().to_vec(),
                *current.account_commitment(),
                commitment,
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        self.connections
            .replace(current.generation(), replacement.clone())
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        Ok(replacement)
    }

    /// The gateway leases only its current generation, so nothing needs an
    /// older one. Best effort: a failed deletion is repeated by the next
    /// rotation, disable, or revoke.
    fn delete_superseded_credentials(&self, current: &ConnectionRecord) {
        let _ = self
            .credentials
            .retain_generations(current.connection_id(), &[current.generation()]);
    }

    /// Revokes new entry after in-flight submissions complete, retaining a
    /// terminal record, withholding every new credential lease, and deleting
    /// every stored credential generation in one persisted mutation, which
    /// needs no free credential-store capacity. Revoking an already revoked
    /// connection finishes a deletion that an earlier revocation failed to
    /// persist.
    ///
    /// # Errors
    /// A failed durable transition never reports revocation complete. A
    /// failed deletion is reported after the record is revoked, which already
    /// withholds every lease; revoking again finishes the deletion.
    pub async fn revoke_connection(&self) -> Result<(), &'static str> {
        let _guard = self.administrative_gate.write().await;
        let current = self
            .connections
            .load(&self.provider, &self.alias)
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")?;
        if current.state() != ConnectionState::Revoked {
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
                    timestamp,
                )
                .map_err(|_| "gateway.admin.transition-unavailable")?;
        }
        self.credentials
            .revoke_connection(current.connection_id())
            .map_err(|_| "gateway.admin.credential-deletion-incomplete")
    }

    /// Deletes at most [`SLOT_SWEEP_LIMIT`] count and sum slots whose expiry,
    /// one full window after their window ends, is at or before the gateway
    /// clock, and returns how many were deleted. Claims are never swept.
    ///
    /// # Errors
    /// `gateway.sweep.clock-unavailable` without a clock, and
    /// `gateway.sweep.unavailable` when the store fails.
    pub async fn sweep_expired_slots(&self) -> Result<usize, &'static str> {
        let now = wall_clock_seconds().ok_or("gateway.sweep.clock-unavailable")?;
        self.attempts
            .sweep_expired(now, SLOT_SWEEP_LIMIT)
            .await
            .map_err(|_| "gateway.sweep.unavailable")
    }

    /// Verifies and attempts one exact action. Only proof and action bytes are
    /// accepted from the application; trust, recipe, connection, and credential
    /// come from the operator's installation. The admission-order step machine
    /// directs every step: a replay never writes again, and for a linked
    /// recipe it may perform one more read-only observation.
    pub async fn submit(&self, proof_cbor: &[u8], action_cbor: &[u8]) -> GatewaySubmitResult {
        let _guard = self.administrative_gate.read().await;
        let io = EngineIo {
            engine: self,
            proof: proof_cbor,
            action: action_cbor,
            started: Instant::now(),
            prepared: OnceLock::new(),
        };
        submit::run(
            &SubmitContext {
                recipe: &self.recipe,
                attempts: &self.attempts,
                context: &self.trusted_context,
                observer: self.observer.as_ref(),
            },
            &io,
        )
        .await
    }

    fn prepare_entry(&self) -> Result<(ConnectionBinding, GatewayHttpTransport), &'static str> {
        let binding = match self.connections.resolve(
            &self.provider,
            Some(&self.alias),
            &self.workload_id,
            &self.profile,
        ) {
            Ok(value) => value,
            Err(_) => return Err("gateway.connection.unavailable"),
        };
        let descriptor = match GatewayConnectionDescriptor::from_binding(&binding, &self.recipe) {
            Ok(value) => value,
            Err(_) => return Err("gateway.connection.recipe-mismatch"),
        };
        if !self.reread(&binding) {
            return Err("gateway.connection.changed");
        }
        #[cfg(feature = "loopback-provider")]
        if let Some(port) = self.loopback_port {
            return GatewayHttpTransport::prepare_loopback(
                &self.recipe,
                descriptor.credential(),
                port,
            )
            .map(|transport| (binding, transport))
            .map_err(|_| "gateway.transport.preparation");
        }
        match GatewayHttpTransport::prepare(&self.recipe, descriptor.credential()) {
            Ok(transport) => Ok((binding, transport)),
            Err(_) => Err("gateway.transport.preparation"),
        }
    }

    /// Rereads this process's connection record and requires the binding to
    /// be unchanged: the re-read immediately before credential acquisition.
    fn reread(&self, binding: &ConnectionBinding) -> bool {
        self.connections
            .reread_before_lease(binding, &self.workload_id, &self.profile)
            .is_ok()
    }

    async fn lease(&self, binding: &ConnectionBinding) -> Result<StoredSecretLease, ()> {
        self.credentials
            .lease_secret(binding, Instant::now() + Duration::from_secs(30))
            .await
            .map_err(|_| ())
    }

    /// Signs one observation for the application. A read-back uses the
    /// installed connection and credential for exactly one bounded read-only
    /// GET built from the approved recipe, after the lease passes every
    /// declared credential check; an outcome reads only the local attempt
    /// store. Nothing here writes to a provider or to the store.
    pub async fn observe(&self, request: &GatewayObserveRequest) -> GatewayObserveResult {
        let Some(observer) = &self.observer else {
            return refused("gateway.observer.not-provisioned");
        };
        match request {
            GatewayObserveRequest::Outcome { operation_id } => {
                let Some(now) = wall_clock_seconds() else {
                    return refused("gateway.observer.clock-unavailable");
                };
                observe_outcome(
                    &self.attempts,
                    self.recipe.namespace(),
                    observer,
                    operation_id,
                    now,
                )
                .await
            }
            GatewayObserveRequest::ReadBack { arguments } => {
                let Ok(target) = self.recipe.read_back_target(arguments) else {
                    return refused("gateway.observer.invalid-read-back");
                };
                let _guard = self.administrative_gate.read().await;
                let Ok((binding, transport)) = self.prepare_entry() else {
                    return refused("gateway.observer.connection-unavailable");
                };
                let Ok(lease) = self.lease(&binding).await else {
                    return refused("gateway.observer.credential-unavailable");
                };
                let port = LeasedTransport {
                    transport: &transport,
                    lease: &lease,
                };
                let prefix = self.recipe.guard_checks().is_none_or(|guard| {
                    lease
                        .expose(Instant::now())
                        .is_ok_and(|secret| guard.admits_secret(secret))
                });
                if !submit::lease_checks(
                    &self.recipe,
                    &port,
                    prefix,
                    Some(*binding.account_commitment()),
                )
                .await
                {
                    return refused("gateway.observer.credential-guard");
                }
                observe_read_back(&target, observer, &port, wall_clock_seconds).await
            }
        }
    }
}

/// The installed engine's I/O for one submission.
struct EngineIo<'a> {
    engine: &'a GatewayEngine,
    proof: &'a [u8],
    action: &'a [u8],
    started: Instant,
    prepared: OnceLock<(ConnectionBinding, GatewayHttpTransport)>,
}

impl SubmitIo for EngineIo<'_> {
    type Lease = StoredSecretLease;

    fn clock(&self) -> Option<u64> {
        wall_clock_seconds()
    }

    fn verify(&self, now: u64) -> Result<VerifiedCommand, GatewaySubmitResult> {
        verify_detailed(
            &self.engine.recipe,
            &self.engine.trusted_context,
            now,
            self.proof,
            self.action,
        )
    }

    fn bind_scope(&self, verified: &VerifiedCommand) -> Result<(), &'static str> {
        crate::bounds::bind_account_scope(
            &self.engine.recipe,
            verified.bound.as_ref(),
            &verified.arguments,
        )
    }

    fn prepare(&self) -> Result<(), &'static str> {
        let prepared = self.engine.prepare_entry()?;
        self.prepared
            .set(prepared)
            .map_err(|_| "gateway.transport.preparation")
    }

    fn reload(&self) -> bool {
        self.prepared
            .get()
            .is_some_and(|(binding, _)| self.engine.reread(binding))
    }

    async fn lease(&self) -> Option<StoredSecretLease> {
        let (binding, _) = self.prepared.get()?;
        self.engine.lease(binding).await.ok()
    }

    fn secret_admitted(&self, lease: &StoredSecretLease, guard: &GuardChecks) -> bool {
        lease
            .expose(Instant::now())
            .is_ok_and(|secret| guard.admits_secret(secret))
    }

    fn account_commitment(&self) -> Option<[u8; 32]> {
        self.prepared
            .get()
            .map(|(binding, _)| *binding.account_commitment())
    }

    fn within_entry_deadline(&self, evaluated_at: u64) -> bool {
        wall_clock_seconds()
            .is_some_and(|now| now <= evaluated_at.saturating_add(ENTRY_DEADLINE_SECONDS))
            && self.started.elapsed() <= Duration::from_secs(ENTRY_DEADLINE_SECONDS)
    }

    async fn write(
        &self,
        lease: &StoredSecretLease,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        match self.prepared.get() {
            Some((_, transport)) => LeasedTransport { transport, lease }.write(request).await,
            None => Err(GatewayTransportError::NotEntered),
        }
    }

    async fn action_read(
        &self,
        lease: &StoredSecretLease,
        url: &str,
        headers: &[RequestHeader],
        maximum_response_bytes: usize,
    ) -> Option<ProviderResponse> {
        let (_, transport) = self.prepared.get()?;
        LeasedTransport { transport, lease }
            .action_read(url, headers, maximum_response_bytes)
            .await
    }

    async fn credential_read(
        &self,
        lease: &StoredSecretLease,
        read: &ClosedCredentialRead,
    ) -> Option<ProviderResponse> {
        let (_, transport) = self.prepared.get()?;
        LeasedTransport { transport, lease }
            .credential_read(read)
            .await
    }
}

/// Whether `namespace` covers `subject` under the trusted context's
/// resource matcher; an unavailable matcher covers nothing.
pub(crate) fn resource_covers(
    context: &TrustedContext,
    namespace: &ResourceId,
    subject: &ResourceId,
) -> bool {
    with_gateway_registries(|registries| {
        registries
            .resource_matcher(context.accepted_registries(), context.resource_matcher())
            .is_some_and(|matcher| matcher.matches(namespace, subject).unwrap_or(false))
    })
    .unwrap_or(false)
}

/// Builds the gateway's immutable verifier registries: the principal methods
/// and suites it accepts plus the `mcp-arguments-v1` action-fact policy, all
/// committed in the verifier configuration a trusted context must pin.
fn with_gateway_registries<T>(check: impl FnOnce(&ImmutableRegistries<'_>) -> T) -> Option<T> {
    let raw_key = auths_raw_key::RawKeyMethod::new().ok()?;
    let did_key = auths_did_key::DidKeyMethod::new().ok()?;
    let did_keri = auths_did_keri::DidKeriMethod::new().ok()?;
    let ed25519 = auths_signature::Ed25519Suite::new().ok()?;
    let p256 = auths_signature::P256Sha256Suite::new().ok()?;
    let methods: [&dyn PrincipalMethod; 3] = [&raw_key, &did_key, &did_keri];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    with_mcp_arguments_registries(&methods, &suites, check).ok()
}

/// Returns the verifier configuration a gateway trusted context must pin.
///
/// # Errors
/// Returns `gateway.verify.registry-unavailable` only if a compiled registry
/// constant is invalid.
#[allow(
    clippy::redundant_closure_for_method_calls,
    reason = "the method path is not general over the registries' borrow lifetime"
)]
pub fn gateway_verifier_configuration() -> Result<VerifierConfigurationId, &'static str> {
    with_gateway_registries(|registries| registries.configuration_id())
        .ok_or("gateway.verify.registry-unavailable")
}

/// Verifies proof and action natively at the gateway clock `now`, admits the
/// action under every bounded policy in its authorized chain, and closes the
/// approved request from the verified command. Trust, registries, and the
/// installed challenge and audience come from the operator; only the
/// evaluation time is the gateway's own, so observation freshness, grant
/// validity, and the counting window are judged when the request arrives.
/// The returned admission, if any, is reserved atomically with the claim.
#[cfg(test)]
pub(crate) fn verify_command(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<(ClosedProviderRequest, Option<BoundAdmission>), GatewaySubmitResult> {
    verify_detailed(recipe, context, now, proof_cbor, action_cbor)
        .map(|verified| (verified.request, verified.bound))
}

/// A command the gateway would admit, with what admission and an auditor
/// need of its authorized branches.
#[derive(Clone, Debug)]
pub(crate) struct VerifiedCommand {
    pub(crate) request: ClosedProviderRequest,
    /// The bounded branch's links and the counters its claim reserves.
    pub(crate) bound: Option<BoundAdmission>,
    pub(crate) actors: Vec<auths_model::PrincipalId>,
    pub(crate) arguments: Map<String, Value>,
    /// Every observation requirement of every grant of every authorized
    /// branch.
    pub(crate) requirements: Vec<ObservationRequirement>,
    /// The verified canonical action, the source of action facts.
    pub(crate) canonical_action: CanonicalAction,
    /// The longest validity window, `expires_at` minus `not_before`, of any
    /// authorized action envelope.
    pub(crate) validity_seconds: u64,
}

/// [`verify_command`] that also reports what admission and an auditor need.
pub(crate) fn verify_detailed(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedCommand, GatewaySubmitResult> {
    if proof_cbor.is_empty()
        || proof_cbor.len() > MAX_PROOF_BYTES
        || action_cbor.is_empty()
        || action_cbor.len() > MAX_ACTION_BYTES
    {
        return Err(GatewaySubmitResult::Indeterminate {
            code: "gateway.submit.invalid-size".to_owned(),
        });
    }
    let request_context = context
        .for_request(
            context.expected_audience().clone(),
            context.expected_challenge(),
            Timestamp::new(now),
        )
        .ok()
        .and_then(|value| auths_codec::encode_verifier_context(&value).ok())
        .ok_or_else(|| GatewaySubmitResult::Indeterminate {
            code: "gateway.verify.invalid-trust".to_owned(),
        })?;
    let sealed = with_gateway_registries(|registries| {
        auths_verifier::verify_v1_sealed(proof_cbor, action_cbor, &request_context, registries)
    })
    .ok_or_else(indeterminate_registry)?
    .map_err(|_| GatewaySubmitResult::Indeterminate {
        code: "gateway.verify.invalid-input".to_owned(),
    })?;
    let Some(action) = sealed.action() else {
        let code = sealed.portable().code().code().to_owned();
        return Err(match sealed.portable().decision() {
            VerificationDecision::Denied => GatewaySubmitResult::Denied { code },
            VerificationDecision::Authorized | VerificationDecision::Indeterminate => {
                GatewaySubmitResult::Indeterminate { code }
            }
        });
    };
    let bound = admit_bounds(proof_cbor, action, recipe, now)?;
    let command = McpProfile
        .decode_verified(action)
        .map_err(|_| not_entered("gateway.action.projection"))?;
    let canonical = auths_codec::encode_canonical_action(action.canonical_action())
        .map_err(|_| not_entered("gateway.action.commitment"))?;
    let action_commitment = auths_codec::domain_commitment("auths.canonical-action.v1", &canonical)
        .map_err(|_| not_entered("gateway.action.commitment"))?;
    let request = recipe
        .closed_request(&command, *action_commitment.as_bytes())
        .map_err(|error| not_entered(error.code()))?;
    let branches = crate::bounds::authorized_branches(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    Ok(VerifiedCommand {
        request,
        bound,
        actors: branches.actors,
        arguments: command.arguments().clone(),
        requirements: branches.requirements,
        canonical_action: action.canonical_action().clone(),
        validity_seconds: branches.validity_seconds,
    })
}

fn indeterminate_registry() -> GatewaySubmitResult {
    GatewaySubmitResult::Indeterminate {
        code: "gateway.verify.registry-unavailable".to_owned(),
    }
}

pub(crate) fn not_entered(code: &'static str) -> GatewaySubmitResult {
    GatewaySubmitResult::NotEntered {
        code: code.to_owned(),
    }
}

pub(crate) fn replay_refused() -> GatewaySubmitResult {
    not_entered("gateway.attempt.replay")
}

fn wall_clock_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|elapsed| elapsed.as_secs())
}

/// Signs the stored stage and commitment of one logical operation.
pub(crate) async fn observe_outcome(
    attempts: &GatewayAttempts,
    namespace: &crate::OperatorNamespace,
    observer: &GatewayObserver,
    operation_id: &str,
    now: u64,
) -> GatewayObserveResult {
    let Ok(operation) = crate::LogicalOperationId::parse(operation_id) else {
        return refused("gateway.observer.invalid-operation");
    };
    let snapshot = match attempts.read(namespace, &operation).await {
        Ok(Some(value)) => value,
        Ok(None) => return refused("gateway.observer.operation-unknown"),
        Err(_) => return refused("gateway.observer.store-unavailable"),
    };
    outcome_facts(&snapshot)
        .and_then(|facts| {
            observer.sign(
                OUTCOME_SCHEMA,
                &operation_subject(namespace, &operation),
                now,
                facts,
            )
        })
        .map_or_else(|error| refused(error.code()), GatewayObserveResult::from)
}

/// Performs one read-only observation and signs what it read. The observation
/// time is taken before the request is sent, so the signed time is never later
/// than the provider state the response reflects.
pub(crate) async fn observe_read_back(
    target: &ClosedObservationRequest,
    observer: &GatewayObserver,
    port: &impl ProviderPort,
    clock: impl Fn() -> Option<u64>,
) -> GatewayObserveResult {
    let Some(observed_at) = clock() else {
        return refused("gateway.observer.clock-unavailable");
    };
    let Some(bytes) = port
        .action_read(
            target.url(),
            target.headers(),
            target.maximum_response_bytes(),
        )
        .await
        .and_then(|response| response.usable_body().map(<[u8]>::to_vec))
    else {
        return refused("gateway.observer.read-unavailable");
    };
    let Some((value, echo)) = target.observed_values(&bytes) else {
        return refused("gateway.observer.value-unavailable");
    };
    read_back_facts(&value, echo.as_ref())
        .and_then(|facts| observer.sign(READ_BACK_SCHEMA, &target.subject(), observed_at, facts))
        .map_or_else(|error| refused(error.code()), GatewayObserveResult::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn airtable_recipe() -> CompiledRecipe {
        CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("fixture compiles")
    }

    // Connection administration over the persistent stores an installed
    // gateway uses. Entry is checked through `prepare_entry`, which every
    // submission and read-back passes before any claim, lease, or write.
    #[cfg(unix)]
    mod administration {
        use super::*;

        struct Installation {
            _state: tempfile::TempDir,
            credentials_directory: std::path::PathBuf,
            connections_directory: std::path::PathBuf,
            connection_id: auths_connections::ConnectionId,
            engine: GatewayEngine,
        }

        fn private_directory(path: &std::path::Path) {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::create_dir(path).expect("directory");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
        }

        fn gateway_secret(value: &str) -> SecretBytes {
            SecretBytes::new(value.as_bytes().to_vec()).expect("secret")
        }

        fn candidate(value: &str) -> zeroize::Zeroizing<Vec<u8>> {
            zeroize::Zeroizing::new(value.as_bytes().to_vec())
        }

        async fn installation(credential_entries: usize) -> Installation {
            let state = tempfile::tempdir().expect("state");
            let credentials_directory = state.path().join("credentials");
            let connections_directory = state.path().join("connections");
            private_directory(&credentials_directory);
            private_directory(&connections_directory);
            let recipe = airtable_recipe();
            let root = crate::harness::Signer::new(0x11);
            let observer = crate::harness::Signer::new(0x33);
            let trust = auths_codec::encode_verifier_context(
                &crate::harness::context(&root, &observer.principal, None, 1_790_000_000)
                    .expect("context"),
            )
            .expect("trust");
            let credentials = PersistentCredentialStore::open_with_limits(
                credentials_directory.join("credentials.cbor"),
                credential_entries,
                1 << 20,
            )
            .expect("credential store");
            let connection_id =
                auths_connections::ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
            let generation = std::num::NonZeroU64::new(1).expect("generation");
            let reference = credentials
                .install(&connection_id, generation, gateway_secret("pat-initial"))
                .await
                .expect("install");
            let profile = ConnectionProfile::new(
                auths_connections::SemanticId::parse("auths.mcp").expect("profile"),
                2,
            )
            .expect("profile");
            let record = ConnectionRecord::new(
                ProviderKind::parse("airtable").expect("provider"),
                ConnectionAlias::parse("primary").expect("alias"),
                connection_id.clone(),
                auths_connections::SemanticId::parse("auths.gateway-operation/1")
                    .expect("contract"),
                auths_connections::SemanticId::parse("auths.gateway-connection-descriptor/1")
                    .expect("schema"),
                GatewayConnectionDescriptor::approve(&recipe, "Authorization")
                    .expect("descriptor")
                    .to_bytes()
                    .expect("descriptor bytes"),
                [4; 32],
                *reference.as_bytes(),
                generation,
                ConnectionState::Active,
                vec!["gateway".to_owned()],
                vec![profile.clone()],
                10,
                10,
                None,
            )
            .expect("record");
            let connections = PersistentConnectionStore::open(
                connections_directory.join("connections.cbor"),
                auths_connections::RegistryLimits::default(),
            )
            .expect("connection store");
            connections.insert(record).expect("insert");
            let attempts_root = std::fs::canonicalize(state.path())
                .expect("canonical state")
                .join("attempts");
            let attempts = GatewayAttempts::new(std::sync::Arc::new(
                crate::FileGatewayAttemptStore::open(attempts_root).expect("attempts"),
            ));
            let digest = *recipe.digest();
            let engine = GatewayEngine::new(
                recipe,
                digest,
                &trust,
                ProviderKind::parse("airtable").expect("provider"),
                ConnectionAlias::parse("primary").expect("alias"),
                "gateway".to_owned(),
                profile,
                connections,
                credentials,
                attempts,
            )
            .expect("engine");
            Installation {
                _state: state,
                credentials_directory,
                connections_directory,
                connection_id,
                engine,
            }
        }

        impl Installation {
            fn stored(&self) -> Vec<u64> {
                self.engine
                    .credentials
                    .stored_generations(&self.connection_id)
                    .expect("stored generations")
                    .into_iter()
                    .map(std::num::NonZeroU64::get)
                    .collect()
            }

            fn record(&self) -> ConnectionRecord {
                self.engine
                    .connections
                    .load(&self.engine.provider, &self.engine.alias)
                    .expect("load")
                    .expect("record")
            }

            /// The refusal code of a new entry, or `None` when entry may lease.
            fn entry_refusal(&self) -> Option<String> {
                self.engine.prepare_entry().err().map(str::to_owned)
            }
        }

        #[tokio::test]
        async fn revocation_after_rotation_and_disable_deletes_every_generation() {
            let installation = installation(8).await;
            let (first, _) = installation.engine.prepare_entry().expect("active entry");
            assert!(installation.engine.lease(&first).await.is_ok());

            installation
                .engine
                .rotate_connection(candidate("pat-rotated"))
                .await
                .expect("rotate");
            assert_eq!(
                installation.stored(),
                [2],
                "rotation deletes the old secret"
            );
            assert!(installation.engine.lease(&first).await.is_err());
            assert_eq!(installation.entry_refusal(), None);

            installation
                .engine
                .disable_connection()
                .await
                .expect("disable");
            assert_eq!(installation.stored(), [2], "disabling stores no credential");
            assert_eq!(
                installation.entry_refusal().as_deref(),
                Some("gateway.connection.unavailable")
            );

            installation
                .engine
                .revoke_connection()
                .await
                .expect("revoke");
            assert!(installation.stored().is_empty());
            let revoked = installation.record();
            assert_eq!(revoked.state(), ConnectionState::Revoked);
            assert_eq!(revoked.generation().get(), 4);
            assert_eq!(
                installation.entry_refusal().as_deref(),
                Some("gateway.connection.unavailable")
            );
        }

        #[tokio::test]
        async fn a_rotation_failing_after_its_credential_write_is_discarded() {
            let installation = installation(8).await;
            // A file where the connection store's directory was makes the record
            // write fail after the successor credential is stored.
            let moved = installation.connections_directory.with_extension("moved");
            std::fs::rename(&installation.connections_directory, &moved).expect("move");
            std::fs::write(&installation.connections_directory, b"blocked").expect("block");
            assert_eq!(
                installation
                    .engine
                    .rotate_connection(candidate("pat-rotated"))
                    .await,
                Err("gateway.admin.transition-unavailable")
            );
            std::fs::remove_file(&installation.connections_directory).expect("unblock");
            std::fs::rename(&moved, &installation.connections_directory).expect("restore");
            assert_eq!(
                installation.stored(),
                [1],
                "the unpublished successor is gone"
            );
            assert_eq!(installation.record().generation().get(), 1);
            assert_eq!(installation.entry_refusal(), None);

            installation
                .engine
                .revoke_connection()
                .await
                .expect("revoke");
            assert!(installation.stored().is_empty());
        }

        #[tokio::test]
        async fn disable_and_revoke_need_no_free_credential_capacity() {
            let installation = installation(1).await;
            assert_eq!(
                installation
                    .engine
                    .rotate_connection(candidate("pat-rotated"))
                    .await,
                Err("gateway.admin.credential-unavailable"),
                "the full store has no room for a successor"
            );
            installation
                .engine
                .disable_connection()
                .await
                .expect("disable");
            installation
                .engine
                .revoke_connection()
                .await
                .expect("revoke");
            assert!(installation.stored().is_empty());
            assert_eq!(installation.record().state(), ConnectionState::Revoked);
        }

        #[tokio::test]
        async fn a_repeated_revoke_finishes_the_credential_deletion() {
            use std::os::unix::fs::PermissionsExt as _;
            let installation = installation(8).await;
            // The credential store refuses to write into a directory other users
            // can read, so the deletion fails after the record is revoked.
            std::fs::set_permissions(
                &installation.credentials_directory,
                std::fs::Permissions::from_mode(0o750),
            )
            .expect("mode");
            assert_eq!(
                installation.engine.revoke_connection().await,
                Err("gateway.admin.credential-deletion-incomplete")
            );
            std::fs::set_permissions(
                &installation.credentials_directory,
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("mode");
            assert_eq!(installation.record().state(), ConnectionState::Revoked);
            assert_eq!(installation.stored(), [1]);
            assert_eq!(
                installation.entry_refusal().as_deref(),
                Some("gateway.connection.unavailable"),
                "the revoked record withholds the lease while the secret is stored"
            );

            installation
                .engine
                .revoke_connection()
                .await
                .expect("repeated revoke");
            assert!(installation.stored().is_empty());
            assert_eq!(
                installation.engine.disable_connection().await,
                Err("gateway.admin.connection-not-active")
            );
        }
    }
}
