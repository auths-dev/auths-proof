//! Native-verified, digest-bound execution coordinator. Attempts persist in
//! the single-host file store or the multi-host `PostgreSQL` store; connection
//! state is per process.

// Explicit matches keep each verification and transport failure mapped to its
// distinct public stage; `let...else` would obscure those boundary decisions.
#![allow(clippy::manual_let_else)]

use crate::bounds::{WindowReservation, admit_bounds};
use crate::observer::{
    GatewayObserver, GatewaySignedObservation, OUTCOME_SCHEMA, READ_BACK_SCHEMA, operation_subject,
    outcome_facts, read_back_facts,
};
use crate::recipe::ReadBack;
use crate::transport::{
    GatewayHttpTransport, LeasedTransport, ProviderPort, WriteTransportOutcome,
};
use crate::{
    ClaimedGatewayAttempt, ClosedObservationRequest, ClosedProviderRequest, CompiledRecipe,
    GatewayAttemptError, GatewayAttempts, GatewayConnectionDescriptor, GatewayEvidenceChannel,
    GatewayProviderEvidence, ObservableGatewayAttempt,
};
use auths_connections::{
    ConnectionAlias, ConnectionBinding, ConnectionCredentialStore, ConnectionProfile,
    ConnectionState, PersistentCredentialStore, ProviderKind, SecretBytes, StoredSecretLease,
};
use auths_model::{Timestamp, TrustedContext, VerificationDecision, VerifierConfigurationId};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{McpProfile, with_mcp_arguments_registries};
use auths_registries::ImmutableRegistries;
use auths_stores::PersistentConnectionStore;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
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
    /// Refuses missing trust or a changed recipe.
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
        let Some(now) = wall_clock_seconds() else {
            return GatewaySubmitResult::Indeterminate {
                code: "gateway.verify.clock-unavailable".to_owned(),
            };
        };
        let (request, bound) = match verify_command(
            &self.recipe,
            &self.trusted_context,
            now,
            proof_cbor,
            action_cbor,
        ) {
            Ok(value) => value,
            Err(result) => return result,
        };
        let _guard = self.administrative_gate.read().await;
        let (binding, transport) = match self.prepare_entry() {
            Ok(value) => value,
            Err(result) => return result,
        };
        let claim = match self.attempts.claim(&request, *self.recipe.digest()).await {
            Ok(value) => value,
            Err(GatewayAttemptError::Replay) => {
                return self
                    .observe_after_replay(&request, &binding, &transport)
                    .await;
            }
            Err(_) => return not_entered("gateway.attempt.unavailable"),
        };
        let claim = match reserve_bound(&self.attempts, bound.as_ref(), &request, claim).await {
            Ok(value) => value,
            Err(result) => return result,
        };
        let lease = match self.lease(&binding).await {
            Ok(value) => value,
            Err(()) => return checkpoint_not_entered(claim).await,
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
        #[cfg(feature = "loopback-provider")]
        if let Some(port) = self.loopback_port {
            return GatewayHttpTransport::prepare_loopback(
                &self.recipe,
                descriptor.credential(),
                port,
            )
            .map(|transport| (binding, transport))
            .map_err(|_| not_entered("gateway.transport.preparation"));
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
            .await
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

    /// Signs one observation for the application. A read-back uses the
    /// installed connection and credential for exactly one bounded read-only
    /// GET built from the approved recipe; an outcome reads only the local
    /// attempt store. Nothing here writes to a provider or to the store.
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
                observe_read_back(&target, observer, &port, wall_clock_seconds).await
            }
        }
    }
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
/// The returned reservation, if any, is taken after the claim.
pub(crate) fn verify_command(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<(ClosedProviderRequest, Option<WindowReservation>), GatewaySubmitResult> {
    verify_detailed(recipe, context, now, proof_cbor, action_cbor)
        .map(|verified| (verified.request, verified.bound))
}

/// A command the gateway would admit, with the actors of its authorized
/// branches.
pub(crate) struct VerifiedCommand {
    pub(crate) request: ClosedProviderRequest,
    pub(crate) bound: Option<WindowReservation>,
    pub(crate) actors: Vec<auths_model::PrincipalId>,
    pub(crate) arguments: Map<String, Value>,
}

/// [`verify_command`] that also reports what an auditor needs.
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
    let bound = admit_bounds(proof_cbor, action, recipe.namespace(), now)?;
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
    let actors = crate::bounds::authorized_actors(proof_cbor, action)
        .map_err(|_| not_entered("gateway.policy.proof-unavailable"))?;
    Ok(VerifiedCommand {
        request,
        bound,
        actors,
        arguments: command.arguments().clone(),
    })
}

/// Reserves the bound's window slot for a fresh claim before any lease. An
/// exhausted or unavailable count leaves the claim `not-entered`.
pub(crate) async fn reserve_bound(
    attempts: &GatewayAttempts,
    bound: Option<&WindowReservation>,
    request: &ClosedProviderRequest,
    claim: ClaimedGatewayAttempt,
) -> Result<ClaimedGatewayAttempt, GatewaySubmitResult> {
    let Some(bound) = bound else {
        return Ok(claim);
    };
    match attempts.reserve_window(bound, request.operation_id()).await {
        Ok(()) => Ok(claim),
        Err(refusal) => Err(match claim.record_not_entered().await {
            Ok(_) => not_entered(refusal.code()),
            Err(_) => GatewaySubmitResult::Unknown,
        }),
    }
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

async fn checkpoint_not_entered(claim: ClaimedGatewayAttempt) -> GatewaySubmitResult {
    match claim.record_not_entered().await {
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
pub(crate) async fn execute_claimed(
    claim: ClaimedGatewayAttempt,
    request: &ClosedProviderRequest,
    port: &impl ProviderPort,
) -> GatewaySubmitResult {
    let write = match port.write(request).await {
        Ok(value) => value,
        Err(_) => return checkpoint_not_entered(claim).await,
    };
    match write {
        WriteTransportOutcome::Unknown => {
            let _ = claim.record_unknown().await;
            GatewaySubmitResult::Unknown
        }
        WriteTransportOutcome::ResponseRecorded { status, digest } => {
            let recorded = match claim.record_response(status, digest).await {
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
pub(crate) async fn reobserve(
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
                .await
                .ok()?;
            Some(GatewaySubmitResult::ObservedByProvider {
                status,
                evidence: snapshot.provider_evidence()?.into(),
            })
        }
        ReadBack::Value { matched } => {
            let status = status?;
            attempt.record_observation(matched).await.ok()?;
            Some(GatewaySubmitResult::Observed { status, matched })
        }
        ReadBack::EchoMismatch => {
            let status = status?;
            attempt.record_echo_mismatch().await.ok()?;
            Some(GatewaySubmitResult::Observed {
                status,
                matched: false,
            })
        }
    }
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
    let Some(bytes) = port.read_back(target).await else {
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
    use crate::store_testkit::{Backend, TestAttempts, postgres_configured};
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
        store: TestAttempts,
    }

    impl Harness {
        fn open(name: &str, backend: Backend) -> Self {
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
            Self {
                recipe: CompiledRecipe::compile(source, lock).expect("fixture compiles"),
                store: TestAttempts::open(backend),
            }
        }

        fn restart(&mut self) {
            self.store.restart();
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
            submit_on(self.store.attempts(), &self.recipe, request, provider).await
        }

        async fn snapshot(&self, request: &ClosedProviderRequest) -> GatewayAttemptSnapshot {
            self.store
                .attempts()
                .read(request.namespace(), request.operation_id())
                .await
                .expect("read")
                .expect("retained claim")
        }

        async fn describe(&self, request: &ClosedProviderRequest) -> String {
            let snapshot = self.snapshot(request).await;
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

    /// The engine's post-verification dispatch over one attempt store.
    async fn submit_on(
        attempts: &crate::GatewayAttempts,
        recipe: &CompiledRecipe,
        request: &ClosedProviderRequest,
        provider: &CountingProvider,
    ) -> GatewaySubmitResult {
        match attempts.claim(request, *recipe.digest()).await {
            Ok(claim) => execute_claimed(claim, request, provider).await,
            Err(GatewayAttemptError::Replay) => {
                match attempts.resume_observable(request, *recipe.digest()).await {
                    Ok(Some(attempt)) => reobserve(attempt, request, provider).await,
                    _ => replay_refused(),
                }
            }
            Err(_) => not_entered("gateway.attempt.unavailable"),
        }
    }

    async fn run_claim_case(id: &str, backend: Backend) -> (String, usize) {
        let mut harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        drop(
            harness
                .store
                .attempts()
                .claim(&original, *harness.recipe.digest())
                .await
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
                format!(
                    "attempting->{}-on-restart",
                    harness.describe(&original).await
                )
            }
            _ => panic!("unhandled claim scenario {id}"),
        };
        assert_eq!(provider.reads(), 0, "{id}");
        (transition, provider.writes())
    }

    async fn run_first_attempt_case(id: &str, backend: Backend) -> (String, usize) {
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
            backend,
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
            format!("{from}->{}", harness.describe(&request).await),
            provider.writes(),
        )
    }

    async fn run_resolution_case(id: &str, backend: Backend) -> (String, usize) {
        let (delivery, reading) = match id {
            "lost-write-echo-absent" => (Delivery::LostBeforeApplying, Reading::Faithful),
            "unknown-echo-overwritten" => (Delivery::TimeoutAfterApplying, Reading::ForeignEcho),
            "fresh-challenge-after-observed-by-provider" => (Delivery::Respond, Reading::Faithful),
            _ => (Delivery::TimeoutAfterApplying, Reading::Faithful),
        };
        let mut harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(delivery, reading);
        let original = harness.airtable(ORIGINAL, "Approved");
        let first = harness.submit(&original, &provider).await;
        let before = harness.describe(&original).await;
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
            harness.snapshot(&original).await.stage(),
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
            format!("{before}->{}", harness.describe(&original).await),
            provider.writes(),
        )
    }

    async fn run_crash_after_entry_case(backend: Backend) -> (String, usize) {
        let mut harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        let claim = harness
            .store
            .attempts()
            .claim(&original, *harness.recipe.digest())
            .await
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
            format!(
                "attempting->{}-on-restart",
                harness.describe(&original).await
            ),
            provider.writes(),
        )
    }

    /// Drives the pre-generated attempt-scenario corpus against `backend`.
    async fn attempt_scenario_corpus(backend: Backend) {
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
                | "crash-after-claim" => run_claim_case(id, backend).await,
                "crash-after-entry-not-reobserved" => run_crash_after_entry_case(backend).await,
                "timeout-after-delivery-read-back"
                | "lost-write-echo-absent"
                | "unknown-echo-overwritten"
                | "restart-during-unknown"
                | "changed-action-during-unknown"
                | "fresh-challenge-after-observed-by-provider" => {
                    run_resolution_case(id, backend).await
                }
                _ => run_first_attempt_case(id, backend).await,
            };
            assert_eq!(transition, case["transition"], "{}: {id}", backend.label());
            assert_eq!(
                u64::try_from(writes).expect("count"),
                case["provider_entries"].as_u64().expect("entries"),
                "{}: {id}",
                backend.label()
            );
        }
    }

    #[tokio::test]
    async fn attempt_scenario_corpus_drives_the_counting_provider() {
        attempt_scenario_corpus(Backend::File).await;
    }

    #[tokio::test]
    #[ignore = "needs the TLS PostgreSQL fixture"]
    async fn postgres_attempt_scenario_corpus_drives_the_counting_provider() {
        assert!(
            postgres_configured(),
            "TLS PostgreSQL environment slots are required"
        );
        attempt_scenario_corpus(Backend::Postgres).await;
    }

    #[tokio::test]
    async fn normal_write_reaches_observed_by_provider_with_secret_free_evidence() {
        let harness = Harness::open("airtable", Backend::File);
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let request = harness.airtable(ORIGINAL, "Approved");
        let result = harness.submit(&request, &provider).await;
        let snapshot = harness.snapshot(&request).await;
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

    // One shared conformance suite for every attempt store. The file store
    // runs it on every test run; the PostgreSQL store runs it
    // against the TLS fixture in the PostgreSQL lifecycle workflow.

    /// A logical operation enters the provider exactly once; an identical
    /// replay neither writes nor reads.
    async fn conformance_claim_exactly_once_and_replay(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        assert!(matches!(
            harness.submit(&original, &provider).await,
            GatewaySubmitResult::ObservedByProvider { .. }
        ));
        for _ in 0..3 {
            assert_eq!(harness.submit(&original, &provider).await, replay_refused());
        }
        assert!(matches!(
            harness
                .store
                .attempts()
                .claim(&original, *harness.recipe.digest())
                .await,
            Err(GatewayAttemptError::Replay)
        ));
        assert_eq!((provider.writes(), provider.reads()), (1, 1));
    }

    /// A fresh challenge, or a changed action, under the same logical ID is
    /// the same operation and never a second entry.
    async fn conformance_fresh_challenge(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        let first = harness
            .submit(&harness.airtable(ORIGINAL, "Approved"), &provider)
            .await;
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

    /// An unknown write is resolved only by a later read-only observation on
    /// another store instance, against the original echo token.
    async fn conformance_unknown_and_reobserve(backend: Backend) {
        let mut harness = Harness::open("airtable", backend);
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

    /// A foreign echo token is recorded as `echo-mismatch`, never as the
    /// attempt's own evidence.
    async fn conformance_echo_mismatch(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::Respond, Reading::ForeignEcho);
        let request = harness.airtable(ORIGINAL, "Approved");
        assert_eq!(
            harness.submit(&request, &provider).await,
            GatewaySubmitResult::Observed {
                status: 200,
                matched: false
            }
        );
        let snapshot = harness.snapshot(&request).await;
        assert_eq!(snapshot.stage(), GatewayAttemptStage::Observed);
        assert_eq!(
            snapshot.observation_fact(),
            Some(GatewayObservationFact::EchoMismatch)
        );
        assert!(snapshot.provider_evidence().is_none());
        assert_eq!(provider.writes(), 1);
    }

    /// Two store instances re-observing the same unknown attempt record
    /// exactly one terminal stage; the other records nothing.
    async fn conformance_concurrent_reobservation(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let provider = CountingProvider::new(Delivery::TimeoutAfterApplying, Reading::Faithful);
        let original = harness.airtable(ORIGINAL, "Approved");
        assert_eq!(
            harness.submit(&original, &provider).await,
            GatewaySubmitResult::Unknown
        );
        let first = harness.store.reopen();
        let second = harness.store.reopen();
        let request = harness.airtable(FRESH, "Approved");
        let digest = *harness.recipe.digest();
        let left = first
            .resume_observable(&request, digest)
            .await
            .expect("resume")
            .expect("observable");
        let right = second
            .resume_observable(&request, digest)
            .await
            .expect("resume")
            .expect("observable");
        let (left, right) = tokio::join!(
            reobserve(left, &request, &provider),
            reobserve(right, &request, &provider)
        );
        let terminal = [&left, &right]
            .iter()
            .filter(|result| matches!(result, GatewaySubmitResult::ObservedByProvider { .. }))
            .count();
        assert_eq!(terminal, 1, "{left:?} {right:?}");
        assert!(left == replay_refused() || right == replay_refused());
        assert_eq!(
            harness.snapshot(&original).await.stage(),
            GatewayAttemptStage::ObservedByProvider
        );
        assert_eq!(provider.writes(), 1);
    }

    /// Replacement is compare-and-swap on the exact stored bytes, and stored
    /// bytes that do not decode fail closed rather than read as unclaimed.
    async fn conformance_mechanism_fails_closed(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let raw = harness.store.raw();
        let key = crate::GatewayAttemptKey::for_operation(
            harness.recipe.namespace(),
            &LogicalOperationId::parse("run-1").expect("operation"),
        );
        tokio::task::spawn_blocking(move || {
            raw.insert(&key, b"{}").expect("insert");
            assert_eq!(raw.insert(&key, b"{}"), Err(GatewayAttemptError::Replay));
            assert_eq!(
                raw.replace(&key, b"{\"other\":1}", b"[]"),
                Err(GatewayAttemptError::Conflict)
            );
            raw.replace(&key, b"{}", b"[]").expect("exact replacement");
            assert_eq!(raw.load(&key).expect("load").as_deref(), Some(&b"[]"[..]));
        })
        .await
        .expect("mechanism checks");
        let request = harness.airtable(ORIGINAL, "Approved");
        assert_eq!(
            harness
                .store
                .attempts()
                .read(request.namespace(), request.operation_id())
                .await,
            Err(GatewayAttemptError::Corrupt)
        );
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        assert_eq!(harness.submit(&request, &provider).await, replay_refused());
        assert_eq!(provider.writes(), 0);
    }

    const RACE_OPERATIONS: usize = 48;
    const CHILD: &str = "AUTHS_GATEWAY_CONFORMANCE_CHILD";

    /// Two separate gateway processes race to claim the same logical
    /// operations; each operation enters the provider exactly once.
    async fn conformance_concurrent_claims_from_two_processes(backend: Backend) {
        let harness = Harness::open("airtable", backend);
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis()
            + 1_500;
        let children: Vec<_> = (0..2)
            .map(|_| {
                std::process::Command::new(std::env::current_exe().expect("test binary"))
                    .args([
                        "--exact",
                        "engine::tests::conformance_child_process",
                        "--ignored",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env(
                        CHILD,
                        format!("{}|{}|{start}", backend.label(), harness.store.location()),
                    )
                    .stdout(std::process::Stdio::piped())
                    .spawn()
                    .expect("child gateway process")
            })
            .collect();
        let mut claimed = 0;
        let mut entries = 0;
        for child in children {
            let output = child.wait_with_output().expect("child exit");
            assert!(output.status.success(), "child failed");
            let text = String::from_utf8(output.stdout).expect("utf-8");
            let line = text
                .lines()
                .find_map(|line| line.split_once("RACE ").map(|(_, counts)| counts))
                .expect("child result");
            let fields: Vec<usize> = line
                .split(' ')
                .map(|value| value.parse().expect("count"))
                .collect();
            claimed += fields[0];
            entries += fields[1];
        }
        assert_eq!(claimed, RACE_OPERATIONS, "{}", backend.label());
        assert_eq!(entries, RACE_OPERATIONS, "{}", backend.label());
        for index in 0..RACE_OPERATIONS {
            let request = race_request(&harness, index);
            assert_eq!(
                harness.snapshot(&request).await.stage(),
                GatewayAttemptStage::ObservedByProvider
            );
        }
    }

    fn race_request(harness: &Harness, index: usize) -> ClosedProviderRequest {
        harness.request(
            ORIGINAL,
            &json!({"operation_id": format!("race-{index}"), "record_id": RECORD, "replacement": "Approved"}),
        )
    }

    /// Child half of the two-process race. It does nothing unless spawned by
    /// the parent with the store location.
    #[tokio::test]
    #[ignore = "spawned by the two-process conformance case"]
    async fn conformance_child_process() {
        let Ok(spec) = std::env::var(CHILD) else {
            return;
        };
        let parts: Vec<&str> = spec.splitn(3, '|').collect();
        let backend = Backend::parse(parts[0]);
        let store = TestAttempts::attach(backend, parts[1]);
        let start: u128 = parts[2].parse().expect("start");
        let harness = Harness {
            recipe: Harness::open("airtable", Backend::File).recipe,
            store,
        };
        let provider = CountingProvider::new(Delivery::Respond, Reading::Faithful);
        while SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_millis()
            < start
        {
            std::thread::yield_now();
        }
        let mut claimed = 0;
        for index in 0..RACE_OPERATIONS {
            let request = race_request(&harness, index);
            if let Ok(claim) = harness
                .store
                .attempts()
                .claim(&request, *harness.recipe.digest())
                .await
            {
                claimed += 1;
                execute_claimed(claim, &request, &provider).await;
            }
        }
        println!("RACE {claimed} {}", provider.writes());
    }

    async fn store_conformance(backend: Backend) {
        conformance_claim_exactly_once_and_replay(backend).await;
        conformance_fresh_challenge(backend).await;
        conformance_unknown_and_reobserve(backend).await;
        conformance_echo_mismatch(backend).await;
        conformance_concurrent_reobservation(backend).await;
        conformance_mechanism_fails_closed(backend).await;
        conformance_concurrent_claims_from_two_processes(backend).await;
    }

    #[tokio::test]
    async fn file_store_passes_attempt_store_conformance() {
        store_conformance(Backend::File).await;
    }

    #[tokio::test]
    #[ignore = "needs the TLS PostgreSQL fixture"]
    async fn postgres_store_passes_attempt_store_conformance() {
        assert!(
            postgres_configured(),
            "TLS PostgreSQL environment slots are required"
        );
        store_conformance(Backend::Postgres).await;
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
