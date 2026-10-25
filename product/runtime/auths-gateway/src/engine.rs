//! Native-verified, digest-bound execution coordinator. Attempts and the
//! connection record persist in the single-host file store or the multi-host
//! `PostgreSQL` store; each process keeps its own credential store.

// Explicit matches keep each verification and transport failure mapped to its
// distinct public stage; `let...else` would obscure those boundary decisions.
#![allow(clippy::manual_let_else)]

use crate::bounds::{BoundAdmission, admit_bounds};
use crate::connection::{
    LoadedConnection, SharedConnection, SharedConnectionError, authorizes_entry,
};
use crate::observer::{
    GatewayObserver, GatewaySignedObservation, OUTCOME_SCHEMA, READ_BACK_SCHEMA, operation_subject,
    outcome_facts, read_back_facts,
};
use crate::recipe::{ENTRY_DEADLINE_SECONDS, GuardChecks};
#[cfg(unix)]
use crate::release_state::FileReleaseTaskLedger;
use crate::submit::{self, SubmitContext, SubmitIo};
#[cfg(unix)]
use crate::task_activation::{
    APPROVAL_TOOL, ApprovedAgentTask, TASK_SERVICE, TaskActivationPins, WriteApprovalMode,
    verify_task_activation,
};
#[cfg(unix)]
use crate::task_effect_plan::verify_effect_plan;
#[cfg(unix)]
use crate::task_populate_attestation::{ExpectedPopulatePreflight, verify_populate_preflight};
#[cfg(unix)]
use crate::task_write::{
    ApprovedTaskWrite, CONFIRMATION_TOOL, TaskWriteBinding, admit_bounded_upfront_write,
    derive_exact_write_intent, verify_exact_write_confirmation,
};
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
    ConnectionAlias, ConnectionCredentialStore, ConnectionProfile, ConnectionRecord,
    ConnectionState, ProviderKind, SecretBytes, StoredSecretLease,
};
use auths_model::{
    Audience, CanonicalAction, ObservationRequirement, ResourceId, Timestamp, TrustedContext,
    VerificationDecision, VerifierConfigurationId,
};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_profile_api::ActionProfile;
#[cfg(unix)]
use auths_profile_mcp::McpToolCall;
use auths_profile_mcp::{McpProfile, with_mcp_arguments_registries};
use auths_registries::ImmutableRegistries;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[cfg(unix)]
#[path = "commissioning_session.rs"]
mod commissioning;
#[cfg(unix)]
#[path = "release_execute.rs"]
mod release_execute;
#[cfg(unix)]
pub use commissioning::{
    CommissioningSession, CommissioningSessionInputs, commissioning_principal_sha256,
};
#[cfg(unix)]
pub use release_execute::{ManagedReleaseResult, TaskReadOperatorInputs, TaskReadSession};

const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_ACTION_BYTES: usize = 64 * 1024;
const MAX_CONTEXT_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const TASK_INSTALLATION_SCHEMA: &str = "auths.gateway-task-installation/3";
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
    /// An independent process measurement scope could not be allocated.
    #[error("gateway execution witness unavailable")]
    WitnessUnavailable,
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

/// A verified submission's bounded, credential-free request projection for
/// offline operator review and differential qualification. It grants no
/// execution authority and records no claim, lease, provider entry or receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewaySubmissionReview {
    /// Exactly `auths.gateway-submission-review/1`.
    pub schema: &'static str,
    /// Every exact actor whose action branch the native verifier authorized.
    pub actors: Vec<String>,
    /// Native commitment to the verified canonical action bytes.
    pub action_commitment: String,
    /// Typed profile arguments decoded from the verified action.
    pub arguments: Map<String, Value>,
    /// The closed outbound request, before any credential is attached.
    pub request: GatewayRequestReview,
}

/// Public request facts used to compare an independently reviewed oracle.
/// No authorization header or provider response is included.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GatewayRequestReview {
    /// Closed HTTP method.
    pub method: String,
    /// Recipe-derived HTTPS URL.
    pub url: String,
    /// Recipe-derived body media type.
    pub content_type: String,
    /// Exact bounded UTF-8 JSON or form body.
    pub body: String,
    /// Ordered recipe-derived headers, without credential material.
    pub headers: Vec<(String, String)>,
    /// Declared derived idempotency key, if any.
    pub idempotency_key: Option<String>,
}

/// Reviews proof and action through the same native verification and closed
/// request construction as submission, without opening custody or a store.
/// `now` is an offline evaluation input; this function grants no lease and
/// cannot replace the production deployment clock.
///
/// # Errors
/// Returns the exact native/profile refusal for invalid or unauthorized input.
/// A successful review establishes only offline eligibility; lifecycle,
/// qualification, custody, guard, evidence and capacity checks still apply
/// when the operator submits through an installed gateway.
#[cfg(unix)]
pub fn review_submission(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    now: u64,
    proof: &[u8],
    action: &[u8],
) -> Result<GatewaySubmissionReview, GatewaySubmitResult> {
    let command = verify_detailed(recipe, context, now, proof, action)?;
    let request = &command.request;
    Ok(GatewaySubmissionReview {
        schema: "auths.gateway-submission-review/1",
        actors: command
            .actors
            .iter()
            .map(|actor| actor.as_str().to_owned())
            .collect(),
        action_commitment: hex::encode(request.action_commitment()),
        arguments: command.arguments,
        request: GatewayRequestReview {
            method: request.method().as_str().to_owned(),
            url: request.url().to_owned(),
            content_type: request.content_type().to_owned(),
            body: std::str::from_utf8(request.body())
                .map_err(|_| not_entered("gateway.action.projection"))?
                .to_owned(),
            headers: request
                .headers()
                .iter()
                .map(|header| (header.name().to_owned(), header.value().to_owned()))
                .collect(),
            idempotency_key: request.idempotency_key().map(str::to_owned),
        },
    })
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
    /// Sign the stored record of one logical operation in this
    /// installation's namespace. No provider is contacted.
    Outcome { operation_id: String },
    /// Return the signed pre-entry observations stored for one logical
    /// operation. Nothing is signed and no provider is contacted.
    PreEntry { operation_id: String },
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
    /// The signed pre-entry observations stored for `operation_id`, in
    /// pointer order, each unpadded base64url; empty when none were
    /// recorded.
    PreEntry {
        operation_id: String,
        observations_b64: Vec<String>,
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

/// How long an admin change waits, after committing, for this process's
/// in-flight entries to finish.
const DRAIN_LIMIT: Duration = Duration::from_secs(20);
/// Compare-and-swap rounds an admin state change retries when another
/// process changes the record between its load and its replacement.
const ADMIN_ROUNDS: usize = 8;

/// The result of one admin change: its code, and whether this process's
/// in-flight entries finished within the drain limit after the commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GatewayAdminOutcome {
    /// The stable code of the change.
    pub code: &'static str,
    /// Whether this process's in-flight count reached zero.
    pub drained: bool,
    /// This process's in-flight count when the change answered.
    pub in_flight: u64,
}

/// Secret-free connection state for the operator's `status` command.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayAdminStatus {
    /// `active`, `disabled`, or `revoked`.
    pub state: String,
    /// The shared record's generation.
    pub generation: u64,
    /// The generation of the last install or rotation.
    pub credential_generation: u64,
    /// Whether this process holds the secret the record commits to.
    pub credential_held: bool,
    /// This process's in-flight entries.
    pub in_flight: u64,
    /// The gateway clock of this process's last successful slot sweep;
    /// absent until one completes.
    pub last_sweep: Option<u64>,
    /// The gateway clock when the status was read; not authenticated.
    pub gateway_clock: u64,
}

/// One immutable installed operation and independently provisioned trust.
///
/// The connection record is shared through the attempt store by every
/// process installed on it; each process keeps only its own credential
/// store. A submission loads the shared record before its claim and reloads
/// it before the lease and again before entry, so a disable, rotation, or
/// revocation committed through any process stops new leases and entries in
/// every process at its next reload. Admin changes commit by
/// compare-and-swap without waiting for any submission or provider call.
pub struct GatewayEngine {
    recipe: CompiledRecipe,
    trusted_context: TrustedContext,
    #[cfg(unix)]
    trusted_context_sha256: auths_recipe_qualification::Sha256Digest,
    observer: Option<GatewayObserver>,
    workload_id: String,
    profile: ConnectionProfile,
    connection: SharedConnection,
    credentials: Arc<dyn ConnectionCredentialStore>,
    credential_journal: Option<crate::CredentialJournal>,
    /// Whether this deployment's recipe is qualified; consulted before every
    /// lease.
    qualification: Arc<crate::QualificationGate>,
    attempts: GatewayAttempts,
    in_flight: AtomicU64,
    execution_witness: Arc<crate::execution_witness::ExecutionWitness>,
    /// The gateway clock of the last successful slot sweep; zero before one.
    last_sweep: AtomicU64,
    drain_limit: Duration,
    /// How long a superseded credential generation is kept after the shared
    /// record commits its successor.
    retirement_delay: Duration,
    /// Superseded generations this process still has to retire.
    retirements: std::sync::Mutex<Vec<Retirement>>,
    #[cfg(feature = "loopback-provider")]
    loopback_port: Option<u16>,
}

/// One superseded credential generation and when it may be revoked.
struct Retirement {
    due: Instant,
    /// The record that superseded it.
    successor: auths_connections::CredentialBinding,
    /// The exact generation to revoke, when this process knows it.
    superseded: Option<std::num::NonZeroU64>,
}

/// The shared record a submission loaded before its claim, and the
/// transport prepared for it.
struct PreparedEntry {
    loaded: LoadedConnection,
    transport: GatewayHttpTransport,
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
        credentials: Arc<dyn ConnectionCredentialStore>,
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
            #[cfg(unix)]
            trusted_context_sha256: {
                use sha2::Digest as _;
                auths_recipe_qualification::Sha256Digest::from_bytes(
                    sha2::Sha256::digest(trusted_context_cbor).into(),
                )
            },
            observer: None,
            workload_id,
            profile,
            connection: SharedConnection::new(attempts.store(), provider, alias),
            credentials,
            credential_journal: None,
            qualification: Arc::new(crate::QualificationGate::unconfigured()),
            attempts,
            in_flight: AtomicU64::new(0),
            execution_witness: Arc::new(
                crate::execution_witness::ExecutionWitness::new()
                    .map_err(|_| GatewayEngineConfigurationError::WitnessUnavailable)?,
            ),
            last_sweep: AtomicU64::new(0),
            drain_limit: DRAIN_LIMIT,
            retirement_delay: crate::CredentialRetirementDelay::FIXED.as_duration(),
            retirements: std::sync::Mutex::new(Vec::new()),
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

    /// Pins the host's independently retained anti-rollback witness.
    #[must_use]
    pub fn with_generation_floor(mut self, floor: crate::GenerationFloor) -> Self {
        self.connection = self.connection.with_generation_floor(floor);
        self
    }

    /// Attaches durable cleanup notes recorded before custody writes.
    #[must_use]
    pub fn with_credential_journal(mut self, journal: crate::CredentialJournal) -> Self {
        self.credential_journal = Some(journal);
        self
    }

    async fn note_credential(
        &self,
        record: &ConnectionRecord,
        next: std::num::NonZeroU64,
    ) -> Result<(), &'static str> {
        if let Some(journal) = self.credential_journal.clone() {
            let id = record.connection_id().clone();
            let current = record.credential_generation();
            tokio::task::spawn_blocking(move || {
                journal.register(&id, current)?;
                journal.register(&id, next)
            })
            .await
            .map_err(|_| "gateway.admin.credential-journal-unavailable")??;
        }
        Ok(())
    }

    /// Collects at most sixteen exact generations from durable notes. It
    /// waits the fixed retirement delay after observing the shared record,
    /// requires it unchanged, and never deletes its active credential or a
    /// future prepared generation. Run under operator workload identity.
    /// Existing attempts and provider state are never changed.
    /// An explicitly revoked record is cleanup authority even when an
    /// interrupted install left no usable execution floor; all other states
    /// still require that floor. Collection never repairs an execution floor.
    ///
    /// # Errors
    /// A damaged journal, changed connection or failed deletion refuses and
    /// retains the obligation for a later operator run.
    pub async fn collect_credentials(&self) -> Result<usize, &'static str> {
        let journal = self
            .credential_journal
            .clone()
            .ok_or("gateway.admin.credential-journal-unavailable")?;
        let current = self.load_for_collection().await?;
        let record = current.record().clone();
        let id = record.connection_id().clone();
        let reading = journal.clone();
        let generations = tokio::task::spawn_blocking(move || reading.generations(&id))
            .await
            .map_err(|_| "gateway.admin.credential-journal-unavailable")??;
        tokio::time::sleep(self.retirement_delay).await;
        let latest = self.load_for_collection().await?;
        if !latest.unchanged(&current) {
            return Err("gateway.admin.generation-conflict");
        }
        let mut deleted = 0;
        for generation in generations
            .into_iter()
            .filter(|generation| {
                *generation <= record.generation()
                    && (record.state() == ConnectionState::Revoked
                        || *generation != record.credential_generation())
            })
            .take(16)
        {
            self.credentials
                .revoke(record.connection_id(), generation)
                .await
                .map_err(|_| "gateway.admin.credential-deletion-incomplete")?;
            let updating = journal.clone();
            let id = record.connection_id().clone();
            tokio::task::spawn_blocking(move || updating.forget(&id, generation))
                .await
                .map_err(|_| "gateway.admin.credential-journal-unavailable")??;
            deleted += 1;
        }
        Ok(deleted)
    }

    async fn load_for_collection(&self) -> Result<LoadedConnection, &'static str> {
        self.connection
            .load_for_credential_collection()
            .await
            .map_err(|_| "gateway.admin.connection-unavailable")?
            .ok_or("gateway.admin.connection-unavailable")
    }

    /// Installs the qualification gate the operator plane built for this
    /// deployment. Without one, every lease is refused as unqualified.
    #[must_use]
    pub fn with_qualification(mut self, gate: Arc<crate::QualificationGate>) -> Self {
        self.qualification = gate;
        self
    }

    #[cfg(test)]
    pub(crate) fn set_qualification(&mut self, gate: Arc<crate::QualificationGate>) {
        self.qualification = gate;
    }

    /// The qualification gate, for the operator plane to reload and report.
    #[must_use]
    pub fn qualification(&self) -> &crate::QualificationGate {
        &self.qualification
    }

    /// Installs the operator-provisioned observer key. Without one, every
    /// observation request is refused.
    #[must_use]
    pub fn with_observer(mut self, observer: GatewayObserver) -> Self {
        self.observer = Some(observer);
        self
    }

    /// Refuses an installation whose operator principal overlaps a root or
    /// an observer of the installed trust, or whose observer key is a root
    /// or is not anchored in it. Overlap compares identifiers and the key
    /// identity of `raw-key-v1` and `did:key` principals.
    ///
    /// # Errors
    /// Returns the first overlap with its stable code.
    pub fn check_principal_separation(
        &self,
        operator: Option<&auths_model::PrincipalId>,
    ) -> Result<(), crate::PrincipalSeparationError> {
        crate::check_principal_separation(
            &self.trusted_context,
            operator,
            self.observer.as_ref().map(GatewayObserver::principal),
        )
    }

    /// This process's entries past their final reload and not yet recorded.
    #[must_use]
    pub fn in_flight(&self) -> u64 {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Waits at most the drain limit for this process's in-flight count to
    /// reach zero. It never cancels an entry.
    async fn drain(&self) -> (bool, u64) {
        let deadline = Instant::now() + self.drain_limit;
        loop {
            let count = self.in_flight();
            if count == 0 {
                return (true, 0);
            }
            if Instant::now() >= deadline {
                return (false, count);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    async fn drained(&self, code: &'static str) -> GatewayAdminOutcome {
        let (drained, in_flight) = self.drain().await;
        GatewayAdminOutcome {
            code,
            drained,
            in_flight,
        }
    }

    /// Commits one state change to the shared record by compare-and-swap.
    /// `change` returns the replacement, or `None` when the record already
    /// has the target state; it is re-evaluated on a fresh load when another
    /// process changed the record first.
    async fn change_state(
        &self,
        change: impl Fn(&ConnectionRecord, u64) -> Result<Option<ConnectionRecord>, &'static str>,
    ) -> Result<ConnectionRecord, &'static str> {
        for _ in 0..ADMIN_ROUNDS {
            let current = self.load_for_admin().await?;
            let now = wall_clock_seconds().ok_or("gateway.admin.clock-unavailable")?;
            let Some(next) = change(current.record(), now)? else {
                return Ok(current.record().clone());
            };
            match self.connection.replace(&current, &next).await {
                Ok(committed) => return Ok(committed.record().clone()),
                Err(SharedConnectionError::Conflict) => {}
                Err(_) => return Err("gateway.admin.transition-unavailable"),
            }
        }
        Err("gateway.admin.generation-conflict")
    }

    async fn load_for_admin(&self) -> Result<LoadedConnection, &'static str> {
        match self.connection.load().await {
            Ok(Some(loaded)) => Ok(loaded),
            Ok(None) | Err(_) => Err("gateway.admin.connection-unavailable"),
        }
    }

    /// Disables new submissions in every process sharing the store. The
    /// change commits without waiting for any submission; the answer then
    /// reports whether this process's in-flight entries finished within the
    /// drain limit. Disabling stores no credential, so it needs no free
    /// credential-store capacity. The operator-only service channel must be
    /// the sole caller.
    ///
    /// # Errors
    /// A failed durable transition never reports disabled.
    pub async fn disable_connection(&self) -> Result<GatewayAdminOutcome, &'static str> {
        self.connection
            .stop(
                false,
                wall_clock_seconds().ok_or("gateway.admin.clock-unavailable")?,
            )
            .await?;
        Ok(self.drained("gateway.admin.disabled").await)
    }

    /// Enables a disabled connection in every process sharing the store. It
    /// stores no credential, so every process that held the secret before
    /// the disable still leases it.
    ///
    /// # Errors
    /// A failed durable transition never reports enabled.
    pub async fn enable_connection(&self) -> Result<GatewayAdminOutcome, &'static str> {
        self.change_state(|record, now| {
            if record.state() != ConnectionState::Disabled {
                return Err("gateway.admin.connection-not-disabled");
            }
            record
                .transition_state(ConnectionState::Active, now)
                .map(Some)
                .map_err(|_| "gateway.admin.transition-unavailable")
        })
        .await?;
        Ok(self.drained("gateway.admin.enabled").await)
    }

    /// Rotates the operator-held secret.
    ///
    /// The candidate must first pass every declared credential check: the
    /// prefix, the probe, the account read against the record's commitment,
    /// and the denied reads. A process that holds the record's current secret
    /// commits a rotation: it stores the candidate at the next generation and
    /// publishes the rotated record, which makes that generation the
    /// credential generation. A process that does not hold it, because the
    /// rotation was committed through another process, takes the candidate
    /// into its own store at the credential generation only when its
    /// reference commitment there equals the record's. A later disable or
    /// enable leaves both valid.
    ///
    /// # Errors
    /// A refused candidate, a commitment that does not match, or a failed
    /// durable transition never reports the rotation complete.
    pub async fn rotate_connection(
        &self,
        candidate: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<GatewayAdminOutcome, &'static str> {
        let current = self.load_for_admin().await?;
        let record = current.record();
        if record.state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-not-active");
        }
        // The provider reads run before anything is stored or committed,
        // and no submission waits on them.
        crate::onboarding::check_candidate_credential(
            &self.recipe,
            self.recipe.review().credential(),
            &candidate,
            crate::onboarding::OnboardingAccount::Commitment(*record.account_commitment()),
        )
        .await
        .map_err(crate::onboarding::OnboardingFailure::admin_code)?;
        let mut candidate = candidate;
        let secret = SecretBytes::new(std::mem::take(&mut *candidate))
            .map_err(|_| "gateway.admin.invalid-credential")?;
        if self.holds(record).await.is_err() {
            return self.accept_rotation(record, secret).await;
        }
        let commitment = self.store_successor(record, secret).await?;
        let committed = self.commit_successor(&current, commitment).await;
        if committed.is_err()
            && let Some(next) =
                auths_connections::kernel::next_generation(record.generation().get())
                    .and_then(std::num::NonZeroU64::new)
        {
            // A one-step rotation has no later commit, so its unpublished
            // successor is discarded now rather than by the next prepare.
            let _ = self.credentials.revoke(record.connection_id(), next).await;
        }
        committed
    }

    /// Stores `secret` at the generation after `record`'s without changing
    /// the shared record, and returns its reference commitment. Nothing
    /// leases the stored secret until a commit publishes it.
    async fn store_successor(
        &self,
        record: &ConnectionRecord,
        secret: SecretBytes,
    ) -> Result<[u8; 32], &'static str> {
        let next = auths_connections::kernel::next_generation(record.generation().get())
            .and_then(std::num::NonZeroU64::new)
            .ok_or("gateway.admin.generation-exhausted")?;
        self.note_credential(record, next).await?;
        // Nothing can name a generation the record has not reached, so a
        // successor left by an earlier failed rotation is discarded, not reused.
        let _ = self.credentials.revoke(record.connection_id(), next).await;
        self.credentials
            .replace(record.connection_id(), record.generation(), next, secret)
            .await
            .map(|commitment| *commitment.as_bytes())
            .map_err(|_| "gateway.admin.credential-unavailable")
    }

    /// Publishes the stored successor whose commitment is `commitment`, then
    /// schedules the superseded generation for retirement.
    async fn commit_successor(
        &self,
        current: &LoadedConnection,
        commitment: [u8; 32],
    ) -> Result<GatewayAdminOutcome, &'static str> {
        let record = current.record();
        match self.publish_rotation(current, commitment).await {
            Ok(rotated) => {
                self.schedule_retirement(&rotated, Some(record.credential_generation()));
                self.delete_superseded_credentials(&rotated).await;
                Ok(self.drained("gateway.admin.rotated").await)
            }
            Err(code) => {
                // The record still names its previous secret. An unpublished
                // successor cannot be leased: it is newer than the credential
                // generation, so no record selects it, and the next prepare
                // discards it.
                Err(code)
            }
        }
    }

    /// The first phase of a two-phase rotation: checks the candidate against
    /// the recipe's declared credential checks, stores it at the next
    /// generation, and returns its reference commitment. The shared record
    /// is unchanged, so every process keeps serving the current credential.
    /// It works on a disabled connection, which is how a possibly
    /// compromised credential is replaced.
    ///
    /// # Errors
    /// A refused candidate, a revoked connection, or a process that does not
    /// serve the current credential stores nothing.
    pub async fn prepare_rotation(
        &self,
        candidate: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<[u8; 32], &'static str> {
        let current = self.load_for_admin().await?;
        let record = current.record();
        if record.state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-not-active");
        }
        crate::onboarding::check_candidate_credential(
            &self.recipe,
            self.recipe.review().credential(),
            &candidate,
            crate::onboarding::OnboardingAccount::Commitment(*record.account_commitment()),
        )
        .await
        .map_err(crate::onboarding::OnboardingFailure::admin_code)?;
        let mut candidate = candidate;
        let secret = SecretBytes::new(std::mem::take(&mut *candidate))
            .map_err(|_| "gateway.admin.invalid-credential")?;
        if self.holds(record).await.is_err() {
            return Err("gateway.admin.credential-unavailable");
        }
        self.store_successor(record, secret).await
    }

    /// The second phase: replaces the credential generation and reference
    /// commitment in the shared record with one compare-and-swap, only when
    /// the store holds, at the next generation, exactly the secret
    /// `commitment` names. The superseded generation is kept for the
    /// retirement delay.
    ///
    /// # Errors
    /// Returns `gateway.admin.rotation-not-prepared` when no such secret is
    /// stored, which includes a record that changed since the prepare; the
    /// operator prepares again. A lost compare-and-swap changes nothing.
    pub async fn commit_rotation(
        &self,
        commitment: [u8; 32],
    ) -> Result<GatewayAdminOutcome, &'static str> {
        let current = self.load_for_admin().await?;
        if current.record().state() == ConnectionState::Revoked {
            return Err("gateway.admin.connection-not-active");
        }
        self.commit_successor(&current, commitment).await
    }

    /// Takes the secret a rotation through another process committed.
    async fn accept_rotation(
        &self,
        record: &ConnectionRecord,
        secret: SecretBytes,
    ) -> Result<GatewayAdminOutcome, &'static str> {
        match self
            .credentials
            .confirm(&record.credential_binding(), secret)
            .await
        {
            Ok(()) => {}
            Err(auths_connections::CredentialStoreError::Substitution) => {
                return Err("gateway.admin.generation-conflict");
            }
            Err(_) => return Err("gateway.admin.credential-unavailable"),
        }
        self.schedule_retirement(record, None);
        self.delete_superseded_credentials(record).await;
        // Taking a secret changes no shared state, so nothing is drained.
        let in_flight = self.in_flight();
        Ok(GatewayAdminOutcome {
            code: "gateway.admin.rotated",
            drained: in_flight == 0,
            in_flight,
        })
    }

    async fn publish_rotation(
        &self,
        current: &LoadedConnection,
        commitment: [u8; 32],
    ) -> Result<ConnectionRecord, &'static str> {
        let timestamp = wall_clock_seconds().ok_or("gateway.admin.clock-unavailable")?;
        let record = current.record();
        let replacement = record
            .rotated(
                record.descriptor().to_vec(),
                *record.account_commitment(),
                commitment,
                timestamp,
            )
            .map_err(|_| "gateway.admin.transition-unavailable")?;
        // The record may only name a credential the store really serves.
        if self
            .credentials
            .holds(&replacement.credential_binding())
            .await
            .is_err()
        {
            return Err("gateway.admin.rotation-not-prepared");
        }
        match self.connection.replace(current, &replacement).await {
            Ok(committed) => Ok(committed.record().clone()),
            Err(SharedConnectionError::Conflict) => Err("gateway.admin.generation-conflict"),
            Err(_) => Err("gateway.admin.transition-unavailable"),
        }
    }

    /// The gateway leases only the credential generation, so nothing needs an
    /// older one. Best effort: a failed deletion is repeated by the next
    /// rotation, disable, or revoke.
    async fn delete_superseded_credentials(&self, current: &ConnectionRecord) {
        self.collect_retired(current, Instant::now()).await;
    }

    /// Remembers that `successor` superseded a credential generation, which
    /// may be revoked once the retirement delay has passed.
    fn schedule_retirement(
        &self,
        successor: &ConnectionRecord,
        superseded: Option<std::num::NonZeroU64>,
    ) {
        if let Ok(mut retirements) = self.retirements.lock() {
            retirements.push(Retirement {
                due: Instant::now() + self.retirement_delay,
                successor: successor.credential_binding(),
                superseded,
            });
        }
    }

    /// Retires every superseded generation that is due at `now`: revokes the
    /// exact generation where it is known, then lets the store delete what
    /// nothing can need. While a retirement is still pending nothing older
    /// is deleted, so an attempt admitted before the commit keeps its whole
    /// generation. Best effort: a failed deletion is repeated by the next
    /// rotation, disable, or revoke.
    async fn collect_retired(&self, current: &ConnectionRecord, now: Instant) {
        let (due, pending) = match self.retirements.lock() {
            Ok(mut retirements) => {
                let (due, kept): (Vec<_>, Vec<_>) = retirements
                    .drain(..)
                    .partition(|retirement| retirement.due <= now);
                let pending = !kept.is_empty();
                *retirements = kept;
                (due, pending)
            }
            Err(_) => return,
        };
        for retirement in due {
            if let Some(generation) = retirement.superseded {
                let _ = self
                    .credentials
                    .revoke(retirement.successor.connection_id(), generation)
                    .await;
            }
            let _ = self
                .credentials
                .retire_superseded(&retirement.successor)
                .await;
        }
        if !pending {
            let _ = self
                .credentials
                .retire_superseded(&current.credential_binding())
                .await;
        }
    }

    /// Whether this process's credential store serves `record`.
    async fn holds(&self, record: &ConnectionRecord) -> Result<(), ()> {
        self.credentials
            .holds(&record.credential_binding())
            .await
            .map_err(|_| ())
    }

    /// Revokes the connection in every process sharing the store, retaining
    /// a terminal record that withholds every new credential lease, and
    /// deletes every credential generation this process stores in one
    /// persisted mutation, which needs no free credential-store capacity.
    /// Revoking an already revoked connection finishes a deletion that an
    /// earlier revocation failed to persist, and deletes the secrets of a
    /// process whose peer committed the revocation.
    ///
    /// # Errors
    /// A failed durable transition never reports revocation complete. A
    /// failed deletion is reported after the record is revoked, which already
    /// withholds every lease; revoking again finishes the deletion.
    pub async fn revoke_connection(&self) -> Result<GatewayAdminOutcome, &'static str> {
        let revoked = self
            .change_state(|record, now| {
                if record.state() == ConnectionState::Revoked {
                    return Ok(None);
                }
                record
                    .transition_state(ConnectionState::Revoked, now)
                    .map(Some)
                    .map_err(|_| "gateway.admin.transition-unavailable")
            })
            .await?;
        let deleted = self
            .credentials
            .delete_connection(revoked.connection_id(), &[revoked.credential_generation()])
            .await
            .map_err(|_| "gateway.admin.credential-deletion-incomplete");
        let outcome = self.drained("gateway.admin.revoked").await;
        deleted.map(|()| outcome)
    }

    /// Reads process-local execution counters without accessing custody, the
    /// store, the network, or qualification authority. A snapshot is diagnostic
    /// evidence only; it never confirms a provider effect.
    #[must_use]
    pub fn execution_witness(&self) -> crate::GatewayExecutionWitness {
        self.execution_witness.snapshot()
    }

    /// Reads the shared record's state and this process's counts. Nothing is
    /// changed.
    ///
    /// # Errors
    /// Returns `gateway.admin.connection-unavailable` when the record cannot
    /// be read.
    pub async fn status(&self) -> Result<GatewayAdminStatus, &'static str> {
        let loaded = self.load_for_admin().await?;
        let record = loaded.record();
        let gateway_clock = wall_clock_seconds().ok_or("gateway.admin.clock-unavailable")?;
        Ok(GatewayAdminStatus {
            state: match record.state() {
                ConnectionState::Active => "active",
                ConnectionState::Disabled => "disabled",
                ConnectionState::Revoked => "revoked",
            }
            .to_owned(),
            generation: record.generation().get(),
            credential_generation: record.credential_generation().get(),
            credential_held: self.holds(record).await.is_ok(),
            in_flight: self.in_flight(),
            last_sweep: Some(self.last_sweep.load(Ordering::SeqCst)).filter(|clock| *clock != 0),
            gateway_clock,
        })
    }

    /// Performs the runtime part of production readiness without leasing a
    /// credential or contacting a provider. The caller must separately check
    /// process isolation, deployment clock and observer policy. This checks
    /// the shared record, exact recipe binding, current generation, bounded
    /// secret-store confirmation and pinned transport construction.
    pub async fn readiness_checks(
        &self,
        credential_store: auths_connections::CredentialStoreKind,
    ) -> crate::RequiredPreconditions {
        use crate::PreconditionState::{NotReady, Ready};
        let mut checks = crate::RequiredPreconditions {
            trust: Ready,
            store: NotReady,
            recipe: NotReady,
            qualification: if self.qualification.status().state
                == auths_recipe_qualification::RecipeQualificationState::Qualified
            {
                Ready
            } else {
                NotReady
            },
            provider_secret_custody: NotReady,
            connection_generation: NotReady,
            clock: NotReady,
            transport_policy: NotReady,
            operator_plane_isolation: NotReady,
        };
        if let Ok(Some(loaded)) = self.connection.load().await {
            checks.store = Ready;
            let record = loaded.record();
            if let Ok(descriptor) = GatewayConnectionDescriptor::from_record(record, &self.recipe) {
                checks.recipe = Ready;
                if GatewayHttpTransport::prepare(&self.recipe, descriptor.credential()).is_ok() {
                    checks.transport_policy = Ready;
                }
            }
            if credential_store.is_production() && self.holds(record).await.is_ok() {
                checks.provider_secret_custody = Ready;
            }
            if authorizes_entry(record, &self.workload_id, &self.profile) {
                checks.connection_generation = Ready;
            }
        }
        checks
    }

    /// Performs the operator's read-only re-observation of one stored
    /// attempt: one read-back from the stored plan under a fresh lease that
    /// passes every credential check, when the recipe digest is unchanged
    /// and the stored stage can be resolved by a read-back. It records only
    /// positive evidence and never writes to the provider. The answer is the
    /// recorded result, or the stored attempt's result when nothing was
    /// recorded.
    ///
    /// # Errors
    /// Returns `gateway.reobserve.not-observable` when the attempt is absent
    /// or cannot be re-observed, and the entry refusal when the connection
    /// cannot be leased.
    pub async fn reobserve(&self, operation_id: &str) -> Result<GatewaySubmitResult, &'static str> {
        let not_observable = "gateway.reobserve.not-observable";
        // The stored observation plan does not retain the native-verified
        // create fields needed for child metadata comparisons. Re-observing
        // it after restart must not turn a name-only match into child evidence.
        if self.recipe.created_child_fields().is_some() {
            return Err(not_observable);
        }
        let operation =
            crate::LogicalOperationId::parse(operation_id).map_err(|_| not_observable)?;
        let namespace = self.recipe.namespace();
        let attempt = match self
            .attempts
            .resume_observable_operation(namespace, &operation, *self.recipe.digest())
            .await
        {
            Ok(Some(attempt)) => attempt,
            Ok(None) | Err(_) => return Err(not_observable),
        };
        let io = EngineIo {
            engine: self,
            proof: &[],
            action: &[],
            started: Instant::now(),
            prepared: OnceLock::new(),
            #[cfg(unix)]
            task_write: None,
            #[cfg(unix)]
            commissioning: None,
            #[cfg(unix)]
            commissioned_action: OnceLock::new(),
            #[cfg(unix)]
            commissioning_refusal: OnceLock::new(),
        };
        io.prepare().await?;
        let context = SubmitContext {
            recipe: &self.recipe,
            attempts: &self.attempts,
            context: &self.trusted_context,
            observer: self.observer.as_ref(),
        };
        if let Some(result) = submit::reobserve(&context, &io, attempt).await {
            return Ok(result);
        }
        match self.attempts.read(namespace, &operation).await {
            Ok(Some(snapshot)) => Ok(stored_result(&snapshot)),
            Ok(None) | Err(_) => Err(not_observable),
        }
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
        let deleted = self
            .attempts
            .sweep_expired(now, SLOT_SWEEP_LIMIT)
            .await
            .map_err(|_| "gateway.sweep.unavailable")?;
        self.last_sweep.store(now, Ordering::SeqCst);
        Ok(deleted)
    }

    /// Verifies and attempts one exact action. Only proof and action bytes are
    /// accepted from the application; trust, recipe, connection, and credential
    /// come from the operator's installation. The admission-order step machine
    /// directs every step: a replay never writes again, and for a linked
    /// recipe it may perform one more read-only observation.
    pub async fn submit(&self, proof_cbor: &[u8], action_cbor: &[u8]) -> GatewaySubmitResult {
        if self.recipe.requires_task_admission() {
            return not_entered("gateway.task.task-submit-required");
        }
        let io = EngineIo {
            engine: self,
            proof: proof_cbor,
            action: action_cbor,
            started: Instant::now(),
            prepared: OnceLock::new(),
            #[cfg(unix)]
            task_write: None,
            #[cfg(unix)]
            commissioning: None,
            #[cfg(unix)]
            commissioned_action: OnceLock::new(),
            #[cfg(unix)]
            commissioning_refusal: OnceLock::new(),
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

    /// Opens a task-write session from canonical, operator-owned installation
    /// bytes and a private single-host task journal. The application socket
    /// never accepts these pins. This early integration is not multi-host.
    ///
    /// # Errors
    /// Refuses malformed, stale or noncanonical operator pins and an unsafe
    /// or unavailable journal directory.
    #[cfg(unix)]
    pub fn task_write_session(
        &self,
        installation_bytes: &[u8],
        ledger_root: impl Into<PathBuf>,
    ) -> Result<TaskWriteSession<'_>, &'static str> {
        let installation: TaskWriteInstallation = serde_json::from_slice(installation_bytes)
            .map_err(|_| "gateway.task.invalid-installation")?;
        let canonical = serde_json_canonicalizer::to_vec(&installation)
            .map_err(|_| "gateway.task.invalid-installation")?;
        if installation_bytes != canonical
            || installation.schema != TASK_INSTALLATION_SCHEMA
            || installation.recipe_digests.is_empty()
            || installation.recipe_digests.len() > 4
            || installation.recipe_digests.iter().any(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            || installation
                .recipe_digests
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || !installation
                .recipe_digests
                .contains(&self.recipe.digest_hex())
            || installation
                .populate_preflight
                .as_ref()
                .is_some_and(|pin| !pin.valid())
        {
            return Err("gateway.task.invalid-installation");
        }
        if !task_trust_available(&self.trusted_context) {
            return Err("gateway.task.trust-profile-unavailable");
        }
        let (resource_field, verb) = self
            .recipe
            .task_binding()
            .ok_or("gateway.task.recipe-not-bound")?;
        let binding = TaskWriteBinding {
            resource_field: resource_field.to_owned(),
            verb,
            connection_id: installation.pins.connection_id.clone(),
            connection_generation: installation.pins.connection_generation,
            connection_subject: installation.pins.connection_subject.clone(),
        };
        let ledger = FileReleaseTaskLedger::open(ledger_root)
            .map_err(|_| "gateway.task.store-unavailable")?;
        Ok(TaskWriteSession {
            engine: self,
            pins: installation.pins,
            recipe_digests: installation.recipe_digests,
            populate_preflight: installation.populate_preflight,
            binding,
            ledger,
        })
    }

    /// Task-aware entry for a recipe that declares `task_binding`. The
    /// caller supplies operator-installed pins and a private journal; these
    /// are never accepted from the agent or ordinary application frame.
    #[cfg(unix)]
    async fn submit_task_write(&self, submission: TaskWriteSubmission<'_>) -> GatewaySubmitResult {
        if !self.recipe.requires_task_admission() {
            return not_entered("gateway.task.recipe-not-bound");
        }
        let Some(now) = wall_clock_seconds() else {
            return GatewaySubmitResult::Indeterminate {
                code: "gateway.verify.clock-unavailable".to_owned(),
            };
        };
        let state = match submission.ledger.load(submission.task_id) {
            Ok(Some(state)) => state,
            Ok(None) => return not_entered("gateway.task.not-activated"),
            Err(error) => return not_entered(error.write_code()),
        };
        let task = match state.activated_task(submission.pins, now) {
            Ok(task) => task,
            Err(error) => return not_entered(error.write_code()),
        };
        let child_scope = state.bound_child_scope();
        let verified = match verify_detailed(
            &self.recipe,
            &self.trusted_context,
            now,
            submission.agent_proof,
            submission.agent_action,
        ) {
            Ok(verified) => verified,
            Err(result) => return result,
        };
        let intent = match derive_exact_write_intent(
            &task,
            &verified,
            &self.recipe,
            submission.binding,
            child_scope.as_ref(),
            now,
        ) {
            Ok(intent) => intent,
            Err(result) => return result,
        };
        let approved = match task.descriptor().write_approval_mode {
            WriteApprovalMode::Exact => {
                if submission.use_effect_plan {
                    if submission.confirmation.is_some() {
                        return not_entered("gateway.task.unexpected-confirmation");
                    }
                    let Some(plan) = state.effect_plan() else {
                        return not_entered("gateway.task.effect-plan-required");
                    };
                    let (approved, preflight_valid_until) = if intent.verb
                        == crate::task_activation::TaskWriteVerb::Create
                    {
                        (
                            ApprovedTaskWrite::from_recorded_effect_plan_create(plan, intent, now),
                            None,
                        )
                    } else {
                        let Some(pin) = submission.preflight_pin else {
                            return not_entered("gateway.task.preflight-not-installed");
                        };
                        let Some(preflight) = state.populate_preflight() else {
                            return not_entered("gateway.task.preflight-required");
                        };
                        if plan.preflight_rule_digest.as_deref() != Some(pin.rule_digest.as_str())
                            || plan.preflight_key_sha256.as_deref()
                                != Some(pin.key_sha256().as_str())
                        {
                            return not_entered("gateway.task.preflight-policy-changed");
                        }
                        (
                            ApprovedTaskWrite::from_recorded_effect_plan_populate(
                                plan,
                                &self.recipe,
                                intent,
                                &verified.arguments,
                                &preflight.facts(),
                                now,
                            ),
                            Some(preflight.facts().valid_until),
                        )
                    };
                    return self
                        .run_admitted_task_write(
                            submission,
                            &task,
                            child_scope,
                            approved,
                            preflight_valid_until,
                        )
                        .await;
                }
                let Some((proof, action)) = submission.confirmation else {
                    return not_entered("gateway.task.exact-confirmation-required");
                };
                verify_exact_write_confirmation(
                    &self.trusted_context,
                    &task,
                    intent,
                    now,
                    proof,
                    action,
                )
            }
            WriteApprovalMode::BoundedUpfront => {
                if submission.confirmation.is_some() {
                    return not_entered("gateway.task.unexpected-confirmation");
                }
                admit_bounded_upfront_write(&task, intent, &verified.arguments, now)
            }
        };
        let approved = match approved {
            Ok(approved) => approved,
            Err(result) => return result,
        };
        self.run_admitted_task_write(submission, &task, child_scope, Ok(approved), None)
            .await
    }

    #[cfg(unix)]
    async fn run_admitted_task_write(
        &self,
        submission: TaskWriteSubmission<'_>,
        task: &ApprovedAgentTask,
        child_scope: Option<crate::task_activation::TaskWriteScope>,
        approved: Result<ApprovedTaskWrite, GatewaySubmitResult>,
        preflight_valid_until: Option<u64>,
    ) -> GatewaySubmitResult {
        let approved = match approved {
            Ok(approved) => approved,
            Err(result) => return result,
        };
        let io = EngineIo {
            engine: self,
            proof: submission.agent_proof,
            action: submission.agent_action,
            started: Instant::now(),
            prepared: OnceLock::new(),
            task_write: Some(TaskWriteAdmission {
                task,
                binding: submission.binding,
                approved: &approved,
                ledger: submission.ledger,
                child_scope,
                preflight_valid_until,
            }),
            commissioning: None,
            commissioned_action: OnceLock::new(),
            commissioning_refusal: OnceLock::new(),
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

    /// Loads the shared record, requires it to authorize this gateway's
    /// workload and profile, requires this process's credential store to
    /// hold the secret its credential generation names, and prepares the
    /// pinned transport. Nothing is stored.
    async fn prepare_entry(&self) -> Result<PreparedEntry, &'static str> {
        self.prepare_entry_for(|| self.qualification.check()).await
    }

    /// Both authority paths perform exactly the same connection and transport
    /// checks; the ordinary path supplies only its qualification check.
    async fn prepare_entry_for(
        &self,
        check_authority: impl FnOnce() -> Result<(), &'static str>,
    ) -> Result<PreparedEntry, &'static str> {
        let loaded = match self.connection.load().await {
            Ok(Some(loaded)) => loaded,
            Err(SharedConnectionError::Rollback) => {
                return Err("gateway.connection.restore-rollback");
            }
            Ok(None) | Err(_) => return Err("gateway.connection.unavailable"),
        };
        let record = loaded.record();
        if !authorizes_entry(record, &self.workload_id, &self.profile) {
            return Err("gateway.connection.unavailable");
        }
        let descriptor = GatewayConnectionDescriptor::from_record(record, &self.recipe)
            .map_err(|_| "gateway.connection.recipe-mismatch")?;
        check_authority()?;
        if self.holds(record).await.is_err() {
            return Err("gateway.connection.credential-generation-missing");
        }
        #[cfg(feature = "loopback-provider")]
        if let Some(port) = self.loopback_port {
            return GatewayHttpTransport::prepare_loopback(
                &self.recipe,
                descriptor.credential(),
                port,
            )
            .map(|transport| PreparedEntry {
                loaded,
                transport: transport.with_witness(Arc::clone(&self.execution_witness)),
            })
            .map_err(|_| "gateway.transport.preparation");
        }
        GatewayHttpTransport::prepare(&self.recipe, descriptor.credential())
            .map(|transport| PreparedEntry {
                loaded,
                transport: transport.with_witness(Arc::clone(&self.execution_witness)),
            })
            .map_err(|_| "gateway.transport.preparation")
    }

    /// Reloads the shared record and requires exactly the bytes loaded before
    /// the claim: the re-read immediately before credential acquisition, and
    /// the final re-read before entry.
    async fn unchanged(&self, prepared: &PreparedEntry) -> bool {
        matches!(
            self.connection.load().await,
            Ok(Some(current)) if current.unchanged(&prepared.loaded)
        )
    }

    /// Leases through the credential-store trait, naming exactly the
    /// credential generation the loaded record seals.
    async fn lease(&self, prepared: &PreparedEntry) -> Result<StoredSecretLease, ()> {
        // Time moved since the entry was prepared, so the gate is asked
        // again: nothing reaches the credential store unqualified.
        self.qualification.check().map_err(|_| ())?;
        self.execution_witness.lease();
        self.credentials
            .lease_secret(
                &prepared.loaded.record().credential_binding(),
                Instant::now() + Duration::from_secs(30),
            )
            .await
            .map_err(|_| ())
    }

    /// Signs one observation for the application. A read-back uses the
    /// installed connection and credential for exactly one bounded read-only
    /// GET built from the approved recipe, after the lease passes every
    /// declared credential check; an outcome reads only the local attempt
    /// store. Nothing here writes to a provider or to the store.
    pub async fn observe(&self, request: &GatewayObserveRequest) -> GatewayObserveResult {
        if let GatewayObserveRequest::PreEntry { operation_id } = request {
            return observe_pre_entry(&self.attempts, self.recipe.namespace(), operation_id).await;
        }
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
            GatewayObserveRequest::PreEntry { operation_id } => {
                observe_pre_entry(&self.attempts, self.recipe.namespace(), operation_id).await
            }
            GatewayObserveRequest::ReadBack { arguments } => {
                let Ok(target) = self.recipe.read_back_target(arguments) else {
                    return refused("gateway.observer.invalid-read-back");
                };
                let Ok(prepared) = self.prepare_entry().await else {
                    return refused("gateway.observer.connection-unavailable");
                };
                let Ok(lease) = self.lease(&prepared).await else {
                    return refused("gateway.observer.credential-unavailable");
                };
                let port = LeasedTransport {
                    transport: &prepared.transport,
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
                    Some(*prepared.loaded.record().account_commitment()),
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

/// The result a stored attempt answers when a re-observation recorded
/// nothing new.
fn stored_result(snapshot: &crate::GatewayAttemptSnapshot) -> GatewaySubmitResult {
    use crate::GatewayAttemptStage as Stage;
    match (snapshot.stage(), snapshot.response_status()) {
        (Stage::NotEntered, _) => GatewaySubmitResult::NotEntered {
            code: snapshot
                .refusal()
                .unwrap_or("gateway.attempt.unavailable")
                .to_owned(),
        },
        (Stage::ResponseRecorded, Some(status)) => GatewaySubmitResult::ResponseRecorded { status },
        (Stage::Observed, Some(status)) => GatewaySubmitResult::Observed {
            status,
            matched: snapshot.observation_match().unwrap_or(false),
        },
        (Stage::ObservedByProvider, status) => match snapshot.provider_evidence() {
            Some(evidence) => GatewaySubmitResult::ObservedByProvider {
                status,
                evidence: evidence.into(),
            },
            None => GatewaySubmitResult::Unknown,
        },
        _ => GatewaySubmitResult::Unknown,
    }
}

/// The installed engine's I/O for one submission.
#[cfg(unix)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TaskWriteInstallation {
    schema: String,
    recipe_digests: Vec<String>,
    pins: TaskActivationPins,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    populate_preflight: Option<PopulatePreflightPin>,
}

#[cfg(unix)]
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PopulatePreflightPin {
    public_key_hex: String,
    rule_digest: String,
}

/// Private operator handoff to a credential-bearing preflight vertical. These
/// facts are read from the activated card, effect plan and bound-child journal;
/// the agent cannot nominate a different child or plan through this command.
#[cfg(unix)]
#[derive(Serialize)]
pub struct TaskPopulatePreflightInputs {
    schema: &'static str,
    task_id: String,
    task_commitment: String,
    plan_commitment: String,
    create_operation_id: String,
    child_id: String,
    populate_recipe_digest: String,
    preflight_rule_digest: String,
    connection_id: String,
    connection_generation: u64,
    connection_subject: String,
    parent_id: String,
    title: String,
    marker: String,
    plan_expires_at: u64,
}

#[cfg(unix)]
impl PopulatePreflightPin {
    fn valid(&self) -> bool {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if !digest(&self.public_key_hex) || !digest(&self.rule_digest) {
            return false;
        }
        hex::decode(&self.public_key_hex)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes.as_slice()).ok())
            .and_then(|bytes| ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok())
            .is_some()
    }

    fn key_sha256(&self) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(
            hex::decode(&self.public_key_hex).expect("validated installation key"),
        ))
    }
}

/// Operator-owned activation and write path for one installed task-bound
/// recipe. The ledger is durable across CLI invocations on this host.
#[cfg(unix)]
pub struct TaskWriteSession<'a> {
    engine: &'a GatewayEngine,
    pins: TaskActivationPins,
    recipe_digests: Vec<String>,
    populate_preflight: Option<PopulatePreflightPin>,
    binding: TaskWriteBinding,
    ledger: FileReleaseTaskLedger,
}

/// Native proofs and actions presented to the operator-owned task session.
/// The confirmation pair is required in exact mode and forbidden in the
/// separately enabled bounded-upfront mode.
#[cfg(unix)]
pub struct TaskWriteProofs<'a> {
    pub task_id: &'a str,
    pub agent_proof: &'a [u8],
    pub agent_action: &'a [u8],
    pub confirmation: Option<(&'a [u8], &'a [u8])>,
}

#[cfg(unix)]
impl TaskWriteSession<'_> {
    /// Read the activated task's redacted accounting and operation stages.
    /// This view makes no assertion that a provider effect was observed.
    ///
    /// # Errors
    /// Refuses an absent or unavailable private task journal.
    pub fn status(&self, task_id: &str) -> Result<crate::TaskStatus, &'static str> {
        self.ledger
            .load(task_id)
            .map_err(|_| "gateway.task.status-unavailable")?
            .map(|state| state.status())
            .ok_or("gateway.task.status-unavailable")
    }

    /// Privately compare a staged source with bytes the gateway released to
    /// the registered agent and durably acknowledged. This exposes only a
    /// boolean; it never returns a digest or the release content.
    ///
    /// # Errors
    /// Refuses an unavailable or corrupt task journal.
    pub fn acknowledged_release_matches(
        &self,
        task_id: &str,
        operation_id: &str,
        resource_handle: &str,
        source: &[u8],
        key: &crate::ReleaseCommitmentKey,
    ) -> Result<bool, &'static str> {
        self.ledger
            .load(task_id)
            .map_err(|_| "gateway.release.source-unavailable")?
            .map(|state| {
                state.acknowledged_content_matches(operation_id, resource_handle, source, key)
            })
            .ok_or("gateway.release.source-unavailable")
    }

    /// Durably stop new reads and writes under one activated task. A provider
    /// call already entered or bytes already delivered cannot be recalled.
    ///
    /// # Errors
    /// Refuses an unknown task or unavailable private journal.
    pub fn revoke(&self, task_id: &str) -> Result<(), &'static str> {
        self.ledger
            .revoke(task_id)
            .map(|_| ())
            .map_err(|_| "gateway.task.revoke-unavailable")
    }

    /// Registers a human-signed task once. Later submissions name this durable
    /// activation and need fresh agent and, in exact mode, human actions.
    ///
    /// # Errors
    /// Refuses invalid native authority, changed connection pins, duplicate
    /// activation or unavailable durable state before any provider entry.
    pub async fn activate(
        &self,
        proof_cbor: &[u8],
        action_cbor: &[u8],
    ) -> Result<(), GatewaySubmitResult> {
        let now = wall_clock_seconds().ok_or_else(|| GatewaySubmitResult::Indeterminate {
            code: "gateway.verify.clock-unavailable".to_owned(),
        })?;
        let task = verify_task_activation(
            &self.engine.trusted_context,
            &self.pins,
            now,
            proof_cbor,
            action_cbor,
        )?;
        if !task.descriptor().recipes_installed(&self.recipe_digests) {
            return Err(not_entered("gateway.task.recipe-not-installed"));
        }
        let loaded = self
            .engine
            .connection
            .load()
            .await
            .map_err(|_| not_entered("gateway.task.connection-unavailable"))?
            .ok_or_else(|| not_entered("gateway.task.connection-unavailable"))?;
        if !authorizes_entry(
            loaded.record(),
            &self.engine.workload_id,
            &self.engine.profile,
        ) || !task_connection_matches(loaded.record(), &self.binding)
        {
            return Err(not_entered("gateway.task.connection-changed"));
        }
        let approved_recipes =
            GatewayConnectionDescriptor::task_recipe_digests(loaded.record(), &self.engine.recipe)
                .map_err(|_| not_entered("gateway.connection.recipe-mismatch"))?;
        if approved_recipes != self.recipe_digests {
            return Err(not_entered("gateway.task.recipe-not-installed"));
        }
        self.ledger.initialize(&task).map_err(|error| {
            if error == crate::release_state::ReleaseStateError::Exists {
                not_entered("gateway.task.already-activated")
            } else {
                not_entered(error.write_code())
            }
        })?;
        Ok(())
    }

    /// Verifies a previously activated task and one agent write, then runs
    /// the gateway's ordinary provider attempt machine under its task gate.
    pub async fn submit(&self, proofs: TaskWriteProofs<'_>) -> GatewaySubmitResult {
        self.engine
            .submit_task_write(TaskWriteSubmission {
                pins: &self.pins,
                binding: &self.binding,
                ledger: &self.ledger,
                preflight_pin: self.populate_preflight.as_ref(),
                task_id: proofs.task_id,
                agent_proof: proofs.agent_proof,
                agent_action: proofs.agent_action,
                confirmation: proofs.confirmation,
                use_effect_plan: false,
            })
            .await
    }

    /// Execute the exact recorded create or one preflight-bound population
    /// under a previously verified human effect plan.
    pub async fn submit_planned_effect(&self, proofs: TaskWriteProofs<'_>) -> GatewaySubmitResult {
        self.engine
            .submit_task_write(TaskWriteSubmission {
                pins: &self.pins,
                binding: &self.binding,
                ledger: &self.ledger,
                preflight_pin: self.populate_preflight.as_ref(),
                task_id: proofs.task_id,
                agent_proof: proofs.agent_proof,
                agent_action: proofs.agent_action,
                confirmation: proofs.confirmation,
                use_effect_plan: true,
            })
            .await
    }

    /// Verify and durably record one human-signed create/populate plan before
    /// either provider write. This records authority but does not execute it.
    ///
    /// # Errors
    /// Refuses a changed task, non-create agent action, invalid human plan,
    /// late or conflicting journal write, or unavailable private state.
    pub fn record_effect_plan(
        &self,
        task_id: &str,
        agent_proof: &[u8],
        agent_action: &[u8],
        plan_proof: &[u8],
        plan_action: &[u8],
    ) -> Result<(), &'static str> {
        if self.engine.recipe.created_child_fields().is_none() {
            return Err("gateway.task.effect-plan-not-create");
        }
        let now = wall_clock_seconds().ok_or("gateway.task.effect-plan-clock")?;
        let task = self
            .ledger
            .load(task_id)
            .map_err(|_| "gateway.task.effect-plan-state")?
            .ok_or("gateway.task.effect-plan-state")?
            .activated_task(&self.pins, now)
            .map_err(|_| "gateway.task.effect-plan-inactive")?;
        let verified = verify_detailed(
            &self.engine.recipe,
            &self.engine.trusted_context,
            now,
            agent_proof,
            agent_action,
        )
        .map_err(|_| "gateway.task.effect-plan-agent-proof")?;
        let create = derive_exact_write_intent(
            &task,
            &verified,
            &self.engine.recipe,
            &self.binding,
            None,
            now,
        )
        .map_err(|_| "gateway.task.effect-plan-create")?;
        let plan = verify_effect_plan(
            &self.engine.trusted_context,
            &task,
            &create,
            now,
            plan_proof,
            plan_action,
        )
        .map_err(|_| "gateway.task.effect-plan-human-proof")?
        .bind_preflight_policy(
            self.populate_preflight
                .as_ref()
                .map(|pin| (pin.rule_digest.as_str(), pin.public_key_hex.as_str())),
        );
        self.ledger
            .record_effect_plan(task_id, &plan, now)
            .map_err(|_| "gateway.task.effect-plan-journal")?;
        Ok(())
    }

    /// Verify and durably bind a fresh preflight report from the installed
    /// credential-bearing vertical. The report signer and rule digest are
    /// pinned before the human effect plan is recorded. This does not write
    /// to the provider or authorize a changed draft.
    pub fn record_populate_preflight(
        &self,
        task_id: &str,
        report: &[u8],
    ) -> Result<(), &'static str> {
        let pin = self
            .populate_preflight
            .as_ref()
            .ok_or("gateway.task.preflight-not-installed")?;
        let now = wall_clock_seconds().ok_or("gateway.task.preflight-clock")?;
        let state = self
            .ledger
            .load(task_id)
            .map_err(|_| "gateway.task.preflight-state")?
            .ok_or("gateway.task.preflight-state")?;
        let task = state
            .activated_task(&self.pins, now)
            .map_err(|_| "gateway.task.preflight-inactive")?;
        let plan = state
            .effect_plan()
            .ok_or("gateway.task.preflight-plan-required")?;
        let child = state
            .bound_child_scope()
            .ok_or("gateway.task.preflight-child-required")?;
        let expected = ExpectedPopulatePreflight {
            task_id,
            task_commitment: &hex::encode(task.commitment()),
            child_id: &child.handle,
            rule_digest: &pin.rule_digest,
            plan,
        };
        let verified = verify_populate_preflight(report, &pin.public_key_hex, &expected, now)
            .ok_or("gateway.task.preflight-report-refused")?;
        self.ledger
            .record_populate_preflight(task_id, &verified, now)
            .map_err(|_| "gateway.task.preflight-journal")?;
        Ok(())
    }

    /// Return only the journal-derived, secret-free inputs required by the
    /// installed vertical's fresh child GETs and signed report.
    pub fn populate_preflight_inputs(
        &self,
        task_id: &str,
    ) -> Result<TaskPopulatePreflightInputs, &'static str> {
        let pin = self
            .populate_preflight
            .as_ref()
            .ok_or("gateway.task.preflight-not-installed")?;
        let now = wall_clock_seconds().ok_or("gateway.task.preflight-clock")?;
        let state = self
            .ledger
            .load(task_id)
            .map_err(|_| "gateway.task.preflight-state")?
            .ok_or("gateway.task.preflight-state")?;
        let task = state
            .activated_task(&self.pins, now)
            .map_err(|_| "gateway.task.preflight-inactive")?;
        let plan = state
            .effect_plan()
            .ok_or("gateway.task.preflight-plan-required")?;
        let child = state
            .bound_child_scope()
            .ok_or("gateway.task.preflight-child-required")?;
        let pending = task
            .descriptor()
            .pending_child
            .as_ref()
            .ok_or("gateway.task.preflight-child-required")?;
        if plan.expires_at <= now
            || plan.preflight_rule_digest.as_deref() != Some(pin.rule_digest.as_str())
            || plan.preflight_key_sha256.as_deref() != Some(pin.key_sha256().as_str())
            || plan.populate_recipe_digest != child.recipe_digest
        {
            return Err("gateway.task.preflight-policy-changed");
        }
        Ok(TaskPopulatePreflightInputs {
            schema: "auths.gateway-task-populate-preflight-inputs/1",
            task_id: task_id.to_owned(),
            task_commitment: hex::encode(task.commitment()),
            plan_commitment: plan.plan_commitment.clone(),
            create_operation_id: plan.create.operation_id.clone(),
            child_id: child.handle,
            populate_recipe_digest: plan.populate_recipe_digest.clone(),
            preflight_rule_digest: pin.rule_digest.clone(),
            connection_id: plan.create.connection_id.clone(),
            connection_generation: plan.create.connection_generation,
            connection_subject: plan.create.connection_subject.clone(),
            parent_id: pending.parent_handle.clone(),
            title: pending.title.clone(),
            marker: pending.marker.clone(),
            plan_expires_at: plan.expires_at,
        })
    }

    /// Reconcile a recorded create response after a crash between the
    /// attempt's metadata observation and the task-journal child binding.
    /// This path re-verifies the original agent and human actions, leases the
    /// same subject-bound connection for one metadata GET, and never repeats
    /// the provider create. A lost response has no ID and is ineligible.
    ///
    /// # Errors
    /// Refuses absent or changed task/attempt evidence, invalid native
    /// proofs, a changed connection, failed metadata, or a journal conflict.
    #[allow(
        clippy::too_many_lines,
        reason = "each proof, attempt and provider-read boundary remains explicit"
    )]
    pub async fn reconcile_created_child(
        &self,
        proofs: TaskWriteProofs<'_>,
    ) -> Result<String, &'static str> {
        if self.engine.recipe.created_child_fields().is_none() {
            return Err("gateway.task.reconcile-not-create");
        }
        let now = wall_clock_seconds().ok_or("gateway.task.reconcile-clock")?;
        let state = self
            .ledger
            .load(proofs.task_id)
            .map_err(|_| "gateway.task.reconcile-state")?
            .ok_or("gateway.task.reconcile-state")?;
        let task = state
            .activated_task(&self.pins, now)
            .map_err(|_| "gateway.task.reconcile-inactive")?;
        if task.descriptor().write_approval_mode != WriteApprovalMode::Exact {
            return Err("gateway.task.reconcile-approval-mode");
        }
        let verified = verify_detailed(
            &self.engine.recipe,
            &self.engine.trusted_context,
            now,
            proofs.agent_proof,
            proofs.agent_action,
        )
        .map_err(|_| "gateway.task.reconcile-agent-proof")?;
        let intent = derive_exact_write_intent(
            &task,
            &verified,
            &self.engine.recipe,
            &self.binding,
            None,
            now,
        )
        .map_err(|_| "gateway.task.reconcile-intent")?;
        if intent.verb != crate::task_activation::TaskWriteVerb::Create {
            return Err("gateway.task.reconcile-not-create");
        }
        let approved = if let Some((proof, action)) = proofs.confirmation {
            verify_exact_write_confirmation(
                &self.engine.trusted_context,
                &task,
                intent.clone(),
                now,
                proof,
                action,
            )
            .map_err(|_| "gateway.task.reconcile-confirmation")?
        } else {
            let plan = state
                .effect_plan()
                .ok_or("gateway.task.reconcile-confirmation")?;
            ApprovedTaskWrite::from_recorded_effect_plan_reconciliation(plan, intent.clone())
                .map_err(|_| "gateway.task.reconcile-confirmation")?
        };
        let request = &verified.request;
        let child = request
            .created_child()
            .ok_or("gateway.task.reconcile-not-create")?;
        let plan = request
            .observation_template()
            .ok_or("gateway.task.reconcile-plan")?;
        let attempt = self
            .engine
            .attempts
            .resume_created_child_observation(
                self.engine.recipe.namespace(),
                request.operation_id(),
                *self.engine.recipe.digest(),
                plan,
            )
            .await
            .map_err(|_| "gateway.task.reconcile-attempt")?
            .ok_or("gateway.task.reconcile-attempt")?;
        let snapshot = attempt
            .snapshot()
            .map_err(|_| "gateway.task.reconcile-attempt")?;
        if hex::encode(snapshot.action_commitment()) != intent.action_commitment {
            return Err("gateway.task.reconcile-action-mismatch");
        }
        let candidate_id = snapshot
            .response_locator()
            .and_then(|locator| locator.get(&child.response_id_pointer))
            .ok_or("gateway.task.reconcile-candidate")?;
        let response_digest = snapshot
            .response_digest()
            .ok_or("gateway.task.reconcile-response")?;
        let observation = attempt
            .observation_request()
            .ok_or("gateway.task.reconcile-plan")?;
        let io = EngineIo {
            engine: self.engine,
            proof: proofs.agent_proof,
            action: proofs.agent_action,
            started: Instant::now(),
            prepared: OnceLock::new(),
            task_write: Some(TaskWriteAdmission {
                task: &task,
                binding: &self.binding,
                approved: &approved,
                ledger: &self.ledger,
                child_scope: None,
                preflight_valid_until: None,
            }),
            commissioning: None,
            commissioned_action: OnceLock::new(),
            commissioning_refusal: OnceLock::new(),
        };
        io.prepare().await?;
        if !io.reload().await {
            return Err("gateway.task.reconcile-connection-changed");
        }
        let lease = io
            .lease()
            .await
            .ok_or("gateway.task.reconcile-credential")?;
        let response = io
            .action_read(
                &lease,
                observation.url(),
                observation.headers(),
                observation.maximum_response_bytes(),
            )
            .await;
        let body = response
            .as_ref()
            .and_then(ProviderResponse::usable_body)
            .ok_or("gateway.task.reconcile-metadata")?;
        if observation.read_back(None, body)
            != Some(crate::recipe::ReadBack::Value { matched: true })
        {
            return Err("gateway.task.reconcile-metadata");
        }
        let verified_child = child
            .verify_metadata(candidate_id, body)
            .ok_or("gateway.task.reconcile-metadata")?;
        if !io.reload().await {
            return Err("gateway.task.reconcile-connection-changed");
        }
        if snapshot.stage() == crate::GatewayAttemptStage::ResponseRecorded {
            attempt
                .record_observation(true)
                .await
                .map_err(|_| "gateway.task.reconcile-observation")?;
        }
        self.ledger
            .bind_created_child(
                &approved,
                &verified_child,
                response_digest,
                wall_clock_seconds().ok_or("gateway.task.reconcile-clock")?,
            )
            .map_err(|_| "gateway.task.reconcile-binding")?;
        Ok(candidate_id.clone())
    }
}

#[cfg(unix)]
fn task_connection_matches(record: &ConnectionRecord, binding: &TaskWriteBinding) -> bool {
    record.connection_id().as_str() == binding.connection_id
        && record.generation().get() == binding.connection_generation
        && record.account_commitment() == &submit::account_commitment(&binding.connection_subject)
}

#[cfg(unix)]
fn task_trust_available(context: &TrustedContext) -> bool {
    let (Ok(audience), Ok(namespace)) = (
        Audience::parse(&format!("mcp://{TASK_SERVICE}")),
        ResourceId::parse(&format!("mcp://{TASK_SERVICE}/")),
    ) else {
        return false;
    };
    [APPROVAL_TOOL, CONFIRMATION_TOOL].into_iter().all(|tool| {
        let Ok(call) = McpToolCall::new(TASK_SERVICE, tool, Map::new()) else {
            return false;
        };
        let (Ok(profile), Ok(permission)) = (call.profile_ref(), call.permission()) else {
            return false;
        };
        context.trust_anchors().iter().any(|anchor| {
            anchor.profiles().contains(&profile)
                && anchor.permissions().contains(&permission)
                && anchor.resource_namespaces().contains(&namespace)
                && anchor.audiences().contains(&audience)
        })
    })
}

#[cfg(unix)]
struct TaskWriteSubmission<'a> {
    pub(crate) pins: &'a TaskActivationPins,
    pub(crate) binding: &'a TaskWriteBinding,
    pub(crate) ledger: &'a FileReleaseTaskLedger,
    pub(crate) preflight_pin: Option<&'a PopulatePreflightPin>,
    pub(crate) task_id: &'a str,
    pub(crate) agent_proof: &'a [u8],
    pub(crate) agent_action: &'a [u8],
    pub(crate) confirmation: Option<(&'a [u8], &'a [u8])>,
    pub(crate) use_effect_plan: bool,
}

#[cfg(unix)]
struct TaskWriteAdmission<'a> {
    task: &'a ApprovedAgentTask,
    binding: &'a TaskWriteBinding,
    approved: &'a ApprovedTaskWrite,
    ledger: &'a FileReleaseTaskLedger,
    child_scope: Option<crate::task_activation::TaskWriteScope>,
    preflight_valid_until: Option<u64>,
}

struct EngineIo<'a> {
    engine: &'a GatewayEngine,
    proof: &'a [u8],
    action: &'a [u8],
    started: Instant,
    prepared: OnceLock<PreparedEntry>,
    #[cfg(unix)]
    task_write: Option<TaskWriteAdmission<'a>>,
    #[cfg(unix)]
    commissioning: Option<&'a CommissioningSession<'a>>,
    #[cfg(unix)]
    commissioned_action: OnceLock<commissioning::CommissionedAction>,
    #[cfg(unix)]
    commissioning_refusal: OnceLock<&'static str>,
}

impl SubmitIo for EngineIo<'_> {
    type Lease = StoredSecretLease;

    fn clock(&self) -> Option<u64> {
        #[cfg(unix)]
        if self.commissioning.is_some() {
            return Some(self.engine.qualification.commissioning_time().0);
        }
        wall_clock_seconds()
    }

    fn verify(&self, now: u64) -> Result<VerifiedCommand, GatewaySubmitResult> {
        let verified = verify_detailed(
            &self.engine.recipe,
            &self.engine.trusted_context,
            now,
            self.proof,
            self.action,
        )?;
        #[cfg(unix)]
        if let Some(admission) = &self.task_write {
            let intent = derive_exact_write_intent(
                admission.task,
                &verified,
                &self.engine.recipe,
                admission.binding,
                admission.child_scope.as_ref(),
                now,
            )?;
            if &intent != admission.approved.intent() {
                return Err(not_entered("gateway.task.write-action-changed"));
            }
        }
        #[cfg(unix)]
        if let Some(session) = self.commissioning {
            let action = session.bind_verified(&verified).map_err(not_entered)?;
            self.commissioned_action
                .set(action)
                .map_err(|_| not_entered("gateway.commissioning.binding-mismatch"))?;
        }
        Ok(verified)
    }

    fn bind_scope(&self, verified: &VerifiedCommand) -> Result<(), &'static str> {
        crate::bounds::bind_account_scope(
            &self.engine.recipe,
            verified.bound.as_ref(),
            &verified.arguments,
        )
    }

    fn reserve_task_write(
        &self,
        _verified: &VerifiedCommand,
        now: u64,
    ) -> Result<(), &'static str> {
        #[cfg(unix)]
        {
            if let Some(admission) = &self.task_write {
                let now = if let Some(valid_until) = admission.preflight_valid_until {
                    let current = wall_clock_seconds().ok_or("gateway.task.preflight-clock")?;
                    if current >= valid_until {
                        return Err("gateway.task.preflight-stale");
                    }
                    current
                } else {
                    now
                };
                return admission
                    .ledger
                    .reserve_write(admission.approved, now)
                    .map(|_| ())
                    .map_err(crate::release_state::ReleaseStateError::write_code);
            }
        }
        if self.engine.recipe.requires_task_admission() {
            Err("gateway.task.task-submit-required")
        } else {
            Ok(())
        }
    }

    fn bind_created_child(
        &self,
        child: &crate::recipe::VerifiedCreatedChild,
        response_digest: &[u8; 32],
        now: u64,
    ) -> bool {
        #[cfg(unix)]
        if let Some(admission) = &self.task_write {
            return admission
                .ledger
                .bind_created_child(admission.approved, child, response_digest, now)
                .is_ok();
        }
        false
    }

    async fn prepare(&self) -> Result<(), &'static str> {
        #[cfg(unix)]
        let prepared = match self.commissioning {
            Some(session) => {
                let action = self
                    .commissioned_action
                    .get()
                    .ok_or("gateway.commissioning.binding-mismatch")?;
                self.engine
                    .prepare_entry_for(|| session.check(action))
                    .await?
            }
            None => self.engine.prepare_entry().await?,
        };
        #[cfg(not(unix))]
        let prepared = self.engine.prepare_entry().await?;
        #[cfg(unix)]
        if let Some(admission) = &self.task_write
            && !task_connection_matches(prepared.loaded.record(), admission.binding)
        {
            return Err("gateway.task.connection-changed");
        }
        self.prepared
            .set(prepared)
            .map_err(|_| "gateway.transport.preparation")
    }

    async fn reload(&self) -> bool {
        #[cfg(unix)]
        if self.task_write.as_ref().is_some_and(|admission| {
            admission.preflight_valid_until.is_some_and(|valid_until| {
                wall_clock_seconds().is_none_or(|now| now >= valid_until)
            })
        }) {
            return false;
        }
        #[cfg(unix)]
        if let Some(session) = self.commissioning {
            let checked = self
                .commissioned_action
                .get()
                .ok_or("gateway.commissioning.binding-mismatch")
                .and_then(|action| session.check(action));
            if let Err(code) = checked {
                let _ = self.commissioning_refusal.set(code);
                return false;
            }
        }
        match self.prepared.get() {
            Some(prepared) => self.engine.unchanged(prepared).await,
            None => false,
        }
    }

    fn enter(&self) {
        self.engine.in_flight.fetch_add(1, Ordering::SeqCst);
    }

    fn leave(&self) {
        self.engine.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    async fn lease(&self) -> Option<StoredSecretLease> {
        let prepared = self.prepared.get()?;
        #[cfg(unix)]
        if let Some(session) = self.commissioning {
            if let Err(code) = session.claim(self.commissioned_action.get()?).await {
                let _ = self.commissioning_refusal.set(code);
                return None;
            }
            if !self.engine.unchanged(prepared).await {
                return None;
            }
            if let Err(code) = session.check(self.commissioned_action.get()?) {
                let _ = self.commissioning_refusal.set(code);
                return None;
            }
            self.engine.execution_witness.lease();
            return self
                .engine
                .credentials
                .lease_secret(
                    &prepared.loaded.record().credential_binding(),
                    Instant::now() + Duration::from_secs(30),
                )
                .await
                .ok();
        }
        self.engine.lease(prepared).await.ok()
    }

    fn authority_refusal(&self) -> Option<&'static str> {
        #[cfg(unix)]
        {
            self.commissioning_refusal.get().copied()
        }
        #[cfg(not(unix))]
        {
            None
        }
    }

    fn secret_admitted(&self, lease: &StoredSecretLease, guard: &GuardChecks) -> bool {
        lease
            .expose(Instant::now())
            .is_ok_and(|secret| guard.admits_secret(secret))
    }

    fn account_commitment(&self) -> Option<[u8; 32]> {
        self.prepared
            .get()
            .map(|prepared| *prepared.loaded.record().account_commitment())
    }

    fn within_entry_deadline(&self, evaluated_at: u64) -> bool {
        self.clock()
            .is_some_and(|now| now <= evaluated_at.saturating_add(ENTRY_DEADLINE_SECONDS))
            && self.started.elapsed() <= Duration::from_secs(ENTRY_DEADLINE_SECONDS)
    }

    async fn write(
        &self,
        lease: &StoredSecretLease,
        request: &ClosedProviderRequest,
    ) -> Result<WriteTransportOutcome, GatewayTransportError> {
        #[cfg(unix)]
        if self.task_write.as_ref().is_some_and(|admission| {
            admission.preflight_valid_until.is_some_and(|valid_until| {
                wall_clock_seconds().is_none_or(|now| now >= valid_until)
            })
        }) {
            return Err(GatewayTransportError::NotEntered);
        }
        match self.prepared.get() {
            Some(prepared) => {
                LeasedTransport {
                    transport: &prepared.transport,
                    lease,
                }
                .write(request)
                .await
            }
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
        let prepared = self.prepared.get()?;
        LeasedTransport {
            transport: &prepared.transport,
            lease,
        }
        .action_read(url, headers, maximum_response_bytes)
        .await
    }

    async fn credential_read(
        &self,
        lease: &StoredSecretLease,
        read: &ClosedCredentialRead,
    ) -> Option<ProviderResponse> {
        let prepared = self.prepared.get()?;
        LeasedTransport {
            transport: &prepared.transport,
            lease,
        }
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
    /// Exact actors of action IDs already sealed by the native verifier.
    #[cfg(unix)]
    pub(crate) actors: Vec<auths_model::PrincipalId>,
    pub(crate) request: ClosedProviderRequest,
    /// The bounded branch's links and the counters its claim reserves.
    pub(crate) bound: Option<BoundAdmission>,
    /// Every approver whose approval the verifier counted, ascending.
    pub(crate) approvers: Vec<auths_model::PrincipalId>,
    pub(crate) arguments: Map<String, Value>,
    /// Every observation requirement of every grant of every authorized
    /// branch.
    pub(crate) requirements: Vec<ObservationRequirement>,
    /// The verified canonical action, the source of action facts.
    pub(crate) canonical_action: CanonicalAction,
    /// The longest validity window, `expires_at` minus `not_before`, of any
    /// authorized action envelope.
    pub(crate) validity_seconds: u64,
    /// The per-proof observer check's refusal: an observer of a satisfying
    /// observation overlaps a principal of the authority it conditions by
    /// key. Admission applies it last, after the retention rule and pre-entry
    /// selection, so their codes take precedence.
    pub(crate) observer_refusal: Option<&'static str>,
}

/// [`verify_command`] that also reports what admission and an auditor need.
pub(crate) fn verify_detailed(
    recipe: &CompiledRecipe,
    context: &TrustedContext,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<VerifiedCommand, GatewaySubmitResult> {
    let audience = Audience::parse(&format!("mcp://{}", recipe.service()))
        .map_err(|_| not_entered("gateway.recipe.audience"))?;
    let sealed = verify_sealed_for_audience(context, audience, now, proof_cbor, action_cbor)?;
    let action = authorized_action(&sealed)?;
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
    let observer_refusal = crate::separation::check_proof_observers(proof_cbor, action).err();
    Ok(VerifiedCommand {
        #[cfg(unix)]
        actors: branches.actors,
        request,
        bound,
        approvers: branches.approvers,
        arguments: command.arguments().clone(),
        requirements: branches.requirements,
        canonical_action: action.canonical_action().clone(),
        validity_seconds: branches.validity_seconds,
        observer_refusal,
    })
}

pub(crate) fn authorized_action(
    sealed: &auths_verifier::SealedVerificationResult,
) -> Result<&auths_verifier::VerifiedAction, GatewaySubmitResult> {
    let Some(action) = sealed.action() else {
        let code = sealed.portable().code().code().to_owned();
        return Err(match sealed.portable().decision() {
            VerificationDecision::Denied => GatewaySubmitResult::Denied { code },
            VerificationDecision::Authorized | VerificationDecision::Indeterminate => {
                GatewaySubmitResult::Indeterminate { code }
            }
        });
    };
    Ok(action)
}

/// Rebinds only the verifier's expected audience for a fixed, gateway-owned
/// approval profile. The caller must supply a code-defined audience; agent
/// input must never choose the audience being verified.
pub(crate) fn verify_sealed_for_audience(
    context: &TrustedContext,
    audience: Audience,
    now: u64,
    proof_cbor: &[u8],
    action_cbor: &[u8],
) -> Result<auths_verifier::SealedVerificationResult, GatewaySubmitResult> {
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
        .for_request(audience, context.expected_challenge(), Timestamp::new(now))
        .ok()
        .and_then(|value| auths_codec::encode_verifier_context(&value).ok())
        .ok_or_else(|| GatewaySubmitResult::Indeterminate {
            code: "gateway.verify.invalid-trust".to_owned(),
        })?;
    with_gateway_registries(|registries| {
        auths_verifier::verify_v1_sealed(proof_cbor, action_cbor, &request_context, registries)
    })
    .ok_or_else(indeterminate_registry)?
    .map_err(|_| GatewaySubmitResult::Indeterminate {
        code: "gateway.verify.invalid-input".to_owned(),
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

/// Returns the signed pre-entry observations stored for one logical
/// operation. It signs nothing and contacts no provider.
pub(crate) async fn observe_pre_entry(
    attempts: &GatewayAttempts,
    namespace: &crate::OperatorNamespace,
    operation_id: &str,
) -> GatewayObserveResult {
    let Ok(operation) = crate::LogicalOperationId::parse(operation_id) else {
        return refused("gateway.observer.invalid-operation");
    };
    let snapshot = match attempts.read(namespace, &operation).await {
        Ok(Some(value)) => value,
        Ok(None) => return refused("gateway.observer.operation-unknown"),
        Err(_) => return refused("gateway.observer.store-unavailable"),
    };
    GatewayObserveResult::PreEntry {
        operation_id: operation.as_str().to_owned(),
        observations_b64: snapshot
            .pre_entry()
            .map(|record| {
                record
                    .observations
                    .iter()
                    .map(|bytes| Base64UrlUnpadded::encode_string(bytes))
                    .collect()
            })
            .unwrap_or_default(),
    }
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
pub(crate) mod tests {
    use super::*;
    use sha2::Digest as _;

    fn airtable_recipe() -> CompiledRecipe {
        CompiledRecipe::compile(
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/recipe.json"),
            include_bytes!("../../../../bindings/fixtures/gateway/airtable/profile.lock.json"),
        )
        .expect("fixture compiles")
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one operator-pinned read and write fixture covers native trust and recipient binding"
    )]
    async fn task_session_uses_canonical_operator_pins_for_the_installed_recipe() {
        use crate::{CompiledReleaseRecipe, QualificationGate};

        let mut installation = administration::installation(8).await;
        let engine = &mut installation.first.engine;
        engine.recipe = CompiledRecipe::compile(
            include_bytes!("../../../../demos/airtable-gateway/write_reference/recipe.json"),
            include_bytes!("../../../../demos/airtable-gateway/write_reference/profile.lock.json"),
        )
        .expect("task recipe");
        let record = engine
            .connection
            .load()
            .await
            .expect("connection read")
            .expect("connection");
        let human = crate::harness::Signer::new(0x22);
        let agent = crate::harness::Signer::new(0x44);
        let read_recipe = CompiledReleaseRecipe::compile(
            include_bytes!("../../../../demos/airtable-gateway/read_reference/recipe.json"),
            include_bytes!("../../../../demos/airtable-gateway/read_reference/profile.lock.json"),
        )
        .expect("read recipe");
        let identity = auths_identity_raw_key::RawKeyIdentityMethod::identity(
            auths_signature_ed25519::ED25519_V1,
            agent.key.verifying_key().to_bytes().to_vec(),
        )
        .expect("identity")
        .into_public_identity()
        .to_descriptor()
        .expect("descriptor")
        .encode()
        .expect("identity packet");
        let pins = TaskActivationPins {
            company_id: "atlas".to_owned(),
            human_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: hex::encode(sha2::Sha256::digest(&identity)),
            connection_id: record.record().connection_id().as_str().to_owned(),
            connection_generation: record.record().generation().get(),
            connection_subject: "acct_TESTPLATFORM1".to_owned(),
            permitted_read_scopes: vec![
                serde_json::from_value(serde_json::json!({
                    "handle": "recTEST0000000001", "recipe_digest": read_recipe.digest_hex(),
                    "connection_id": record.record().connection_id().as_str(),
                    "connection_generation": record.record().generation().get(),
                    "connection_subject": "acct_TESTPLATFORM1"
                }))
                .expect("read scope"),
            ],
            delivery_channel: "agent-channel".to_owned(),
            operator_policy_digest: "b".repeat(64),
            allow_bounded_writes: false,
        };
        let config = TaskWriteInstallation {
            schema: TASK_INSTALLATION_SCHEMA.to_owned(),
            populate_preflight: None,
            recipe_digests: vec![engine.recipe.digest_hex()],
            pins,
        };
        let bytes = serde_json_canonicalizer::to_vec(&config).expect("canonical config");
        let directory = tempfile::tempdir().expect("private journal root");
        let task_root = std::fs::canonicalize(directory.path())
            .expect("canonical root")
            .join("task-state");
        assert_eq!(
            engine.task_write_session(&bytes, &task_root).err(),
            Some("gateway.task.trust-profile-unavailable")
        );
        let root = crate::harness::Signer::new(0x11);
        let observer = GatewayObserver::from_test_seed(0x33);
        engine.trusted_context =
            crate::harness::context_for_agent_and_task(&root, observer.principal(), 1_790_000_000)
                .expect("task-capable trust");
        let session = engine
            .task_write_session(&bytes, &task_root)
            .expect("operator session");
        let read_inputs = |recipe, packet| TaskReadOperatorInputs {
            recipe,
            provider: record.record().provider_kind().clone(),
            alias: record.record().alias().clone(),
            generation_floor: crate::GenerationFloor::new(directory.path().to_path_buf()),
            qualification: Arc::new(QualificationGate::development()),
            commitment_key: crate::ReleaseCommitmentKey::new(
                1,
                zeroize::Zeroizing::new([0x77; 32]),
            )
            .expect("commitment key"),
            channel_socket: std::fs::canonicalize(directory.path())
                .expect("canonical path")
                .join("agent.sock"),
            channel_name: "agent-channel".to_owned(),
            agent_identity_packet: packet,
        };
        assert_eq!(
            session
                .read_session(read_inputs(
                    CompiledReleaseRecipe::compile(
                        include_bytes!(
                            "../../../../demos/google-employee-delegation/read_reference/recipe.json"
                        ),
                        include_bytes!(
                            "../../../../demos/google-employee-delegation/read_reference/profile.lock.json"
                        ),
                    )
                    .expect("other read recipe"),
                    identity.clone(),
                ))
                .err(),
            Some("gateway.release.recipe-not-installed")
        );
        assert_eq!(
            session
                .read_session(read_inputs(read_recipe.clone(), vec![0x01]))
                .err(),
            Some("gateway.release.recipient-not-installed")
        );
        session
            .read_session(read_inputs(read_recipe, identity))
            .expect("operator-pinned read session");
        // The shared administration fixture deliberately uses a synthetic
        // account commitment, so it cannot assert this provider subject.
        assert!(!task_connection_matches(record.record(), &session.binding));
        let bound = record.record();
        let subject_bound = ConnectionRecord::new(
            bound.provider_kind().clone(),
            bound.alias().clone(),
            bound.connection_id().clone(),
            bound.contract().clone(),
            bound.descriptor_schema().clone(),
            bound.descriptor().to_vec(),
            submit::account_commitment("acct_TESTPLATFORM1"),
            *bound.credential_reference_commitment(),
            bound.generation(),
            bound.state(),
            bound.allowed_workloads().to_vec(),
            bound.allowed_profiles().to_vec(),
            bound.created_at_unix_seconds(),
            bound.updated_at_unix_seconds(),
            bound.revoked_at_unix_seconds(),
        )
        .expect("subject-bound connection");
        assert!(task_connection_matches(&subject_bound, &session.binding));
        let changed_generation = TaskWriteBinding {
            connection_generation: session.binding.connection_generation + 1,
            ..session.binding.clone()
        };
        assert!(!task_connection_matches(
            &subject_bound,
            &changed_generation
        ));
        assert!(session.activate(&[], &[]).await.is_err());
        let mut noncanonical = serde_json::to_vec_pretty(&config).expect("JSON");
        noncanonical.push(b'\n');
        assert_eq!(
            engine.task_write_session(&noncanonical, &task_root).err(),
            Some("gateway.task.invalid-installation")
        );
        let mut changed: Value = serde_json::from_slice(&bytes).expect("JSON");
        changed["recipe_digests"] = serde_json::json!(["0".repeat(64)]);
        assert_eq!(
            engine
                .task_write_session(
                    &serde_json_canonicalizer::to_vec(&changed).expect("JSON"),
                    &task_root,
                )
                .err(),
            Some("gateway.task.invalid-installation")
        );
        changed["recipe_digests"] = serde_json::json!(vec![engine.recipe.digest_hex(); 2]);
        assert_eq!(
            engine
                .task_write_session(
                    &serde_json_canonicalizer::to_vec(&changed).expect("JSON"),
                    &task_root,
                )
                .err(),
            Some("gateway.task.invalid-installation")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "installed activation fixture includes connection, task and native human proof"
    )]
    async fn installed_task_session_activates_and_gates_exact_agent_write() {
        use crate::harness::{self, Signer};
        use crate::observed_tests::submission_for;
        use crate::task_activation::AgentTaskDescriptor;
        use serde_json::{Map, json};

        let mut installation = administration::installation(8).await;
        let engine = &mut installation.first.engine;
        engine.recipe = CompiledRecipe::compile(
            include_bytes!("../../../../demos/airtable-gateway/write_reference/recipe.json"),
            include_bytes!("../../../../demos/airtable-gateway/write_reference/profile.lock.json"),
        )
        .expect("task recipe");
        #[cfg(feature = "loopback-provider")]
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("loopback listener");
        #[cfg(feature = "loopback-provider")]
        {
            engine.loopback_port = Some(listener.local_addr().expect("loopback address").port());
        }
        let now = wall_clock_seconds().expect("clock");
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let observer = GatewayObserver::from_test_seed(0x33);
        engine.trusted_context = harness::context_for_agent_and_task_profile(
            &root,
            observer.principal(),
            now,
            "airtable-gateway-demo",
            "set_demo_status_v2",
        )
        .expect("installed trust");
        let loaded = engine
            .connection
            .load()
            .await
            .expect("connection read")
            .expect("connection");
        let old = loaded.record();
        let subject = "acct_TESTPLATFORM1";
        let task_descriptor = GatewayConnectionDescriptor::approve(&engine.recipe, "Authorization")
            .expect("task descriptor")
            .to_bytes()
            .expect("task descriptor bytes");
        let bound = ConnectionRecord::new(
            old.provider_kind().clone(),
            old.alias().clone(),
            old.connection_id().clone(),
            old.contract().clone(),
            old.descriptor_schema().clone(),
            task_descriptor,
            submit::account_commitment(subject),
            *old.credential_reference_commitment(),
            old.generation(),
            old.state(),
            old.allowed_workloads().to_vec(),
            old.allowed_profiles().to_vec(),
            old.created_at_unix_seconds(),
            old.updated_at_unix_seconds(),
            old.revoked_at_unix_seconds(),
        )
        .expect("subject-bound connection");
        engine
            .connection
            .replace(&loaded, &bound)
            .await
            .expect("bind subject");
        let pins = TaskActivationPins {
            company_id: "atlas".to_owned(),
            human_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: "a".repeat(64),
            connection_id: bound.connection_id().as_str().to_owned(),
            connection_generation: bound.generation().get(),
            connection_subject: subject.to_owned(),
            permitted_read_scopes: vec![],
            delivery_channel: "agent-channel".to_owned(),
            operator_policy_digest: "b".repeat(64),
            allow_bounded_writes: false,
        };
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/2",
            "task_id": "task-installed-1",
            "company_id": pins.company_id,
            "human_principal": pins.human_principal,
            "agent_principal": pins.agent_principal,
            "agent_key_fingerprint": pins.agent_key_fingerprint,
            "connection_id": pins.connection_id,
            "connection_generation": pins.connection_generation,
            "connection_subject": pins.connection_subject,
            "read_scopes": [],
            "write_scopes": [{"handle": "recTEST0000000001",
                              "recipe_digest": engine.recipe.digest_hex(), "verb": "edit",
                              "connection_id": pins.connection_id,
                              "connection_generation": pins.connection_generation,
                              "connection_subject": pins.connection_subject}],
            "delivery_channel": pins.delivery_channel,
            "not_before": now - 30,
            "expires_at": now + 600,
            "max_provider_calls": 0,
            "max_releases": 0,
            "max_release_bytes": 0,
            "max_writes": 1,
            "write_approval_mode": "exact",
            "operator_policy_digest": pins.operator_policy_digest,
            "purpose": "Edit one test record"
        }))
        .expect("card");
        let config = TaskWriteInstallation {
            schema: TASK_INSTALLATION_SCHEMA.to_owned(),
            populate_preflight: None,
            recipe_digests: vec![engine.recipe.digest_hex()],
            pins,
        };
        let bytes = serde_json_canonicalizer::to_vec(&config).expect("canonical config");
        let directory = tempfile::tempdir().expect("private journal root");
        let root_path = std::fs::canonicalize(directory.path())
            .expect("canonical path")
            .join("task-state");
        let session = engine
            .task_write_session(&bytes, &root_path)
            .expect("operator session");
        let grant = harness::grant_for(
            &root,
            &human.principal,
            now,
            "auths-agent-task",
            "approve_agent_task_v1",
        )
        .expect("human grant");
        let mut arguments = Map::new();
        arguments.insert(
            "task".to_owned(),
            serde_json::to_value(&card).expect("card"),
        );
        let signed = submission_for(
            &root,
            &human,
            &grant,
            &arguments,
            &[],
            "auths-agent-task",
            "approve_agent_task_v1",
            now,
        );
        let mut expanded: Value = serde_json::to_value(&config).expect("task installation");
        let mut digests = vec![engine.recipe.digest_hex(), "f".repeat(64)];
        digests.sort();
        expanded["recipe_digests"] = serde_json::json!(digests);
        let expanded_bytes = serde_json_canonicalizer::to_vec(&expanded).expect("installation");
        let expanded_session = engine
            .task_write_session(&expanded_bytes, root_path.with_file_name("expanded-state"))
            .expect("bounded task installation");
        assert!(matches!(
            expanded_session.activate(&signed.proof, &signed.action).await,
            Err(GatewaySubmitResult::NotEntered { code }) if code == "gateway.task.recipe-not-installed"
        ));
        session
            .activate(&signed.proof, &signed.action)
            .await
            .expect("activated signed task");
        let activated = session
            .ledger
            .load(&card.task_id)
            .expect("journal read")
            .expect("activated state");
        assert!(activated.activated_task(&config.pins, now + 301).is_ok());
        assert_eq!(
            activated.activated_task(&config.pins, now + 601).err(),
            Some(crate::release_state::ReleaseStateError::Inactive)
        );
        let mut drifted_pins: TaskActivationPins =
            serde_json::from_value(serde_json::to_value(&config.pins).expect("pins"))
                .expect("pins");
        drifted_pins.operator_policy_digest = "c".repeat(64);
        assert_eq!(
            activated.activated_task(&drifted_pins, now + 301).err(),
            Some(crate::release_state::ReleaseStateError::Binding)
        );
        assert!(
            session
                .activate(&signed.proof, &signed.action)
                .await
                .is_err()
        );
        let approved = verify_task_activation(
            &engine.trusted_context,
            &config.pins,
            now,
            &signed.proof,
            &signed.action,
        )
        .expect("approved task");
        let agent_grant = harness::grant_for(
            &root,
            &agent.principal,
            now,
            "airtable-gateway-demo",
            "set_demo_status_v2",
        )
        .expect("agent grant");
        let agent_arguments = json!({
            "operator_namespace": "airtable-demo",
            "operation_id": "write-installed-1",
            "recipe_digest": engine.recipe.digest_hex(),
            "record_id": "recTEST0000000001",
            "replacement": "Approved",
            "task_id": card.task_id,
            "task_commitment": hex::encode(approved.commitment()),
        });
        let agent_signed = submission_for(
            &root,
            &agent,
            &agent_grant,
            agent_arguments.as_object().expect("agent arguments"),
            &[],
            "airtable-gateway-demo",
            "set_demo_status_v2",
            now,
        );
        let verified = verify_detailed(
            &engine.recipe,
            &engine.trusted_context,
            now,
            &agent_signed.proof,
            &agent_signed.action,
        )
        .expect("native agent action");
        let intent = derive_exact_write_intent(
            &approved,
            &verified,
            &engine.recipe,
            &session.binding,
            None,
            now,
        )
        .expect("closed write intent");
        let missing_confirmation = session
            .submit(TaskWriteProofs {
                task_id: &card.task_id,
                agent_proof: &agent_signed.proof,
                agent_action: &agent_signed.action,
                confirmation: None,
            })
            .await;
        assert_eq!(
            missing_confirmation,
            not_entered("gateway.task.exact-confirmation-required")
        );
        assert_eq!(
            session
                .ledger
                .load("task-installed-1")
                .expect("ledger")
                .expect("task")
                .write_count(),
            0
        );
        let confirmation_grant = harness::grant_for(
            &root,
            &human.principal,
            now,
            TASK_SERVICE,
            CONFIRMATION_TOOL,
        )
        .expect("confirmation grant");
        let mut confirmation_arguments = Map::new();
        confirmation_arguments.insert(
            "write".to_owned(),
            serde_json::to_value(&intent).expect("intent"),
        );
        let confirmation = submission_for(
            &root,
            &human,
            &confirmation_grant,
            &confirmation_arguments,
            &[],
            TASK_SERVICE,
            CONFIRMATION_TOOL,
            now,
        );
        assert!(
            verify_exact_write_confirmation(
                &engine.trusted_context,
                &approved,
                intent,
                now,
                &confirmation.proof,
                &confirmation.action,
            )
            .is_ok()
        );
        let current = engine
            .connection
            .load()
            .await
            .expect("connection")
            .expect("record");
        let active = current.record();
        let drifted = ConnectionRecord::new(
            active.provider_kind().clone(),
            active.alias().clone(),
            active.connection_id().clone(),
            active.contract().clone(),
            active.descriptor_schema().clone(),
            old.descriptor().to_vec(),
            *active.account_commitment(),
            *active.credential_reference_commitment(),
            active.generation(),
            active.state(),
            active.allowed_workloads().to_vec(),
            active.allowed_profiles().to_vec(),
            active.created_at_unix_seconds(),
            active.updated_at_unix_seconds(),
            active.revoked_at_unix_seconds(),
        )
        .expect("drifted descriptor");
        engine
            .connection
            .replace(&current, &drifted)
            .await
            .expect("simulate operator descriptor change");
        let result = session
            .submit(TaskWriteProofs {
                task_id: &card.task_id,
                agent_proof: &agent_signed.proof,
                agent_action: &agent_signed.action,
                confirmation: Some((&confirmation.proof, &confirmation.action)),
            })
            .await;
        // A changed connection descriptor after activation refuses at
        // preparation before a claim, lease or provider request.
        assert_eq!(result, not_entered("gateway.connection.recipe-mismatch"));
        assert_eq!(
            session
                .ledger
                .load("task-installed-1")
                .expect("ledger")
                .expect("task")
                .write_count(),
            0
        );
        assert_eq!(installation.first.leases.load(Ordering::SeqCst), 0);

        #[cfg(feature = "loopback-provider")]
        {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            let loaded = engine
                .connection
                .load()
                .await
                .expect("connection")
                .expect("record");
            let old = loaded.record();
            let descriptor = GatewayConnectionDescriptor::approve(&engine.recipe, "Authorization")
                .expect("descriptor")
                .to_bytes()
                .expect("descriptor bytes");
            let ready = ConnectionRecord::new(
                old.provider_kind().clone(),
                old.alias().clone(),
                old.connection_id().clone(),
                old.contract().clone(),
                old.descriptor_schema().clone(),
                descriptor,
                *old.account_commitment(),
                *old.credential_reference_commitment(),
                old.generation(),
                old.state(),
                old.allowed_workloads().to_vec(),
                old.allowed_profiles().to_vec(),
                old.created_at_unix_seconds(),
                old.updated_at_unix_seconds(),
                old.revoked_at_unix_seconds(),
            )
            .expect("ready connection");
            engine
                .connection
                .replace(&loaded, &ready)
                .await
                .expect("install task descriptor");
            let provider = tokio::spawn(async move {
                const BODY: &[u8] =
                    br#"{"id":"recTEST0000000001","fields":{"DemoStatus":"Approved"}}"#;
                let mut methods = Vec::new();
                for _ in 0..2 {
                    let Ok(Ok((mut stream, _))) =
                        tokio::time::timeout(Duration::from_secs(5), listener.accept()).await
                    else {
                        break;
                    };
                    let mut bytes = Vec::new();
                    let mut chunk = [0_u8; 4096];
                    let end = loop {
                        let read = stream.read(&mut chunk).await.expect("provider request");
                        assert!(read > 0, "provider request ended early");
                        bytes.extend_from_slice(&chunk[..read]);
                        if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                            break end;
                        }
                    };
                    let head = String::from_utf8(bytes[..end].to_vec()).expect("request head");
                    methods.push(head.split_whitespace().next().expect("method").to_owned());
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(str::to_owned)
                        })
                        .map_or(0, |value| value.trim().parse::<usize>().expect("length"));
                    while bytes.len() < end + 4 + length {
                        let read = stream.read(&mut chunk).await.expect("provider body");
                        assert!(read > 0, "provider body ended early");
                        bytes.extend_from_slice(&chunk[..read]);
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        BODY.len()
                    );
                    stream
                        .write_all(response.as_bytes())
                        .await
                        .expect("response");
                    stream.write_all(BODY).await.expect("response body");
                }
                methods
            });
            let result = session
                .submit(TaskWriteProofs {
                    task_id: &card.task_id,
                    agent_proof: &agent_signed.proof,
                    agent_action: &agent_signed.action,
                    confirmation: Some((&confirmation.proof, &confirmation.action)),
                })
                .await;
            let methods = provider.await.expect("provider task");
            assert_eq!(methods, ["PATCH", "GET"]);
            assert!(
                matches!(result, GatewaySubmitResult::Observed { matched: true, .. }),
                "unexpected gateway result: {result:?}"
            );
            assert_eq!(
                session
                    .ledger
                    .load("task-installed-1")
                    .expect("ledger")
                    .expect("task")
                    .write_count(),
                1
            );
            let leases = installation.first.leases.load(Ordering::SeqCst);
            assert!(leases > 0);
            let replay = session
                .submit(TaskWriteProofs {
                    task_id: &card.task_id,
                    agent_proof: &agent_signed.proof,
                    agent_action: &agent_signed.action,
                    confirmation: Some((&confirmation.proof, &confirmation.action)),
                })
                .await;
            assert_eq!(replay, not_entered("gateway.task.write-replay"));
            assert_eq!(installation.first.leases.load(Ordering::SeqCst), leases);
            session
                .revoke(&card.task_id)
                .expect("durable task revocation");
            let revoked = session
                .submit(TaskWriteProofs {
                    task_id: &card.task_id,
                    agent_proof: &agent_signed.proof,
                    agent_action: &agent_signed.action,
                    confirmation: Some((&confirmation.proof, &confirmation.action)),
                })
                .await;
            assert_eq!(revoked, not_entered("gateway.task.inactive"));
            assert_eq!(installation.first.leases.load(Ordering::SeqCst), leases);
        }
    }

    #[cfg(all(unix, feature = "loopback-provider"))]
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "the crash recovery fixture spans native proofs, two journals and one metadata-only provider read"
    )]
    async fn recorded_create_reconciles_child_without_reentering_provider_write() {
        use crate::harness::{self, Signer};
        use crate::observed_tests::submission_for;
        use crate::task_activation::{AgentTaskDescriptor, ApprovedAgentTask};
        use auths_connections::SemanticId;
        use base64ct::{Base64Unpadded, Encoding as _};
        use ed25519_dalek::{Signer as _, SigningKey};
        use serde_json::{Map, json};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let mut installation = administration::installation(8).await;
        let engine = &mut installation.first.engine;
        engine.recipe = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/create_reference/profile.lock.json"
            ),
        )
        .expect("create recipe");
        let populate = CompiledRecipe::compile(
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/recipe.json"
            ),
            include_bytes!(
                "../../../../demos/google-employee-delegation/populate_reference/profile.lock.json"
            ),
        )
        .expect("populate recipe");
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("read-only provider listener");
        engine.loopback_port = Some(listener.local_addr().expect("loopback address").port());
        let now = wall_clock_seconds().expect("clock");
        let root = Signer::new(0x11);
        let human = Signer::new(0x22);
        let agent = Signer::new(0x44);
        let observer = GatewayObserver::from_test_seed(0x33);
        engine.trusted_context = harness::context_for_agent_and_task_profiles(
            &root,
            observer.principal(),
            now,
            &[
                (
                    "google-drive-delegation-demo",
                    "create_project_a_document_v1",
                ),
                (
                    "google-docs-delegation-demo",
                    "populate_created_project_a_document_v1",
                ),
            ],
        )
        .expect("task trust");
        let loaded = engine
            .connection
            .load()
            .await
            .expect("connection")
            .expect("record");
        let old = loaded.record();
        let subject = "jules-subject";
        let descriptor = crate::GatewayTaskConnectionDescriptor::approve(
            &[&engine.recipe, &populate],
            "Authorization",
        )
        .expect("paired descriptor")
        .to_bytes()
        .expect("descriptor bytes");
        let bound = ConnectionRecord::new(
            old.provider_kind().clone(),
            old.alias().clone(),
            old.connection_id().clone(),
            old.contract().clone(),
            SemanticId::parse(crate::binding::TASK_CONNECTION_DESCRIPTOR_SCHEMA)
                .expect("descriptor schema"),
            descriptor,
            submit::account_commitment(subject),
            *old.credential_reference_commitment(),
            old.generation(),
            old.state(),
            old.allowed_workloads().to_vec(),
            old.allowed_profiles().to_vec(),
            old.created_at_unix_seconds(),
            old.updated_at_unix_seconds(),
            old.revoked_at_unix_seconds(),
        )
        .expect("subject-bound task connection");
        engine
            .connection
            .replace(&loaded, &bound)
            .await
            .expect("replace descriptor");
        let pins = TaskActivationPins {
            company_id: "atlas".to_owned(),
            human_principal: human.principal.as_str().to_owned(),
            agent_principal: agent.principal.as_str().to_owned(),
            agent_key_fingerprint: "a".repeat(64),
            connection_id: bound.connection_id().as_str().to_owned(),
            connection_generation: bound.generation().get(),
            connection_subject: subject.to_owned(),
            permitted_read_scopes: vec![],
            delivery_channel: "agent-channel".to_owned(),
            operator_policy_digest: "b".repeat(64),
            allow_bounded_writes: false,
        };
        let marker = format!("ap071_{}", "d".repeat(32));
        let card: AgentTaskDescriptor = serde_json::from_value(json!({
            "schema": "auths.agent-task/2", "task_id": "task-create-reconcile",
            "company_id": pins.company_id,
            "human_principal": pins.human_principal,
            "agent_principal": pins.agent_principal,
            "agent_key_fingerprint": pins.agent_key_fingerprint,
            "connection_id": pins.connection_id,
            "connection_generation": pins.connection_generation,
            "connection_subject": pins.connection_subject,
            "read_scopes": [],
            "write_scopes": [{"handle": "project-a-folder",
                "recipe_digest": engine.recipe.digest_hex(), "verb": "create",
                "connection_id": pins.connection_id,
                "connection_generation": pins.connection_generation,
                "connection_subject": pins.connection_subject}],
            "pending_child": {"create_operation_id": "create-reconcile-1",
                "create_recipe_digest": engine.recipe.digest_hex(),
                "populate_recipe_digest": populate.digest_hex(),
                "parent_handle": "project-a-folder",
                "title": "Auths AP-071 Project A handoff", "marker": marker},
            "delivery_channel": pins.delivery_channel,
            "not_before": now - 30, "expires_at": now + 600,
            "max_provider_calls": 0, "max_releases": 0,
            "max_release_bytes": 0, "max_writes": 2,
            "write_approval_mode": "exact",
            "operator_policy_digest": pins.operator_policy_digest,
            "purpose": "Create one child for a handoff"
        }))
        .expect("task card");
        let canonical = serde_json_canonicalizer::to_vec(&card).expect("canonical card");
        let commitment = auths_codec::domain_commitment("auths.agent-task.v2", &canonical)
            .expect("card commitment");
        let task = ApprovedAgentTask::from_test_card(card, *commitment.as_bytes());
        let mut digests = vec![engine.recipe.digest_hex(), populate.digest_hex()];
        digests.sort();
        let preflight_key = SigningKey::from_bytes(&[0x55; 32]);
        let preflight_rule_digest = "2".repeat(64);
        let installation_bytes = serde_json_canonicalizer::to_vec(&TaskWriteInstallation {
            schema: TASK_INSTALLATION_SCHEMA.to_owned(),
            populate_preflight: Some(PopulatePreflightPin {
                public_key_hex: hex::encode(preflight_key.verifying_key().to_bytes()),
                rule_digest: preflight_rule_digest.clone(),
            }),
            recipe_digests: digests,
            pins,
        })
        .expect("task installation");
        let directory = tempfile::tempdir().expect("private root");
        let state_root = std::fs::canonicalize(directory.path())
            .expect("canonical root")
            .join("task-state");
        let session = engine
            .task_write_session(&installation_bytes, &state_root)
            .expect("paired task session");
        session
            .ledger
            .initialize(&task)
            .expect("activate fixture task");
        let grant = harness::grant_for(
            &root,
            &agent.principal,
            now,
            "google-drive-delegation-demo",
            "create_project_a_document_v1",
        )
        .expect("agent create grant");
        let args = json!({
            "operator_namespace": "google-drive-create-demo",
            "operation_id": "create-reconcile-1",
            "recipe_digest": engine.recipe.digest_hex(),
            "task_id": "task-create-reconcile",
            "task_commitment": hex::encode(commitment.as_bytes()),
            "parent_id": "project-a-folder",
            "title": "Auths AP-071 Project A handoff",
            "recovery_marker": marker,
        });
        let signed = submission_for(
            &root,
            &agent,
            &grant,
            args.as_object().expect("arguments"),
            &[],
            "google-drive-delegation-demo",
            "create_project_a_document_v1",
            now,
        );
        let verified = verify_detailed(
            &engine.recipe,
            &engine.trusted_context,
            now,
            &signed.proof,
            &signed.action,
        )
        .expect("verified agent create");
        let intent = derive_exact_write_intent(
            &task,
            &verified,
            &engine.recipe,
            &session.binding,
            None,
            now,
        )
        .expect("exact create intent");
        let effect_plan_grant = harness::grant_for(
            &root,
            &human.principal,
            now,
            TASK_SERVICE,
            crate::task_effect_plan::EFFECT_PLAN_TOOL,
        )
        .expect("human effect-plan grant");
        let mut plan_args = Map::new();
        plan_args.insert(
            "plan".to_owned(),
            json!({
                "schema": "auths.agent-effect-plan/1",
                "task_id": "task-create-reconcile",
                "task_commitment": hex::encode(commitment.as_bytes()),
                "create": intent,
                "populate_recipe_digest": populate.digest_hex(),
                "populate_operation_id": "populate-reconcile-1",
                "initial_text": "Project A handoff draft",
                "expires_at": now + 300,
            }),
        );
        let effect_plan = submission_for(
            &root,
            &human,
            &effect_plan_grant,
            &plan_args,
            &[],
            TASK_SERVICE,
            crate::task_effect_plan::EFFECT_PLAN_TOOL,
            now,
        );
        let mut altered_plan = effect_plan.action.clone();
        *altered_plan.last_mut().expect("plan action byte") ^= 1;
        assert_eq!(
            session
                .submit_planned_effect(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &signed.proof,
                    agent_action: &signed.action,
                    confirmation: None,
                })
                .await,
            GatewaySubmitResult::NotEntered {
                code: "gateway.task.effect-plan-required".to_owned(),
            },
            "no provider entry is possible before the signed plan is durable"
        );
        assert!(
            session
                .record_effect_plan(
                    "task-create-reconcile",
                    &signed.proof,
                    &signed.action,
                    &effect_plan.proof,
                    &altered_plan,
                )
                .is_err(),
            "altered human plan cannot be recorded"
        );
        session
            .record_effect_plan(
                "task-create-reconcile",
                &signed.proof,
                &signed.action,
                &effect_plan.proof,
                &effect_plan.action,
            )
            .expect("record signed effect plan before create reservation");
        assert_eq!(
            session
                .populate_preflight_inputs("task-create-reconcile")
                .err(),
            Some("gateway.task.preflight-child-required"),
            "no preflight may be prepared for an unbound child"
        );
        let mut changed_plan_args = plan_args.clone();
        changed_plan_args
            .get_mut("plan")
            .expect("plan")
            .as_object_mut()
            .expect("plan object")
            .insert("initial_text".to_owned(), json!("Changed draft"));
        let changed_plan = submission_for(
            &root,
            &human,
            &effect_plan_grant,
            &changed_plan_args,
            &[],
            TASK_SERVICE,
            crate::task_effect_plan::EFFECT_PLAN_TOOL,
            now,
        );
        assert_eq!(
            session.record_effect_plan(
                "task-create-reconcile",
                &signed.proof,
                &signed.action,
                &changed_plan.proof,
                &changed_plan.action,
            ),
            Err("gateway.task.effect-plan-journal"),
            "a second signed plan cannot change approved content"
        );
        assert_eq!(installation.first.leases.load(Ordering::SeqCst), 0);
        let provider = tokio::spawn(async move {
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.expect("provider request");
                let mut request = [0_u8; 4096];
                let size = stream
                    .read(&mut request)
                    .await
                    .expect("provider request bytes");
                let head = std::str::from_utf8(&request[..size]).expect("request head");
                if step == 0 {
                    assert!(head.starts_with("POST /drive/v3/files?"), "{head}");
                    let body = br#"{"id":"child_ABC-123"}"#;
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(headers.as_bytes()).await.expect("headers");
                    stream.write_all(body).await.expect("create response");
                    continue;
                }
                assert!(
                    head.starts_with("GET /drive/v3/files/child_ABC-123?"),
                    "{head}"
                );
                if step == 1 {
                    // The create response is recorded, but the observation
                    // connection drops before any metadata can be recorded.
                    continue;
                }
                let parent = if step == 2 {
                    "wrong-parent"
                } else {
                    "project-a-folder"
                };
                let body = format!(
                    "{{\"id\":\"child_ABC-123\",\"name\":\"Auths AP-071 Project A handoff\",\"parents\":[\"{parent}\"],\"properties\":{{\"auths_operation_marker\":\"ap071_dddddddddddddddddddddddddddddddd\"}},\"mimeType\":\"application/vnd.google-apps.document\",\"driveId\":\"0ACsJUU1uex2wUk9PVA\",\"trashed\":false,\"createdTime\":\"2026-10-25T10:03:00Z\"}}"
                );
                let headers = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(headers.as_bytes()).await.expect("headers");
                stream.write_all(body.as_bytes()).await.expect("metadata");
            }
        });
        let result = session
            .submit_planned_effect(TaskWriteProofs {
                task_id: "task-create-reconcile",
                agent_proof: &signed.proof,
                agent_action: &signed.action,
                confirmation: None,
            })
            .await;
        assert!(
            matches!(
                result,
                GatewaySubmitResult::ResponseRecorded { status: 200 }
            ),
            "the provider write entered once and its response was recorded: {result:?}"
        );
        assert_eq!(
            session
                .ledger
                .load("task-create-reconcile")
                .expect("task journal")
                .expect("task state")
                .write_count(),
            1
        );
        drop(session);
        engine.attempts = installation.attempts.reopen();
        let session = engine
            .task_write_session(&installation_bytes, &state_root)
            .expect("reopened task session");
        session
            .record_effect_plan(
                "task-create-reconcile",
                &signed.proof,
                &signed.action,
                &effect_plan.proof,
                &effect_plan.action,
            )
            .expect("same signed plan is idempotent after restart");

        let mut altered = signed.action.clone();
        *altered.last_mut().expect("action byte") ^= 1;
        assert_eq!(
            session
                .reconcile_created_child(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &signed.proof,
                    agent_action: &altered,
                    confirmation: None,
                })
                .await,
            Err("gateway.task.reconcile-agent-proof")
        );
        assert_eq!(installation.first.leases.load(Ordering::SeqCst), 2);
        assert_eq!(
            session
                .reconcile_created_child(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &signed.proof,
                    agent_action: &signed.action,
                    confirmation: None,
                })
                .await,
            Err("gateway.task.reconcile-metadata")
        );
        assert!(
            session
                .ledger
                .load("task-create-reconcile")
                .expect("task journal")
                .expect("task state")
                .bound_child_scope()
                .is_none(),
            "a wrong provider parent cannot bind the child"
        );
        assert_eq!(
            session
                .reconcile_created_child(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &signed.proof,
                    agent_action: &signed.action,
                    confirmation: None,
                })
                .await,
            Ok("child_ABC-123".to_owned())
        );
        provider.await.expect("provider reads completed");
        let state = session
            .ledger
            .load("task-create-reconcile")
            .expect("task journal")
            .expect("task state");
        assert_eq!(
            state.bound_child_scope().expect("bound child").handle,
            "child_ABC-123"
        );
        assert_eq!(
            state.write_count(),
            1,
            "reconciliation cannot reserve another write"
        );
        assert_eq!(installation.first.leases.load(Ordering::SeqCst), 4);

        let preflight_inputs = serde_json::to_value(
            session
                .populate_preflight_inputs("task-create-reconcile")
                .expect("journal-derived preflight inputs"),
        )
        .expect("preflight inputs JSON");
        assert_eq!(preflight_inputs["child_id"], "child_ABC-123");
        assert_eq!(preflight_inputs["parent_id"], "project-a-folder");
        assert_eq!(preflight_inputs["marker"], marker);
        assert_eq!(
            preflight_inputs["plan_commitment"],
            state.effect_plan().expect("plan").plan_commitment
        );

        let recorded_plan = state.effect_plan().expect("recorded effect plan").clone();
        drop(session);
        let populate_listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("populate provider listener");
        engine.loopback_port = Some(
            populate_listener
                .local_addr()
                .expect("populate address")
                .port(),
        );
        engine.recipe = populate;
        let session = engine
            .task_write_session(&installation_bytes, &state_root)
            .expect("populate task session");
        let populate_grant = harness::grant_for(
            &root,
            &agent.principal,
            now,
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
        )
        .expect("agent populate grant");
        let populate_args = json!({
            "operator_namespace": "google-docs-populate-demo",
            "operation_id": "populate-reconcile-1",
            "recipe_digest": engine.recipe.digest_hex(),
            "task_id": "task-create-reconcile",
            "task_commitment": hex::encode(commitment.as_bytes()),
            "document_id": "child_ABC-123",
            "text": "Project A handoff draft",
            "tab_id": "t.0",
            "required_revision_id": "revision-1",
        });
        let populate_signed = submission_for(
            &root,
            &agent,
            &populate_grant,
            populate_args.as_object().expect("populate arguments"),
            &[],
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
            now,
        );
        assert_eq!(
            session
                .submit_planned_effect(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &populate_signed.proof,
                    agent_action: &populate_signed.action,
                    confirmation: None,
                })
                .await,
            not_entered("gateway.task.preflight-required"),
            "a child binding alone cannot authorize population"
        );
        let checked_at = wall_clock_seconds().expect("preflight time");
        let statement = json!({
            "schema": "auths.gateway-task-populate-preflight/1",
            "task_id": "task-create-reconcile",
            "task_commitment": hex::encode(commitment.as_bytes()),
            "plan_commitment": recorded_plan.plan_commitment,
            "create_operation_id": "create-reconcile-1",
            "child_id": "child_ABC-123",
            "populate_recipe_digest": engine.recipe.digest_hex(),
            "preflight_rule_digest": preflight_rule_digest,
            "connection_id": bound.connection_id().as_str(),
            "connection_generation": bound.generation().get(),
            "connection_subject": subject,
            "tab_id": "t.0",
            "revision_id": "revision-1",
            "metadata_sha256": "3".repeat(64),
            "capability_sha256": "4".repeat(64),
            "docs_sha256": "5".repeat(64),
            "checked_at": checked_at,
            "valid_until": checked_at + 60,
        });
        let mut preimage = b"auths.gateway-task-populate-preflight/1\0".to_vec();
        preimage.extend(serde_json_canonicalizer::to_vec(&statement).expect("statement"));
        let report = serde_json_canonicalizer::to_vec(&json!({
            "statement": statement,
            "signature_b64": Base64Unpadded::encode_string(&preflight_key.sign(&preimage).to_bytes()),
        }))
        .expect("signed report");
        session
            .record_populate_preflight("task-create-reconcile", &report)
            .expect("durably record Jules child preflight");
        let mut changed_args = populate_args.clone();
        changed_args["text"] = json!("Changed handoff draft");
        let changed = submission_for(
            &root,
            &agent,
            &populate_grant,
            changed_args.as_object().expect("changed arguments"),
            &[],
            "google-docs-delegation-demo",
            "populate_created_project_a_document_v1",
            now,
        );
        assert_eq!(
            session
                .submit_planned_effect(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &changed.proof,
                    agent_action: &changed.action,
                    confirmation: None,
                })
                .await,
            not_entered("gateway.task.effect-plan-populate-mismatch"),
            "the agent cannot change the human-approved text"
        );
        let populate_provider = tokio::spawn(async move {
            let (mut stream, _) = populate_listener.accept().await.expect("populate request");
            let mut request = [0_u8; 4096];
            let size = stream.read(&mut request).await.expect("populate bytes");
            let request = std::str::from_utf8(&request[..size]).expect("populate request text");
            assert!(
                request.starts_with("POST /v1/documents/child_ABC-123:batchUpdate "),
                "{request}"
            );
            assert!(request.contains("Project A handoff draft"), "{request}");
            assert!(request.contains("revision-1"), "{request}");
            assert!(request.contains("t.0"), "{request}");
            let body = br#"{"documentId":"child_ABC-123","replies":[{}]}"#;
            let headers = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.expect("headers");
            stream.write_all(body).await.expect("populate response");
        });
        let result = session
            .submit_planned_effect(TaskWriteProofs {
                task_id: "task-create-reconcile",
                agent_proof: &populate_signed.proof,
                agent_action: &populate_signed.action,
                confirmation: None,
            })
            .await;
        assert!(
            matches!(
                result,
                GatewaySubmitResult::ResponseRecorded { status: 200 }
            ),
            "planned population entered once: {result:?}"
        );
        tokio::time::timeout(Duration::from_secs(3), populate_provider)
            .await
            .expect("populate provider completed")
            .expect("populate provider task");
        assert_eq!(
            session
                .ledger
                .load("task-create-reconcile")
                .expect("task journal")
                .expect("task state")
                .write_count(),
            2,
            "create and populate share one two-write budget"
        );
        assert_eq!(
            session
                .submit_planned_effect(TaskWriteProofs {
                    task_id: "task-create-reconcile",
                    agent_proof: &populate_signed.proof,
                    agent_action: &populate_signed.action,
                    confirmation: None,
                })
                .await,
            not_entered("gateway.task.write-replay"),
            "a successful population cannot enter the provider again"
        );
    }

    // Connection administration over the shared record and each process's
    // own credential store. Entry is checked through `prepare_entry`, which
    // every submission and read-back passes before any claim, lease, or
    // write, and through the reload the step machine performs before the
    // lease and before entry.
    #[cfg(unix)]
    pub(crate) mod administration {
        use super::*;
        use std::os::unix::fs::PermissionsExt as _;

        struct CountedCredentials {
            store: Arc<auths_connections::PersistentCredentialStore>,
            leases: Arc<AtomicU64>,
        }

        #[async_trait::async_trait]
        impl ConnectionCredentialStore for CountedCredentials {
            async fn install(
                &self,
                connection_id: &auths_connections::ConnectionId,
                generation: std::num::NonZeroU64,
                secret: SecretBytes,
            ) -> Result<
                auths_connections::CredentialReferenceCommitment,
                auths_connections::CredentialStoreError,
            > {
                self.store.install(connection_id, generation, secret).await
            }
            async fn lease_secret(
                &self,
                binding: &auths_connections::CredentialBinding,
                deadline: Instant,
            ) -> Result<StoredSecretLease, auths_connections::CredentialStoreError> {
                self.leases.fetch_add(1, Ordering::SeqCst);
                self.store.lease_secret(binding, deadline).await
            }
            async fn replace(
                &self,
                connection_id: &auths_connections::ConnectionId,
                old_generation: std::num::NonZeroU64,
                new_generation: std::num::NonZeroU64,
                secret: SecretBytes,
            ) -> Result<
                auths_connections::CredentialReferenceCommitment,
                auths_connections::CredentialStoreError,
            > {
                self.store
                    .replace(connection_id, old_generation, new_generation, secret)
                    .await
            }
            async fn revoke(
                &self,
                connection_id: &auths_connections::ConnectionId,
                generation: std::num::NonZeroU64,
            ) -> Result<(), auths_connections::CredentialStoreError> {
                self.store.revoke(connection_id, generation).await
            }
            async fn holds(
                &self,
                binding: &auths_connections::CredentialBinding,
            ) -> Result<(), auths_connections::CredentialStoreError> {
                self.store.holds(binding).await
            }
            async fn confirm(
                &self,
                binding: &auths_connections::CredentialBinding,
                secret: SecretBytes,
            ) -> Result<(), auths_connections::CredentialStoreError> {
                self.store.confirm(binding, secret).await
            }
            async fn retire_superseded(
                &self,
                binding: &auths_connections::CredentialBinding,
            ) -> Result<(), auths_connections::CredentialStoreError> {
                self.store.retire_superseded(binding).await
            }
            async fn delete_connection(
                &self,
                connection_id: &auths_connections::ConnectionId,
                known: &[std::num::NonZeroU64],
            ) -> Result<(), auths_connections::CredentialStoreError> {
                self.store.delete_connection(connection_id, known).await
            }
        }

        /// One gateway process: its own credential store over the shared
        /// attempt store.
        pub(crate) struct Host {
            _state: tempfile::TempDir,
            credentials_directory: std::path::PathBuf,
            pub(crate) engine: GatewayEngine,
            pub(crate) leases: Arc<AtomicU64>,
            /// The same store the engine holds, for assertions on what it
            /// stores.
            store: Arc<auths_connections::PersistentCredentialStore>,
        }

        /// A connection installed through a first host on a shared store.
        pub(crate) struct Installation {
            pub(crate) attempts: crate::store_testkit::TestAttempts,
            pub(crate) connection_id: auths_connections::ConnectionId,
            pub(crate) first: Host,
        }

        fn private_directory(path: &std::path::Path) {
            std::fs::create_dir(path).expect("directory");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("mode");
        }

        pub(crate) fn candidate(value: &str) -> zeroize::Zeroizing<Vec<u8>> {
            zeroize::Zeroizing::new(value.as_bytes().to_vec())
        }

        fn profile() -> ConnectionProfile {
            ConnectionProfile::new(
                auths_connections::SemanticId::parse("auths.mcp").expect("profile"),
                2,
            )
            .expect("profile")
        }

        fn provider() -> ProviderKind {
            ProviderKind::parse("airtable").expect("provider")
        }

        fn alias() -> ConnectionAlias {
            ConnectionAlias::parse("primary").expect("alias")
        }

        /// Opens a host whose credential store holds at most
        /// `credential_entries` generations, over the shared store at
        /// `attempts`, its own instance of the shared store.
        fn host(attempts: GatewayAttempts, credential_entries: usize) -> Host {
            let state = tempfile::tempdir().expect("state");
            let credentials_directory = state.path().join("credentials");
            private_directory(&credentials_directory);
            let store = Arc::new(
                auths_connections::PersistentCredentialStore::open_with_limits(
                    credentials_directory.join("credentials.cbor"),
                    credential_entries,
                    1 << 20,
                )
                .expect("credential store"),
            );
            let leases = Arc::new(AtomicU64::new(0));
            let credentials: Arc<dyn ConnectionCredentialStore> = Arc::new(CountedCredentials {
                store: Arc::clone(&store),
                leases: Arc::clone(&leases),
            });
            let root = crate::harness::Signer::new(0x11);
            let observer = crate::harness::Signer::new(0x33);
            let trust = auths_codec::encode_verifier_context(
                &crate::harness::context(&root, &observer.principal, None, 1_790_000_000)
                    .expect("context"),
            )
            .expect("trust");
            let recipe = airtable_recipe();
            let digest = *recipe.digest();
            let engine = GatewayEngine::new(
                recipe,
                digest,
                &trust,
                provider(),
                alias(),
                "gateway".to_owned(),
                profile(),
                credentials,
                attempts,
            )
            .expect("engine")
            .with_qualification(Arc::new(crate::QualificationGate::development()));
            let mut engine = engine;
            engine.retirement_delay = Duration::ZERO;
            Host {
                _state: state,
                credentials_directory,
                engine,
                leases,
                store,
            }
        }

        pub(crate) async fn installation(credential_entries: usize) -> Installation {
            installation_on(crate::store_testkit::Backend::File, credential_entries).await
        }

        pub(crate) async fn installation_on(
            backend: crate::store_testkit::Backend,
            credential_entries: usize,
        ) -> Installation {
            let attempts = crate::store_testkit::TestAttempts::open(backend);
            let first = host(attempts.reopen(), credential_entries);
            let connection_id =
                auths_connections::ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA").expect("id");
            let recipe = airtable_recipe();
            crate::install_connection(
                &first.engine.connection,
                &*first.engine.credentials,
                |reference| {
                    ConnectionRecord::new(
                        provider(),
                        alias(),
                        auths_connections::ConnectionId::parse("conn_AAAAAAAAAAAAAAAAAAAAAA")
                            .map_err(|_| "id")?,
                        auths_connections::SemanticId::parse("auths.gateway-operation/1")
                            .map_err(|_| "contract")?,
                        auths_connections::SemanticId::parse(
                            "auths.gateway-connection-descriptor/1",
                        )
                        .map_err(|_| "schema")?,
                        GatewayConnectionDescriptor::approve(&recipe, "Authorization")
                            .and_then(|descriptor| descriptor.to_bytes())
                            .map_err(|_| "descriptor")?,
                        [4; 32],
                        reference,
                        std::num::NonZeroU64::MIN,
                        ConnectionState::Active,
                        vec!["gateway".to_owned()],
                        vec![profile()],
                        10,
                        10,
                        None,
                    )
                    .map_err(|_| "record")
                },
                &connection_id,
                SecretBytes::new(b"pat-initial".to_vec()).expect("secret"),
            )
            .await
            .expect("install");
            Installation {
                attempts,
                connection_id,
                first,
            }
        }

        impl Installation {
            /// Opens a further process over the same shared store, holding
            /// no secret until it joins.
            pub(crate) fn second_host(&self) -> Host {
                host(self.attempts.reopen(), 8)
            }

            /// The file store's directory.
            fn file_root(&self) -> std::path::PathBuf {
                std::path::PathBuf::from(self.attempts.location())
            }
        }

        impl Host {
            pub(crate) fn stored(
                &self,
                connection_id: &auths_connections::ConnectionId,
            ) -> Vec<u64> {
                self.store
                    .stored_generations(connection_id)
                    .expect("stored generations")
                    .into_iter()
                    .map(std::num::NonZeroU64::get)
                    .collect()
            }

            pub(crate) async fn record(&self) -> ConnectionRecord {
                self.engine
                    .connection
                    .load()
                    .await
                    .expect("load")
                    .expect("record")
                    .record()
                    .clone()
            }

            /// The refusal code of a new entry, or `None` when entry may
            /// lease: the load before the claim, then the lease itself.
            pub(crate) async fn entry_refusal(&self) -> Option<String> {
                match self.engine.prepare_entry().await {
                    Err(code) => Some(code.to_owned()),
                    Ok(prepared) => self
                        .engine
                        .lease(&prepared)
                        .await
                        .err()
                        .map(|()| "lease".to_owned()),
                }
            }

            /// Prepares an entry, runs `between`, and reports whether the
            /// lease is then refused.
            pub(crate) async fn lease_refused_after(&self, between: impl FnOnce()) -> bool {
                let prepared = self.engine.prepare_entry().await;
                between();
                match prepared {
                    Ok(prepared) => self.engine.lease(&prepared).await.is_err(),
                    Err(_) => true,
                }
            }

            pub(crate) async fn join(
                &self,
                secret: &str,
            ) -> Result<ConnectionRecord, &'static str> {
                crate::join_connection(
                    &self.engine.connection,
                    &*self.engine.credentials,
                    &self.engine.recipe,
                    &candidate(secret),
                )
                .await
            }
        }

        #[tokio::test]
        async fn revocation_after_rotation_and_disable_deletes_every_generation() {
            let installation = installation(8).await;
            let host = &installation.first;
            let id = &installation.connection_id;
            let first = host.engine.prepare_entry().await.expect("active entry");
            assert!(host.engine.lease(&first).await.is_ok());

            let rotated = host
                .engine
                .rotate_connection(candidate("pat-rotated"))
                .await
                .expect("rotate");
            assert_eq!(rotated.code, "gateway.admin.rotated");
            assert!(rotated.drained);
            assert_eq!(host.stored(id), [2], "rotation deletes the old secret");
            assert!(
                !host.engine.unchanged(&first).await,
                "an entry prepared before the rotation fails its reload"
            );
            assert_eq!(host.entry_refusal().await, None);

            let disabled = host.engine.disable_connection().await.expect("disable");
            assert_eq!(disabled.code, "gateway.admin.disabled");
            assert_eq!(host.stored(id), [2], "disabling stores no credential");
            assert_eq!(
                host.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );

            let revoked = host.engine.revoke_connection().await.expect("revoke");
            assert_eq!(revoked.code, "gateway.admin.revoked");
            assert!(host.stored(id).is_empty());
            let record = host.record().await;
            assert_eq!(record.state(), ConnectionState::Revoked);
            assert_eq!(record.generation().get(), 4);
            assert_eq!(record.credential_generation().get(), 2);
            assert_eq!(
                host.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );
        }

        #[tokio::test]
        async fn a_restored_store_below_the_host_floor_cannot_lease_after_restart() {
            restored_store_floor(crate::store_testkit::Backend::File).await;
        }

        #[tokio::test]
        #[ignore = "requires the TLS PostgreSQL fixture"]
        async fn postgres_restore_below_the_host_floor_cannot_lease_after_restart() {
            restored_store_floor(crate::store_testkit::Backend::Postgres).await;
        }

        async fn restored_store_floor(backend: crate::store_testkit::Backend) {
            let installation = installation_on(backend, 8).await;
            let first = &installation.first;
            let old = first.record().await;
            let directory = tempfile::tempdir().expect("floor directory");
            let floor = crate::GenerationFloor::new(directory.path().to_path_buf());
            floor.initialize(&old).expect("first generation");
            let disabled = first
                .engine
                .connection
                .stop(false, wall_clock_seconds().expect("clock"))
                .await
                .expect("disable");
            floor.accept(&disabled).expect("new generation");
            let raw = SharedConnection::new(
                first.engine.attempts.store(),
                old.provider_kind().clone(),
                old.alias().clone(),
            );
            let current = raw.load().await.expect("load").expect("connection");
            raw.replace(&current, &old)
                .await
                .expect("simulate restored database");
            let guarded = raw
                .with_generation_floor(crate::GenerationFloor::new(directory.path().to_path_buf()));
            assert_eq!(guarded.load().await, Err(SharedConnectionError::Rollback));
            let mut restarted = host(first.engine.attempts.clone(), 8);
            restarted.engine.connection = guarded;
            let before = restarted.leases.load(Ordering::SeqCst);
            assert_eq!(
                restarted.entry_refusal().await.as_deref(),
                Some("gateway.connection.restore-rollback")
            );
            assert_eq!(restarted.leases.load(Ordering::SeqCst), before);
            assert_eq!(
                floor.accept(&old),
                Err("gateway.connection.restore-rollback")
            );
            std::fs::write(directory.path().join("connection-floor.json"), b"corrupt")
                .expect("corrupt floor");
            assert_eq!(
                floor.accept(&disabled),
                Err("gateway.connection.restore-rollback")
            );
            for (generation, digest) in [
                (0, "00".repeat(32)),
                (1, "invalid-digest".to_owned()),
                (1, "AA".repeat(32)),
            ] {
                let damaged = serde_json::to_vec(&serde_json::json!({
                    "schema": "auths.gateway-generation-floor/1",
                    "generation": generation,
                    "record_sha256": digest,
                }))
                .expect("damaged floor");
                let path = directory.path().join("connection-floor.json");
                std::fs::write(&path, &damaged).expect("write damaged floor");
                assert_eq!(
                    floor.accept(&disabled),
                    Err("gateway.connection.restore-rollback")
                );
                assert_eq!(std::fs::read(path).expect("retained floor"), damaged);
                assert_eq!(
                    restarted.entry_refusal().await.as_deref(),
                    Some("gateway.connection.restore-rollback")
                );
                assert_eq!(restarted.leases.load(Ordering::SeqCst), before);
            }
        }

        #[tokio::test]
        async fn durable_cleanup_retires_abandoned_generations_and_keeps_active_and_future_secrets()
        {
            let mut installation = installation(8).await;
            let host = &mut installation.first;
            let record = host.record().await;
            let journal = crate::CredentialJournal::new(
                host.credentials_directory
                    .parent()
                    .expect("private root")
                    .to_path_buf(),
            );
            journal.initialize(record.connection_id()).expect("journal");
            journal
                .register(record.connection_id(), record.credential_generation())
                .expect("initial note");
            host.engine.credential_journal = Some(journal.clone());
            host.engine
                .prepare_rotation(candidate("abandoned-secret"))
                .await
                .expect("prepare");
            assert_eq!(host.stored(&installation.connection_id), [1, 2]);
            host.engine.disable_connection().await.expect("disable");
            // Reopening notes models the operator process exiting after prepare.
            host.engine.credential_journal = Some(crate::CredentialJournal::new(
                host.credentials_directory
                    .parent()
                    .expect("root")
                    .to_path_buf(),
            ));
            assert_eq!(
                host.engine
                    .collect_credentials()
                    .await
                    .expect("collect abandoned"),
                1
            );
            assert_eq!(host.stored(&installation.connection_id), [1]);
            host.engine
                .rotate_connection(candidate("published-secret"))
                .await
                .expect("rotate while disabled");
            host.engine
                .collect_credentials()
                .await
                .expect("collect old");
            assert_eq!(host.stored(&installation.connection_id), [3]);
            host.engine
                .prepare_rotation(candidate("future-secret"))
                .await
                .expect("prepare future");
            assert_eq!(
                host.engine
                    .collect_credentials()
                    .await
                    .expect("keep future"),
                0
            );
            assert_eq!(host.stored(&installation.connection_id), [3, 4]);
            let before = host.leases.load(Ordering::SeqCst);
            host.engine
                .connection
                .stop(true, wall_clock_seconds().expect("clock"))
                .await
                .expect("store-only revoke");
            host.engine
                .collect_credentials()
                .await
                .expect("collect revoked");
            assert!(host.stored(&installation.connection_id).is_empty());
            assert_eq!(host.leases.load(Ordering::SeqCst), before);
            assert!(
                journal
                    .generations(&installation.connection_id)
                    .expect("notes")
                    .is_empty()
            );
        }

        #[tokio::test]
        async fn interrupted_install_cleanup_requires_revocation_and_never_repairs_the_floor() {
            let mut installation = installation(8).await;
            let host = &mut installation.first;
            let record = host.record().await;
            let directory = tempfile::tempdir().expect("private cleanup root");
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
                .expect("private cleanup mode");
            let journal = crate::CredentialJournal::new(directory.path().to_path_buf());
            journal.initialize(record.connection_id()).expect("journal");
            journal
                .register(record.connection_id(), record.credential_generation())
                .expect("note");
            host.engine.credential_journal = Some(journal);
            host.engine.connection = host
                .engine
                .connection
                .clone()
                .with_generation_floor(crate::GenerationFloor::new(directory.path().to_path_buf()));
            let path = directory.path().join("connection-floor.json");
            let leases = host.leases.load(Ordering::SeqCst);
            for damaged in [None, Some(b"corrupt".to_vec())] {
                if let Some(bytes) = damaged {
                    std::fs::write(&path, bytes).expect("damaged floor");
                }
                assert!(matches!(
                    host.engine.prepare_entry().await,
                    Err("gateway.connection.restore-rollback")
                ));
                assert_eq!(
                    host.engine.collect_credentials().await,
                    Err("gateway.admin.connection-unavailable")
                );
                assert_eq!(host.stored(&installation.connection_id), [1]);
            }
            SharedConnection::new(host.engine.attempts.store(), provider(), alias())
                .stop(true, wall_clock_seconds().expect("clock"))
                .await
                .expect("explicit store-only revoke");
            assert_eq!(host.engine.collect_credentials().await, Ok(1));
            assert!(host.stored(&installation.connection_id).is_empty());
            assert_eq!(
                std::fs::read(&path).expect("retained floor").as_slice(),
                b"corrupt"
            );
            assert!(matches!(
                host.engine.prepare_entry().await,
                Err("gateway.connection.restore-rollback")
            ));
            assert_eq!(host.leases.load(Ordering::SeqCst), leases);
        }

        #[tokio::test]
        async fn readiness_and_emergency_stop_make_no_credential_lease() {
            let installation = installation(8).await;
            let host = &installation.first;
            let before = host.leases.load(Ordering::SeqCst);
            let checked = host
                .engine
                .readiness_checks(auths_connections::CredentialStoreKind::LocalFileV1)
                .await;
            assert_eq!(checked.store, crate::PreconditionState::Ready);
            assert_eq!(checked.recipe, crate::PreconditionState::Ready);
            assert_eq!(
                checked.connection_generation,
                crate::PreconditionState::Ready
            );
            assert_eq!(
                checked.provider_secret_custody,
                crate::PreconditionState::NotReady
            );
            assert_eq!(checked.qualification, crate::PreconditionState::NotReady);
            // Remove custody entirely. The store-only stop is still usable,
            // is idempotent, and does not touch or reclassify attempts.
            std::fs::remove_dir_all(&host.credentials_directory).expect("remove custody");
            let now = wall_clock_seconds().expect("clock");
            let stopped = host.engine.connection.stop(false, now).await.expect("stop");
            assert_eq!(stopped.state(), ConnectionState::Disabled);
            let repeated = host
                .engine
                .connection
                .stop(false, now)
                .await
                .expect("repeat");
            assert_eq!(stopped.generation(), repeated.generation());
            let revoked = host
                .engine
                .connection
                .stop(true, now)
                .await
                .expect("revoke");
            assert_eq!(revoked.state(), ConnectionState::Revoked);
            assert_eq!(
                host.engine
                    .connection
                    .stop(false, now)
                    .await
                    .expect("stop revoked")
                    .state(),
                ConnectionState::Revoked
            );
            assert_eq!(host.leases.load(Ordering::SeqCst), before);
        }

        #[tokio::test]
        async fn a_prepared_rotation_changes_nothing_until_it_is_committed() {
            let installation = installation(8).await;
            let host = &installation.first;
            let id = &installation.connection_id;
            let before = host.engine.status().await.expect("status");

            let commitment = host
                .engine
                .prepare_rotation(candidate("prepared-secret"))
                .await
                .expect("prepare");
            let prepared = host.engine.status().await.expect("status");
            assert_eq!(
                prepared.generation, before.generation,
                "the record is unchanged"
            );
            assert_eq!(prepared.credential_generation, before.credential_generation);
            assert!(
                prepared.credential_held,
                "the current credential still serves"
            );
            assert_eq!(
                host.stored(id).len(),
                2,
                "the successor is stored beside it"
            );
            assert!(host.entry_refusal().await.is_none());

            assert_eq!(
                host.engine.commit_rotation([9; 32]).await.unwrap_err(),
                "gateway.admin.rotation-not-prepared",
                "a commitment the store does not hold commits nothing"
            );
            assert_eq!(
                host.engine.status().await.expect("status").generation,
                before.generation
            );

            let outcome = host
                .engine
                .commit_rotation(commitment)
                .await
                .expect("commit");
            assert_eq!(outcome.code, "gateway.admin.rotated");
            let rotated = host.engine.status().await.expect("status");
            assert_eq!(rotated.generation, before.generation + 1);
            assert_eq!(rotated.credential_generation, before.generation + 1);
            assert!(rotated.credential_held);
            assert_eq!(
                host.engine.commit_rotation(commitment).await.unwrap_err(),
                "gateway.admin.rotation-not-prepared",
                "a commit is not repeatable"
            );
        }

        #[tokio::test]
        async fn a_record_that_changed_since_the_prepare_is_not_committed() {
            let mut installation = installation(8).await;
            let host = &mut installation.first;
            let journal = crate::CredentialJournal::new(
                host.credentials_directory
                    .parent()
                    .expect("private root")
                    .to_path_buf(),
            );
            journal
                .initialize(&installation.connection_id)
                .expect("journal");
            host.engine.credential_journal = Some(journal);
            let leases = host.leases.load(Ordering::SeqCst);
            let commitment = host
                .engine
                .prepare_rotation(candidate("prepared-secret"))
                .await
                .expect("prepare");
            host.engine.disable_connection().await.expect("disable");
            assert_eq!(
                host.engine.commit_rotation(commitment).await.unwrap_err(),
                "gateway.admin.rotation-not-prepared",
                "the successor was stored for the generation before the disable"
            );
            assert_eq!(
                host.engine
                    .prepare_rotation(candidate("prepared-secret"))
                    .await,
                Err("gateway.admin.credential-unavailable"),
                "the abandoned successor blocks the current generation until collected"
            );
            assert_eq!(
                host.engine
                    .collect_credentials()
                    .await
                    .expect("collect abandoned"),
                1
            );
            // The emergency flow collects the abandoned successor before
            // preparing another rotation while the connection remains disabled.
            let again = host
                .engine
                .prepare_rotation(candidate("prepared-secret"))
                .await
                .expect("prepare while disabled");
            host.engine
                .commit_rotation(again)
                .await
                .expect("commit while disabled");
            assert_eq!(host.record().await.state(), ConnectionState::Disabled);
            assert_eq!(
                host.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );
            assert_eq!(host.leases.load(Ordering::SeqCst), leases);
            host.engine.enable_connection().await.expect("enable");
            assert!(host.engine.status().await.expect("status").credential_held);
            assert_eq!(host.entry_refusal().await, None);
        }

        #[tokio::test]
        async fn a_superseded_generation_is_kept_for_the_retirement_delay() {
            let installation = installation(8).await;
            let mut first = installation.first;
            let id = installation.connection_id.clone();
            first.engine.retirement_delay = crate::CredentialRetirementDelay::FIXED.as_duration();
            let before = first.stored(&id);
            first
                .engine
                .rotate_connection(candidate("rotated-secret"))
                .await
                .expect("rotate");
            let mut kept = before.clone();
            kept.push(before[before.len() - 1] + 1);
            assert_eq!(
                first.stored(&id),
                kept,
                "the old generation is still stored"
            );

            let record = first
                .engine
                .load_for_admin()
                .await
                .expect("record")
                .record()
                .clone();
            let committed = Instant::now();
            first
                .engine
                .collect_retired(&record, committed + Duration::from_secs(19))
                .await;
            assert_eq!(
                first.stored(&id),
                kept,
                "19 seconds after the commit it is kept"
            );
            first
                .engine
                .collect_retired(&record, committed + Duration::from_secs(21))
                .await;
            assert_eq!(
                first.stored(&id),
                [kept[kept.len() - 1]],
                "after the delay only the current generation remains"
            );
        }

        #[tokio::test]
        async fn a_rotation_failing_after_its_credential_write_is_discarded() {
            let installation = installation(8).await;
            let host = &installation.first;
            // A read-only shared store makes the record write fail after the
            // successor credential is stored.
            let root = installation.file_root();
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o500)).expect("mode");
            let refused = host
                .engine
                .rotate_connection(candidate("pat-rotated"))
                .await;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("mode");
            assert_eq!(refused, Err("gateway.admin.transition-unavailable"));
            assert_eq!(
                host.stored(&installation.connection_id),
                [1],
                "the unpublished successor is gone"
            );
            assert_eq!(host.record().await.generation().get(), 1);
            assert_eq!(host.entry_refusal().await, None);

            host.engine.revoke_connection().await.expect("revoke");
            assert!(host.stored(&installation.connection_id).is_empty());
        }

        #[tokio::test]
        async fn disable_and_revoke_need_no_free_credential_capacity() {
            let installation = installation(1).await;
            let host = &installation.first;
            assert_eq!(
                host.engine
                    .rotate_connection(candidate("pat-rotated"))
                    .await,
                Err("gateway.admin.credential-unavailable"),
                "the full store has no room for a successor"
            );
            host.engine.disable_connection().await.expect("disable");
            host.engine.revoke_connection().await.expect("revoke");
            assert!(host.stored(&installation.connection_id).is_empty());
            assert_eq!(host.record().await.state(), ConnectionState::Revoked);
        }

        #[tokio::test]
        async fn a_repeated_revoke_finishes_the_credential_deletion() {
            let installation = installation(8).await;
            let host = &installation.first;
            // The credential store refuses to write into a directory other users
            // can read, so the deletion fails after the record is revoked.
            std::fs::set_permissions(
                &host.credentials_directory,
                std::fs::Permissions::from_mode(0o750),
            )
            .expect("mode");
            assert_eq!(
                host.engine.revoke_connection().await,
                Err("gateway.admin.credential-deletion-incomplete")
            );
            std::fs::set_permissions(
                &host.credentials_directory,
                std::fs::Permissions::from_mode(0o700),
            )
            .expect("mode");
            assert_eq!(host.record().await.state(), ConnectionState::Revoked);
            assert_eq!(host.stored(&installation.connection_id), [1]);
            assert_eq!(
                host.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable"),
                "the revoked record withholds the lease while the secret is stored"
            );

            host.engine
                .revoke_connection()
                .await
                .expect("repeated revoke");
            assert!(host.stored(&installation.connection_id).is_empty());
            let generation = host.record().await.generation();
            let stopped = host
                .engine
                .disable_connection()
                .await
                .expect("stop revoked");
            assert_eq!(stopped.code, "gateway.admin.disabled");
            assert_eq!(host.record().await.state(), ConnectionState::Revoked);
            assert_eq!(host.record().await.generation(), generation);
            assert!(host.stored(&installation.connection_id).is_empty());
        }

        async fn a_second_host_joins_only_with_the_matching_secret_after_state_changes(
            backend: crate::store_testkit::Backend,
        ) {
            let installation = installation_on(backend, 8).await;
            let first = &installation.first;
            first.engine.disable_connection().await.expect("disable");
            first.engine.enable_connection().await.expect("enable");
            let record = first.record().await;
            assert_eq!(record.generation().get(), 3);
            assert_eq!(record.credential_generation().get(), 1);

            let second = installation.second_host();
            assert_eq!(
                second.entry_refusal().await.as_deref(),
                Some("gateway.connection.credential-generation-missing"),
                "a host that has not joined refuses before any claim"
            );
            assert_eq!(
                second.join("pat-other").await.map(|_| ()),
                Err("gateway.install.join-commitment-mismatch")
            );
            assert!(second.stored(&installation.connection_id).is_empty());
            second.join("pat-initial").await.expect("join");
            assert_eq!(second.stored(&installation.connection_id), [1]);
            assert_eq!(second.entry_refusal().await, None);
            assert_eq!(first.entry_refusal().await, None);
        }

        #[tokio::test]
        async fn a_join_needs_an_installed_record() {
            let installation = installation(8).await;
            let other =
                crate::store_testkit::TestAttempts::open(crate::store_testkit::Backend::File);
            let lonely = host(other.reopen(), 8);
            assert_eq!(
                lonely.join("pat-initial").await.map(|_| ()),
                Err("gateway.install.join-record-missing")
            );
            installation
                .first
                .engine
                .revoke_connection()
                .await
                .expect("revoke");
            let late = installation.second_host();
            assert_eq!(
                late.join("pat-initial").await.map(|_| ()),
                Err("gateway.install.connection-revoked")
            );
        }

        async fn a_disable_or_revoke_through_one_process_stops_entry_in_another(
            backend: crate::store_testkit::Backend,
        ) {
            let installation = installation_on(backend, 8).await;
            let first = &installation.first;
            let second = installation.second_host();
            second.join("pat-initial").await.expect("join");
            let prepared = second.engine.prepare_entry().await.expect("entry");
            assert!(second.engine.unchanged(&prepared).await);

            first.engine.disable_connection().await.expect("disable");
            assert!(
                !second.engine.unchanged(&prepared).await,
                "the next reload in the other process sees the disable"
            );
            assert_eq!(
                second.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );
            assert_eq!(
                second
                    .engine
                    .enable_connection()
                    .await
                    .map(|outcome| outcome.code),
                Ok("gateway.admin.enabled"),
                "any process may commit the next change"
            );
            assert_eq!(first.entry_refusal().await, None);
            assert_eq!(second.entry_refusal().await, None);

            first.engine.revoke_connection().await.expect("revoke");
            assert_eq!(
                second.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );
            assert_eq!(
                second.stored(&installation.connection_id),
                [1],
                "the other process keeps its secret until its own revoke"
            );
            second.engine.revoke_connection().await.expect("revoke");
            assert!(second.stored(&installation.connection_id).is_empty());
        }

        async fn a_cross_process_rotation_then_disable_and_enable_leases_on_every_host(
            backend: crate::store_testkit::Backend,
        ) {
            let installation = installation_on(backend, 8).await;
            let first = &installation.first;
            let second = installation.second_host();
            second.join("pat-initial").await.expect("join");

            first
                .engine
                .rotate_connection(candidate("pat-rotated"))
                .await
                .expect("rotate");
            assert_eq!(
                second.entry_refusal().await.as_deref(),
                Some("gateway.connection.credential-generation-missing"),
                "the other process leases nothing until it takes the rotation"
            );
            assert_eq!(
                second
                    .engine
                    .rotate_connection(candidate("pat-other"))
                    .await
                    .map(|outcome| outcome.code),
                Err("gateway.admin.generation-conflict")
            );
            let accepted = second
                .engine
                .rotate_connection(candidate("pat-rotated"))
                .await
                .expect("accept");
            assert_eq!(accepted.code, "gateway.admin.rotated");
            assert_eq!(
                second.record().await.generation().get(),
                2,
                "nothing committed"
            );
            assert_eq!(second.stored(&installation.connection_id), [2]);

            first.engine.disable_connection().await.expect("disable");
            second.engine.enable_connection().await.expect("enable");
            let record = first.record().await;
            assert_eq!(record.generation().get(), 4);
            assert_eq!(record.credential_generation().get(), 2);
            for host in [first, &second] {
                assert_eq!(host.entry_refusal().await, None);
                let status = host.engine.status().await.expect("status");
                assert_eq!(status.state, "active");
                assert_eq!(status.credential_generation, 2);
                assert!(status.credential_held);
            }
        }

        #[tokio::test]
        async fn an_admin_change_commits_without_waiting_and_reports_the_drain() {
            let mut installation = installation(8).await;
            installation.first.engine.drain_limit = Duration::from_millis(50);
            let host = &installation.first;
            host.engine.in_flight.fetch_add(1, Ordering::SeqCst);
            let started = Instant::now();
            let outcome = host.engine.disable_connection().await.expect("disable");
            assert!(started.elapsed() < Duration::from_secs(5));
            assert_eq!(
                outcome,
                GatewayAdminOutcome {
                    code: "gateway.admin.disabled",
                    drained: false,
                    in_flight: 1,
                }
            );
            assert_eq!(
                host.record().await.state(),
                ConnectionState::Disabled,
                "the change committed before the drain"
            );
            host.engine.in_flight.fetch_sub(1, Ordering::SeqCst);
            let outcome = host.engine.enable_connection().await.expect("enable");
            assert!(outcome.drained);
            assert_eq!(outcome.in_flight, 0);
        }

        #[tokio::test]
        async fn status_reports_the_last_slot_sweep() {
            let installation = installation(8).await;
            let host = &installation.first;
            assert_eq!(host.engine.status().await.expect("status").last_sweep, None);
            host.engine.sweep_expired_slots().await.expect("sweep");
            let status = host.engine.status().await.expect("status");
            let swept = status.last_sweep.expect("a completed sweep is reported");
            assert!(swept <= status.gateway_clock);
        }

        #[tokio::test]
        async fn an_obsolete_record_is_refused_as_state() {
            let installation = installation(8).await;
            let host = &installation.first;
            let current = host.record().await.to_canonical_cbor().expect("bytes");
            let mut obsolete = current.clone();
            obsolete[0] = 0xb1;
            obsolete[2] = 0x01;
            obsolete.truncate(obsolete.len() - 2);
            let store = host.engine.attempts.store();
            let key = crate::connection_key(&provider(), &alias());
            tokio::task::spawn_blocking(move || {
                store.replace(
                    crate::GatewayRecordKind::Connection,
                    &key,
                    &current,
                    &obsolete,
                )
            })
            .await
            .expect("join")
            .expect("replace");
            assert_eq!(
                host.engine.connection.load().await.err(),
                Some(SharedConnectionError::Obsolete)
            );
            assert_eq!(
                host.entry_refusal().await.as_deref(),
                Some("gateway.connection.unavailable")
            );
            assert_eq!(
                host.engine.status().await.err(),
                Some("gateway.admin.connection-unavailable")
            );
        }

        #[tokio::test]
        async fn a_second_install_never_replaces_the_record() {
            let installation = installation(8).await;
            let second = installation.second_host();
            let id =
                auths_connections::ConnectionId::parse("conn_BBBBBBBBBBBBBBBBBBBBBA").expect("id");
            let recipe = airtable_recipe();
            let refused = crate::install_connection(
                &second.engine.connection,
                &*second.engine.credentials,
                |reference| {
                    ConnectionRecord::new(
                        provider(),
                        alias(),
                        auths_connections::ConnectionId::parse("conn_BBBBBBBBBBBBBBBBBBBBBA")
                            .map_err(|_| "id")?,
                        auths_connections::SemanticId::parse("auths.gateway-operation/1")
                            .map_err(|_| "contract")?,
                        auths_connections::SemanticId::parse(
                            "auths.gateway-connection-descriptor/1",
                        )
                        .map_err(|_| "schema")?,
                        GatewayConnectionDescriptor::approve(&recipe, "Authorization")
                            .and_then(|descriptor| descriptor.to_bytes())
                            .map_err(|_| "descriptor")?,
                        [4; 32],
                        reference,
                        std::num::NonZeroU64::MIN,
                        ConnectionState::Active,
                        vec!["gateway".to_owned()],
                        vec![profile()],
                        10,
                        10,
                        None,
                    )
                    .map_err(|_| "record")
                },
                &id,
                SecretBytes::new(b"pat-second".to_vec()).expect("secret"),
            )
            .await;
            assert_eq!(
                refused.map(|_| ()),
                Err("gateway.install.connection-exists")
            );
            assert!(
                second.stored(&id).is_empty(),
                "the refused secret is deleted"
            );
            assert_eq!(
                second.record().await.connection_id(),
                &installation.connection_id
            );
        }

        /// The processes of one connection over each shared store: the file
        /// store, and the `PostgreSQL` store where the TLS fixture runs.
        async fn across_processes(backend: crate::store_testkit::Backend) {
            a_second_host_joins_only_with_the_matching_secret_after_state_changes(backend).await;
            a_disable_or_revoke_through_one_process_stops_entry_in_another(backend).await;
            a_cross_process_rotation_then_disable_and_enable_leases_on_every_host(backend).await;
        }

        #[tokio::test]
        async fn file_store_shares_the_connection_across_processes() {
            across_processes(crate::store_testkit::Backend::File).await;
        }

        #[tokio::test]
        #[ignore = "needs the TLS PostgreSQL fixture"]
        async fn postgres_store_shares_the_connection_across_processes() {
            assert!(
                crate::store_testkit::postgres_configured(),
                "TLS PostgreSQL environment slots are required"
            );
            across_processes(crate::store_testkit::Backend::Postgres).await;
        }
    }
}
