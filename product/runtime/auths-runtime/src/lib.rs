//! Target V1 authorization-before-execution runtime for MCP.

#![forbid(unsafe_code)]

pub mod production;
pub use auths_production_client as production_client;

use async_trait::async_trait;
use auths_codec::context_digest;
use auths_errors::EffectState;
pub use auths_kernel_runtime::AuthsKernel;
use auths_model::{
    ActionId, Audience, BudgetCeiling, Challenge, Digest, ReceiptId, SignatureBytes, Timestamp,
    TrustedContext,
};
use auths_operations::{
    EventSink, NoopEventSink, OperationalEventV2, OperationalOutcome, OperationalReasonCode,
    OperationalStage,
};
use auths_profile_api::ActionProfile;
use auths_profile_mcp::{
    McpChannelBindingKind, McpCommand, McpProfile, McpToolCall, PROFILE_ID, PROFILE_VERSION,
};
use auths_proof_exchange_model::{
    AUTHS_PROTOCOL_V1, ActionChallenge, ActionResponse, ActionSubmission, ChallengeNonce,
    ChannelBindingPolicy, ExchangeAudience, ExchangeCapabilities, ExchangeMetrics, ExchangeOutcome,
    ExchangeProfileId, PeerObservation, ProfileBinding, RefusalKind, VerdictDecision,
    VerdictSummary,
};
use auths_proof_exchange_port::{ProofExchangeService, ServiceError};
use auths_receipts::{
    AttestedDecisionReceipt, AttestedExecutionReceipt, DecisionClass, DecisionReceipt,
    ExecutionOutcome as ReceiptExecutionOutcome, ExecutionReceipt, ReceiptSigner,
    decision_receipt_id, decision_signing_preimage, encode_attested_decision,
    encode_attested_execution, execution_receipt_id, execution_signing_preimage,
};
use auths_verifier::{VerificationOutcome, VerifiedAction};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq as _;

const REQUEST_ID_DOMAIN: &[u8] = b"AUTHS-APPS-REQUEST\x00\x01";

/// Upper bound for an adapter-supplied failure summary. Kept below the exchange
/// refusal-message maximum so the projection can never fail.
const MAX_FAILURE_SUMMARY_BYTES: usize = 512;

/// Runtime clock effect.
pub trait Clock: Send + Sync {
    /// Returns whole Unix seconds.
    fn now(&self) -> u64;
}

/// System clock implementation.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

/// Secure challenge source effect.
pub trait ChallengeSource: Send + Sync {
    /// Generates an unpredictable 32-byte nonce.
    ///
    /// # Errors
    ///
    /// Returns an error if secure randomness is unavailable.
    fn generate(&self) -> Result<ChallengeNonce, ChallengeSourceError>;
}

/// Operating-system secure randomness.
pub struct OperatingSystemChallengeSource;

impl ChallengeSource for OperatingSystemChallengeSource {
    fn generate(&self) -> Result<ChallengeNonce, ChallengeSourceError> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| ChallengeSourceError)?;
        Ok(ChallengeNonce::new(bytes))
    }
}

/// Secure randomness failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeSourceError;

impl fmt::Display for ChallengeSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secure challenge generation failed")
    }
}

impl std::error::Error for ChallengeSourceError {}

/// Atomic replay claim result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeClaim {
    /// Challenge was atomically claimed.
    Claimed,
    /// Challenge was never issued.
    Unknown,
    /// Challenge expired.
    Expired,
    /// Challenge was already consumed.
    Consumed,
    /// Store could not make an atomic decision.
    Unavailable,
}

/// Atomic challenge/replay storage port.
pub trait ChallengeLedger: Send + Sync {
    /// Records one freshly issued challenge.
    fn issue(&self, challenge: ChallengeNonce, expires_at: u64) -> bool;
    /// Atomically claims one challenge.
    fn claim(&self, challenge: ChallengeNonce, now: u64) -> ChallengeClaim;
}

#[derive(Clone, Copy)]
struct LedgerEntry {
    expires_at: u64,
    consumed: bool,
}

/// Bounded in-memory replay store for reference applications and tests.
pub struct InMemoryChallengeLedger {
    entries: Mutex<BTreeMap<[u8; 32], LedgerEntry>>,
    max_entries: usize,
}

impl InMemoryChallengeLedger {
    /// Constructs a bounded ledger.
    ///
    /// # Errors
    ///
    /// Returns a configuration error when capacity is zero or above the hard
    /// application maximum.
    pub fn new(max_entries: usize) -> Result<Self, ServiceConfigurationError> {
        if max_entries == 0 || max_entries > 1_000_000 {
            return Err(ServiceConfigurationError::InvalidLedgerCapacity);
        }
        Ok(Self {
            entries: Mutex::new(BTreeMap::new()),
            max_entries,
        })
    }
}

impl ChallengeLedger for InMemoryChallengeLedger {
    fn issue(&self, challenge: ChallengeNonce, expires_at: u64) -> bool {
        let Ok(mut entries) = self.entries.lock() else {
            return false;
        };
        if entries.len() >= self.max_entries || entries.contains_key(challenge.as_bytes()) {
            return false;
        }
        entries.insert(
            *challenge.as_bytes(),
            LedgerEntry {
                expires_at,
                consumed: false,
            },
        );
        true
    }

    fn claim(&self, challenge: ChallengeNonce, now: u64) -> ChallengeClaim {
        let Ok(mut entries) = self.entries.lock() else {
            return ChallengeClaim::Unavailable;
        };
        let Some(entry) = entries.get_mut(challenge.as_bytes()) else {
            return ChallengeClaim::Unknown;
        };
        if entry.consumed {
            return ChallengeClaim::Consumed;
        }
        if now > entry.expires_at {
            entry.consumed = true;
            return ChallengeClaim::Expired;
        }
        entry.consumed = true;
        ChallengeClaim::Claimed
    }
}

/// Atomic stateful budget claim result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetClaim {
    /// Requested budget was atomically reserved.
    Claimed,
    /// The configured budget is exhausted.
    Exhausted,
    /// Store could not make an atomic decision.
    Unavailable,
}

/// Stateful budget storage port.
pub trait BudgetLedger: Send + Sync {
    /// Atomically claims an action's requested budget.
    fn claim(&self, action: ActionId, requested: Option<&BudgetCeiling>) -> BudgetClaim;
}

/// Budget ledger that accepts actions without stateful budget and rejects
/// budget-bearing actions. Useful when stateful budgets are disabled.
pub struct NoBudgetLedger;

impl BudgetLedger for NoBudgetLedger {
    fn claim(&self, _action: ActionId, requested: Option<&BudgetCeiling>) -> BudgetClaim {
        if requested.is_none() {
            BudgetClaim::Claimed
        } else {
            BudgetClaim::Exhausted
        }
    }
}

/// Canonical receipt persistence port.
pub trait ReceiptSink: Send + Sync {
    /// Persists one canonical decision receipt under its content identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError`] if the sink cannot persist the bytes or
    /// an existing identifier is bound to different bytes.
    fn store_decision(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError>;
    /// Persists one canonical execution receipt under its content identifier.
    ///
    /// # Errors
    ///
    /// Returns [`ReceiptStoreError`] if the sink cannot persist the bytes or
    /// an existing identifier is bound to different bytes.
    fn store_execution(&self, id: ReceiptId, bytes: Vec<u8>) -> Result<(), ReceiptStoreError>;
}

/// External signer for verifier decision and execution attestations.
///
/// The runtime passes exact domain-separated receipt bytes to this port and
/// never owns the corresponding private key.
pub trait ReceiptAttestor: Send + Sync {
    /// Returns the public verifier identity, key reference, and suite.
    fn signer(&self) -> ReceiptSigner;

    /// Signs one exact receipt preimage.
    ///
    /// # Errors
    ///
    /// Returns a typed failure without a partially attested receipt.
    fn sign(&self, signing_preimage: &[u8]) -> Result<SignatureBytes, ReceiptAttestationError>;
}

/// Receipt-signing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptAttestationError;

impl fmt::Display for ReceiptAttestationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("receipt attestation unavailable")
    }
}

impl std::error::Error for ReceiptAttestationError {}

/// Receipt sink used when persistence is not required by local policy.
pub struct NoopReceiptSink;

impl ReceiptSink for NoopReceiptSink {
    fn store_decision(&self, _id: ReceiptId, _bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        Ok(())
    }

    fn store_execution(&self, _id: ReceiptId, _bytes: Vec<u8>) -> Result<(), ReceiptStoreError> {
        Ok(())
    }
}

/// Receipt persistence failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptStoreError;

impl fmt::Display for ReceiptStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("receipt store unavailable")
    }
}

impl std::error::Error for ReceiptStoreError {}

fn evaluate_kernel(
    kernel: &AuthsKernel,
    proof: &[u8],
    canonical_action: &auths_model::CanonicalAction,
    challenge: ChallengeNonce,
    audience: &ExchangeAudience,
    now: u64,
) -> Result<(VerificationOutcome, TrustedContext), auths_model::DenialReason> {
    let expected_audience = Audience::parse(audience.as_str())
        .map_err(|_| auths_model::DenialReason::AudienceMismatch)?;
    kernel.verify_with_context(
        proof,
        canonical_action,
        expected_audience,
        Challenge::new(*challenge.as_bytes()),
        Timestamp::new(now),
    )
}

/// Replay- and budget-bound execution authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionLease {
    challenge: ChallengeNonce,
    action: ActionId,
    audience: String,
    expires_at: u64,
}

impl ExecutionLease {
    /// Returns the claimed challenge.
    #[must_use]
    pub const fn challenge(&self) -> ChallengeNonce {
        self.challenge
    }

    /// Returns the exact verified action identifier.
    #[must_use]
    pub const fn action(&self) -> ActionId {
        self.action
    }

    /// Returns the execution audience.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Returns the lease expiry.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// Command that passed Auths, channel, replay, budget, and application policy.
pub struct ExecutableAction<C> {
    lease: ExecutionLease,
    verified: VerifiedAction,
    command: C,
}

impl<C> ExecutableAction<C> {
    /// Returns the execution lease.
    #[must_use]
    pub const fn lease(&self) -> &ExecutionLease {
        &self.lease
    }

    /// Returns the sealed verified source.
    #[must_use]
    pub const fn verified(&self) -> &VerifiedAction {
        &self.verified
    }

    /// Returns the profile-decoded command.
    #[must_use]
    pub const fn command(&self) -> &C {
        &self.command
    }
}

/// Whether a failing provider call had already entered the provider.
///
/// This boundary is the entire safety question for a failed execution. Before
/// entry the adapter holds proof that the exact effect was not applied. After
/// entry it holds none: a refused connection, a timeout, and a lost response for
/// an applied write are indistinguishable from inside the adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderBoundary {
    /// The exact command provably never reached the provider.
    BeforeEntry,
    /// The exact command entered, or may have entered, the provider.
    AfterEntry,
}

/// Bounded executor failure that states exactly what the adapter can prove.
///
/// There is deliberately no `From<String>` and no default boundary. An adapter
/// must choose, because Auths cannot choose for it and the wrong default mints a
/// signed proof that a real-world effect did not happen.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ToolExecutionFailure {
    boundary: ProviderBoundary,
    summary: String,
}

impl ToolExecutionFailure {
    /// Declares a failure that provably occurred before provider entry.
    ///
    /// Use this only when the adapter can prove the exact command never reached
    /// the provider: local validation, a policy refusal, or a connection that
    /// was refused before any request byte was written.
    #[must_use]
    pub fn before_provider_entry(summary: impl AsRef<str>) -> Self {
        Self::new(ProviderBoundary::BeforeEntry, summary)
    }

    /// Declares a failure whose exact effect may already have been applied.
    ///
    /// This is the correct answer for a timeout, a cancellation, a reset
    /// connection, an unparsable provider response, and any failure the adapter
    /// cannot place on the near side of provider entry.
    #[must_use]
    pub fn after_provider_entry(summary: impl AsRef<str>) -> Self {
        Self::new(ProviderBoundary::AfterEntry, summary)
    }

    fn new(boundary: ProviderBoundary, summary: impl AsRef<str>) -> Self {
        Self {
            boundary,
            summary: bounded_summary(summary.as_ref()),
        }
    }

    /// Returns the exact provider boundary this failure crossed.
    #[must_use]
    pub const fn boundary(&self) -> ProviderBoundary {
        self.boundary
    }

    /// Returns the bounded, display-safe failure summary.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Projects the Rust-owned effect state this failure is entitled to claim.
    #[must_use]
    pub const fn effect(&self) -> EffectState {
        match self.boundary {
            ProviderBoundary::BeforeEntry => EffectState::NotApplied,
            ProviderBoundary::AfterEntry => EffectState::Possible,
        }
    }
}

/// Reports whether a failed execution may be recorded as a signed receipt
/// asserting the exact effect did not happen.
///
/// `ExecutionOutcome::Failed` is an assertion of non-effect, not a description
/// of an error. Only a failure the adapter proved occurred before provider entry
/// may be minted as one.
const fn may_sign_non_effect_receipt(failure: &ToolExecutionFailure) -> bool {
    matches!(failure.effect(), EffectState::NotApplied)
}

/// Selects the signed execution outcome a failed execution is entitled to
/// record (decision 11.8, contract §10A / §5A.3).
///
/// This is the single place the adapter's proven provider boundary becomes a
/// durable assertion, and it is total: `Failed` for a proven pre-entry failure,
/// `Indeterminate` for everything else. `Succeeded` is unreachable here because
/// the executor returned an error.
const fn receipt_outcome_for(failure: &ToolExecutionFailure) -> ReceiptExecutionOutcome {
    if may_sign_non_effect_receipt(failure) {
        ReceiptExecutionOutcome::Failed
    } else {
        ReceiptExecutionOutcome::Indeterminate
    }
}

/// Prefix that marks a refusal whose exact effect may already have been applied.
pub const OUTCOME_UNKNOWN_PREFIX: &str = "effect possible, reconcile before retry: ";

/// Prefixes an unknown-effect summary so the refusal message cannot be read as
/// an assertion that nothing happened.
fn alloc_unknown_message(summary: &str) -> String {
    let mut message = String::with_capacity(OUTCOME_UNKNOWN_PREFIX.len() + summary.len());
    message.push_str(OUTCOME_UNKNOWN_PREFIX);
    message.push_str(summary);
    message
}

/// Normalizes an adapter-supplied summary into the bounded, control-character
/// free form the exchange refusal message requires.
///
/// An adapter cannot crash the service with an empty, oversized, or control
/// character message.
fn bounded_summary(value: &str) -> String {
    let mut summary = String::with_capacity(value.len().min(MAX_FAILURE_SUMMARY_BYTES));
    for character in value.chars() {
        if character.is_control() {
            continue;
        }
        if summary.len() + character.len_utf8() > MAX_FAILURE_SUMMARY_BYTES {
            break;
        }
        summary.push(character);
    }
    if summary.is_empty() {
        summary.push_str("provider adapter reported no summary");
    }
    summary
}

/// MCP executor boundary. No API accepts original request bytes.
#[async_trait]
pub trait McpToolExecutor: Send + Sync {
    /// Executes a command decoded from a sealed verified action.
    ///
    /// # Errors
    ///
    /// Returns a [`ToolExecutionFailure`] that names the provider boundary the
    /// failure crossed. Auths signs an execution receipt asserting non-effect
    /// only for [`ProviderBoundary::BeforeEntry`].
    async fn execute(
        &self,
        action: ExecutableAction<McpCommand>,
    ) -> Result<Vec<u8>, ToolExecutionFailure>;
}

/// Static MCP runtime configuration.
pub struct McpServiceConfig {
    service_id: String,
    audience: ExchangeAudience,
    challenge_ttl_seconds: u64,
    max_body_bytes: u32,
    max_proof_bytes: u32,
    channel_policy: ChannelBindingPolicy,
    local_iroh_endpoint: Option<[u8; 32]>,
}

impl McpServiceConfig {
    /// Constructs a bounded service configuration.
    ///
    /// # Errors
    ///
    /// Returns a typed configuration error for invalid service, TTL, limits,
    /// or channel policy.
    pub fn new(
        service_id: impl Into<String>,
        challenge_ttl_seconds: u64,
        max_body_bytes: u32,
        max_proof_bytes: u32,
        channel_policy: ChannelBindingPolicy,
        local_iroh_endpoint: Option<[u8; 32]>,
    ) -> Result<Self, ServiceConfigurationError> {
        let service_id = service_id.into();
        let audience = ExchangeAudience::parse(&format!("mcp://{service_id}"))
            .map_err(|_| ServiceConfigurationError::InvalidService)?;
        if challenge_ttl_seconds == 0 || challenge_ttl_seconds > 300 {
            return Err(ServiceConfigurationError::InvalidChallengeTtl);
        }
        ActionChallenge::new(
            ChallengeNonce::new([0; 32]),
            audience.clone(),
            1,
            max_body_bytes,
            max_proof_bytes,
            ProfileBinding::new(
                AUTHS_PROTOCOL_V1,
                ExchangeProfileId::parse(PROFILE_ID)
                    .map_err(|_| ServiceConfigurationError::InvalidService)?,
                PROFILE_VERSION,
            )
            .map_err(|_| ServiceConfigurationError::InvalidService)?,
        )
        .map_err(|_| ServiceConfigurationError::InvalidExchangeLimits)?;
        if matches!(
            channel_policy,
            ChannelBindingPolicy::RequireSignedRecipientBinding
        ) && local_iroh_endpoint.is_none()
        {
            return Err(ServiceConfigurationError::InvalidChannelPolicy);
        }
        Ok(Self {
            service_id,
            audience,
            challenge_ttl_seconds,
            max_body_bytes,
            max_proof_bytes,
            channel_policy,
            local_iroh_endpoint,
        })
    }

    /// Returns the exact capabilities this service can negotiate.
    ///
    /// # Errors
    ///
    /// Returns a configuration error only if compiled target profile
    /// identifiers are invalid.
    pub fn capabilities(&self) -> Result<ExchangeCapabilities, ServiceConfigurationError> {
        ExchangeCapabilities::new(
            vec![auths_proof_exchange_model::EXCHANGE_VERSION_V1],
            vec![
                ProfileBinding::new(
                    AUTHS_PROTOCOL_V1,
                    ExchangeProfileId::parse(PROFILE_ID)
                        .map_err(|_| ServiceConfigurationError::InvalidService)?,
                    PROFILE_VERSION,
                )
                .map_err(|_| ServiceConfigurationError::InvalidService)?,
            ],
            self.max_body_bytes,
            self.max_proof_bytes,
        )
        .map_err(|_| ServiceConfigurationError::InvalidExchangeLimits)
    }

    fn signed_channel_binding_id(
        &self,
    ) -> Result<auths_model::ChannelBindingId, ServiceConfigurationError> {
        let identifier = match self.channel_policy {
            ChannelBindingPolicy::None | ChannelBindingPolicy::RequireAuthenticatedPeer => {
                "none-v1"
            }
            ChannelBindingPolicy::RequireSignedSenderBinding => "iroh-sender-v1",
            ChannelBindingPolicy::RequireSignedRecipientBinding => "iroh-recipient-v1",
        };
        auths_model::ChannelBindingId::parse(identifier)
            .map_err(|_| ServiceConfigurationError::InvalidChannelPolicy)
    }
}

/// Complete MCP exchange service.
pub struct McpAuthorizationService {
    config: McpServiceConfig,
    clock: Arc<dyn Clock>,
    challenge_source: Arc<dyn ChallengeSource>,
    replay: Arc<dyn ChallengeLedger>,
    budgets: Arc<dyn BudgetLedger>,
    receipts: Arc<dyn ReceiptSink>,
    receipt_attestor: Arc<dyn ReceiptAttestor>,
    kernel: Arc<AuthsKernel>,
    executor: Arc<dyn McpToolExecutor>,
    events: Arc<dyn EventSink>,
    profile: McpProfile,
}

/// Explicit effect and kernel dependencies for one MCP authorization service.
pub struct McpRuntimeDependencies {
    clock: Arc<dyn Clock>,
    challenge_source: Arc<dyn ChallengeSource>,
    replay: Arc<dyn ChallengeLedger>,
    budgets: Arc<dyn BudgetLedger>,
    receipts: Arc<dyn ReceiptSink>,
    receipt_attestor: Arc<dyn ReceiptAttestor>,
    kernel: Arc<AuthsKernel>,
    executor: Arc<dyn McpToolExecutor>,
}

/// Time, challenge, replay, and budget state used before execution.
pub struct McpRequestStateDependencies {
    clock: Arc<dyn Clock>,
    challenge_source: Arc<dyn ChallengeSource>,
    replay: Arc<dyn ChallengeLedger>,
    budgets: Arc<dyn BudgetLedger>,
}

impl McpRequestStateDependencies {
    /// Groups the request-lifecycle state ports.
    #[must_use]
    pub fn new(
        clock: Arc<dyn Clock>,
        challenge_source: Arc<dyn ChallengeSource>,
        replay: Arc<dyn ChallengeLedger>,
        budgets: Arc<dyn BudgetLedger>,
    ) -> Self {
        Self {
            clock,
            challenge_source,
            replay,
            budgets,
        }
    }
}

/// Receipt, kernel, and executor dependencies used after request admission.
pub struct McpExecutionDependencies {
    receipts: Arc<dyn ReceiptSink>,
    receipt_attestor: Arc<dyn ReceiptAttestor>,
    kernel: Arc<AuthsKernel>,
    executor: Arc<dyn McpToolExecutor>,
}

impl McpExecutionDependencies {
    /// Groups the verified-execution and receipt ports.
    #[must_use]
    pub fn new(
        receipts: Arc<dyn ReceiptSink>,
        receipt_attestor: Arc<dyn ReceiptAttestor>,
        kernel: Arc<AuthsKernel>,
        executor: Arc<dyn McpToolExecutor>,
    ) -> Self {
        Self {
            receipts,
            receipt_attestor,
            kernel,
            executor,
        }
    }
}

impl McpRuntimeDependencies {
    /// Groups the service's request-state and verified-execution dependencies.
    #[must_use]
    pub fn new(request: McpRequestStateDependencies, execution: McpExecutionDependencies) -> Self {
        Self {
            clock: request.clock,
            challenge_source: request.challenge_source,
            replay: request.replay,
            budgets: request.budgets,
            receipts: execution.receipts,
            receipt_attestor: execution.receipt_attestor,
            kernel: execution.kernel,
            executor: execution.executor,
        }
    }
}

impl McpAuthorizationService {
    /// Constructs the service from explicit effects and pure inputs.
    ///
    /// # Errors
    ///
    /// Returns a configuration failure when the pure trusted context does
    /// not require the channel-binding identifier selected by the service.
    pub fn new(
        config: McpServiceConfig,
        dependencies: McpRuntimeDependencies,
    ) -> Result<Self, ServiceConfigurationError> {
        if dependencies.kernel.context_template().channel_policy()
            != &config.signed_channel_binding_id()?
        {
            return Err(ServiceConfigurationError::InvalidKernelChannelPolicy);
        }
        Ok(Self {
            config,
            clock: dependencies.clock,
            challenge_source: dependencies.challenge_source,
            replay: dependencies.replay,
            budgets: dependencies.budgets,
            receipts: dependencies.receipts,
            receipt_attestor: dependencies.receipt_attestor,
            kernel: dependencies.kernel,
            executor: dependencies.executor,
            events: Arc::new(NoopEventSink),
            profile: McpProfile,
        })
    }

    /// Installs a privacy-preserving metrics/trace/log sink.
    #[must_use]
    pub fn with_event_sink(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }

    fn observe(
        &self,
        stage: OperationalStage,
        outcome: OperationalOutcome,
        reason: OperationalReasonCode,
        elapsed_micros: u64,
    ) {
        self.events.record(&OperationalEventV2::runtime(
            None,
            stage,
            outcome,
            reason,
            elapsed_micros,
        ));
    }

    fn refusal(
        kind: RefusalKind,
        verdict: Option<VerdictSummary>,
        message: &str,
        verification_micros: u64,
    ) -> ActionResponse {
        ActionResponse::new(
            None,
            ExchangeOutcome::refused(kind, verdict, message)
                .expect("static runtime refusal is bounded"),
            ExchangeMetrics::new(verification_micros, 0),
        )
    }
}

// This linear, fail-closed orchestration intentionally mirrors the protocol
// stages so every refusal remains adjacent to the gate that emits it.
#[allow(clippy::too_many_lines)]
#[async_trait]
impl ProofExchangeService for McpAuthorizationService {
    async fn issue_challenge(
        &self,
        _peer: &PeerObservation,
    ) -> Result<ActionChallenge, ServiceError> {
        let now = self.clock.now();
        let expires_at = now.saturating_add(self.config.challenge_ttl_seconds);
        for _ in 0..4 {
            let challenge = self
                .challenge_source
                .generate()
                .map_err(|_| ServiceError::ChallengeUnavailable)?;
            if self.replay.issue(challenge, expires_at) {
                return ActionChallenge::new(
                    challenge,
                    self.config.audience.clone(),
                    expires_at,
                    self.config.max_body_bytes,
                    self.config.max_proof_bytes,
                    ProfileBinding::new(
                        AUTHS_PROTOCOL_V1,
                        ExchangeProfileId::parse(PROFILE_ID)
                            .map_err(|_| ServiceError::ChallengeStateUnavailable)?,
                        PROFILE_VERSION,
                    )
                    .map_err(|_| ServiceError::ChallengeStateUnavailable)?,
                )
                .map_err(|_| ServiceError::ChallengeStateUnavailable);
            }
        }
        Err(ServiceError::ChallengeStateUnavailable)
    }

    async fn handle_action(
        &self,
        peer: &PeerObservation,
        challenge: &ActionChallenge,
        request: ActionSubmission,
    ) -> ActionResponse {
        let now = self.clock.now();
        if request.challenge() != challenge.challenge()
            || request.auths_protocol() != AUTHS_PROTOCOL_V1
            || request.profile_id().as_str() != PROFILE_ID
            || request.profile_version() != PROFILE_VERSION
        {
            return Self::refusal(
                RefusalKind::MalformedInput,
                None,
                "submission binding mismatch",
                0,
            );
        }
        if now > challenge.expires_at() {
            return Self::refusal(RefusalKind::ExpiredChallenge, None, "expired challenge", 0);
        }
        if !channel_policy_satisfied(
            self.config.channel_policy,
            peer,
            self.config.local_iroh_endpoint,
        ) {
            return Self::refusal(
                RefusalKind::TransportPolicy,
                None,
                "channel policy failed",
                0,
            );
        }
        let Ok(canonical) = self.profile.canonicalize(request.body()) else {
            return Self::refusal(
                RefusalKind::MalformedInput,
                None,
                "invalid MCP profile input",
                0,
            );
        };
        let verification_started = Instant::now();
        let (outcome, request_context) = match evaluate_kernel(
            &self.kernel,
            request.proof(),
            &canonical,
            challenge.challenge(),
            challenge.audience(),
            now,
        ) {
            Ok(evaluation) => evaluation,
            Err(reason) => {
                return Self::refusal(
                    RefusalKind::AuthsVerdict,
                    Some(verdict_summary(&VerificationOutcome::Denied(reason))),
                    "Auths context construction failed",
                    0,
                );
            }
        };
        let verification_micros = micros(verification_started.elapsed());
        match &outcome {
            VerificationOutcome::Authorized(_) => self.observe(
                OperationalStage::Verification,
                OperationalOutcome::Succeeded,
                OperationalReasonCode::Authorized,
                verification_micros,
            ),
            VerificationOutcome::Denied(_) => self.observe(
                OperationalStage::Verification,
                OperationalOutcome::Denied,
                OperationalReasonCode::Denied,
                verification_micros,
            ),
            VerificationOutcome::Indeterminate(_) => self.observe(
                OperationalStage::Verification,
                OperationalOutcome::Indeterminate,
                OperationalReasonCode::EvidenceUnavailable,
                verification_micros,
            ),
        }
        let verified = match outcome {
            VerificationOutcome::Authorized(action) => *action,
            denied @ (VerificationOutcome::Denied(_) | VerificationOutcome::Indeterminate(_)) => {
                if self
                    .record_decision(request.proof(), &canonical, &request_context, &denied, now)
                    .is_none()
                {
                    return Self::refusal(
                        RefusalKind::ApplicationPolicy,
                        None,
                        "receipt store unavailable",
                        verification_micros,
                    );
                }
                return Self::refusal(
                    RefusalKind::AuthsVerdict,
                    Some(verdict_summary(&denied)),
                    "Auths did not authorize the MCP call",
                    verification_micros,
                );
            }
        };
        let command = match self.profile.decode_verified(&verified) {
            Ok(command) if command.call().service() == self.config.service_id => command,
            _ => {
                return Self::refusal(
                    RefusalKind::ApplicationPolicy,
                    Some(verdict_summary(&VerificationOutcome::Authorized(Box::new(
                        verified.clone(),
                    )))),
                    "verified command violates local MCP policy",
                    verification_micros,
                );
            }
        };
        if !signed_channel_binding_satisfied(
            self.config.channel_policy,
            peer,
            self.config.local_iroh_endpoint,
            &command,
        ) {
            return Self::refusal(
                RefusalKind::TransportPolicy,
                Some(verdict_summary(&VerificationOutcome::Authorized(Box::new(
                    verified,
                )))),
                "signed channel binding does not match the observed endpoint",
                verification_micros,
            );
        }
        // Contract §5A.4. Every refusing gate runs BEFORE the authorization
        // receipt is signed. A durable receipt asserting `Authorized` for a
        // request the runtime then refuses is a false audit record, and writing
        // one per attempt hands an attacker unbounded write amplification into
        // the receipt sink. The pure action-identifier check is hoisted above
        // the replay claim so a verified action the runtime cannot lease does
        // not consume the caller's challenge either.
        let Some(action_id) = verified.action_ids().first().copied() else {
            return Self::refusal(
                RefusalKind::AuthsVerdict,
                None,
                "verified action has no action identifier",
                verification_micros,
            );
        };
        match self.replay.claim(challenge.challenge(), now) {
            ChallengeClaim::Claimed => {}
            ChallengeClaim::Unknown => {
                return Self::refusal(RefusalKind::UnknownChallenge, None, "unknown challenge", 0);
            }
            ChallengeClaim::Expired => {
                return Self::refusal(RefusalKind::ExpiredChallenge, None, "expired challenge", 0);
            }
            ChallengeClaim::Consumed => {
                return Self::refusal(
                    RefusalKind::ConsumedChallenge,
                    None,
                    "challenge already consumed",
                    0,
                );
            }
            ChallengeClaim::Unavailable => {
                return Self::refusal(
                    RefusalKind::ApplicationPolicy,
                    None,
                    "replay store unavailable",
                    0,
                );
            }
        }
        match self
            .budgets
            .claim(action_id, verified.canonical_action().requested_budget())
        {
            BudgetClaim::Claimed => {}
            BudgetClaim::Exhausted => {
                return Self::refusal(
                    RefusalKind::ApplicationPolicy,
                    None,
                    "budget exhausted",
                    verification_micros,
                );
            }
            BudgetClaim::Unavailable => {
                return Self::refusal(
                    RefusalKind::ApplicationPolicy,
                    None,
                    "budget store unavailable",
                    verification_micros,
                );
            }
        }
        // Last refusing gate has passed. Only now is `Authorized` a claim this
        // runtime can stand behind, so only now is it signed.
        let Some(decision_receipt_id) = self.record_decision(
            request.proof(),
            &canonical,
            &request_context,
            &VerificationOutcome::Authorized(Box::new(verified.clone())),
            now,
        ) else {
            return Self::refusal(
                RefusalKind::ApplicationPolicy,
                None,
                "receipt store unavailable",
                verification_micros,
            );
        };
        let lease = ExecutionLease {
            challenge: challenge.challenge(),
            action: action_id,
            audience: challenge.audience().as_str().into(),
            expires_at: challenge.expires_at(),
        };
        let lease_digest = execution_lease_digest(&lease);
        let executable = ExecutableAction {
            lease,
            verified: verified.clone(),
            command,
        };
        let execution_started = Instant::now();
        let result = match self.executor.execute(executable).await {
            Ok(result) => result,
            Err(failure) => {
                let applied_is_possible = !may_sign_non_effect_receipt(&failure);
                self.observe(
                    OperationalStage::ProviderResult,
                    if applied_is_possible {
                        OperationalOutcome::OutcomeUnknown
                    } else {
                        OperationalOutcome::Failed
                    },
                    if applied_is_possible {
                        OperationalReasonCode::ProviderUnknown
                    } else {
                        OperationalReasonCode::ProviderFailed
                    },
                    micros(execution_started.elapsed()),
                );
                // Decision 11.8 (contract §10A / §5A.3). The provider boundary
                // the adapter proved is projected directly onto the signed
                // receipt: `Failed` asserts the exact effect did not happen and
                // is reserved for a proven pre-entry failure; everything the
                // adapter cannot place on the near side of provider entry is
                // recorded as `Indeterminate`. Both are durable evidence — an
                // unknown effect is exactly the case an auditor most needs
                // signed, so silence is not an option either.
                let stored = self.record_execution(
                    decision_receipt_id,
                    lease_digest,
                    &verified,
                    receipt_outcome_for(&failure),
                    None,
                );
                let verdict = Some(verdict_summary(&VerificationOutcome::Authorized(Box::new(
                    verified,
                ))));
                if !stored {
                    // Losing the receipt does not make the effect definite.
                    // Only a proven pre-entry failure may still be refused.
                    let unstored = if applied_is_possible {
                        ExchangeOutcome::indeterminate(
                            verdict,
                            "effect possible, reconcile before retry: receipt store unavailable",
                        )
                    } else {
                        ExchangeOutcome::refused(
                            RefusalKind::ApplicationPolicy,
                            verdict,
                            "receipt store unavailable",
                        )
                    }
                    .expect("static runtime message is bounded");
                    return ActionResponse::new(
                        None,
                        unstored,
                        ExchangeMetrics::new(verification_micros, 0),
                    );
                }
                // A refusal is read by every caller as "nothing happened", so a
                // possibly-applied effect must never be projected as one.
                let outcome = if applied_is_possible {
                    ExchangeOutcome::indeterminate(
                        verdict,
                        alloc_unknown_message(failure.summary()),
                    )
                } else {
                    ExchangeOutcome::refused(
                        RefusalKind::ApplicationPolicy,
                        verdict,
                        failure.summary(),
                    )
                }
                // INVARIANT: `ToolExecutionFailure` normalizes every adapter
                // summary through `bounded_summary`, which guarantees a
                // non-empty, control-character-free string of at most
                // `MAX_FAILURE_SUMMARY_BYTES`, and `OUTCOME_UNKNOWN_PREFIX` is
                // printable ASCII. Proved by
                // `an_adapter_summary_can_never_panic_the_outcome_projection`.
                .expect("bounded adapter summary is a valid exchange message");
                return ActionResponse::new(
                    None,
                    outcome,
                    ExchangeMetrics::new(verification_micros, 0),
                );
            }
        };
        self.observe(
            OperationalStage::ProviderResult,
            OperationalOutcome::Succeeded,
            OperationalReasonCode::None,
            micros(execution_started.elapsed()),
        );
        // The two failures below happen AFTER the provider applied the effect.
        // Projecting either as a refusal would tell the caller nothing happened
        // and invite a duplicate side effect, so both are unknown-effect
        // results even though this runtime knows the effect applied: there is
        // no "applied but undeliverable" member, and `Indeterminate` is the
        // only projection that does not assert a falsehood.
        if !self.record_execution(
            decision_receipt_id,
            lease_digest,
            &verified,
            ReceiptExecutionOutcome::Succeeded,
            Some(&result),
        ) {
            return ActionResponse::new(
                None,
                ExchangeOutcome::indeterminate(
                    None,
                    "effect applied; receipt store unavailable, reconcile before retry",
                )
                .expect("static runtime message is bounded"),
                ExchangeMetrics::new(verification_micros, 0),
            );
        }
        let execution_micros = micros(execution_started.elapsed());
        let request_id = request_id(challenge.challenge(), request.body(), request.proof());
        let outcome = ExchangeOutcome::completed(result).unwrap_or_else(|_| {
            ExchangeOutcome::indeterminate(
                Some(verdict_summary(&VerificationOutcome::Authorized(Box::new(
                    verified,
                )))),
                "effect applied; tool result exceeds exchange limit, reconcile before retry",
            )
            .expect("static runtime message is bounded")
        });
        ActionResponse::new(
            Some(request_id),
            outcome,
            ExchangeMetrics::new(verification_micros, execution_micros),
        )
    }
}

impl McpAuthorizationService {
    fn record_decision(
        &self,
        proof: &[u8],
        canonical_action: &auths_model::CanonicalAction,
        context: &TrustedContext,
        outcome: &VerificationOutcome,
        now: u64,
    ) -> Option<ReceiptId> {
        let (decision, reason) = match outcome {
            VerificationOutcome::Authorized(_) => (DecisionClass::Authorized, "authorized"),
            VerificationOutcome::Denied(reason) => (DecisionClass::Denied, reason.code()),
            VerificationOutcome::Indeterminate(requirement) => {
                (DecisionClass::Indeterminate, requirement.code())
            }
        };
        let receipt = DecisionReceipt::new(
            raw_digest(proof),
            raw_digest(canonical_action.body()),
            context_digest(context).ok()?,
            context.principal_status_snapshot().id(),
            context.grant_status_snapshot().id(),
            canonical_action.profile().clone(),
            decision,
            vec![reason.into()],
            Timestamp::new(now),
        )
        .ok()?;
        let identifier = decision_receipt_id(&receipt).ok()?;
        let signer = self.receipt_attestor.signer();
        let signature = self
            .receipt_attestor
            .sign(&decision_signing_preimage(&receipt, &signer).ok()?)
            .ok()?;
        let bytes =
            encode_attested_decision(&AttestedDecisionReceipt::new(receipt, signer, signature))
                .ok()?;
        self.receipts.store_decision(identifier, bytes).ok()?;
        Some(identifier)
    }

    fn record_execution(
        &self,
        decision_receipt: ReceiptId,
        lease_digest: Digest,
        verified: &VerifiedAction,
        outcome: ReceiptExecutionOutcome,
        result: Option<&[u8]>,
    ) -> bool {
        let receipt = ExecutionReceipt::new(
            decision_receipt,
            lease_digest,
            raw_digest(verified.canonical_action().body()),
            outcome,
            result.map(raw_digest),
            Timestamp::new(self.clock.now()),
        );
        let Ok(identifier) = execution_receipt_id(&receipt) else {
            return false;
        };
        let signer = self.receipt_attestor.signer();
        let Ok(preimage) = execution_signing_preimage(&receipt, &signer) else {
            return false;
        };
        let Ok(signature) = self.receipt_attestor.sign(&preimage) else {
            return false;
        };
        let Ok(bytes) =
            encode_attested_execution(&AttestedExecutionReceipt::new(receipt, signer, signature))
        else {
            return false;
        };
        self.receipts.store_execution(identifier, bytes).is_ok()
    }
}

/// Reports whether a transport observation authenticates the *remote peer that
/// submitted this action*.
///
/// This deliberately does NOT use `PeerObservation::is_authenticated`. That
/// predicate is satisfied by two kinds of observation this service must never
/// accept as peer authentication:
///
/// * `AuthenticatedOpaque { kind, identifier }` carries no transport material
///   this service can corroborate. Its variant and fields are public, so any
///   caller — including an in-process channel that performed no authentication
///   at all — can mint one and satisfy a blanket `is_authenticated()` gate.
/// * `ServerAuthenticated` and `HttpsServerCertificate` are *client-side*
///   observations: they record that the local side authenticated the remote
///   SERVER. This runtime is the responder, so they say nothing about the
///   caller submitting the action.
///
/// Only observations that name concrete, transport-supplied peer material are
/// accepted. Unlisted and future observations fail closed.
const fn peer_is_authenticated_to_this_service(peer: &PeerObservation) -> bool {
    matches!(
        peer,
        PeerObservation::IrohEndpoint(_)
            | PeerObservation::MutualTlsCertificate(_)
            | PeerObservation::UnixPeerCredentials { .. }
    )
}

fn channel_policy_satisfied(
    policy: ChannelBindingPolicy,
    peer: &PeerObservation,
    local_endpoint: Option<[u8; 32]>,
) -> bool {
    match policy {
        ChannelBindingPolicy::None => true,
        ChannelBindingPolicy::RequireAuthenticatedPeer => {
            peer_is_authenticated_to_this_service(peer)
        }
        ChannelBindingPolicy::RequireSignedSenderBinding => {
            matches!(peer, PeerObservation::IrohEndpoint(_))
        }
        ChannelBindingPolicy::RequireSignedRecipientBinding => {
            local_endpoint.is_some() && matches!(peer, PeerObservation::IrohEndpoint(_))
        }
    }
}

fn signed_channel_binding_satisfied(
    policy: ChannelBindingPolicy,
    peer: &PeerObservation,
    local_endpoint: Option<[u8; 32]>,
    command: &McpCommand,
) -> bool {
    let binding = command.call().channel_binding();
    match policy {
        ChannelBindingPolicy::None | ChannelBindingPolicy::RequireAuthenticatedPeer => {
            binding.is_none()
        }
        ChannelBindingPolicy::RequireSignedSenderBinding => {
            let (Some(binding), PeerObservation::IrohEndpoint(observed)) = (binding, peer) else {
                return false;
            };
            binding.kind() == McpChannelBindingKind::Sender
                && binding
                    .endpoint_id()
                    .is_ok_and(|expected| bool::from(expected.ct_eq(observed)))
        }
        ChannelBindingPolicy::RequireSignedRecipientBinding => {
            let (Some(binding), Some(observed)) = (binding, local_endpoint) else {
                return false;
            };
            binding.kind() == McpChannelBindingKind::Recipient
                && binding
                    .endpoint_id()
                    .is_ok_and(|expected| bool::from(expected.ct_eq(&observed)))
        }
    }
}

fn verdict_summary(outcome: &VerificationOutcome) -> VerdictSummary {
    let (decision, reason) = match outcome {
        VerificationOutcome::Authorized(_) => (VerdictDecision::Authorized, "authorized"),
        VerificationOutcome::Denied(reason) => (VerdictDecision::Denied, reason.code()),
        VerificationOutcome::Indeterminate(requirement) => {
            (VerdictDecision::Indeterminate, requirement.code())
        }
    };
    VerdictSummary::new(decision, vec![reason.into()])
        .expect("stable Auths reason codes fit exchange limits")
}

fn request_id(challenge: ChallengeNonce, body: &[u8], proof: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REQUEST_ID_DOMAIN);
    digest.update(challenge.as_bytes());
    digest.update((body.len() as u64).to_be_bytes());
    digest.update(body);
    digest.update((proof.len() as u64).to_be_bytes());
    digest.update(proof);
    digest.finalize().into()
}

fn raw_digest(bytes: &[u8]) -> Digest {
    Digest::new(Sha256::digest(bytes).into())
}

fn execution_lease_digest(lease: &ExecutionLease) -> Digest {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-EXECUTION-LEASE\x00\x01");
    digest.update(lease.challenge.as_bytes());
    digest.update(lease.action.as_bytes());
    digest.update(
        u64::try_from(lease.audience.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(lease.audience.as_bytes());
    digest.update(lease.expires_at.to_be_bytes());
    Digest::new(digest.finalize().into())
}

fn micros(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

/// Runtime configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceConfigurationError {
    /// Replay ledger capacity is invalid.
    InvalidLedgerCapacity,
    /// No principal-method or signature-suite implementation was supplied.
    MissingRegistryImplementation,
    /// MCP service identifier is invalid.
    InvalidService,
    /// Challenge lifetime is outside the application limit.
    InvalidChallengeTtl,
    /// Exchange byte limits are invalid.
    InvalidExchangeLimits,
    /// Channel policy lacks required local configuration.
    InvalidChannelPolicy,
    /// Pure trusted context and signed outer channel policy disagree.
    InvalidKernelChannelPolicy,
}

impl fmt::Display for ServiceConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLedgerCapacity => "invalid replay-ledger capacity",
            Self::MissingRegistryImplementation => "missing exact registry implementation",
            Self::InvalidService => "invalid MCP service",
            Self::InvalidChallengeTtl => "invalid challenge TTL",
            Self::InvalidExchangeLimits => "invalid exchange limits",
            Self::InvalidChannelPolicy => "invalid channel policy configuration",
            Self::InvalidKernelChannelPolicy => {
                "verifier context does not match the signed channel-binding policy"
            }
        })
    }
}

impl std::error::Error for ServiceConfigurationError {}

/// Exact target profile binding compiled into the runtime.
#[must_use]
pub const fn mcp_profile_binding() -> (&'static str, u16) {
    (PROFILE_ID, PROFILE_VERSION)
}

/// Parses a verified command body for audit/reporting without creating an
/// executable value.
///
/// # Errors
///
/// Returns a profile error for non-canonical bytes.
pub fn inspect_mcp_body(
    canonical_body: &[u8],
) -> Result<McpToolCall, auths_profile_mcp::ProfileError> {
    McpToolCall::from_canonical_bytes(canonical_body)
}

#[cfg(test)]
mod channel_policy_tests {
    use super::{ChannelBindingPolicy, PeerObservation, channel_policy_satisfied};

    /// Regression for `peer-observation-fail-open`: `PeerObservation` is a
    /// public enum with public variants, so any caller can mint an observation
    /// that `PeerObservation::is_authenticated` reports as authenticated. The
    /// service must not accept a free-form assertion as peer authentication.
    #[test]
    fn forgeable_observations_do_not_satisfy_require_authenticated_peer() {
        let forged = PeerObservation::AuthenticatedOpaque {
            kind: "memory-demo".into(),
            identifier: vec![1],
        };
        assert!(
            forged.is_authenticated(),
            "guard the premise: the model still reports this as authenticated"
        );
        assert!(!channel_policy_satisfied(
            ChannelBindingPolicy::RequireAuthenticatedPeer,
            &forged,
            None,
        ));
    }

    #[test]
    fn client_side_observations_do_not_authenticate_the_submitting_peer() {
        for peer in [
            PeerObservation::ServerAuthenticated,
            PeerObservation::HttpsServerCertificate([3; 32]),
        ] {
            assert!(peer.is_authenticated());
            assert!(
                !channel_policy_satisfied(
                    ChannelBindingPolicy::RequireAuthenticatedPeer,
                    &peer,
                    None,
                ),
                "{peer:?} authenticates the server, not the caller"
            );
        }
    }

    #[test]
    fn unauthenticated_transports_are_refused() {
        for peer in [
            PeerObservation::Unauthenticated,
            PeerObservation::TcpEndpoint("127.0.0.1:9".into()),
            PeerObservation::FileEnvelope {
                digest: [4; 32],
                sequence: 7,
            },
        ] {
            assert!(!channel_policy_satisfied(
                ChannelBindingPolicy::RequireAuthenticatedPeer,
                &peer,
                None,
            ));
        }
    }

    #[test]
    fn transport_supplied_peer_material_is_accepted() {
        for peer in [
            PeerObservation::IrohEndpoint([9; 32]),
            PeerObservation::MutualTlsCertificate([9; 32]),
            PeerObservation::UnixPeerCredentials {
                uid: 501,
                gid: 20,
                pid: Some(4242),
            },
        ] {
            assert!(channel_policy_satisfied(
                ChannelBindingPolicy::RequireAuthenticatedPeer,
                &peer,
                None,
            ));
        }
    }
}

#[cfg(test)]
mod provider_boundary_tests {
    use super::{
        EffectState, MAX_FAILURE_SUMMARY_BYTES, OUTCOME_UNKNOWN_PREFIX, ProviderBoundary,
        ReceiptExecutionOutcome, ToolExecutionFailure, alloc_unknown_message,
        may_sign_non_effect_receipt, receipt_outcome_for,
    };
    use auths_proof_exchange_model::{ExchangeOutcome, RefusalKind};

    /// Regression for `provider-error-asserts-non-effect`. The executor boundary
    /// used to be `Result<Vec<u8>, String>`, so every adapter failure — including
    /// a timeout after the provider had been entered — reached the gateway
    /// indistinguishable from a local policy refusal and was minted as a signed
    /// `ExecutionOutcome::Failed` receipt asserting the effect did not happen.
    #[test]
    fn a_failure_after_provider_entry_never_mints_a_non_effect_receipt() {
        let failure = ToolExecutionFailure::after_provider_entry("provider call timed out");
        assert_eq!(failure.boundary(), ProviderBoundary::AfterEntry);
        assert_eq!(failure.effect(), EffectState::Possible);
        assert!(
            !may_sign_non_effect_receipt(&failure),
            "a possibly-applied effect was about to be signed as not applied"
        );
    }

    #[test]
    fn only_a_proven_pre_entry_failure_mints_a_non_effect_receipt() {
        let failure = ToolExecutionFailure::before_provider_entry("command outside local policy");
        assert_eq!(failure.boundary(), ProviderBoundary::BeforeEntry);
        assert_eq!(failure.effect(), EffectState::NotApplied);
        assert!(may_sign_non_effect_receipt(&failure));
    }

    #[test]
    fn the_two_provider_boundaries_never_collapse() {
        let before = ToolExecutionFailure::before_provider_entry("same words");
        let after = ToolExecutionFailure::after_provider_entry("same words");
        assert_ne!(before, after);
        assert_ne!(before.effect(), after.effect());
        assert_ne!(
            may_sign_non_effect_receipt(&before),
            may_sign_non_effect_receipt(&after)
        );
    }

    #[test]
    fn an_unknown_effect_refusal_message_does_not_read_as_failure() {
        let failure = ToolExecutionFailure::after_provider_entry("connection reset");
        let message = alloc_unknown_message(failure.summary());
        assert!(message.starts_with(OUTCOME_UNKNOWN_PREFIX));
        assert!(message.contains("connection reset"));
    }

    /// The adapter-supplied summary used to flow straight into
    /// `ExchangeOutcome::refused(..).expect("static runtime refusal is bounded")`,
    /// so an empty, oversized, or control-character summary panicked the
    /// authorization service. The unknown-effect branch now carries the same
    /// obligation through `ExchangeOutcome::indeterminate`.
    #[test]
    fn an_adapter_summary_can_never_panic_the_outcome_projection() {
        for raw in [
            String::new(),
            "\u{0}\u{7}\n\r\t".to_owned(),
            "x".repeat(64 * 1024),
        ] {
            for failure in [
                ToolExecutionFailure::before_provider_entry(&raw),
                ToolExecutionFailure::after_provider_entry(&raw),
            ] {
                let possible = !may_sign_non_effect_receipt(&failure);
                let message = if possible {
                    alloc_unknown_message(failure.summary())
                } else {
                    failure.summary().to_owned()
                };
                assert!(!message.is_empty());
                assert!(message.len() <= OUTCOME_UNKNOWN_PREFIX.len() + MAX_FAILURE_SUMMARY_BYTES);
                assert!(!message.bytes().any(|byte| byte.is_ascii_control()));
                let projected = if possible {
                    ExchangeOutcome::indeterminate(None, message)
                } else {
                    ExchangeOutcome::refused(RefusalKind::ApplicationPolicy, None, message)
                };
                assert!(projected.is_ok());
            }
        }
    }

    /// The production mapping from proven provider boundary to signed receipt
    /// outcome, exercised directly. A timeout must never mint `Failed`, and a
    /// proven pre-entry failure must never be downgraded to `Indeterminate` —
    /// the third variant is not a place to hide a definite answer.
    #[test]
    fn the_provider_boundary_selects_the_signed_receipt_outcome() {
        assert_eq!(
            receipt_outcome_for(&ToolExecutionFailure::after_provider_entry(
                "provider call timed out"
            )),
            ReceiptExecutionOutcome::Indeterminate
        );
        assert_eq!(
            receipt_outcome_for(&ToolExecutionFailure::before_provider_entry(
                "connection refused before any request byte"
            )),
            ReceiptExecutionOutcome::Failed
        );
        // No failure of any wording may be signed as a success.
        for summary in ["", "ok", "succeeded", "\u{0}"] {
            for failure in [
                ToolExecutionFailure::before_provider_entry(summary),
                ToolExecutionFailure::after_provider_entry(summary),
            ] {
                assert_ne!(
                    receipt_outcome_for(&failure),
                    ReceiptExecutionOutcome::Succeeded
                );
            }
        }
    }
}
