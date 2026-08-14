use auths_bounded_policy::{ProfileId, VerifierTime};
use auths_errors::{EffectState, RecommendedAction};
use auths_lifecycle::{
    DecisionInputV1, DurableTransitionV1, EffectConclusion, ExecutionAuthorizationV1,
    ExecutionIntentV1, LifecycleRecordV1, LifecycleState, LifecycleStore,
    ProviderCallAuthorizationV1, ProviderResultDigest, ReconciliationObservationV1,
    RecoveryReferenceDigest, StoreError, StoreTransactionV1, TransitionCommandV1,
    TransitionContextV1, WorkflowId, execute_store_transaction,
};
use auths_operations::{
    EventSink, NoopEventSink, OperationalEventV2, OperationalOutcome, OperationalReasonCode,
    OperationalStage,
};
use auths_receipts::ReceiptDisclosureLocator;
use base64ct::{Base64UrlUnpadded, Encoding as _};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq as _;

const RECOVERY_REFERENCE_DOMAIN: &[u8] = b"AUTHS-RECOVERY-REFERENCE\x00\x01";
const MAX_RECOVERY_REFERENCES: usize = 1_000_000;
const MAX_RECOVERY_BATCH: u16 = 100;
const MAX_LEASE_SECONDS: u64 = 300;

pub struct OpaqueRecoveryReference([u8; 32]);

impl OpaqueRecoveryReference {
    /// Parses a fixed-size URL-safe recovery token.
    ///
    /// # Errors
    ///
    /// Returns malformed when the token is not the canonical 32-byte form.
    pub fn parse_url_token(value: &str) -> Result<Self, RecoveryReferenceError> {
        if value.len() != 43 {
            return Err(RecoveryReferenceError::Malformed);
        }
        let mut bytes = [0; 32];
        Base64UrlUnpadded::decode(value, &mut bytes)
            .map_err(|_| RecoveryReferenceError::Malformed)?;
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn to_url_token(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.0)
    }

    #[must_use]
    pub fn digest(&self) -> RecoveryReferenceDigest {
        recovery_digest(&self.0)
    }

    fn generate(source: &impl RecoveryReferenceSource) -> Result<Self, RecoveryReferenceError> {
        let mut bytes = [0; 32];
        source.fill(&mut bytes)?;
        if bytes.ct_eq(&[0; 32]).into() {
            return Err(RecoveryReferenceError::Unavailable);
        }
        Ok(Self(bytes))
    }
}

impl Drop for OpaqueRecoveryReference {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryReferenceError {
    Malformed,
    Unavailable,
}

pub trait RecoveryReferenceSource: Send + Sync {
    /// Fills one recovery-reference nonce.
    ///
    /// # Errors
    ///
    /// Returns unavailable when secure randomness cannot be produced.
    fn fill(&self, output: &mut [u8; 32]) -> Result<(), RecoveryReferenceError>;
}

pub struct OperatingSystemRecoveryReferenceSource;

impl RecoveryReferenceSource for OperatingSystemRecoveryReferenceSource {
    fn fill(&self, output: &mut [u8; 32]) -> Result<(), RecoveryReferenceError> {
        getrandom::fill(output).map_err(|_| RecoveryReferenceError::Unavailable)
    }
}

pub trait TrustedClock: Send + Sync {
    fn now(&self) -> VerifierTime;
}

pub struct SystemTrustedClock;

impl TrustedClock for SystemTrustedClock {
    fn now(&self) -> VerifierTime {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        VerifierTime::from_unix_seconds(seconds)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryTarget {
    workflow: WorkflowId,
    profile: ProfileId,
}

impl RecoveryTarget {
    #[must_use]
    pub const fn new(workflow: WorkflowId, profile: ProfileId) -> Self {
        Self { workflow, profile }
    }

    #[must_use]
    pub const fn workflow(&self) -> &WorkflowId {
        &self.workflow
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }
}

pub trait LifecycleReader: Send + Sync {
    /// Loads the durable lifecycle record for a workflow.
    ///
    /// # Errors
    ///
    /// Returns a store error when durable state cannot be read safely.
    fn load_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<LifecycleRecordV1>, StoreError>;
}

pub trait RecoveryReferenceStore: Send + Sync {
    /// Binds one opaque reference digest to its recovery target.
    ///
    /// # Errors
    ///
    /// Returns a store error for conflicts or unavailable durable state.
    fn bind_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
        target: &RecoveryTarget,
    ) -> Result<(), StoreError>;

    /// Resolves one opaque reference digest without exposing its token.
    ///
    /// # Errors
    ///
    /// Returns a store error when durable state cannot be read safely.
    fn resolve_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
    ) -> Result<Option<RecoveryTarget>, StoreError>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCursor(Option<WorkflowId>);

impl RecoveryCursor {
    #[must_use]
    pub const fn beginning() -> Self {
        Self(None)
    }

    #[must_use]
    pub fn after(workflow: WorkflowId) -> Self {
        Self(Some(workflow))
    }

    #[must_use]
    pub const fn workflow(&self) -> Option<&WorkflowId> {
        self.0.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoveryBatchSize(u16);

impl RecoveryBatchSize {
    /// Creates a bounded recovery batch size.
    ///
    /// # Errors
    ///
    /// Returns invalid-batch-size for zero or a value above the hard limit.
    pub const fn new(value: u16) -> Result<Self, RecoveryConfigurationError> {
        if value == 0 || value > MAX_RECOVERY_BATCH {
            return Err(RecoveryConfigurationError::InvalidBatchSize);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryPage {
    targets: Vec<RecoveryTarget>,
    next: Option<RecoveryCursor>,
}

impl RecoveryPage {
    /// Creates one bounded page of recovery targets.
    ///
    /// # Errors
    ///
    /// Returns invalid-batch-size when the page exceeds the hard limit.
    pub fn new(
        targets: Vec<RecoveryTarget>,
        next: Option<RecoveryCursor>,
    ) -> Result<Self, RecoveryConfigurationError> {
        if targets.len() > usize::from(MAX_RECOVERY_BATCH) {
            return Err(RecoveryConfigurationError::InvalidBatchSize);
        }
        Ok(Self { targets, next })
    }

    #[must_use]
    pub fn targets(&self) -> &[RecoveryTarget] {
        &self.targets
    }

    #[must_use]
    pub const fn next(&self) -> Option<&RecoveryCursor> {
        self.next.as_ref()
    }
}

pub struct RecoveryLeaseRequest {
    target: RecoveryTarget,
    expected_revision: u64,
    now: VerifierTime,
    lease_seconds: u64,
    lease_nonce: [u8; 32],
}

impl RecoveryLeaseRequest {
    /// Creates a time-bounded lease request with a fresh nonce.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for invalid revision, duration, or
    /// unavailable secure randomness.
    pub fn new(
        target: RecoveryTarget,
        expected_revision: u64,
        now: VerifierTime,
        lease_seconds: u64,
        source: &impl RecoveryReferenceSource,
    ) -> Result<Self, RecoveryConfigurationError> {
        if expected_revision == 0 || lease_seconds == 0 || lease_seconds > MAX_LEASE_SECONDS {
            return Err(RecoveryConfigurationError::InvalidLease);
        }
        let mut lease_nonce = [0; 32];
        source
            .fill(&mut lease_nonce)
            .map_err(|_| RecoveryConfigurationError::RandomnessUnavailable)?;
        Ok(Self {
            target,
            expected_revision,
            now,
            lease_seconds,
            lease_nonce,
        })
    }

    #[must_use]
    pub const fn target(&self) -> &RecoveryTarget {
        &self.target
    }

    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub const fn now(&self) -> VerifierTime {
        self.now
    }

    #[must_use]
    pub const fn lease_seconds(&self) -> u64 {
        self.lease_seconds
    }

    #[must_use]
    pub const fn lease_nonce(&self) -> &[u8; 32] {
        &self.lease_nonce
    }

    #[must_use]
    pub fn lease_digest(&self) -> RecoveryReferenceDigest {
        recovery_digest(&self.lease_nonce)
    }
}

impl Drop for RecoveryLeaseRequest {
    fn drop(&mut self) {
        self.lease_nonce.fill(0);
    }
}

pub struct RecoveryLease {
    target: RecoveryTarget,
    expected_revision: u64,
    expires_at: VerifierTime,
    lease_digest: RecoveryReferenceDigest,
}

impl RecoveryLease {
    #[must_use]
    pub const fn acknowledged(
        target: RecoveryTarget,
        expected_revision: u64,
        expires_at: VerifierTime,
        lease_digest: RecoveryReferenceDigest,
    ) -> Self {
        Self {
            target,
            expected_revision,
            expires_at,
            lease_digest,
        }
    }

    #[must_use]
    pub const fn target(&self) -> &RecoveryTarget {
        &self.target
    }

    #[must_use]
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }

    #[must_use]
    pub const fn expires_at(&self) -> VerifierTime {
        self.expires_at
    }

    #[must_use]
    pub const fn lease_digest(&self) -> RecoveryReferenceDigest {
        self.lease_digest
    }
}

pub trait RecoverableWorkStore: Send + Sync {
    /// Lists bounded recoverable work for one profile.
    ///
    /// # Errors
    ///
    /// Returns a store error when durable work cannot be enumerated safely.
    fn list_recoverable(
        &self,
        profile: &ProfileId,
        cursor: &RecoveryCursor,
        limit: RecoveryBatchSize,
    ) -> Result<RecoveryPage, StoreError>;

    /// Atomically claims one reconciliation lease.
    ///
    /// # Errors
    ///
    /// Returns a store error when the lease conflicts or cannot be persisted.
    fn claim_reconciliation(
        &self,
        request: RecoveryLeaseRequest,
    ) -> Result<RecoveryLease, StoreError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryConfigurationError {
    InvalidCapacity,
    InvalidBatchSize,
    InvalidLease,
    RandomnessUnavailable,
}

struct InMemoryRecoveryState {
    references: BTreeMap<RecoveryReferenceDigest, RecoveryTarget>,
    workflows: BTreeMap<WorkflowId, RecoveryReferenceDigest>,
    leases: BTreeMap<WorkflowId, InMemoryLease>,
}

struct InMemoryLease {
    revision: u64,
    expires_at: VerifierTime,
    digest: RecoveryReferenceDigest,
}

pub struct InMemoryRecoveryStore {
    maximum_references: usize,
    state: Mutex<InMemoryRecoveryState>,
}

impl InMemoryRecoveryStore {
    /// Creates a bounded in-memory recovery index.
    ///
    /// # Errors
    ///
    /// Returns invalid-capacity for zero or a value above the hard limit.
    pub fn new(maximum_references: usize) -> Result<Self, RecoveryConfigurationError> {
        if maximum_references == 0 || maximum_references > MAX_RECOVERY_REFERENCES {
            return Err(RecoveryConfigurationError::InvalidCapacity);
        }
        Ok(Self {
            maximum_references,
            state: Mutex::new(InMemoryRecoveryState {
                references: BTreeMap::new(),
                workflows: BTreeMap::new(),
                leases: BTreeMap::new(),
            }),
        })
    }
}

impl RecoveryReferenceStore for InMemoryRecoveryStore {
    fn bind_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
        target: &RecoveryTarget,
    ) -> Result<(), StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(existing) = state.references.get(&digest) {
            return if existing == target {
                Ok(())
            } else {
                Err(StoreError::Conflict)
            };
        }
        if state.references.len() >= self.maximum_references
            || state.workflows.contains_key(&target.workflow)
        {
            return Err(StoreError::Conflict);
        }
        state.references.insert(digest, target.clone());
        state.workflows.insert(target.workflow.clone(), digest);
        Ok(())
    }

    fn resolve_recovery_reference(
        &self,
        digest: RecoveryReferenceDigest,
    ) -> Result<Option<RecoveryTarget>, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Unavailable)
            .map(|state| state.references.get(&digest).cloned())
    }
}

impl RecoverableWorkStore for InMemoryRecoveryStore {
    fn list_recoverable(
        &self,
        profile: &ProfileId,
        cursor: &RecoveryCursor,
        limit: RecoveryBatchSize,
    ) -> Result<RecoveryPage, StoreError> {
        let state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        let mut targets = state
            .workflows
            .iter()
            .filter(|(workflow, _)| cursor.workflow().is_none_or(|start| *workflow > start))
            .filter_map(|(_, digest)| state.references.get(digest))
            .filter(|target| target.profile == *profile)
            .take(usize::from(limit.get()) + 1)
            .cloned()
            .collect::<Vec<_>>();
        let has_more = targets.len() > usize::from(limit.get());
        targets.truncate(usize::from(limit.get()));
        let next = has_more
            .then(|| {
                targets
                    .last()
                    .map(|target| RecoveryCursor::after(target.workflow.clone()))
            })
            .flatten();
        RecoveryPage::new(targets, next).map_err(|_| StoreError::LimitExceeded)
    }

    fn claim_reconciliation(
        &self,
        request: RecoveryLeaseRequest,
    ) -> Result<RecoveryLease, StoreError> {
        let mut state = self.state.lock().map_err(|_| StoreError::Unavailable)?;
        if state
            .leases
            .get(&request.target.workflow)
            .is_some_and(|lease| lease.expires_at > request.now)
        {
            return Err(StoreError::Conflict);
        }
        let expires_at = VerifierTime::from_unix_seconds(
            request
                .now
                .unix_seconds()
                .checked_add(request.lease_seconds)
                .ok_or(StoreError::LimitExceeded)?,
        );
        let digest = request.lease_digest();
        state.leases.insert(
            request.target.workflow.clone(),
            InMemoryLease {
                revision: request.expected_revision,
                expires_at,
                digest,
            },
        );
        let stored = state
            .leases
            .get(&request.target.workflow)
            .ok_or(StoreError::Unavailable)?;
        Ok(RecoveryLease::acknowledged(
            request.target.clone(),
            stored.revision,
            stored.expires_at,
            stored.digest,
        ))
    }
}

pub struct LifecycleCoordinator<
    S,
    R,
    C = SystemTrustedClock,
    N = OperatingSystemRecoveryReferenceSource,
> {
    store: S,
    recovery: R,
    clock: C,
    references: N,
    events: Arc<dyn EventSink>,
}

impl<S, R> LifecycleCoordinator<S, R> {
    #[must_use]
    pub fn new(store: S, recovery: R) -> Self {
        Self {
            store,
            recovery,
            clock: SystemTrustedClock,
            references: OperatingSystemRecoveryReferenceSource,
            events: Arc::new(NoopEventSink),
        }
    }
}

impl<S, R, C, N> LifecycleCoordinator<S, R, C, N> {
    #[must_use]
    pub fn with_dependencies(store: S, recovery: R, clock: C, references: N) -> Self {
        Self {
            store,
            recovery,
            clock,
            references,
            events: Arc::new(NoopEventSink),
        }
    }

    #[must_use]
    pub fn with_event_sink(mut self, events: Arc<dyn EventSink>) -> Self {
        self.events = events;
        self
    }
}

impl<S, R, C, N> LifecycleCoordinator<S, R, C, N>
where
    S: LifecycleStore + LifecycleReader,
    R: RecoveryReferenceStore,
    C: TrustedClock,
    N: RecoveryReferenceSource,
{
    /// Begins a workflow and binds a fresh opaque recovery reference.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when randomness, reference binding, or
    /// durable decision persistence fails.
    pub fn begin(
        &self,
        mut input: DecisionInputV1,
        context: TransitionContextV1,
    ) -> Result<(OpaqueRecoveryReference, RecordedDecision), CoordinatorError> {
        let reference = OpaqueRecoveryReference::generate(&self.references)?;
        input.recovery_reference_digest = reference.digest();
        let target = RecoveryTarget::new(
            input.workflow_id.clone(),
            input.commitments.profile_id().clone(),
        );
        self.recovery
            .bind_recovery_reference(reference.digest(), &target)?;
        let durable = execute_store_transaction(
            &self.store,
            &StoreTransactionV1 {
                workflow_id: input.workflow_id.clone(),
                expected_revision: None,
                command: TransitionCommandV1::RecordDecision(Box::new(input)),
                context,
            },
        );
        self.observe_result(
            OperationalStage::DecisionPersistence,
            OperationalReasonCode::None,
            &durable,
        );
        let durable = durable?;
        Ok((reference, RecordedDecision(durable)))
    }

    /// Atomically reserves the authority required by a recorded decision.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition is stale, invalid, or
    /// cannot be persisted.
    pub fn reserve(
        &self,
        stage: RecordedDecision,
        context: TransitionContextV1,
    ) -> Result<Reserved, CoordinatorError> {
        self.transition(stage.0, TransitionCommandV1::Reserve, context)
            .map(Reserved)
    }

    /// Persists the exact execution intent before credential access.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition is stale, invalid, or
    /// cannot be persisted.
    pub fn record_intent(
        &self,
        stage: Reserved,
        intent: ExecutionIntentV1,
        context: TransitionContextV1,
    ) -> Result<IntentRecorded, CoordinatorError> {
        self.transition(
            stage.0,
            TransitionCommandV1::RecordExecutionIntent(intent),
            context,
        )
        .map(IntentRecorded)
    }

    /// Authorizes credential acquisition from a durably recorded intent.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition or resulting stage is
    /// invalid or cannot be persisted.
    pub fn authorize_credential(
        &self,
        stage: IntentRecorded,
        context: TransitionContextV1,
    ) -> Result<CredentialAuthorized, CoordinatorError> {
        let durable =
            self.transition(stage.0, TransitionCommandV1::AuthorizeCredential, context)?;
        let authorization = ExecutionAuthorizationV1::from_durable(&durable)
            .map_err(|_| CoordinatorError::InvalidStage)?;
        Ok(CredentialAuthorized {
            durable,
            authorization,
        })
    }

    /// Records the start of one provider attempt.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition is stale, invalid, or
    /// cannot be persisted.
    pub fn start_attempt(
        &self,
        stage: CredentialAuthorized,
        context: TransitionContextV1,
    ) -> Result<AttemptStarted, CoordinatorError> {
        self.transition(stage.durable, TransitionCommandV1::StartAttempt, context)
            .map(AttemptStarted)
    }

    /// Records provider entry and produces the bound provider authorization.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition or resulting stage is
    /// invalid or cannot be persisted.
    pub fn enter_provider(
        &self,
        stage: AttemptStarted,
        context: TransitionContextV1,
    ) -> Result<ProviderEntered, CoordinatorError> {
        let durable = self.transition(
            stage.0,
            TransitionCommandV1::MarkProviderCallEntered,
            context,
        )?;
        let authorization = ProviderCallAuthorizationV1::from_durable(&durable)
            .map_err(|_| CoordinatorError::InvalidStage)?;
        Ok(ProviderEntered {
            durable,
            authorization,
        })
    }

    /// Marks a provider-entered attempt as effect-unknown.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition is stale, invalid, or
    /// cannot be persisted.
    pub fn mark_unknown(
        &self,
        stage: ProviderEntered,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Recoverable, CoordinatorError> {
        self.transition(
            stage.durable,
            TransitionCommandV1::MarkOutcomeUnknown {
                domain_receipt_digest,
            },
            context,
        )
        .map(Recoverable)
    }

    /// Commits a conclusive provider success.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the transition is stale, invalid, or
    /// cannot be persisted.
    pub fn commit(
        &self,
        stage: ProviderEntered,
        result_digest: ProviderResultDigest,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Terminal, CoordinatorError> {
        self.transition(
            stage.durable,
            TransitionCommandV1::Commit {
                result_digest,
                domain_receipt_digest,
            },
            context,
        )
        .map(Terminal)
    }

    /// Releases a reservation after a proven non-effect.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when release is invalid or cannot be
    /// persisted.
    pub fn cancel_reserved(
        &self,
        stage: Reserved,
        result_digest: ProviderResultDigest,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Terminal, CoordinatorError> {
        self.release(stage.0, result_digest, domain_receipt_digest, context)
    }

    /// Releases an intent after a proven non-effect.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when release is invalid or cannot be
    /// persisted.
    pub fn cancel_intent(
        &self,
        stage: IntentRecorded,
        result_digest: ProviderResultDigest,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Terminal, CoordinatorError> {
        self.release(stage.0, result_digest, domain_receipt_digest, context)
    }

    /// Releases a provider-entered attempt after a proven non-effect.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when release is invalid or cannot be
    /// persisted.
    pub fn release_provider(
        &self,
        stage: ProviderEntered,
        result_digest: ProviderResultDigest,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Terminal, CoordinatorError> {
        self.release(stage.durable, result_digest, domain_receipt_digest, context)
    }

    /// Reconciles one leased effect-unknown workflow from provider evidence.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error for an unknown or stale lease, profile
    /// mismatch, invalid observation, or failed durable transition.
    pub fn reconcile(
        &self,
        lease: &RecoveryLease,
        observation: ReconciliationObservationV1,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<DurableTransitionV1, CoordinatorError> {
        let current = self
            .store
            .load_lifecycle(lease.target.workflow())?
            .ok_or(CoordinatorError::UnknownReference)?;
        if current.revision() != lease.expected_revision
            || current.decision_input().commitments.profile_id() != lease.target.profile()
        {
            return Err(CoordinatorError::StaleLease);
        }
        let result = execute_store_transaction(
            &self.store,
            &StoreTransactionV1 {
                workflow_id: current.workflow_id().clone(),
                expected_revision: Some(current.revision()),
                command: TransitionCommandV1::Reconcile {
                    observation,
                    domain_receipt_digest,
                },
                context,
            },
        );
        self.observe_result(
            OperationalStage::Reconciliation,
            OperationalReasonCode::Recovered,
            &result,
        );
        result.map_err(Into::into)
    }

    /// Resolves the public status for one opaque recovery reference.
    ///
    /// # Errors
    ///
    /// Returns a coordinator error when the reference is unknown, mismatched,
    /// or durable state is unavailable.
    pub fn status(
        &self,
        reference: &OpaqueRecoveryReference,
    ) -> Result<WorkflowStatus, CoordinatorError> {
        let target = self
            .recovery
            .resolve_recovery_reference(reference.digest())?
            .ok_or(CoordinatorError::UnknownReference)?;
        let record = self
            .store
            .load_lifecycle(target.workflow())?
            .ok_or(CoordinatorError::UnknownReference)?;
        if record.decision_input().recovery_reference_digest != reference.digest()
            || record.decision_input().commitments.profile_id() != target.profile()
        {
            return Err(CoordinatorError::ReferenceMismatch);
        }
        Ok(WorkflowStatus::from_record(&record))
    }

    #[allow(clippy::needless_pass_by_value)]
    fn transition(
        &self,
        current: DurableTransitionV1,
        command: TransitionCommandV1,
        context: TransitionContextV1,
    ) -> Result<DurableTransitionV1, CoordinatorError> {
        let stage = transition_stage(&command);
        let result = execute_store_transaction(
            &self.store,
            &StoreTransactionV1 {
                workflow_id: current.record().workflow_id().clone(),
                expected_revision: Some(current.record().revision()),
                command,
                context,
            },
        );
        self.observe_result(stage, OperationalReasonCode::None, &result);
        result.map_err(Into::into)
    }

    fn release(
        &self,
        current: DurableTransitionV1,
        result_digest: ProviderResultDigest,
        domain_receipt_digest: auths_lifecycle::DomainReceiptDigest,
        context: TransitionContextV1,
    ) -> Result<Terminal, CoordinatorError> {
        self.transition(
            current,
            TransitionCommandV1::Release {
                result_digest,
                domain_receipt_digest,
                conclusion: EffectConclusion::NonEffect,
            },
            context,
        )
        .map(Terminal)
    }

    #[must_use]
    pub fn now(&self) -> VerifierTime {
        self.clock.now()
    }

    fn observe_result(
        &self,
        stage: OperationalStage,
        success_reason: OperationalReasonCode,
        result: &Result<DurableTransitionV1, StoreError>,
    ) {
        let (outcome, reason) = match result {
            Ok(_) => (OperationalOutcome::Succeeded, success_reason),
            Err(StoreError::Conflict) => (
                OperationalOutcome::Conflict,
                OperationalReasonCode::StoreConflict,
            ),
            Err(_) => (
                OperationalOutcome::Unavailable,
                OperationalReasonCode::StoreUnavailable,
            ),
        };
        self.events.record(&OperationalEventV2::runtime(
            None, stage, outcome, reason, 0,
        ));
    }
}

pub struct RecordedDecision(DurableTransitionV1);
pub struct Reserved(DurableTransitionV1);
pub struct IntentRecorded(DurableTransitionV1);

pub struct CredentialAuthorized {
    durable: DurableTransitionV1,
    authorization: ExecutionAuthorizationV1,
}

impl CredentialAuthorized {
    #[must_use]
    pub const fn authorization(&self) -> &ExecutionAuthorizationV1 {
        &self.authorization
    }
}

pub struct AttemptStarted(DurableTransitionV1);

pub struct ProviderEntered {
    durable: DurableTransitionV1,
    authorization: ProviderCallAuthorizationV1,
}

impl ProviderEntered {
    #[must_use]
    pub const fn authorization(&self) -> &ProviderCallAuthorizationV1 {
        &self.authorization
    }
}

pub struct Recoverable(DurableTransitionV1);
pub struct Terminal(DurableTransitionV1);

impl Recoverable {
    #[must_use]
    pub const fn record(&self) -> &LifecycleRecordV1 {
        self.0.record()
    }
}

impl Terminal {
    #[must_use]
    pub const fn record(&self) -> &LifecycleRecordV1 {
        self.0.record()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoverableState {
    Reserved,
    ExecutionIntentRecorded,
    Executing,
    OutcomeUnknown,
}

pub enum WorkflowResult<R> {
    Completed {
        receipt: R,
    },
    Denied {
        code: &'static str,
    },
    Indeterminate {
        code: &'static str,
    },
    Recoverable {
        reference: OpaqueRecoveryReference,
        state: RecoverableState,
    },
    Unavailable {
        code: &'static str,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkflowStatus {
    state: LifecycleState,
    revision: u64,
    profile: ProfileId,
    effect_state: EffectState,
    recovery_action: RecommendedAction,
    updated_at: VerifierTime,
    receipt: Option<ReceiptDisclosureLocator>,
}

impl WorkflowStatus {
    fn from_record(record: &LifecycleRecordV1) -> Self {
        let (effect_state, recovery_action) = status_classification(record.state());
        Self {
            state: record.state(),
            revision: record.revision(),
            profile: record.decision_input().commitments.profile_id().clone(),
            effect_state,
            recovery_action,
            updated_at: record.updated_at(),
            receipt: None,
        }
    }

    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    #[must_use]
    pub const fn profile(&self) -> &ProfileId {
        &self.profile
    }

    #[must_use]
    pub const fn effect_state(&self) -> EffectState {
        self.effect_state
    }

    #[must_use]
    pub const fn recovery_action(&self) -> RecommendedAction {
        self.recovery_action
    }

    #[must_use]
    pub const fn updated_at(&self) -> VerifierTime {
        self.updated_at
    }

    #[must_use]
    pub const fn receipt(&self) -> Option<&ReceiptDisclosureLocator> {
        self.receipt.as_ref()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorError {
    Store(StoreError),
    Reference(RecoveryReferenceError),
    UnknownReference,
    ReferenceMismatch,
    InvalidStage,
    StaleLease,
}

impl From<StoreError> for CoordinatorError {
    fn from(value: StoreError) -> Self {
        Self::Store(value)
    }
}

impl From<RecoveryReferenceError> for CoordinatorError {
    fn from(value: RecoveryReferenceError) -> Self {
        Self::Reference(value)
    }
}

fn recovery_digest(bytes: &[u8; 32]) -> RecoveryReferenceDigest {
    let mut hasher = Sha256::new();
    hasher.update(RECOVERY_REFERENCE_DOMAIN);
    hasher.update(bytes);
    RecoveryReferenceDigest::new(hasher.finalize().into())
}

const fn transition_stage(command: &TransitionCommandV1) -> OperationalStage {
    match command {
        TransitionCommandV1::RecordDecision(_) => OperationalStage::DecisionPersistence,
        TransitionCommandV1::Reserve => OperationalStage::Reservation,
        TransitionCommandV1::RecordExecutionIntent(_) => OperationalStage::ExecutionIntent,
        TransitionCommandV1::AuthorizeCredential => OperationalStage::Credential,
        TransitionCommandV1::StartAttempt | TransitionCommandV1::MarkProviderCallEntered => {
            OperationalStage::ProviderEntry
        }
        TransitionCommandV1::MarkOutcomeUnknown { .. }
        | TransitionCommandV1::Commit { .. }
        | TransitionCommandV1::Release { .. } => OperationalStage::ProviderResult,
        TransitionCommandV1::Reconcile { .. } => OperationalStage::Reconciliation,
    }
}

const fn status_classification(state: LifecycleState) -> (EffectState, RecommendedAction) {
    match state {
        LifecycleState::Committed | LifecycleState::ReconciledCommitted => {
            (EffectState::Applied, RecommendedAction::InspectReceipt)
        }
        LifecycleState::Released | LifecycleState::ReconciledReleased => {
            (EffectState::NotApplied, RecommendedAction::InspectReceipt)
        }
        LifecycleState::Executing | LifecycleState::OutcomeUnknown => {
            (EffectState::Possible, RecommendedAction::ResumeAndReconcile)
        }
        LifecycleState::DecisionRecorded
        | LifecycleState::Reserved
        | LifecycleState::ExecutionIntentRecorded => (
            EffectState::NotApplied,
            RecommendedAction::ResumeAndReconcile,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixedSource([u8; 32]);

    impl RecoveryReferenceSource for FixedSource {
        fn fill(&self, output: &mut [u8; 32]) -> Result<(), RecoveryReferenceError> {
            output.copy_from_slice(&self.0);
            Ok(())
        }
    }

    #[test]
    fn reference_is_url_safe_opaque_and_domain_separated() {
        let reference = OpaqueRecoveryReference::generate(&FixedSource([7; 32])).unwrap();
        let token = reference.to_url_token();
        let parsed = OpaqueRecoveryReference::parse_url_token(&token).unwrap();
        assert_eq!(reference.digest(), parsed.digest());
        assert_ne!(reference.digest().bytes(), &[7; 32]);
        assert!(OpaqueRecoveryReference::parse_url_token("not-a-token").is_err());
    }

    #[test]
    fn in_memory_references_are_exact_and_leases_are_exclusive() {
        let store = InMemoryRecoveryStore::new(2).unwrap();
        let target = RecoveryTarget {
            workflow: WorkflowId::parse("workflow-1").unwrap(),
            profile: ProfileId::parse("auths.test.profile/1").unwrap(),
        };
        let digest = RecoveryReferenceDigest::new([1; 32]);
        store.bind_recovery_reference(digest, &target).unwrap();
        assert_eq!(
            store.resolve_recovery_reference(digest).unwrap(),
            Some(target.clone())
        );
        let request = RecoveryLeaseRequest::new(
            target.clone(),
            1,
            VerifierTime::from_unix_seconds(10),
            30,
            &FixedSource([2; 32]),
        )
        .unwrap();
        store.claim_reconciliation(request).unwrap();
        let competing = RecoveryLeaseRequest::new(
            target,
            1,
            VerifierTime::from_unix_seconds(11),
            30,
            &FixedSource([3; 32]),
        )
        .unwrap();
        assert!(matches!(
            store.claim_reconciliation(competing),
            Err(StoreError::Conflict)
        ));
    }
}
