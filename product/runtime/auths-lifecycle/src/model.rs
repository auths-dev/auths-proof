use alloc::{boxed::Box, string::String, vec::Vec};

use auths_bounded_policy::{
    BoundedOutputs, CommitmentDigest, ConfigurationCommitmentV1, EvaluationCommitmentsV1,
    ImplementationId, IntentId, ProfileId, ReservationIntentCommitmentV1, ReservationKind, UnitId,
    VerifierTime,
};
use sha2::{Digest as _, Sha256};

use crate::{
    DecisionReceiptDigest, DomainId, DomainReceiptDigest, ExecutionId, ExecutionIntentDigest,
    ExecutorAudienceId, LifecycleId, LifecycleReceiptDigest, MAX_LIFECYCLE_EVENTS,
    MAX_PROVIDER_ATTEMPTS, MAX_RECONCILIATION_OBSERVATIONS, MAX_RESERVATION_INTENTS,
    ObservationDigest, ProviderConditionDigest, ProviderContractId, ProviderRequestDigest,
    ProviderResultDigest, ReconciliationId, ReservationAlgebraId, ReservationId,
    ReservationSetDigest, WorkflowId,
};

/// Closed V1 lifecycle states. Numeric order has no semantic meaning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleState {
    /// Pure authorization and eligibility were durably recorded.
    DecisionRecorded,
    /// Every reservation intent was atomically acquired.
    Reserved,
    /// Exact command and provider-request commitments were durably recorded.
    ExecutionIntentRecorded,
    /// One provider attempt was durably recorded before provider I/O.
    Executing,
    /// Fresh domain evidence proves the exact effect occurred.
    Committed,
    /// Fresh domain evidence or a permitted pre-attempt cancellation proves non-effect.
    Released,
    /// The exact effect may have occurred and reservations remain held.
    OutcomeUnknown,
    /// Reconciliation proved the exact effect.
    ReconciledCommitted,
    /// Reconciliation proved definite non-effect.
    ReconciledReleased,
}

impl LifecycleState {
    /// Returns whether no later transition is legal.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Committed | Self::Released | Self::ReconciledCommitted | Self::ReconciledReleased
        )
    }
}

/// Provider retry semantics declared by one domain-owned provider contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderRetryClass {
    /// Exact request and key identify one logical effect for the declared window.
    ExactIdempotent,
    /// The provider atomically enforces the committed precondition.
    Conditional,
    /// Reconciliation must prove non-effect before retry.
    ObserveBeforeRetry,
    /// Ambiguity is never automatically retried.
    NonRetryable,
}

/// Reservation mechanics shared without importing domain meaning.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReservationMode {
    /// Exact additive capacity in an explicit unit.
    Additive {
        /// Capacity unit.
        unit: UnitId,
        /// Exact non-zero amount.
        amount: u64,
    },
    /// One live owner for an exact domain scope.
    Exclusive,
}

/// One derived reservation key and amount.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationRequestV1 {
    reservation_id: ReservationId,
    algebra_id: ReservationAlgebraId,
    intent_id: IntentId,
    scope_digest: CommitmentDigest,
    window_digest: Option<CommitmentDigest>,
    mode: ReservationMode,
    intent_digest: CommitmentDigest,
}

impl ReservationRequestV1 {
    /// Derives the V1 reservation identity from exact committed inputs.
    ///
    /// # Errors
    ///
    /// Returns [`crate::IdentifierError`] only if the derived fixed-width
    /// hexadecimal identity violates the closed identifier contract.
    pub fn derive(
        workflow: &WorkflowId,
        domain: &DomainId,
        profile: &ProfileId,
        evaluator: &auths_bounded_policy::EvaluatorSemanticId,
        audience: &ExecutorAudienceId,
        algebra_id: &ReservationAlgebraId,
        intent: &ReservationIntentCommitmentV1,
    ) -> Result<Self, crate::IdentifierError> {
        let mode = match intent.kind() {
            ReservationKind::Additive { unit, amount } => ReservationMode::Additive {
                unit: unit.clone(),
                amount: *amount,
            },
            ReservationKind::Exclusive => ReservationMode::Exclusive,
        };
        let mut hasher = Sha256::new();
        hasher.update(b"AUTHS-RESERVATION-KEY\x00\x01");
        for value in [
            workflow.as_str().as_bytes(),
            domain.as_str().as_bytes(),
            profile.as_str().as_bytes(),
            evaluator.as_str().as_bytes(),
            audience.as_str().as_bytes(),
            algebra_id.as_str().as_bytes(),
            intent.intent_id().as_str().as_bytes(),
        ] {
            hasher.update((value.len() as u64).to_be_bytes());
            hasher.update(value);
        }
        for digest in [
            intent.scope_digest(),
            intent.action_digest(),
            intent.policy_digest(),
            intent.evidence_digest(),
            intent.canonical_digest(),
        ] {
            hasher.update(digest.as_bytes());
        }
        if let Some(window) = intent.window_digest() {
            hasher.update([1]);
            hasher.update(window.as_bytes());
        } else {
            hasher.update([0]);
        }
        match &mode {
            ReservationMode::Additive { unit, amount } => {
                hasher.update([0]);
                hasher.update(unit.as_str().as_bytes());
                hasher.update(amount.to_be_bytes());
            }
            ReservationMode::Exclusive => hasher.update([1]),
        }
        let digest: [u8; 32] = hasher.finalize().into();
        let reservation_id = ReservationId::parse(&hex(&digest))?;
        Ok(Self {
            reservation_id,
            algebra_id: algebra_id.clone(),
            intent_id: intent.intent_id().clone(),
            scope_digest: intent.scope_digest(),
            window_digest: intent.window_digest(),
            mode,
            intent_digest: intent.canonical_digest(),
        })
    }

    /// Returns the derived exact reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &ReservationId {
        &self.reservation_id
    }

    /// Returns the closed reservation algebra.
    #[must_use]
    pub const fn algebra_id(&self) -> &ReservationAlgebraId {
        &self.algebra_id
    }

    /// Returns the domain-owned intent identity.
    #[must_use]
    pub const fn intent_id(&self) -> &IntentId {
        &self.intent_id
    }

    /// Returns the domain scope commitment.
    #[must_use]
    pub const fn scope_digest(&self) -> CommitmentDigest {
        self.scope_digest
    }

    /// Returns the fixed or rolling window commitment.
    #[must_use]
    pub const fn window_digest(&self) -> Option<CommitmentDigest> {
        self.window_digest
    }

    /// Returns additive or exclusive mechanics.
    #[must_use]
    pub const fn mode(&self) -> &ReservationMode {
        &self.mode
    }

    /// Returns the canonical domain reservation-intent commitment.
    #[must_use]
    pub const fn intent_digest(&self) -> CommitmentDigest {
        self.intent_digest
    }
}

/// Canonically ordered atomic reservation set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationSetV1 {
    entries: Vec<ReservationRequestV1>,
    commitment: ReservationSetDigest,
}

impl ReservationSetV1 {
    /// Derives and validates one atomic reservation set.
    ///
    /// # Errors
    ///
    /// Returns [`ReservationSetError`] for an oversized set, duplicate derived
    /// key, inconsistent intent binding, or invalid derived identity.
    #[allow(clippy::too_many_arguments)]
    pub fn derive(
        workflow: &WorkflowId,
        domain: &DomainId,
        profile: &ProfileId,
        evaluator: &auths_bounded_policy::EvaluatorSemanticId,
        audience: &ExecutorAudienceId,
        algebra_id: &ReservationAlgebraId,
        outputs: &BoundedOutputs,
    ) -> Result<Self, ReservationSetError> {
        if outputs.reservation_intents().len() > MAX_RESERVATION_INTENTS {
            return Err(ReservationSetError::TooMany);
        }
        let mut entries = Vec::with_capacity(outputs.reservation_intents().len());
        for intent in outputs.reservation_intents() {
            entries.push(
                ReservationRequestV1::derive(
                    workflow, domain, profile, evaluator, audience, algebra_id, intent,
                )
                .map_err(|_| ReservationSetError::InvalidIdentity)?,
            );
        }
        entries.sort_by(|left, right| left.reservation_id.cmp(&right.reservation_id));
        if entries
            .windows(2)
            .any(|pair| pair[0].reservation_id >= pair[1].reservation_id)
        {
            return Err(ReservationSetError::Duplicate);
        }
        let mut hasher = Sha256::new();
        hasher.update(b"AUTHS-RESERVATION-SET\x00\x01");
        for entry in &entries {
            hasher.update(entry.reservation_id.as_str().as_bytes());
            hasher.update(entry.intent_digest.as_bytes());
        }
        Ok(Self {
            entries,
            commitment: ReservationSetDigest::new(hasher.finalize().into()),
        })
    }

    /// Returns canonical requests.
    #[must_use]
    pub fn entries(&self) -> &[ReservationRequestV1] {
        &self.entries
    }

    /// Returns the set commitment.
    #[must_use]
    pub const fn commitment(&self) -> ReservationSetDigest {
        self.commitment
    }
}

/// Reservation-set construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReservationSetError {
    /// The set exceeds 32 intents.
    TooMany,
    /// Two intents derive the same reservation key.
    Duplicate,
    /// A derived semantic identity was invalid.
    InvalidIdentity,
}

/// Durable state of one reservation entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationEntryV1 {
    request: ReservationRequestV1,
    committed: bool,
    released: bool,
}

impl ReservationEntryV1 {
    /// Creates one live reservation.
    #[must_use]
    pub const fn reserved(request: ReservationRequestV1) -> Self {
        Self {
            request,
            committed: false,
            released: false,
        }
    }

    /// Returns its immutable request.
    #[must_use]
    pub const fn request(&self) -> &ReservationRequestV1 {
        &self.request
    }

    /// Returns whether it contributes committed use.
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        self.committed
    }

    /// Returns whether it was definitely released.
    #[must_use]
    pub const fn is_released(&self) -> bool {
        self.released
    }

    pub(crate) fn mark_committed(&mut self) {
        self.committed = true;
    }

    pub(crate) fn mark_released(&mut self) {
        self.released = true;
    }
}

/// Exact capacity facts supplied to the pure transition kernel.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CapacityEntryV1 {
    /// Exact additive use for one scope, window, and unit.
    Additive {
        /// Scope digest.
        scope_digest: CommitmentDigest,
        /// Optional window.
        window_digest: Option<CommitmentDigest>,
        /// Exact unit.
        unit: UnitId,
        /// Capacity ceiling.
        ceiling: u64,
        /// Already committed use.
        committed: u64,
        /// Reserved, executing, or outcome-unknown use.
        active: u64,
    },
    /// Exact live ownership for one exclusive scope.
    Exclusive {
        /// Scope digest.
        scope_digest: CommitmentDigest,
        /// Optional window.
        window_digest: Option<CommitmentDigest>,
        /// Existing live owner, if any.
        live_owner: Option<ReservationId>,
    },
}

/// Canonically ordered capacity snapshot supplied explicitly by the store.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacitySnapshotV1 {
    entries: Vec<CapacityEntryV1>,
}

impl CapacitySnapshotV1 {
    /// Constructs an exact capacity snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CapacitySnapshotError`] if the snapshot exceeds the intent
    /// ceiling, contains zero ceilings, overcommitted arithmetic, or duplicate
    /// keys.
    pub fn new(mut entries: Vec<CapacityEntryV1>) -> Result<Self, CapacitySnapshotError> {
        if entries.len() > MAX_RESERVATION_INTENTS {
            return Err(CapacitySnapshotError::TooMany);
        }
        for entry in &entries {
            if let CapacityEntryV1::Additive {
                ceiling,
                committed,
                active,
                ..
            } = entry
                && (*ceiling == 0
                    || committed
                        .checked_add(*active)
                        .is_none_or(|used| used > *ceiling))
            {
                return Err(CapacitySnapshotError::InvalidCapacity);
            }
        }
        entries.sort_by(capacity_key_cmp);
        if entries
            .windows(2)
            .any(|pair| capacity_key_equal(&pair[0], &pair[1]))
        {
            return Err(CapacitySnapshotError::Duplicate);
        }
        Ok(Self { entries })
    }

    /// Returns exact capacity entries.
    #[must_use]
    pub fn entries(&self) -> &[CapacityEntryV1] {
        &self.entries
    }
}

fn capacity_key_cmp(left: &CapacityEntryV1, right: &CapacityEntryV1) -> core::cmp::Ordering {
    match (left, right) {
        (
            CapacityEntryV1::Additive {
                scope_digest: left_scope,
                window_digest: left_window,
                unit: left_unit,
                ..
            },
            CapacityEntryV1::Additive {
                scope_digest: right_scope,
                window_digest: right_window,
                unit: right_unit,
                ..
            },
        ) => (left_scope, left_window, left_unit).cmp(&(right_scope, right_window, right_unit)),
        (CapacityEntryV1::Additive { .. }, CapacityEntryV1::Exclusive { .. }) => {
            core::cmp::Ordering::Less
        }
        (CapacityEntryV1::Exclusive { .. }, CapacityEntryV1::Additive { .. }) => {
            core::cmp::Ordering::Greater
        }
        (
            CapacityEntryV1::Exclusive {
                scope_digest: left_scope,
                window_digest: left_window,
                ..
            },
            CapacityEntryV1::Exclusive {
                scope_digest: right_scope,
                window_digest: right_window,
                ..
            },
        ) => (left_scope, left_window).cmp(&(right_scope, right_window)),
    }
}

/// Invalid capacity snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacitySnapshotError {
    /// More than 32 entries were supplied.
    TooMany,
    /// A ceiling was zero, arithmetic overflowed, or existing use exceeded it.
    InvalidCapacity,
    /// Two entries described one capacity key.
    Duplicate,
}

fn capacity_key_equal(left: &CapacityEntryV1, right: &CapacityEntryV1) -> bool {
    match (left, right) {
        (
            CapacityEntryV1::Additive {
                scope_digest: ls,
                window_digest: lw,
                unit: lu,
                ..
            },
            CapacityEntryV1::Additive {
                scope_digest: rs,
                window_digest: rw,
                unit: ru,
                ..
            },
        ) => ls == rs && lw == rw && lu == ru,
        (
            CapacityEntryV1::Exclusive {
                scope_digest: ls,
                window_digest: lw,
                ..
            },
            CapacityEntryV1::Exclusive {
                scope_digest: rs,
                window_digest: rw,
                ..
            },
        ) => ls == rs && lw == rw,
        _ => false,
    }
}

/// Explicit revocation and expiry facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RevocationSnapshotV1 {
    /// Whether authority was revoked at the supplied verifier time.
    pub revoked: bool,
    /// Digest of the domain-owned revocation evidence.
    pub snapshot_digest: CommitmentDigest,
}

/// Domain cancellation semantics before possible delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationDisposition {
    /// A reserved action with no attempt may be released.
    BeforeAttemptAllowed,
    /// Domain policy requires explicit definite-non-effect evidence.
    EvidenceRequired,
}

/// Closed conclusion supplied by domain/provider evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EffectConclusion {
    /// Exact effect definitely occurred.
    Effect,
    /// Exact effect definitely did not occur.
    NonEffect,
    /// Delivery or effect remains ambiguous.
    Unknown,
    /// Reconciliation evidence cannot establish either conclusion.
    Inconclusive,
}

/// Exact execution intent committed before credential acquisition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecutionIntentV1 {
    /// Commitment to the domain-owned verified command.
    verified_command_digest: CommitmentDigest,
    /// Commitment to the exact provider request.
    provider_request_digest: ProviderRequestDigest,
    /// Commitment to idempotency or conditional material.
    provider_condition_digest: ProviderConditionDigest,
    /// Closed provider semantics.
    provider_contract_id: ProviderContractId,
    /// Declared retry class.
    retry_class: ProviderRetryClass,
    /// Canonical execution-intent commitment.
    intent_digest: ExecutionIntentDigest,
}

impl ExecutionIntentV1 {
    /// Constructs and commits one exact execution intent.
    #[must_use]
    pub fn new(
        verified_command_digest: CommitmentDigest,
        provider_request_digest: ProviderRequestDigest,
        provider_condition_digest: ProviderConditionDigest,
        provider_contract_id: ProviderContractId,
        retry_class: ProviderRetryClass,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"AUTHS-EXECUTION-INTENT\x00\x01");
        hasher.update(verified_command_digest.as_bytes());
        hasher.update(provider_request_digest.bytes());
        hasher.update(provider_condition_digest.bytes());
        hasher.update(provider_contract_id.as_str().as_bytes());
        hasher.update([retry_class_code(retry_class)]);
        Self {
            verified_command_digest,
            provider_request_digest,
            provider_condition_digest,
            provider_contract_id,
            retry_class,
            intent_digest: ExecutionIntentDigest::new(hasher.finalize().into()),
        }
    }

    /// Returns the verified command commitment.
    #[must_use]
    pub const fn verified_command_digest(&self) -> CommitmentDigest {
        self.verified_command_digest
    }

    /// Returns the exact provider-request commitment.
    #[must_use]
    pub const fn provider_request_digest(&self) -> ProviderRequestDigest {
        self.provider_request_digest
    }

    /// Returns the idempotency or condition commitment.
    #[must_use]
    pub const fn provider_condition_digest(&self) -> ProviderConditionDigest {
        self.provider_condition_digest
    }

    /// Returns the closed provider-contract identity.
    #[must_use]
    pub const fn provider_contract_id(&self) -> &ProviderContractId {
        &self.provider_contract_id
    }

    /// Returns the declared retry class.
    #[must_use]
    pub const fn retry_class(&self) -> ProviderRetryClass {
        self.retry_class
    }

    /// Returns the canonical execution-intent commitment.
    #[must_use]
    pub const fn intent_digest(&self) -> ExecutionIntentDigest {
        self.intent_digest
    }
}

const fn retry_class_code(value: ProviderRetryClass) -> u8 {
    match value {
        ProviderRetryClass::ExactIdempotent => 0,
        ProviderRetryClass::Conditional => 1,
        ProviderRetryClass::ObserveBeforeRetry => 2,
        ProviderRetryClass::NonRetryable => 3,
    }
}

/// Monotonic one-based provider attempt ordinal.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct AttemptOrdinal(u8);

impl AttemptOrdinal {
    /// Constructs a valid V1 attempt ordinal.
    ///
    /// # Errors
    ///
    /// Returns [`AttemptOrdinalError`] for zero or values above 16.
    pub const fn new(value: u8) -> Result<Self, AttemptOrdinalError> {
        if value == 0 || value as usize > MAX_PROVIDER_ATTEMPTS {
            Err(AttemptOrdinalError)
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the one-based ordinal.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Invalid provider-attempt ordinal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttemptOrdinalError;

/// Durable provider attempt recorded before provider I/O.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAttemptV1 {
    /// Monotonic attempt ordinal.
    pub ordinal: AttemptOrdinal,
    /// Exact start time.
    pub started_at: VerifierTime,
    /// Provider request commitment.
    pub provider_request_digest: ProviderRequestDigest,
    /// Provider condition/idempotency commitment.
    pub provider_condition_digest: ProviderConditionDigest,
    /// Provider contract.
    pub provider_contract_id: ProviderContractId,
    /// Whether call entry was durably recorded.
    pub call_entered: bool,
}

/// Fresh domain-owned reconciliation evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReconciliationObservationV1 {
    /// Observation identity.
    pub reconciliation_id: ReconciliationId,
    /// Observation adapter/source.
    pub source_id: auths_bounded_policy::EvidenceSourceId,
    /// Observation time.
    pub observed_at: VerifierTime,
    /// Evidence expiry.
    pub fresh_until: VerifierTime,
    /// Exact canonical observation digest.
    pub observation_digest: ObservationDigest,
    /// Conclusion under the registered domain contract.
    pub conclusion: EffectConclusion,
    /// Exact provider request.
    pub provider_request_digest: ProviderRequestDigest,
}

impl ReconciliationObservationV1 {
    /// Constructs exact domain-owned reconciliation evidence.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub const fn new(
        reconciliation_id: ReconciliationId,
        source_id: auths_bounded_policy::EvidenceSourceId,
        observed_at: VerifierTime,
        fresh_until: VerifierTime,
        observation_digest: ObservationDigest,
        conclusion: EffectConclusion,
        provider_request_digest: ProviderRequestDigest,
    ) -> Self {
        Self {
            reconciliation_id,
            source_id,
            observed_at,
            fresh_until,
            observation_digest,
            conclusion,
            provider_request_digest,
        }
    }
}

/// Lifecycle trace event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleEventKind {
    /// Decision and canonical decision receipt became durable.
    DecisionPersisted,
    /// All reservation intents became durable.
    ReservationPersisted,
    /// Exact execution intent became durable.
    ExecutionIntentPersisted,
    /// The durable stage was approved for credential acquisition.
    CredentialAuthorized,
    /// Provider attempt became durable.
    AttemptPersisted,
    /// Provider call entry became durable before I/O.
    ProviderCallEntered,
    /// Exact provider result was durably classified.
    ProviderResultPersisted,
    /// Outcome unknown became durable.
    OutcomeUnknownPersisted,
    /// Reconciliation observation became durable.
    ReconciliationObserved,
    /// A terminal reconciliation became durable.
    ReconciliationPersisted,
}

/// One append-only event in a lifecycle record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleEventV1 {
    /// Event kind.
    pub kind: LifecycleEventKind,
    /// Record revision after the event.
    pub revision: u64,
    /// Explicit verifier time.
    pub verifier_time: VerifierTime,
    /// Triggering command or evidence commitment.
    pub trigger_digest: CommitmentDigest,
}

/// Shared lifecycle receipt envelope. Domain receipt payloads stay separate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleReceiptEnvelopeV1 {
    /// Monotonic record revision.
    pub revision: u64,
    /// Previous lifecycle-receipt link.
    pub previous: Option<LifecycleReceiptDigest>,
    /// Source state, absent only for decision creation.
    pub from: Option<LifecycleState>,
    /// Resulting state.
    pub to: LifecycleState,
    /// Triggering command commitment.
    pub trigger_digest: CommitmentDigest,
    /// Explicit verifier time.
    pub verifier_time: VerifierTime,
    /// Required configuration.
    pub required_configuration: ConfigurationCommitmentV1,
    /// Executed configuration.
    pub executed_configuration: ConfigurationCommitmentV1,
    /// Implementation provenance.
    pub implementation_id: ImplementationId,
    /// Optional canonical domain receipt.
    pub domain_receipt_digest: Option<DomainReceiptDigest>,
    /// Canonical shared receipt commitment.
    pub receipt_digest: LifecycleReceiptDigest,
}

/// Complete input for a new durable decision record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionInputV1 {
    /// Core authorization must already have succeeded.
    pub core_authorized: bool,
    /// Commitment to the core authorization result.
    pub core_authorization_digest: CommitmentDigest,
    /// Workflow identity.
    pub workflow_id: WorkflowId,
    /// Shared lifecycle identity.
    pub lifecycle_id: LifecycleId,
    /// One logical execution identity.
    pub execution_id: ExecutionId,
    /// Domain identity.
    pub domain_id: DomainId,
    /// Exact executor audience.
    pub executor_audience: ExecutorAudienceId,
    /// Closed reservation algebra applied to every emitted intent.
    pub reservation_algebra_id: ReservationAlgebraId,
    /// Complete pure-evaluation commitments.
    pub commitments: EvaluationCommitmentsV1,
    /// Eligible outputs. Denied and indeterminate results cannot be supplied.
    pub outputs: BoundedOutputs,
    /// Derived atomic reservation set.
    pub reservations: ReservationSetV1,
    /// Canonical decision receipt.
    pub decision_receipt_digest: DecisionReceiptDigest,
    /// Domain decision receipt.
    pub domain_decision_receipt_digest: DomainReceiptDigest,
    /// Lifecycle implementation provenance.
    pub implementation_id: ImplementationId,
    /// Build provenance.
    pub implementation_build_digest: CommitmentDigest,
    /// Exact authority expiry.
    pub expires_at: VerifierTime,
    /// Domain cancellation contract.
    pub cancellation: CancellationDisposition,
}

/// Complete durable lifecycle record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRecordV1 {
    pub(crate) input: DecisionInputV1,
    pub(crate) state: LifecycleState,
    pub(crate) revision: u64,
    pub(crate) created_at: VerifierTime,
    pub(crate) updated_at: VerifierTime,
    pub(crate) reservation_entries: Vec<ReservationEntryV1>,
    pub(crate) execution_intent: Option<ExecutionIntentV1>,
    pub(crate) credential_authorized: bool,
    pub(crate) attempts: Vec<ProviderAttemptV1>,
    pub(crate) observations: Vec<ReconciliationObservationV1>,
    pub(crate) terminal_result: Option<ProviderResultDigest>,
    pub(crate) events: Vec<LifecycleEventV1>,
    pub(crate) receipts: Vec<LifecycleReceiptEnvelopeV1>,
}

impl LifecycleRecordV1 {
    /// Returns current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> LifecycleState {
        self.state
    }

    /// Returns the monotonic record revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns immutable workflow identity.
    #[must_use]
    pub const fn workflow_id(&self) -> &WorkflowId {
        &self.input.workflow_id
    }

    /// Returns immutable lifecycle identity.
    #[must_use]
    pub const fn lifecycle_id(&self) -> &LifecycleId {
        &self.input.lifecycle_id
    }

    /// Returns immutable execution identity.
    #[must_use]
    pub const fn execution_id(&self) -> &ExecutionId {
        &self.input.execution_id
    }

    /// Returns immutable decision input and commitments.
    #[must_use]
    pub const fn decision_input(&self) -> &DecisionInputV1 {
        &self.input
    }

    /// Returns reservations.
    #[must_use]
    pub fn reservations(&self) -> &[ReservationEntryV1] {
        &self.reservation_entries
    }

    /// Returns the execution intent when durably recorded.
    #[must_use]
    pub const fn execution_intent(&self) -> Option<&ExecutionIntentV1> {
        self.execution_intent.as_ref()
    }

    /// Returns provider attempts.
    #[must_use]
    pub fn attempts(&self) -> &[ProviderAttemptV1] {
        &self.attempts
    }

    /// Returns reconciliation observations.
    #[must_use]
    pub fn observations(&self) -> &[ReconciliationObservationV1] {
        &self.observations
    }

    /// Returns append-only trace events.
    #[must_use]
    pub fn events(&self) -> &[LifecycleEventV1] {
        &self.events
    }

    /// Returns hash-linked shared receipt envelopes.
    #[must_use]
    pub fn receipts(&self) -> &[LifecycleReceiptEnvelopeV1] {
        &self.receipts
    }

    /// Returns whether credential acquisition was durably authorized.
    #[must_use]
    pub const fn credential_authorized(&self) -> bool {
        self.credential_authorized
    }
}

/// Explicit pure transition context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransitionContextV1 {
    /// Explicit verifier time.
    pub verifier_time: VerifierTime,
    /// Current executed configuration; exact commitment cannot drift.
    pub executed_configuration: ConfigurationCommitmentV1,
    /// Current revocation snapshot.
    pub revocation: RevocationSnapshotV1,
    /// Exact capacity snapshot for reservation.
    pub capacity: CapacitySnapshotV1,
}

/// Closed lifecycle commands.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TransitionCommandV1 {
    /// Create the first durable decision.
    RecordDecision(Box<DecisionInputV1>),
    /// Atomically acquire every reservation.
    Reserve,
    /// Durably bind exact command and provider request commitments.
    RecordExecutionIntent(ExecutionIntentV1),
    /// Durably authorize the subsequent credential acquisition event.
    AuthorizeCredential,
    /// Durably record one attempt before provider I/O.
    StartAttempt,
    /// Durably record provider call entry immediately before I/O.
    MarkProviderCallEntered,
    /// Persist a definite provider effect.
    Commit {
        /// Exact provider result.
        result_digest: ProviderResultDigest,
        /// Domain receipt for the effect.
        domain_receipt_digest: DomainReceiptDigest,
    },
    /// Persist definite non-effect or permitted pre-attempt cancellation.
    Release {
        /// Exact provider/evidence result where required.
        result_digest: ProviderResultDigest,
        /// Domain receipt for non-effect.
        domain_receipt_digest: DomainReceiptDigest,
        /// Domain-classified conclusion.
        conclusion: EffectConclusion,
    },
    /// Persist an ambiguous provider outcome without releasing capacity.
    MarkOutcomeUnknown {
        /// Domain receipt describing the ambiguity.
        domain_receipt_digest: DomainReceiptDigest,
    },
    /// Persist a fresh reconciliation observation and possibly terminate.
    Reconcile {
        /// Exact observation.
        observation: ReconciliationObservationV1,
        /// Domain reconciliation receipt.
        domain_receipt_digest: DomainReceiptDigest,
    },
}

/// Store-level compare-and-swap transaction request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoreTransactionV1 {
    /// Exact workflow addressed by this transaction.
    pub workflow_id: WorkflowId,
    /// Expected record revision; `None` requires record absence.
    pub expected_revision: Option<u64>,
    /// Pure transition command.
    pub command: TransitionCommandV1,
    /// Pure explicit context.
    pub context: TransitionContextV1,
}

/// Deterministic work performed by validation and transition.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LifecycleWork {
    /// Reservation intents inspected.
    pub reservation_intents: u8,
    /// Capacity entries inspected.
    pub capacity_entries: u8,
    /// Events inspected.
    pub events: u8,
    /// Attempts inspected.
    pub attempts: u8,
    /// Observations inspected.
    pub observations: u8,
    /// Transition predicates evaluated.
    pub transition_predicates: u8,
}

pub(crate) fn can_append_event(record: &LifecycleRecordV1) -> bool {
    record.events.len() < MAX_LIFECYCLE_EVENTS
}

pub(crate) fn can_append_attempt(record: &LifecycleRecordV1) -> bool {
    record.attempts.len() < MAX_PROVIDER_ATTEMPTS
}

pub(crate) fn can_append_observation(record: &LifecycleRecordV1) -> bool {
    record.observations.len() < MAX_RECONCILIATION_OBSERVATIONS
}

fn hex(bytes: &[u8; 32]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(ALPHABET[usize::from(byte >> 4)]));
        output.push(char::from(ALPHABET[usize::from(byte & 0x0f)]));
    }
    output
}
