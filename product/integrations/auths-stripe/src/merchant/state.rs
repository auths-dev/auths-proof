//! Stripe-local durable merchant-payment reservation, claim, and replay state.
//!
//! This is deliberately not a generic reservation runtime. Its schema and
//! accounting keys are reusable Stripe merchant leaves, while automatic
//! collection lifecycle semantics remain owned by specification 0013.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

use crate::{
    canonical::{canonical_json, sha256},
    merchant::{
        MerchantAggregateSnapshot, MerchantAggregateUsage, MerchantConnectAccount,
        MerchantOperation, MerchantReservationIntent, StripeBoundedMerchantPaymentPolicyV1,
        collect::{
            PaymentCollectReconciliationOutcome, PaymentCollectTransition,
            transition_payment_collect,
        },
    },
    types::{ChargeId, Currency, CustomerId, DigestHex, PaymentIntentId, StripeAccountId},
};

const RESERVATION_SCHEMA: &str = "auths.stripe.merchant-reservation/1";
const STATE_SCHEMA: &str = "auths.stripe.merchant-reservation-state/1";
const MAX_STATE_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECORDS: usize = 100_000;

/// Exact durable lifecycle of a Stripe merchant effect.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum MerchantReservationState {
    /// Aggregate capacity is durably held.
    Reserved,
    /// The exact verified command owns the effect claim.
    Claimed,
    /// Provider delivery is about to be attempted.
    Attempting,
    /// A normalized provider response is durable but not yet observed.
    ProviderAccepted,
    /// Automatic collection is durably committed.
    Committed,
    /// Definite non-execution returned capacity.
    Released,
    /// Delivery may have reached Stripe; capacity stays held.
    OutcomeUnknown,
    /// Retrieval proved automatic collection.
    ReconciledCommitted,
    /// Retrieval proved definite non-execution.
    ReconciledReleased,
}

impl MerchantReservationState {
    fn holds_reserved(self) -> bool {
        matches!(
            self,
            Self::Reserved | Self::Claimed | Self::Attempting | Self::ProviderAccepted
        )
    }

    fn holds_committed(self) -> bool {
        matches!(self, Self::Committed | Self::ReconciledCommitted)
    }

    fn holds_unknown(self) -> bool {
        self == Self::OutcomeUnknown
    }
}

/// Public provider projection retained without credentials or client secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantProviderProjection {
    /// PaymentIntent created by Stripe.
    pub payment_intent_id: PaymentIntentId,
    /// Latest Charge, when Stripe supplied one.
    pub charge_id: Option<ChargeId>,
    /// Normalized provider status.
    pub status: String,
    /// Exact amount.
    pub amount_minor: u64,
    /// Currency.
    pub currency: Currency,
    /// Amount capturable for manual authorization.
    pub amount_capturable_minor: u64,
    /// Amount received by Stripe.
    pub amount_received_minor: u64,
    /// Card authorization expiry, if known.
    pub capture_before: Option<u64>,
    /// Stripe request correlation, never a secret.
    pub stripe_request_id: Option<String>,
    /// Commitment to the bounded sanitized provider response.
    pub response_digest: DigestHex,
    /// Observation time.
    pub observed_at: u64,
    /// Retrieval, create response, or webhook.
    pub source: String,
}

/// Durable record for one exact merchant-payment workflow.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantReservationRecord {
    schema: String,
    reservation_id: DigestHex,
    workflow_id: String,
    operation: MerchantOperation,
    exact_action_profile: String,
    action_digest: DigestHex,
    decision_receipt_digest: DigestHex,
    policy_digest: DigestHex,
    evaluator_semantic_id: String,
    evaluator_semantic_version: u16,
    evidence_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    stripe_account_id: StripeAccountId,
    connect_account: MerchantConnectAccount,
    customer_id: CustomerId,
    order_scope: String,
    currency: Currency,
    amount_minor: u64,
    intents: Vec<MerchantReservationIntent>,
    state: MerchantReservationState,
    idempotency_key_digest: DigestHex,
    provider: Option<MerchantProviderProjection>,
    created_at: u64,
    updated_at: u64,
}

impl MerchantReservationRecord {
    /// Deterministic reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    /// Workflow identity.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Merchant operation.
    #[must_use]
    pub const fn operation(&self) -> MerchantOperation {
        self.operation
    }

    /// Exact action profile committed by this record.
    #[must_use]
    pub fn exact_action_profile(&self) -> &str {
        &self.exact_action_profile
    }

    /// Exact action commitment.
    #[must_use]
    pub const fn action_digest(&self) -> &DigestHex {
        &self.action_digest
    }

    /// Immutable configured-policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Durable decision receipt commitment.
    #[must_use]
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }

    /// Required configuration commitment.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Executed configuration commitment.
    #[must_use]
    pub const fn executed_configuration_digest(&self) -> &DigestHex {
        &self.executed_configuration_digest
    }

    /// Current lifecycle state.
    #[must_use]
    pub const fn state(&self) -> MerchantReservationState {
        self.state
    }

    /// Stripe account.
    #[must_use]
    pub const fn stripe_account_id(&self) -> &StripeAccountId {
        &self.stripe_account_id
    }

    /// Connect context.
    #[must_use]
    pub const fn connect_account(&self) -> &MerchantConnectAccount {
        &self.connect_account
    }

    /// Exact Customer.
    #[must_use]
    pub const fn customer_id(&self) -> &CustomerId {
        &self.customer_id
    }

    /// Protected order scope.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Exact amount.
    #[must_use]
    pub const fn amount_minor(&self) -> u64 {
        self.amount_minor
    }

    /// Exact currency.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Aggregate reservation intents.
    #[must_use]
    pub fn intents(&self) -> &[MerchantReservationIntent] {
        &self.intents
    }

    /// Bounded provider projection, if known.
    #[must_use]
    pub const fn provider(&self) -> Option<&MerchantProviderProjection> {
        self.provider.as_ref()
    }

    /// Deterministic protected idempotency-key commitment.
    #[must_use]
    pub const fn idempotency_key_digest(&self) -> &DigestHex {
        &self.idempotency_key_digest
    }
}

/// Complete inputs to an atomic merchant reservation.
pub struct ReserveMerchantPaymentRequest {
    /// Workflow identity.
    pub workflow_id: String,
    /// Operation.
    pub operation: MerchantOperation,
    /// Exact profile corresponding to the operation.
    pub exact_action_profile: String,
    /// Exact action commitment.
    pub action_digest: DigestHex,
    /// Durable decision receipt commitment.
    pub decision_receipt_digest: DigestHex,
    /// Immutable configured-policy commitment.
    pub policy_digest: DigestHex,
    /// Evaluator semantic ID.
    pub evaluator_semantic_id: String,
    /// Evaluator semantic version.
    pub evaluator_semantic_version: u16,
    /// Fresh evidence commitment.
    pub evidence_digest: DigestHex,
    /// Required runtime configuration.
    pub required_configuration_digest: DigestHex,
    /// Executed runtime configuration.
    pub executed_configuration_digest: DigestHex,
    /// Stripe account.
    pub stripe_account_id: StripeAccountId,
    /// Platform or Connect context.
    pub connect_account: MerchantConnectAccount,
    /// Exact Customer.
    pub customer_id: CustomerId,
    /// Protected order scope.
    pub order_scope: String,
    /// Currency.
    pub currency: Currency,
    /// Amount.
    pub amount_minor: u64,
    /// Pure evaluator reservation intents.
    pub intents: Vec<MerchantReservationIntent>,
    /// Protected idempotency-key commitment.
    pub idempotency_key_digest: DigestHex,
    /// Trusted time.
    pub now: u64,
}

#[derive(Serialize)]
struct MerchantReservationIdentity<'a> {
    schema: &'static str,
    workflow_id: &'a str,
    operation: MerchantOperation,
    exact_action_profile: &'a str,
    action_digest: &'a DigestHex,
    policy_digest: &'a DigestHex,
    stripe_account_id: &'a StripeAccountId,
    connect_account: &'a MerchantConnectAccount,
    intents: &'a [MerchantReservationIntent],
}

impl ReserveMerchantPaymentRequest {
    /// Computes the exact deterministic reservation identity.
    ///
    /// # Errors
    ///
    /// Returns a closed persistence failure.
    pub fn reservation_id(&self) -> Result<DigestHex, MerchantStateError> {
        canonical_json(&MerchantReservationIdentity {
            schema: RESERVATION_SCHEMA,
            workflow_id: &self.workflow_id,
            operation: self.operation,
            exact_action_profile: &self.exact_action_profile,
            action_digest: &self.action_digest,
            policy_digest: &self.policy_digest,
            stripe_account_id: &self.stripe_account_id,
            connect_account: &self.connect_account,
            intents: &self.intents,
        })
        .map(|bytes| sha256(&bytes))
        .map_err(|_| MerchantStateError::Corrupt)
    }

    fn into_record(self, reservation_id: DigestHex) -> MerchantReservationRecord {
        MerchantReservationRecord {
            schema: RESERVATION_SCHEMA.into(),
            reservation_id,
            workflow_id: self.workflow_id,
            operation: self.operation,
            exact_action_profile: self.exact_action_profile,
            action_digest: self.action_digest,
            decision_receipt_digest: self.decision_receipt_digest,
            policy_digest: self.policy_digest,
            evaluator_semantic_id: self.evaluator_semantic_id,
            evaluator_semantic_version: self.evaluator_semantic_version,
            evidence_digest: self.evidence_digest,
            required_configuration_digest: self.required_configuration_digest,
            executed_configuration_digest: self.executed_configuration_digest,
            stripe_account_id: self.stripe_account_id,
            connect_account: self.connect_account,
            customer_id: self.customer_id,
            order_scope: self.order_scope,
            currency: self.currency,
            amount_minor: self.amount_minor,
            intents: self.intents,
            state: MerchantReservationState::Reserved,
            idempotency_key_digest: self.idempotency_key_digest,
            provider: None,
            created_at: self.now,
            updated_at: self.now,
        }
    }
}

/// Opaque authority to transition one exact merchant reservation.
#[derive(Debug)]
pub struct MerchantReservationLease {
    workflow_id: String,
    reservation_id: DigestHex,
    action_digest: DigestHex,
}

impl MerchantReservationLease {
    /// Workflow identity.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }
}

/// Atomic reservation result.
#[derive(Debug)]
pub enum ReserveMerchantPaymentResult {
    /// This caller owns a new reservation.
    Reserved {
        /// Transition lease.
        lease: MerchantReservationLease,
        /// Durable record.
        record: MerchantReservationRecord,
    },
    /// Same workflow and exact action already exist.
    Replay(MerchantReservationRecord),
    /// Workflow is already bound to different inputs.
    Conflict(MerchantReservationRecord),
    /// Capacity changed after pure evaluation.
    CapacityExceeded {
        /// Stable aggregate budget identifier.
        budget_id: String,
        /// Capacity observed atomically.
        available_minor: u64,
    },
    /// State was unavailable.
    Unavailable,
}

/// Stripe-local durable merchant state contract.
pub trait MerchantPaymentStore: Send + Sync {
    /// Reads aggregate capacity for the exact policy/account/time.
    fn snapshot(
        &self,
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<MerchantAggregateSnapshot, MerchantStateError>;

    /// Atomically reserves all aggregate intents or none.
    fn reserve(&self, request: ReserveMerchantPaymentRequest) -> ReserveMerchantPaymentResult;

    /// Claims a new reservation for one verified command.
    fn claim(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists provider-attempt intent before credential/provider use.
    fn mark_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists a normalized provider response before accounting transition.
    fn record_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Commits automatic collection.
    fn commit_collection(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Releases capacity only after definite non-execution.
    fn release(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Retains capacity after ambiguous delivery.
    fn mark_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Applies fresh provider reconciliation without a second create request.
    fn reconcile_collection(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCollectReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Reads one durable workflow.
    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<MerchantReservationRecord>, MerchantStateError>;
}

impl<T: MerchantPaymentStore + ?Sized> MerchantPaymentStore for Arc<T> {
    fn snapshot(
        &self,
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<MerchantAggregateSnapshot, MerchantStateError> {
        (**self).snapshot(policy, account, now)
    }

    fn reserve(&self, request: ReserveMerchantPaymentRequest) -> ReserveMerchantPaymentResult {
        (**self).reserve(request)
    }

    fn claim(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).claim(lease, now)
    }

    fn mark_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_attempting(lease, now)
    }

    fn record_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).record_provider_accepted(lease, provider, now)
    }

    fn commit_collection(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).commit_collection(lease, now)
    }

    fn release(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).release(lease, now)
    }

    fn mark_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_outcome_unknown(lease, provider, now)
    }

    fn reconcile_collection(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCollectReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).reconcile_collection(workflow_id, action_digest, outcome, now)
    }

    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<MerchantReservationRecord>, MerchantStateError> {
        (**self).get(workflow_id)
    }
}

/// In-process merchant state used by unit tests and embedded operation.
#[derive(Default)]
pub struct InMemoryMerchantPaymentStore {
    records: Mutex<BTreeMap<String, MerchantReservationRecord>>,
}

impl InMemoryMerchantPaymentStore {
    fn with_records<T>(
        &self,
        operation: impl FnOnce(
            &mut BTreeMap<String, MerchantReservationRecord>,
        ) -> Result<T, MerchantStateError>,
    ) -> Result<T, MerchantStateError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| MerchantStateError::Unavailable)?;
        operation(&mut records)
    }
}

impl MerchantPaymentStore for InMemoryMerchantPaymentStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<MerchantAggregateSnapshot, MerchantStateError> {
        let records = self
            .records
            .lock()
            .map_err(|_| MerchantStateError::Unavailable)?;
        snapshot_in(&records, policy, account, now)
    }

    fn reserve(&self, request: ReserveMerchantPaymentRequest) -> ReserveMerchantPaymentResult {
        let Ok(mut records) = self.records.lock() else {
            return ReserveMerchantPaymentResult::Unavailable;
        };
        reserve_in(&mut records, request)
    }

    fn claim(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(records, lease, PaymentCollectTransition::Claim, None, now)
        })
    }

    fn mark_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_collection(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::CollectionCommitted,
                None,
                now,
            )
        })
    }

    fn release(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
    }

    fn reconcile_collection(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCollectReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            reconcile_collection_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<MerchantReservationRecord>, MerchantStateError> {
        self.records
            .lock()
            .map(|records| records.get(workflow_id).cloned())
            .map_err(|_| MerchantStateError::Unavailable)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MerchantStateFile {
    schema: String,
    records: BTreeMap<String, MerchantReservationRecord>,
}

/// Crash-persistent and cross-process locked merchant-payment store.
pub struct PersistentMerchantPaymentStore {
    path: PathBuf,
    lock_path: PathBuf,
    process_lock: Mutex<()>,
}

impl PersistentMerchantPaymentStore {
    /// Opens and validates one canonical state file.
    ///
    /// # Errors
    ///
    /// Rejects malformed, noncanonical, oversized, or inconsistent state.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, MerchantStateError> {
        let path = path.into();
        let parent = path.parent().ok_or(MerchantStateError::Unavailable)?;
        fs::create_dir_all(parent).map_err(|_| MerchantStateError::Unavailable)?;
        let store = Self {
            lock_path: path.with_extension("lock"),
            path,
            process_lock: Mutex::new(()),
        };
        store.with_locked_records(|_| Ok(()))?;
        Ok(store)
    }

    fn with_locked_records<T>(
        &self,
        operation: impl FnOnce(
            &mut BTreeMap<String, MerchantReservationRecord>,
        ) -> Result<T, MerchantStateError>,
    ) -> Result<T, MerchantStateError> {
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| MerchantStateError::Unavailable)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .map_err(|_| MerchantStateError::Unavailable)?;
        lock.lock().map_err(|_| MerchantStateError::Unavailable)?;
        let mut records = load_records(&self.path)?;
        let output = operation(&mut records)?;
        persist_records(&self.path, &records)?;
        lock.unlock().map_err(|_| MerchantStateError::Unavailable)?;
        Ok(output)
    }
}

impl MerchantPaymentStore for PersistentMerchantPaymentStore {
    fn snapshot(
        &self,
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<MerchantAggregateSnapshot, MerchantStateError> {
        self.with_locked_records(|records| snapshot_in(records, policy, account, now))
    }

    fn reserve(&self, request: ReserveMerchantPaymentRequest) -> ReserveMerchantPaymentResult {
        self.with_locked_records(|records| Ok(reserve_in(records, request)))
            .unwrap_or(ReserveMerchantPaymentResult::Unavailable)
    }

    fn claim(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(records, lease, PaymentCollectTransition::Claim, None, now)
        })
    }

    fn mark_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_collection(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::CollectionCommitted,
                None,
                now,
            )
        })
    }

    fn release(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_in(
                records,
                lease,
                PaymentCollectTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
    }

    fn reconcile_collection(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCollectReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            reconcile_collection_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<MerchantReservationRecord>, MerchantStateError> {
        self.with_locked_records(|records| Ok(records.get(workflow_id).cloned()))
    }
}

fn reserve_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    request: ReserveMerchantPaymentRequest,
) -> ReserveMerchantPaymentResult {
    if let Some(existing) = records.get(&request.workflow_id) {
        if existing.action_digest == request.action_digest
            && existing.policy_digest == request.policy_digest
            && existing.operation == request.operation
        {
            return ReserveMerchantPaymentResult::Replay(existing.clone());
        }
        return ReserveMerchantPaymentResult::Conflict(existing.clone());
    }
    if request.operation != MerchantOperation::Collect
        || request.exact_action_profile != crate::merchant::PAYMENT_COLLECT_PROFILE
        || request.intents.is_empty()
        || request.amount_minor == 0
        || request.intents.iter().any(|intent| {
            intent.operation != request.operation
                || intent.currency != request.currency
                || intent.amount_minor != request.amount_minor
        })
    {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    for intent in &request.intents {
        let mut used = 0_u64;
        for record in records.values().filter(|record| {
            record.stripe_account_id == request.stripe_account_id
                && record.operation == intent.operation
                && record.intents.iter().any(|candidate| {
                    candidate.budget_id == intent.budget_id
                        && candidate.operation == intent.operation
                        && candidate.window == intent.window
                        && candidate.currency == intent.currency
                })
                && (record.state.holds_reserved()
                    || record.state.holds_committed()
                    || record.state.holds_unknown())
        }) {
            let Some(next) = used.checked_add(record.amount_minor) else {
                return ReserveMerchantPaymentResult::Unavailable;
            };
            used = next;
        }
        let Some(available) = intent.limit_minor.checked_sub(used) else {
            return ReserveMerchantPaymentResult::Unavailable;
        };
        if request.amount_minor > available {
            return ReserveMerchantPaymentResult::CapacityExceeded {
                budget_id: intent.budget_id.clone(),
                available_minor: available,
            };
        }
    }
    if records.len() >= MAX_RECORDS {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    let Ok(reservation_id) = request.reservation_id() else {
        return ReserveMerchantPaymentResult::Unavailable;
    };
    let workflow_id = request.workflow_id.clone();
    let action_digest = request.action_digest.clone();
    let record = request.into_record(reservation_id.clone());
    records.insert(workflow_id.clone(), record.clone());
    ReserveMerchantPaymentResult::Reserved {
        lease: MerchantReservationLease {
            workflow_id,
            reservation_id,
            action_digest,
        },
        record,
    }
}

fn snapshot_in(
    records: &BTreeMap<String, MerchantReservationRecord>,
    policy: &StripeBoundedMerchantPaymentPolicyV1,
    account: &StripeAccountId,
    now: u64,
) -> Result<MerchantAggregateSnapshot, MerchantStateError> {
    let mut usages = Vec::new();
    for budget in policy.aggregate_budgets() {
        let window = budget
            .window()
            .identity(now)
            .map_err(|_| MerchantStateError::InvalidTransition)?;
        let mut usage = MerchantAggregateUsage {
            budget_id: budget.budget_id().into(),
            operation: budget.operation(),
            currency: budget.currency().clone(),
            window: window.clone(),
            committed_minor: 0,
            reserved_minor: 0,
            outcome_unknown_minor: 0,
            active_authorization_minor: 0,
        };
        for record in records.values().filter(|record| {
            record.stripe_account_id == *account
                && record.operation == budget.operation()
                && record.intents.iter().any(|intent| {
                    intent.budget_id == budget.budget_id()
                        && intent.operation == budget.operation()
                        && intent.currency == *budget.currency()
                        && intent.window == window
                })
        }) {
            let target = if record.state.holds_reserved() {
                &mut usage.reserved_minor
            } else if record.state.holds_committed() {
                &mut usage.committed_minor
            } else if record.state.holds_unknown() {
                &mut usage.outcome_unknown_minor
            } else {
                continue;
            };
            *target = target
                .checked_add(record.amount_minor)
                .ok_or(MerchantStateError::Arithmetic)?;
        }
        usages.push(usage);
    }
    Ok(MerchantAggregateSnapshot { usages })
}

fn transition_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    event: PaymentCollectTransition,
    provider: Option<MerchantProviderProjection>,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if record.reservation_id != lease.reservation_id || record.action_digest != lease.action_digest
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    if record.operation != MerchantOperation::Collect {
        return Err(MerchantStateError::InvalidTransition);
    }
    let next = transition_payment_collect(record.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if let Some(provider) = provider {
        validate_provider(record, &provider)?;
        record.provider = Some(provider);
    }
    if matches!(
        event,
        PaymentCollectTransition::ProviderAccepted | PaymentCollectTransition::CollectionCommitted
    ) && record.provider.is_none()
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    record.state = next;
    record.updated_at = now;
    Ok(record.clone())
}

fn reconcile_collection_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    outcome: PaymentCollectReconciliationOutcome,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if &record.action_digest != action_digest {
        return Err(MerchantStateError::InvalidTransition);
    }
    if record.operation != MerchantOperation::Collect {
        return Err(MerchantStateError::InvalidTransition);
    }
    let (event, provider) = match outcome {
        PaymentCollectReconciliationOutcome::Committed(provider) => {
            validate_provider(record, &provider)?;
            (PaymentCollectTransition::ReconcileCommitted, Some(provider))
        }
        PaymentCollectReconciliationOutcome::Released(provider) => {
            if let Some(provider) = &provider {
                validate_provider(record, provider)?;
            }
            (PaymentCollectTransition::ReconcileReleased, provider)
        }
        PaymentCollectReconciliationOutcome::OutcomeUnknown(provider) => {
            if let Some(provider) = &provider {
                validate_provider(record, provider)?;
            }
            (PaymentCollectTransition::ReconcileStillUnknown, provider)
        }
    };
    record.state = transition_payment_collect(record.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if provider.is_some() {
        record.provider = provider;
    }
    record.updated_at = now;
    Ok(record.clone())
}

fn validate_provider(
    record: &MerchantReservationRecord,
    provider: &MerchantProviderProjection,
) -> Result<(), MerchantStateError> {
    if provider.amount_minor != record.amount_minor
        || provider.currency != record.currency
        || provider.status.is_empty()
        || provider.status.len() > 64
        || !matches!(
            provider.source.as_str(),
            "create-response" | "retrieve" | "webhook"
        )
        || provider
            .stripe_request_id
            .as_ref()
            .is_some_and(|value| !valid_request_id(value))
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
}

fn valid_request_id(value: &str) -> bool {
    (4..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn load_records(
    path: &Path,
) -> Result<BTreeMap<String, MerchantReservationRecord>, MerchantStateError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let bytes = fs::read(path).map_err(|_| MerchantStateError::Unavailable)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(MerchantStateError::Corrupt);
    }
    let state: MerchantStateFile =
        serde_json::from_slice(&bytes).map_err(|_| MerchantStateError::Corrupt)?;
    if state.schema != STATE_SCHEMA
        || state.records.len() > MAX_RECORDS
        || canonical_json(&state).map_err(|_| MerchantStateError::Corrupt)? != bytes
        || state
            .records
            .iter()
            .any(|(workflow, record)| workflow != &record.workflow_id || !valid_record(record))
    {
        return Err(MerchantStateError::Corrupt);
    }
    Ok(state.records)
}

fn valid_record(record: &MerchantReservationRecord) -> bool {
    let identity = MerchantReservationIdentity {
        schema: RESERVATION_SCHEMA,
        workflow_id: &record.workflow_id,
        operation: record.operation,
        exact_action_profile: &record.exact_action_profile,
        action_digest: &record.action_digest,
        policy_digest: &record.policy_digest,
        stripe_account_id: &record.stripe_account_id,
        connect_account: &record.connect_account,
        intents: &record.intents,
    };
    let identity_matches =
        canonical_json(&identity).is_ok_and(|bytes| sha256(&bytes) == record.reservation_id);
    let provider_shape = match record.state {
        MerchantReservationState::ProviderAccepted
        | MerchantReservationState::Committed
        | MerchantReservationState::ReconciledCommitted => record.provider.is_some(),
        MerchantReservationState::Reserved
        | MerchantReservationState::Claimed
        | MerchantReservationState::Attempting
        | MerchantReservationState::Released => record.provider.is_none(),
        MerchantReservationState::OutcomeUnknown | MerchantReservationState::ReconciledReleased => {
            true
        }
    };
    record.schema == RESERVATION_SCHEMA
        && identity_matches
        && record.operation == MerchantOperation::Collect
        && record.exact_action_profile == crate::merchant::PAYMENT_COLLECT_PROFILE
        && provider_shape
        && (8..=96).contains(&record.workflow_id.len())
        && record.amount_minor > 0
        && !record.intents.is_empty()
        && record.intents.iter().all(|intent| {
            intent.operation == record.operation
                && intent.currency == record.currency
                && intent.amount_minor == record.amount_minor
        })
}

fn persist_records(
    path: &Path,
    records: &BTreeMap<String, MerchantReservationRecord>,
) -> Result<(), MerchantStateError> {
    if records.len() > MAX_RECORDS {
        return Err(MerchantStateError::Unavailable);
    }
    let bytes = canonical_json(&MerchantStateFile {
        schema: STATE_SCHEMA.into(),
        records: records.clone(),
    })
    .map_err(|_| MerchantStateError::Corrupt)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(MerchantStateError::Unavailable);
    }
    let parent = path.parent().ok_or(MerchantStateError::Unavailable)?;
    let mut temporary =
        NamedTempFile::new_in(parent).map_err(|_| MerchantStateError::Unavailable)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| MerchantStateError::Unavailable)?;
    temporary
        .persist(path)
        .map_err(|_| MerchantStateError::Unavailable)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| MerchantStateError::Unavailable)
}

/// Closed merchant-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MerchantStateError {
    /// Durable state is unavailable.
    #[error("Stripe merchant-payment state is unavailable")]
    Unavailable,
    /// Durable state is malformed or noncanonical.
    #[error("Stripe merchant-payment state is corrupt")]
    Corrupt,
    /// Workflow does not exist.
    #[error("Stripe merchant-payment workflow was not found")]
    NotFound,
    /// State transition conflicts with durable history.
    #[error("invalid Stripe merchant-payment state transition")]
    InvalidTransition,
    /// Checked aggregate arithmetic failed.
    #[error("Stripe merchant-payment aggregate arithmetic overflow")]
    Arithmetic,
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{Arc, Barrier},
        thread,
    };

    use super::*;
    use crate::{
        canonical::sha256,
        merchant::{MERCHANT_EVALUATOR_ID, MERCHANT_EVALUATOR_VERSION},
        test_support::{NOW, merchant_policy},
        types::CustomerId,
    };

    fn request(
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        operation: MerchantOperation,
        workflow: &str,
        amount_minor: u64,
    ) -> ReserveMerchantPaymentRequest {
        let budget = policy
            .aggregate_budgets()
            .iter()
            .find(|budget| budget.operation() == operation)
            .unwrap();
        let currency = Currency::parse("usd").unwrap();
        ReserveMerchantPaymentRequest {
            workflow_id: workflow.into(),
            operation,
            exact_action_profile: match operation {
                MerchantOperation::Collect => crate::merchant::PAYMENT_COLLECT_PROFILE,
                MerchantOperation::Authorize => crate::merchant::PAYMENT_AUTHORIZE_PROFILE,
                MerchantOperation::Capture | MerchantOperation::Cancel => {
                    "unsupported-test-profile"
                }
            }
            .into(),
            action_digest: sha256(format!("action-{workflow}").as_bytes()),
            decision_receipt_digest: sha256(format!("decision-{workflow}").as_bytes()),
            policy_digest: policy.digest().unwrap(),
            evaluator_semantic_id: MERCHANT_EVALUATOR_ID.into(),
            evaluator_semantic_version: MERCHANT_EVALUATOR_VERSION,
            evidence_digest: sha256(format!("evidence-{workflow}").as_bytes()),
            required_configuration_digest: sha256(b"configuration"),
            executed_configuration_digest: sha256(b"configuration"),
            stripe_account_id: StripeAccountId::parse("acct_authsdemo01").unwrap(),
            connect_account: MerchantConnectAccount::Platform,
            customer_id: CustomerId::parse("cus_authsdemo00000001").unwrap(),
            order_scope: format!("order-{workflow}"),
            currency: currency.clone(),
            amount_minor,
            intents: vec![MerchantReservationIntent {
                budget_id: budget.budget_id().into(),
                operation,
                currency,
                window: budget.window().identity(NOW).unwrap(),
                limit_minor: budget.limit_minor(),
                amount_minor,
                available_before_minor: budget.limit_minor(),
            }],
            idempotency_key_digest: sha256(format!("idempotency-{workflow}").as_bytes()),
            now: NOW,
        }
    }

    #[test]
    fn concurrent_last_unit_is_reserved_once() {
        let policy = Arc::new(merchant_policy(MerchantOperation::Collect, 1_000, 1_000));
        let store = Arc::new(InMemoryMerchantPaymentStore::default());
        let barrier = Arc::new(Barrier::new(3));
        let mut handles = Vec::new();
        for suffix in ["0001", "0002"] {
            let policy = Arc::clone(&policy);
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.reserve(request(
                    &policy,
                    MerchantOperation::Collect,
                    &format!("merchant-concurrent-{suffix}"),
                    1_000,
                ))
            }));
        }
        barrier.wait();
        let outcomes: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, ReserveMerchantPaymentResult::Reserved { .. }))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        ReserveMerchantPaymentResult::CapacityExceeded {
                            available_minor: 0,
                            ..
                        }
                    )
                })
                .count(),
            1
        );
    }

    #[test]
    fn replay_survives_restart_and_never_returns_a_second_lease() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("merchant-state.json");
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 2_000);
        let action_digest = sha256(b"action-merchant-restart-0001");
        {
            let store = PersistentMerchantPaymentStore::open(&path).unwrap();
            let result = store.reserve(request(
                &policy,
                MerchantOperation::Collect,
                "merchant-restart-0001",
                1_000,
            ));
            assert!(matches!(
                result,
                ReserveMerchantPaymentResult::Reserved { .. }
            ));
        }
        let store = PersistentMerchantPaymentStore::open(&path).unwrap();
        let replay = store.reserve(request(
            &policy,
            MerchantOperation::Collect,
            "merchant-restart-0001",
            1_000,
        ));
        let ReserveMerchantPaymentResult::Replay(record) = replay else {
            panic!("restart must return replay");
        };
        assert_eq!(record.action_digest(), &action_digest);
        assert_eq!(record.state(), MerchantReservationState::Reserved);
    }

    #[test]
    fn collect_store_rejects_an_authorization_lifecycle_record() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_000);
        assert!(matches!(
            InMemoryMerchantPaymentStore::default().reserve(request(
                &policy,
                MerchantOperation::Authorize,
                "merchant-authorize-state-0001",
                1_000,
            )),
            ReserveMerchantPaymentResult::Unavailable
        ));
    }

    #[test]
    fn unknown_capacity_is_held_until_fresh_reconciliation_releases_it() {
        let policy = merchant_policy(MerchantOperation::Collect, 1_000, 1_000);
        let store = InMemoryMerchantPaymentStore::default();
        let ReserveMerchantPaymentResult::Reserved { lease, .. } = store.reserve(request(
            &policy,
            MerchantOperation::Collect,
            "merchant-unknown-0001",
            1_000,
        )) else {
            panic!("reservation expected");
        };
        store.claim(&lease, NOW).unwrap();
        store.mark_attempting(&lease, NOW).unwrap();
        let unknown = store.mark_outcome_unknown(&lease, None, NOW).unwrap();
        assert_eq!(unknown.state(), MerchantReservationState::OutcomeUnknown);
        let snapshot = store
            .snapshot(
                &policy,
                &StripeAccountId::parse("acct_authsdemo01").unwrap(),
                NOW,
            )
            .unwrap();
        assert_eq!(snapshot.usages[0].outcome_unknown_minor, 1_000);
        let reconciled = store
            .reconcile_collection(
                "merchant-unknown-0001",
                unknown.action_digest(),
                PaymentCollectReconciliationOutcome::Released(None),
                NOW + 1,
            )
            .unwrap();
        assert_eq!(
            reconciled.state(),
            MerchantReservationState::ReconciledReleased
        );
        let snapshot = store
            .snapshot(
                &policy,
                &StripeAccountId::parse("acct_authsdemo01").unwrap(),
                NOW,
            )
            .unwrap();
        assert_eq!(snapshot.usages[0].outcome_unknown_minor, 0);
    }
}
