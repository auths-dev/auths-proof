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
        authorize::{
            PaymentAuthorizeReconciliationOutcome, PaymentAuthorizeTransition,
            transition_payment_authorize,
        },
        cancel::{
            PaymentCancelProviderProjection, PaymentCancelReconciliationOutcome,
            PaymentCancelTransition, PaymentCancellationReason, transition_payment_cancel,
        },
        capture::{
            PaymentCaptureProviderProjection, PaymentCaptureReconciliationOutcome,
            PaymentCaptureTransition, transition_payment_capture,
        },
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
    /// Manual-capture authorization is durably held and remains an obligation.
    Authorized,
    /// Definite non-execution returned capacity.
    Released,
    /// Delivery may have reached Stripe; capacity stays held.
    OutcomeUnknown,
    /// Retrieval proved automatic collection.
    ReconciledCommitted,
    /// Retrieval proved the manual-capture authorization remains held.
    ReconciledAuthorized,
    /// Final capture is committed to the settlement budget.
    CaptureCommitted,
    /// Retrieval proved final capture and committed settlement.
    ReconciledCaptureCommitted,
    /// Terminal cancellation was observed.
    CancelCommitted,
    /// Retrieval proved terminal cancellation.
    ReconciledCancelCommitted,
    /// A capture won the cancellation race; no hold was released by cancellation.
    CancelCaptureConflict,
    /// An atomic final capture released this authorization hold.
    AuthorizationReleasedByCapture,
    /// An observed terminal cancellation released this authorization hold.
    AuthorizationReleasedByCancel,
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
        matches!(
            self,
            Self::Committed
                | Self::ReconciledCommitted
                | Self::CaptureCommitted
                | Self::ReconciledCaptureCommitted
        )
    }

    fn holds_active_authorization(self) -> bool {
        matches!(self, Self::Authorized | Self::ReconciledAuthorized)
    }

    fn holds_unknown(self) -> bool {
        self == Self::OutcomeUnknown
    }
}

/// Public provider projection retained without credentials or client secrets.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantProviderProjection {
    /// `PaymentIntent` created by Stripe.
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_provider: Option<PaymentCaptureProviderProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancel_provider: Option<PaymentCancelProviderProjection>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_workflow_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_action_digest: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_reservation_id: Option<DigestHex>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    authorization_release_minor: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_payment_intent_id: Option<PaymentIntentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    capture_charge_id: Option<ChargeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancel_payment_intent_id: Option<PaymentIntentId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancellation_reason: Option<PaymentCancellationReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancel_pre_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cancel_amount_minor: Option<u64>,
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

    /// Capture-owned provider projection, if known.
    #[must_use]
    pub const fn capture_provider(&self) -> Option<&PaymentCaptureProviderProjection> {
        self.capture_provider.as_ref()
    }

    /// Cancellation-owned provider projection, if known.
    #[must_use]
    pub const fn cancel_provider(&self) -> Option<&PaymentCancelProviderProjection> {
        self.cancel_provider.as_ref()
    }

    /// Linked authorization workflow for final capture.
    #[must_use]
    pub fn authorization_workflow_id(&self) -> Option<&str> {
        self.authorization_workflow_id.as_deref()
    }

    /// Linked authorization action commitment for final capture.
    #[must_use]
    pub const fn authorization_action_digest(&self) -> Option<&DigestHex> {
        self.authorization_action_digest.as_ref()
    }

    /// Linked authorization reservation for final capture.
    #[must_use]
    pub const fn authorization_reservation_id(&self) -> Option<&DigestHex> {
        self.authorization_reservation_id.as_ref()
    }

    /// Hold amount released atomically when capture commits.
    #[must_use]
    pub const fn authorization_release_minor(&self) -> Option<u64> {
        self.authorization_release_minor
    }

    /// Exact `PaymentIntent` targeted by final capture.
    #[must_use]
    pub const fn capture_payment_intent_id(&self) -> Option<&PaymentIntentId> {
        self.capture_payment_intent_id.as_ref()
    }

    /// Exact Charge linked before final capture.
    #[must_use]
    pub const fn capture_charge_id(&self) -> Option<&ChargeId> {
        self.capture_charge_id.as_ref()
    }

    /// Exact `PaymentIntent` targeted by cancellation.
    #[must_use]
    pub const fn cancel_payment_intent_id(&self) -> Option<&PaymentIntentId> {
        self.cancel_payment_intent_id.as_ref()
    }

    /// Exact cancellation reason.
    #[must_use]
    pub const fn cancellation_reason(&self) -> Option<PaymentCancellationReason> {
        self.cancellation_reason
    }

    /// Provider state immediately before the cancellation claim.
    #[must_use]
    pub fn cancel_pre_status(&self) -> Option<&str> {
        self.cancel_pre_status.as_deref()
    }

    /// Original amount of the cancellation target.
    #[must_use]
    pub const fn cancel_amount_minor(&self) -> Option<u64> {
        self.cancel_amount_minor
    }

    /// Durable creation time.
    #[must_use]
    pub const fn created_at(&self) -> u64 {
        self.created_at
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
            capture_provider: None,
            cancel_provider: None,
            authorization_workflow_id: None,
            authorization_action_digest: None,
            authorization_reservation_id: None,
            authorization_release_minor: None,
            capture_payment_intent_id: None,
            capture_charge_id: None,
            cancel_payment_intent_id: None,
            cancellation_reason: None,
            cancel_pre_status: None,
            cancel_amount_minor: None,
            created_at: self.now,
            updated_at: self.now,
        }
    }
}

/// Complete inputs to an exact capture settlement reservation.
///
/// The constructor fixes operation and profile internally, so callers cannot
/// select a generic operation tag or another profile.
pub struct ReservePaymentCaptureRequest {
    base: ReserveMerchantPaymentRequest,
    authorization_workflow_id: String,
    authorization_action_digest: DigestHex,
    authorization_reservation_id: DigestHex,
    authorization_release_minor: u64,
    capture_payment_intent_id: PaymentIntentId,
    capture_charge_id: ChargeId,
}

/// Complete inputs to one exact cancellation exclusivity claim.
///
/// The constructor fixes operation and profile internally. It carries no
/// monetary reservation intent; an optional linked hold is released only by
/// the cancellation-specific observed terminal transition.
pub struct ReservePaymentCancelRequest {
    base: ReserveMerchantPaymentRequest,
    authorization_workflow_id: Option<String>,
    authorization_action_digest: Option<DigestHex>,
    authorization_reservation_id: Option<DigestHex>,
    authorization_release_minor: Option<u64>,
    cancel_payment_intent_id: PaymentIntentId,
    cancellation_reason: PaymentCancellationReason,
    cancel_pre_status: String,
    cancel_amount_minor: u64,
}

impl ReservePaymentCancelRequest {
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "cancellation claim binds every exact decision, target, and optional hold fact"
    )]
    pub fn new(
        workflow_id: String,
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
        idempotency_key_digest: DigestHex,
        authorization_workflow_id: Option<String>,
        authorization_action_digest: Option<DigestHex>,
        authorization_reservation_id: Option<DigestHex>,
        authorization_release_minor: Option<u64>,
        cancel_payment_intent_id: PaymentIntentId,
        cancellation_reason: PaymentCancellationReason,
        cancel_pre_status: String,
        cancel_amount_minor: u64,
        now: u64,
    ) -> Self {
        Self {
            base: ReserveMerchantPaymentRequest {
                workflow_id,
                operation: MerchantOperation::Cancel,
                exact_action_profile: crate::merchant::PAYMENT_CANCEL_PROFILE.into(),
                action_digest,
                decision_receipt_digest,
                policy_digest,
                evaluator_semantic_id,
                evaluator_semantic_version,
                evidence_digest,
                required_configuration_digest,
                executed_configuration_digest,
                stripe_account_id,
                connect_account,
                customer_id,
                order_scope,
                currency,
                amount_minor: 0,
                intents: Vec::new(),
                idempotency_key_digest,
                now,
            },
            authorization_workflow_id,
            authorization_action_digest,
            authorization_reservation_id,
            authorization_release_minor,
            cancel_payment_intent_id,
            cancellation_reason,
            cancel_pre_status,
            cancel_amount_minor,
        }
    }
}

impl ReservePaymentCaptureRequest {
    /// Binds settlement capacity to one exact durable authorization.
    #[must_use]
    #[allow(
        clippy::too_many_arguments,
        reason = "capture reservation binds every durable decision and authorization fact"
    )]
    pub fn new(
        workflow_id: String,
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
        idempotency_key_digest: DigestHex,
        authorization_workflow_id: String,
        authorization_action_digest: DigestHex,
        authorization_reservation_id: DigestHex,
        authorization_release_minor: u64,
        capture_payment_intent_id: PaymentIntentId,
        capture_charge_id: ChargeId,
        now: u64,
    ) -> Self {
        Self {
            base: ReserveMerchantPaymentRequest {
                workflow_id,
                operation: MerchantOperation::Capture,
                exact_action_profile: crate::merchant::PAYMENT_CAPTURE_PROFILE.into(),
                action_digest,
                decision_receipt_digest,
                policy_digest,
                evaluator_semantic_id,
                evaluator_semantic_version,
                evidence_digest,
                required_configuration_digest,
                executed_configuration_digest,
                stripe_account_id,
                connect_account,
                customer_id,
                order_scope,
                currency,
                amount_minor,
                intents,
                idempotency_key_digest,
                now,
            },
            authorization_workflow_id,
            authorization_action_digest,
            authorization_reservation_id,
            authorization_release_minor,
            capture_payment_intent_id,
            capture_charge_id,
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
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or corrupt.
    fn snapshot(
        &self,
        policy: &StripeBoundedMerchantPaymentPolicyV1,
        account: &StripeAccountId,
        now: u64,
    ) -> Result<MerchantAggregateSnapshot, MerchantStateError>;

    /// Atomically reserves all aggregate intents or none.
    fn reserve(&self, request: ReserveMerchantPaymentRequest) -> ReserveMerchantPaymentResult;

    /// Atomically reserves exact capture settlement capacity linked to one hold.
    fn reserve_capture(
        &self,
        request: ReservePaymentCaptureRequest,
    ) -> ReserveMerchantPaymentResult;

    /// Claims a new exact final-capture reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn claim_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists final-capture provider-attempt intent.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_capture_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists a normalized final-capture response.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the projection is invalid.
    fn record_capture_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Atomically commits settlement and releases the linked authorization hold.
    ///
    /// # Errors
    ///
    /// Returns an error without changing either record when any link or state differs.
    fn commit_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Releases only capture settlement capacity after definite non-execution.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn release_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Retains both capture settlement capacity and the authorization hold.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_capture_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCaptureProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Atomically claims one exact cancellation target.
    fn reserve_cancel(&self, request: ReservePaymentCancelRequest) -> ReserveMerchantPaymentResult;

    /// Claims the cancellation workflow.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn claim_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists cancellation delivery intent.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_cancel_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists a normalized cancellation response before observation.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn record_cancel_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Commits observed cancellation and atomically releases an optional hold.
    ///
    /// # Errors
    ///
    /// Returns an error without partial state change when the terminal observation is invalid.
    fn commit_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Releases only the cancellation exclusivity claim after definite non-delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn release_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Retains the cancellation claim and optional hold after ambiguous delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_cancel_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCancelProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Records that capture won the cancellation race without releasing the hold.
    ///
    /// # Errors
    ///
    /// Returns an error without partial state change when the provider conflict is invalid.
    fn record_cancel_capture_conflict(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Claims a new reservation for one verified command.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn claim(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists provider-attempt intent before credential/provider use.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists a normalized provider response before accounting transition.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn record_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Commits automatic collection.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn commit_collection(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Claims a new manual-capture authorization reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn claim_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists manual-authorization provider-attempt intent.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_authorization_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Persists a normalized manual-authorization response.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the projection is invalid.
    fn record_authorization_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Commits an observed `requires_capture` authorization hold.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the hold is not exact.
    fn commit_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Releases authorization capacity only after definite non-execution.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn release_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Retains authorization capacity after ambiguous delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the projection is invalid.
    fn mark_authorization_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Releases capacity only after definite non-execution.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn release(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Retains capacity after ambiguous delivery.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or the transition is invalid.
    fn mark_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Applies fresh provider reconciliation without a second create request.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or reconciliation is invalid.
    fn reconcile_collection(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCollectReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Applies fresh manual-authorization reconciliation without another create.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or reconciliation is invalid.
    fn reconcile_authorization(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentAuthorizeReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Reconciles final capture without issuing another capture request.
    ///
    /// # Errors
    ///
    /// Returns an error without partial state change when reconciliation is invalid.
    fn reconcile_capture(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCaptureReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Reconciles cancellation by retrieval and never repeats cancellation.
    ///
    /// # Errors
    ///
    /// Returns an error without partial state change when reconciliation is invalid.
    fn reconcile_cancel(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCancelReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError>;

    /// Reads one durable workflow.
    ///
    /// # Errors
    ///
    /// Returns an error when durable state is unavailable or corrupt.
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

    fn reserve_capture(
        &self,
        request: ReservePaymentCaptureRequest,
    ) -> ReserveMerchantPaymentResult {
        (**self).reserve_capture(request)
    }

    fn claim_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).claim_capture(lease, now)
    }

    fn mark_capture_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_capture_attempting(lease, now)
    }

    fn record_capture_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).record_capture_provider_accepted(lease, provider, now)
    }

    fn commit_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).commit_capture(lease, now)
    }

    fn release_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).release_capture(lease, now)
    }

    fn mark_capture_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCaptureProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_capture_outcome_unknown(lease, provider, now)
    }

    fn reserve_cancel(&self, request: ReservePaymentCancelRequest) -> ReserveMerchantPaymentResult {
        (**self).reserve_cancel(request)
    }

    fn claim_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).claim_cancel(lease, now)
    }

    fn mark_cancel_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_cancel_attempting(lease, now)
    }

    fn record_cancel_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).record_cancel_provider_accepted(lease, provider, now)
    }

    fn commit_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).commit_cancel(lease, now)
    }

    fn release_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).release_cancel(lease, now)
    }

    fn mark_cancel_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCancelProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_cancel_outcome_unknown(lease, provider, now)
    }

    fn record_cancel_capture_conflict(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).record_cancel_capture_conflict(lease, provider, now)
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

    fn claim_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).claim_authorization(lease, now)
    }

    fn mark_authorization_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_authorization_attempting(lease, now)
    }

    fn record_authorization_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).record_authorization_provider_accepted(lease, provider, now)
    }

    fn commit_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).commit_authorization(lease, now)
    }

    fn release_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).release_authorization(lease, now)
    }

    fn mark_authorization_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).mark_authorization_outcome_unknown(lease, provider, now)
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

    fn reconcile_authorization(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentAuthorizeReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).reconcile_authorization(workflow_id, action_digest, outcome, now)
    }

    fn reconcile_capture(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCaptureReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).reconcile_capture(workflow_id, action_digest, outcome, now)
    }

    fn reconcile_cancel(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCancelReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        (**self).reconcile_cancel(workflow_id, action_digest, outcome, now)
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

    fn reserve_capture(
        &self,
        request: ReservePaymentCaptureRequest,
    ) -> ReserveMerchantPaymentResult {
        let Ok(mut records) = self.records.lock() else {
            return ReserveMerchantPaymentResult::Unavailable;
        };
        reserve_capture_in(&mut records, request)
    }

    fn claim_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_capture_in(records, lease, PaymentCaptureTransition::Claim, None, now)
        })
    }

    fn reserve_cancel(&self, request: ReservePaymentCancelRequest) -> ReserveMerchantPaymentResult {
        let Ok(mut records) = self.records.lock() else {
            return ReserveMerchantPaymentResult::Unavailable;
        };
        reserve_cancel_in(&mut records, request)
    }

    fn claim_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(records, lease, PaymentCancelTransition::Claim, None, now)
        })
    }

    fn mark_cancel_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_cancel_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| commit_cancel_in(records, lease, false, now))
    }

    fn release_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_cancel_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCancelProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
    }

    fn record_cancel_capture_conflict(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::CaptureConflictObserved,
                Some(provider),
                now,
            )
        })
    }

    fn mark_capture_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_capture_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| commit_capture_in(records, lease, false, now))
    }

    fn release_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_capture_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCaptureProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
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

    fn claim_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::Claim,
                None,
                now,
            )
        })
    }

    fn mark_authorization_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_authorization_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::AuthorizationHeld,
                None,
                now,
            )
        })
    }

    fn release_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_authorization_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
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

    fn reconcile_authorization(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentAuthorizeReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            reconcile_authorization_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn reconcile_capture(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCaptureReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            reconcile_capture_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn reconcile_cancel(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCancelReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_records(|records| {
            reconcile_cancel_in(records, workflow_id, action_digest, outcome, now)
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

    fn reserve_cancel(&self, request: ReservePaymentCancelRequest) -> ReserveMerchantPaymentResult {
        self.with_locked_records(|records| Ok(reserve_cancel_in(records, request)))
            .unwrap_or(ReserveMerchantPaymentResult::Unavailable)
    }

    fn reserve_capture(
        &self,
        request: ReservePaymentCaptureRequest,
    ) -> ReserveMerchantPaymentResult {
        self.with_locked_records(|records| Ok(reserve_capture_in(records, request)))
            .unwrap_or(ReserveMerchantPaymentResult::Unavailable)
    }

    fn claim_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_capture_in(records, lease, PaymentCaptureTransition::Claim, None, now)
        })
    }

    fn mark_capture_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_capture_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCaptureProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| commit_capture_in(records, lease, false, now))
    }

    fn release_capture(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_capture_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCaptureProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_capture_in(
                records,
                lease,
                PaymentCaptureTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
    }

    fn claim_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(records, lease, PaymentCancelTransition::Claim, None, now)
        })
    }

    fn mark_cancel_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_cancel_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| commit_cancel_in(records, lease, false, now))
    }

    fn release_cancel(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_cancel_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<PaymentCancelProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::OutcomeBecameUnknown,
                provider,
                now,
            )
        })
    }

    fn record_cancel_capture_conflict(
        &self,
        lease: &MerchantReservationLease,
        provider: PaymentCancelProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_cancel_in(
                records,
                lease,
                PaymentCancelTransition::CaptureConflictObserved,
                Some(provider),
                now,
            )
        })
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

    fn claim_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::Claim,
                None,
                now,
            )
        })
    }

    fn mark_authorization_attempting(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::BeginAttempt,
                None,
                now,
            )
        })
    }

    fn record_authorization_provider_accepted(
        &self,
        lease: &MerchantReservationLease,
        provider: MerchantProviderProjection,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::ProviderAccepted,
                Some(provider),
                now,
            )
        })
    }

    fn commit_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::AuthorizationHeld,
                None,
                now,
            )
        })
    }

    fn release_authorization(
        &self,
        lease: &MerchantReservationLease,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::DefiniteFailureReleased,
                None,
                now,
            )
        })
    }

    fn mark_authorization_outcome_unknown(
        &self,
        lease: &MerchantReservationLease,
        provider: Option<MerchantProviderProjection>,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            transition_authorization_in(
                records,
                lease,
                PaymentAuthorizeTransition::OutcomeBecameUnknown,
                provider,
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

    fn reconcile_authorization(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentAuthorizeReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            reconcile_authorization_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn reconcile_capture(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCaptureReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            reconcile_capture_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn reconcile_cancel(
        &self,
        workflow_id: &str,
        action_digest: &DigestHex,
        outcome: PaymentCancelReconciliationOutcome,
        now: u64,
    ) -> Result<MerchantReservationRecord, MerchantStateError> {
        self.with_locked_records(|records| {
            reconcile_cancel_in(records, workflow_id, action_digest, outcome, now)
        })
    }

    fn get(
        &self,
        workflow_id: &str,
    ) -> Result<Option<MerchantReservationRecord>, MerchantStateError> {
        self.with_locked_records(|records| Ok(records.get(workflow_id).cloned()))
    }
}

fn reserve_capture_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    request: ReservePaymentCaptureRequest,
) -> ReserveMerchantPaymentResult {
    if records.values().any(|record| {
        record.operation == MerchantOperation::Cancel
            && record.cancel_payment_intent_id.as_ref() == Some(&request.capture_payment_intent_id)
            && !matches!(
                record.state,
                MerchantReservationState::Released | MerchantReservationState::ReconciledReleased
            )
    }) {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    let authorization = match records.get(&request.authorization_workflow_id) {
        Some(record)
            if request.base.workflow_id != request.authorization_workflow_id
                && record.operation == MerchantOperation::Authorize
                && record.state.holds_active_authorization()
                && record.action_digest == request.authorization_action_digest
                && record.reservation_id == request.authorization_reservation_id
                && record.amount_minor == request.authorization_release_minor
                && record.stripe_account_id == request.base.stripe_account_id
                && record.connect_account == request.base.connect_account
                && record.customer_id == request.base.customer_id
                && record.order_scope == request.base.order_scope
                && record.currency == request.base.currency
                && record.provider.as_ref().is_some_and(|provider| {
                    provider.payment_intent_id == request.capture_payment_intent_id
                        && provider.charge_id.as_ref() == Some(&request.capture_charge_id)
                }) =>
        {
            record
        }
        _ => return ReserveMerchantPaymentResult::Unavailable,
    };
    let _ = authorization;
    let authorization_workflow_id = request.authorization_workflow_id;
    let authorization_action_digest = request.authorization_action_digest;
    let authorization_reservation_id = request.authorization_reservation_id;
    let authorization_release_minor = request.authorization_release_minor;
    let capture_payment_intent_id = request.capture_payment_intent_id;
    let capture_charge_id = request.capture_charge_id;
    let workflow_id = request.base.workflow_id.clone();
    let mut result = reserve_in(records, request.base);
    match &mut result {
        ReserveMerchantPaymentResult::Reserved {
            record: returned, ..
        } => {
            let Some(record) = records.get_mut(&workflow_id) else {
                return ReserveMerchantPaymentResult::Unavailable;
            };
            record.authorization_workflow_id = Some(authorization_workflow_id);
            record.authorization_action_digest = Some(authorization_action_digest);
            record.authorization_reservation_id = Some(authorization_reservation_id);
            record.authorization_release_minor = Some(authorization_release_minor);
            record.capture_payment_intent_id = Some(capture_payment_intent_id);
            record.capture_charge_id = Some(capture_charge_id);
            *returned = record.clone();
        }
        ReserveMerchantPaymentResult::Replay(record)
            if record.authorization_workflow_id.as_deref()
                != Some(authorization_workflow_id.as_str())
                || record.authorization_action_digest.as_ref()
                    != Some(&authorization_action_digest)
                || record.authorization_reservation_id.as_ref()
                    != Some(&authorization_reservation_id)
                || record.authorization_release_minor != Some(authorization_release_minor)
                || record.capture_payment_intent_id.as_ref()
                    != Some(&capture_payment_intent_id)
                || record.capture_charge_id.as_ref() != Some(&capture_charge_id) =>
        {
            return ReserveMerchantPaymentResult::Conflict(record.clone());
        }
        _ => {}
    }
    result
}

#[allow(
    clippy::too_many_lines,
    reason = "the atomic profile-specific claim validation remains linear and auditable"
)]
fn reserve_cancel_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    request: ReservePaymentCancelRequest,
) -> ReserveMerchantPaymentResult {
    if let Some(existing) = records.get(&request.base.workflow_id) {
        if existing.action_digest == request.base.action_digest
            && existing.policy_digest == request.base.policy_digest
            && existing.operation == MerchantOperation::Cancel
            && existing.authorization_workflow_id == request.authorization_workflow_id
            && existing.authorization_action_digest == request.authorization_action_digest
            && existing.authorization_reservation_id == request.authorization_reservation_id
            && existing.authorization_release_minor == request.authorization_release_minor
            && existing.cancel_payment_intent_id.as_ref() == Some(&request.cancel_payment_intent_id)
            && existing.cancellation_reason == Some(request.cancellation_reason)
            && existing.cancel_pre_status.as_ref() == Some(&request.cancel_pre_status)
            && existing.cancel_amount_minor == Some(request.cancel_amount_minor)
        {
            return ReserveMerchantPaymentResult::Replay(existing.clone());
        }
        return ReserveMerchantPaymentResult::Conflict(existing.clone());
    }
    let hold_fields = [
        request.authorization_workflow_id.is_some(),
        request.authorization_action_digest.is_some(),
        request.authorization_reservation_id.is_some(),
        request.authorization_release_minor.is_some(),
    ];
    let complete_hold = hold_fields.iter().all(|present| *present);
    let no_hold = hold_fields.iter().all(|present| !*present);
    let hold_shape = if request.cancel_pre_status == "requires_capture" {
        complete_hold
            && request
                .authorization_release_minor
                .is_some_and(|amount| amount > 0)
    } else {
        no_hold
    };
    if request.base.operation != MerchantOperation::Cancel
        || request.base.exact_action_profile != crate::merchant::PAYMENT_CANCEL_PROFILE
        || request.base.amount_minor != 0
        || !request.base.intents.is_empty()
        || request.cancel_amount_minor == 0
        || !matches!(
            request.cancel_pre_status.as_str(),
            "requires_payment_method"
                | "requires_capture"
                | "requires_confirmation"
                | "requires_action"
        )
        || !hold_shape
    {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    if complete_hold {
        let Some(authorization) = request
            .authorization_workflow_id
            .as_deref()
            .and_then(|workflow| records.get(workflow))
        else {
            return ReserveMerchantPaymentResult::Unavailable;
        };
        if authorization.operation != MerchantOperation::Authorize
            || !authorization.state.holds_active_authorization()
            || Some(&authorization.action_digest) != request.authorization_action_digest.as_ref()
            || Some(&authorization.reservation_id) != request.authorization_reservation_id.as_ref()
            || Some(authorization.amount_minor) != request.authorization_release_minor
            || authorization.amount_minor != request.cancel_amount_minor
            || authorization.stripe_account_id != request.base.stripe_account_id
            || authorization.connect_account != request.base.connect_account
            || authorization.customer_id != request.base.customer_id
            || authorization.order_scope != request.base.order_scope
            || authorization.currency != request.base.currency
            || authorization.provider.as_ref().is_none_or(|provider| {
                provider.payment_intent_id != request.cancel_payment_intent_id
            })
        {
            return ReserveMerchantPaymentResult::Unavailable;
        }
    }
    if records.values().any(|record| {
        let same_target = record.capture_payment_intent_id.as_ref()
            == Some(&request.cancel_payment_intent_id)
            || record.cancel_payment_intent_id.as_ref() == Some(&request.cancel_payment_intent_id);
        same_target
            && !matches!(
                record.state,
                MerchantReservationState::Released | MerchantReservationState::ReconciledReleased
            )
    }) {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    if records.len() >= MAX_RECORDS {
        return ReserveMerchantPaymentResult::Unavailable;
    }
    let Ok(reservation_id) = request.base.reservation_id() else {
        return ReserveMerchantPaymentResult::Unavailable;
    };
    let workflow_id = request.base.workflow_id.clone();
    let action_digest = request.base.action_digest.clone();
    let authorization_workflow_id = request.authorization_workflow_id;
    let authorization_action_digest = request.authorization_action_digest;
    let authorization_reservation_id = request.authorization_reservation_id;
    let authorization_release_minor = request.authorization_release_minor;
    let cancel_payment_intent_id = request.cancel_payment_intent_id;
    let cancellation_reason = request.cancellation_reason;
    let cancel_pre_status = request.cancel_pre_status;
    let cancel_amount_minor = request.cancel_amount_minor;
    let mut record = request.base.into_record(reservation_id.clone());
    record.authorization_workflow_id = authorization_workflow_id;
    record.authorization_action_digest = authorization_action_digest;
    record.authorization_reservation_id = authorization_reservation_id;
    record.authorization_release_minor = authorization_release_minor;
    record.cancel_payment_intent_id = Some(cancel_payment_intent_id);
    record.cancellation_reason = Some(cancellation_reason);
    record.cancel_pre_status = Some(cancel_pre_status);
    record.cancel_amount_minor = Some(cancel_amount_minor);
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
    let exact_profile_matches = matches!(
        (request.operation, request.exact_action_profile.as_str()),
        (
            MerchantOperation::Collect,
            crate::merchant::PAYMENT_COLLECT_PROFILE
        ) | (
            MerchantOperation::Authorize,
            crate::merchant::PAYMENT_AUTHORIZE_PROFILE
        ) | (
            MerchantOperation::Capture,
            crate::merchant::PAYMENT_CAPTURE_PROFILE
        )
    );
    if !exact_profile_matches
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
                    || record.state.holds_active_authorization()
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
            } else if record.state.holds_active_authorization() {
                &mut usage.active_authorization_minor
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

fn transition_capture_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    event: PaymentCaptureTransition,
    provider: Option<PaymentCaptureProviderProjection>,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let current = records
        .get(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if current.reservation_id != lease.reservation_id
        || current.action_digest != lease.action_digest
        || current.operation != MerchantOperation::Capture
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    let next = transition_payment_capture(current.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if let Some(projection) = &provider {
        validate_capture_projection(records, current, projection)?;
    }
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if let Some(provider) = provider {
        record.capture_provider = Some(provider);
    }
    if event == PaymentCaptureTransition::ProviderAccepted && record.capture_provider.is_none() {
        return Err(MerchantStateError::InvalidTransition);
    }
    record.state = next;
    record.updated_at = now;
    Ok(record.clone())
}

fn commit_capture_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    reconciled: bool,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let capture = records
        .get(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?
        .clone();
    if capture.reservation_id != lease.reservation_id
        || capture.action_digest != lease.action_digest
        || capture.operation != MerchantOperation::Capture
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    let event = if reconciled {
        PaymentCaptureTransition::ReconcileCommitted
    } else {
        PaymentCaptureTransition::CaptureCommitted
    };
    let next = transition_payment_capture(capture.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    let provider = capture
        .capture_provider
        .as_ref()
        .ok_or(MerchantStateError::InvalidTransition)?;
    validate_committed_capture_projection(records, &capture, provider)?;
    let authorization_workflow = capture
        .authorization_workflow_id
        .as_deref()
        .ok_or(MerchantStateError::InvalidTransition)?;
    let authorization = records
        .get(authorization_workflow)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if authorization.operation != MerchantOperation::Authorize
        || !authorization.state.holds_active_authorization()
        || Some(&authorization.action_digest) != capture.authorization_action_digest.as_ref()
        || Some(&authorization.reservation_id) != capture.authorization_reservation_id.as_ref()
        || Some(authorization.amount_minor) != capture.authorization_release_minor
        || authorization.stripe_account_id != capture.stripe_account_id
        || authorization.connect_account != capture.connect_account
        || authorization.customer_id != capture.customer_id
        || authorization.order_scope != capture.order_scope
        || authorization.currency != capture.currency
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    let authorization_workflow = authorization_workflow.to_owned();
    let capture_record = records
        .get_mut(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    capture_record.state = next;
    capture_record.updated_at = now;
    let output = capture_record.clone();
    let authorization_record = records
        .get_mut(&authorization_workflow)
        .ok_or(MerchantStateError::InvalidTransition)?;
    authorization_record.state = MerchantReservationState::AuthorizationReleasedByCapture;
    authorization_record.updated_at = now;
    Ok(output)
}

fn reconcile_capture_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    outcome: PaymentCaptureReconciliationOutcome,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let capture = records
        .get(workflow_id)
        .ok_or(MerchantStateError::NotFound)?
        .clone();
    if &capture.action_digest != action_digest || capture.operation != MerchantOperation::Capture {
        return Err(MerchantStateError::InvalidTransition);
    }
    let lease = MerchantReservationLease {
        workflow_id: workflow_id.into(),
        reservation_id: capture.reservation_id.clone(),
        action_digest: action_digest.clone(),
    };
    match outcome {
        PaymentCaptureReconciliationOutcome::Committed(provider) => {
            validate_committed_capture_projection(records, &capture, &provider)?;
            records
                .get_mut(workflow_id)
                .ok_or(MerchantStateError::NotFound)?
                .capture_provider = Some(provider);
            commit_capture_in(records, &lease, true, now)
        }
        PaymentCaptureReconciliationOutcome::Released(provider) => {
            if let Some(provider) = &provider {
                validate_capture_projection(records, &capture, provider)?;
                if provider.captured_amount_minor != 0 || provider.status != "requires_capture" {
                    return Err(MerchantStateError::InvalidTransition);
                }
            }
            transition_capture_in(
                records,
                &lease,
                PaymentCaptureTransition::ReconcileReleased,
                provider,
                now,
            )
        }
        PaymentCaptureReconciliationOutcome::OutcomeUnknown(provider) => transition_capture_in(
            records,
            &lease,
            PaymentCaptureTransition::ReconcileStillUnknown,
            provider,
            now,
        ),
    }
}

fn transition_cancel_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    event: PaymentCancelTransition,
    provider: Option<PaymentCancelProviderProjection>,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let current = records
        .get(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if current.reservation_id != lease.reservation_id
        || current.action_digest != lease.action_digest
        || current.operation != MerchantOperation::Cancel
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    let next = transition_payment_cancel(current.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if let Some(projection) = &provider {
        validate_cancel_projection(current, projection)?;
        if matches!(
            event,
            PaymentCancelTransition::CaptureConflictObserved
                | PaymentCancelTransition::ReconcileCaptureConflict
        ) {
            validate_cancel_capture_conflict_projection(projection)?;
        }
    }
    let record = records
        .get_mut(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if let Some(provider) = provider {
        record.cancel_provider = Some(provider);
    }
    if event == PaymentCancelTransition::ProviderAccepted && record.cancel_provider.is_none() {
        return Err(MerchantStateError::InvalidTransition);
    }
    record.state = next;
    record.updated_at = now;
    Ok(record.clone())
}

fn commit_cancel_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    reconciled: bool,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let cancel = records
        .get(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?
        .clone();
    if cancel.reservation_id != lease.reservation_id
        || cancel.action_digest != lease.action_digest
        || cancel.operation != MerchantOperation::Cancel
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    let event = if reconciled {
        PaymentCancelTransition::ReconcileCanceled
    } else {
        PaymentCancelTransition::CancelObserved
    };
    let next = transition_payment_cancel(cancel.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    let provider = cancel
        .cancel_provider
        .as_ref()
        .ok_or(MerchantStateError::InvalidTransition)?;
    validate_committed_cancel_projection(&cancel, provider)?;
    let authorization_workflow = cancel.authorization_workflow_id.clone();
    if let Some(workflow) = authorization_workflow.as_deref() {
        let authorization = records
            .get(workflow)
            .ok_or(MerchantStateError::InvalidTransition)?;
        if authorization.operation != MerchantOperation::Authorize
            || !authorization.state.holds_active_authorization()
            || Some(&authorization.action_digest) != cancel.authorization_action_digest.as_ref()
            || Some(&authorization.reservation_id) != cancel.authorization_reservation_id.as_ref()
            || Some(authorization.amount_minor) != cancel.authorization_release_minor
            || Some(authorization.amount_minor) != cancel.cancel_amount_minor
            || authorization.stripe_account_id != cancel.stripe_account_id
            || authorization.connect_account != cancel.connect_account
            || authorization.customer_id != cancel.customer_id
            || authorization.order_scope != cancel.order_scope
            || authorization.currency != cancel.currency
        {
            return Err(MerchantStateError::InvalidTransition);
        }
    }
    let cancel_record = records
        .get_mut(&lease.workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    cancel_record.state = next;
    cancel_record.updated_at = now;
    let output = cancel_record.clone();
    if let Some(workflow) = authorization_workflow {
        let authorization = records
            .get_mut(&workflow)
            .ok_or(MerchantStateError::InvalidTransition)?;
        authorization.state = MerchantReservationState::AuthorizationReleasedByCancel;
        authorization.updated_at = now;
    }
    Ok(output)
}

fn reconcile_cancel_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    outcome: PaymentCancelReconciliationOutcome,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let cancel = records
        .get(workflow_id)
        .ok_or(MerchantStateError::NotFound)?
        .clone();
    if &cancel.action_digest != action_digest || cancel.operation != MerchantOperation::Cancel {
        return Err(MerchantStateError::InvalidTransition);
    }
    let lease = MerchantReservationLease {
        workflow_id: workflow_id.into(),
        reservation_id: cancel.reservation_id.clone(),
        action_digest: action_digest.clone(),
    };
    match outcome {
        PaymentCancelReconciliationOutcome::Canceled(provider) => {
            validate_committed_cancel_projection(&cancel, &provider)?;
            records
                .get_mut(workflow_id)
                .ok_or(MerchantStateError::NotFound)?
                .cancel_provider = Some(provider);
            commit_cancel_in(records, &lease, true, now)
        }
        PaymentCancelReconciliationOutcome::Released(provider) => {
            if let Some(provider) = &provider {
                validate_released_cancel_projection(&cancel, provider)?;
            }
            transition_cancel_in(
                records,
                &lease,
                PaymentCancelTransition::ReconcileReleased,
                provider,
                now,
            )
        }
        PaymentCancelReconciliationOutcome::CaptureConflict(provider) => transition_cancel_in(
            records,
            &lease,
            PaymentCancelTransition::ReconcileCaptureConflict,
            Some(provider),
            now,
        ),
        PaymentCancelReconciliationOutcome::OutcomeUnknown(provider) => transition_cancel_in(
            records,
            &lease,
            PaymentCancelTransition::ReconcileStillUnknown,
            provider,
            now,
        ),
    }
}

fn transition_authorization_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    lease: &MerchantReservationLease,
    event: PaymentAuthorizeTransition,
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
    if record.operation != MerchantOperation::Authorize {
        return Err(MerchantStateError::InvalidTransition);
    }
    let next = transition_payment_authorize(record.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if let Some(provider) = provider {
        validate_provider(record, &provider)?;
        record.provider = Some(provider);
    }
    if matches!(
        event,
        PaymentAuthorizeTransition::ProviderAccepted
            | PaymentAuthorizeTransition::AuthorizationHeld
    ) && record.provider.is_none()
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    if event == PaymentAuthorizeTransition::AuthorizationHeld {
        validate_authorization_provider(
            record,
            record
                .provider
                .as_ref()
                .ok_or(MerchantStateError::InvalidTransition)?,
        )?;
    }
    record.state = next;
    record.updated_at = now;
    Ok(record.clone())
}

fn reconcile_authorization_in(
    records: &mut BTreeMap<String, MerchantReservationRecord>,
    workflow_id: &str,
    action_digest: &DigestHex,
    outcome: PaymentAuthorizeReconciliationOutcome,
    now: u64,
) -> Result<MerchantReservationRecord, MerchantStateError> {
    let record = records
        .get_mut(workflow_id)
        .ok_or(MerchantStateError::NotFound)?;
    if &record.action_digest != action_digest || record.operation != MerchantOperation::Authorize {
        return Err(MerchantStateError::InvalidTransition);
    }
    let (event, provider) = match outcome {
        PaymentAuthorizeReconciliationOutcome::Held(provider) => {
            validate_authorization_provider(record, &provider)?;
            (PaymentAuthorizeTransition::ReconcileHeld, Some(provider))
        }
        PaymentAuthorizeReconciliationOutcome::Released(provider) => {
            if let Some(provider) = &provider {
                validate_provider(record, provider)?;
            }
            (PaymentAuthorizeTransition::ReconcileReleased, provider)
        }
        PaymentAuthorizeReconciliationOutcome::OutcomeUnknown(provider) => {
            if let Some(provider) = &provider {
                validate_provider(record, provider)?;
            }
            (PaymentAuthorizeTransition::ReconcileStillUnknown, provider)
        }
    };
    record.state = transition_payment_authorize(record.state, event)
        .ok_or(MerchantStateError::InvalidTransition)?;
    if provider.is_some() {
        record.provider = provider;
    }
    record.updated_at = now;
    Ok(record.clone())
}

fn validate_capture_projection(
    records: &BTreeMap<String, MerchantReservationRecord>,
    capture: &MerchantReservationRecord,
    provider: &PaymentCaptureProviderProjection,
) -> Result<(), MerchantStateError> {
    let authorization = capture
        .authorization_workflow_id
        .as_deref()
        .and_then(|workflow| records.get(workflow))
        .ok_or(MerchantStateError::InvalidTransition)?;
    let authorization_provider = authorization
        .provider
        .as_ref()
        .ok_or(MerchantStateError::InvalidTransition)?;
    if provider.payment_intent_id != authorization_provider.payment_intent_id
        || Some(&provider.charge_id) != authorization_provider.charge_id.as_ref()
        || provider.authorized_amount_minor != authorization.amount_minor
        || provider.currency != capture.currency
        || provider.captured_amount_minor > capture.amount_minor
        || provider.status.is_empty()
        || provider.status.len() > 64
        || !matches!(
            provider.source.as_str(),
            "capture-response" | "retrieve" | "webhook"
        )
        || provider
            .stripe_request_id
            .as_ref()
            .is_some_and(|value| !valid_request_id(value))
        || provider
            .balance_transaction_id
            .as_ref()
            .is_some_and(|value| !valid_balance_transaction_id(value))
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
}

fn validate_committed_capture_projection(
    records: &BTreeMap<String, MerchantReservationRecord>,
    capture: &MerchantReservationRecord,
    provider: &PaymentCaptureProviderProjection,
) -> Result<(), MerchantStateError> {
    validate_capture_projection(records, capture, provider)?;
    if provider.status != "succeeded"
        || provider.captured_amount_minor != capture.amount_minor
        || provider.amount_capturable_minor != 0
        || provider.amount_received_minor != capture.amount_minor
        || provider.balance_transaction_id.is_none()
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
}

fn validate_cancel_projection(
    cancel: &MerchantReservationRecord,
    provider: &PaymentCancelProviderProjection,
) -> Result<(), MerchantStateError> {
    if Some(&provider.payment_intent_id) != cancel.cancel_payment_intent_id.as_ref()
        || Some(provider.amount_minor) != cancel.cancel_amount_minor
        || provider.currency != cancel.currency
        || provider.amount_capturable_minor > provider.amount_minor
        || provider.amount_received_minor > provider.amount_minor
        || provider.status.is_empty()
        || provider.status.len() > 64
        || !matches!(
            provider.source.as_str(),
            "cancel-response" | "retrieve" | "webhook"
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

fn validate_committed_cancel_projection(
    cancel: &MerchantReservationRecord,
    provider: &PaymentCancelProviderProjection,
) -> Result<(), MerchantStateError> {
    validate_cancel_projection(cancel, provider)?;
    if provider.status != "canceled"
        || provider.amount_capturable_minor != 0
        || provider.amount_received_minor != 0
        || provider.cancellation_reason != cancel.cancellation_reason
        || provider.charge_captured == Some(true)
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
}

fn validate_released_cancel_projection(
    cancel: &MerchantReservationRecord,
    provider: &PaymentCancelProviderProjection,
) -> Result<(), MerchantStateError> {
    validate_cancel_projection(cancel, provider)?;
    let expected_capturable = cancel.authorization_release_minor.unwrap_or(0);
    if Some(provider.status.as_str()) != cancel.cancel_pre_status.as_deref()
        || provider.amount_capturable_minor != expected_capturable
        || provider.amount_received_minor != 0
        || provider.cancellation_reason.is_some()
        || provider.charge_captured == Some(true)
    {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
}

fn validate_cancel_capture_conflict_projection(
    provider: &PaymentCancelProviderProjection,
) -> Result<(), MerchantStateError> {
    if provider.status != "succeeded" && provider.charge_captured != Some(true) {
        return Err(MerchantStateError::InvalidTransition);
    }
    Ok(())
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

fn validate_authorization_provider(
    record: &MerchantReservationRecord,
    provider: &MerchantProviderProjection,
) -> Result<(), MerchantStateError> {
    validate_provider(record, provider)?;
    if provider.status != "requires_capture"
        || provider.amount_capturable_minor != record.amount_minor
        || provider.amount_received_minor != 0
        || provider.charge_id.is_none()
        || provider.capture_before.is_none()
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

fn valid_balance_transaction_id(value: &str) -> bool {
    value.starts_with("txn_")
        && (12..=96).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
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

#[allow(
    clippy::too_many_lines,
    reason = "the validator keeps the complete persisted-record invariant visible in one place"
)]
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
    let provider_shape = match record.operation {
        MerchantOperation::Capture => {
            record.provider.is_none()
                && record.cancel_provider.is_none()
                && match record.state {
                    MerchantReservationState::ProviderAccepted
                    | MerchantReservationState::CaptureCommitted
                    | MerchantReservationState::ReconciledCaptureCommitted => {
                        record.capture_provider.is_some()
                    }
                    MerchantReservationState::Reserved
                    | MerchantReservationState::Claimed
                    | MerchantReservationState::Attempting
                    | MerchantReservationState::Released => record.capture_provider.is_none(),
                    MerchantReservationState::OutcomeUnknown
                    | MerchantReservationState::ReconciledReleased => true,
                    _ => false,
                }
        }
        MerchantOperation::Cancel => {
            record.provider.is_none()
                && record.capture_provider.is_none()
                && match record.state {
                    MerchantReservationState::ProviderAccepted
                    | MerchantReservationState::CancelCommitted
                    | MerchantReservationState::ReconciledCancelCommitted
                    | MerchantReservationState::CancelCaptureConflict => {
                        record.cancel_provider.is_some()
                    }
                    MerchantReservationState::Reserved
                    | MerchantReservationState::Claimed
                    | MerchantReservationState::Attempting
                    | MerchantReservationState::Released => record.cancel_provider.is_none(),
                    MerchantReservationState::OutcomeUnknown
                    | MerchantReservationState::ReconciledReleased => true,
                    _ => false,
                }
        }
        MerchantOperation::Collect | MerchantOperation::Authorize => {
            record.capture_provider.is_none()
                && record.cancel_provider.is_none()
                && match record.state {
                    MerchantReservationState::ProviderAccepted
                    | MerchantReservationState::Committed
                    | MerchantReservationState::ReconciledCommitted
                    | MerchantReservationState::Authorized
                    | MerchantReservationState::ReconciledAuthorized
                    | MerchantReservationState::AuthorizationReleasedByCapture
                    | MerchantReservationState::AuthorizationReleasedByCancel => {
                        record.provider.is_some()
                    }
                    MerchantReservationState::Reserved
                    | MerchantReservationState::Claimed
                    | MerchantReservationState::Attempting
                    | MerchantReservationState::Released => record.provider.is_none(),
                    MerchantReservationState::OutcomeUnknown
                    | MerchantReservationState::ReconciledReleased => true,
                    _ => false,
                }
        }
    };
    let operation_profile_matches = matches!(
        (record.operation, record.exact_action_profile.as_str()),
        (
            MerchantOperation::Collect,
            crate::merchant::PAYMENT_COLLECT_PROFILE
        ) | (
            MerchantOperation::Authorize,
            crate::merchant::PAYMENT_AUTHORIZE_PROFILE
        ) | (
            MerchantOperation::Capture,
            crate::merchant::PAYMENT_CAPTURE_PROFILE
        ) | (
            MerchantOperation::Cancel,
            crate::merchant::PAYMENT_CANCEL_PROFILE
        )
    );
    let lifecycle_matches = match record.operation {
        MerchantOperation::Collect => !matches!(
            record.state,
            MerchantReservationState::Authorized
                | MerchantReservationState::ReconciledAuthorized
                | MerchantReservationState::AuthorizationReleasedByCapture
                | MerchantReservationState::AuthorizationReleasedByCancel
                | MerchantReservationState::CaptureCommitted
                | MerchantReservationState::ReconciledCaptureCommitted
                | MerchantReservationState::CancelCommitted
                | MerchantReservationState::ReconciledCancelCommitted
                | MerchantReservationState::CancelCaptureConflict
        ),
        MerchantOperation::Authorize => !matches!(
            record.state,
            MerchantReservationState::Committed
                | MerchantReservationState::ReconciledCommitted
                | MerchantReservationState::CaptureCommitted
                | MerchantReservationState::ReconciledCaptureCommitted
                | MerchantReservationState::CancelCommitted
                | MerchantReservationState::ReconciledCancelCommitted
                | MerchantReservationState::CancelCaptureConflict
        ),
        MerchantOperation::Capture => !matches!(
            record.state,
            MerchantReservationState::Committed
                | MerchantReservationState::ReconciledCommitted
                | MerchantReservationState::Authorized
                | MerchantReservationState::ReconciledAuthorized
                | MerchantReservationState::AuthorizationReleasedByCapture
                | MerchantReservationState::AuthorizationReleasedByCancel
                | MerchantReservationState::CancelCommitted
                | MerchantReservationState::ReconciledCancelCommitted
                | MerchantReservationState::CancelCaptureConflict
        ),
        MerchantOperation::Cancel => !matches!(
            record.state,
            MerchantReservationState::Committed
                | MerchantReservationState::ReconciledCommitted
                | MerchantReservationState::Authorized
                | MerchantReservationState::ReconciledAuthorized
                | MerchantReservationState::AuthorizationReleasedByCapture
                | MerchantReservationState::AuthorizationReleasedByCancel
                | MerchantReservationState::CaptureCommitted
                | MerchantReservationState::ReconciledCaptureCommitted
        ),
    };
    let operation_links_match = if record.operation == MerchantOperation::Capture {
        record.authorization_workflow_id.is_some()
            && record.authorization_action_digest.is_some()
            && record.authorization_reservation_id.is_some()
            && record
                .authorization_release_minor
                .is_some_and(|amount| amount > 0)
            && record.capture_payment_intent_id.is_some()
            && record.capture_charge_id.is_some()
            && record.cancel_payment_intent_id.is_none()
            && record.cancellation_reason.is_none()
            && record.cancel_pre_status.is_none()
            && record.cancel_amount_minor.is_none()
    } else if record.operation == MerchantOperation::Cancel {
        let hold_fields = [
            record.authorization_workflow_id.is_some(),
            record.authorization_action_digest.is_some(),
            record.authorization_reservation_id.is_some(),
            record.authorization_release_minor.is_some(),
        ];
        let complete_hold = hold_fields.iter().all(|present| *present);
        let no_hold = hold_fields.iter().all(|present| !*present);
        record.capture_payment_intent_id.is_none()
            && record.capture_charge_id.is_none()
            && record.cancel_payment_intent_id.is_some()
            && record.cancellation_reason.is_some()
            && record.cancel_amount_minor.is_some_and(|amount| amount > 0)
            && record.cancel_pre_status.as_deref().is_some_and(|status| {
                matches!(
                    status,
                    "requires_payment_method"
                        | "requires_capture"
                        | "requires_confirmation"
                        | "requires_action"
                )
            })
            && if record.cancel_pre_status.as_deref() == Some("requires_capture") {
                complete_hold
                    && record
                        .authorization_release_minor
                        .is_some_and(|amount| amount > 0)
            } else {
                no_hold
            }
    } else {
        record.authorization_workflow_id.is_none()
            && record.authorization_action_digest.is_none()
            && record.authorization_reservation_id.is_none()
            && record.authorization_release_minor.is_none()
            && record.capture_payment_intent_id.is_none()
            && record.capture_charge_id.is_none()
            && record.cancel_payment_intent_id.is_none()
            && record.cancellation_reason.is_none()
            && record.cancel_pre_status.is_none()
            && record.cancel_amount_minor.is_none()
    };
    let amount_shape = if record.operation == MerchantOperation::Cancel {
        record.amount_minor == 0 && record.intents.is_empty()
    } else {
        record.amount_minor > 0
            && !record.intents.is_empty()
            && record.intents.iter().all(|intent| {
                intent.operation == record.operation
                    && intent.currency == record.currency
                    && intent.amount_minor == record.amount_minor
            })
    };
    record.schema == RESERVATION_SCHEMA
        && identity_matches
        && operation_profile_matches
        && lifecycle_matches
        && operation_links_match
        && provider_shape
        && (8..=96).contains(&record.workflow_id.len())
        && amount_shape
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

    fn held_authorization(
        store: &InMemoryMerchantPaymentStore,
        workflow: &str,
        payment_intent: &PaymentIntentId,
        charge: &ChargeId,
    ) -> MerchantReservationRecord {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_000);
        let ReserveMerchantPaymentResult::Reserved { lease, .. } = store.reserve(request(
            &policy,
            MerchantOperation::Authorize,
            workflow,
            1_000,
        )) else {
            panic!("authorization reservation expected");
        };
        store.claim_authorization(&lease, NOW).unwrap();
        store.mark_authorization_attempting(&lease, NOW).unwrap();
        store
            .record_authorization_provider_accepted(
                &lease,
                MerchantProviderProjection {
                    payment_intent_id: payment_intent.clone(),
                    charge_id: Some(charge.clone()),
                    status: "requires_capture".into(),
                    amount_minor: 1_000,
                    currency: Currency::parse("usd").unwrap(),
                    amount_capturable_minor: 1_000,
                    amount_received_minor: 0,
                    capture_before: Some(NOW + 3_600),
                    stripe_request_id: Some("req_concurrent_authorization".into()),
                    response_digest: sha256(b"concurrent-authorization-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        store.commit_authorization(&lease, NOW).unwrap()
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
    fn concurrent_last_authorization_hold_is_reserved_once() {
        let policy = Arc::new(merchant_policy(MerchantOperation::Authorize, 1_000, 1_000));
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
                    MerchantOperation::Authorize,
                    &format!("merchant-authorize-concurrent-{suffix}"),
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
                .filter(|outcome| matches!(
                    outcome,
                    ReserveMerchantPaymentResult::CapacityExceeded {
                        available_minor: 0,
                        ..
                    }
                ))
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
    fn authorization_replay_survives_restart_without_a_second_lease() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("merchant-authorize-state.json");
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 2_000);
        let action_digest = sha256(b"action-merchant-authorize-restart-0001");
        {
            let store = PersistentMerchantPaymentStore::open(&path).unwrap();
            assert!(matches!(
                store.reserve(request(
                    &policy,
                    MerchantOperation::Authorize,
                    "merchant-authorize-restart-0001",
                    1_000,
                )),
                ReserveMerchantPaymentResult::Reserved { .. }
            ));
        }
        let store = PersistentMerchantPaymentStore::open(&path).unwrap();
        let replay = store.reserve(request(
            &policy,
            MerchantOperation::Authorize,
            "merchant-authorize-restart-0001",
            1_000,
        ));
        let ReserveMerchantPaymentResult::Replay(record) = replay else {
            panic!("authorization restart must return replay");
        };
        assert_eq!(record.action_digest(), &action_digest);
        assert_eq!(record.state(), MerchantReservationState::Reserved);
    }

    #[test]
    fn collect_and_authorize_store_transitions_remain_profile_owned() {
        let policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_000);
        let store = InMemoryMerchantPaymentStore::default();
        let ReserveMerchantPaymentResult::Reserved { lease, .. } = store.reserve(request(
            &policy,
            MerchantOperation::Authorize,
            "merchant-authorize-state-0001",
            1_000,
        )) else {
            panic!("authorization reservation expected");
        };
        assert!(store.claim(&lease, NOW).is_err());
        assert_eq!(
            store.claim_authorization(&lease, NOW).unwrap().state(),
            MerchantReservationState::Claimed
        );
        store.mark_authorization_attempting(&lease, NOW).unwrap();
        store
            .record_authorization_provider_accepted(
                &lease,
                MerchantProviderProjection {
                    payment_intent_id: PaymentIntentId::parse("pi_authorize_state_test").unwrap(),
                    charge_id: Some(ChargeId::parse("ch_authorize_state_test").unwrap()),
                    status: "requires_capture".into(),
                    amount_minor: 1_000,
                    currency: Currency::parse("usd").unwrap(),
                    amount_capturable_minor: 1_000,
                    amount_received_minor: 0,
                    capture_before: Some(NOW + 3_600),
                    stripe_request_id: Some("req_authorize_state_test".into()),
                    response_digest: sha256(b"authorization-state-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        assert_eq!(
            store.commit_authorization(&lease, NOW).unwrap().state(),
            MerchantReservationState::Authorized
        );
        let snapshot = store
            .snapshot(
                &policy,
                &StripeAccountId::parse("acct_authsdemo01").unwrap(),
                NOW,
            )
            .unwrap();
        assert_eq!(snapshot.usages[0].active_authorization_minor, 1_000);
        assert_eq!(snapshot.usages[0].committed_minor, 0);
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

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test proves both sides of the atomic cross-budget transition"
    )]
    fn final_capture_atomically_commits_settlement_and_releases_the_linked_hold() {
        let authorization_policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_000);
        let capture_policy = merchant_policy(MerchantOperation::Capture, 1_000, 1_000);
        let store = InMemoryMerchantPaymentStore::default();
        let authorization_workflow = "merchant-capture-source-0001";
        let ReserveMerchantPaymentResult::Reserved {
            lease: authorization_lease,
            ..
        } = store.reserve(request(
            &authorization_policy,
            MerchantOperation::Authorize,
            authorization_workflow,
            1_000,
        ))
        else {
            panic!("authorization reservation expected");
        };
        store
            .claim_authorization(&authorization_lease, NOW)
            .unwrap();
        store
            .mark_authorization_attempting(&authorization_lease, NOW)
            .unwrap();
        store
            .record_authorization_provider_accepted(
                &authorization_lease,
                MerchantProviderProjection {
                    payment_intent_id: PaymentIntentId::parse("pi_capture_state_test").unwrap(),
                    charge_id: Some(ChargeId::parse("ch_capture_state_test").unwrap()),
                    status: "requires_capture".into(),
                    amount_minor: 1_000,
                    currency: Currency::parse("usd").unwrap(),
                    amount_capturable_minor: 1_000,
                    amount_received_minor: 0,
                    capture_before: Some(NOW + 3_600),
                    stripe_request_id: Some("req_capture_authorize_test".into()),
                    response_digest: sha256(b"capture-source-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        let authorization = store
            .commit_authorization(&authorization_lease, NOW)
            .unwrap();

        let budget = &capture_policy.aggregate_budgets()[0];
        let capture_request = ReservePaymentCaptureRequest::new(
            "merchant-final-capture-0001".into(),
            sha256(b"capture-action"),
            sha256(b"capture-decision"),
            capture_policy.digest().unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"capture-evidence"),
            sha256(b"capture-configuration"),
            sha256(b"capture-configuration"),
            authorization.stripe_account_id().clone(),
            authorization.connect_account().clone(),
            authorization.customer_id().clone(),
            authorization.order_scope().into(),
            authorization.currency().clone(),
            500,
            vec![MerchantReservationIntent {
                budget_id: budget.budget_id().into(),
                operation: MerchantOperation::Capture,
                currency: authorization.currency().clone(),
                window: budget.window().identity(NOW).unwrap(),
                limit_minor: budget.limit_minor(),
                amount_minor: 500,
                available_before_minor: budget.limit_minor(),
            }],
            sha256(b"capture-idempotency"),
            authorization_workflow.into(),
            authorization.action_digest().clone(),
            authorization.reservation_id().clone(),
            1_000,
            PaymentIntentId::parse("pi_capture_state_test").unwrap(),
            ChargeId::parse("ch_capture_state_test").unwrap(),
            NOW,
        );
        let ReserveMerchantPaymentResult::Reserved {
            lease: capture_lease,
            ..
        } = store.reserve_capture(capture_request)
        else {
            panic!("capture settlement reservation expected");
        };
        store.claim_capture(&capture_lease, NOW).unwrap();
        store.mark_capture_attempting(&capture_lease, NOW).unwrap();
        store
            .record_capture_provider_accepted(
                &capture_lease,
                PaymentCaptureProviderProjection {
                    payment_intent_id: PaymentIntentId::parse("pi_capture_state_test").unwrap(),
                    charge_id: ChargeId::parse("ch_capture_state_test").unwrap(),
                    balance_transaction_id: Some("txn_capture_state_test".into()),
                    status: "succeeded".into(),
                    authorized_amount_minor: 1_000,
                    captured_amount_minor: 500,
                    currency: Currency::parse("usd").unwrap(),
                    amount_capturable_minor: 0,
                    amount_received_minor: 500,
                    capture_before: Some(NOW + 3_600),
                    stripe_request_id: Some("req_capture_state_test".into()),
                    response_digest: sha256(b"capture-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        let capture = store.commit_capture(&capture_lease, NOW).unwrap();
        let released_authorization = store.get(authorization_workflow).unwrap().unwrap();
        assert_eq!(capture.state(), MerchantReservationState::CaptureCommitted);
        assert_eq!(
            released_authorization.state(),
            MerchantReservationState::AuthorizationReleasedByCapture
        );
        let authorization_snapshot = store
            .snapshot(
                &authorization_policy,
                &StripeAccountId::parse("acct_authsdemo01").unwrap(),
                NOW,
            )
            .unwrap();
        let capture_snapshot = store
            .snapshot(
                &capture_policy,
                &StripeAccountId::parse("acct_authsdemo01").unwrap(),
                NOW,
            )
            .unwrap();
        assert_eq!(
            authorization_snapshot.usages[0].active_authorization_minor,
            0
        );
        assert_eq!(capture_snapshot.usages[0].committed_minor, 500);
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test proves the complete atomic cancellation and hold-release path"
    )]
    fn cancellation_claim_excludes_capture_and_terminal_observation_releases_the_hold() {
        let authorization_policy = merchant_policy(MerchantOperation::Authorize, 1_000, 1_000);
        let capture_policy = merchant_policy(MerchantOperation::Capture, 1_000, 1_000);
        let store = InMemoryMerchantPaymentStore::default();
        let authorization_workflow = "merchant-cancel-source-0001";
        let ReserveMerchantPaymentResult::Reserved {
            lease: authorization_lease,
            ..
        } = store.reserve(request(
            &authorization_policy,
            MerchantOperation::Authorize,
            authorization_workflow,
            1_000,
        ))
        else {
            panic!("authorization reservation expected");
        };
        store
            .claim_authorization(&authorization_lease, NOW)
            .unwrap();
        store
            .mark_authorization_attempting(&authorization_lease, NOW)
            .unwrap();
        let payment_intent = PaymentIntentId::parse("pi_cancel_state_test").unwrap();
        let charge = ChargeId::parse("ch_cancel_state_test").unwrap();
        store
            .record_authorization_provider_accepted(
                &authorization_lease,
                MerchantProviderProjection {
                    payment_intent_id: payment_intent.clone(),
                    charge_id: Some(charge.clone()),
                    status: "requires_capture".into(),
                    amount_minor: 1_000,
                    currency: Currency::parse("usd").unwrap(),
                    amount_capturable_minor: 1_000,
                    amount_received_minor: 0,
                    capture_before: Some(NOW + 3_600),
                    stripe_request_id: Some("req_cancel_authorize_test".into()),
                    response_digest: sha256(b"cancel-source-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        let authorization = store
            .commit_authorization(&authorization_lease, NOW)
            .unwrap();
        let cancel_request = ReservePaymentCancelRequest::new(
            "merchant-payment-cancel-0001".into(),
            sha256(b"cancel-action"),
            sha256(b"cancel-decision"),
            merchant_policy(MerchantOperation::Cancel, 0, 0)
                .digest()
                .unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"cancel-evidence"),
            sha256(b"cancel-configuration"),
            sha256(b"cancel-configuration"),
            authorization.stripe_account_id().clone(),
            authorization.connect_account().clone(),
            authorization.customer_id().clone(),
            authorization.order_scope().into(),
            authorization.currency().clone(),
            sha256(b"cancel-idempotency"),
            Some(authorization_workflow.into()),
            Some(authorization.action_digest().clone()),
            Some(authorization.reservation_id().clone()),
            Some(authorization.amount_minor()),
            payment_intent.clone(),
            PaymentCancellationReason::RequestedByCustomer,
            "requires_capture".into(),
            authorization.amount_minor(),
            NOW,
        );
        let ReserveMerchantPaymentResult::Reserved {
            lease: cancel_lease,
            ..
        } = store.reserve_cancel(cancel_request)
        else {
            panic!("cancellation claim expected");
        };

        let budget = &capture_policy.aggregate_budgets()[0];
        let competing_capture = ReservePaymentCaptureRequest::new(
            "merchant-competing-capture-0001".into(),
            sha256(b"competing-capture-action"),
            sha256(b"competing-capture-decision"),
            capture_policy.digest().unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"competing-capture-evidence"),
            sha256(b"capture-configuration"),
            sha256(b"capture-configuration"),
            authorization.stripe_account_id().clone(),
            authorization.connect_account().clone(),
            authorization.customer_id().clone(),
            authorization.order_scope().into(),
            authorization.currency().clone(),
            1_000,
            vec![MerchantReservationIntent {
                budget_id: budget.budget_id().into(),
                operation: MerchantOperation::Capture,
                currency: authorization.currency().clone(),
                window: budget.window().identity(NOW).unwrap(),
                limit_minor: budget.limit_minor(),
                amount_minor: 1_000,
                available_before_minor: budget.limit_minor(),
            }],
            sha256(b"competing-capture-idempotency"),
            authorization_workflow.into(),
            authorization.action_digest().clone(),
            authorization.reservation_id().clone(),
            authorization.amount_minor(),
            payment_intent.clone(),
            charge.clone(),
            NOW,
        );
        assert!(matches!(
            store.reserve_capture(competing_capture),
            ReserveMerchantPaymentResult::Unavailable
        ));

        store.claim_cancel(&cancel_lease, NOW).unwrap();
        store.mark_cancel_attempting(&cancel_lease, NOW).unwrap();
        store
            .record_cancel_provider_accepted(
                &cancel_lease,
                PaymentCancelProviderProjection {
                    payment_intent_id: payment_intent,
                    latest_charge_id: Some(charge),
                    status: "canceled".into(),
                    cancellation_reason: Some(PaymentCancellationReason::RequestedByCustomer),
                    amount_minor: 1_000,
                    amount_capturable_minor: 0,
                    amount_received_minor: 0,
                    currency: Currency::parse("usd").unwrap(),
                    charge_captured: Some(false),
                    stripe_request_id: Some("req_cancel_state_test".into()),
                    response_digest: sha256(b"cancel-provider"),
                    observed_at: NOW,
                    source: "retrieve".into(),
                },
                NOW,
            )
            .unwrap();
        let canceled = store.commit_cancel(&cancel_lease, NOW).unwrap();
        assert_eq!(canceled.state(), MerchantReservationState::CancelCommitted);
        assert_eq!(
            store.get(authorization_workflow).unwrap().unwrap().state(),
            MerchantReservationState::AuthorizationReleasedByCancel
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the test constructs both complete profile-specific race requests"
    )]
    fn concurrent_capture_and_cancel_reservations_are_mutually_exclusive() {
        let store = Arc::new(InMemoryMerchantPaymentStore::default());
        let payment_intent = PaymentIntentId::parse("pi_cancel_capture_race").unwrap();
        let charge = ChargeId::parse("ch_cancel_capture_race").unwrap();
        let authorization_workflow = "merchant-race-authorization-0001";
        let authorization =
            held_authorization(&store, authorization_workflow, &payment_intent, &charge);
        let capture_policy = merchant_policy(MerchantOperation::Capture, 1_000, 1_000);
        let capture_budget = &capture_policy.aggregate_budgets()[0];
        let capture_request = ReservePaymentCaptureRequest::new(
            "merchant-race-capture-0001".into(),
            sha256(b"race-capture-action"),
            sha256(b"race-capture-decision"),
            capture_policy.digest().unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"race-capture-evidence"),
            sha256(b"capture-configuration"),
            sha256(b"capture-configuration"),
            authorization.stripe_account_id().clone(),
            authorization.connect_account().clone(),
            authorization.customer_id().clone(),
            authorization.order_scope().into(),
            authorization.currency().clone(),
            1_000,
            vec![MerchantReservationIntent {
                budget_id: capture_budget.budget_id().into(),
                operation: MerchantOperation::Capture,
                currency: authorization.currency().clone(),
                window: capture_budget.window().identity(NOW).unwrap(),
                limit_minor: capture_budget.limit_minor(),
                amount_minor: 1_000,
                available_before_minor: capture_budget.limit_minor(),
            }],
            sha256(b"race-capture-idempotency"),
            authorization_workflow.into(),
            authorization.action_digest().clone(),
            authorization.reservation_id().clone(),
            authorization.amount_minor(),
            payment_intent.clone(),
            charge,
            NOW,
        );
        let cancel_request = ReservePaymentCancelRequest::new(
            "merchant-race-cancel-0001".into(),
            sha256(b"race-cancel-action"),
            sha256(b"race-cancel-decision"),
            merchant_policy(MerchantOperation::Cancel, 0, 0)
                .digest()
                .unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"race-cancel-evidence"),
            sha256(b"cancel-configuration"),
            sha256(b"cancel-configuration"),
            authorization.stripe_account_id().clone(),
            authorization.connect_account().clone(),
            authorization.customer_id().clone(),
            authorization.order_scope().into(),
            authorization.currency().clone(),
            sha256(b"race-cancel-idempotency"),
            Some(authorization_workflow.into()),
            Some(authorization.action_digest().clone()),
            Some(authorization.reservation_id().clone()),
            Some(authorization.amount_minor()),
            payment_intent,
            PaymentCancellationReason::RequestedByCustomer,
            "requires_capture".into(),
            authorization.amount_minor(),
            NOW,
        );
        let barrier = Arc::new(Barrier::new(3));
        let capture_store = Arc::clone(&store);
        let capture_barrier = Arc::clone(&barrier);
        let capture = thread::spawn(move || {
            capture_barrier.wait();
            capture_store.reserve_capture(capture_request)
        });
        let cancel_store = Arc::clone(&store);
        let cancel_barrier = Arc::clone(&barrier);
        let cancel = thread::spawn(move || {
            cancel_barrier.wait();
            cancel_store.reserve_cancel(cancel_request)
        });
        barrier.wait();
        let outcomes = [capture.join().unwrap(), cancel.join().unwrap()];
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
                .filter(|outcome| matches!(outcome, ReserveMerchantPaymentResult::Unavailable))
                .count(),
            1
        );
        assert_eq!(
            store.get(authorization_workflow).unwrap().unwrap().state(),
            MerchantReservationState::Authorized
        );
    }

    #[test]
    fn released_cancel_reconciliation_requires_the_exact_unchanged_provider_state() {
        let store = InMemoryMerchantPaymentStore::default();
        let payment_intent = PaymentIntentId::parse("pi_cancel_release_validation").unwrap();
        let cancel_request = ReservePaymentCancelRequest::new(
            "merchant-cancel-release-validation-0001".into(),
            sha256(b"cancel-release-action"),
            sha256(b"cancel-release-decision"),
            merchant_policy(MerchantOperation::Cancel, 0, 0)
                .digest()
                .unwrap(),
            MERCHANT_EVALUATOR_ID.into(),
            MERCHANT_EVALUATOR_VERSION,
            sha256(b"cancel-release-evidence"),
            sha256(b"cancel-configuration"),
            sha256(b"cancel-configuration"),
            StripeAccountId::parse("acct_authsdemo01").unwrap(),
            MerchantConnectAccount::Platform,
            CustomerId::parse("cus_authsdemo00000001").unwrap(),
            "order-cancel-release-validation".into(),
            Currency::parse("usd").unwrap(),
            sha256(b"cancel-release-idempotency"),
            None,
            None,
            None,
            None,
            payment_intent.clone(),
            PaymentCancellationReason::Duplicate,
            "requires_confirmation".into(),
            1_000,
            NOW,
        );
        let ReserveMerchantPaymentResult::Reserved { lease, .. } =
            store.reserve_cancel(cancel_request)
        else {
            panic!("cancellation claim expected");
        };
        store.claim_cancel(&lease, NOW).unwrap();
        store.mark_cancel_attempting(&lease, NOW).unwrap();
        let unknown = store
            .mark_cancel_outcome_unknown(&lease, None, NOW)
            .unwrap();
        let projection = PaymentCancelProviderProjection {
            payment_intent_id: payment_intent,
            latest_charge_id: None,
            status: "requires_action".into(),
            cancellation_reason: None,
            amount_minor: 1_000,
            amount_capturable_minor: 0,
            amount_received_minor: 0,
            currency: Currency::parse("usd").unwrap(),
            charge_captured: None,
            stripe_request_id: Some("req_cancel_release_validation".into()),
            response_digest: sha256(b"cancel-release-provider"),
            observed_at: NOW,
            source: "retrieve".into(),
        };
        assert_eq!(
            store.reconcile_cancel(
                lease.workflow_id(),
                unknown.action_digest(),
                PaymentCancelReconciliationOutcome::Released(Some(projection.clone())),
                NOW + 1,
            ),
            Err(MerchantStateError::InvalidTransition)
        );
        assert_eq!(
            store.get(lease.workflow_id()).unwrap().unwrap().state(),
            MerchantReservationState::OutcomeUnknown
        );
        let mut unchanged = projection;
        unchanged.status = "requires_confirmation".into();
        let released = store
            .reconcile_cancel(
                lease.workflow_id(),
                unknown.action_digest(),
                PaymentCancelReconciliationOutcome::Released(Some(unchanged)),
                NOW + 2,
            )
            .unwrap();
        assert_eq!(
            released.state(),
            MerchantReservationState::ReconciledReleased
        );
    }
}
