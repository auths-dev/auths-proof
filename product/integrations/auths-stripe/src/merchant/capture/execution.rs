//! Narrow protected effect boundary for one exact final capture.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};
use serde::{Deserialize, Serialize};

use super::{
    evidence::PaymentCaptureEvidenceV1,
    profile::{StripePaymentCaptureCommand, StripePaymentCaptureProfile},
};
use crate::{
    merchant::{
        MerchantConnectAccount, MerchantReservationRecord, MerchantReservationState,
        StripeExactPaymentCaptureV1,
    },
    ports::{PaymentCaptureCredential, PortError},
    types::{ChargeId, Currency, DigestHex, PaymentIntentId, StripeAccountId},
};

/// Exact capture proof-verification result.
pub enum PaymentCaptureProofDecision {
    /// Exact authority was established.
    Authorized(Box<Authorized<StripePaymentCaptureCommand>>),
    /// Complete inputs establish denial.
    Denied {
        /// Stable Auths code.
        code: String,
    },
    /// Trusted verification input or implementation is unavailable.
    Indeterminate {
        /// Stable Auths code.
        code: String,
    },
}

/// Auths kernel boundary fixed to the exact final-capture profile.
pub trait PaymentCaptureProofVerifier: Send + Sync {
    /// Verifies proof against an already canonicalized exact action.
    ///
    /// # Errors
    ///
    /// Returns a closed verifier integration failure.
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCaptureProofDecision, PortError>;
}

impl<T: PaymentCaptureProofVerifier + ?Sized> PaymentCaptureProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCaptureProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

/// SDK adapter fixed to `auths.stripe.exact-payment-capture/1`.
pub struct SdkPaymentCaptureProofVerifier {
    verifier: Verifier,
}

impl SdkPaymentCaptureProofVerifier {
    /// Wraps an explicitly configured Auths verifier.
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PaymentCaptureProofVerifier for SdkPaymentCaptureProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCaptureProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePaymentCaptureProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => {
                Ok(PaymentCaptureProofDecision::Authorized(authorized))
            }
            VerifyResult::Denied(explanation) => Ok(PaymentCaptureProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => {
                Ok(PaymentCaptureProofDecision::Indeterminate {
                    code: explanation.code().into(),
                })
            }
        }
    }
}

/// Protected pre-provider final-capture command.
///
/// No public constructor exists. Only the service can combine an Auths-opened
/// action with the bounded decision, settlement reservation, and claim.
pub struct VerifiedPaymentCaptureCommand {
    authorized: Authorized<StripePaymentCaptureCommand>,
    workflow_id: String,
    evidence: PaymentCaptureEvidenceV1,
    policy_digest: DigestHex,
    reservation_id: DigestHex,
    decision_receipt_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    minimum_capture_window_seconds: u64,
    idempotency_key: String,
}

/// Closed provider request derived from a verified final-capture command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentCaptureProviderRequest {
    payment_intent_id: String,
    amount_to_capture_minor: u64,
    final_capture: bool,
    statement_descriptor_suffix: String,
    profile: String,
    order_scope: String,
    policy_digest: String,
    workflow_id: String,
    authorization_reservation_id: String,
}

impl PaymentCaptureProviderRequest {
    /// Existing exact `PaymentIntent`.
    #[must_use]
    pub fn payment_intent_id(&self) -> &str {
        &self.payment_intent_id
    }

    /// Exact positive amount to settle.
    #[must_use]
    pub const fn amount_to_capture_minor(&self) -> u64 {
        self.amount_to_capture_minor
    }

    /// V1 always performs a final capture.
    #[must_use]
    pub const fn final_capture(&self) -> bool {
        self.final_capture
    }

    /// Fixed protected statement suffix.
    #[must_use]
    pub fn statement_descriptor_suffix(&self) -> &str {
        &self.statement_descriptor_suffix
    }

    /// Exact capture profile metadata.
    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    /// Exact protected order metadata.
    #[must_use]
    pub fn order_scope(&self) -> &str {
        &self.order_scope
    }

    /// Immutable policy metadata commitment.
    #[must_use]
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }

    /// Durable capture workflow metadata.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Linked durable authorization reservation metadata.
    #[must_use]
    pub fn authorization_reservation_id(&self) -> &str {
        &self.authorization_reservation_id
    }
}

impl VerifiedPaymentCaptureCommand {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private constructor requires every completed trust-boundary fact"
    )]
    pub(crate) fn new(
        authorized: Authorized<StripePaymentCaptureCommand>,
        workflow_id: String,
        evidence: PaymentCaptureEvidenceV1,
        policy_digest: DigestHex,
        reservation_id: DigestHex,
        decision_receipt_digest: DigestHex,
        required_configuration_digest: DigestHex,
        executed_configuration_digest: DigestHex,
        minimum_capture_window_seconds: u64,
        idempotency_key: String,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            evidence,
            policy_digest,
            reservation_id,
            decision_receipt_digest,
            required_configuration_digest,
            executed_configuration_digest,
            minimum_capture_window_seconds,
            idempotency_key,
        }
    }

    /// Exact action opened by Auths.
    #[must_use]
    pub fn action(&self) -> &StripeExactPaymentCaptureV1 {
        self.authorized.command().action()
    }

    /// Durable workflow identity.
    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    /// Eligibility evidence bound to the command.
    #[must_use]
    pub const fn evidence(&self) -> &PaymentCaptureEvidenceV1 {
        &self.evidence
    }

    /// Immutable configured-policy commitment.
    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    /// Durable capture reservation identity.
    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    /// Durable decision receipt commitment.
    #[must_use]
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }

    /// Required runtime configuration commitment.
    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    /// Executed runtime configuration commitment.
    #[must_use]
    pub const fn executed_configuration_digest(&self) -> &DigestHex {
        &self.executed_configuration_digest
    }

    /// Minimum provider-observed time left before capture.
    #[must_use]
    pub const fn minimum_capture_window_seconds(&self) -> u64 {
        self.minimum_capture_window_seconds
    }

    /// Stable server-derived Stripe idempotency key.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    /// Fixed statement descriptor constructed by the product.
    #[must_use]
    pub const fn statement_descriptor(&self) -> &'static str {
        crate::merchant::PAYMENT_STATEMENT_DESCRIPTOR
    }

    /// Derives the only provider request shape accepted by V1.
    #[must_use]
    pub fn provider_request(&self) -> PaymentCaptureProviderRequest {
        PaymentCaptureProviderRequest {
            payment_intent_id: self.action().payment_intent_id().to_string(),
            amount_to_capture_minor: self.action().amount_to_capture_minor(),
            final_capture: true,
            statement_descriptor_suffix: self.statement_descriptor().into(),
            profile: self.action().profile().into(),
            order_scope: self.action().order_scope().into(),
            policy_digest: self.policy_digest.to_string(),
            workflow_id: self.workflow_id.clone(),
            authorization_reservation_id: self.action().authorization_reservation_id().to_string(),
        }
    }
}

/// Capture-owned public provider projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCaptureProviderProjection {
    /// Exact existing `PaymentIntent`.
    pub payment_intent_id: PaymentIntentId,
    /// Exact Charge linked before and after capture.
    pub charge_id: ChargeId,
    /// Balance transaction created by settlement, when observed.
    pub balance_transaction_id: Option<String>,
    /// Normalized post-capture status.
    pub status: String,
    /// Original authorized amount.
    pub authorized_amount_minor: u64,
    /// Amount settled by this final capture.
    pub captured_amount_minor: u64,
    /// Exact currency.
    pub currency: Currency,
    /// Remaining capturable amount after the provider effect.
    pub amount_capturable_minor: u64,
    /// Total received amount after the provider effect.
    pub amount_received_minor: u64,
    /// Prior authorization expiry, when retained by Stripe.
    pub capture_before: Option<u64>,
    /// Stripe request correlation, never a secret.
    pub stripe_request_id: Option<String>,
    /// Commitment to the bounded sanitized provider response.
    pub response_digest: DigestHex,
    /// Observation time.
    pub observed_at: u64,
    /// Capture response, retrieval, or webhook.
    pub source: String,
}

/// Normalized result of one exact capture request.
pub enum PaymentCaptureEffect {
    /// Stripe accepted and returned one bounded response.
    Accepted(PaymentCaptureProviderProjection),
    /// Stripe definitively declined without settlement.
    Declined {
        /// Stable, non-secret provider category.
        code: String,
    },
    /// Adapter proved no capture request was delivered to Stripe.
    NotDelivered {
        /// Stable non-secret transport category.
        code: String,
    },
    /// Delivery or response was ambiguous.
    OutcomeUnknown(Option<PaymentCaptureProviderProjection>),
}

/// Closed events in the exact final-capture lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentCaptureTransition {
    /// Exact verified command claims a new settlement reservation.
    Claim,
    /// Provider delivery is about to begin.
    BeginAttempt,
    /// A bounded provider response is durably accepted.
    ProviderAccepted,
    /// Observation proves capture and closes the linked hold.
    CaptureCommitted,
    /// Definite non-execution returns only settlement capacity.
    DefiniteFailureReleased,
    /// Provider delivery or state is ambiguous.
    OutcomeBecameUnknown,
    /// Retrieval proves capture and closes the linked hold.
    ReconcileCommitted,
    /// Retrieval proves definite non-execution.
    ReconcileReleased,
    /// Retrieval remains ambiguous.
    ReconcileStillUnknown,
}

/// Returns the only legal next state for exact final capture.
#[must_use]
pub const fn transition_payment_capture(
    current: MerchantReservationState,
    event: PaymentCaptureTransition,
) -> Option<MerchantReservationState> {
    use MerchantReservationState::{
        Attempting, Claimed, OutcomeUnknown, ProviderAccepted, Reserved,
    };
    use PaymentCaptureTransition::{
        BeginAttempt, CaptureCommitted, Claim, DefiniteFailureReleased, OutcomeBecameUnknown,
        ProviderAccepted as ProviderAcceptedEvent, ReconcileCommitted, ReconcileReleased,
        ReconcileStillUnknown,
    };

    match (current, event) {
        (Reserved, Claim) => Some(Claimed),
        (Claimed, BeginAttempt) => Some(Attempting),
        (Attempting | ProviderAccepted, ProviderAcceptedEvent) => Some(ProviderAccepted),
        (ProviderAccepted, CaptureCommitted) => Some(MerchantReservationState::CaptureCommitted),
        (Reserved | Claimed | Attempting, DefiniteFailureReleased) => {
            Some(MerchantReservationState::Released)
        }
        (Claimed | Attempting | ProviderAccepted, OutcomeBecameUnknown)
        | (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileStillUnknown,
        ) => Some(OutcomeUnknown),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileCommitted,
        ) => Some(MerchantReservationState::ReconciledCaptureCommitted),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileReleased,
        ) => Some(MerchantReservationState::ReconciledReleased),
        _ => None,
    }
}

/// Fresh Stripe facts used to reconcile one exact final capture.
pub enum PaymentCaptureReconciliationOutcome {
    /// Retrieval proves the final capture committed.
    Committed(PaymentCaptureProviderProjection),
    /// Retrieval proves no capture executed.
    Released(Option<PaymentCaptureProviderProjection>),
    /// Retrieval cannot establish execution or non-execution.
    OutcomeUnknown(Option<PaymentCaptureProviderProjection>),
}

/// Only Stripe provider surface reachable by a verified final-capture command.
pub trait PaymentCaptureGateway: Send + Sync {
    /// Re-reads `PaymentIntent`, Charge, window, amounts, and linked hold facts.
    ///
    /// # Errors
    ///
    /// Returns a closed credential, provider, or evidence failure.
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEvidenceV1, PortError>;

    /// Captures the exact existing `PaymentIntent` once.
    ///
    /// # Errors
    ///
    /// Ambiguous delivery is represented by [`PaymentCaptureEffect::OutcomeUnknown`].
    fn capture(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEffect, PortError>;

    /// Retrieves `PaymentIntent`, Charge, and balance transaction after acceptance.
    ///
    /// # Errors
    ///
    /// Returns a closed retrieval or projection failure.
    fn observe(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureProviderProjection, PortError>;

    /// Reconciles durable state without issuing another capture request.
    ///
    /// # Errors
    ///
    /// Returns a closed retrieval or projection failure.
    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureReconciliationOutcome, PortError>;
}

impl<T: PaymentCaptureGateway + ?Sized> PaymentCaptureGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }

    fn capture(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureEffect, PortError> {
        (**self).capture(command, credential, now)
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCaptureCommand,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureProviderProjection, PortError> {
        (**self).observe(command, credential, now)
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCaptureCredential,
        now: u64,
    ) -> Result<PaymentCaptureReconciliationOutcome, PortError> {
        (**self).reconcile(record, credential, now)
    }
}

/// Protected Connect header for the capture adapter.
#[must_use]
#[allow(
    dead_code,
    reason = "the standalone demo currently exercises platform-account capture only"
)]
pub fn connected_account_header(connect: &MerchantConnectAccount) -> Option<&StripeAccountId> {
    connect.connected_account_id()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_transition_is_closed_and_profile_owned() {
        assert_eq!(
            transition_payment_capture(
                MerchantReservationState::Reserved,
                PaymentCaptureTransition::Claim,
            ),
            Some(MerchantReservationState::Claimed)
        );
        assert_eq!(
            transition_payment_capture(
                MerchantReservationState::ProviderAccepted,
                PaymentCaptureTransition::ProviderAccepted,
            ),
            Some(MerchantReservationState::ProviderAccepted)
        );
        assert_eq!(
            transition_payment_capture(
                MerchantReservationState::ProviderAccepted,
                PaymentCaptureTransition::CaptureCommitted,
            ),
            Some(MerchantReservationState::CaptureCommitted)
        );
        assert_eq!(
            transition_payment_capture(
                MerchantReservationState::CaptureCommitted,
                PaymentCaptureTransition::ReconcileReleased,
            ),
            None
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    // Compile-time completeness guard: adding a `MerchantReservationState`
    // variant fails to compile here, which forces `arbitrary_state` to be
    // extended instead of silently under-sampling the state space. Omitted
    // states are exactly how an illegal edge stays invisible to a harness whose
    // name claims to quantify over all of them.
    const fn state_index(state: MerchantReservationState) -> u8 {
        use MerchantReservationState as S;
        match state {
            S::Reserved => 0,
            S::Claimed => 1,
            S::Attempting => 2,
            S::ProviderAccepted => 3,
            S::Committed => 4,
            S::Authorized => 5,
            S::Released => 6,
            S::OutcomeUnknown => 7,
            S::ReconciledCommitted => 8,
            S::ReconciledAuthorized => 9,
            S::CaptureCommitted => 10,
            S::ReconciledCaptureCommitted => 11,
            S::CancelCommitted => 12,
            S::ReconciledCancelCommitted => 13,
            S::CancelCaptureConflict => 14,
            S::AuthorizationReleasedByCapture => 15,
            S::AuthorizationReleasedByCancel => 16,
            S::ReconciledReleased => 17,
        }
    }

    // Every `MerchantReservationState` variant must appear here. A generator
    // that omits variants silently exempts those states from every harness
    // below, which is how an illegal edge out of an omitted state would survive.
    fn arbitrary_state() -> MerchantReservationState {
        let state = match kani::any::<u8>() % 18 {
            0 => MerchantReservationState::Reserved,
            1 => MerchantReservationState::Claimed,
            2 => MerchantReservationState::Attempting,
            3 => MerchantReservationState::ProviderAccepted,
            4 => MerchantReservationState::Committed,
            5 => MerchantReservationState::Authorized,
            6 => MerchantReservationState::Released,
            7 => MerchantReservationState::OutcomeUnknown,
            8 => MerchantReservationState::ReconciledCommitted,
            9 => MerchantReservationState::ReconciledAuthorized,
            10 => MerchantReservationState::CaptureCommitted,
            11 => MerchantReservationState::ReconciledCaptureCommitted,
            12 => MerchantReservationState::CancelCommitted,
            13 => MerchantReservationState::ReconciledCancelCommitted,
            14 => MerchantReservationState::CancelCaptureConflict,
            15 => MerchantReservationState::AuthorizationReleasedByCapture,
            16 => MerchantReservationState::AuthorizationReleasedByCancel,
            _ => MerchantReservationState::ReconciledReleased,
        };
        // Tripwire, not a constraint: `state_index` is always in range, so this
        // never prunes the state space. Its purpose is the exhaustive match in
        // `state_index`, which fails to compile when a variant is added and so
        // forces an author to extend the generator above.
        assert!(state_index(state) < 18);
        state
    }

    #[kani::proof]
    fn capture_commit_requires_provider_acceptance() {
        let state = arbitrary_state();
        let next = transition_payment_capture(state, PaymentCaptureTransition::CaptureCommitted);
        if next.is_some() {
            assert_eq!(state, MerchantReservationState::ProviderAccepted);
            assert_eq!(next, Some(MerchantReservationState::CaptureCommitted));
        }
    }

    #[kani::proof]
    fn provider_acceptance_never_commits_settlement() {
        let state = arbitrary_state();
        // Provider acceptance is a pre-settlement fact. Over the whole state
        // space it may only park the reservation at `ProviderAccepted`; it must
        // never itself produce a committed or reconciled-committed settlement.
        let next = transition_payment_capture(state, PaymentCaptureTransition::ProviderAccepted);
        if let Some(next) = next {
            assert_eq!(next, MerchantReservationState::ProviderAccepted);
            assert!(matches!(
                state,
                MerchantReservationState::Attempting | MerchantReservationState::ProviderAccepted
            ));
        }
    }
}
