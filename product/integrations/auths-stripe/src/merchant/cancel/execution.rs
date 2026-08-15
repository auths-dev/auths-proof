//! Narrow protected effect boundary for one exact cancellation.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};
use serde::{Deserialize, Serialize};

use super::{
    action::PaymentCancellationReason,
    evidence::PaymentCancelEvidenceV1,
    profile::{StripePaymentCancelCommand, StripePaymentCancelProfile},
};
use crate::{
    merchant::{MerchantReservationRecord, MerchantReservationState, StripeExactPaymentCancelV1},
    ports::{PaymentCancelCredential, PortError},
    types::{ChargeId, Currency, DigestHex, PaymentIntentId},
};

/// Exact cancellation proof-verification result.
pub enum PaymentCancelProofDecision {
    Authorized(Box<Authorized<StripePaymentCancelCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

/// Auths kernel boundary fixed to the exact cancellation profile.
pub trait PaymentCancelProofVerifier: Send + Sync {
    /// Verifies exact cancellation authority.
    ///
    /// # Errors
    ///
    /// Returns a closed verification-port failure.
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCancelProofDecision, PortError>;
}

impl<T: PaymentCancelProofVerifier + ?Sized> PaymentCancelProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCancelProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

/// SDK adapter fixed to `auths.stripe.exact-payment-cancel/1`.
pub struct SdkPaymentCancelProofVerifier {
    verifier: Verifier,
}

impl SdkPaymentCancelProofVerifier {
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PaymentCancelProofVerifier for SdkPaymentCancelProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentCancelProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePaymentCancelProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => {
                Ok(PaymentCancelProofDecision::Authorized(authorized))
            }
            VerifyResult::Denied(explanation) => Ok(PaymentCancelProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => {
                Ok(PaymentCancelProofDecision::Indeterminate {
                    code: explanation.code().into(),
                })
            }
        }
    }
}

/// Protected pre-provider cancellation command.
pub struct VerifiedPaymentCancelCommand {
    authorized: Authorized<StripePaymentCancelCommand>,
    workflow_id: String,
    evidence: PaymentCancelEvidenceV1,
    policy_digest: DigestHex,
    reservation_id: DigestHex,
    decision_receipt_digest: DigestHex,
    required_configuration_digest: DigestHex,
    executed_configuration_digest: DigestHex,
    idempotency_key: String,
}

/// Closed provider request derived only from a verified cancellation command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentCancelProviderRequest {
    payment_intent_id: String,
    cancellation_reason: PaymentCancellationReason,
    profile: String,
    workflow_id: String,
    authorization_reservation_id: Option<String>,
}

impl PaymentCancelProviderRequest {
    #[must_use]
    pub fn payment_intent_id(&self) -> &str {
        &self.payment_intent_id
    }

    #[must_use]
    pub const fn cancellation_reason(&self) -> PaymentCancellationReason {
        self.cancellation_reason
    }

    #[must_use]
    pub fn profile(&self) -> &str {
        &self.profile
    }

    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    #[must_use]
    pub fn authorization_reservation_id(&self) -> Option<&str> {
        self.authorization_reservation_id.as_deref()
    }
}

impl VerifiedPaymentCancelCommand {
    #[allow(
        clippy::too_many_arguments,
        reason = "the private constructor binds every completed trust-boundary fact"
    )]
    pub(crate) fn new(
        authorized: Authorized<StripePaymentCancelCommand>,
        workflow_id: String,
        evidence: PaymentCancelEvidenceV1,
        policy_digest: DigestHex,
        reservation_id: DigestHex,
        decision_receipt_digest: DigestHex,
        required_configuration_digest: DigestHex,
        executed_configuration_digest: DigestHex,
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
            idempotency_key,
        }
    }

    #[must_use]
    pub fn action(&self) -> &StripeExactPaymentCancelV1 {
        self.authorized.command().action()
    }

    #[must_use]
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }

    #[must_use]
    pub const fn evidence(&self) -> &PaymentCancelEvidenceV1 {
        &self.evidence
    }

    #[must_use]
    pub const fn policy_digest(&self) -> &DigestHex {
        &self.policy_digest
    }

    #[must_use]
    pub const fn reservation_id(&self) -> &DigestHex {
        &self.reservation_id
    }

    #[must_use]
    pub const fn decision_receipt_digest(&self) -> &DigestHex {
        &self.decision_receipt_digest
    }

    #[must_use]
    pub const fn required_configuration_digest(&self) -> &DigestHex {
        &self.required_configuration_digest
    }

    #[must_use]
    pub const fn executed_configuration_digest(&self) -> &DigestHex {
        &self.executed_configuration_digest
    }

    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }

    #[must_use]
    pub fn provider_request(&self) -> PaymentCancelProviderRequest {
        PaymentCancelProviderRequest {
            payment_intent_id: self.action().payment_intent_id().to_string(),
            cancellation_reason: self.action().cancellation_reason(),
            profile: self.action().profile().into(),
            workflow_id: self.workflow_id.clone(),
            authorization_reservation_id: self
                .action()
                .authorization_reservation_id()
                .map(ToString::to_string),
        }
    }
}

/// Cancellation-owned provider projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentCancelProviderProjection {
    pub payment_intent_id: PaymentIntentId,
    pub latest_charge_id: Option<ChargeId>,
    pub status: String,
    pub cancellation_reason: Option<PaymentCancellationReason>,
    pub amount_minor: u64,
    pub amount_capturable_minor: u64,
    pub amount_received_minor: u64,
    pub currency: Currency,
    pub charge_captured: Option<bool>,
    pub stripe_request_id: Option<String>,
    pub response_digest: DigestHex,
    pub observed_at: u64,
    pub source: String,
}

/// Normalized result of one exact cancellation request.
pub enum PaymentCancelEffect {
    Accepted(PaymentCancelProviderProjection),
    Declined {
        code: String,
    },
    NotDelivered {
        code: String,
    },
    OutcomeUnknown(Option<PaymentCancelProviderProjection>),
    /// A capture won the race; cancellation must not be retried.
    CaptureConflict(PaymentCancelProviderProjection),
}

/// Closed events in the exact cancellation lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentCancelTransition {
    Claim,
    BeginAttempt,
    ProviderAccepted,
    CancelObserved,
    DefiniteFailureReleased,
    OutcomeBecameUnknown,
    CaptureConflictObserved,
    ReconcileCanceled,
    ReconcileReleased,
    ReconcileCaptureConflict,
    ReconcileStillUnknown,
}

/// Returns the only legal next state for exact cancellation.
#[must_use]
pub const fn transition_payment_cancel(
    current: MerchantReservationState,
    event: PaymentCancelTransition,
) -> Option<MerchantReservationState> {
    use MerchantReservationState::{
        Attempting, Claimed, OutcomeUnknown, ProviderAccepted, Reserved,
    };
    use PaymentCancelTransition::{
        BeginAttempt, CancelObserved, CaptureConflictObserved, Claim, DefiniteFailureReleased,
        OutcomeBecameUnknown, ProviderAccepted as ProviderAcceptedEvent, ReconcileCanceled,
        ReconcileCaptureConflict, ReconcileReleased, ReconcileStillUnknown,
    };
    match (current, event) {
        (Reserved, Claim) => Some(Claimed),
        (Claimed, BeginAttempt) => Some(Attempting),
        (Attempting | ProviderAccepted, ProviderAcceptedEvent) => Some(ProviderAccepted),
        (ProviderAccepted, CancelObserved) => Some(MerchantReservationState::CancelCommitted),
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
            CaptureConflictObserved | ReconcileCaptureConflict,
        ) => Some(MerchantReservationState::CancelCaptureConflict),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileCanceled,
        ) => Some(MerchantReservationState::ReconciledCancelCommitted),
        (
            Reserved | Claimed | Attempting | ProviderAccepted | OutcomeUnknown,
            ReconcileReleased,
        ) => Some(MerchantReservationState::ReconciledReleased),
        _ => None,
    }
}

/// Fresh Stripe facts used to reconcile one exact cancellation.
pub enum PaymentCancelReconciliationOutcome {
    Canceled(PaymentCancelProviderProjection),
    Released(Option<PaymentCancelProviderProjection>),
    CaptureConflict(PaymentCancelProviderProjection),
    OutcomeUnknown(Option<PaymentCancelProviderProjection>),
}

/// Only provider surface reachable by a verified cancellation command.
pub trait PaymentCancelGateway: Send + Sync {
    /// Re-reads the critical target facts before cancellation delivery.
    ///
    /// # Errors
    ///
    /// Returns a closed Stripe-port failure.
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEvidenceV1, PortError>;

    /// Sends one exact cancellation request.
    ///
    /// # Errors
    ///
    /// Returns a closed Stripe-port failure.
    fn cancel(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEffect, PortError>;

    /// Retrieves the provider state after a cancellation response.
    ///
    /// # Errors
    ///
    /// Returns a closed Stripe-port failure.
    fn observe(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelProviderProjection, PortError>;

    /// Retrieves state to reconcile an ambiguous cancellation without repeating it.
    ///
    /// # Errors
    ///
    /// Returns a closed Stripe-port failure.
    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelReconciliationOutcome, PortError>;
}

impl<T: PaymentCancelGateway + ?Sized> PaymentCancelGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }

    fn cancel(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelEffect, PortError> {
        (**self).cancel(command, credential, now)
    }

    fn observe(
        &self,
        command: &VerifiedPaymentCancelCommand,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelProviderProjection, PortError> {
        (**self).observe(command, credential, now)
    }

    fn reconcile(
        &self,
        record: &MerchantReservationRecord,
        credential: &PaymentCancelCredential,
        now: u64,
    ) -> Result<PaymentCancelReconciliationOutcome, PortError> {
        (**self).reconcile(record, credential, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_transition_is_closed_and_profile_owned() {
        assert_eq!(
            transition_payment_cancel(
                MerchantReservationState::Reserved,
                PaymentCancelTransition::Claim,
            ),
            Some(MerchantReservationState::Claimed)
        );
        assert_eq!(
            transition_payment_cancel(
                MerchantReservationState::ProviderAccepted,
                PaymentCancelTransition::CancelObserved,
            ),
            Some(MerchantReservationState::CancelCommitted)
        );
        assert_eq!(
            transition_payment_cancel(
                MerchantReservationState::CancelCommitted,
                PaymentCancelTransition::ReconcileReleased,
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
    fn terminal_cancel_commit_requires_provider_acceptance() {
        let state = arbitrary_state();
        let next = transition_payment_cancel(state, PaymentCancelTransition::CancelObserved);
        if next.is_some() {
            assert_eq!(state, MerchantReservationState::ProviderAccepted);
            assert_eq!(next, Some(MerchantReservationState::CancelCommitted));
        }
    }

    #[kani::proof]
    fn capture_conflict_never_becomes_a_cancel_commit() {
        let state = arbitrary_state();
        let next =
            transition_payment_cancel(state, PaymentCancelTransition::CaptureConflictObserved);
        if let Some(next) = next {
            assert_eq!(next, MerchantReservationState::CancelCaptureConflict);
            assert_ne!(next, MerchantReservationState::CancelCommitted);
        }
    }
}
