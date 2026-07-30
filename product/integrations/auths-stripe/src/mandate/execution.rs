//! Closed proof and `SetupIntent` provider boundaries for mandates.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};
use serde::{Deserialize, Serialize};

use super::{
    PaymentConsentEvidenceV1, PaymentMandateCapabilityRecord, PaymentMandateCapabilityState,
    PaymentMandateEvidenceV1, StripeExactPaymentMandateV1, StripePaymentMandateCommand,
    StripePaymentMandateProfile,
};
use crate::{
    ports::{PaymentMandateCredential, PortError},
    types::{CustomerId, DigestHex, MandateId, PaymentMethodId, SetupAttemptId, SetupIntentId},
};

/// Exact proof-verification result.
pub enum PaymentMandateProofDecision {
    Authorized(Box<Authorized<StripePaymentMandateCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

/// Auths verifier fixed to the mandate profile.
pub trait PaymentMandateProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentMandateProofDecision, PortError>;
}

impl<T: PaymentMandateProofVerifier + ?Sized> PaymentMandateProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentMandateProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

/// SDK verifier adapter fixed to `auths.stripe.exact-payment-mandate/1`.
pub struct SdkPaymentMandateProofVerifier {
    verifier: Verifier,
}

impl SdkPaymentMandateProofVerifier {
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PaymentMandateProofVerifier for SdkPaymentMandateProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PaymentMandateProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePaymentMandateProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => Ok(PaymentMandateProofDecision::Authorized(value)),
            VerifyResult::Denied(value) => Ok(PaymentMandateProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => Ok(PaymentMandateProofDecision::Indeterminate {
                code: value.code().into(),
            }),
        }
    }
}

/// Protected command created only after proof, evaluation, reservation, and claim.
pub struct VerifiedPaymentMandateCommand {
    authorized: Authorized<StripePaymentMandateCommand>,
    workflow_id: String,
    consent: PaymentConsentEvidenceV1,
    evidence: PaymentMandateEvidenceV1,
    capability: PaymentMandateCapabilityRecord,
    idempotency_key: String,
}

impl VerifiedPaymentMandateCommand {
    pub(crate) fn new(
        authorized: Authorized<StripePaymentMandateCommand>,
        workflow_id: String,
        consent: PaymentConsentEvidenceV1,
        evidence: PaymentMandateEvidenceV1,
        capability: PaymentMandateCapabilityRecord,
    ) -> Self {
        let idempotency_key = format!("auths-mandate-{}", capability.capability_id());
        Self {
            authorized,
            workflow_id,
            consent,
            evidence,
            capability,
            idempotency_key,
        }
    }

    pub fn action(&self) -> &StripeExactPaymentMandateV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn consent(&self) -> &PaymentConsentEvidenceV1 {
        &self.consent
    }
    pub const fn evidence(&self) -> &PaymentMandateEvidenceV1 {
        &self.evidence
    }
    pub const fn capability(&self) -> &PaymentMandateCapabilityRecord {
        &self.capability
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

/// Sanitized provider projection. The `SetupIntent` client secret is absent by type.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentMandateProviderProjection {
    pub setup_intent_id: SetupIntentId,
    pub latest_setup_attempt_id: Option<SetupAttemptId>,
    pub mandate_id: Option<MandateId>,
    pub customer_id: CustomerId,
    pub payment_method_id: PaymentMethodId,
    pub usage: String,
    pub status: String,
    pub livemode: bool,
    pub stripe_request_id: Option<String>,
    pub response_digest: DigestHex,
    pub observed_at: u64,
    pub source: String,
}

/// Normalized create+confirm result.
pub enum PaymentMandateEffect {
    Succeeded(PaymentMandateProviderProjection),
    CustomerActionRequired(PaymentMandateProviderProjection),
    Processing(PaymentMandateProviderProjection),
    KnownFailure {
        code: String,
        projection: Option<PaymentMandateProviderProjection>,
    },
    OutcomeUnknown(Option<PaymentMandateProviderProjection>),
}

/// Normalized reconciliation result.
pub enum PaymentMandateReconciliationOutcome {
    Succeeded(PaymentMandateProviderProjection),
    CustomerActionRequired(PaymentMandateProviderProjection),
    KnownFailure(PaymentMandateProviderProjection),
    StillUnknown(Option<PaymentMandateProviderProjection>),
}

/// Mandate-only provider surface.
pub trait PaymentMandateGateway: Send + Sync {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEvidenceV1, PortError>;

    fn create_and_confirm(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEffect, PortError>;

    fn reconcile(
        &self,
        capability: &PaymentMandateCapabilityRecord,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateReconciliationOutcome, PortError>;
}

impl<T: PaymentMandateGateway + ?Sized> PaymentMandateGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }

    fn create_and_confirm(
        &self,
        command: &VerifiedPaymentMandateCommand,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateEffect, PortError> {
        (**self).create_and_confirm(command, credential, now)
    }

    fn reconcile(
        &self,
        capability: &PaymentMandateCapabilityRecord,
        credential: &PaymentMandateCredential,
        now: u64,
    ) -> Result<PaymentMandateReconciliationOutcome, PortError> {
        (**self).reconcile(capability, credential, now)
    }
}

/// Closed semantic events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PaymentMandateTransition {
    Claim,
    BeginAttempt,
    ProviderSucceeded,
    KnownFailureReleased,
    OutcomeBecameUnknown,
    CustomerActionRequired,
    ReconcileSucceeded,
    ReconcileReleased,
    ReconcileStillUnknown,
}

/// Pure transition kernel.
#[must_use]
pub const fn transition_payment_mandate(
    state: PaymentMandateCapabilityState,
    event: PaymentMandateTransition,
) -> Option<PaymentMandateCapabilityState> {
    use PaymentMandateCapabilityState as State;
    use PaymentMandateTransition as Event;
    match (state, event) {
        (State::Reserved, Event::Claim) => Some(State::Claimed),
        (State::Claimed, Event::BeginAttempt) => Some(State::Attempting),
        (State::Claimed | State::Attempting, Event::KnownFailureReleased) => Some(State::Released),
        (State::Attempting, Event::ProviderSucceeded) => Some(State::Committed),
        (State::Attempting, Event::OutcomeBecameUnknown) => Some(State::OutcomeUnknown),
        (State::Attempting, Event::CustomerActionRequired) => Some(State::CustomerActionRequired),
        (State::OutcomeUnknown | State::CustomerActionRequired, Event::ReconcileSucceeded) => {
            Some(State::Committed)
        }
        (State::OutcomeUnknown | State::CustomerActionRequired, Event::ReconcileReleased) => {
            Some(State::Released)
        }
        (State::OutcomeUnknown | State::CustomerActionRequired, Event::ReconcileStillUnknown) => {
            Some(state)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_and_customer_action_hold_the_capability_slot() {
        assert_eq!(
            transition_payment_mandate(
                PaymentMandateCapabilityState::Attempting,
                PaymentMandateTransition::OutcomeBecameUnknown,
            ),
            Some(PaymentMandateCapabilityState::OutcomeUnknown)
        );
        assert!(PaymentMandateCapabilityState::OutcomeUnknown.consumes_slot());
        assert!(PaymentMandateCapabilityState::CustomerActionRequired.consumes_slot());
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn unknown_never_releases_capability() {
        let state = transition_payment_mandate(
            PaymentMandateCapabilityState::Attempting,
            PaymentMandateTransition::OutcomeBecameUnknown,
        )
        .unwrap();
        assert_eq!(state, PaymentMandateCapabilityState::OutcomeUnknown);
        assert!(state.consumes_slot());
    }

    #[kani::proof]
    fn only_success_commits_attempting_capability() {
        let event = match kani::any::<u8>() % 9 {
            0 => PaymentMandateTransition::Claim,
            1 => PaymentMandateTransition::BeginAttempt,
            2 => PaymentMandateTransition::ProviderSucceeded,
            3 => PaymentMandateTransition::KnownFailureReleased,
            4 => PaymentMandateTransition::OutcomeBecameUnknown,
            5 => PaymentMandateTransition::CustomerActionRequired,
            6 => PaymentMandateTransition::ReconcileSucceeded,
            7 => PaymentMandateTransition::ReconcileReleased,
            _ => PaymentMandateTransition::ReconcileStillUnknown,
        };
        let next = transition_payment_mandate(PaymentMandateCapabilityState::Attempting, event);
        if next == Some(PaymentMandateCapabilityState::Committed) {
            assert_eq!(event, PaymentMandateTransition::ProviderSucceeded);
        }
    }
}
