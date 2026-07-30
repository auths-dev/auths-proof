//! Closed proof, command, provider, and transition boundaries for modification.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::{
    StripeExactSubscriptionModifyV1, StripeSubscriptionModifyCommand,
    StripeSubscriptionModifyProfile, SubscriptionModificationRecord, SubscriptionModificationState,
    SubscriptionModifyEvidenceV1, SubscriptionModifyProviderProjection,
};
use crate::ports::{PortError, SubscriptionModifyCredential};

pub enum SubscriptionModifyProofDecision {
    Authorized(Box<Authorized<StripeSubscriptionModifyCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait SubscriptionModifyProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionModifyProofDecision, PortError>;
}

impl<T: SubscriptionModifyProofVerifier + ?Sized> SubscriptionModifyProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionModifyProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkSubscriptionModifyProofVerifier {
    verifier: Verifier,
}

impl SdkSubscriptionModifyProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl SubscriptionModifyProofVerifier for SdkSubscriptionModifyProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionModifyProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripeSubscriptionModifyProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => {
                Ok(SubscriptionModifyProofDecision::Authorized(value))
            }
            VerifyResult::Denied(value) => Ok(SubscriptionModifyProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => {
                Ok(SubscriptionModifyProofDecision::Indeterminate {
                    code: value.code().into(),
                })
            }
        }
    }
}

/// Constructed only after decision persistence, atomic reservation, and claim.
pub struct VerifiedSubscriptionModifyCommand {
    authorized: Authorized<StripeSubscriptionModifyCommand>,
    workflow_id: String,
    evidence: SubscriptionModifyEvidenceV1,
    modification: SubscriptionModificationRecord,
    idempotency_key: String,
}

impl VerifiedSubscriptionModifyCommand {
    pub(crate) fn new(
        authorized: Authorized<StripeSubscriptionModifyCommand>,
        workflow_id: String,
        evidence: SubscriptionModifyEvidenceV1,
        modification: SubscriptionModificationRecord,
    ) -> Self {
        let idempotency_key = format!("auths-sub-modify-{}", modification.transition_id());
        Self {
            authorized,
            workflow_id,
            evidence,
            modification,
            idempotency_key,
        }
    }
    pub fn action(&self) -> &StripeExactSubscriptionModifyV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn evidence(&self) -> &SubscriptionModifyEvidenceV1 {
        &self.evidence
    }
    pub const fn modification(&self) -> &SubscriptionModificationRecord {
        &self.modification
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

pub enum SubscriptionModifyEffect {
    Applied(SubscriptionModifyProviderProjection),
    PendingPayment(SubscriptionModifyProviderProjection),
    KnownFailure {
        code: String,
        projection: Option<SubscriptionModifyProviderProjection>,
    },
    OutcomeUnknown(Option<SubscriptionModifyProviderProjection>),
}

pub enum SubscriptionModifyReconciliationOutcome {
    Applied(SubscriptionModifyProviderProjection),
    PendingPayment(SubscriptionModifyProviderProjection),
    ExpiredOrVoided(SubscriptionModifyProviderProjection),
    KnownNoEffect,
    StillUnknown(Option<SubscriptionModifyProviderProjection>),
}

/// Modify-only Stripe Billing surface.
pub trait SubscriptionModifyGateway: Send + Sync {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEvidenceV1, PortError>;

    fn modify(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEffect, PortError>;

    fn reconcile(
        &self,
        modification: &SubscriptionModificationRecord,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyReconciliationOutcome, PortError>;
}

impl<T: SubscriptionModifyGateway + ?Sized> SubscriptionModifyGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }
    fn modify(
        &self,
        command: &VerifiedSubscriptionModifyCommand,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyEffect, PortError> {
        (**self).modify(command, credential, now)
    }
    fn reconcile(
        &self,
        modification: &SubscriptionModificationRecord,
        credential: &SubscriptionModifyCredential,
        now: u64,
    ) -> Result<SubscriptionModifyReconciliationOutcome, PortError> {
        (**self).reconcile(modification, credential, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionModifyTransition {
    Claim,
    BeginAttempt,
    ProviderApplied,
    ProviderPendingPayment,
    KnownFailureReleased,
    OutcomeBecameUnknown,
    ReconcileApplied,
    ReconcilePendingPayment,
    ReconcileExpired,
    ReconcileNoEffect,
    ReconcileStillUnknown,
}

/// Modify-owned transition relation. No operation tag dispatches it.
#[must_use]
#[allow(
    clippy::match_same_arms,
    reason = "the explicit modify-owned transition relation is the review surface"
)]
pub const fn transition_subscription_modify(
    state: SubscriptionModificationState,
    event: SubscriptionModifyTransition,
) -> Option<SubscriptionModificationState> {
    use SubscriptionModificationState as State;
    use SubscriptionModifyTransition as Event;
    match (state, event) {
        (State::Reserved, Event::Claim) => Some(State::Claimed),
        (State::Claimed, Event::BeginAttempt) => Some(State::Attempting),
        (State::Attempting, Event::ProviderApplied) => Some(State::Applied),
        (State::Attempting, Event::ProviderPendingPayment) => Some(State::PendingPayment),
        (State::Claimed | State::Attempting, Event::KnownFailureReleased) => Some(State::Released),
        (State::Attempting, Event::OutcomeBecameUnknown) => Some(State::OutcomeUnknown),
        (State::PendingPayment | State::OutcomeUnknown, Event::ReconcileApplied) => {
            Some(State::Applied)
        }
        (State::PendingPayment | State::OutcomeUnknown, Event::ReconcilePendingPayment) => {
            Some(State::PendingPayment)
        }
        (State::PendingPayment | State::OutcomeUnknown, Event::ReconcileExpired) => {
            Some(State::Expired)
        }
        (State::OutcomeUnknown, Event::ReconcileNoEffect) => Some(State::Released),
        (State::PendingPayment | State::OutcomeUnknown, Event::ReconcileStillUnknown) => {
            Some(state)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subscription::{
        SubscriptionCreateTransition, SubscriptionLiabilityState, transition_subscription_create,
    };

    #[test]
    fn ambiguity_holds_until_fresh_reconciliation() {
        assert_eq!(
            transition_subscription_modify(
                SubscriptionModificationState::Attempting,
                SubscriptionModifyTransition::OutcomeBecameUnknown
            ),
            Some(SubscriptionModificationState::OutcomeUnknown)
        );
        assert_eq!(
            transition_subscription_modify(
                SubscriptionModificationState::OutcomeUnknown,
                SubscriptionModifyTransition::KnownFailureReleased
            ),
            None
        );
    }

    #[test]
    fn create_events_cannot_enter_modify_state_and_modify_events_cannot_enter_create_state() {
        assert_eq!(
            transition_subscription_create(
                SubscriptionLiabilityState::Active,
                SubscriptionCreateTransition::ProviderIncomplete
            ),
            None
        );
        assert_eq!(
            transition_subscription_modify(
                SubscriptionModificationState::Applied,
                SubscriptionModifyTransition::ProviderPendingPayment
            ),
            None
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_event() -> SubscriptionModifyTransition {
        match kani::any::<u8>() % 11 {
            0 => SubscriptionModifyTransition::Claim,
            1 => SubscriptionModifyTransition::BeginAttempt,
            2 => SubscriptionModifyTransition::ProviderApplied,
            3 => SubscriptionModifyTransition::ProviderPendingPayment,
            4 => SubscriptionModifyTransition::KnownFailureReleased,
            5 => SubscriptionModifyTransition::OutcomeBecameUnknown,
            6 => SubscriptionModifyTransition::ReconcileApplied,
            7 => SubscriptionModifyTransition::ReconcilePendingPayment,
            8 => SubscriptionModifyTransition::ReconcileExpired,
            9 => SubscriptionModifyTransition::ReconcileNoEffect,
            _ => SubscriptionModifyTransition::ReconcileStillUnknown,
        }
    }

    #[kani::proof]
    fn applied_is_terminal() {
        assert!(
            transition_subscription_modify(SubscriptionModificationState::Applied, any_event())
                .is_none()
        );
    }

    #[kani::proof]
    fn unknown_releases_only_after_known_no_effect() {
        let event = any_event();
        let next =
            transition_subscription_modify(SubscriptionModificationState::OutcomeUnknown, event);
        if next == Some(SubscriptionModificationState::Released) {
            assert!(matches!(
                event,
                SubscriptionModifyTransition::ReconcileNoEffect
            ));
        }
    }
}
