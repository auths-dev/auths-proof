//! Closed proof, command, provider, and transition boundaries for creation.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::{
    StripeExactSubscriptionCreateV1, StripeSubscriptionCreateCommand,
    StripeSubscriptionCreateProfile,
};
use crate::{
    ports::{PortError, SubscriptionCreateCredential},
    subscription::{
        SubscriptionCreateEvidenceV1, SubscriptionLiabilityRecord, SubscriptionLiabilityState,
        SubscriptionProviderProjection,
    },
};

pub enum SubscriptionCreateProofDecision {
    Authorized(Box<Authorized<StripeSubscriptionCreateCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait SubscriptionCreateProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCreateProofDecision, PortError>;
}

impl<T: SubscriptionCreateProofVerifier + ?Sized> SubscriptionCreateProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCreateProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkSubscriptionCreateProofVerifier {
    verifier: Verifier,
}

impl SdkSubscriptionCreateProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl SubscriptionCreateProofVerifier for SdkSubscriptionCreateProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCreateProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripeSubscriptionCreateProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => {
                Ok(SubscriptionCreateProofDecision::Authorized(value))
            }
            VerifyResult::Denied(value) => Ok(SubscriptionCreateProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => {
                Ok(SubscriptionCreateProofDecision::Indeterminate {
                    code: value.code().into(),
                })
            }
        }
    }
}

/// Command constructed only after decision persistence, reservation, and claim.
pub struct VerifiedSubscriptionCreateCommand {
    authorized: Authorized<StripeSubscriptionCreateCommand>,
    workflow_id: String,
    evidence: SubscriptionCreateEvidenceV1,
    liability: SubscriptionLiabilityRecord,
    idempotency_key: String,
}

impl VerifiedSubscriptionCreateCommand {
    pub(crate) fn new(
        authorized: Authorized<StripeSubscriptionCreateCommand>,
        workflow_id: String,
        evidence: SubscriptionCreateEvidenceV1,
        liability: SubscriptionLiabilityRecord,
    ) -> Self {
        let idempotency_key = format!("auths-sub-create-{}", liability.liability_id());
        Self {
            authorized,
            workflow_id,
            evidence,
            liability,
            idempotency_key,
        }
    }
    pub fn action(&self) -> &StripeExactSubscriptionCreateV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn evidence(&self) -> &SubscriptionCreateEvidenceV1 {
        &self.evidence
    }
    pub const fn liability(&self) -> &SubscriptionLiabilityRecord {
        &self.liability
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
}

pub enum SubscriptionCreateEffect {
    Active(SubscriptionProviderProjection),
    Trialing(SubscriptionProviderProjection),
    Incomplete(SubscriptionProviderProjection),
    IncompleteExpired(SubscriptionProviderProjection),
    KnownFailure {
        code: String,
        projection: Option<SubscriptionProviderProjection>,
    },
    OutcomeUnknown(Option<SubscriptionProviderProjection>),
}

pub enum SubscriptionCreateReconciliationOutcome {
    Active(SubscriptionProviderProjection),
    Trialing(SubscriptionProviderProjection),
    Incomplete(SubscriptionProviderProjection),
    IncompleteExpired(SubscriptionProviderProjection),
    KnownNoEffect,
    StillUnknown(Option<SubscriptionProviderProjection>),
}

/// Subscription-create-only Stripe Billing surface.
pub trait SubscriptionCreateGateway: Send + Sync {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEvidenceV1, PortError>;

    fn create(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEffect, PortError>;

    fn reconcile(
        &self,
        liability: &SubscriptionLiabilityRecord,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateReconciliationOutcome, PortError>;
}

impl<T: SubscriptionCreateGateway + ?Sized> SubscriptionCreateGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }
    fn create(
        &self,
        command: &VerifiedSubscriptionCreateCommand,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateEffect, PortError> {
        (**self).create(command, credential, now)
    }
    fn reconcile(
        &self,
        liability: &SubscriptionLiabilityRecord,
        credential: &SubscriptionCreateCredential,
        now: u64,
    ) -> Result<SubscriptionCreateReconciliationOutcome, PortError> {
        (**self).reconcile(liability, credential, now)
    }
}

/// Create-owned events; no operation tag enters this transition kernel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionCreateTransition {
    Claim,
    BeginAttempt,
    ProviderActive,
    ProviderTrialing,
    ProviderIncomplete,
    ProviderIncompleteExpired,
    KnownFailureReleased,
    OutcomeBecameUnknown,
    ReconcileActive,
    ReconcileTrialing,
    ReconcileIncomplete,
    ReconcileIncompleteExpired,
    ReconcileNoEffect,
    ReconcileStillUnknown,
}

#[must_use]
#[allow(
    clippy::match_same_arms,
    reason = "the explicit event relation is the review surface"
)]
pub const fn transition_subscription_create(
    state: SubscriptionLiabilityState,
    event: SubscriptionCreateTransition,
) -> Option<SubscriptionLiabilityState> {
    use SubscriptionCreateTransition as Event;
    use SubscriptionLiabilityState as State;
    match (state, event) {
        (State::Reserved, Event::Claim) => Some(State::Claimed),
        (State::Claimed, Event::BeginAttempt) => Some(State::Attempting),
        (State::Attempting, Event::ProviderActive) => Some(State::Active),
        (State::Attempting, Event::ProviderTrialing) => Some(State::Trialing),
        (State::Attempting, Event::ProviderIncomplete) => Some(State::Incomplete),
        (State::Attempting, Event::ProviderIncompleteExpired) => Some(State::IncompleteExpired),
        (State::Claimed | State::Attempting, Event::KnownFailureReleased) => Some(State::Released),
        (State::Attempting, Event::OutcomeBecameUnknown) => Some(State::OutcomeUnknown),
        (State::OutcomeUnknown | State::Incomplete, Event::ReconcileActive) => Some(State::Active),
        (State::OutcomeUnknown | State::Incomplete, Event::ReconcileTrialing) => {
            Some(State::Trialing)
        }
        (State::OutcomeUnknown | State::Incomplete, Event::ReconcileIncomplete) => {
            Some(State::Incomplete)
        }
        (State::OutcomeUnknown | State::Incomplete, Event::ReconcileIncompleteExpired) => {
            Some(State::IncompleteExpired)
        }
        (State::OutcomeUnknown, Event::ReconcileNoEffect) => Some(State::Released),
        (State::OutcomeUnknown | State::Incomplete, Event::ReconcileStillUnknown) => Some(state),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_transition_is_closed_and_holds_ambiguity() {
        assert_eq!(
            transition_subscription_create(
                SubscriptionLiabilityState::Attempting,
                SubscriptionCreateTransition::OutcomeBecameUnknown
            ),
            Some(SubscriptionLiabilityState::OutcomeUnknown)
        );
        assert_eq!(
            transition_subscription_create(
                SubscriptionLiabilityState::Active,
                SubscriptionCreateTransition::KnownFailureReleased
            ),
            None
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_event() -> SubscriptionCreateTransition {
        match kani::any::<u8>() % 14 {
            0 => SubscriptionCreateTransition::Claim,
            1 => SubscriptionCreateTransition::BeginAttempt,
            2 => SubscriptionCreateTransition::ProviderActive,
            3 => SubscriptionCreateTransition::ProviderTrialing,
            4 => SubscriptionCreateTransition::ProviderIncomplete,
            5 => SubscriptionCreateTransition::ProviderIncompleteExpired,
            6 => SubscriptionCreateTransition::KnownFailureReleased,
            7 => SubscriptionCreateTransition::OutcomeBecameUnknown,
            8 => SubscriptionCreateTransition::ReconcileActive,
            9 => SubscriptionCreateTransition::ReconcileTrialing,
            10 => SubscriptionCreateTransition::ReconcileIncomplete,
            11 => SubscriptionCreateTransition::ReconcileIncompleteExpired,
            12 => SubscriptionCreateTransition::ReconcileNoEffect,
            _ => SubscriptionCreateTransition::ReconcileStillUnknown,
        }
    }

    #[kani::proof]
    fn terminal_success_never_releases_liability() {
        let event = any_event();
        let next = transition_subscription_create(SubscriptionLiabilityState::Active, event);
        assert!(next.is_none());
    }

    #[kani::proof]
    fn ambiguous_outcome_cannot_become_released_without_reconciliation_fact() {
        let event = any_event();
        let next =
            transition_subscription_create(SubscriptionLiabilityState::OutcomeUnknown, event);
        if next == Some(SubscriptionLiabilityState::Released) {
            assert!(matches!(
                event,
                SubscriptionCreateTransition::ReconcileNoEffect
            ));
        }
    }
}
