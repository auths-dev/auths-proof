//! Closed proof, command, gateway, and cancellation transition boundaries.

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::{
    StripeExactSubscriptionCancelV1, StripeSubscriptionCancelCommand,
    StripeSubscriptionCancelProfile, SubscriptionCancelEvidenceV1,
    SubscriptionCancelProviderProjection, SubscriptionCancellationRecord,
    SubscriptionCancellationState,
};
use crate::ports::{PortError, SubscriptionCancelCredential};

pub enum SubscriptionCancelProofDecision {
    Authorized(Box<Authorized<StripeSubscriptionCancelCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait SubscriptionCancelProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCancelProofDecision, PortError>;
}

impl<T: SubscriptionCancelProofVerifier + ?Sized> SubscriptionCancelProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCancelProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkSubscriptionCancelProofVerifier {
    verifier: Verifier,
}

impl SdkSubscriptionCancelProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl SubscriptionCancelProofVerifier for SdkSubscriptionCancelProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<SubscriptionCancelProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripeSubscriptionCancelProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => {
                Ok(SubscriptionCancelProofDecision::Authorized(value))
            }
            VerifyResult::Denied(value) => Ok(SubscriptionCancelProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => {
                Ok(SubscriptionCancelProofDecision::Indeterminate {
                    code: value.code().into(),
                })
            }
        }
    }
}

pub struct VerifiedSubscriptionCancelCommand {
    authorized: Authorized<StripeSubscriptionCancelCommand>,
    workflow_id: String,
    evidence: SubscriptionCancelEvidenceV1,
    cancellation: SubscriptionCancellationRecord,
}

impl VerifiedSubscriptionCancelCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripeSubscriptionCancelCommand>,
        workflow_id: String,
        evidence: SubscriptionCancelEvidenceV1,
        cancellation: SubscriptionCancellationRecord,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            evidence,
            cancellation,
        }
    }
    pub fn action(&self) -> &StripeExactSubscriptionCancelV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn evidence(&self) -> &SubscriptionCancelEvidenceV1 {
        &self.evidence
    }
    pub const fn cancellation(&self) -> &SubscriptionCancellationRecord {
        &self.cancellation
    }
    pub fn idempotency_key(&self) -> String {
        self.cancellation.idempotency_key()
    }
}

pub enum SubscriptionCancelEffect {
    Scheduled(SubscriptionCancelProviderProjection),
    Terminal(SubscriptionCancelProviderProjection),
    KnownFailure { code: String },
    OutcomeUnknown(Option<SubscriptionCancelProviderProjection>),
}

pub enum SubscriptionCancelReconciliationOutcome {
    Scheduled(SubscriptionCancelProviderProjection),
    Terminal(SubscriptionCancelProviderProjection),
    KnownNoEffect,
    StillUnknown(Option<SubscriptionCancelProviderProjection>),
    Conflict(SubscriptionCancelProviderProjection),
}

pub trait SubscriptionCancelGateway: Send + Sync {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionCancelCommand,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelEvidenceV1, PortError>;
    fn cancel(
        &self,
        command: &VerifiedSubscriptionCancelCommand,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelEffect, PortError>;
    fn reconcile(
        &self,
        cancellation: &SubscriptionCancellationRecord,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelReconciliationOutcome, PortError>;
}

impl<T: SubscriptionCancelGateway + ?Sized> SubscriptionCancelGateway for Arc<T> {
    fn reread_critical_evidence(
        &self,
        command: &VerifiedSubscriptionCancelCommand,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelEvidenceV1, PortError> {
        (**self).reread_critical_evidence(command, credential, now)
    }
    fn cancel(
        &self,
        command: &VerifiedSubscriptionCancelCommand,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelEffect, PortError> {
        (**self).cancel(command, credential, now)
    }
    fn reconcile(
        &self,
        cancellation: &SubscriptionCancellationRecord,
        credential: &SubscriptionCancelCredential,
        now: u64,
    ) -> Result<SubscriptionCancelReconciliationOutcome, PortError> {
        (**self).reconcile(cancellation, credential, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubscriptionCancelTransition {
    Claim,
    BeginAttempt,
    ProviderScheduled,
    ProviderTerminal,
    KnownFailure,
    OutcomeUnknown,
    ReconcileScheduled,
    ReconcileTerminal,
    ReconcileNoEffect,
    ReconcileStillUnknown,
}

#[must_use]
pub const fn transition_subscription_cancel(
    state: SubscriptionCancellationState,
    event: SubscriptionCancelTransition,
) -> Option<SubscriptionCancellationState> {
    use SubscriptionCancelTransition as Event;
    use SubscriptionCancellationState as State;
    match (state, event) {
        (State::Reserved, Event::Claim) => Some(State::Claimed),
        (State::Claimed, Event::BeginAttempt) => Some(State::Attempting),
        (State::Attempting, Event::ProviderScheduled | Event::ReconcileScheduled) => {
            Some(State::Scheduled)
        }
        (
            State::Attempting | State::Scheduled | State::OutcomeUnknown,
            Event::ProviderTerminal | Event::ReconcileTerminal,
        )
        | (State::Claimed | State::Attempting, Event::KnownFailure)
        | (State::OutcomeUnknown, Event::ReconcileNoEffect) => Some(State::Released),
        (State::Attempting, Event::OutcomeUnknown) => Some(State::OutcomeUnknown),
        (
            State::Scheduled | State::OutcomeUnknown,
            Event::ReconcileStillUnknown | Event::ReconcileScheduled,
        ) => Some(state),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_terminal_observation_is_the_only_direct_release_path() {
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::Attempting,
                SubscriptionCancelTransition::ProviderTerminal,
            ),
            Some(SubscriptionCancellationState::Released)
        );
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::Claimed,
                SubscriptionCancelTransition::ProviderTerminal,
            ),
            None
        );
    }

    #[test]
    fn unknown_result_never_becomes_release_without_reconciliation() {
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::Attempting,
                SubscriptionCancelTransition::OutcomeUnknown,
            ),
            Some(SubscriptionCancellationState::OutcomeUnknown)
        );
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::OutcomeUnknown,
                SubscriptionCancelTransition::ReconcileStillUnknown,
            ),
            Some(SubscriptionCancellationState::OutcomeUnknown)
        );
    }

    #[test]
    fn scheduled_cancellation_can_release_only_after_terminal_observation() {
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::Attempting,
                SubscriptionCancelTransition::ProviderScheduled,
            ),
            Some(SubscriptionCancellationState::Scheduled)
        );
        assert_eq!(
            transition_subscription_cancel(
                SubscriptionCancellationState::Scheduled,
                SubscriptionCancelTransition::ReconcileTerminal,
            ),
            Some(SubscriptionCancellationState::Released)
        );
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_event() -> SubscriptionCancelTransition {
        match kani::any::<u8>() % 11 {
            0 => SubscriptionCancelTransition::Claim,
            1 => SubscriptionCancelTransition::BeginAttempt,
            2 => SubscriptionCancelTransition::ProviderScheduled,
            3 => SubscriptionCancelTransition::ProviderTerminal,
            4 => SubscriptionCancelTransition::KnownFailure,
            5 => SubscriptionCancelTransition::OutcomeUnknown,
            6 => SubscriptionCancelTransition::ReconcileScheduled,
            7 => SubscriptionCancelTransition::ReconcileTerminal,
            8 => SubscriptionCancelTransition::ReconcileNoEffect,
            9 => SubscriptionCancelTransition::ReconcileStillUnknown,
            _ => SubscriptionCancelTransition::ReconcileStillUnknown,
        }
    }

    #[kani::proof]
    fn released_cancellation_is_terminal() {
        assert!(
            transition_subscription_cancel(SubscriptionCancellationState::Released, any_event())
                .is_none()
        );
    }

    #[kani::proof]
    fn reserved_intent_cannot_skip_claim() {
        let event = any_event();
        let next = transition_subscription_cancel(SubscriptionCancellationState::Reserved, event);
        if next.is_some() {
            assert!(matches!(event, SubscriptionCancelTransition::Claim));
            assert_eq!(next, Some(SubscriptionCancellationState::Claimed));
        }
    }

    #[kani::proof]
    fn unknown_intent_releases_only_after_exact_observation_or_known_no_effect() {
        let event = any_event();
        let next =
            transition_subscription_cancel(SubscriptionCancellationState::OutcomeUnknown, event);
        if next == Some(SubscriptionCancellationState::Released) {
            assert!(matches!(
                event,
                SubscriptionCancelTransition::ProviderTerminal
                    | SubscriptionCancelTransition::ReconcileTerminal
                    | SubscriptionCancelTransition::ReconcileNoEffect
            ));
        }
    }
}
