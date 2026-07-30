//! Closed proof, provider, and lifecycle boundaries for Payout.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "port contracts are documented at the profile boundary"
)]

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::{
    PayoutEvidenceV1, PayoutProviderProjection, PayoutReservationRecord, PayoutReservationState,
    PayoutStatus, StripeExactPayoutV1, StripePayoutCommand, StripePayoutProfile,
};
use crate::{
    ports::{PayoutCredential, PortError},
    types::PayoutId,
};

pub enum PayoutProofDecision {
    Authorized(Box<Authorized<StripePayoutCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait PayoutProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PayoutProofDecision, PortError>;
}

impl<T: PayoutProofVerifier + ?Sized> PayoutProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PayoutProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkPayoutProofVerifier {
    verifier: Verifier,
}

impl SdkPayoutProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PayoutProofVerifier for SdkPayoutProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PayoutProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePayoutProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => Ok(PayoutProofDecision::Authorized(value)),
            VerifyResult::Denied(value) => Ok(PayoutProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => Ok(PayoutProofDecision::Indeterminate {
                code: value.code().into(),
            }),
        }
    }
}

pub struct VerifiedPayoutCommand {
    authorized: Authorized<StripePayoutCommand>,
    workflow_id: String,
    reservation: PayoutReservationRecord,
}

impl VerifiedPayoutCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripePayoutCommand>,
        workflow_id: String,
        reservation: PayoutReservationRecord,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            reservation,
        }
    }
    pub fn action(&self) -> &StripeExactPayoutV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn reservation(&self) -> &PayoutReservationRecord {
        &self.reservation
    }
}

pub trait PayoutGateway: Send + Sync {
    fn critical_read(
        &self,
        action: &StripeExactPayoutV1,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutEvidenceV1, PortError>;
    fn create(
        &self,
        command: &VerifiedPayoutCommand,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutProviderProjection, PortError>;
    fn reconcile(
        &self,
        action: &StripeExactPayoutV1,
        payout_id: Option<&PayoutId>,
        workflow_id: &str,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutProviderProjection, PortError>;
}

impl<T: PayoutGateway + ?Sized> PayoutGateway for Arc<T> {
    fn critical_read(
        &self,
        action: &StripeExactPayoutV1,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutEvidenceV1, PortError> {
        (**self).critical_read(action, credential, now)
    }
    fn create(
        &self,
        command: &VerifiedPayoutCommand,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutProviderProjection, PortError> {
        (**self).create(command, credential, now)
    }
    fn reconcile(
        &self,
        action: &StripeExactPayoutV1,
        payout_id: Option<&PayoutId>,
        workflow_id: &str,
        credential: &PayoutCredential,
        now: u64,
    ) -> Result<PayoutProviderProjection, PortError> {
        (**self).reconcile(action, payout_id, workflow_id, credential, now)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayoutTransition {
    ProviderAccepted,
    OutcomeUnknown,
    KnownFailure,
    ObservedPending,
    ObservedPaid,
    ObservedFailedWithoutReturn,
    ObservedFundsReturned,
    ObservedOutsidePolicy,
}

#[must_use]
pub const fn transition_payout(
    state: PayoutReservationState,
    event: PayoutTransition,
) -> Option<PayoutReservationState> {
    use PayoutReservationState as State;
    use PayoutTransition as Event;
    match (state, event) {
        (State::Reserved, Event::ProviderAccepted | Event::ObservedPending) => {
            Some(State::ProviderAccepted)
        }
        (State::Reserved, Event::OutcomeUnknown) => Some(State::OutcomeUnknown),
        (State::Reserved, Event::KnownFailure) => Some(State::Released),
        (
            State::ProviderAccepted | State::OutcomeUnknown | State::DeliveryFailedAwaitingReturn,
            Event::ObservedPending | Event::ObservedPaid,
        ) => Some(State::ProviderAccepted),
        (State::ProviderAccepted | State::OutcomeUnknown, Event::ObservedFailedWithoutReturn) => {
            Some(State::DeliveryFailedAwaitingReturn)
        }
        (State::DeliveryFailedAwaitingReturn, Event::ObservedFundsReturned) => {
            Some(State::Released)
        }
        (_, Event::ObservedOutsidePolicy) => Some(State::ObservationOutsidePolicy),
        _ => None,
    }
}

pub const fn state_for_projection(projection: &PayoutProviderProjection) -> PayoutReservationState {
    match projection.status {
        PayoutStatus::Pending | PayoutStatus::Paid => PayoutReservationState::ProviderAccepted,
        PayoutStatus::Failed | PayoutStatus::Canceled | PayoutStatus::Reversed => {
            if projection.funds_returned_to_available_balance {
                PayoutReservationState::Released
            } else {
                PayoutReservationState::DeliveryFailedAwaitingReturn
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failed_delivery_releases_only_after_balance_return_observation() {
        assert_eq!(
            transition_payout(
                PayoutReservationState::ProviderAccepted,
                PayoutTransition::ObservedFailedWithoutReturn,
            ),
            Some(PayoutReservationState::DeliveryFailedAwaitingReturn)
        );
        assert_eq!(
            transition_payout(
                PayoutReservationState::DeliveryFailedAwaitingReturn,
                PayoutTransition::ObservedFundsReturned,
            ),
            Some(PayoutReservationState::Released)
        );
        assert_eq!(
            transition_payout(
                PayoutReservationState::ProviderAccepted,
                PayoutTransition::ObservedFundsReturned,
            ),
            None
        );
    }
}
