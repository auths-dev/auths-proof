//! Closed proof, response, retrieval, and lifecycle boundaries.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "port contracts and verified-command accessors are documented at the boundary level"
)]

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};
use serde::{Deserialize, Serialize};

use super::{
    StripeExactPurchaseAuthorizationV1, StripePurchaseAuthorizationCommand,
    StripePurchaseAuthorizationProfile,
};
use crate::{
    issuing::{
        PurchaseAuthorizationProviderProjection, PurchaseReservationRecord,
        PurchaseReservationState,
    },
    ports::{PortError, PurchaseAuthorizationCredential},
    types::IssuingAuthorizationId,
};

pub enum PurchaseAuthorizationProofDecision {
    Authorized(Box<Authorized<StripePurchaseAuthorizationCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait PurchaseAuthorizationProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PurchaseAuthorizationProofDecision, PortError>;
}

impl<T: PurchaseAuthorizationProofVerifier + ?Sized> PurchaseAuthorizationProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PurchaseAuthorizationProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkPurchaseAuthorizationProofVerifier {
    verifier: Verifier,
}

impl SdkPurchaseAuthorizationProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl PurchaseAuthorizationProofVerifier for SdkPurchaseAuthorizationProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<PurchaseAuthorizationProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripePurchaseAuthorizationProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => {
                Ok(PurchaseAuthorizationProofDecision::Authorized(value))
            }
            VerifyResult::Denied(value) => Ok(PurchaseAuthorizationProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => {
                Ok(PurchaseAuthorizationProofDecision::Indeterminate {
                    code: value.code().into(),
                })
            }
        }
    }
}

/// Constructed only after exact proof, durable decision, and atomic reservation.
pub struct VerifiedPurchaseAuthorizationCommand {
    authorized: Authorized<StripePurchaseAuthorizationCommand>,
    workflow_id: String,
    record: PurchaseReservationRecord,
}

impl VerifiedPurchaseAuthorizationCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripePurchaseAuthorizationCommand>,
        workflow_id: String,
        record: PurchaseReservationRecord,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            record,
        }
    }
    pub fn action(&self) -> &StripeExactPurchaseAuthorizationV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn record(&self) -> &PurchaseReservationRecord {
        &self.record
    }
}

/// Exact direct response accepted by Stripe's synchronous webhook.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PurchaseAuthorizationDirectResponse {
    pub approved: bool,
}

/// Retrieval-only provider boundary used after the direct response.
pub trait PurchaseAuthorizationGateway: Send + Sync {
    fn retrieve(
        &self,
        authorization: &IssuingAuthorizationId,
        credential: &PurchaseAuthorizationCredential,
        now: u64,
    ) -> Result<PurchaseAuthorizationProviderProjection, PortError>;
}

impl<T: PurchaseAuthorizationGateway + ?Sized> PurchaseAuthorizationGateway for Arc<T> {
    fn retrieve(
        &self,
        authorization: &IssuingAuthorizationId,
        credential: &PurchaseAuthorizationCredential,
        now: u64,
    ) -> Result<PurchaseAuthorizationProviderProjection, PortError> {
        (**self).retrieve(authorization, credential, now)
    }
}

/// Purchase-owned state events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PurchaseAuthorizationTransition {
    ResponseUnknown,
    ObservedApproved,
    ObservedDeclined,
    ObservedCaptured,
    ObservedReleased,
    ObservedOutsidePolicy,
}

/// Closed lifecycle relation; no generic operation tag dispatches behavior.
#[must_use]
pub const fn transition_purchase_authorization(
    state: PurchaseReservationState,
    event: PurchaseAuthorizationTransition,
) -> Option<PurchaseReservationState> {
    use PurchaseAuthorizationTransition as Event;
    use PurchaseReservationState as State;
    match (state, event) {
        (State::Approved, Event::ResponseUnknown) => Some(State::OutcomeUnknown),
        (State::Approved | State::OutcomeUnknown, Event::ObservedApproved) => Some(State::Approved),
        (State::Approved | State::OutcomeUnknown, Event::ObservedDeclined) => Some(State::Declined),
        (State::Approved | State::OutcomeUnknown, Event::ObservedCaptured) => Some(State::Captured),
        (State::Approved | State::OutcomeUnknown, Event::ObservedReleased) => Some(State::Released),
        (_, Event::ObservedOutsidePolicy) => Some(State::ObservationOutsidePolicy),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn response_uncertainty_holds_capacity_until_observation() {
        assert_eq!(
            transition_purchase_authorization(
                PurchaseReservationState::Approved,
                PurchaseAuthorizationTransition::ResponseUnknown
            ),
            Some(PurchaseReservationState::OutcomeUnknown)
        );
        assert!(PurchaseReservationState::OutcomeUnknown.holds_capacity());
        assert_eq!(
            transition_purchase_authorization(
                PurchaseReservationState::OutcomeUnknown,
                PurchaseAuthorizationTransition::ObservedReleased
            ),
            Some(PurchaseReservationState::Released)
        );
    }
}
