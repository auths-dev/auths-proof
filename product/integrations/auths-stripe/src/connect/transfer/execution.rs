//! Closed proof, provider, and lifecycle boundaries for Connect Transfer.

#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "port contracts are documented at the profile boundary"
)]

use std::sync::Arc;

use auths_model::CanonicalAction;
use auths_sdk::{Authorized, RequestContext, Verifier, VerifyResult};

use super::{
    ConnectTransferEvidenceV1, ConnectTransferProviderProjection, ConnectTransferReservationRecord,
    ConnectTransferReservationState, StripeConnectTransferCommand, StripeConnectTransferProfile,
    StripeExactConnectTransferV1,
};
use crate::{
    ports::{ConnectTransferCredential, PortError},
    types::TransferId,
};

pub enum ConnectTransferProofDecision {
    Authorized(Box<Authorized<StripeConnectTransferCommand>>),
    Denied { code: String },
    Indeterminate { code: String },
}

pub trait ConnectTransferProofVerifier: Send + Sync {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ConnectTransferProofDecision, PortError>;
}

impl<T: ConnectTransferProofVerifier + ?Sized> ConnectTransferProofVerifier for Arc<T> {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ConnectTransferProofDecision, PortError> {
        (**self).verify(proof, action, request)
    }
}

pub struct SdkConnectTransferProofVerifier {
    verifier: Verifier,
}

impl SdkConnectTransferProofVerifier {
    pub const fn new(verifier: Verifier) -> Self {
        Self { verifier }
    }
}

impl ConnectTransferProofVerifier for SdkConnectTransferProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &CanonicalAction,
        request: &RequestContext,
    ) -> Result<ConnectTransferProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &StripeConnectTransferProfile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(value) => Ok(ConnectTransferProofDecision::Authorized(value)),
            VerifyResult::Denied(value) => Ok(ConnectTransferProofDecision::Denied {
                code: value.code().into(),
            }),
            VerifyResult::Indeterminate(value) => Ok(ConnectTransferProofDecision::Indeterminate {
                code: value.code().into(),
            }),
        }
    }
}

/// Constructed only after exact proof and atomic reservation.
pub struct VerifiedConnectTransferCommand {
    authorized: Authorized<StripeConnectTransferCommand>,
    workflow_id: String,
    reservation: ConnectTransferReservationRecord,
}

impl VerifiedConnectTransferCommand {
    pub(crate) const fn new(
        authorized: Authorized<StripeConnectTransferCommand>,
        workflow_id: String,
        reservation: ConnectTransferReservationRecord,
    ) -> Self {
        Self {
            authorized,
            workflow_id,
            reservation,
        }
    }
    pub fn action(&self) -> &StripeExactConnectTransferV1 {
        self.authorized.command().action()
    }
    pub fn workflow_id(&self) -> &str {
        &self.workflow_id
    }
    pub const fn reservation(&self) -> &ConnectTransferReservationRecord {
        &self.reservation
    }
}

/// Profile-specific Stripe Connect provider boundary.
pub trait ConnectTransferGateway: Send + Sync {
    fn critical_read(
        &self,
        action: &StripeExactConnectTransferV1,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferEvidenceV1, PortError>;
    fn create(
        &self,
        command: &VerifiedConnectTransferCommand,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferProviderProjection, PortError>;
    fn reconcile(
        &self,
        action: &StripeExactConnectTransferV1,
        transfer_id: Option<&TransferId>,
        workflow_id: &str,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferProviderProjection, PortError>;
}

impl<T: ConnectTransferGateway + ?Sized> ConnectTransferGateway for Arc<T> {
    fn critical_read(
        &self,
        action: &StripeExactConnectTransferV1,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferEvidenceV1, PortError> {
        (**self).critical_read(action, credential, now)
    }
    fn create(
        &self,
        command: &VerifiedConnectTransferCommand,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferProviderProjection, PortError> {
        (**self).create(command, credential, now)
    }
    fn reconcile(
        &self,
        action: &StripeExactConnectTransferV1,
        transfer_id: Option<&TransferId>,
        workflow_id: &str,
        credential: &ConnectTransferCredential,
        now: u64,
    ) -> Result<ConnectTransferProviderProjection, PortError> {
        (**self).reconcile(action, transfer_id, workflow_id, credential, now)
    }
}

/// Transfer-owned lifecycle events.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectTransferTransition {
    ProviderAccepted,
    OutcomeUnknown,
    KnownFailure,
    ObservedExact,
    ObservedOutsidePolicy,
}

/// Closed transfer lifecycle relation.
#[must_use]
pub const fn transition_connect_transfer(
    state: ConnectTransferReservationState,
    event: ConnectTransferTransition,
) -> Option<ConnectTransferReservationState> {
    use ConnectTransferReservationState as State;
    use ConnectTransferTransition as Event;
    match (state, event) {
        (State::Reserved, Event::ProviderAccepted) => Some(State::ProviderAccepted),
        (State::Reserved, Event::OutcomeUnknown) => Some(State::OutcomeUnknown),
        (State::Reserved, Event::KnownFailure) => Some(State::Released),
        (State::ProviderAccepted | State::OutcomeUnknown, Event::ObservedExact) => {
            Some(State::ProviderAccepted)
        }
        (_, Event::ObservedOutsidePolicy) => Some(State::ObservationOutsidePolicy),
        _ => None,
    }
}
