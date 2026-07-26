//! Semantic proof-exchange port.
//!
//! This is intentionally not a generic byte-stream or RPC abstraction.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, PeerObservation,
};
use std::fmt;

#[async_trait]
pub trait ClientProofChannel {
    type Error: std::error::Error + Send + Sync + 'static;

    fn peer_observation(&self) -> &PeerObservation;

    async fn receive_challenge(&mut self) -> Result<ActionChallenge, Self::Error>;

    async fn submit_action(
        &mut self,
        request: ActionSubmission,
    ) -> Result<ActionResponse, Self::Error>;
}

#[async_trait]
pub trait ServerProofChannel {
    type Error: std::error::Error + Send + Sync + 'static;

    fn peer_observation(&self) -> &PeerObservation;

    async fn send_challenge(&mut self, challenge: ActionChallenge) -> Result<(), Self::Error>;

    async fn receive_action(
        &mut self,
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, Self::Error>;

    async fn send_response(&mut self, response: ActionResponse) -> Result<(), Self::Error>;
}

#[async_trait]
pub trait ProofExchangeService: Send + Sync {
    async fn issue_challenge(
        &self,
        peer: &PeerObservation,
    ) -> Result<ActionChallenge, ServiceError>;

    async fn handle_action(
        &self,
        peer: &PeerObservation,
        challenge: &ActionChallenge,
        request: ActionSubmission,
    ) -> ActionResponse;
}

/// Runs the only exchange sequence admitted by V1.
///
/// Transport failures stay transport failures. The function never manufactures
/// an Auths verdict or application response for a failed channel.
///
/// # Errors
///
/// Returns [`ServeError::Transport`] for channel failures and
/// [`ServeError::Service`] when the application cannot issue a challenge.
pub async fn serve_one<C, S>(channel: &mut C, service: &S) -> Result<(), ServeError<C::Error>>
where
    C: ServerProofChannel + Send,
    S: ProofExchangeService,
{
    let challenge = service
        .issue_challenge(channel.peer_observation())
        .await
        .map_err(ServeError::Service)?;
    channel
        .send_challenge(challenge.clone())
        .await
        .map_err(ServeError::Transport)?;
    let request = channel
        .receive_action(&challenge)
        .await
        .map_err(ServeError::Transport)?;
    let response = service
        .handle_action(channel.peer_observation(), &challenge, request)
        .await;
    channel
        .send_response(response)
        .await
        .map_err(ServeError::Transport)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    ChallengeUnavailable,
    ChallengeStateUnavailable,
}

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChallengeUnavailable => formatter.write_str("challenge source unavailable"),
            Self::ChallengeStateUnavailable => formatter.write_str("challenge state unavailable"),
        }
    }
}

impl std::error::Error for ServiceError {}

#[derive(Debug)]
pub enum ServeError<E> {
    Transport(E),
    Service(ServiceError),
}

impl<E: fmt::Display> fmt::Display for ServeError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => write!(formatter, "transport failed: {error}"),
            Self::Service(error) => write!(formatter, "exchange service failed: {error}"),
        }
    }
}

impl<E> std::error::Error for ServeError<E> where E: std::error::Error + 'static {}
