//! In-memory proof-exchange adapter.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, PeerObservation,
};
use auths_proof_exchange_port::{ClientProofChannel, ServerProofChannel};
use std::fmt;
use tokio::sync::mpsc;

enum ClientToServer {
    Submission(ActionSubmission),
}

enum ServerToClient {
    Challenge(ActionChallenge),
    Response(ActionResponse),
}

pub struct MemoryClientChannel {
    peer: PeerObservation,
    to_server: mpsc::Sender<ClientToServer>,
    from_server: mpsc::Receiver<ServerToClient>,
    state: ClientState,
    challenge: Option<ActionChallenge>,
}

pub struct MemoryServerChannel {
    peer: PeerObservation,
    from_client: mpsc::Receiver<ClientToServer>,
    to_client: mpsc::Sender<ServerToClient>,
    state: ServerState,
    challenge: Option<ActionChallenge>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientState {
    Connected,
    Challenged,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServerState {
    Connected,
    Challenged,
    Submitted,
    Completed,
}

#[must_use]
pub fn channel_pair(
    client_observes: PeerObservation,
    server_observes: PeerObservation,
) -> (MemoryClientChannel, MemoryServerChannel) {
    let (to_server, from_client) = mpsc::channel(1);
    let (to_client, from_server) = mpsc::channel(1);
    (
        MemoryClientChannel {
            peer: client_observes,
            to_server,
            from_server,
            state: ClientState::Connected,
            challenge: None,
        },
        MemoryServerChannel {
            peer: server_observes,
            from_client,
            to_client,
            state: ServerState::Connected,
            challenge: None,
        },
    )
}

#[async_trait]
impl ClientProofChannel for MemoryClientChannel {
    type Error = MemoryTransportError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn receive_challenge(&mut self) -> Result<ActionChallenge, Self::Error> {
        if self.state != ClientState::Connected {
            return Err(MemoryTransportError::InvalidSequence);
        }
        match self.from_server.recv().await {
            Some(ServerToClient::Challenge(challenge)) => {
                self.state = ClientState::Challenged;
                self.challenge = Some(challenge.clone());
                Ok(challenge)
            }
            Some(ServerToClient::Response(_)) => Err(MemoryTransportError::InvalidSequence),
            None => Err(MemoryTransportError::Disconnected),
        }
    }

    async fn submit_action(
        &mut self,
        request: ActionSubmission,
    ) -> Result<ActionResponse, Self::Error> {
        if self.state != ClientState::Challenged {
            return Err(MemoryTransportError::InvalidSequence);
        }
        if self
            .challenge
            .as_ref()
            .is_none_or(|challenge| !request.matches_challenge(challenge))
        {
            return Err(MemoryTransportError::BindingMismatch);
        }
        self.to_server
            .send(ClientToServer::Submission(request))
            .await
            .map_err(|_| MemoryTransportError::Disconnected)?;
        match self.from_server.recv().await {
            Some(ServerToClient::Response(response)) => {
                self.state = ClientState::Completed;
                Ok(response)
            }
            Some(ServerToClient::Challenge(_)) => Err(MemoryTransportError::InvalidSequence),
            None => Err(MemoryTransportError::Disconnected),
        }
    }
}

#[async_trait]
impl ServerProofChannel for MemoryServerChannel {
    type Error = MemoryTransportError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn send_challenge(&mut self, challenge: ActionChallenge) -> Result<(), Self::Error> {
        if self.state != ServerState::Connected {
            return Err(MemoryTransportError::InvalidSequence);
        }
        self.to_client
            .send(ServerToClient::Challenge(challenge.clone()))
            .await
            .map_err(|_| MemoryTransportError::Disconnected)?;
        self.challenge = Some(challenge);
        self.state = ServerState::Challenged;
        Ok(())
    }

    async fn receive_action(
        &mut self,
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, Self::Error> {
        if self.state != ServerState::Challenged {
            return Err(MemoryTransportError::InvalidSequence);
        }
        if self.challenge.as_ref() != Some(challenge) {
            return Err(MemoryTransportError::BindingMismatch);
        }
        match self.from_client.recv().await {
            Some(ClientToServer::Submission(request)) => {
                if !request.matches_challenge(challenge) {
                    return Err(MemoryTransportError::BindingMismatch);
                }
                self.state = ServerState::Submitted;
                Ok(request)
            }
            None => Err(MemoryTransportError::Disconnected),
        }
    }

    async fn send_response(&mut self, response: ActionResponse) -> Result<(), Self::Error> {
        if self.state != ServerState::Submitted {
            return Err(MemoryTransportError::InvalidSequence);
        }
        self.to_client
            .send(ServerToClient::Response(response))
            .await
            .map_err(|_| MemoryTransportError::Disconnected)?;
        self.state = ServerState::Completed;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryTransportError {
    Disconnected,
    InvalidSequence,
    BindingMismatch,
}

impl fmt::Display for MemoryTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disconnected => formatter.write_str("in-memory channel disconnected"),
            Self::InvalidSequence => formatter.write_str("invalid in-memory exchange sequence"),
            Self::BindingMismatch => formatter.write_str("in-memory submission binding mismatch"),
        }
    }
}

impl std::error::Error for MemoryTransportError {}
