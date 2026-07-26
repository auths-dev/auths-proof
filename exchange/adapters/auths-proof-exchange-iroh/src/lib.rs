//! Iroh adapter for the Auths proof-exchange protocol.
//!
//! Connections are fully handshaken before use. This adapter deliberately has
//! no 0-RTT path for authorization-bearing messages.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_codec::{
    CodecError, decode_challenge, decode_request, decode_response, encode_challenge,
    encode_request, encode_response,
};
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, MAX_BODY_BYTES, MAX_PROOF_BYTES,
    MAX_RESULT_BYTES, PeerObservation,
};
use auths_proof_exchange_port::{ClientProofChannel, ServerProofChannel};
use iroh::{
    Endpoint, EndpointAddr,
    endpoint::{Connection, RecvStream, SendStream},
};
use std::{fmt, time::Duration};
use tokio::time::timeout;

pub const ALPN_V1: &[u8] = b"/auths-proof/action/1";
const MAX_CHALLENGE_FRAME: usize = 2048;
const MAX_REQUEST_FRAME: usize = MAX_BODY_BYTES as usize + MAX_PROOF_BYTES as usize + 1024;
const MAX_RESPONSE_FRAME: usize = MAX_RESULT_BYTES + 8192;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelState {
    Connected,
    Challenged,
    Submitted,
    Completed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathObservation {
    Direct,
    Relayed,
    MixedOrUnknown,
}

#[derive(Clone, Copy, Debug)]
pub struct IrohChannelConfig {
    io_timeout: Duration,
}

impl IrohChannelConfig {
    /// Constructs bounded I/O deadline configuration.
    ///
    /// # Errors
    ///
    /// Returns an [`IrohTransportError`] when the deadline is zero or exceeds
    /// sixty seconds.
    pub fn new(io_timeout: Duration) -> Result<Self, IrohTransportError> {
        if io_timeout.is_zero() || io_timeout > Duration::from_mins(1) {
            return Err(IrohTransportError::configuration(
                "I/O timeout must be between 1ns and 60s",
            ));
        }
        Ok(Self { io_timeout })
    }

    #[must_use]
    pub const fn io_timeout(self) -> Duration {
        self.io_timeout
    }
}

impl Default for IrohChannelConfig {
    fn default() -> Self {
        Self {
            io_timeout: Duration::from_secs(10),
        }
    }
}

pub struct IrohClientChannel {
    _connection: Connection,
    peer: PeerObservation,
    send: SendStream,
    recv: RecvStream,
    state: ChannelState,
    config: IrohChannelConfig,
    path: PathObservation,
    challenge: Option<ActionChallenge>,
}

pub struct IrohServerChannel {
    _connection: Connection,
    peer: PeerObservation,
    send: SendStream,
    recv: RecvStream,
    state: ChannelState,
    config: IrohChannelConfig,
    path: PathObservation,
    challenge: Option<ActionChallenge>,
}

impl IrohClientChannel {
    /// Completes an Iroh handshake and accepts the single V1 bidirectional
    /// stream opened by the service.
    ///
    /// # Errors
    ///
    /// Returns an [`IrohTransportError`] for discovery, connection, handshake,
    /// ALPN, or stream failures.
    pub async fn connect(
        endpoint: &Endpoint,
        target: EndpointAddr,
        config: IrohChannelConfig,
    ) -> Result<Self, IrohTransportError> {
        let target_path = classify_target(&target);
        let connection = endpoint
            .connect(target, ALPN_V1)
            .await
            .map_err(|error| IrohTransportError::iroh("connect", error))?;
        if connection.alpn() != ALPN_V1 {
            return Err(IrohTransportError::protocol("unexpected negotiated ALPN"));
        }
        let peer = PeerObservation::IrohEndpoint(*connection.remote_id().as_bytes());
        // The accepting side opens the V1 stream and sends the challenge. Waiting
        // here cannot expose application data before the completed handshake.
        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|error| IrohTransportError::iroh("accept V1 stream", error))?;
        Ok(Self {
            _connection: connection,
            peer,
            send,
            recv,
            state: ChannelState::Connected,
            config,
            path: target_path,
            challenge: None,
        })
    }

    #[must_use]
    pub const fn path_observation(&self) -> PathObservation {
        self.path
    }
}

impl IrohServerChannel {
    /// Accepts a fully handshaken Iroh connection and opens its V1 stream.
    ///
    /// # Errors
    ///
    /// Returns an [`IrohTransportError`] for endpoint, handshake, ALPN, or
    /// stream failures.
    pub async fn accept(
        endpoint: &Endpoint,
        config: IrohChannelConfig,
    ) -> Result<Self, IrohTransportError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| IrohTransportError::protocol("endpoint closed"))?;
        let connection = incoming
            .await
            .map_err(|error| IrohTransportError::iroh("handshake", error))?;
        if connection.alpn() != ALPN_V1 {
            return Err(IrohTransportError::protocol("unexpected negotiated ALPN"));
        }
        let peer = PeerObservation::IrohEndpoint(*connection.remote_id().as_bytes());
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|error| IrohTransportError::iroh("open V1 stream", error))?;
        Ok(Self {
            _connection: connection,
            peer,
            send,
            recv,
            state: ChannelState::Connected,
            config,
            path: PathObservation::MixedOrUnknown,
            challenge: None,
        })
    }

    #[must_use]
    pub const fn path_observation(&self) -> PathObservation {
        self.path
    }
}

#[async_trait]
impl ClientProofChannel for IrohClientChannel {
    type Error = IrohTransportError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn receive_challenge(&mut self) -> Result<ActionChallenge, Self::Error> {
        if self.state != ChannelState::Connected {
            return Err(IrohTransportError::sequence());
        }
        let frame = read_frame(&mut self.recv, MAX_CHALLENGE_FRAME, self.config.io_timeout).await?;
        let challenge =
            decode_challenge(&frame).map_err(|error| IrohTransportError::codec(&error))?;
        self.challenge = Some(challenge.clone());
        self.state = ChannelState::Challenged;
        Ok(challenge)
    }

    async fn submit_action(
        &mut self,
        request: ActionSubmission,
    ) -> Result<ActionResponse, Self::Error> {
        if self.state != ChannelState::Challenged {
            return Err(IrohTransportError::sequence());
        }
        if self
            .challenge
            .as_ref()
            .is_none_or(|challenge| !request.matches_challenge(challenge))
        {
            return Err(IrohTransportError::binding());
        }
        write_frame(
            &mut self.send,
            &encode_request(&request),
            MAX_REQUEST_FRAME,
            self.config.io_timeout,
        )
        .await?;
        self.state = ChannelState::Submitted;
        let frame = read_frame(&mut self.recv, MAX_RESPONSE_FRAME, self.config.io_timeout).await?;
        let response =
            decode_response(&frame).map_err(|error| IrohTransportError::codec(&error))?;
        self.state = ChannelState::Completed;
        Ok(response)
    }
}

#[async_trait]
impl ServerProofChannel for IrohServerChannel {
    type Error = IrohTransportError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn send_challenge(&mut self, challenge: ActionChallenge) -> Result<(), Self::Error> {
        if self.state != ChannelState::Connected {
            return Err(IrohTransportError::sequence());
        }
        write_frame(
            &mut self.send,
            &encode_challenge(&challenge),
            MAX_CHALLENGE_FRAME,
            self.config.io_timeout,
        )
        .await?;
        self.challenge = Some(challenge);
        self.state = ChannelState::Challenged;
        Ok(())
    }

    async fn receive_action(
        &mut self,
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, Self::Error> {
        if self.state != ChannelState::Challenged {
            return Err(IrohTransportError::sequence());
        }
        if self.challenge.as_ref() != Some(challenge) {
            return Err(IrohTransportError::binding());
        }
        let frame = read_frame(&mut self.recv, MAX_REQUEST_FRAME, self.config.io_timeout).await?;
        let request =
            decode_request(&frame, challenge).map_err(|error| IrohTransportError::codec(&error))?;
        self.state = ChannelState::Submitted;
        Ok(request)
    }

    async fn send_response(&mut self, response: ActionResponse) -> Result<(), Self::Error> {
        if self.state != ChannelState::Submitted {
            return Err(IrohTransportError::sequence());
        }
        write_frame(
            &mut self.send,
            &encode_response(&response),
            MAX_RESPONSE_FRAME,
            self.config.io_timeout,
        )
        .await?;
        self.send
            .finish()
            .map_err(|error| IrohTransportError::iroh("finish V1 stream", error))?;
        timeout(self.config.io_timeout, self.send.stopped())
            .await
            .map_err(|_| IrohTransportError::timeout())?
            .map_err(|error| IrohTransportError::iroh("acknowledge V1 response", error))?;
        self.state = ChannelState::Completed;
        Ok(())
    }
}

async fn write_frame(
    send: &mut SendStream,
    payload: &[u8],
    max: usize,
    deadline: Duration,
) -> Result<(), IrohTransportError> {
    if payload.len() > max || payload.len() > u32::MAX as usize {
        return Err(IrohTransportError::frame("outgoing frame exceeds limit"));
    }
    let length = u32::try_from(payload.len())
        .map_err(|_| IrohTransportError::frame("outgoing frame exceeds u32"))?;
    let operation = async {
        send.write_all(&length.to_be_bytes())
            .await
            .map_err(|error| IrohTransportError::iroh("write frame length", error))?;
        send.write_all(payload)
            .await
            .map_err(|error| IrohTransportError::iroh("write frame payload", error))
    };
    timeout(deadline, operation)
        .await
        .map_err(|_| IrohTransportError::timeout())?
}

async fn read_frame(
    recv: &mut RecvStream,
    max: usize,
    deadline: Duration,
) -> Result<Vec<u8>, IrohTransportError> {
    let operation = async {
        let mut length = [0_u8; 4];
        recv.read_exact(&mut length)
            .await
            .map_err(|error| IrohTransportError::iroh("read frame length", error))?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > max {
            return Err(IrohTransportError::frame(
                "incoming frame length exceeds limit",
            ));
        }
        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload)
            .await
            .map_err(|error| IrohTransportError::iroh("read frame payload", error))?;
        Ok(payload)
    };
    timeout(deadline, operation)
        .await
        .map_err(|_| IrohTransportError::timeout())?
}

fn classify_target(target: &EndpointAddr) -> PathObservation {
    let has_direct = target.ip_addrs().next().is_some();
    let has_relay = target.relay_urls().next().is_some();
    match (has_direct, has_relay) {
        (true, false) => PathObservation::Direct,
        (false, true) => PathObservation::Relayed,
        _ => PathObservation::MixedOrUnknown,
    }
}

#[derive(Debug)]
pub struct IrohTransportError {
    category: ErrorCategory,
    context: &'static str,
    detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCategory {
    Configuration,
    DiscoveryOrConnection,
    Timeout,
    Framing,
    Sequence,
    Binding,
    Codec,
    Protocol,
}

impl IrohTransportError {
    fn configuration(detail: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Configuration, "configuration", detail)
    }
    fn iroh(context: &'static str, error: impl fmt::Display) -> Self {
        Self::new(
            ErrorCategory::DiscoveryOrConnection,
            context,
            error.to_string(),
        )
    }
    fn timeout() -> Self {
        Self::new(ErrorCategory::Timeout, "I/O", "deadline exceeded")
    }
    fn frame(detail: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Framing, "frame", detail)
    }
    fn sequence() -> Self {
        Self::new(
            ErrorCategory::Sequence,
            "state machine",
            "invalid V1 message sequence",
        )
    }
    fn binding() -> Self {
        Self::new(
            ErrorCategory::Binding,
            "challenge binding",
            "submission does not match the issued challenge",
        )
    }
    fn codec(error: &CodecError) -> Self {
        Self::new(ErrorCategory::Codec, "message codec", error.to_string())
    }
    fn protocol(detail: impl Into<String>) -> Self {
        Self::new(ErrorCategory::Protocol, "protocol", detail)
    }
    fn new(category: ErrorCategory, context: &'static str, detail: impl Into<String>) -> Self {
        Self {
            category,
            context,
            detail: detail.into(),
        }
    }

    #[must_use]
    pub const fn category(&self) -> ErrorCategory {
        self.category
    }
}

impl fmt::Display for IrohTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} failed: {}", self.context, self.detail)
    }
}

impl std::error::Error for IrohTransportError {}
