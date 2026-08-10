//! Iroh adapter for the Auths proof-exchange protocol.
//!
//! Connections are fully handshaken before use. This adapter deliberately has
//! no 0-RTT path for authorization-bearing messages.

#![forbid(unsafe_code)]

use async_trait::async_trait;
pub use auths_iroh::PathObservation;
use auths_iroh::{Endpoint, EndpointAddr, IrohChannel, IrohConfig, IrohError, StreamInitiator};
use auths_proof_exchange_codec::{
    CodecError, decode_challenge, decode_request, decode_response, encode_challenge,
    encode_request, encode_response,
};
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, MAX_BODY_BYTES, MAX_PROOF_BYTES,
    MAX_RESULT_BYTES, PeerObservation,
};
use auths_proof_exchange_port::{ClientProofChannel, ServerProofChannel};
use std::{fmt, sync::Arc, time::Duration};

pub const ALPN_V1: &[u8] = b"/auths-proof/action/1";
const MAX_CHALLENGE_FRAME: usize = 2048;
const MAX_REQUEST_FRAME: usize = MAX_BODY_BYTES as usize + MAX_PROOF_BYTES as usize + 1024;
const MAX_RESPONSE_FRAME: usize = MAX_RESULT_BYTES + 8192;
const MAX_PROTOCOL_FRAME: usize = MAX_REQUEST_FRAME;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChannelState {
    Connected,
    Challenged,
    Submitted,
    Completed,
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
    channel: IrohChannel,
    peer: PeerObservation,
    state: ChannelState,
    path: PathObservation,
    challenge: Option<ActionChallenge>,
}

pub struct IrohServerChannel {
    channel: IrohChannel,
    peer: PeerObservation,
    state: ChannelState,
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
        let channel = IrohChannel::connect(endpoint, target, transport_config(config)?)
            .await
            .map_err(|error| IrohTransportError::iroh("connect", error))?;
        let peer = PeerObservation::IrohEndpoint(*channel.peer_endpoint_id());
        let path = channel.path_observation();
        Ok(Self {
            channel,
            peer,
            state: ChannelState::Connected,
            path,
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
        let channel = IrohChannel::accept(endpoint, transport_config(config)?)
            .await
            .map_err(|error| IrohTransportError::iroh("accept", error))?;
        let peer = PeerObservation::IrohEndpoint(*channel.peer_endpoint_id());
        Ok(Self {
            channel,
            peer,
            state: ChannelState::Connected,
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
        let frame = self
            .channel
            .receive()
            .await
            .map_err(|error| IrohTransportError::iroh("receive challenge", error))?;
        check_frame(frame.payload(), MAX_CHALLENGE_FRAME)?;
        let challenge =
            decode_challenge(frame.payload()).map_err(|error| IrohTransportError::codec(&error))?;
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
        let encoded = encode_request(&request);
        check_frame(&encoded, MAX_REQUEST_FRAME)?;
        self.channel
            .send(&encoded)
            .await
            .map_err(|error| IrohTransportError::iroh("send request", error))?;
        self.channel
            .finish_send()
            .map_err(|error| IrohTransportError::iroh("finish request", error))?;
        self.state = ChannelState::Submitted;
        let frame = self
            .channel
            .receive()
            .await
            .map_err(|error| IrohTransportError::iroh("receive response", error))?;
        check_frame(frame.payload(), MAX_RESPONSE_FRAME)?;
        let response =
            decode_response(frame.payload()).map_err(|error| IrohTransportError::codec(&error))?;
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
        let encoded = encode_challenge(&challenge);
        check_frame(&encoded, MAX_CHALLENGE_FRAME)?;
        self.channel
            .send(&encoded)
            .await
            .map_err(|error| IrohTransportError::iroh("send challenge", error))?;
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
        let frame = self
            .channel
            .receive()
            .await
            .map_err(|error| IrohTransportError::iroh("receive request", error))?;
        check_frame(frame.payload(), MAX_REQUEST_FRAME)?;
        let request = decode_request(frame.payload(), challenge)
            .map_err(|error| IrohTransportError::codec(&error))?;
        self.state = ChannelState::Submitted;
        Ok(request)
    }

    async fn send_response(&mut self, response: ActionResponse) -> Result<(), Self::Error> {
        if self.state != ChannelState::Submitted {
            return Err(IrohTransportError::sequence());
        }
        let encoded = encode_response(&response);
        check_frame(&encoded, MAX_RESPONSE_FRAME)?;
        self.channel
            .send(&encoded)
            .await
            .map_err(|error| IrohTransportError::iroh("send response", error))?;
        self.channel
            .finish_send_and_wait()
            .await
            .map_err(|error| IrohTransportError::iroh("finish response", error))?;
        self.state = ChannelState::Completed;
        Ok(())
    }
}

fn transport_config(config: IrohChannelConfig) -> Result<IrohConfig, IrohTransportError> {
    IrohConfig::new(
        Arc::<[u8]>::from(ALPN_V1),
        MAX_PROTOCOL_FRAME,
        config.io_timeout(),
        StreamInitiator::AcceptingEndpoint,
    )
    .map_err(|error| IrohTransportError::iroh("configuration", error))
}

fn check_frame(payload: &[u8], max: usize) -> Result<(), IrohTransportError> {
    if payload.is_empty() || payload.len() > max {
        Err(IrohTransportError::frame("frame exceeds message limit"))
    } else {
        Ok(())
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
    fn iroh(context: &'static str, error: IrohError) -> Self {
        let category = match error {
            IrohError::Configuration => ErrorCategory::Configuration,
            IrohError::Limit => ErrorCategory::Framing,
            IrohError::Connection => ErrorCategory::DiscoveryOrConnection,
            IrohError::Timeout => ErrorCategory::Timeout,
            IrohError::Protocol => ErrorCategory::Protocol,
            IrohError::Sequence => ErrorCategory::Sequence,
        };
        Self::new(category, context, error.to_string())
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
