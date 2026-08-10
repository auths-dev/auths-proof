//! Semantics-free bounded byte exchange over Iroh.
//!
//! This crate transports opaque bytes under caller-selected protocol bounds.
//! It does not decode identity, proof, capability, approval, or application
//! messages and never manufactures an authorization result.

#![forbid(unsafe_code)]

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use auths_byte_channel::{
    BoundedByteChannel, ChannelLimits, PeerObservation as BytePeerObservation,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
pub use iroh::{Endpoint, EndpointAddr};
use tokio::time::timeout;

const MAX_ALPN_BYTES: usize = 255;

/// Caller-owned protocol and resource bounds for one byte exchange.
#[derive(Clone, Debug)]
pub struct IrohConfig {
    alpn: Arc<[u8]>,
    limits: ChannelLimits,
    stream_initiator: StreamInitiator,
}

/// Endpoint role that opens the protocol's bidirectional stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamInitiator {
    /// The endpoint initiating the Iroh connection opens the stream.
    ConnectingEndpoint,
    /// The endpoint accepting the Iroh connection opens the stream.
    AcceptingEndpoint,
}

impl IrohConfig {
    /// Constructs a bounded, application-selected Iroh protocol configuration.
    ///
    /// # Errors
    ///
    /// Rejects an empty or oversized ALPN, a zero or oversized frame limit,
    /// and deadlines outside the neutral channel port's hard bounds.
    pub fn new(
        alpn: impl Into<Arc<[u8]>>,
        max_frame_bytes: usize,
        io_timeout: Duration,
        stream_initiator: StreamInitiator,
    ) -> Result<Self, IrohError> {
        let alpn = alpn.into();
        if alpn.is_empty() || alpn.len() > MAX_ALPN_BYTES {
            return Err(IrohError::Configuration);
        }
        let limits = ChannelLimits::new(max_frame_bytes, io_timeout)
            .map_err(|_| IrohError::Configuration)?;
        Ok(Self {
            alpn,
            limits,
            stream_initiator,
        })
    }

    /// Returns the caller-selected ALPN bytes.
    #[must_use]
    pub fn alpn(&self) -> &[u8] {
        &self.alpn
    }

    /// Returns the largest accepted payload.
    #[must_use]
    pub const fn max_frame_bytes(&self) -> usize {
        self.limits.max_frame_bytes()
    }

    /// Returns the per-operation deadline.
    #[must_use]
    pub const fn io_timeout(&self) -> Duration {
        self.limits.operation_timeout()
    }

    /// Returns which endpoint opens the bidirectional stream.
    #[must_use]
    pub const fn stream_initiator(&self) -> StreamInitiator {
        self.stream_initiator
    }
}

/// Direct/relay information observed while connecting to the Iroh peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PathObservation {
    /// Target advertised only a direct socket address.
    Direct,
    /// Target advertised only a relay URL.
    Relayed,
    /// Target advertised both forms or neither form.
    MixedOrUnknown,
}

/// Opaque received bytes paired with the authenticated Iroh endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceivedBytes {
    peer_endpoint_id: [u8; 32],
    payload: Vec<u8>,
}

impl ReceivedBytes {
    /// Returns the remote Iroh endpoint identifier.
    #[must_use]
    pub const fn peer_endpoint_id(&self) -> &[u8; 32] {
        &self.peer_endpoint_id
    }

    /// Returns the exact opaque payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the observation and returns the opaque payload.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }
}

/// Bounded duplex channel carrying only opaque byte frames.
pub struct IrohChannel {
    _connection: Connection,
    peer_endpoint_id: [u8; 32],
    send: SendStream,
    recv: RecvStream,
    config: IrohConfig,
    path: PathObservation,
    peer_observation: BytePeerObservation,
    send_finished: bool,
}

impl IrohChannel {
    /// Connects with the caller-selected ALPN and opens the request stream.
    ///
    /// # Errors
    ///
    /// Returns a typed transport error for connection, ALPN, or stream
    /// failures.
    pub async fn connect(
        endpoint: &Endpoint,
        target: EndpointAddr,
        config: IrohConfig,
    ) -> Result<Self, IrohError> {
        let path = classify_target(&target);
        let connection = endpoint
            .connect(target, config.alpn())
            .await
            .map_err(|_| IrohError::Connection)?;
        if connection.alpn() != config.alpn() {
            return Err(IrohError::Protocol);
        }
        let peer_endpoint_id = *connection.remote_id().as_bytes();
        let peer_observation =
            BytePeerObservation::transport_authenticated(peer_endpoint_id.to_vec())
                .map_err(|_| IrohError::Configuration)?;
        let (send, recv) = match config.stream_initiator() {
            StreamInitiator::ConnectingEndpoint => connection.open_bi().await,
            StreamInitiator::AcceptingEndpoint => connection.accept_bi().await,
        }
        .map_err(|_| IrohError::Connection)?;
        Ok(Self {
            _connection: connection,
            peer_endpoint_id,
            send,
            recv,
            config,
            path,
            peer_observation,
            send_finished: false,
        })
    }

    /// Accepts one handshaken connection and its caller-selected byte stream.
    ///
    /// # Errors
    ///
    /// Returns a typed transport error for endpoint, ALPN, or stream failures.
    pub async fn accept(endpoint: &Endpoint, config: IrohConfig) -> Result<Self, IrohError> {
        let incoming = endpoint.accept().await.ok_or(IrohError::Connection)?;
        let connection = incoming.await.map_err(|_| IrohError::Connection)?;
        if connection.alpn() != config.alpn() {
            return Err(IrohError::Protocol);
        }
        let peer_endpoint_id = *connection.remote_id().as_bytes();
        let peer_observation =
            BytePeerObservation::transport_authenticated(peer_endpoint_id.to_vec())
                .map_err(|_| IrohError::Configuration)?;
        let (send, recv) = match config.stream_initiator() {
            StreamInitiator::ConnectingEndpoint => connection.accept_bi().await,
            StreamInitiator::AcceptingEndpoint => connection.open_bi().await,
        }
        .map_err(|_| IrohError::Connection)?;
        Ok(Self {
            _connection: connection,
            peer_endpoint_id,
            send,
            recv,
            config,
            path: PathObservation::MixedOrUnknown,
            peer_observation,
            send_finished: false,
        })
    }

    /// Returns whether the target was direct, relayed, or mixed.
    #[must_use]
    pub const fn path_observation(&self) -> PathObservation {
        self.path
    }

    /// Returns the authenticated remote Iroh endpoint identifier.
    #[must_use]
    pub const fn peer_endpoint_id(&self) -> &[u8; 32] {
        &self.peer_endpoint_id
    }

    /// Sends one opaque bounded frame.
    ///
    /// # Errors
    ///
    /// Returns a typed error for framing, timeout, transport, bounds, or a send
    /// attempted after [`Self::finish_send`]. Payload semantics are never
    /// inspected.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), IrohError> {
        if self.send_finished {
            return Err(IrohError::Sequence);
        }
        write_frame(&mut self.send, payload, &self.config).await?;
        Ok(())
    }

    /// Receives one opaque bounded frame.
    ///
    /// # Errors
    ///
    /// Returns a typed framing, timeout, transport, or bounds error.
    pub async fn receive(&mut self) -> Result<ReceivedBytes, IrohError> {
        let payload = read_frame(&mut self.recv, &self.config).await?;
        Ok(ReceivedBytes {
            peer_endpoint_id: self.peer_endpoint_id,
            payload,
        })
    }

    /// Closes the sending side without waiting for peer acknowledgement.
    ///
    /// # Errors
    ///
    /// Returns [`IrohError::Sequence`] if the sending side is already closed,
    /// or a typed transport error.
    pub fn finish_send(&mut self) -> Result<(), IrohError> {
        if self.send_finished {
            return Err(IrohError::Sequence);
        }
        self.send_finished = true;
        self.send.finish().map_err(|_| IrohError::Connection)
    }

    /// Closes the sending side and waits for peer acknowledgement.
    ///
    /// This is normally used by the final responder after the requester has
    /// already closed its sending side.
    ///
    /// # Errors
    ///
    /// Returns a typed sequence, timeout, or transport error.
    pub async fn finish_send_and_wait(&mut self) -> Result<(), IrohError> {
        self.finish_send()?;
        timeout(self.config.io_timeout(), self.send.stopped())
            .await
            .map_err(|_| IrohError::Timeout)?
            .map(|_| ())
            .map_err(|_| IrohError::Connection)
    }
}

#[async_trait]
impl BoundedByteChannel for IrohChannel {
    type Error = IrohError;

    fn limits(&self) -> ChannelLimits {
        self.config.limits
    }

    fn peer_observation(&self) -> &BytePeerObservation {
        &self.peer_observation
    }

    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        IrohChannel::send(self, payload).await
    }

    async fn receive_frame(&mut self) -> Result<Vec<u8>, Self::Error> {
        IrohChannel::receive(self)
            .await
            .map(ReceivedBytes::into_payload)
    }

    async fn finish_send(&mut self) -> Result<(), Self::Error> {
        IrohChannel::finish_send_and_wait(self).await
    }
}

async fn write_frame(
    send: &mut SendStream,
    payload: &[u8],
    config: &IrohConfig,
) -> Result<(), IrohError> {
    if payload.is_empty() || payload.len() > config.max_frame_bytes() {
        return Err(IrohError::Limit);
    }
    let length = u32::try_from(payload.len()).map_err(|_| IrohError::Limit)?;
    timeout(config.io_timeout(), async {
        send.write_all(&length.to_be_bytes())
            .await
            .map_err(|_| IrohError::Connection)?;
        send.write_all(payload)
            .await
            .map_err(|_| IrohError::Connection)
    })
    .await
    .map_err(|_| IrohError::Timeout)?
}

async fn read_frame(recv: &mut RecvStream, config: &IrohConfig) -> Result<Vec<u8>, IrohError> {
    timeout(config.io_timeout(), async {
        let mut length = [0_u8; 4];
        recv.read_exact(&mut length)
            .await
            .map_err(|_| IrohError::Connection)?;
        let length = usize::try_from(u32::from_be_bytes(length)).map_err(|_| IrohError::Limit)?;
        if length == 0 || length > config.max_frame_bytes() {
            return Err(IrohError::Limit);
        }
        let mut payload = vec![0_u8; length];
        recv.read_exact(&mut payload)
            .await
            .map_err(|_| IrohError::Connection)?;
        Ok(payload)
    })
    .await
    .map_err(|_| IrohError::Timeout)?
}

fn classify_target(target: &EndpointAddr) -> PathObservation {
    match (
        target.ip_addrs().next().is_some(),
        target.relay_urls().next().is_some(),
    ) {
        (true, false) => PathObservation::Direct,
        (false, true) => PathObservation::Relayed,
        _ => PathObservation::MixedOrUnknown,
    }
}

/// Typed generic Iroh configuration, framing, sequence, and transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IrohError {
    /// ALPN, frame limit, or I/O deadline is outside its hard bounds.
    Configuration,
    /// Declared or actual frame input exceeds the caller-selected bound.
    Limit,
    /// Iroh discovery, handshake, or stream I/O failed.
    Connection,
    /// I/O deadline elapsed.
    Timeout,
    /// Negotiated ALPN did not match the caller-selected protocol.
    Protocol,
    /// The duplex channel's send-side sequence was violated.
    Sequence,
}

impl fmt::Display for IrohError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid Iroh transport configuration",
            Self::Limit => "Iroh frame resource limit exceeded",
            Self::Connection => "Iroh transport failed",
            Self::Timeout => "Iroh transport timed out",
            Self::Protocol => "unexpected Iroh application protocol",
            Self::Sequence => "invalid Iroh exchange sequence",
        })
    }
}

impl std::error::Error for IrohError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn applications_choose_protocol_and_bounds() {
        let config = IrohConfig::new(
            Arc::<[u8]>::from(&b"/example/arbitrary-bytes/1"[..]),
            4096,
            Duration::from_secs(2),
            StreamInitiator::ConnectingEndpoint,
        )
        .unwrap();
        assert_eq!(config.alpn(), b"/example/arbitrary-bytes/1");
        assert_eq!(config.max_frame_bytes(), 4096);
    }

    #[test]
    fn invalid_protocol_and_resource_bounds_fail_closed() {
        assert_eq!(
            IrohConfig::new(
                Arc::<[u8]>::from(&b""[..]),
                1,
                Duration::from_secs(1),
                StreamInitiator::ConnectingEndpoint,
            )
            .unwrap_err(),
            IrohError::Configuration
        );
        assert_eq!(
            IrohConfig::new(
                Arc::<[u8]>::from(&b"/test/1"[..]),
                0,
                Duration::from_secs(1),
                StreamInitiator::ConnectingEndpoint,
            )
            .unwrap_err(),
            IrohError::Configuration
        );
    }
}
