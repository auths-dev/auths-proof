//! Transport-neutral bounded opaque byte-channel port.
//!
//! This crate contains no application, identity, proof, authority, or transport protocol types.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use std::{fmt, time::Duration};

const MAX_FRAME_BYTES: usize = u32::MAX as usize;
const MAX_PEER_OBSERVATION_BYTES: usize = 4096;
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_mins(5);

/// Caller-selected resource and deadline limits for one channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelLimits {
    max_frame_bytes: usize,
    operation_timeout: Duration,
}

impl ChannelLimits {
    /// Constructs explicit per-frame and per-operation bounds.
    ///
    /// # Errors
    ///
    /// Rejects zero or unrepresentable frame limits and zero or excessive deadlines.
    pub fn new(
        max_frame_bytes: usize,
        operation_timeout: Duration,
    ) -> Result<Self, ChannelConfigurationError> {
        if max_frame_bytes == 0
            || max_frame_bytes > MAX_FRAME_BYTES
            || operation_timeout.is_zero()
            || operation_timeout > MAX_OPERATION_TIMEOUT
        {
            return Err(ChannelConfigurationError);
        }
        Ok(Self {
            max_frame_bytes,
            operation_timeout,
        })
    }

    #[must_use]
    pub const fn max_frame_bytes(self) -> usize {
        self.max_frame_bytes
    }

    #[must_use]
    pub const fn operation_timeout(self) -> Duration {
        self.operation_timeout
    }
}

/// Opaque transport-level fact about the remote endpoint.
///
/// Authenticated observations mean only that the selected transport authenticated these bytes;
/// they are not an Auths identity or principal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerObservation {
    /// The transport supplies no mutually authenticated remote identifier.
    Unauthenticated,
    /// The transport authenticated bounded opaque endpoint bytes.
    TransportAuthenticated(Vec<u8>),
}

impl PeerObservation {
    /// Constructs a bounded transport-authenticated observation.
    ///
    /// # Errors
    ///
    /// Rejects empty or oversized observations.
    pub fn transport_authenticated(bytes: Vec<u8>) -> Result<Self, ChannelConfigurationError> {
        if bytes.is_empty() || bytes.len() > MAX_PEER_OBSERVATION_BYTES {
            return Err(ChannelConfigurationError);
        }
        Ok(Self::TransportAuthenticated(bytes))
    }

    /// Returns authenticated opaque bytes when the transport supplied them.
    #[must_use]
    pub fn authenticated_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Unauthenticated => None,
            Self::TransportAuthenticated(bytes) => Some(bytes),
        }
    }
}

/// Minimal duplex port for non-empty bounded opaque frames.
#[async_trait]
pub trait BoundedByteChannel {
    /// Adapter-specific failure preserving transport diagnostics outside this neutral port.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Returns the caller-selected hard bounds used by this channel.
    fn limits(&self) -> ChannelLimits;

    /// Returns an opaque transport fact, never an application identity.
    fn peer_observation(&self) -> &PeerObservation;

    /// Sends one non-empty bounded frame without interpreting it.
    ///
    /// # Errors
    ///
    /// Returns the adapter's limit, timeout, sequence, or transport failure.
    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), Self::Error>;

    /// Receives one non-empty bounded frame without interpreting it.
    ///
    /// # Errors
    ///
    /// Returns the adapter's limit, timeout, sequence, or transport failure.
    async fn receive_frame(&mut self) -> Result<Vec<u8>, Self::Error>;

    /// Finishes the sending side of the channel.
    ///
    /// # Errors
    ///
    /// Returns the adapter's sequence, timeout, or transport failure.
    async fn finish_send(&mut self) -> Result<(), Self::Error>;
}

/// A generic channel limit or peer-observation configuration was invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChannelConfigurationError;

impl fmt::Display for ChannelConfigurationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid bounded byte-channel configuration")
    }
}

impl std::error::Error for ChannelConfigurationError {}
