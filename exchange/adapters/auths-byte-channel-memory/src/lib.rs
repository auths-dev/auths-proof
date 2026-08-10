//! In-memory proof adapter for the bounded opaque byte-channel port.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_byte_channel::{BoundedByteChannel, ChannelLimits, PeerObservation};
use std::fmt;
use tokio::{sync::mpsc, time::timeout};

/// One endpoint of a bounded in-memory duplex channel.
pub struct MemoryByteChannel {
    limits: ChannelLimits,
    peer: PeerObservation,
    send: Option<mpsc::Sender<Vec<u8>>>,
    receive: mpsc::Receiver<Vec<u8>>,
}

impl MemoryByteChannel {
    /// Constructs a connected pair with caller-owned peer observations.
    #[must_use]
    pub fn pair(
        limits: ChannelLimits,
        left_observes_right: PeerObservation,
        right_observes_left: PeerObservation,
    ) -> (Self, Self) {
        let (left_send, right_receive) = mpsc::channel(1);
        let (right_send, left_receive) = mpsc::channel(1);
        (
            Self {
                limits,
                peer: left_observes_right,
                send: Some(left_send),
                receive: left_receive,
            },
            Self {
                limits,
                peer: right_observes_left,
                send: Some(right_send),
                receive: right_receive,
            },
        )
    }
}

#[async_trait]
impl BoundedByteChannel for MemoryByteChannel {
    type Error = MemoryChannelError;

    fn limits(&self) -> ChannelLimits {
        self.limits
    }

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn send_frame(&mut self, payload: &[u8]) -> Result<(), Self::Error> {
        if payload.is_empty() || payload.len() > self.limits.max_frame_bytes() {
            return Err(MemoryChannelError::Limit);
        }
        let send = self.send.as_ref().ok_or(MemoryChannelError::Sequence)?;
        timeout(self.limits.operation_timeout(), send.send(payload.to_vec()))
            .await
            .map_err(|_| MemoryChannelError::Timeout)?
            .map_err(|_| MemoryChannelError::Transport)
    }

    async fn receive_frame(&mut self) -> Result<Vec<u8>, Self::Error> {
        let payload = timeout(self.limits.operation_timeout(), self.receive.recv())
            .await
            .map_err(|_| MemoryChannelError::Timeout)?
            .ok_or(MemoryChannelError::Transport)?;
        if payload.is_empty() || payload.len() > self.limits.max_frame_bytes() {
            return Err(MemoryChannelError::Limit);
        }
        Ok(payload)
    }

    async fn finish_send(&mut self) -> Result<(), Self::Error> {
        self.send.take().ok_or(MemoryChannelError::Sequence)?;
        Ok(())
    }
}

/// In-memory limit, deadline, sequencing, or channel failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryChannelError {
    /// A frame is empty or exceeds the caller-selected limit.
    Limit,
    /// The caller-selected operation deadline elapsed.
    Timeout,
    /// The send side was used after it was finished.
    Sequence,
    /// The remote endpoint was dropped before the operation completed.
    Transport,
}

impl fmt::Display for MemoryChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Limit => "in-memory byte-channel limit exceeded",
            Self::Timeout => "in-memory byte-channel timed out",
            Self::Sequence => "in-memory byte-channel sequence violated",
            Self::Transport => "in-memory byte-channel peer unavailable",
        })
    }
}

impl std::error::Error for MemoryChannelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn pair_moves_only_bounded_opaque_bytes() {
        let limits = ChannelLimits::new(32, Duration::from_secs(1)).unwrap();
        let (mut left, mut right) = MemoryByteChannel::pair(
            limits,
            PeerObservation::Unauthenticated,
            PeerObservation::Unauthenticated,
        );
        left.send_frame(b"opaque request").await.unwrap();
        assert_eq!(right.receive_frame().await.unwrap(), b"opaque request");
        left.finish_send().await.unwrap();
        assert_eq!(
            left.send_frame(b"too late").await,
            Err(MemoryChannelError::Sequence)
        );
    }
}
