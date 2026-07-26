//! Shared bounded stream framing for TCP and Unix exchange adapters.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_codec::{
    decode_challenge, decode_request, decode_response, encode_challenge, encode_request,
    encode_response,
};
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, MAX_BODY_BYTES, MAX_PROOF_BYTES,
    MAX_RESULT_BYTES, PeerObservation,
};
use auths_proof_exchange_port::{ClientProofChannel, ServerProofChannel};
use std::{fmt, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::timeout,
};

const MAX_CHALLENGE_FRAME: usize = 4 * 1024;
const MAX_SUBMISSION_FRAME: usize = MAX_BODY_BYTES as usize + MAX_PROOF_BYTES as usize + 4096;
const MAX_RESPONSE_FRAME: usize = MAX_RESULT_BYTES + 16 * 1024;

/// Bounded I/O deadline shared by stream transports.
#[derive(Clone, Copy, Debug)]
pub struct FramingConfig {
    deadline: Duration,
}

impl FramingConfig {
    /// Constructs a deadline between one nanosecond and sixty seconds.
    ///
    /// # Errors
    ///
    /// Returns a configuration error outside that range.
    pub fn new(deadline: Duration) -> Result<Self, FramingError> {
        if deadline.is_zero() || deadline > Duration::from_mins(1) {
            return Err(FramingError::Configuration);
        }
        Ok(Self { deadline })
    }

    /// Returns the per-frame I/O deadline.
    #[must_use]
    pub const fn deadline(self) -> Duration {
        self.deadline
    }
}

impl Default for FramingConfig {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(10),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Connected,
    Challenged,
    Submitted,
    Completed,
}

/// Client side of the one-submission stream state machine.
pub struct FramedClient<S> {
    stream: S,
    peer: PeerObservation,
    state: State,
    config: FramingConfig,
    challenge: Option<ActionChallenge>,
}

impl<S> FramedClient<S> {
    /// Wraps an already connected stream and its typed peer observation.
    #[must_use]
    pub const fn new(stream: S, peer: PeerObservation, config: FramingConfig) -> Self {
        Self {
            stream,
            peer,
            state: State::Connected,
            config,
            challenge: None,
        }
    }
}

/// Service side of the one-submission stream state machine.
pub struct FramedServer<S> {
    stream: S,
    peer: PeerObservation,
    state: State,
    config: FramingConfig,
    challenge: Option<ActionChallenge>,
}

impl<S> FramedServer<S> {
    /// Wraps an already accepted stream and its typed peer observation.
    #[must_use]
    pub const fn new(stream: S, peer: PeerObservation, config: FramingConfig) -> Self {
        Self {
            stream,
            peer,
            state: State::Connected,
            config,
            challenge: None,
        }
    }
}

#[async_trait]
impl<S> ClientProofChannel for FramedClient<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Error = FramingError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn receive_challenge(&mut self) -> Result<ActionChallenge, Self::Error> {
        if self.state != State::Connected {
            return Err(FramingError::Sequence);
        }
        let frame = read_frame(&mut self.stream, MAX_CHALLENGE_FRAME, self.config.deadline).await?;
        let challenge = decode_challenge(&frame).map_err(|_| FramingError::Codec)?;
        self.challenge = Some(challenge.clone());
        self.state = State::Challenged;
        Ok(challenge)
    }

    async fn submit_action(
        &mut self,
        request: ActionSubmission,
    ) -> Result<ActionResponse, Self::Error> {
        if self.state != State::Challenged {
            return Err(FramingError::Sequence);
        }
        if self
            .challenge
            .as_ref()
            .is_none_or(|challenge| !request.matches_challenge(challenge))
        {
            return Err(FramingError::Binding);
        }
        write_frame(
            &mut self.stream,
            &encode_request(&request),
            MAX_SUBMISSION_FRAME,
            self.config.deadline,
        )
        .await?;
        self.state = State::Submitted;
        let frame = read_frame(&mut self.stream, MAX_RESPONSE_FRAME, self.config.deadline).await?;
        let response = decode_response(&frame).map_err(|_| FramingError::Codec)?;
        self.state = State::Completed;
        Ok(response)
    }
}

#[async_trait]
impl<S> ServerProofChannel for FramedServer<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    type Error = FramingError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn send_challenge(&mut self, challenge: ActionChallenge) -> Result<(), Self::Error> {
        if self.state != State::Connected {
            return Err(FramingError::Sequence);
        }
        write_frame(
            &mut self.stream,
            &encode_challenge(&challenge),
            MAX_CHALLENGE_FRAME,
            self.config.deadline,
        )
        .await?;
        self.challenge = Some(challenge);
        self.state = State::Challenged;
        Ok(())
    }

    async fn receive_action(
        &mut self,
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, Self::Error> {
        if self.state != State::Challenged {
            return Err(FramingError::Sequence);
        }
        if self.challenge.as_ref() != Some(challenge) {
            return Err(FramingError::Binding);
        }
        let frame =
            read_frame(&mut self.stream, MAX_SUBMISSION_FRAME, self.config.deadline).await?;
        let submission = decode_request(&frame, challenge).map_err(|_| FramingError::Codec)?;
        self.state = State::Submitted;
        Ok(submission)
    }

    async fn send_response(&mut self, response: ActionResponse) -> Result<(), Self::Error> {
        if self.state != State::Submitted {
            return Err(FramingError::Sequence);
        }
        write_frame(
            &mut self.stream,
            &encode_response(&response),
            MAX_RESPONSE_FRAME,
            self.config.deadline,
        )
        .await?;
        self.stream.shutdown().await.map_err(|_| FramingError::Io)?;
        self.state = State::Completed;
        Ok(())
    }
}

async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    payload: &[u8],
    maximum: usize,
    deadline: Duration,
) -> Result<(), FramingError> {
    if payload.len() > maximum {
        return Err(FramingError::Limit);
    }
    let length = u32::try_from(payload.len()).map_err(|_| FramingError::Limit)?;
    timeout(deadline, async {
        stream
            .write_all(&length.to_be_bytes())
            .await
            .map_err(|_| FramingError::Io)?;
        stream
            .write_all(payload)
            .await
            .map_err(|_| FramingError::Io)?;
        stream.flush().await.map_err(|_| FramingError::Io)
    })
    .await
    .map_err(|_| FramingError::Timeout)?
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
    deadline: Duration,
) -> Result<Vec<u8>, FramingError> {
    timeout(deadline, async {
        let mut length = [0; 4];
        stream
            .read_exact(&mut length)
            .await
            .map_err(|_| FramingError::Io)?;
        let length =
            usize::try_from(u32::from_be_bytes(length)).map_err(|_| FramingError::Limit)?;
        if length > maximum {
            return Err(FramingError::Limit);
        }
        let mut payload = vec![0; length];
        stream
            .read_exact(&mut payload)
            .await
            .map_err(|_| FramingError::Io)?;
        Ok(payload)
    })
    .await
    .map_err(|_| FramingError::Timeout)?
}

/// Stream framing failure, kept separate from Auths verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramingError {
    /// Configuration is invalid.
    Configuration,
    /// Semantic message sequence is invalid.
    Sequence,
    /// Declared or encoded frame exceeds its bound.
    Limit,
    /// Deterministic message codec rejected a frame.
    Codec,
    /// Submission or service state does not match the issued challenge.
    Binding,
    /// Stream I/O failed.
    Io,
    /// Per-frame deadline elapsed.
    Timeout,
}

impl fmt::Display for FramingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid framing configuration",
            Self::Sequence => "invalid exchange sequence",
            Self::Limit => "exchange frame limit exceeded",
            Self::Codec => "invalid deterministic exchange message",
            Self::Binding => "exchange challenge binding mismatch",
            Self::Io => "exchange stream I/O failed",
            Self::Timeout => "exchange frame deadline elapsed",
        })
    }
}

impl std::error::Error for FramingError {}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_exchange_model::{
        AUTHS_PROTOCOL_V1, ChallengeNonce, ExchangeAudience, ExchangeMetrics, ExchangeOutcome,
        ExchangeProfileId, ProfileBinding,
    };
    fn challenge() -> ActionChallenge {
        ActionChallenge::new(
            ChallengeNonce::new([7; 32]),
            ExchangeAudience::parse("mcp://reports").unwrap(),
            100,
            1024,
            4096,
            ProfileBinding::new(
                AUTHS_PROTOCOL_V1,
                ExchangeProfileId::parse("auths.mcp").unwrap(),
                1,
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn duplex_state_machine_allows_exactly_one_submission() {
        let (client_stream, server_stream) = tokio::io::duplex(16 * 1024);
        let config = FramingConfig::default();
        let mut client =
            FramedClient::new(client_stream, PeerObservation::ServerAuthenticated, config);
        let mut server = FramedServer::new(server_stream, PeerObservation::Unauthenticated, config);
        let expected = challenge();
        let server_task = tokio::spawn(async move {
            server.send_challenge(expected.clone()).await.unwrap();
            let submission = server.receive_action(&expected).await.unwrap();
            assert_eq!(submission.body(), b"body");
            server
                .send_response(ActionResponse::new(
                    Some([4; 32]),
                    ExchangeOutcome::completed(b"ok".to_vec()).unwrap(),
                    ExchangeMetrics::default(),
                ))
                .await
                .unwrap();
        });
        let received = client.receive_challenge().await.unwrap();
        let mismatched_challenge = ActionChallenge::new(
            ChallengeNonce::new([8; 32]),
            received.audience().clone(),
            received.expires_at(),
            received.max_body_bytes(),
            received.max_proof_bytes(),
            ProfileBinding::new(
                received.auths_protocol(),
                received.profile_id().clone(),
                received.profile_version(),
            )
            .unwrap(),
        )
        .unwrap();
        let mismatched =
            ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &mismatched_challenge)
                .unwrap();
        assert_eq!(
            client.submit_action(mismatched).await,
            Err(FramingError::Binding)
        );
        let submission =
            ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &received).unwrap();
        let response = client.submit_action(submission.clone()).await.unwrap();
        assert_eq!(response.request_id(), Some(&[4; 32]));
        assert_eq!(
            client.submit_action(submission).await,
            Err(FramingError::Sequence)
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_declared_frame_is_rejected_before_allocation() {
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer
            .write_all(&(u32::try_from(MAX_CHALLENGE_FRAME + 1).unwrap()).to_be_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_frame(&mut reader, MAX_CHALLENGE_FRAME, Duration::from_secs(1)).await,
            Err(FramingError::Limit)
        );
    }
}
