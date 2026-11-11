//! Server-authenticated HTTPS exchange client and framework-neutral service
//! codec.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_codec::{
    decode_challenge, decode_request, decode_response, encode_challenge, encode_request,
    encode_response,
};
use auths_proof_exchange_model::{
    ActionChallenge, ActionResponse, ActionSubmission, MAX_RESULT_BYTES, PeerObservation,
};
use auths_proof_exchange_port::ClientProofChannel;
use reqwest::{Client, Response};
use std::fmt;

/// Exact content type for deterministic exchange messages.
pub const CONTENT_TYPE: &str = "application/vnd.auths.exchange.v1+cbor";
const MAX_CHALLENGE_BYTES: usize = 4 * 1024;
const MAX_RESPONSE_BYTES: usize = MAX_RESULT_BYTES + 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum State {
    Connected,
    Challenged,
    Completed,
    Unavailable,
}

/// HTTPS client using deterministic messages without treating TLS identity as
/// Auths authority.
pub struct HttpsClientChannel {
    client: Client,
    base_url: String,
    peer: PeerObservation,
    challenge: Option<ActionChallenge>,
    state: State,
}

impl HttpsClientChannel {
    /// Constructs a channel for an exact HTTPS origin.
    ///
    /// # Errors
    ///
    /// Returns a configuration error for a non-HTTPS, whitespace-bearing, or
    /// oversized origin.
    pub fn new(
        client: Client,
        base_url: impl Into<String>,
        peer: PeerObservation,
    ) -> Result<Self, HttpsTransportError> {
        let base_url = base_url.into();
        if !base_url.starts_with("https://")
            || base_url.len() > 2048
            || base_url.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(HttpsTransportError::Configuration);
        }
        if !peer.is_authenticated() {
            return Err(HttpsTransportError::Configuration);
        }
        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').into(),
            peer,
            challenge: None,
            state: State::Connected,
        })
    }
}

#[async_trait]
impl ClientProofChannel for HttpsClientChannel {
    type Error = HttpsTransportError;

    fn peer_observation(&self) -> &PeerObservation {
        &self.peer
    }

    async fn receive_challenge(&mut self) -> Result<ActionChallenge, Self::Error> {
        if self.state != State::Connected {
            return Err(HttpsTransportError::Sequence);
        }
        self.state = State::Unavailable;
        let response = self
            .client
            .get(format!("{}/auths/v1/challenge", self.base_url))
            .header("accept", CONTENT_TYPE)
            .send()
            .await
            .map_err(|_| HttpsTransportError::Network)?
            .error_for_status()
            .map_err(|_| HttpsTransportError::HttpStatus)?;
        let bytes = bounded_body(response, MAX_CHALLENGE_BYTES).await?;
        let challenge = decode_challenge(&bytes).map_err(|_| HttpsTransportError::Codec)?;
        self.challenge = Some(challenge.clone());
        self.state = State::Challenged;
        Ok(challenge)
    }

    async fn submit_action(
        &mut self,
        request: ActionSubmission,
    ) -> Result<ActionResponse, Self::Error> {
        if self.state != State::Challenged {
            return Err(HttpsTransportError::Sequence);
        }
        if self
            .challenge
            .as_ref()
            .is_none_or(|challenge| !request.matches_challenge(challenge))
        {
            return Err(HttpsTransportError::Binding);
        }
        // Retain the admitted attempt even if its response is lost or its
        // waiter is dropped. A new channel is required after uncertainty.
        self.state = State::Unavailable;
        let response = self
            .client
            .post(format!("{}/auths/v1/submission", self.base_url))
            .header("content-type", CONTENT_TYPE)
            .header("accept", CONTENT_TYPE)
            .body(encode_request(&request))
            .send()
            .await
            .map_err(|_| HttpsTransportError::Network)?
            .error_for_status()
            .map_err(|_| HttpsTransportError::HttpStatus)?;
        let bytes = bounded_body(response, MAX_RESPONSE_BYTES).await?;
        let response = decode_response(&bytes).map_err(|_| HttpsTransportError::Codec)?;
        self.state = State::Completed;
        Ok(response)
    }
}

/// Framework-neutral deterministic HTTPS service mapping.
pub struct HttpsServiceCodec;

impl HttpsServiceCodec {
    /// Encodes a challenge response body.
    #[must_use]
    pub fn challenge(challenge: &ActionChallenge) -> Vec<u8> {
        encode_challenge(challenge)
    }

    /// Decodes a submission request body against issued challenge state.
    ///
    /// # Errors
    ///
    /// Returns a codec error for malformed, non-canonical, over-limit, or
    /// mismatched input.
    pub fn submission(
        bytes: &[u8],
        challenge: &ActionChallenge,
    ) -> Result<ActionSubmission, HttpsTransportError> {
        decode_request(bytes, challenge).map_err(|_| HttpsTransportError::Codec)
    }

    /// Encodes an application response body.
    #[must_use]
    pub fn response(response: &ActionResponse) -> Vec<u8> {
        encode_response(response)
    }
}

async fn bounded_body(
    mut response: Response,
    maximum: usize,
) -> Result<Vec<u8>, HttpsTransportError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(HttpsTransportError::Limit);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| HttpsTransportError::Network)?
    {
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(HttpsTransportError::Limit);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

/// HTTPS adapter failure, separate from Auths verdicts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpsTransportError {
    /// Origin or peer configuration is invalid.
    Configuration,
    /// Exchange sequence is invalid.
    Sequence,
    /// Network request failed.
    Network,
    /// HTTP status is not successful.
    HttpStatus,
    /// Response exceeded its message bound.
    Limit,
    /// Deterministic exchange codec rejected a message.
    Codec,
    /// Submission does not match the complete issued challenge binding.
    Binding,
}

impl fmt::Display for HttpsTransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Configuration => "invalid HTTPS exchange configuration",
            Self::Sequence => "invalid HTTPS exchange sequence",
            Self::Network => "HTTPS exchange network failure",
            Self::HttpStatus => "HTTPS exchange returned a non-success status",
            Self::Limit => "HTTPS exchange response limit exceeded",
            Self::Codec => "invalid deterministic HTTPS exchange message",
            Self::Binding => "HTTPS submission binding mismatch",
        })
    }
}

impl std::error::Error for HttpsTransportError {}

#[cfg(test)]
mod delivery_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_proof_exchange_model::{
        AUTHS_PROTOCOL_V1, ChallengeNonce, ExchangeAudience, ExchangeProfileId, ProfileBinding,
    };
    use std::{
        future::Future as _,
        task::{Context, Poll, Waker},
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
    async fn cancelled_http_attempt_cannot_start_another_submission() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let transport = Client::builder()
            .no_proxy()
            .resolve("held.invalid", address)
            .build()
            .unwrap();
        let mut channel = HttpsClientChannel::new(
            transport,
            format!("https://held.invalid:{}", address.port()),
            PeerObservation::ServerAuthenticated,
        )
        .unwrap();
        let expected = challenge();
        channel.challenge = Some(expected.clone());
        channel.state = State::Challenged;
        let request =
            ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &expected).unwrap();
        let mut operation = Box::pin(channel.submit_action(request.clone()));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        // No TLS peer is serving this listener. A retry must reject locally,
        // rather than begin another HTTP request or wait for the lost reply.
        let mut retry = Box::pin(channel.submit_action(request));
        assert!(matches!(
            retry.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(Err(HttpsTransportError::Sequence))
        ));
    }

    #[tokio::test]
    async fn failed_challenge_acquisition_is_not_a_fresh_channel() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let transport = Client::builder()
            .no_proxy()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        let mut channel = HttpsClientChannel::new(
            transport,
            format!("https://{address}"),
            PeerObservation::ServerAuthenticated,
        )
        .unwrap();
        assert_eq!(
            channel.receive_challenge().await,
            Err(HttpsTransportError::Network)
        );
        assert_eq!(
            channel.receive_challenge().await,
            Err(HttpsTransportError::Sequence)
        );
    }
}
