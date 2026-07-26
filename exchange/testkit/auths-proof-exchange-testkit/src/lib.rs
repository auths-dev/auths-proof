//! Shared proof-exchange transport conformance.

#![forbid(unsafe_code)]

use async_trait::async_trait;
use auths_proof_exchange_codec::{decode_challenge, decode_response};
use auths_proof_exchange_file::FileExchange;
use auths_proof_exchange_framing::FramingConfig;
use auths_proof_exchange_https::HttpsServiceCodec;
use auths_proof_exchange_iroh::{
    ALPN_V1, IrohChannelConfig, IrohClientChannel, IrohServerChannel, PathObservation,
};
use auths_proof_exchange_memory::channel_pair;
use auths_proof_exchange_model::{
    AUTHS_PROTOCOL_V1, ActionChallenge, ActionResponse, ActionSubmission, ChallengeNonce,
    ExchangeAudience, ExchangeMetrics, ExchangeOutcome, ExchangeProfileId, PeerObservation,
    ProfileBinding,
};
use auths_proof_exchange_port::{
    ClientProofChannel, ProofExchangeService, ServerProofChannel, ServiceError, serve_one,
};
use auths_proof_exchange_tcp::{accept as accept_tcp, connect as connect_tcp};
#[cfg(unix)]
use auths_proof_exchange_unix::{accept as accept_unix, connect as connect_unix};
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;

pub const TEST_BODY: &[u8] = br#"{"arguments":{"name":"q3"},"name":"read_report"}"#;
/// Opaque proof payload used to prove transports do not interpret kernel
/// bytes.
pub const TEST_PROOF: &[u8] = b"opaque-auths-proof-transport-sentinel-v1";

#[derive(Clone)]
struct RecordingService {
    challenge: ActionChallenge,
    received: Arc<Mutex<Vec<ActionSubmission>>>,
}

impl RecordingService {
    fn new() -> Self {
        Self {
            challenge: test_challenge(),
            received: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn received(&self) -> Vec<ActionSubmission> {
        self.received.lock().expect("test mutex").clone()
    }
}

#[async_trait]
impl ProofExchangeService for RecordingService {
    async fn issue_challenge(
        &self,
        _peer: &PeerObservation,
    ) -> Result<ActionChallenge, ServiceError> {
        Ok(self.challenge.clone())
    }

    async fn handle_action(
        &self,
        _peer: &PeerObservation,
        _challenge: &ActionChallenge,
        request: ActionSubmission,
    ) -> ActionResponse {
        self.received
            .lock()
            .expect("test mutex")
            .push(request.clone());
        ActionResponse::new(
            Some([0x44; 32]),
            ExchangeOutcome::completed(b"report:q3".to_vec()).expect("fixed result"),
            ExchangeMetrics::new(7, 3),
        )
    }
}

/// Returns the fixed challenge shared by all transport conformance tests.
///
/// # Panics
///
/// Panics if the repository-owned constant fixture is invalid.
#[must_use]
pub fn test_challenge() -> ActionChallenge {
    ActionChallenge::new(
        ChallengeNonce::new([0xa5; 32]),
        ExchangeAudience::parse("mcp://reports").expect("fixed audience"),
        1_900_000_000,
        4096,
        8192,
        ProfileBinding::new(
            AUTHS_PROTOCOL_V1,
            ExchangeProfileId::parse("auths.mcp").expect("fixed profile"),
            1,
        )
        .expect("fixed profile binding"),
    )
    .expect("fixed challenge")
}

/// Asserts the complete V1 sequence over the in-memory adapter.
///
/// # Panics
///
/// Panics when a conformance invariant or repository-owned fixture fails.
pub async fn assert_memory_conformance() {
    let service = RecordingService::new();
    let (mut client, mut server) = channel_pair(
        PeerObservation::ServerAuthenticated,
        PeerObservation::AuthenticatedOpaque {
            kind: "memory-test".into(),
            identifier: vec![1, 2, 3],
        },
    );
    let server_service = service.clone();
    let server_task =
        tokio::spawn(async move { serve_one(&mut server, &server_service).await.unwrap() });

    assert_eq!(
        client.peer_observation(),
        &PeerObservation::ServerAuthenticated
    );
    let challenge = client.receive_challenge().await.expect("challenge");
    let request = ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge)
        .expect("request");
    let response = client
        .submit_action(request.clone())
        .await
        .expect("response");
    server_task.await.expect("server task");

    assert_eq!(response.request_id(), Some(&[0x44; 32]));
    assert_eq!(service.received(), vec![request]);

    let replay = ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge)
        .expect("request");
    assert!(
        client.submit_action(replay).await.is_err(),
        "V1 channel admitted a second submission"
    );
}

/// Asserts the complete V1 sequence over a local direct Iroh connection.
///
/// # Panics
///
/// Panics when local Iroh setup or any conformance invariant fails.
pub async fn assert_iroh_conformance() {
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN_V1.to_vec()])
        .bind()
        .await
        .expect("bind server endpoint");
    let client_endpoint = Endpoint::bind(presets::N0)
        .await
        .expect("bind client endpoint");
    let server_addr = direct_addr(&server_endpoint);
    let expected_server_id = *server_endpoint.id().as_bytes();
    let expected_client_id = *client_endpoint.id().as_bytes();
    let config = IrohChannelConfig::default();
    let service = RecordingService::new();
    let server_service = service.clone();
    let server_endpoint_task = server_endpoint.clone();

    let server_task = tokio::spawn(async move {
        let mut channel = IrohServerChannel::accept(&server_endpoint_task, config)
            .await
            .expect("accept Iroh");
        assert_eq!(
            channel.peer_observation(),
            &PeerObservation::IrohEndpoint(expected_client_id)
        );
        serve_one(&mut channel, &server_service)
            .await
            .expect("serve Iroh");
    });

    let mut client = IrohClientChannel::connect(&client_endpoint, server_addr, config)
        .await
        .expect("connect Iroh");
    assert_eq!(
        client.peer_observation(),
        &PeerObservation::IrohEndpoint(expected_server_id)
    );
    assert_eq!(client.path_observation(), PathObservation::Direct);
    let challenge = client.receive_challenge().await.expect("Iroh challenge");
    let request = ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge)
        .expect("request");
    let response = client.submit_action(request.clone()).await;
    server_task.await.expect("Iroh server task");
    let response = response.expect("Iroh response");

    assert_eq!(response.request_id(), Some(&[0x44; 32]));
    assert_eq!(service.received(), vec![request]);
    client_endpoint.close().await;
    server_endpoint.close().await;
}

/// Asserts the complete V1 sequence over a loopback raw TCP connection.
///
/// # Panics
///
/// Panics if loopback setup, transport I/O, or a conformance assertion fails.
pub async fn assert_tcp_conformance() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind TCP listener");
    let address = listener.local_addr().expect("TCP listener address");
    let service = RecordingService::new();
    let server_service = service.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = accept_tcp(&listener, FramingConfig::default())
            .await
            .expect("accept TCP");
        assert!(matches!(
            channel.peer_observation(),
            PeerObservation::TcpEndpoint(_)
        ));
        serve_one(&mut channel, &server_service)
            .await
            .expect("serve TCP");
    });
    let mut client = connect_tcp(address, FramingConfig::default())
        .await
        .expect("connect TCP");
    assert!(matches!(
        client.peer_observation(),
        PeerObservation::TcpEndpoint(_)
    ));
    assert_stream_exchange(&mut client).await;
    server_task.await.expect("TCP server task");
    assert_eq!(service.received().len(), 1);
}

/// Asserts the complete V1 sequence over a local Unix-domain socket.
///
/// # Panics
///
/// Panics if local socket setup, transport I/O, or a conformance assertion
/// fails.
#[cfg(unix)]
pub async fn assert_unix_conformance() {
    let directory = tempfile::tempdir().expect("Unix socket directory");
    let path = directory.path().join("auths.sock");
    let listener = UnixListener::bind(&path).expect("bind Unix listener");
    let service = RecordingService::new();
    let server_service = service.clone();
    let server_task = tokio::spawn(async move {
        let mut channel = accept_unix(&listener, FramingConfig::default())
            .await
            .expect("accept Unix");
        assert!(matches!(
            channel.peer_observation(),
            PeerObservation::UnixPeerCredentials { .. }
        ));
        serve_one(&mut channel, &server_service)
            .await
            .expect("serve Unix");
    });
    let mut client = connect_unix(&path, FramingConfig::default())
        .await
        .expect("connect Unix");
    assert_eq!(
        client.peer_observation(),
        &PeerObservation::ServerAuthenticated
    );
    assert_stream_exchange(&mut client).await;
    server_task.await.expect("Unix server task");
    assert_eq!(service.received().len(), 1);
}

/// Asserts deterministic file-envelope round trips and typed observations.
///
/// # Panics
///
/// Panics if temporary-file I/O or a conformance assertion fails.
pub async fn assert_file_conformance() {
    let directory = tempfile::tempdir().expect("file exchange directory");
    let exchange = FileExchange::new(directory.path(), 7);
    let challenge = test_challenge();
    let challenge_observation = exchange
        .write_challenge(&challenge)
        .await
        .expect("write challenge");
    assert!(matches!(
        challenge_observation,
        PeerObservation::FileEnvelope { sequence: 7, .. }
    ));
    assert_eq!(
        exchange.read_challenge().await.expect("read challenge"),
        challenge
    );
    let submission =
        ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge).unwrap();
    exchange
        .write_submission(&submission)
        .await
        .expect("write submission");
    assert_eq!(
        exchange
            .read_submission(&challenge)
            .await
            .expect("read submission"),
        submission
    );
    let response = test_response();
    exchange
        .write_response(&response)
        .await
        .expect("write response");
    assert_eq!(
        exchange.read_response().await.expect("read response"),
        response
    );
    let acknowledgement = exchange
        .write_acknowledgement(&submission, &response)
        .await
        .expect("write acknowledgment");
    assert_eq!(acknowledgement.sequence(), 7);
    assert_eq!(
        exchange
            .read_acknowledgement(&submission, &response)
            .await
            .expect("read acknowledgment"),
        acknowledgement
    );
}

/// Asserts the framework-neutral HTTPS mapping uses the same deterministic
/// challenge, submission, and response messages.
///
/// # Panics
///
/// Panics if a repository-owned message is invalid or a conformance assertion
/// fails.
pub fn assert_https_codec_conformance() {
    let challenge = test_challenge();
    let challenge_bytes = HttpsServiceCodec::challenge(&challenge);
    assert_eq!(
        decode_challenge(&challenge_bytes).expect("HTTPS challenge"),
        challenge
    );
    let submission =
        ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge).unwrap();
    let submission_bytes = auths_proof_exchange_codec::encode_request(&submission);
    assert_eq!(
        HttpsServiceCodec::submission(&submission_bytes, &challenge).expect("HTTPS submission"),
        submission
    );
    let response = test_response();
    let response_bytes = HttpsServiceCodec::response(&response);
    assert_eq!(
        decode_response(&response_bytes).expect("HTTPS response"),
        response
    );
}

async fn assert_stream_exchange<C>(client: &mut C)
where
    C: ClientProofChannel,
    C::Error: core::fmt::Debug,
{
    let challenge = client.receive_challenge().await.expect("stream challenge");
    let request =
        ActionSubmission::new(TEST_BODY.to_vec(), TEST_PROOF.to_vec(), &challenge).unwrap();
    let response = client
        .submit_action(request)
        .await
        .expect("stream response");
    assert_eq!(response, test_response());
}

fn test_response() -> ActionResponse {
    ActionResponse::new(
        Some([0x44; 32]),
        ExchangeOutcome::completed(b"report:q3".to_vec()).expect("fixed result"),
        ExchangeMetrics::new(7, 3),
    )
}

fn direct_addr(endpoint: &Endpoint) -> EndpointAddr {
    let address = endpoint.addr();
    let direct = address
        .ip_addrs()
        .next()
        .copied()
        .expect("local endpoint has a direct address");
    EndpointAddr::new(endpoint.id()).with_ip_addr(direct)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_adapter_passes_shared_conformance() {
        assert_memory_conformance().await;
    }

    #[tokio::test]
    #[ignore = "requires local UDP sockets"]
    async fn iroh_adapter_passes_shared_conformance() {
        assert_iroh_conformance().await;
    }

    #[tokio::test]
    #[ignore = "requires local TCP sockets"]
    async fn tcp_adapter_passes_shared_conformance() {
        assert_tcp_conformance().await;
    }

    #[cfg(unix)]
    #[tokio::test]
    #[ignore = "requires local Unix sockets"]
    async fn unix_adapter_passes_shared_conformance() {
        assert_unix_conformance().await;
    }

    #[tokio::test]
    async fn file_adapter_passes_shared_conformance() {
        assert_file_conformance().await;
    }

    #[test]
    fn https_adapter_passes_shared_codec_conformance() {
        assert_https_codec_conformance();
    }
}
