use super::*;
use auths_proof_exchange_model::{
    AUTHS_PROTOCOL_V1, ChallengeNonce, ExchangeAudience, ExchangeMetrics, ExchangeOutcome,
    ExchangeProfileId, ProfileBinding,
};
use std::{
    future::Future as _,
    io::{Read as _, Write as _},
    net::{SocketAddr, TcpListener},
    sync::{Arc, mpsc},
    task::{Context, Poll, Waker},
    thread::JoinHandle,
    time::Duration,
};

struct HeldResponse {
    address: SocketAddr,
    certificate: reqwest::Certificate,
    delivered: tokio::sync::oneshot::Receiver<()>,
    release: mpsc::Sender<()>,
    thread: JoinHandle<()>,
}

fn held_response(expected_body: Vec<u8>) -> HeldResponse {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = reqwest::Certificate::from_der(key.cert.der()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.key_pair.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (delivered, received) = tokio::sync::oneshot::channel();
    let (release, wait) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let connection = rustls::ServerConnection::new(Arc::new(config)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            assert!(header.len() < 16 * 1024);
            let mut byte = [0_u8];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
        }
        let header = std::str::from_utf8(&header).unwrap();
        assert!(header.starts_with("POST /auths/v1/submission HTTP/1.1\r\n"));
        let length = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert_eq!(length, expected_body.len());
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        assert_eq!(body, expected_body);
        delivered.send(()).unwrap();
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        let body = encode_response(&ActionResponse::new(
            None,
            ExchangeOutcome::completed(b"ok".to_vec()).unwrap(),
            ExchangeMetrics::default(),
        ));
        let header = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: {CONTENT_TYPE}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
            body.len()
        );
        // The cancelled client may have closed its response connection already.
        let _ = stream
            .write_all(header.as_bytes())
            .and_then(|()| stream.write_all(&body));
        let _ = stream.flush();
    });
    HeldResponse {
        address,
        certificate,
        delivered: received,
        release,
        thread,
    }
}

#[tokio::test]
async fn cancelled_delivered_https_submission_cannot_be_sent_again() {
    let expected = ActionChallenge::new(
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
    .unwrap();
    let request = ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &expected).unwrap();
    let peer = held_response(encode_request(&request));
    let client = Client::builder()
        .no_proxy()
        .http1_only()
        .add_root_certificate(peer.certificate)
        .resolve("localhost", peer.address)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let mut channel = HttpsClientChannel::new(
        client,
        format!("https://localhost:{}", peer.address.port()),
        PeerObservation::ServerAuthenticated,
    )
    .unwrap();
    channel.state = State::Challenged;
    channel.challenge = Some(expected);
    let mut submission = Box::pin(channel.submit_action(request.clone()));
    tokio::select! {
        result = &mut submission => panic!("submission completed before the held response: {result:?}"),
        delivered = peer.delivered => delivered.unwrap(),
    }
    drop(submission);
    let mut retry = Box::pin(channel.submit_action(request));
    assert!(matches!(
        retry.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(HttpsTransportError::Sequence))
    ));
    peer.release.send(()).unwrap();
    peer.thread.join().unwrap();
}
