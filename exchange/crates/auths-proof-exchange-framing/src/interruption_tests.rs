use super::*;
use std::{
    future::Future as _,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
};
use tokio::io::ReadBuf;

struct PartialStream {
    input: Vec<u8>,
    read_position: usize,
    written: usize,
    write_capacity: usize,
    polls: Arc<AtomicUsize>,
}

impl PartialStream {
    fn new(input: Vec<u8>, write_capacity: usize) -> Self {
        Self {
            input,
            read_position: 0,
            written: 0,
            write_capacity,
            polls: Arc::default(),
        }
    }
}

impl AsyncRead for PartialStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let remaining = &self.input[self.read_position..];
        if remaining.is_empty() {
            return Poll::Pending;
        }
        let count = remaining.len().min(buffer.remaining());
        buffer.put_slice(&remaining[..count]);
        self.read_position += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for PartialStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        let count = bytes.len().min(self.write_capacity - self.written);
        if count == 0 {
            return Poll::Pending;
        }
        self.written += count;
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn cancelled_partial_challenge_reads_cannot_restart_at_a_false_frame_boundary() {
    let encoded = encode_challenge(&tests::challenge());
    let mut complete = u32::try_from(encoded.len()).unwrap().to_be_bytes().to_vec();
    complete.extend_from_slice(&encoded);
    for consumed in [1, 3, 4, complete.len() - 1] {
        let stream = PartialStream::new(complete[..consumed].to_vec(), usize::MAX);
        let polls = Arc::clone(&stream.polls);
        let mut client = FramedClient::new(
            stream,
            PeerObservation::Unauthenticated,
            FramingConfig::default(),
        );
        let mut operation = Box::pin(client.receive_challenge());
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        assert_eq!(client.stream.read_position, consumed);
        let previous = polls.load(Ordering::SeqCst);
        assert_eq!(
            client.receive_challenge().await,
            Err(FramingError::Sequence)
        );
        assert_eq!(
            polls.load(Ordering::SeqCst),
            previous,
            "no I/O after abandonment"
        );
    }
}

#[tokio::test]
async fn timed_out_partial_challenge_stays_unavailable() {
    let stream = PartialStream::new(vec![0, 0], usize::MAX);
    let mut client = FramedClient::new(
        stream,
        PeerObservation::Unauthenticated,
        FramingConfig::new(Duration::from_millis(1)).unwrap(),
    );
    assert_eq!(client.receive_challenge().await, Err(FramingError::Timeout));
    assert_eq!(client.stream.read_position, 2);
    assert_eq!(
        client.receive_challenge().await,
        Err(FramingError::Sequence)
    );
}

#[tokio::test]
async fn cancelled_partial_challenge_write_cannot_append_a_second_frame() {
    for capacity in [1, 4, 5] {
        let stream = PartialStream::new(Vec::new(), capacity);
        let mut server = FramedServer::new(
            stream,
            PeerObservation::Unauthenticated,
            FramingConfig::default(),
        );
        let mut operation = Box::pin(server.send_challenge(tests::challenge()));
        assert!(
            operation
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        drop(operation);
        assert_eq!(server.stream.written, capacity);
        assert_eq!(
            server.send_challenge(tests::challenge()).await,
            Err(FramingError::Sequence)
        );
        assert_eq!(server.stream.written, capacity);
    }
}

#[tokio::test]
async fn delivered_submission_cancelled_before_response_cannot_be_resent() {
    let expected = tests::challenge();
    let request = ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &expected).unwrap();
    let stream = PartialStream::new(Vec::new(), usize::MAX);
    let mut client = FramedClient::new(
        stream,
        PeerObservation::Unauthenticated,
        FramingConfig::default(),
    );
    client.challenge = Some(expected);
    client.state = State::Challenged;
    let mut operation = Box::pin(client.submit_action(request.clone()));
    assert!(
        operation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(operation);
    let sent = client.stream.written;
    assert!(sent > 4);
    assert_eq!(
        client.submit_action(request).await,
        Err(FramingError::Sequence)
    );
    assert_eq!(client.stream.written, sent);
}

#[tokio::test]
async fn malformed_challenge_is_consumed_and_terminal() {
    let stream = PartialStream::new(vec![0, 0, 0, 1, 0xff], usize::MAX);
    let mut client = FramedClient::new(
        stream,
        PeerObservation::Unauthenticated,
        FramingConfig::default(),
    );
    assert_eq!(client.receive_challenge().await, Err(FramingError::Codec));
    assert_eq!(
        client.receive_challenge().await,
        Err(FramingError::Sequence)
    );
}

#[tokio::test]
async fn cancelled_server_action_read_cannot_admit_a_response_or_restart() {
    let expected = tests::challenge();
    let request = ActionSubmission::new(b"body".to_vec(), b"proof".to_vec(), &expected).unwrap();
    let encoded = encode_request(&request);
    let mut partial = u32::try_from(encoded.len()).unwrap().to_be_bytes().to_vec();
    partial.extend_from_slice(&encoded[..1]);
    let stream = PartialStream::new(partial, usize::MAX);
    let mut server = FramedServer::new(
        stream,
        PeerObservation::Unauthenticated,
        FramingConfig::default(),
    );
    server.state = State::Challenged;
    server.challenge = Some(expected.clone());
    let mut operation = Box::pin(server.receive_action(&expected));
    assert!(
        operation
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_pending()
    );
    drop(operation);
    assert_eq!(server.stream.read_position, 5);
    assert_eq!(
        server.receive_action(&expected).await,
        Err(FramingError::Sequence)
    );
    let response = ActionResponse::new(
        None,
        auths_proof_exchange_model::ExchangeOutcome::completed(b"ok".to_vec()).unwrap(),
        auths_proof_exchange_model::ExchangeMetrics::default(),
    );
    assert_eq!(
        server.send_response(response).await,
        Err(FramingError::Sequence)
    );
    assert_eq!(server.stream.written, 0);
}

#[tokio::test]
async fn response_shutdown_timeout_does_not_make_response_retriable() {
    let stream = PartialStream::new(Vec::new(), usize::MAX);
    let mut server = FramedServer::new(
        stream,
        PeerObservation::Unauthenticated,
        FramingConfig::new(Duration::from_millis(1)).unwrap(),
    );
    server.state = State::Submitted;
    let response = ActionResponse::new(
        None,
        auths_proof_exchange_model::ExchangeOutcome::completed(b"ok".to_vec()).unwrap(),
        auths_proof_exchange_model::ExchangeMetrics::default(),
    );
    assert_eq!(
        server.send_response(response.clone()).await,
        Err(FramingError::Timeout)
    );
    assert_eq!(
        server.send_response(response).await,
        Err(FramingError::Sequence)
    );
}
