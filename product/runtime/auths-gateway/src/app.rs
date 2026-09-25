//! The application-socket protocol: one length-prefixed JSON frame in, one
//! out. A frame is exactly one of two closed schemas, a proof/action
//! submission or an observation request; anything else is refused without
//! reaching the application.

use crate::{GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::pin;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep_until, timeout_at};

/// Schema of a proof/action submission frame.
pub const APP_REQUEST_SCHEMA: &str = "auths.gateway-submit/1";
/// Schema of an observation request frame.
pub const APP_OBSERVE_SCHEMA: &str = "auths.gateway-observe/1";
/// Largest frame either side accepts.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

/// Deadlines for one socket session.
///
/// Every phase also ends by the session deadline, measured from accept. No
/// deadline cancels the engine call a session has started: when a deadline
/// passes first, the connection closes without a response and the call still
/// runs to completion, and the task serving the session, with the capacity
/// permit it holds, ends only then.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Longest wait for each request frame.
    pub frame_read: Duration,
    /// Longest wait for the engine's result, from the start of the call.
    pub result_wait: Duration,
    /// Longest wait to write the response frame.
    pub response_write: Duration,
    /// End of the whole session, whatever phase it is in.
    pub session: Duration,
}

/// Application sessions: the frame within 5 seconds, the result within 90
/// seconds, and the response within 5 seconds, all inside one 100-second
/// session deadline.
pub const APP_SESSION_LIMITS: SessionLimits = SessionLimits {
    frame_read: Duration::from_secs(5),
    result_wait: Duration::from_secs(90),
    response_write: Duration::from_secs(5),
    session: Duration::from_secs(100),
};

/// One session's deadline, started at accept. Every read, write, and wait on
/// the session's stream ends by it.
#[derive(Clone, Copy, Debug)]
pub struct SessionClock {
    limits: SessionLimits,
    deadline: Instant,
}

impl SessionClock {
    /// Starts the clock for a session accepted now.
    #[must_use]
    pub fn start(limits: SessionLimits) -> Self {
        Self {
            limits,
            deadline: Instant::now() + limits.session,
        }
    }

    /// Reads one frame within the frame-read limit and the session deadline.
    ///
    /// # Errors
    /// Returns [`read_frame`]'s codes, or `gateway.ipc.read-timeout` when a
    /// deadline passes first.
    pub async fn read_frame(&self, stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
        let until = self.deadline.min(Instant::now() + self.limits.frame_read);
        timeout_at(until, read_frame(stream))
            .await
            .unwrap_or(Err("gateway.ipc.read-timeout"))
    }

    /// Writes one frame within the response-write limit and the session
    /// deadline.
    ///
    /// # Errors
    /// Returns [`write_frame`]'s codes, or `gateway.ipc.write-timeout` when a
    /// deadline passes first.
    pub async fn write_frame(
        &self,
        stream: &mut UnixStream,
        bytes: &[u8],
    ) -> Result<(), &'static str> {
        let until = self
            .deadline
            .min(Instant::now() + self.limits.response_write);
        timeout_at(until, write_frame(stream, bytes))
            .await
            .unwrap_or(Err("gateway.ipc.write-timeout"))
    }

    /// Drives `work` to completion and never cancels it.
    ///
    /// Returns the stream and `work`'s output when `work` finishes within the
    /// result-wait limit and the session deadline. Otherwise closes `stream`
    /// when the first of them passes, still waits for `work`, and returns
    /// `None`.
    pub async fn complete<F: Future>(
        &self,
        stream: UnixStream,
        work: F,
    ) -> Option<(UnixStream, F::Output)> {
        let until = self.deadline.min(Instant::now() + self.limits.result_wait);
        let mut work = pin!(work);
        tokio::select! {
            biased;
            output = &mut work => Some((stream, output)),
            () = sleep_until(until) => {
                drop(stream);
                let _ = work.await;
                None
            }
        }
    }
}

/// A proof/action submission frame.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppSubmission {
    /// Must equal [`APP_REQUEST_SCHEMA`].
    pub schema: String,
    /// Canonical proof bytes, unpadded base64url.
    pub proof_b64: String,
    /// Canonical action bytes, unpadded base64url.
    pub action_b64: String,
}

/// An observation request frame.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppObservation {
    /// Must equal [`APP_OBSERVE_SCHEMA`].
    pub schema: String,
    /// The closed observation request.
    pub request: GatewayObserveRequest,
}

/// Every application frame is exactly one of the two closed schemas.
#[derive(Deserialize)]
#[serde(untagged)]
enum AppFrame {
    Submit(AppSubmission),
    Observe(AppObservation),
}

/// What serves the application socket: the gateway engine, or the test
/// harness that follows the same dispatch against a counting provider.
pub trait GatewayApplication {
    /// Verifies and attempts one exact action.
    fn submit(&self, proof: &[u8], action: &[u8]) -> impl Future<Output = GatewaySubmitResult>;

    /// Signs one read-only observation.
    fn observe(
        &self,
        request: &GatewayObserveRequest,
    ) -> impl Future<Output = GatewayObserveResult>;
}

impl GatewayApplication for GatewayEngine {
    async fn submit(&self, proof: &[u8], action: &[u8]) -> GatewaySubmitResult {
        GatewayEngine::submit(self, proof, action).await
    }

    async fn observe(&self, request: &GatewayObserveRequest) -> GatewayObserveResult {
        GatewayEngine::observe(self, request).await
    }
}

/// Reads one bounded frame.
///
/// # Errors
/// Returns a stable code for an unreadable or out-of-bounds frame.
pub async fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, &'static str> {
    let length = stream
        .read_u32()
        .await
        .map_err(|_| "gateway.ipc.read-failed")? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err("gateway.ipc.invalid-size");
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| "gateway.ipc.read-failed")?;
    Ok(bytes)
}

/// Writes one bounded frame.
///
/// # Errors
/// Returns a stable code for an out-of-bounds frame or a failed write.
pub async fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), &'static str> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err("gateway.ipc.invalid-size");
    }
    let length = u32::try_from(bytes.len()).map_err(|_| "gateway.ipc.invalid-size")?;
    stream
        .write_u32(length)
        .await
        .map_err(|_| "gateway.ipc.write-failed")?;
    stream
        .write_all(bytes)
        .await
        .map_err(|_| "gateway.ipc.write-failed")
}

fn invalid_frame() -> GatewaySubmitResult {
    GatewaySubmitResult::Indeterminate {
        code: "gateway.submit.invalid-frame".to_owned(),
    }
}

async fn submit_frame(submission: AppSubmission, application: &impl GatewayApplication) -> Vec<u8> {
    let result = if submission.schema == APP_REQUEST_SCHEMA {
        match (
            Base64UrlUnpadded::decode_vec(&submission.proof_b64),
            Base64UrlUnpadded::decode_vec(&submission.action_b64),
        ) {
            (Ok(proof), Ok(action)) => application.submit(&proof, &action).await,
            _ => GatewaySubmitResult::Indeterminate {
                code: "gateway.submit.invalid-encoding".to_owned(),
            },
        }
    } else {
        invalid_frame()
    };
    serde_json::to_vec(&result).unwrap_or_default()
}

async fn observe_frame(
    observation: AppObservation,
    application: &impl GatewayApplication,
) -> Vec<u8> {
    let result = if observation.schema == APP_OBSERVE_SCHEMA {
        application.observe(&observation.request).await
    } else {
        GatewayObserveResult::Refused {
            code: "gateway.observer.invalid-frame".to_owned(),
        }
    };
    serde_json::to_vec(&result).unwrap_or_default()
}

/// Serves one application connection: one frame in, one result out, within
/// [`APP_SESSION_LIMITS`].
pub async fn app_session(stream: UnixStream, application: &impl GatewayApplication) {
    app_session_within(stream, application, APP_SESSION_LIMITS).await;
}

/// Serves one application connection within `limits`. A frame that does not
/// arrive in time is answered as an invalid frame; a result that is not ready
/// in time is still awaited, but the connection is closed without it.
pub async fn app_session_within(
    mut stream: UnixStream,
    application: &impl GatewayApplication,
    limits: SessionLimits,
) {
    let clock = SessionClock::start(limits);
    let request = clock.read_frame(&mut stream).await;
    let response = async {
        match request {
            Ok(bytes) => match serde_json::from_slice::<AppFrame>(&bytes) {
                Ok(AppFrame::Submit(submission)) => submit_frame(submission, application).await,
                Ok(AppFrame::Observe(observation)) => observe_frame(observation, application).await,
                Err(_) => serde_json::to_vec(&invalid_frame()).unwrap_or_default(),
            },
            Err(_) => serde_json::to_vec(&invalid_frame()).unwrap_or_default(),
        }
    };
    if let Some((mut stream, bytes)) = clock.complete(stream, response).await
        && !bytes.is_empty()
    {
        let _ = clock.write_frame(&mut stream, &bytes).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::sync::Notify;

    /// Answers a submission only when the test releases it, with a result of
    /// `result_bytes` code bytes.
    struct HeldApplication {
        release: Notify,
        finished: AtomicBool,
        result_bytes: usize,
    }

    impl HeldApplication {
        fn new(result_bytes: usize) -> Arc<Self> {
            Arc::new(Self {
                release: Notify::new(),
                finished: AtomicBool::new(false),
                result_bytes,
            })
        }
    }

    impl GatewayApplication for HeldApplication {
        async fn submit(&self, _proof: &[u8], _action: &[u8]) -> GatewaySubmitResult {
            self.release.notified().await;
            self.finished.store(true, Ordering::SeqCst);
            GatewaySubmitResult::Indeterminate {
                code: "x".repeat(self.result_bytes),
            }
        }

        async fn observe(&self, _request: &GatewayObserveRequest) -> GatewayObserveResult {
            GatewayObserveResult::Refused {
                code: "test.unused".to_owned(),
            }
        }
    }

    fn submission() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schema": APP_REQUEST_SCHEMA,
            "proof_b64": "AA",
            "action_b64": "AA"
        }))
        .expect("submission frame")
    }

    const SHORT: SessionLimits = SessionLimits {
        frame_read: Duration::from_millis(200),
        result_wait: Duration::from_millis(200),
        response_write: Duration::from_millis(200),
        session: Duration::from_secs(30),
    };

    #[tokio::test]
    async fn an_idle_connection_is_answered_at_the_frame_deadline() {
        let application = HeldApplication::new(1);
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        let session = tokio::spawn({
            let application = Arc::clone(&application);
            async move { app_session_within(server, application.as_ref(), SHORT).await }
        });
        let response = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut client))
            .await
            .expect("answered by the frame deadline")
            .expect("response frame");
        assert!(started.elapsed() >= SHORT.frame_read);
        let result: serde_json::Value = serde_json::from_slice(&response).expect("result");
        assert_eq!(result["code"], "gateway.submit.invalid-frame");
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await.expect("closed"), 0);
        tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("session ended")
            .expect("session task");
    }

    #[tokio::test]
    async fn the_deadline_closes_the_connection_but_never_cancels_the_call() {
        let application = HeldApplication::new(1);
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let session = tokio::spawn({
            let application = Arc::clone(&application);
            async move { app_session_within(server, application.as_ref(), SHORT).await }
        });
        write_frame(&mut client, &submission())
            .await
            .expect("submit frame");
        let mut byte = [0_u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut byte))
            .await
            .expect("connection closed at the result deadline");
        assert!(matches!(read, Ok(0) | Err(_)), "no response is written");
        assert!(!application.finished.load(Ordering::SeqCst));
        assert!(!session.is_finished(), "the session still owns the call");
        application.release.notify_one();
        tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("session ended after the call")
            .expect("session task");
        assert!(application.finished.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_response_the_peer_never_reads_ends_at_the_write_deadline() {
        let application = HeldApplication::new(4 * 1024 * 1024);
        application.release.notify_one();
        let (server, mut client) = UnixStream::pair().expect("socket pair");
        let limits = SessionLimits {
            result_wait: Duration::from_secs(10),
            ..SHORT
        };
        let session = tokio::spawn({
            let application = Arc::clone(&application);
            async move { app_session_within(server, application.as_ref(), limits).await }
        });
        write_frame(&mut client, &submission())
            .await
            .expect("submit frame");
        tokio::time::timeout(Duration::from_secs(5), session)
            .await
            .expect("an unread response does not hold the session")
            .expect("session task");
        assert!(application.finished.load(Ordering::SeqCst));
        drop(client);
    }

    #[test]
    fn observation_frame_is_closed_and_read_only() {
        let read_back = serde_json::json!({
            "schema": APP_OBSERVE_SCHEMA,
            "request": {"kind": "read-back", "arguments": {"record_id": "recTEST0000000001"}}
        });
        let outcome = serde_json::json!({
            "schema": APP_OBSERVE_SCHEMA,
            "request": {"kind": "outcome", "operation_id": "step-1"}
        });
        for frame in [&read_back, &outcome] {
            assert!(matches!(
                serde_json::from_value::<AppFrame>(frame.clone()),
                Ok(AppFrame::Observe(_))
            ));
        }
        for (key, value) in [
            ("url", "https://attacker.example"),
            ("method", "PUT"),
            ("headers", "Authorization: stolen"),
            ("body", "arbitrary"),
            ("subject", "https://attacker.example/"),
            ("observed_at", "0"),
            ("schema", "auths.gateway-readback/1"),
        ] {
            let mut mutated = read_back.clone();
            mutated["request"][key] = serde_json::Value::String(value.to_owned());
            assert!(
                serde_json::from_value::<AppFrame>(mutated).is_err(),
                "{key}"
            );
            let mut outer = outcome.clone();
            outer[key] = serde_json::Value::String(value.to_owned());
            assert!(
                key == "schema" || serde_json::from_value::<AppFrame>(outer).is_err(),
                "{key}"
            );
        }
        let mut unknown = outcome;
        unknown["request"]["kind"] = serde_json::Value::String("write".to_owned());
        assert!(serde_json::from_value::<AppFrame>(unknown).is_err());
    }
}
