//! The application-socket protocol: one length-prefixed JSON frame in, one
//! out. Frames carry a proof/action submission, independently approved recovery,
//! or retained local history; anything else is refused without
//! reaching the application.

use crate::effect::{ExactEffectApproval, MAX_EFFECT_APPROVAL_BYTES};
use crate::{GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::pin;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::{Instant, sleep_until, timeout_at};
use zeroize::{Zeroize as _, Zeroizing};

/// Schema of a proof/action submission frame.
pub const APP_REQUEST_SCHEMA: &str = "auths.gateway-submit/2";
/// Schema of an observation request frame.
pub const APP_OBSERVE_SCHEMA: &str = "auths.gateway-observe/3";
/// Independently approved recovery acquisition and evidence refinement.
pub const APP_RECOVERY_SCHEMA: &str = "auths.gateway-recover/1";
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
    /// Native canonical exact-effect approval, unpadded base64url.
    pub approval_b64: String,
}

/// Bounded decoded transport input. This is data only, not verified authority.
pub struct DecodedSubmission {
    /// Canonical proof bytes for native verification.
    pub proof: Zeroizing<Vec<u8>>,
    /// Canonical action bytes for native verification.
    pub action: Zeroizing<Vec<u8>>,
    /// Parsed exact-effect approval; native entry still validates it.
    pub approval: ExactEffectApproval,
}

impl AppSubmission {
    /// Decodes one bounded proof/action/approval frame without authorizing it.
    ///
    /// # Errors
    /// Refuses wrong schema, oversized fields and invalid native encoding.
    pub fn decode(&self) -> Result<DecodedSubmission, &'static str> {
        let invalid = "gateway.submit.invalid-encoding";
        if self.schema != APP_REQUEST_SCHEMA
            || self.approval_b64.len() > (MAX_EFFECT_APPROVAL_BYTES * 4).div_ceil(3)
        {
            return Err("gateway.submit.invalid-frame");
        }
        if self.proof_b64.len() > (4 * 1024 * 1024 * 4_usize).div_ceil(3)
            || self.action_b64.len() > (64 * 1024 * 4_usize).div_ceil(3)
        {
            return Err(invalid);
        }
        let proof =
            Zeroizing::new(Base64UrlUnpadded::decode_vec(&self.proof_b64).map_err(|_| invalid)?);
        let action =
            Zeroizing::new(Base64UrlUnpadded::decode_vec(&self.action_b64).map_err(|_| invalid)?);
        let approval =
            Zeroizing::new(Base64UrlUnpadded::decode_vec(&self.approval_b64).map_err(|_| invalid)?);
        let approval = ExactEffectApproval::from_private_bytes(&approval).map_err(|_| invalid)?;
        Ok(DecodedSubmission {
            proof,
            action,
            approval,
        })
    }
}

impl Drop for AppSubmission {
    fn drop(&mut self) {
        self.proof_b64.zeroize();
        self.action_b64.zeroize();
        self.approval_b64.zeroize();
    }
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

/// One separately authorized provider recovery read. The nested submission
/// uses the same bounded canonical decoder as mutation and operator recovery.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AppRecovery {
    /// Must equal `APP_RECOVERY_SCHEMA`.
    pub schema: String,
    /// Original retained mutation, never a provider path.
    pub source_operation: String,
    /// Native read authority and exact approval.
    pub submission: AppSubmission,
}

impl AppRecovery {
    /// Decodes transport data only; native compilation still establishes authority.
    ///
    /// # Errors
    /// Refuses obsolete schema, invalid operation and invalid native envelope.
    pub fn decode(&self) -> Result<DecodedSubmission, &'static str> {
        if self.schema != APP_RECOVERY_SCHEMA
            || crate::LogicalOperationId::parse(&self.source_operation).is_err()
        {
            return Err("gateway.submit.invalid-frame");
        }
        self.submission.decode()
    }
}

/// Redacted native facts or a native refusal. No response body or signed
/// provider value is released through this channel.
#[derive(Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum AppRecoveryResult {
    /// Distinct retained mutation/acquisition facts, not a claim of success.
    RecoveryReport {
        /// Native redacted source/acquisition projection.
        report: crate::GatewayRecoveryReport,
    },
    /// Native refusal/indeterminate outcome preserves its stable code.
    Refused {
        /// Original native stage and refusal code.
        result: GatewaySubmitResult,
    },
}

/// Every application frame selects one closed native operation.
#[derive(Deserialize)]
#[serde(untagged)]
enum AppFrame {
    Submit(AppSubmission),
    Observe(AppObservation),
    Recover(AppRecovery),
}

/// Which closed frame `bytes` parse as, schema included: `submit`,
/// `observe`, `recover`, or `None`.
#[cfg(feature = "fuzzing")]
pub(crate) fn frame_kind(bytes: &[u8]) -> Option<&'static str> {
    match serde_json::from_slice::<AppFrame>(bytes).ok()? {
        AppFrame::Submit(submission) => {
            (submission.schema == APP_REQUEST_SCHEMA).then_some("submit")
        }
        AppFrame::Observe(observation) => {
            (observation.schema == APP_OBSERVE_SCHEMA).then_some("observe")
        }
        AppFrame::Recover(recovery) => recovery.decode().ok().map(|_| "recover"),
    }
}

/// What serves the application socket: the gateway engine, or the test
/// harness that follows the same dispatch against a counting provider.
pub trait GatewayApplication {
    /// Verifies and attempts one exact action.
    fn submit(
        &self,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> impl Future<Output = GatewaySubmitResult>;

    /// Acquires separately approved recovery evidence through the native engine.
    fn recover(
        &self,
        source_operation: &str,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> impl Future<Output = AppRecoveryResult>;

    /// Signs or returns retained local history, without provider I/O.
    fn observe(
        &self,
        request: &GatewayObserveRequest,
    ) -> impl Future<Output = GatewayObserveResult>;
}

impl GatewayApplication for GatewayEngine {
    async fn submit(
        &self,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> GatewaySubmitResult {
        GatewayEngine::submit(self, proof, action, approval).await
    }

    async fn recover(
        &self,
        source_operation: &str,
        proof: &[u8],
        action: &[u8],
        approval: ExactEffectApproval,
    ) -> AppRecoveryResult {
        match GatewayEngine::recover(self, source_operation, proof, action, approval).await {
            Ok(snapshot) => AppRecoveryResult::RecoveryReport {
                report: snapshot.report(),
            },
            Err(result) => AppRecoveryResult::Refused { result },
        }
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
    let result = match submission.decode() {
        Ok(decoded) => {
            application
                .submit(&decoded.proof, &decoded.action, decoded.approval)
                .await
        }
        Err(code) => GatewaySubmitResult::Indeterminate {
            code: code.to_owned(),
        },
    };
    serde_json::to_vec(&result).unwrap_or_default()
}

async fn recovery_frame(recovery: AppRecovery, application: &impl GatewayApplication) -> Vec<u8> {
    let result = match recovery.decode() {
        Ok(decoded) => {
            application
                .recover(
                    &recovery.source_operation,
                    &decoded.proof,
                    &decoded.action,
                    decoded.approval,
                )
                .await
        }
        Err(code) => AppRecoveryResult::Refused {
            result: GatewaySubmitResult::Indeterminate {
                code: code.to_owned(),
            },
        },
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
                Ok(AppFrame::Recover(recovery)) => recovery_frame(recovery, application).await,
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
        async fn submit(
            &self,
            _proof: &[u8],
            _action: &[u8],
            _approval: ExactEffectApproval,
        ) -> GatewaySubmitResult {
            self.release.notified().await;
            self.finished.store(true, Ordering::SeqCst);
            GatewaySubmitResult::Indeterminate {
                code: "x".repeat(self.result_bytes),
            }
        }

        async fn recover(
            &self,
            _source: &str,
            _proof: &[u8],
            _action: &[u8],
            _approval: ExactEffectApproval,
        ) -> AppRecoveryResult {
            AppRecoveryResult::Refused {
                result: GatewaySubmitResult::NotEntered {
                    code: "test.unused".to_owned(),
                },
            }
        }

        async fn observe(&self, _request: &GatewayObserveRequest) -> GatewayObserveResult {
            GatewayObserveResult::Refused {
                code: "test.unused".to_owned(),
            }
        }
    }

    fn submission() -> Vec<u8> {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../bindings/fixtures/gateway/effect-binding.json"
        ))
        .expect("native fixture");
        let approval = fixture["approval_canonical"].as_str().expect("approval");
        serde_json::to_vec(&serde_json::json!({
            "schema": APP_REQUEST_SCHEMA,
            "proof_b64": "AA",
            "action_b64": "AA",
            "approval_b64": Base64UrlUnpadded::encode_string(approval.as_bytes())
        }))
        .expect("submission frame")
    }

    #[tokio::test]
    async fn obsolete_missing_and_oversized_approval_frames_do_not_dispatch() {
        let valid: serde_json::Value = serde_json::from_slice(&submission()).expect("frame");
        let mut missing = valid.clone();
        missing
            .as_object_mut()
            .expect("object")
            .remove("approval_b64");
        assert!(serde_json::from_value::<AppFrame>(missing).is_err());
        for (field, value) in [
            ("schema", "auths.gateway-submit/1".to_owned()),
            ("approval_b64", "x".repeat(MAX_EFFECT_APPROVAL_BYTES * 2)),
            ("approval_b64", "not+base64url".to_owned()),
        ] {
            let mut changed = valid.clone();
            changed[field] = serde_json::Value::String(value);
            let frame: AppSubmission = serde_json::from_value(changed).expect("typed frame");
            let application = HeldApplication::new(1);
            let output = tokio::time::timeout(
                Duration::from_millis(100),
                submit_frame(frame, application.as_ref()),
            )
            .await
            .expect("refusal without dispatch");
            let result: GatewaySubmitResult = serde_json::from_slice(&output).expect("result");
            assert!(matches!(result, GatewaySubmitResult::Indeterminate { .. }));
            assert!(!application.finished.load(Ordering::SeqCst));
        }
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
        assert!(serde_json::from_value::<AppFrame>(read_back.clone()).is_err());
        for frame in [&outcome] {
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

    /// Real socket framing/dispatch evidence. The application is a counting
    /// refusal oracle; this does not claim installed proof or provider entry.
    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one bounded framing corpus keeps mutations and dispatch evidence together"
    )]
    async fn native_application_recovery_frame_fixture_is_current() {
        use std::sync::atomic::AtomicUsize;
        struct Counted {
            calls: AtomicUsize,
        }
        impl GatewayApplication for Counted {
            async fn submit(
                &self,
                _: &[u8],
                _: &[u8],
                _: ExactEffectApproval,
            ) -> GatewaySubmitResult {
                panic!("wrong route")
            }
            async fn observe(&self, _: &GatewayObserveRequest) -> GatewayObserveResult {
                panic!("provider read used observation route")
            }
            async fn recover(
                &self,
                source: &str,
                proof: &[u8],
                action: &[u8],
                _: ExactEffectApproval,
            ) -> AppRecoveryResult {
                assert_eq!(source, "source-1");
                assert_eq!(proof, &[0]);
                assert_eq!(action, &[0]);
                self.calls.fetch_add(1, Ordering::SeqCst);
                AppRecoveryResult::Refused {
                    result: GatewaySubmitResult::NotEntered {
                        code: "gateway.acquisition.binding".to_owned(),
                    },
                }
            }
        }
        let native: serde_json::Value = serde_json::from_slice(&submission()).expect("submission");
        let valid = serde_json::json!({"schema": APP_RECOVERY_SCHEMA, "source_operation": "source-1", "submission": native});
        let corpus_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fuzz/corpus/target_gateway_app_frame");
        for (name, frame) in [
            ("recover", valid.clone()),
            ("submit", valid["submission"].clone()),
            (
                "obsolete-read-back",
                serde_json::json!({"schema": APP_OBSERVE_SCHEMA,
                "request": {"kind": "read-back", "arguments": {"record_id": "recTEST0000000001"}}}),
            ),
        ] {
            let bytes = serde_json::to_vec(&frame).expect("seed");
            let path = corpus_root.join(name);
            if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
                std::fs::write(&path, &bytes).expect("seed");
            }
            assert_eq!(std::fs::read(path).expect("seed"), bytes);
        }
        let mut cases = vec![("bounded-envelope", valid.clone(), true)];
        for (name, pointer, replacement) in [
            (
                "obsolete-recovery-schema",
                "/schema",
                serde_json::json!("auths.gateway-recover/0"),
            ),
            (
                "obsolete-submit-schema",
                "/submission/schema",
                serde_json::json!("auths.gateway-submit/1"),
            ),
            (
                "invalid-operation",
                "/source_operation",
                serde_json::json!("../other"),
            ),
            (
                "null-approval",
                "/submission/approval_b64",
                serde_json::Value::Null,
            ),
            (
                "invalid-approval",
                "/submission/approval_b64",
                serde_json::json!("AA"),
            ),
            (
                "oversized-approval",
                "/submission/approval_b64",
                serde_json::json!("A".repeat(MAX_EFFECT_APPROVAL_BYTES * 2)),
            ),
        ] {
            let mut frame = valid.clone();
            *frame.pointer_mut(pointer).expect("field") = replacement;
            cases.push((name, frame, false));
        }
        let mut missing = valid.clone();
        missing["submission"]
            .as_object_mut()
            .expect("submission")
            .remove("approval_b64");
        cases.push(("missing-approval", missing, false));
        let mut substituted = valid.clone();
        substituted["url"] = serde_json::json!("https://attacker.example");
        cases.push(("transport-substitution", substituted, false));
        for schema in ["auths.gateway-observe/2", APP_OBSERVE_SCHEMA] {
            cases.push((schema, serde_json::json!({"schema": schema, "request": {"kind": "read-back", "arguments": {"record_id": "recTEST0000000001"}}}), false));
        }
        let mut evidence = Vec::new();
        for (name, frame, dispatched) in cases {
            let application = Arc::new(Counted {
                calls: AtomicUsize::new(0),
            });
            let (mut client, server) = UnixStream::pair().expect("socket pair");
            let held = Arc::clone(&application);
            let task = tokio::spawn(async move { app_session(server, &*held).await });
            write_frame(&mut client, &serde_json::to_vec(&frame).expect("frame"))
                .await
                .expect("write");
            let response: serde_json::Value =
                serde_json::from_slice(&read_frame(&mut client).await.expect("response"))
                    .expect("JSON");
            task.await.expect("server");
            let calls = application.calls.load(Ordering::SeqCst);
            assert_eq!(calls, usize::from(dispatched));
            evidence.push(serde_json::json!({"case": name, "recovery_dispatches": calls, "response": response}));
        }
        let fixture = serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "auths.application-recovery-frame-fixture/1",
            "scope": "real Unix socket and bounded decoder with counting refusal oracle; no installed native authority or provider entry claim",
            "request": valid, "cases": evidence,
        })).expect("fixture");
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../bindings/fixtures/gateway/application-recovery-frame.json");
        if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
            std::fs::write(&path, &fixture).expect("write fixture");
        }
        assert_eq!(std::fs::read(path).expect("fixture"), fixture);
    }
}
