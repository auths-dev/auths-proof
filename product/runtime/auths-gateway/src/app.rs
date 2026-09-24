//! The application-socket protocol: one length-prefixed JSON frame in, one
//! out. A frame is exactly one of two closed schemas, a proof/action
//! submission or an observation request; anything else is refused without
//! reaching the application.

use crate::{GatewayEngine, GatewayObserveRequest, GatewayObserveResult, GatewaySubmitResult};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;

/// Schema of a proof/action submission frame.
pub const APP_REQUEST_SCHEMA: &str = "auths.gateway-submit/1";
/// Schema of an observation request frame.
pub const APP_OBSERVE_SCHEMA: &str = "auths.gateway-observe/1";
/// Largest frame either side accepts.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

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

/// Serves one application connection: one frame in, one result out.
pub async fn app_session(mut stream: UnixStream, application: &impl GatewayApplication) {
    let bytes = match tokio::time::timeout(Duration::from_secs(5), read_frame(&mut stream)).await {
        Ok(Ok(bytes)) => match serde_json::from_slice::<AppFrame>(&bytes) {
            Ok(AppFrame::Submit(submission)) => submit_frame(submission, application).await,
            Ok(AppFrame::Observe(observation)) => observe_frame(observation, application).await,
            Err(_) => serde_json::to_vec(&invalid_frame()).unwrap_or_default(),
        },
        _ => serde_json::to_vec(&invalid_frame()).unwrap_or_default(),
    };
    if !bytes.is_empty() {
        let _ = write_frame(&mut stream, &bytes).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
