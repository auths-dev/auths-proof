//! Local-agent protocol framing and effect-free SDK telemetry projection.
//!
//! The prelaunch remote production request protocol was deleted. Provider
//! effects are available only through the generated local-agent operation and
//! recovery routes in [`local_agent`].

mod local_agent;

pub use local_agent::{
    ClientRequestId, ExecuteOperationRequest, LOCAL_AGENT_CONTENT_TYPE, LocalAgentHttpRequest,
    LocalAgentHttpResponse, LocalAgentProtocolError, LocalOperationCompletion,
    LocalOperationOutcome, LocalPendingOperation, LocalReceiptEntry, MAX_LOCAL_REQUEST_BYTES,
    MAX_LOCAL_RESPONSE_BYTES, OperationId, PreparationEvidenceLease, PreparationEvidenceRequest,
    PrepareOperationRequest, ProfileAdvertisement, ProfileConnectionAdvertisement,
    ProfileQualificationAdvertisement, ProfileRoute, RecoverOperationRequest, SessionMode,
    SessionProfileKey, SessionRequest, SessionResponse, decode_execute_operation_request,
    decode_local_agent_http_request, decode_local_agent_http_response,
    decode_local_operation_outcome, decode_preparation_evidence_outcome,
    decode_preparation_evidence_request, decode_prepare_operation_request,
    decode_recover_operation_request, decode_session_request, decode_session_response,
    encode_execute_operation_request, encode_local_operation_outcome, encode_pending_operations,
    encode_preparation_evidence_lease, encode_preparation_evidence_outcome,
    encode_preparation_evidence_request, encode_prepare_operation_request,
    encode_qualification_client_result_frame, encode_receipt_entries,
    encode_recover_operation_request, encode_session_request, encode_session_response,
    local_agent_http_message_length, local_idempotency_commitment,
    local_preparation_input_commitment, local_principal_commitment, local_request_commitment,
    qualification_client_cancellation_result,
};

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt};

const ALLOWED_EVENT_ATTRIBUTES: &[&str] = &[
    "abi.version",
    "adapter.id",
    "adapter.kind",
    "chunk.size",
    "code",
    "contract_version",
    "item.count",
    "profile",
    "profile.id",
    "profile_version",
    "profile.version",
    "runtime.family",
    "stage",
    "work.units",
];

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SdkEventV2 {
    name: String,
    timestamp: u64,
    correlation_id: String,
    operation: String,
    stage: SdkEventStage,
    outcome: SdkEventOutcome,
    duration_ms: Option<f64>,
    #[serde(default)]
    attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SdkEventStage {
    Acquisition,
    Construction,
    Approval,
    Signing,
    Verification,
    Reservation,
    Execution,
    Receipt,
    Open,
    Authority,
    Cleanup,
    Telemetry,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum SdkEventOutcome {
    Started,
    Succeeded,
    Failed,
    Denied,
    Indeterminate,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SdkEventProjection<'a> {
    schema_version: &'static str,
    #[serde(flatten)]
    event: &'a SdkEventV2,
}

/// Projects a bounded telemetry event into the stable SDK event schema.
///
/// # Errors
///
/// Returns an error when the input is oversized, malformed, or contains an
/// unsupported field or value.
pub fn project_sdk_event_v2(input: &str) -> Result<String, TelemetryProjectionError> {
    if input.len() > 16_384 {
        return Err(TelemetryProjectionError::LimitExceeded);
    }
    if input.trim() != input {
        return Err(TelemetryProjectionError::Malformed);
    }
    let event: SdkEventV2 =
        serde_json::from_str(input).map_err(|_| TelemetryProjectionError::Malformed)?;
    if !valid_event_text(&event.name, 96)
        || !valid_event_text(&event.operation, 96)
        || !valid_event_text(&event.correlation_id, 128)
        || event
            .duration_ms
            .is_some_and(|value| !value.is_finite() || value < 0.0)
        || event.attributes.len() > 32
    {
        return Err(TelemetryProjectionError::InvalidBody);
    }
    for (key, value) in &event.attributes {
        if !ALLOWED_EVENT_ATTRIBUTES.contains(&key.as_str())
            || !valid_event_text(key, 64)
            || !valid_event_attribute(value)
        {
            return Err(TelemetryProjectionError::InvalidBody);
        }
    }
    serde_json::to_string(&SdkEventProjection {
        schema_version: "auths.telemetry/2",
        event: &event,
    })
    .map_err(|_| TelemetryProjectionError::Malformed)
}

fn valid_event_text(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_event_attribute(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(value) => valid_event_text(value, 256),
        serde_json::Value::Number(value) => value.as_i64().is_some() || value.as_u64().is_some(),
        serde_json::Value::Bool(_) => true,
        _ => false,
    }
}

/// Failure while projecting an effect-free telemetry event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TelemetryProjectionError {
    LimitExceeded,
    Malformed,
    InvalidBody,
}

impl fmt::Display for TelemetryProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LimitExceeded => "telemetry event exceeds its bound",
            Self::Malformed => "telemetry event is malformed",
            Self::InvalidBody => "telemetry event contains an unsupported value",
        })
    }
}

impl std::error::Error for TelemetryProjectionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_projection_is_bounded_and_closed() {
        let value = r#"{"name":"sdk.call","timestamp":1,"correlationId":"cor_1","operation":"verify","stage":"telemetry","outcome":"succeeded","durationMs":1.5,"attributes":{"code":"ok"}}"#;
        let projected = project_sdk_event_v2(value).unwrap();
        assert!(projected.contains(r#""schemaVersion":"auths.telemetry/2""#));
        assert_eq!(
            project_sdk_event_v2(&format!("{value} ")),
            Err(TelemetryProjectionError::Malformed)
        );
        assert_eq!(
            project_sdk_event_v2(&"x".repeat(16_385)),
            Err(TelemetryProjectionError::LimitExceeded)
        );
    }
}
