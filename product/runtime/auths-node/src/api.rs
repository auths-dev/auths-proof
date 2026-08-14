use crate::{
    config::NodeConfig,
    profiles::{ReceiptSummary, RuntimeFailure, WorkflowProjection, failure_response},
};
use auths_operations::{
    EventSink as _, OperationalEventV2, OperationalOutcome, OperationalReasonCode, OperationalStage,
};
use auths_operations_otel::PrometheusProjection;
use auths_production_client::{
    ClientOutcomeKind, MAX_PRODUCTION_REQUEST_BYTES, PRODUCTION_CLIENT_CONTENT_TYPE, ProductVerb,
    ProductionRequest, ProductionResponse, QualifiedProfile, RecoveryReference, decode_request,
    encode_response,
};
use axum::{
    Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Serialize;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tower_http::{limit::RequestBodyLimitLayer, timeout::TimeoutLayer};

pub trait NodeRuntime: Send + Sync {
    fn handle(&self, request: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure>;
    fn status(&self, reference: &RecoveryReference) -> Result<WorkflowProjection, RuntimeFailure>;
    fn receipt_summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure>;
    fn disclose_receipt(
        &self,
        receipt_id: &str,
        authorization: &[u8],
    ) -> Result<Vec<u8>, RuntimeFailure>;
    fn ready(&self) -> bool;
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<dyn NodeRuntime>,
    release: Arc<str>,
    semantic_id: Arc<str>,
    accepting: Arc<AtomicBool>,
    metrics: Arc<PrometheusProjection>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Health<'a> {
    status: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    contract_version: u16,
    release: String,
    semantic_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApiError<'a> {
    code: &'a str,
    retry: &'a str,
}

#[must_use]
pub fn app(
    config: &NodeConfig,
    runtime: Arc<dyn NodeRuntime>,
    accepting: Arc<AtomicBool>,
) -> Router {
    let state = AppState {
        runtime,
        release: config.release().into(),
        semantic_id: config.semantic_id().into(),
        accepting,
        metrics: Arc::new(PrometheusProjection::default()),
    };
    Router::new()
        .route("/live", get(live))
        .route("/ready", get(ready))
        .route("/version", get(version))
        .route("/metrics", get(metrics))
        .route("/v1/authority/create", post(create))
        .route("/v1/authority/delegate", post(delegate))
        .route("/v1/authority/verify", post(verify))
        .route(
            "/v1/profiles/opentofu/saved-plan-apply/execute",
            post(execute_opentofu),
        )
        .route(
            "/v1/profiles/postgresql/bounded-update/execute",
            post(execute_postgresql),
        )
        .route(
            "/v1/profiles/github/issue-address/execute",
            post(execute_github),
        )
        .route("/v1/workflows/resume", post(resume))
        .route("/v1/workflows/{reference}", get(workflow_status))
        .route("/v1/receipts/{receipt_id}/summary", get(receipt_summary))
        .route("/v1/receipts/{receipt_id}/disclose", post(receipt_disclose))
        .layer(DefaultBodyLimit::disable())
        .layer(RequestBodyLimitLayer::new(MAX_PRODUCTION_REQUEST_BYTES))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            config.request_timeout(),
        ))
        .with_state(state)
}

async fn live() -> impl IntoResponse {
    (StatusCode::OK, axum::Json(Health { status: "live" }))
}

async fn ready(State(state): State<AppState>) -> Response {
    let ready = state.accepting.load(Ordering::Acquire) && state.runtime.ready();
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        axum::Json(Health {
            status: if ready { "ready" } else { "unready" },
        }),
    )
        .into_response()
}

async fn version(State(state): State<AppState>) -> impl IntoResponse {
    axum::Json(Version {
        contract_version: 1,
        release: state.release.to_string(),
        semantic_id: state.semantic_id.to_string(),
    })
}

async fn metrics(State(state): State<AppState>) -> Response {
    let mut response = state.metrics.render().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    response
}

async fn create(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    production_call(state, headers, body, ProductVerb::Create, None)
}

async fn delegate(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    production_call(state, headers, body, ProductVerb::Delegate, None)
}

async fn verify(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    production_call(state, headers, body, ProductVerb::Verify, None)
}

async fn execute_opentofu(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    production_call(
        state,
        headers,
        body,
        ProductVerb::Execute,
        Some(QualifiedProfile::OpenTofuSavedPlanApply),
    )
}

async fn execute_postgresql(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    production_call(
        state,
        headers,
        body,
        ProductVerb::Execute,
        Some(QualifiedProfile::PostgreSqlBoundedUpdate),
    )
}

async fn execute_github(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    production_call(
        state,
        headers,
        body,
        ProductVerb::Execute,
        Some(QualifiedProfile::GitHubIssueAddress),
    )
}

async fn resume(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    production_call(state, headers, body, ProductVerb::Resume, None)
}

fn production_call(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    expected_verb: ProductVerb,
    expected_profile: Option<QualifiedProfile>,
) -> Response {
    let started = Instant::now();
    if !state.accepting.load(Ordering::Acquire) {
        let response = failure_response(RuntimeFailure::Unavailable);
        record_operation(&state, expected_verb, &response, started);
        return encoded_response(response);
    }
    if !content_type_is_exact(&headers, PRODUCTION_CLIENT_CONTENT_TYPE) {
        let response = failure_response(RuntimeFailure::Malformed);
        record_operation(&state, expected_verb, &response, started);
        return encoded_response(response);
    }
    let request = match decode_request(&body) {
        Ok(request)
            if request.verb() == expected_verb
                && expected_profile.is_none_or(|profile| request.profile() == profile) =>
        {
            request
        }
        _ => {
            let response = failure_response(RuntimeFailure::Malformed);
            record_operation(&state, expected_verb, &response, started);
            return encoded_response(response);
        }
    };
    let response = state
        .runtime
        .handle(request)
        .unwrap_or_else(failure_response);
    record_operation(&state, expected_verb, &response, started);
    encoded_response(response)
}

fn record_operation(
    state: &AppState,
    verb: ProductVerb,
    response: &ProductionResponse,
    started: Instant,
) {
    let (outcome, reason) = match response.kind() {
        ClientOutcomeKind::Completed | ClientOutcomeKind::Verified => (
            OperationalOutcome::Succeeded,
            OperationalReasonCode::Authorized,
        ),
        ClientOutcomeKind::Denied | ClientOutcomeKind::Rejected => {
            (OperationalOutcome::Denied, OperationalReasonCode::Denied)
        }
        ClientOutcomeKind::Indeterminate => (
            OperationalOutcome::Indeterminate,
            OperationalReasonCode::EvidenceUnavailable,
        ),
        ClientOutcomeKind::Recoverable => (
            OperationalOutcome::OutcomeUnknown,
            OperationalReasonCode::RecoveryPending,
        ),
    };
    let stage = match verb {
        ProductVerb::Create | ProductVerb::Delegate => OperationalStage::Policy,
        ProductVerb::Verify => OperationalStage::Verification,
        ProductVerb::Execute => OperationalStage::ProviderResult,
        ProductVerb::Resume => OperationalStage::Recovery,
    };
    let elapsed = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    state.metrics.record(&OperationalEventV2::runtime(
        None, stage, outcome, reason, elapsed,
    ));
}

async fn workflow_status(State(state): State<AppState>, Path(reference): Path<String>) -> Response {
    let reference = match RecoveryReference::parse(&reference) {
        Ok(value) => value,
        Err(_) => return json_error(StatusCode::BAD_REQUEST, RuntimeFailure::Malformed),
    };
    match state.runtime.status(&reference) {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(error) => json_error(status_for(error), error),
    }
}

async fn receipt_summary(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> Response {
    if !valid_receipt_id(&receipt_id) {
        return json_error(StatusCode::BAD_REQUEST, RuntimeFailure::Malformed);
    }
    match state.runtime.receipt_summary(&receipt_id) {
        Ok(value) => (StatusCode::OK, axum::Json(value)).into_response(),
        Err(error) => json_error(status_for(error), error),
    }
}

async fn receipt_disclose(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !valid_receipt_id(&receipt_id)
        || body.is_empty()
        || !content_type_is_exact(&headers, PRODUCTION_CLIENT_CONTENT_TYPE)
    {
        return json_error(StatusCode::BAD_REQUEST, RuntimeFailure::Malformed);
    }
    match state.runtime.disclose_receipt(&receipt_id, &body) {
        Ok(value) => binary_response(value),
        Err(error) => json_error(status_for(error), error),
    }
}

fn encoded_response(response: ProductionResponse) -> Response {
    match encode_response(&response) {
        Ok(body) => binary_response(body),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn binary_response(body: Vec<u8>) -> Response {
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PRODUCTION_CLIENT_CONTENT_TYPE),
    );
    response
}

fn content_type_is_exact(headers: &HeaderMap, expected: &str) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(expected))
}

fn valid_receipt_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn status_for(error: RuntimeFailure) -> StatusCode {
    match error {
        RuntimeFailure::Denied | RuntimeFailure::DisclosureDenied => StatusCode::FORBIDDEN,
        RuntimeFailure::UnknownWorkflow | RuntimeFailure::UnknownReceipt => StatusCode::NOT_FOUND,
        RuntimeFailure::Malformed | RuntimeFailure::ProfileDisabled => StatusCode::BAD_REQUEST,
        RuntimeFailure::Indeterminate | RuntimeFailure::Unavailable => {
            StatusCode::SERVICE_UNAVAILABLE
        }
    }
}

fn json_error(status: StatusCode, error: RuntimeFailure) -> Response {
    (
        status,
        axum::Json(ApiError {
            code: error.code(),
            retry: match error.retry() {
                auths_production_client::RetryClass::Never => "never",
                auths_production_client::RetryClass::Backoff => "backoff",
                auths_production_client::RetryClass::Resume => "resume",
                auths_production_client::RetryClass::Reconcile => "reconcile",
            },
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_production_client::{
        ProductVerb, ProductionRequest, QualifiedProfile, decode_response, encode_request,
    };
    use std::sync::atomic::AtomicBool;
    use tower::ServiceExt as _;

    struct Runtime;

    impl NodeRuntime for Runtime {
        fn handle(&self, request: ProductionRequest) -> Result<ProductionResponse, RuntimeFailure> {
            ProductionResponse::new(
                auths_production_client::ClientOutcomeKind::Completed,
                None,
                auths_production_client::RetryClass::Never,
                None,
                Some(request.body().unwrap_or_default().to_vec()),
                Some(vec![1]),
            )
            .map_err(|_| RuntimeFailure::Malformed)
        }

        fn status(
            &self,
            reference: &RecoveryReference,
        ) -> Result<WorkflowProjection, RuntimeFailure> {
            Ok(WorkflowProjection {
                reference: reference.as_str().into(),
                profile: QualifiedProfile::GitHubIssueAddress.as_str().into(),
                state: "outcome-unknown".into(),
                effect: "unknown".into(),
                retry: "resume".into(),
                updated_at: 1,
                receipt_id: None,
            })
        }

        fn receipt_summary(&self, receipt_id: &str) -> Result<ReceiptSummary, RuntimeFailure> {
            Ok(ReceiptSummary {
                receipt_id: receipt_id.into(),
                profile: QualifiedProfile::GitHubIssueAddress.as_str().into(),
                outcome: "succeeded".into(),
                completed_at: 1,
                disclosure: "summary",
            })
        }

        fn disclose_receipt(
            &self,
            _receipt_id: &str,
            authorization: &[u8],
        ) -> Result<Vec<u8>, RuntimeFailure> {
            if authorization == b"authorized" {
                Ok(vec![1])
            } else {
                Err(RuntimeFailure::DisclosureDenied)
            }
        }

        fn ready(&self) -> bool {
            true
        }
    }

    fn config() -> NodeConfig {
        NodeConfig::parse(
            r#"contract_version = 1
mode = "local"
bind = "127.0.0.1:8080"
release = "test"
semantic_id = "auths.open-production/1"
request_timeout_ms = 10000
drain_timeout_seconds = 1
ingress_tls = false

[lifecycle]
url_env = "AUTHS_POSTGRES_URL"
ca_pem = "/tmp/ca.pem"
server_name = "postgres"
maximum_records = 4096

[custody]
kind = "software-fixture"
seed_env = "AUTHS_LOCAL_SEED"

[telemetry]
otlp_endpoint = "http://otel:4317"
service_name = "auths-node"

[profiles]
opentofu_saved_plan_apply = true
postgresql_bounded_update = true
github_issue_address = true
sandbox_providers = true
"#,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn route_and_envelope_must_agree() {
        let router = app(
            &config(),
            Arc::new(Runtime),
            Arc::new(AtomicBool::new(true)),
        );
        let request = ProductionRequest::new(
            ProductVerb::Execute,
            QualifiedProfile::GitHubIssueAddress,
            vec![1],
            Some(vec![2]),
            Some(vec![3]),
            None,
        )
        .unwrap();
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/profiles/opentofu/saved-plan-apply/execute")
                    .header(header::CONTENT_TYPE, PRODUCTION_CLIENT_CONTENT_TYPE)
                    .body(axum::body::Body::from(encode_request(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(
            decode_response(&bytes).unwrap().code(),
            Some("core.malformed-input")
        );
    }

    #[tokio::test]
    async fn readiness_drains_before_liveness() {
        let accepting = Arc::new(AtomicBool::new(false));
        let router = app(&config(), Arc::new(Runtime), accepting);
        let ready = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/ready")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let live = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/live")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(live.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_expose_only_the_frozen_operational_vocabulary() {
        let router = app(
            &config(),
            Arc::new(Runtime),
            Arc::new(AtomicBool::new(true)),
        );
        let request = ProductionRequest::new(
            ProductVerb::Create,
            QualifiedProfile::GitHubIssueAddress,
            b"sensitive-identity".to_vec(),
            None,
            Some(b"sensitive-action".to_vec()),
            None,
        )
        .unwrap();
        let called = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/v1/authority/create")
                    .header(header::CONTENT_TYPE, PRODUCTION_CLIENT_CONTENT_TYPE)
                    .body(axum::body::Body::from(encode_request(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(called.status(), StatusCode::OK);
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/metrics")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let projection = std::str::from_utf8(&bytes).unwrap();
        assert!(projection.contains("auths_operations_total"));
        assert!(projection.contains("stage=\"policy\""));
        assert!(!projection.contains("sensitive-identity"));
        assert!(!projection.contains("sensitive-action"));
    }
}
