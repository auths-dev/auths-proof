//! Native HTTP API for protected PostgreSQL discovery and execution.

use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_postgresql::{
    BoundedUpdateService, ClaimStore, ExecuteBoundedUpdateRequest, FixedClock, MemoryClaimStore,
    MemoryReceiptSink, PersistentClaimStore, PortError, PostgresBoundedUpdateV1, PostgresReceipt,
    ReceiptSink, SdkProofVerifier, ServiceDependencies, WorkflowOutcome, canonical::canonical_json,
};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{
    fixture::{DemoVariant, demo_fixture_from_product, fixture_at, fixture_from_evidence},
    postgres::PostgresBackend,
};

const API_SCHEMA: &str = "auths-postgresql-demo-api/1";
const SESSION_TTL_SECONDS: u64 = 10 * 60;

#[derive(Clone)]
enum BackendSettings {
    Fixture,
    Live(Arc<PostgresBackend>),
}

/// Explicit deployment configuration.
#[derive(Clone)]
pub struct AppConfig {
    bind: SocketAddr,
    allowed_origin: HeaderValue,
    region: String,
    release: String,
    state_directory: Arc<Path>,
    backend: BackendSettings,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, StartupError> {
        let bind = env::var("AUTHS_POSTGRESQL_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| StartupError::Configuration)?;
        let allowed_origin = HeaderValue::from_str(
            &env::var("AUTHS_POSTGRESQL_ALLOWED_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
        )
        .map_err(|_| StartupError::Configuration)?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("FLY_IMAGE_REF").unwrap_or_else(|_| "development".into());
        let state_directory = PathBuf::from(
            env::var("AUTHS_POSTGRESQL_STATE_DIR").unwrap_or_else(|_| ".state/postgresql".into()),
        );
        let mode = env::var("AUTHS_POSTGRESQL_MODE").unwrap_or_else(|_| "fixture".into());
        let backend = match mode.as_str() {
            "fixture" => BackendSettings::Fixture,
            "live" => BackendSettings::Live(Arc::new(
                PostgresBackend::live(
                    required_env("AUTHS_POSTGRESQL_CONNECTION_STRING")?,
                    optional_ca_pem()?,
                    required_env("AUTHS_POSTGRESQL_SERVER_IDENTITY")?,
                    required_env("AUTHS_POSTGRESQL_AUDIENCE")?,
                    required_env("AUTHS_POSTGRESQL_DEMO_TENANT")?,
                )
                .map_err(|_| StartupError::Configuration)?,
            )),
            _ => return Err(StartupError::Configuration),
        };
        Ok(Self {
            bind,
            allowed_origin,
            region,
            release,
            state_directory: state_directory.into(),
            backend,
        })
    }

    #[cfg(test)]
    fn for_test(state_directory: PathBuf) -> Self {
        Self {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: "test".into(),
            release: "test".into(),
            state_directory: state_directory.into(),
            backend: BackendSettings::Fixture,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    claims: Arc<dyn ClaimStore>,
    durable_receipts: Arc<dyn ReceiptSink>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    variants: Vec<DemoVariant>,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    auths_request: auths_sdk::RequestContext,
    backend: Arc<PostgresBackend>,
    receipts: Arc<MemoryReceiptSink>,
    initial_rows: Value,
    last_result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the production API router.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    fs::create_dir_all(config.state_directory.as_ref()).map_err(|_| StartupError::State)?;
    let claims: Arc<dyn ClaimStore> = if matches!(config.backend, BackendSettings::Fixture) {
        Arc::new(MemoryClaimStore::default())
    } else {
        Arc::new(
            PersistentClaimStore::open(config.state_directory.join("claims.json"))
                .map_err(|_| StartupError::State)?,
        )
    };
    let durable_receipts = Arc::new(
        JsonlReceiptSink::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/build", get(build))
        .route("/api/v1/scenarios", get(scenarios))
        .route("/api/v1/credential-probe", get(credential_probe))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/receipts/{session_id}", get(receipt))
        .with_state(AppState {
            config,
            claims,
            durable_receipts,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        })
        .layer(cors))
}

/// Serves until shutdown.
pub async fn serve(config: AppConfig) -> Result<(), StartupError> {
    let bind = config.bind;
    let router = app(config)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| StartupError::Bind)?;
    axum::serve(listener, router)
        .await
        .map_err(|_| StartupError::Serve)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": state.config.region,
        "release": state.config.release,
    }))
}

async fn readiness(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    if let BackendSettings::Live(backend) = &state.config.backend {
        backend.readiness().await.map_err(ApiError::port)?;
    }
    Ok(Json(json!({
        "status": "ready",
        "schema": API_SCHEMA,
        "database": backend_label(&state.config.backend),
        "credential_boundary": "native-executor-only",
        "destructive_probe": false,
    })))
}

async fn build(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "profile": "auths.postgresql.bounded-update/1",
        "driver": "tokio-postgres/0.7.18+rustls",
    }))
}

async fn scenarios(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "database": backend_label(&state.config.backend),
        "variants": [
            {"id": "exact", "label": "Exact three-row transition"},
            {"id": "extra-row", "label": "An extra row appears"},
            {"id": "tenant-changed", "label": "Tenant changed"},
            {"id": "before-changed", "label": "A before value changed"},
            {"id": "forbidden-column", "label": "Forbidden column added"},
            {"id": "value-outside-enum", "label": "Value outside enum"},
            {"id": "schema-policy-changed", "label": "RLS policy changed"},
            {"id": "configuration-changed", "label": "Verifier ceiling changed"}
        ]
    }))
}

async fn credential_probe() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "credential_access": "denied",
        "database_credential_exposed": false,
        "credential_provider_called": false,
        "detail": "the browser and proposing agent have no database credential operation"
    }))
}

async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let session_id = random_id()?;
    let challenge = random_challenge()?;
    let (mut product, backend) = match &state.config.backend {
        BackendSettings::Fixture => {
            let product = fixture_at(now);
            let backend = Arc::new(PostgresBackend::fixture(product.evidence.clone()));
            (product, backend)
        }
        BackendSettings::Live(backend) => {
            let evidence = backend.discover(now).await.map_err(ApiError::port)?;
            let product =
                fixture_from_evidence(evidence, now).map_err(|_| ApiError::unavailable())?;
            (product, Arc::clone(backend))
        }
    };
    product.intent.nonce = format!("postgresql-session-{}", hex::encode(&challenge[..16]));
    product.action = PostgresBoundedUpdateV1::build(
        product.intent.clone(),
        &product.evidence,
        &product.configuration,
    )
    .map_err(|_| ApiError::internal())?;
    let demo = demo_fixture_from_product(product, now, challenge);
    let rows =
        serde_json::to_value(&demo.product.evidence.rows).map_err(|_| ApiError::internal())?;
    let response_variants = demo
        .variants
        .iter()
        .map(|variant| {
            json!({
                "id": variant.id,
                "label": variant.label,
                "description": variant.description,
                "predicted_decision": variant.decision,
                "typed_mutation": variant.action.intent,
                "required_configuration_digest": variant.required_configuration_digest,
                "executed_configuration_digest": variant.executed_configuration_digest,
            })
        })
        .collect::<Vec<_>>();
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "profile": "auths.postgresql.bounded-update/1",
        "principal": demo.auths.principal,
        "proof_bytes": demo.auths.proof.len(),
        "rows_before": rows,
        "variants": response_variants,
        "receipt_url": format!("/api/v1/receipts/{session_id}"),
        "receipt_page": format!("/receipts/{session_id}"),
    });
    let session = Session {
        expires_at: now + SESSION_TTL_SECONDS,
        variants: demo.variants,
        proof_verifier: Arc::new(SdkProofVerifier::new(demo.auths.verifier)),
        proof: demo.auths.proof,
        auths_request: demo.auths.request,
        backend,
        receipts: Arc::new(MemoryReceiptSink::default()),
        initial_rows: rows,
        last_result: None,
    };
    state
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .insert(session_id, session);
    Ok(Json(response))
}

async fn execute(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let (variant, verifier, proof, auths_request, backend, receipts, initial_rows) = {
        let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
        let session = sessions.get(&session_id).ok_or_else(ApiError::not_found)?;
        if session.expires_at < now {
            return Err(ApiError::expired());
        }
        let variant = session
            .variants
            .iter()
            .find(|variant| variant.id == request.variant)
            .cloned()
            .ok_or_else(ApiError::bad_request)?;
        (
            variant,
            Arc::clone(&session.proof_verifier),
            session.proof.clone(),
            session.auths_request.clone(),
            Arc::clone(&session.backend),
            Arc::clone(&session.receipts),
            session.initial_rows.clone(),
        )
    };
    let credential_calls_before = backend.credential_calls();
    let transaction_calls_before = backend.transaction_calls();
    let sink = TeeReceiptSink {
        session: Arc::clone(&receipts),
        durable: Arc::clone(&state.durable_receipts),
    };
    let service = BoundedUpdateService::new(ServiceDependencies {
        proof_verifier: verifier,
        credential_provider: Arc::clone(&backend),
        transaction_gateway: Arc::clone(&backend),
        claim_store: Arc::clone(&state.claims),
        receipt_sink: sink,
        clock: FixedClock(now),
        executed_configuration: variant.executed_configuration.clone(),
    });
    let outcome = service
        .execute(ExecuteBoundedUpdateRequest {
            action: variant.action,
            evidence: variant.evidence,
            required_configuration: variant.required_configuration,
            proof,
            auths_request,
        })
        .await;
    let rows_after = backend.demo_rows().await.unwrap_or_default();
    let result = match outcome {
        Ok(WorkflowOutcome::Rejected { receipt }) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": receipt.decision.class,
            "stable_code": receipt.decision.code,
            "stage": receipt.decision.stage,
            "claim_state": "not-created",
            "database_effect": "not-attempted",
            "credential_acquired": backend.credential_calls() > credential_calls_before,
            "transaction_started": backend.transaction_calls() > transaction_calls_before,
            "rows_before": initial_rows,
            "rows_after": rows_after,
            "decision_receipt": receipt,
            "receipt_url": format!("/api/v1/receipts/{session_id}"),
            "receipt_page": format!("/receipts/{session_id}"),
        }),
        Ok(WorkflowOutcome::Replay { record }) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": "replay",
            "stable_code": "already-claimed",
            "stage": "claim",
            "claim_state": record.stage,
            "database_effect": "not-reissued",
            "credential_acquired": false,
            "transaction_started": false,
            "rows_before": initial_rows,
            "rows_after": rows_after,
            "claim_receipt": record,
            "receipt_url": format!("/api/v1/receipts/{session_id}"),
            "receipt_page": format!("/receipts/{session_id}"),
        }),
        Ok(WorkflowOutcome::Conflict { record }) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": "denied",
            "stable_code": "already-claimed",
            "stage": "claim",
            "claim_state": record.stage,
            "database_effect": "not-attempted",
            "credential_acquired": false,
            "transaction_started": false,
            "rows_before": initial_rows,
            "rows_after": rows_after,
            "claim_receipt": record,
            "receipt_url": format!("/api/v1/receipts/{session_id}"),
            "receipt_page": format!("/receipts/{session_id}"),
        }),
        Ok(WorkflowOutcome::Executed {
            decision,
            transaction,
            observation,
            result: _,
        }) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": if transaction.reconciled { "reconciled" } else { "committed" },
            "stable_code": "authorized",
            "stage": "observation",
            "claim_state": "observed",
            "database_effect": "exact-three-row-update-committed",
            "credential_acquired": true,
            "transaction_started": true,
            "rows_before": initial_rows,
            "rows_after": rows_after,
            "decision_receipt": decision,
            "transaction_receipt": transaction,
            "observation_receipt": observation,
            "receipt_url": format!("/api/v1/receipts/{session_id}"),
            "receipt_page": format!("/receipts/{session_id}"),
        }),
        Err(error) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": "indeterminate",
            "stable_code": service_error_code(&error),
            "stage": "database-transaction",
            "claim_state": "failed-or-outcome-unknown",
            "database_effect": "reconcile-required",
            "credential_acquired": backend.credential_calls() > credential_calls_before,
            "transaction_started": backend.transaction_calls() > transaction_calls_before,
            "rows_before": initial_rows,
            "rows_after": rows_after,
            "receipt_url": format!("/api/v1/receipts/{session_id}"),
            "receipt_page": format!("/receipts/{session_id}"),
        }),
    };
    state
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .get_mut(&session_id)
        .ok_or_else(ApiError::not_found)?
        .last_result = Some(receipt_result(&result));
    Ok(Json(result))
}

fn receipt_result(result: &Value) -> Value {
    json!({
        "schema": result.get("schema"),
        "session_id": result.get("session_id"),
        "variant": result.get("variant"),
        "state": result.get("state"),
        "stable_code": result.get("stable_code"),
        "stage": result.get("stage"),
        "claim_state": result.get("claim_state"),
        "database_effect": result.get("database_effect"),
        "credential_acquired": result.get("credential_acquired"),
        "transaction_started": result.get("transaction_started"),
        "decision_receipt": result.get("decision_receipt"),
        "claim_receipt": result.get("claim_receipt"),
        "transaction_receipt": result.get("transaction_receipt"),
        "observation_receipt": result.get("observation_receipt"),
        "receipt_url": result.get("receipt_url"),
        "receipt_page": result.get("receipt_page"),
    })
}

async fn receipt(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ApiError::bad_request());
    }
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions.get(&session_id).ok_or_else(ApiError::not_found)?;
    Ok(Json(json!({
        "schema": "auths.postgresql.receipt-bundle/1",
        "session_id": session_id,
        "last_result": session.last_result,
        "receipts": session.receipts.receipts(),
        "privacy": {
            "primary_keys_in_receipts": false,
            "tenant_values_in_receipts": false,
            "column_values_in_receipts": false,
        },
    })))
}

fn service_error_code(error: &auths_postgresql::ServiceError) -> &'static str {
    match error {
        auths_postgresql::ServiceError::OutcomeUnknown => "execution-outcome-unknown",
        auths_postgresql::ServiceError::Port(PortError::CredentialUnavailable) => {
            "credential-unavailable"
        }
        auths_postgresql::ServiceError::Port(PortError::TransactionConflict) => {
            "transaction-conflict"
        }
        auths_postgresql::ServiceError::Port(PortError::CardinalityMismatch) => {
            "cardinality-mismatch"
        }
        auths_postgresql::ServiceError::Port(PortError::AfterStateMismatch) => {
            "after-state-mismatch"
        }
        auths_postgresql::ServiceError::Port(PortError::BeforeStateMismatch) => {
            "before-state-mismatch"
        }
        _ => "database-execution-failed",
    }
}

fn backend_label(settings: &BackendSettings) -> &'static str {
    match settings {
        BackendSettings::Fixture => "deterministic-postgresql-fixture",
        BackendSettings::Live(backend) => backend.label(),
    }
}

fn required_env(name: &'static str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(StartupError::Configuration)
}

fn optional_ca_pem() -> Result<Option<String>, StartupError> {
    if let Ok(value) = env::var("AUTHS_POSTGRESQL_CA_PEM") {
        if value.is_empty() || value.len() > 1024 * 1024 {
            return Err(StartupError::Configuration);
        }
        return Ok(Some(value));
    }
    let Ok(path) = env::var("AUTHS_POSTGRESQL_CA_FILE") else {
        return Ok(None);
    };
    let bytes = fs::read(path).map_err(|_| StartupError::Configuration)?;
    if bytes.is_empty() || bytes.len() > 1024 * 1024 {
        return Err(StartupError::Configuration);
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| StartupError::Configuration)
}

fn unix_time() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal())
}

fn random_id() -> Result<String, ApiError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(bytes))
}

fn random_challenge() -> Result<[u8; 32], ApiError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(bytes)
}

struct TeeReceiptSink {
    session: Arc<MemoryReceiptSink>,
    durable: Arc<dyn ReceiptSink>,
}

impl ReceiptSink for TeeReceiptSink {
    fn append(&self, receipt: &PostgresReceipt) -> Result<(), PortError> {
        self.session.append(receipt)?;
        self.durable.append(receipt)
    }
}

struct JsonlReceiptSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonlReceiptSink {
    fn new(path: PathBuf) -> Result<Self, PortError> {
        let parent = path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }
}

impl ReceiptSink for JsonlReceiptSink {
    fn append(&self, receipt: &PostgresReceipt) -> Result<(), PortError> {
        let _guard = self.lock.lock().map_err(|_| PortError::Persistence)?;
        let mut bytes = canonical_json(receipt).map_err(|_| PortError::Persistence)?;
        bytes.push(b'\n');
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_data())
            .map_err(|_| PortError::Persistence)
    }
}

/// Startup failure.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid configuration")]
    Configuration,
    #[error("durable state unavailable")]
    State,
    #[error("failed to bind")]
    Bind,
    #[error("service failed")]
    Serve,
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal-error",
        }
    }

    const fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "database-unavailable",
        }
    }

    const fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "receipt-or-session-not-found",
        }
    }

    const fn expired() -> Self {
        Self {
            status: StatusCode::GONE,
            code: "session-expired",
        }
    }

    const fn bad_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "malformed-request",
        }
    }

    const fn port(_: PortError) -> Self {
        Self::unavailable()
    }
}

impl From<PortError> for ApiError {
    fn from(error: PortError) -> Self {
        Self::port(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
                "state": "indeterminate",
                "code": self.code,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::{Request, StatusCode, header::CONTENT_TYPE},
    };
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn health_and_readiness_do_not_acquire_mutation_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let router = app(AppConfig::for_test(directory.path().into())).unwrap();
        for path in ["/healthz", "/readyz", "/api/v1/credential-probe"] {
            let response = router
                .clone()
                .oneshot(Request::get(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn receipt_endpoint_excludes_row_and_tenant_values() {
        let directory = tempfile::tempdir().unwrap();
        let router = app(AppConfig::for_test(directory.path().into())).unwrap();
        let created = router
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let session_id = created["session_id"].as_str().unwrap();
        let executed = router
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"configuration-changed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(executed.status(), StatusCode::OK);
        let response = router
            .oneshot(
                Request::get(format!("/api/v1/receipts/{session_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let receipt: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        assert!(receipt["last_result"].get("rows_before").is_none());
        assert!(receipt["last_result"].get("rows_after").is_none());
        let encoded = serde_json::to_string(&receipt).unwrap();
        assert!(!encoded.contains("tenant-demo"));
        assert!(!encoded.contains("00000000-0000-0000-0000-000000000001"));
    }
}
