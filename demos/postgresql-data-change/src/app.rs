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
    BoundedUpdateService, ExecuteBoundedUpdateRequest, FixedClock, MemoryReceiptSink, PortError,
    PostgresBoundedUpdateV1, PostgresEvidenceV1, PostgresLifecycleStore, PostgresReceipt,
    PostgresVerifierConfigurationV1, ReceiptSink, SdkProofVerifier, ServiceDependencies,
    WorkflowOutcome, canonical::canonical_json, reservation_scope_digest, test_support::Fixture,
};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{
    fixture::{DemoVariant, demo_fixture_from_product, fixture_at, fixture_from_evidence},
    postgres::{PostgresBackend, PostgresFault},
};

const API_SCHEMA: &str = "auths-postgresql-demo-api/1";
const SESSION_TTL_SECONDS: u64 = 10 * 60;

#[derive(Clone)]
enum BackendSettings {
    Fixture,
    Live(Arc<PostgresBackend>),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReceiptFault {
    None,
    BeforeCredential,
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
    receipt_fault: ReceiptFault,
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
        let receipt_fault = match env::var("AUTHS_POSTGRESQL_RECEIPT_FAULT")
            .unwrap_or_else(|_| "none".into())
            .as_str()
        {
            "none" => ReceiptFault::None,
            "before-credential" => ReceiptFault::BeforeCredential,
            _ => return Err(StartupError::Configuration),
        };
        let mode = env::var("AUTHS_POSTGRESQL_MODE").unwrap_or_else(|_| "fixture".into());
        let backend = match mode.as_str() {
            "fixture" => BackendSettings::Fixture,
            "live" => {
                let backend = PostgresBackend::live(
                    required_env("AUTHS_POSTGRESQL_CONNECTION_STRING")?,
                    optional_ca_pem()?,
                    required_env("AUTHS_POSTGRESQL_SERVER_IDENTITY")?,
                    required_env("AUTHS_POSTGRESQL_AUDIENCE")?,
                    required_env("AUTHS_POSTGRESQL_DEMO_TENANT")?,
                )
                .map_err(|_| StartupError::Configuration)?;
                let fault = match env::var("AUTHS_POSTGRESQL_FAULT")
                    .unwrap_or_else(|_| "none".into())
                    .as_str()
                {
                    "none" => PostgresFault::None,
                    "before-transaction" => PostgresFault::BeforeTransaction,
                    "after-update-rollback" => PostgresFault::AfterUpdateRollback,
                    "before-commit-unknown" => PostgresFault::BeforeCommitUnknown,
                    "after-commit-unknown" => PostgresFault::AfterCommitUnknown,
                    "after-commit-unreconciled" => PostgresFault::AfterCommitUnreconciled,
                    "statement-timeout" => PostgresFault::StatementTimeout,
                    _ => return Err(StartupError::Configuration),
                };
                backend.set_fault(fault);
                BackendSettings::Live(Arc::new(backend))
            }
            _ => return Err(StartupError::Configuration),
        };
        Ok(Self {
            bind,
            allowed_origin,
            region,
            release,
            state_directory: state_directory.into(),
            backend,
            receipt_fault,
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
            receipt_fault: ReceiptFault::None,
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    lifecycles: Arc<PostgresLifecycleRegistry>,
    durable_receipts: Arc<dyn ReceiptSink>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct DemoPostgresLifecycleStore {
    inner: auths_stores::PersistentLifecycleStore,
}

impl auths_lifecycle::LifecycleStore for DemoPostgresLifecycleStore {
    fn transact(
        &self,
        transaction: &auths_lifecycle::StoreTransactionV1,
    ) -> Result<auths_lifecycle::StoredTransitionV1, auths_lifecycle::StoreError> {
        self.inner.transact(transaction)
    }
}

impl PostgresLifecycleStore for DemoPostgresLifecycleStore {
    fn load_postgres_lifecycle(
        &self,
        workflow: &auths_lifecycle::WorkflowId,
    ) -> Result<Option<auths_lifecycle::LifecycleRecordV1>, auths_lifecycle::StoreError> {
        self.inner.load(workflow)
    }
}

struct PostgresLifecycleRegistry {
    directory: PathBuf,
    stores: Mutex<HashMap<String, Arc<DemoPostgresLifecycleStore>>>,
}

impl PostgresLifecycleRegistry {
    fn new(directory: PathBuf) -> Result<Self, StartupError> {
        fs::create_dir_all(&directory).map_err(|_| StartupError::State)?;
        Ok(Self {
            directory,
            stores: Mutex::new(HashMap::new()),
        })
    }

    fn for_action(
        &self,
        action: &PostgresBoundedUpdateV1,
    ) -> Result<Arc<DemoPostgresLifecycleStore>, PortError> {
        let scope = reservation_scope_digest(action).map_err(|_| PortError::Persistence)?;
        let scope_hex = hex::encode(scope.as_bytes());
        let mut stores = self.stores.lock().map_err(|_| PortError::Persistence)?;
        if let Some(store) = stores.get(&scope_hex) {
            return Ok(Arc::clone(store));
        }
        let store = Arc::new(DemoPostgresLifecycleStore {
            inner: auths_stores::PersistentLifecycleStore::open(
                self.directory.join(format!("{scope_hex}.lifecycle")),
                vec![auths_stores::LifecycleCapacityRuleV1::Exclusive {
                    scope_digest: scope,
                    window_digest: None,
                    retain_after_commit: false,
                }],
                4096,
            )
            .map_err(|_| PortError::Persistence)?,
        });
        stores.insert(scope_hex, Arc::clone(&store));
        Ok(store)
    }
}

struct Session {
    created_at: u64,
    expires_at: u64,
    challenge: [u8; 32],
    product: Fixture,
    variants: Vec<DemoVariant>,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    auths_request: auths_sdk::RequestContext,
    backend: Arc<PostgresBackend>,
    receipts: Arc<MemoryReceiptSink>,
    initial_rows: Value,
    last_result: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSession {
    schema: String,
    session_id: String,
    created_at: u64,
    expires_at: u64,
    challenge: [u8; 32],
    action: PostgresBoundedUpdateV1,
    intent: auths_postgresql::PostgresBoundedUpdateIntentV1,
    evidence: PostgresEvidenceV1,
    configuration: PostgresVerifierConfigurationV1,
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
    if config.state_directory.join("claims.json").exists() {
        return Err(StartupError::State);
    }
    let lifecycles = Arc::new(PostgresLifecycleRegistry::new(
        config.state_directory.join("lifecycle"),
    )?);
    let durable_receipts = Arc::new(
        JsonlReceiptSink::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let sessions = restore_sessions(&config)?;
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
            lifecycles,
            durable_receipts,
            sessions: Arc::new(Mutex::new(sessions)),
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
            {"id": "changed-parameter", "label": "Assignment value changed"},
            {"id": "unauthorized-table", "label": "Table changed"},
            {"id": "value-outside-enum", "label": "Value outside enum"},
            {"id": "policy-changed", "label": "RLS policy changed"},
            {"id": "schema-changed", "label": "Schema changed"},
            {"id": "trigger-changed", "label": "Trigger inventory changed"},
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
    let product = Fixture {
        action: demo.product.action.clone(),
        intent: demo.product.intent.clone(),
        evidence: demo.product.evidence.clone(),
        configuration: demo.product.configuration.clone(),
    };
    let session = Session {
        created_at: now,
        expires_at: now + SESSION_TTL_SECONDS,
        challenge,
        product,
        variants: demo.variants,
        proof_verifier: Arc::new(SdkProofVerifier::new(demo.auths.verifier)),
        proof: demo.auths.proof,
        auths_request: demo.auths.request,
        backend,
        receipts: Arc::new(MemoryReceiptSink::default()),
        initial_rows: rows,
        last_result: None,
    };
    persist_session(&state.config, &session_id, &session)?;
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
        fault: state.config.receipt_fault,
    };
    let lifecycle_store = state
        .lifecycles
        .for_action(&variant.action)
        .map_err(ApiError::port)?;
    let service = BoundedUpdateService::new(ServiceDependencies {
        proof_verifier: verifier,
        credential_provider: Arc::clone(&backend),
        transaction_gateway: Arc::clone(&backend),
        lifecycle_store,
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
        Ok(WorkflowOutcome::OutcomeUnknown { record }) => json!({
            "schema": API_SCHEMA,
            "session_id": session_id,
            "variant": request.variant,
            "state": "indeterminate",
            "stable_code": "execution-outcome-unknown",
            "stage": "reconciliation",
            "claim_state": record.stage,
            "database_effect": "reconcile-required",
            "credential_acquired": backend.credential_calls() > credential_calls_before,
            "transaction_started": backend.transaction_calls() > transaction_calls_before,
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
            "credential_acquired": backend.credential_calls() > credential_calls_before,
            "transaction_started": backend.transaction_calls() > transaction_calls_before,
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
    {
        let mut sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(ApiError::not_found)?;
        session.last_result = Some(receipt_result(&result));
        persist_session(&state.config, &session_id, session)?;
    }
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
        auths_postgresql::ServiceError::NotCommitted => "not-committed",
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

fn restore_sessions(config: &AppConfig) -> Result<HashMap<String, Session>, StartupError> {
    if matches!(config.backend, BackendSettings::Fixture) {
        return Ok(HashMap::new());
    }
    let directory = config.state_directory.join("sessions");
    fs::create_dir_all(&directory).map_err(|_| StartupError::State)?;
    let mut paths = fs::read_dir(&directory)
        .map_err(|_| StartupError::State)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let BackendSettings::Live(backend) = &config.backend else {
        return Err(StartupError::State);
    };
    let mut sessions = HashMap::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|_| StartupError::State)?;
        let persisted: PersistedSession =
            serde_json::from_slice(&bytes).map_err(|_| StartupError::State)?;
        if canonical_json(&persisted).map_err(|_| StartupError::State)? != bytes
            || !valid_session_id(&persisted.session_id)
            || path.file_stem().and_then(|value| value.to_str())
                != Some(persisted.session_id.as_str())
        {
            return Err(StartupError::State);
        }
        let product = Fixture {
            action: persisted.action,
            intent: persisted.intent,
            evidence: persisted.evidence,
            configuration: persisted.configuration,
        };
        let demo = demo_fixture_from_product(
            Fixture {
                action: product.action.clone(),
                intent: product.intent.clone(),
                evidence: product.evidence.clone(),
                configuration: product.configuration.clone(),
            },
            persisted.created_at,
            persisted.challenge,
        );
        sessions.insert(
            persisted.session_id,
            Session {
                created_at: persisted.created_at,
                expires_at: persisted.expires_at,
                challenge: persisted.challenge,
                product,
                variants: demo.variants,
                proof_verifier: Arc::new(SdkProofVerifier::new(demo.auths.verifier)),
                proof: demo.auths.proof,
                auths_request: demo.auths.request,
                backend: Arc::clone(backend),
                receipts: Arc::new(MemoryReceiptSink::default()),
                initial_rows: persisted.initial_rows,
                last_result: persisted.last_result,
            },
        );
    }
    Ok(sessions)
}

fn persist_session(
    config: &AppConfig,
    session_id: &str,
    session: &Session,
) -> Result<(), ApiError> {
    if matches!(config.backend, BackendSettings::Fixture) {
        return Ok(());
    }
    let directory = config.state_directory.join("sessions");
    fs::create_dir_all(&directory).map_err(|_| ApiError::internal())?;
    let persisted = PersistedSession {
        schema: "auths-postgresql-demo-session/1".into(),
        session_id: session_id.into(),
        created_at: session.created_at,
        expires_at: session.expires_at,
        challenge: session.challenge,
        action: session.product.action.clone(),
        intent: session.product.intent.clone(),
        evidence: session.product.evidence.clone(),
        configuration: session.product.configuration.clone(),
        initial_rows: session.initial_rows.clone(),
        last_result: session.last_result.clone(),
    };
    let bytes = canonical_json(&persisted).map_err(|_| ApiError::internal())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(&directory).map_err(|_| ApiError::internal())?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| ApiError::internal())?;
    temporary
        .persist(directory.join(format!("{session_id}.json")))
        .map_err(|_| ApiError::internal())?;
    Ok(())
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

struct TeeReceiptSink {
    session: Arc<MemoryReceiptSink>,
    durable: Arc<dyn ReceiptSink>,
    fault: ReceiptFault,
}

impl ReceiptSink for TeeReceiptSink {
    fn append(&self, receipt: &PostgresReceipt) -> Result<(), PortError> {
        if self.fault == ReceiptFault::BeforeCredential {
            return Err(PortError::Persistence);
        }
        self.durable.append(receipt)?;
        self.session.append(receipt)
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

    #[test]
    fn obsolete_prelaunch_claim_state_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::write(directory.path().join("claims.json"), b"{}").unwrap();

        assert!(matches!(
            app(AppConfig::for_test(directory.path().into())),
            Err(StartupError::State)
        ));
    }
}
