//! Native API and browser surface for an exact manual Stripe Payout.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the demo keeps compact HTTP and state boundaries explicit"
)]

use std::{
    collections::HashMap,
    env, fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::Html,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

const API_SCHEMA: &str = "auths.stripe.payout-demo/1";
const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    state_directory: Arc<Path>,
    region: Arc<str>,
    release: Arc<str>,
}

impl AppConfig {
    pub fn from_environment() -> Result<Self, StartupError> {
        let origin = env::var("AUTHS_STRIPE_ALLOWED_ORIGIN")
            .map_err(|_| StartupError::Missing("AUTHS_STRIPE_ALLOWED_ORIGIN"))?;
        if !(origin.starts_with("https://") || origin.starts_with("http://localhost:"))
            || origin.ends_with('/')
            || origin.len() > 256
        {
            return Err(StartupError::Invalid);
        }
        let state_directory = PathBuf::from(
            env::var("AUTHS_STRIPE_STATE_DIR")
                .unwrap_or_else(|_| "/data/auths-stripe-payout".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        Ok(Self {
            allowed_origin: HeaderValue::from_str(&origin).map_err(|_| StartupError::Invalid)?,
            state_directory: state_directory.into(),
            region: checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?
                .into(),
            release: checked_label(
                env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
            )?
            .into(),
        })
    }

    #[cfg(test)]
    fn for_test(path: PathBuf) -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("http://localhost:8080"),
            state_directory: path.into(),
            region: "test".into(),
            release: "test".into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    workflows: Arc<Mutex<HashMap<String, DemoRecord>>>,
    journal: Arc<Journal>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PayoutRequest {
    workflow_id: String,
    experiment: Experiment,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Experiment {
    Pending,
    Denied,
    Unknown,
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct DemoRecord {
    schema: &'static str,
    workflow_id: String,
    outcome: &'static str,
    code: &'static str,
    amount_minor: u64,
    currency: &'static str,
    destination_commitment: &'static str,
    method: &'static str,
    source_type: &'static str,
    approvals: u8,
    available_before_minor: u64,
    available_after_minor: u64,
    minimum_retained_minor: u64,
    credential_requests: u8,
    provider_calls: u8,
    capacity_held: bool,
}

struct Journal {
    path: PathBuf,
    lock: Mutex<()>,
}

impl Journal {
    fn append(&self, value: &DemoRecord) -> Result<(), StartupError> {
        let _guard = self.lock.lock().map_err(|_| StartupError::State)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| StartupError::State)?;
        file.write_all(&serde_json::to_vec(value).map_err(|_| StartupError::State)?)
            .map_err(|_| StartupError::State)?;
        file.write_all(b"\n").map_err(|_| StartupError::State)
    }
}

pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    fs::create_dir_all(&*config.state_directory).map_err(|_| StartupError::State)?;
    let state = AppState {
        workflows: Arc::new(Mutex::new(HashMap::new())),
        journal: Arc::new(Journal {
            path: config.state_directory.join("receipts.ndjson"),
            lock: Mutex::new(()),
        }),
        config: config.clone(),
    };
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    Ok(Router::new()
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/styles.css",
            get(|| async {
                (
                    [(CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../web/styles.css"),
                )
            }),
        )
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/payouts", post(payout))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ok",
        "region": &*state.config.region,
        "release": &*state.config.release
    }))
}

async fn readiness() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ready",
        "credential_scope": "stripe-payout-create",
        "agent_has_stripe_key": false
    }))
}

async fn scenario() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": auths_stripe::PAYOUT_PROFILE,
        "policy_type": auths_stripe::PAYOUT_POLICY_TYPE,
        "evaluator": auths_stripe::PAYOUT_EVALUATOR_ID,
        "amount_minor": 500,
        "currency": "usd",
        "method": "standard",
        "available_before_minor": 2000,
        "minimum_retained_minor": 500,
        "available_after_minor": 1500,
        "required_distinct_approvers": 2,
        "test_mode_bank_funds_moved": false
    }))
}

async fn payout(
    State(state): State<AppState>,
    Json(request): Json<PayoutRequest>,
) -> Result<Json<DemoRecord>, (StatusCode, Json<Value>)> {
    if !valid_workflow(&request.workflow_id) {
        return Err(error(StatusCode::BAD_REQUEST, "invalid-workflow-id"));
    }
    let mut workflows = state
        .workflows
        .lock()
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "state-failure"))?;
    if let Some(existing) = workflows.get(&request.workflow_id) {
        let mut replay = existing.clone();
        replay.outcome = "replay";
        replay.code = "payout-replay";
        replay.credential_requests = 0;
        replay.provider_calls = 0;
        return Ok(Json(replay));
    }
    let record = match request.experiment {
        Experiment::Pending => record(request.workflow_id, "pending", "payout-pending", 1, 1, true),
        Experiment::Denied => record(
            request.workflow_id,
            "denied",
            "payout-approval-required",
            0,
            0,
            false,
        ),
        Experiment::Unknown => record(
            request.workflow_id,
            "outcome-unknown",
            "payout-outcome-unknown",
            1,
            1,
            true,
        ),
    };
    state
        .journal
        .append(&record)
        .map_err(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "receipt-failure"))?;
    workflows.insert(record.workflow_id.clone(), record.clone());
    Ok(Json(record))
}

fn record(
    workflow_id: String,
    outcome: &'static str,
    code: &'static str,
    credential_requests: u8,
    provider_calls: u8,
    capacity_held: bool,
) -> DemoRecord {
    DemoRecord {
        schema: API_SCHEMA,
        workflow_id,
        outcome,
        code,
        amount_minor: 500,
        currency: "usd",
        destination_commitment: "sha256:repository-owned-bank-fixture",
        method: "standard",
        source_type: "bank_account",
        approvals: 2,
        available_before_minor: 2_000,
        available_after_minor: 1_500,
        minimum_retained_minor: 500,
        credential_requests,
        provider_calls,
        capacity_held,
    }
}

fn valid_workflow(value: &str) -> bool {
    (8..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn checked_label(value: String) -> Result<String, StartupError> {
    if !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Ok(value)
    } else {
        Err(StartupError::Invalid)
    }
}

fn error(status: StatusCode, code: &'static str) -> (StatusCode, Json<Value>) {
    (status, Json(json!({ "error": code })))
}

#[derive(Debug)]
pub enum StartupError {
    Missing(&'static str),
    Invalid,
    State,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => {
                write!(formatter, "missing required environment variable {name}")
            }
            Self::Invalid => formatter.write_str("invalid demo configuration"),
            Self::State => formatter.write_str("demo state is unavailable"),
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn approval_denial_is_pre_credential_and_pending_replays_once() {
        let temporary = tempfile::tempdir().unwrap();
        let app = app(AppConfig::for_test(temporary.path().to_path_buf())).unwrap();
        let denied = call(
            &app,
            r#"{"workflow_id":"workflow-denied","experiment":"denied"}"#,
        )
        .await;
        assert_eq!(denied["provider_calls"], 0);
        let first = call(
            &app,
            r#"{"workflow_id":"workflow-pending","experiment":"pending"}"#,
        )
        .await;
        assert_eq!(first["provider_calls"], 1);
        let replay = call(
            &app,
            r#"{"workflow_id":"workflow-pending","experiment":"pending"}"#,
        )
        .await;
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["provider_calls"], 0);
    }

    #[tokio::test]
    async fn unknown_outcome_keeps_outgoing_capacity() {
        let temporary = tempfile::tempdir().unwrap();
        let app = app(AppConfig::for_test(temporary.path().to_path_buf())).unwrap();
        let result = call(
            &app,
            r#"{"workflow_id":"workflow-unknown","experiment":"unknown"}"#,
        )
        .await;
        assert_eq!(result["capacity_held"], true);
    }

    async fn call(app: &Router, body: &'static str) -> Value {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/payouts")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap(),
        )
        .unwrap()
    }
}
