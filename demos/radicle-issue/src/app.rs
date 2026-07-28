use std::{
    collections::BTreeMap,
    env, fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_radicle::{DecisionClass, EvaluationContext, RadiclePatchProfile, evaluate};
use auths_sdk::{Verifier, VerifyResult};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{AuthorizationFixture, DemoScenario, DemoVariant, authorization_fixture};

const API_SCHEMA: &str = "auths-radicle-demo/v1";
const SESSION_TTL_SECONDS: u64 = 15 * 60;
const MAX_SESSIONS: usize = 2_048;
const MAX_EXECUTION_ATTEMPTS: u8 = 8;
const MAX_REQUEST_BYTES: usize = 2 * 1024;

/// Native demo startup configuration.
#[derive(Clone)]
pub struct AppConfig {
    pub(crate) allowed_origin: HeaderValue,
    pub(crate) region: Arc<str>,
    pub(crate) release: Arc<str>,
}

impl AppConfig {
    /// Loads production configuration from the environment.
    ///
    /// # Errors
    ///
    /// Returns a closed startup failure for missing or malformed inputs.
    pub fn from_environment() -> Result<Self, StartupError> {
        let origin = env::var("AUTHS_RADICLE_ALLOWED_ORIGIN")
            .map_err(|_| StartupError::Missing("AUTHS_RADICLE_ALLOWED_ORIGIN"))?;
        if !(origin.starts_with("https://") || origin.starts_with("http://localhost:"))
            || origin.ends_with('/')
            || origin.len() > 256
        {
            return Err(StartupError::Invalid);
        }
        let allowed_origin = HeaderValue::from_str(&origin).map_err(|_| StartupError::Invalid)?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("AUTHS_RADICLE_RELEASE").unwrap_or_else(|_| "development".into());
        for value in [&region, &release] {
            if value.is_empty()
                || value.len() > 128
                || value
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
            {
                return Err(StartupError::Invalid);
            }
        }
        Ok(Self {
            allowed_origin,
            region: region.into(),
            release: release.into(),
        })
    }

    #[cfg(test)]
    fn for_test() -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: "test".into(),
            release: "test".into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    exact: Arc<ExactRuntime>,
    variants: Arc<Vec<Value>>,
    sessions: Arc<Mutex<BTreeMap<String, Session>>>,
}

struct ExactRuntime {
    scenario: DemoScenario,
    verifier: Arc<Verifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
    human_principal: String,
    workflow_principal: String,
    agent_principal: String,
}

struct Session {
    expires_at: u64,
    attempts: u8,
    execution_claimed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the native Radicle demo API.
///
/// # Errors
///
/// Returns a startup failure if a repository-owned Git/Auths fixture cannot
/// be constructed or does not authorize exactly.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let exact_scenario =
        DemoScenario::new(DemoVariant::Exact).map_err(|_| StartupError::Fixture)?;
    let fixture = authorization_fixture(&exact_scenario.action, exact_scenario.now, [0x71; 32]);
    verify_exact(&exact_scenario, &fixture)?;
    let exact = Arc::new(ExactRuntime {
        scenario: exact_scenario,
        verifier: Arc::new(fixture.verifier),
        proof: fixture.proof,
        request: fixture.request,
        human_principal: fixture.human_principal,
        workflow_principal: fixture.workflow_principal,
        agent_principal: fixture.agent_principal,
    });
    let variants = [
        DemoVariant::Exact,
        DemoVariant::RequestChanged,
        DemoVariant::ConfigurationDrift,
        DemoVariant::IssueClosed,
    ]
    .into_iter()
    .map(variant_projection)
    .collect::<Result<Vec<_>, _>>()?;
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    let state = AppState {
        config,
        exact,
        variants: Arc::new(variants),
        sessions: Arc::new(Mutex::new(BTreeMap::new())),
    };
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": &*state.config.region,
        "release": &*state.config.release,
    }))
}

async fn scenario(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "region": &*state.config.region,
        "release": &*state.config.release,
        "execution_mode": "sealed-native-fixture",
        "profile": "auths.radicle.issue-address/1",
        "human_principal": state.exact.human_principal,
        "workflow_principal": state.exact.workflow_principal,
        "agent_principal": state.exact.agent_principal,
        "rid": state.exact.scenario.grant.rid(),
        "issue_id": state.exact.scenario.grant.issue_id(),
        "candidate_oid": state.exact.scenario.candidate.candidate_oid(),
        "variants": &*state.variants,
    }))
}

async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    let session_id = hex::encode(bytes);
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the bounded native session pool is full",
        ));
    }
    sessions.insert(
        session_id.clone(),
        Session {
            expires_at: now + SESSION_TTL_SECONDS,
            attempts: 0,
            execution_claimed: false,
        },
    );
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "region": &*state.config.region,
    })))
}

async fn execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let variant = DemoVariant::parse(&request.variant).ok_or_else(|| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown-variant",
            "variant is not one of the repository-owned experiments",
        )
    })?;
    if variant != DemoVariant::Exact {
        let projection = state
            .variants
            .iter()
            .find(|value| value["id"] == variant.as_str())
            .cloned()
            .ok_or_else(ApiError::internal)?;
        return Ok(Json(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "decision": projection["decision"],
            "executions": 0,
            "receipts": 1,
        })));
    }

    verify_runtime(&state.exact).map_err(|_| ApiError::internal())?;
    let now = unix_time().map_err(|_| ApiError::internal())?;
    {
        let mut sessions = state.sessions.lock().await;
        let session = sessions.get_mut(&session_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::GONE,
                "session-unavailable",
                "the native session is missing or expired",
            )
        })?;
        if session.expires_at <= now {
            sessions.remove(&session_id);
            return Err(ApiError::new(
                StatusCode::GONE,
                "session-expired",
                "the native session expired",
            ));
        }
        if session.attempts >= MAX_EXECUTION_ATTEMPTS {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "attempt-limit",
                "the bounded session attempt limit was reached",
            ));
        }
        session.attempts += 1;
        if session.execution_claimed {
            return Err(ApiError::new(
                StatusCode::CONFLICT,
                "execution-lease-consumed",
                "verification can repeat, but this exact workflow already executed",
            ));
        }
        session.execution_claimed = true;
    }

    let action_digest = state
        .exact
        .scenario
        .action
        .digest()
        .map_err(|_| ApiError::internal())?;
    let patch_id = &action_digest.as_str()[..40];
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "entered_executor": true,
        "execution_mode": "sealed-native-fixture",
        "decision": {
            "class": "authorized",
            "code": "authorized",
            "stage": "auths-kernel",
        },
        "publication": {
            "patch_id": patch_id,
            "revision_id": patch_id,
            "candidate_oid": state.exact.scenario.candidate.candidate_oid(),
            "canonical_updated": false,
        },
        "stages": [
            {"name": "authorized", "status": "proven"},
            {"name": "claimed", "status": "durable"},
            {"name": "stored", "status": "fixture"},
            {"name": "announced", "status": "fixture"},
            {"name": "replicated", "status": "fixture"}
        ],
        "executions": 1,
        "receipts": 3,
    })))
}

pub(crate) fn variant_projection(variant: DemoVariant) -> Result<Value, StartupError> {
    let scenario = DemoScenario::new(variant).map_err(|_| StartupError::Fixture)?;
    let decision = evaluate(&EvaluationContext {
        grant: &scenario.grant,
        action: &scenario.action,
        submission: &scenario.submission,
        candidate: &scenario.candidate,
        evidence: &scenario.evidence,
        required_configuration: &scenario.required_configuration,
        executed_configuration: &scenario.executed_configuration,
        request_audience: scenario.required_configuration.executor_audience().as_str(),
        now: scenario.now,
    });
    let required = scenario
        .required_configuration
        .digest()
        .map_err(|_| StartupError::Fixture)?;
    let executed = scenario
        .executed_configuration
        .digest()
        .map_err(|_| StartupError::Fixture)?;
    Ok(json!({
        "id": variant.as_str(),
        "decision": {
            "class": decision_class(decision.class),
            "code": decision.code,
            "detail": decision.detail,
            "stage": if decision.class == DecisionClass::Authorized {
                "auths-kernel"
            } else {
                "radicle-containment"
            },
        },
        "required_configuration": required,
        "executed_configuration": executed,
        "configuration_match": required == executed,
        "changed_files": scenario.candidate.changes().len(),
        "changed_bytes": scenario.candidate.changed_bytes(),
        "issue_open": scenario.evidence.issue_open(),
        "signer_is_delegate": scenario
            .evidence
            .delegates()
            .contains(scenario.grant.expected_signer_did()),
    }))
}

fn verify_exact(
    scenario: &DemoScenario,
    fixture: &AuthorizationFixture,
) -> Result<(), StartupError> {
    let canonical = RadiclePatchProfile
        .canonicalize(
            &scenario
                .action
                .canonical_bytes()
                .map_err(|_| StartupError::Fixture)?,
        )
        .map_err(|_| StartupError::Fixture)?;
    let result = fixture
        .verifier
        .verify(
            &fixture.proof,
            &canonical,
            &fixture.request,
            &RadiclePatchProfile,
        )
        .map_err(|_| StartupError::Fixture)?;
    if matches!(result, VerifyResult::Authorized(_)) {
        Ok(())
    } else {
        Err(StartupError::Fixture)
    }
}

fn verify_runtime(runtime: &ExactRuntime) -> Result<(), StartupError> {
    let canonical = RadiclePatchProfile
        .canonicalize(
            &runtime
                .scenario
                .action
                .canonical_bytes()
                .map_err(|_| StartupError::Fixture)?,
        )
        .map_err(|_| StartupError::Fixture)?;
    let result = runtime
        .verifier
        .verify(
            &runtime.proof,
            &canonical,
            &runtime.request,
            &RadiclePatchProfile,
        )
        .map_err(|_| StartupError::Fixture)?;
    if matches!(result, VerifyResult::Authorized(_)) {
        Ok(())
    } else {
        Err(StartupError::Fixture)
    }
}

const fn decision_class(class: DecisionClass) -> &'static str {
    match class {
        DecisionClass::Authorized => "authorized",
        DecisionClass::Denied => "denied",
        DecisionClass::Indeterminate => "indeterminate",
    }
}

fn unix_time() -> Result<u64, StartupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StartupError::Invalid)
}

/// Demo startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    /// Required environment is missing.
    Missing(&'static str),
    /// Configuration is malformed.
    Invalid,
    /// A repository-owned Git/Auths fixture failed closed.
    Fixture,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => {
                write!(formatter, "required environment variable {name} missing")
            }
            Self::Invalid => formatter.write_str("invalid Radicle demo configuration"),
            Self::Fixture => formatter.write_str("Radicle demo fixture failed validation"),
        }
    }
}

impl std::error::Error for StartupError {}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl ApiError {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    const fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "the bounded native demo failed closed",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
                "error": {
                    "code": self.code,
                    "message": self.message,
                }
            })),
        )
            .into_response()
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
    async fn exact_execution_succeeds_once_and_replay_fails_closed() {
        let app = app(AppConfig::for_test()).unwrap();
        let create = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(create.into_body(), 64 * 1024).await.unwrap();
        let session: Value = serde_json::from_slice(&body).unwrap();
        let path = format!(
            "/api/v1/sessions/{}/execute",
            session["session_id"].as_str().unwrap()
        );
        let request = || {
            Request::post(&path)
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"variant":"exact"}"#))
                .unwrap()
        };

        let first = app.clone().oneshot(request()).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let replay = app.oneshot(request()).await.unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn denied_variant_never_enters_executor() {
        let app = app(AppConfig::for_test()).unwrap();
        let response = app
            .oneshot(
                Request::post("/api/v1/sessions/unused/execute")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"configuration-drift"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 64 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["entered_executor"], false);
        assert_eq!(value["executions"], 0);
    }
}
