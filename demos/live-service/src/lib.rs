#![forbid(unsafe_code)]

use auths_apps_testkit::{DemoRuntimeSession, demo_fixture_bytes_for_challenge};
use auths_live_lab::generate_variants;
use auths_proof_exchange_model::{ActionResponse, ExchangeOutcome, RefusalKind, VerdictDecision};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, Request, State},
    http::{
        HeaderMap, HeaderName, HeaderValue, Method, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE},
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use hmac::{Hmac, Mac as _};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    env, fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

const API_SCHEMA: &str = "auths-live-service/v1";
const SESSION_TTL_SECONDS: u64 = 15 * 60;
const MAX_SESSIONS: usize = 2_048;
const MAX_SESSION_ATTEMPTS: u32 = 16;
const MAX_CREATIONS_PER_MINUTE: usize = 120;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const FLY_REPLAY: HeaderName = HeaderName::from_static("fly-replay");
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct AppConfig {
    release_id: Arc<str>,
    wasm_sha256: Arc<str>,
    allowed_origin: HeaderValue,
    region: Arc<str>,
    token_key: [u8; 32],
}

impl AppConfig {
    /// Loads and validates the complete service security configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when a required value is missing, malformed, or
    /// outside the bounded production contract.
    pub fn from_environment() -> Result<Self, StartupError> {
        let release_id = required_environment("AUTHS_LIVE_RELEASE_ID")?;
        validate_identifier("release ID", &release_id, 128)?;
        let wasm_sha256 = required_environment("AUTHS_LIVE_WASM_SHA256")?;
        if wasm_sha256.len() != 64
            || !wasm_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(StartupError::Invalid(
                "AUTHS_LIVE_WASM_SHA256 must be a 32-byte lowercase hex digest".into(),
            ));
        }
        let allowed_origin = required_environment("AUTHS_LIVE_ALLOWED_ORIGIN")?;
        validate_exact_origin(&allowed_origin)?;
        let allowed_origin = HeaderValue::from_str(&allowed_origin)
            .map_err(|_| StartupError::Invalid("allowed origin is not a valid header".into()))?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        validate_identifier("region", &region, 16)?;
        let token_key = required_environment("AUTHS_LIVE_TOKEN_KEY_HEX")?;
        let token_key = hex::decode(token_key)
            .map_err(|_| StartupError::Invalid("token key is not hex".into()))?
            .try_into()
            .map_err(|_| StartupError::Invalid("token key must be exactly 32 bytes".into()))?;
        Ok(Self {
            release_id: release_id.into(),
            wasm_sha256: wasm_sha256.into(),
            allowed_origin,
            region: region.into(),
            token_key,
        })
    }

    #[must_use]
    pub fn release_id(&self) -> &str {
        &self.release_id
    }

    #[must_use]
    pub fn region(&self) -> &str {
        &self.region
    }

    #[cfg(test)]
    fn for_test(region: &str) -> Self {
        Self {
            release_id: "test-release".into(),
            wasm_sha256: "00".repeat(32).into(),
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: region.to_owned().into(),
            token_key: [0x73; 32],
        }
    }
}

#[derive(Debug)]
pub enum StartupError {
    Missing(&'static str),
    Invalid(String),
    Engine(auths_proof_wasm::EngineError),
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => {
                write!(formatter, "required environment variable {name} is missing")
            }
            Self::Invalid(message) => formatter.write_str(message),
            Self::Engine(error) => write!(formatter, "could not initialize verifier: {error}"),
        }
    }
}

impl std::error::Error for StartupError {}

impl From<auths_proof_wasm::EngineError> for StartupError {
    fn from(error: auths_proof_wasm::EngineError) -> Self {
        Self::Engine(error)
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    verifier_configuration: Arc<str>,
    sessions: Arc<Mutex<BTreeMap<String, SessionRecord>>>,
    creation_times: Arc<Mutex<VecDeque<u64>>>,
}

struct SessionRecord {
    expires_at: u64,
    attempts: u32,
    runtime: Arc<DemoRuntimeSession>,
    variants: BTreeMap<String, Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the native live-service router.
///
/// # Errors
///
/// Returns an error when the built-in verifier configuration cannot be
/// initialized.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let verifier_configuration = auths_proof_wasm::self_contained_v1_configuration()
        .map(hex::encode)
        .map_err(StartupError::Engine)?;
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);
    let state = AppState {
        config,
        verifier_configuration: verifier_configuration.into(),
        sessions: Arc::new(Mutex::new(BTreeMap::new())),
        creation_times: Arc::new(Mutex::new(VecDeque::new())),
    };
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/meta", get(meta))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .fallback(not_found)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(middleware::from_fn(security_headers))
        .layer(cors)
        .with_state(state))
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "release_id": state.config.release_id(),
        "region": state.config.region(),
    }))
}

async fn meta(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release_id": state.config.release_id(),
        "region": state.config.region(),
        "protocol_major": 1,
        "portable_abi": 2,
        "verifier_configuration": &*state.verifier_configuration,
        "wasm_sha256": &*state.config.wasm_sha256,
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "max_session_attempts": MAX_SESSION_ATTEMPTS,
    }))
}

async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    enforce_creation_rate(&state, now).await?;
    {
        let mut sessions = state.sessions.lock().await;
        sessions.retain(|_, session| session.expires_at > now);
        if sessions.len() >= MAX_SESSIONS {
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "session-capacity",
                "the regional demo session pool is full",
            ));
        }
    }

    let mut session_bytes = [0_u8; 16];
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut session_bytes)
        .and_then(|()| getrandom::fill(&mut challenge))
        .map_err(|_| ApiError::internal("secure randomness is unavailable"))?;
    let session_id = hex::encode(session_bytes);
    let expires_at = now + SESSION_TTL_SECONDS;
    let fixture = demo_fixture_bytes_for_challenge(challenge);
    let variants = generate_variants(fixture)
        .map_err(|_| ApiError::internal("could not build session verifier inputs"))?;
    let runtime = Arc::new(DemoRuntimeSession::new(challenge).await);
    let mut native = BTreeMap::new();
    let response_variants = variants
        .into_iter()
        .map(|variant| {
            let projection = variant.projection["native"].clone();
            native.insert(variant.id.to_owned(), projection.clone());
            json!({
                "id": variant.id,
                "proof": Base64UrlUnpadded::encode_string(&variant.proof),
                "action": Base64UrlUnpadded::encode_string(&variant.action),
                "context": Base64UrlUnpadded::encode_string(&variant.context),
                "native": projection,
            })
        })
        .collect::<Vec<_>>();
    let token = issue_token(&state.config, &session_id, expires_at)?;
    let record = SessionRecord {
        expires_at,
        attempts: 0,
        runtime,
        variants: native,
    };
    let mut sessions = state.sessions.lock().await;
    if sessions.insert(session_id.clone(), record).is_some() {
        return Err(ApiError::internal("session identifier collision"));
    }
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "release_id": state.config.release_id(),
        "region": state.config.region(),
        "session_id": session_id,
        "expires_at": expires_at,
        "token": token,
        "variants": response_variants,
    })))
}

async fn execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<ExecuteRequest>,
) -> Result<Response, ApiError> {
    if !matches!(
        request.variant.as_str(),
        "valid" | "tampered-action" | "tampered-proof" | "wrong-configuration"
    ) {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown-variant",
            "variant is not one of the four repository-owned experiments",
        ));
    }
    let token = bearer_token(&headers)?;
    let claims = validate_token(&state.config, token)?;
    if claims.session_id != session_id {
        return Err(ApiError::new(
            StatusCode::UNAUTHORIZED,
            "session-token-mismatch",
            "the token does not own this session",
        ));
    }
    if claims.region != state.config.region() {
        let replay = HeaderValue::from_str(&format!("region={}", claims.region))
            .map_err(|_| ApiError::internal("invalid replay region"))?;
        let mut response = ApiError::new(
            StatusCode::CONFLICT,
            "wrong-region",
            "request must be replayed to the session owner",
        )
        .into_response();
        response.headers_mut().insert(FLY_REPLAY, replay);
        return Ok(response);
    }
    let now = unix_time()?;
    let (runtime, native) = {
        let mut sessions = state.sessions.lock().await;
        let Some(session) = sessions.get_mut(&session_id) else {
            return Err(ApiError::new(
                StatusCode::GONE,
                "session-unavailable",
                "the owning machine no longer has this session",
            ));
        };
        if session.expires_at <= now {
            sessions.remove(&session_id);
            return Err(ApiError::new(
                StatusCode::GONE,
                "session-expired",
                "the interactive session expired",
            ));
        }
        if session.attempts >= MAX_SESSION_ATTEMPTS {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "attempt-limit",
                "the session attempt limit was reached",
            ));
        }
        session.attempts += 1;
        (
            session.runtime.clone(),
            session
                .variants
                .get(&request.variant)
                .cloned()
                .ok_or_else(|| ApiError::internal("session variant missing"))?,
        )
    };

    let runtime_projection = if request.variant == "valid" {
        let submission = runtime.execute().await;
        json!({
            "entered": true,
            "response": response_projection(&submission.response),
            "executor_invocations": submission.executor_invocations,
            "decision_receipts": submission.decision_receipts,
            "execution_receipts": submission.execution_receipts,
        })
    } else {
        json!({
            "entered": false,
            "reason": "portable-verifier-denied",
            "executor_invocations": 0,
            "decision_receipts": 0,
            "execution_receipts": 0,
        })
    };
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "release_id": state.config.release_id(),
        "region": state.config.region(),
        "session_id": session_id,
        "variant": request.variant,
        "native": native,
        "runtime": runtime_projection,
    }))
    .into_response())
}

async fn enforce_creation_rate(state: &AppState, now: u64) -> Result<(), ApiError> {
    let mut times = state.creation_times.lock().await;
    while times.front().is_some_and(|created| *created + 60 <= now) {
        times.pop_front();
    }
    if times.len() >= MAX_CREATIONS_PER_MINUTE {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "creation-rate",
            "the regional session creation limit was reached",
        ));
    }
    times.push_back(now);
    Ok(())
}

struct TokenClaims {
    region: String,
    session_id: String,
}

fn issue_token(config: &AppConfig, session_id: &str, expires_at: u64) -> Result<String, ApiError> {
    let payload = token_payload(expires_at, config.region(), session_id, config.release_id());
    let mut mac = HmacSha256::new_from_slice(&config.token_key)
        .map_err(|_| ApiError::internal("invalid token key"))?;
    mac.update(payload.as_bytes());
    Ok(format!(
        "v1.{expires_at}.{}.{}.{tag}",
        config.region(),
        session_id,
        tag = hex::encode(mac.finalize().into_bytes())
    ))
}

fn validate_token(config: &AppConfig, token: &str) -> Result<TokenClaims, ApiError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 5 || parts[0] != "v1" {
        return Err(ApiError::unauthorized(
            "invalid-token",
            "invalid session token",
        ));
    }
    let expires_at = parts[1]
        .parse::<u64>()
        .map_err(|_| ApiError::unauthorized("invalid-token", "invalid session token"))?;
    validate_identifier("token region", parts[2], 16)
        .map_err(|_| ApiError::unauthorized("invalid-token", "invalid session token"))?;
    if parts[3].len() != 32 || hex::decode(parts[3]).map_or(true, |bytes| bytes.len() != 16) {
        return Err(ApiError::unauthorized(
            "invalid-token",
            "invalid session token",
        ));
    }
    let tag = hex::decode(parts[4])
        .map_err(|_| ApiError::unauthorized("invalid-token", "invalid session token"))?;
    let payload = token_payload(expires_at, parts[2], parts[3], config.release_id());
    let mut mac = HmacSha256::new_from_slice(&config.token_key)
        .map_err(|_| ApiError::internal("invalid token key"))?;
    mac.update(payload.as_bytes());
    mac.verify_slice(&tag)
        .map_err(|_| ApiError::unauthorized("invalid-token", "invalid session token"))?;
    if expires_at <= unix_time()? {
        return Err(ApiError::unauthorized(
            "expired-token",
            "session token expired",
        ));
    }
    Ok(TokenClaims {
        region: parts[2].to_owned(),
        session_id: parts[3].to_owned(),
    })
}

fn token_payload(expires_at: u64, region: &str, session_id: &str, release_id: &str) -> String {
    format!("v1\n{expires_at}\n{region}\n{session_id}\n{release_id}")
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|value| !value.is_empty() && !value.contains(char::is_whitespace))
        .ok_or_else(|| {
            ApiError::unauthorized("missing-token", "a session bearer token is required")
        })
}

fn response_projection(response: &ActionResponse) -> Value {
    let request_id = response.request_id().map(hex::encode);
    match response.outcome() {
        ExchangeOutcome::Completed { result } => json!({
            "outcome": "completed",
            "request_id": request_id,
            "result_sha256": hex::encode(Sha256::digest(result)),
        }),
        ExchangeOutcome::Refused {
            kind,
            verdict,
            message,
        } => json!({
            "outcome": "refused",
            "kind": refusal_name(*kind),
            "message": message,
            "verdict": verdict.as_ref().map(|summary| json!({
                "decision": verdict_name(summary.decision()),
                "reasons": summary.reasons(),
            })),
            "request_id": request_id,
        }),
    }
}

const fn refusal_name(kind: RefusalKind) -> &'static str {
    match kind {
        RefusalKind::ApplicationPolicy => "application-policy",
        RefusalKind::TransportPolicy => "transport-policy",
        RefusalKind::AuthsVerdict => "auths-verdict",
        RefusalKind::MalformedInput => "malformed-input",
        RefusalKind::OversizedInput => "oversized-input",
        RefusalKind::UnknownChallenge => "unknown-challenge",
        RefusalKind::ExpiredChallenge => "expired-challenge",
        RefusalKind::ConsumedChallenge => "consumed-challenge",
    }
}

const fn verdict_name(decision: VerdictDecision) -> &'static str {
    match decision {
        VerdictDecision::Authorized => "authorized",
        VerdictDecision::Denied => "denied",
        VerdictDecision::Indeterminate => "indeterminate",
    }
}

async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    response
}

async fn not_found() -> ApiError {
    ApiError::new(StatusCode::NOT_FOUND, "not-found", "route does not exist")
}

#[derive(Debug)]
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

    const fn unauthorized(code: &'static str, message: &'static str) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    const fn internal(message: &'static str) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal-error", message)
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
                },
            })),
        )
            .into_response()
    }
}

fn required_environment(name: &'static str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(StartupError::Missing(name))
}

fn validate_identifier(kind: &str, value: &str, max_len: usize) -> Result<(), StartupError> {
    if value.is_empty()
        || value.len() > max_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StartupError::Invalid(format!(
            "{kind} must contain only ASCII letters, numbers, '-' or '_' and be at most {max_len} bytes"
        )));
    }
    Ok(())
}

fn validate_exact_origin(value: &str) -> Result<(), StartupError> {
    if let Some(authority) = value
        .strip_prefix("http://127.0.0.1:")
        .or_else(|| value.strip_prefix("http://localhost:"))
    {
        if authority.is_empty() || !authority.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(StartupError::Invalid(
                "local allowed origins must include a numeric port".into(),
            ));
        }
        return Ok(());
    }
    let Some(authority) = value.strip_prefix("https://") else {
        return Err(StartupError::Invalid(
            "allowed origin must use HTTPS, except for explicit localhost development".into(),
        ));
    };
    if authority.is_empty()
        || authority.len() > 253
        || authority
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#' | b'@'))
    {
        return Err(StartupError::Invalid(
            "AUTHS_LIVE_ALLOWED_ORIGIN must be one exact origin without credentials or a path"
                .into(),
        ));
    }
    Ok(())
}

fn unix_time() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal("system clock is before the Unix epoch"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use tower::ServiceExt as _;

    #[test]
    fn allowed_origin_is_exact_https_or_explicit_localhost() {
        assert!(validate_exact_origin("https://auths-live-demo.vercel.app").is_ok());
        assert!(validate_exact_origin("http://127.0.0.1:4173").is_ok());
        for invalid in [
            "http://auths-live-demo.vercel.app",
            "https://",
            "https://auths-live-demo.vercel.app/path",
            "https://user@auths-live-demo.vercel.app",
            "http://localhost:",
        ] {
            assert!(validate_exact_origin(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn token_rejects_tampering_and_release_drift() {
        let config = AppConfig::for_test("lhr");
        let valid_expiry = unix_time().unwrap() + 60;
        let token = issue_token(&config, "11aa22bb33cc44dd55ee66ff77889900", valid_expiry).unwrap();
        let claims = validate_token(&config, &token).unwrap();
        assert_eq!(claims.region, "lhr");

        let mut tampered = token.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
        assert!(validate_token(&config, std::str::from_utf8(&tampered).unwrap()).is_err());

        let mut other_release = config;
        other_release.release_id = "other-release".into();
        assert!(validate_token(&other_release, &token).is_err());

        let expired_token = issue_token(
            &AppConfig::for_test("lhr"),
            "11aa22bb33cc44dd55ee66ff77889900",
            unix_time().unwrap() - 1,
        )
        .unwrap();
        assert!(validate_token(&AppConfig::for_test("lhr"), &expired_token).is_err());
    }

    #[tokio::test]
    async fn valid_executes_once_and_replay_is_consumed() {
        let application = app(AppConfig::for_test("lhr")).unwrap();
        let created = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/sessions")
                    .header("origin", "https://demo.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let session = created["session_id"].as_str().unwrap();
        let token = created["token"].as_str().unwrap();

        let first = execute_request(&application, session, token, "valid").await;
        assert_eq!(first["runtime"]["response"]["outcome"], "completed");
        assert_eq!(first["runtime"]["executor_invocations"], 1);
        assert_eq!(first["runtime"]["decision_receipts"], 1);
        assert_eq!(first["runtime"]["execution_receipts"], 1);

        let replay = execute_request(&application, session, token, "valid").await;
        assert_eq!(replay["runtime"]["response"]["kind"], "consumed-challenge");
        assert_eq!(replay["runtime"]["executor_invocations"], 1);
        assert_eq!(replay["runtime"]["decision_receipts"], 1);
        assert_eq!(replay["runtime"]["execution_receipts"], 1);
    }

    #[tokio::test]
    async fn hostile_variant_never_enters_runtime() {
        let application = app(AppConfig::for_test("iad")).unwrap();
        let created = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let response = execute_request(
            &application,
            created["session_id"].as_str().unwrap(),
            created["token"].as_str().unwrap(),
            "tampered-proof",
        )
        .await;
        assert_eq!(response["native"]["decision"], "denied");
        assert_eq!(response["runtime"]["entered"], false);
        assert_eq!(response["runtime"]["executor_invocations"], 0);
    }

    #[tokio::test]
    async fn authenticated_owner_token_is_required_before_region_replay() {
        let iad = app(AppConfig::for_test("iad")).unwrap();
        let lhr = app(AppConfig::for_test("lhr")).unwrap();
        let created = lhr
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let session = created["session_id"].as_str().unwrap();
        let token = created["token"].as_str().unwrap();
        let response = iad
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/sessions/{session}/execute"))
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"valid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(response.headers().get(FLY_REPLAY).unwrap(), "region=lhr");

        let unauthenticated = app(AppConfig::for_test("iad"))
            .unwrap()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/sessions/{session}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"valid"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert!(unauthenticated.headers().get(FLY_REPLAY).is_none());
    }

    #[tokio::test]
    async fn body_and_session_attempt_limits_are_hard() {
        let application = app(AppConfig::for_test("lhr")).unwrap();
        let created = application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let created: Value =
            serde_json::from_slice(&to_bytes(created.into_body(), 1_000_000).await.unwrap())
                .unwrap();
        let session = created["session_id"].as_str().unwrap();
        let token = created["token"].as_str().unwrap();
        for _ in 0..MAX_SESSION_ATTEMPTS {
            let response = execute_response(&application, session, token, "tampered-action").await;
            assert_eq!(response.status(), StatusCode::OK);
        }
        let limited = execute_response(&application, session, token, "tampered-action").await;
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);

        let oversized = application
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/sessions/{session}/execute"))
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("x".repeat(MAX_REQUEST_BYTES + 1)))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    async fn execute_request(
        application: &Router,
        session: &str,
        token: &str,
        variant: &str,
    ) -> Value {
        let response = execute_response(application, session, token, variant).await;
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&to_bytes(response.into_body(), 1_000_000).await.unwrap()).unwrap()
    }

    async fn execute_response(
        application: &Router,
        session: &str,
        token: &str,
        variant: &str,
    ) -> Response {
        application
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/api/v1/sessions/{session}/execute"))
                    .header(AUTHORIZATION, format!("Bearer {token}"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"variant":"{variant}"}}"#)))
                    .unwrap(),
            )
            .await
            .unwrap()
    }
}
