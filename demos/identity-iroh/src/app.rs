use std::{env, net::SocketAddr, sync::Arc};

use auths_identity_iroh::{
    IDENTITY_ALPN_V1, IdentityError, IdentityPacket, IrohIdentityClient, IrohIdentityConfig,
    IrohIdentityServer, PathObservation, PublicIdentity, SignedIdentityMessage,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use ed25519_dalek::{Signer as _, SigningKey};
use iroh::{Endpoint, EndpointAddr, RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::cors::CorsLayer;

const API_SCHEMA: &str = "auths.identity-iroh-demo/1";
const MAX_DEMO_MESSAGE_BYTES: usize = 256;

/// Deployment configuration for the public demo shell.
#[derive(Clone, Debug)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    region: Arc<str>,
    release: Arc<str>,
}

impl AppConfig {
    /// Loads non-secret presentation settings from the environment.
    #[must_use]
    pub fn from_environment() -> Self {
        let origin = env::var("AUTHS_IDENTITY_ALLOWED_ORIGIN").unwrap_or_else(|_| "*".into());
        let allowed_origin = match origin.parse() {
            Ok(value) => value,
            Err(_) => HeaderValue::from_static("*"),
        };
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("AUTHS_IDENTITY_RELEASE").unwrap_or_else(|_| "development".into());
        Self {
            allowed_origin,
            region: region.into(),
            release: release.into(),
        }
    }

    #[cfg(test)]
    fn test() -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("*"),
            region: "test".into(),
            release: "test".into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    server_endpoint: Endpoint,
    server_target: EndpointAddr,
    server_signing: Arc<SigningKey>,
    server_identity: PublicIdentity,
    config: AppConfig,
}

/// Builds the complete native demo with one real local Iroh endpoint.
///
/// # Errors
///
/// Returns a startup error if entropy, identity construction, endpoint
/// binding, or direct local addressing is unavailable.
pub async fn app(config: AppConfig) -> Result<Router, StartupError> {
    let server_signing = Arc::new(ephemeral_signing_key()?);
    let server_identity = PublicIdentity::from_ed25519(server_signing.verifying_key().to_bytes())
        .map_err(|_| StartupError)?;
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![IDENTITY_ALPN_V1.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|_| StartupError)?;
    let server_target = direct_target(&server_endpoint).ok_or(StartupError)?;
    let allowed_origin = config.allowed_origin.clone();
    let state = AppState {
        server_endpoint,
        server_target,
        server_signing,
        server_identity,
        config,
    };
    let cors = if allowed_origin == HeaderValue::from_static("*") {
        CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers(tower_http::cors::Any)
    } else {
        CorsLayer::new()
            .allow_origin(allowed_origin)
            .allow_methods([Method::GET, Method::POST])
            .allow_headers([CONTENT_TYPE])
    };
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.js", get(javascript))
        .route("/styles.css", get(styles))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/api/v1/status", get(status))
        .route("/api/v1/exchanges", post(exchange))
        .layer(DefaultBodyLimit::max(4 * 1024))
        .layer(cors)
        .with_state(state))
}

/// Serves the complete browser and API application.
///
/// # Errors
///
/// Returns a startup error if the Iroh or HTTP listener cannot be bound, or
/// the HTTP service terminates unexpectedly.
pub async fn serve(config: AppConfig, address: SocketAddr) -> Result<(), StartupError> {
    let router = app(config).await?;
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| StartupError)?;
    println!("auths-identity-iroh-demo listening on http://{address}");
    axum::serve(listener, router)
        .await
        .map_err(|_| StartupError)
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn javascript() -> Response {
    static_asset(
        include_str!("../web/app.js"),
        "application/javascript; charset=utf-8",
    )
}

async fn styles() -> Response {
    static_asset(include_str!("../web/styles.css"), "text/css; charset=utf-8")
}

fn static_asset(content: &'static str, content_type: &'static str) -> Response {
    ([(CONTENT_TYPE, content_type)], content).into_response()
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": state.config.region,
        "release": state.config.release,
    }))
}

#[derive(Serialize)]
struct StatusResponse {
    schema: &'static str,
    server_principal: String,
    server_public_key: String,
    server_iroh_endpoint_id: String,
    capability_api_required: bool,
    approval_api_required: bool,
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        schema: API_SCHEMA,
        server_principal: state.server_identity.principal().as_str().into(),
        server_public_key: hex::encode(state.server_identity.public_key()),
        server_iroh_endpoint_id: hex::encode(state.server_endpoint.id().as_bytes()),
        capability_api_required: false,
        approval_api_required: false,
    })
}

#[derive(Deserialize)]
struct ExchangeRequest {
    experiment: String,
    message: Option<String>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Experiment {
    PublicIdentity,
    SignedMessage,
    TamperedMessage,
}

impl Experiment {
    fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "public-identity" => Ok(Self::PublicIdentity),
            "signed-message" => Ok(Self::SignedMessage),
            "tampered-message" => Ok(Self::TamperedMessage),
            _ => Err(ApiError::bad_request("unknown closed demo experiment")),
        }
    }
}

#[derive(Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct ExchangeResponse {
    schema: &'static str,
    experiment: Experiment,
    code: &'static str,
    detail: &'static str,
    client: IdentityView,
    server: IdentityView,
    transport: TransportView,
    message: Option<String>,
    signature: Option<String>,
    signature_verified: bool,
    authorization_evaluated: bool,
    capability_api_required: bool,
    approval_api_required: bool,
    policy_loaded: bool,
    lifecycle_state_created: bool,
}

#[derive(Serialize)]
struct IdentityView {
    principal: String,
    public_key: String,
}

#[derive(Serialize)]
struct TransportView {
    family: &'static str,
    alpn: &'static str,
    path: &'static str,
    client_endpoint_id: String,
    server_endpoint_id: String,
    server_observed_client_endpoint_id: String,
    client_observed_server_endpoint_id: String,
}

async fn exchange(
    State(state): State<AppState>,
    Json(request): Json<ExchangeRequest>,
) -> Result<Json<ExchangeResponse>, ApiError> {
    let experiment = Experiment::parse(&request.experiment)?;
    let message = request
        .message
        .unwrap_or_else(|| "hello from an Ed25519 identity".into());
    validate_demo_message(&message)?;

    let client_signing = Arc::new(ephemeral_signing_key().map_err(|_| ApiError::internal())?);
    let client_identity = PublicIdentity::from_ed25519(client_signing.verifying_key().to_bytes())
        .map_err(|_| ApiError::internal())?;
    let outbound = packet_for_experiment(experiment, &client_signing, &client_identity, &message)?;
    let client_endpoint = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|_| ApiError::service_unavailable())?;
    let client_endpoint_id = *client_endpoint.id().as_bytes();
    let server_endpoint_id = *state.server_endpoint.id().as_bytes();
    let server_endpoint = state.server_endpoint.clone();
    let server_signing = Arc::clone(&state.server_signing);
    let server_identity = state.server_identity.clone();
    let config = IrohIdentityConfig::default();

    let server_task = tokio::spawn(async move {
        let mut channel = IrohIdentityServer::accept(&server_endpoint, config).await?;
        let received = channel.receive().await?;
        let signature_verified = verify_packet(received.packet());
        let response = response_packet(&server_signing, &server_identity, signature_verified)?;
        channel.respond(&response).await?;
        Ok::<_, IdentityError>((received, signature_verified))
    });

    let client = IrohIdentityClient::connect(&client_endpoint, state.server_target.clone(), config)
        .await
        .map_err(ApiError::identity)?;
    let path = client.path_observation();
    let response = client
        .exchange(&outbound)
        .await
        .map_err(ApiError::identity)?;
    let (server_received, signature_verified) = server_task
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::identity)?;
    let response_identity = response.packet().identity();
    let exchanged_identity = server_received.packet().identity();
    let (code, detail) = result_copy(experiment, signature_verified);
    let signature = match server_received.packet() {
        IdentityPacket::PublicIdentity(_) => None,
        IdentityPacket::SignedMessage(signed) => Some(hex::encode(signed.signature())),
    };
    client_endpoint.close().await;

    Ok(Json(ExchangeResponse {
        schema: API_SCHEMA,
        experiment,
        code,
        detail,
        client: identity_view(exchanged_identity),
        server: identity_view(response_identity),
        transport: TransportView {
            family: "iroh",
            alpn: "/auths/identity/1",
            path: path_name(path),
            client_endpoint_id: hex::encode(client_endpoint_id),
            server_endpoint_id: hex::encode(server_endpoint_id),
            server_observed_client_endpoint_id: hex::encode(server_received.peer_endpoint_id()),
            client_observed_server_endpoint_id: hex::encode(response.peer_endpoint_id()),
        },
        message: (!matches!(experiment, Experiment::PublicIdentity)).then_some(message),
        signature,
        signature_verified,
        authorization_evaluated: false,
        capability_api_required: false,
        approval_api_required: false,
        policy_loaded: false,
        lifecycle_state_created: false,
    }))
}

fn packet_for_experiment(
    experiment: Experiment,
    signing: &SigningKey,
    identity: &PublicIdentity,
    message: &str,
) -> Result<IdentityPacket, ApiError> {
    if matches!(experiment, Experiment::PublicIdentity) {
        return Ok(IdentityPacket::PublicIdentity(identity.clone()));
    }
    let signed_message = if matches!(experiment, Experiment::TamperedMessage) {
        let mut original = message.as_bytes().to_vec();
        original.extend_from_slice(b"\0before-tampering");
        let preimage = SignedIdentityMessage::signing_preimage(identity, &original)
            .map_err(ApiError::identity)?;
        SignedIdentityMessage::new(
            identity.clone(),
            message.as_bytes().to_vec(),
            signing.sign(&preimage).to_bytes(),
        )
    } else {
        let preimage = SignedIdentityMessage::signing_preimage(identity, message.as_bytes())
            .map_err(ApiError::identity)?;
        SignedIdentityMessage::new(
            identity.clone(),
            message.as_bytes().to_vec(),
            signing.sign(&preimage).to_bytes(),
        )
    }
    .map_err(ApiError::identity)?;
    Ok(IdentityPacket::SignedMessage(signed_message))
}

fn response_packet(
    signing: &SigningKey,
    identity: &PublicIdentity,
    request_verified: bool,
) -> Result<IdentityPacket, IdentityError> {
    let message = if request_verified {
        b"server verified the signed identity message".as_slice()
    } else {
        b"server received a public or unverified identity".as_slice()
    };
    let preimage = SignedIdentityMessage::signing_preimage(identity, message)?;
    Ok(IdentityPacket::SignedMessage(SignedIdentityMessage::new(
        identity.clone(),
        message.to_vec(),
        signing.sign(&preimage).to_bytes(),
    )?))
}

fn verify_packet(packet: &IdentityPacket) -> bool {
    match packet {
        IdentityPacket::PublicIdentity(_) => false,
        IdentityPacket::SignedMessage(message) => message.verify().is_ok(),
    }
}

fn result_copy(experiment: Experiment, verified: bool) -> (&'static str, &'static str) {
    match (experiment, verified) {
        (Experiment::PublicIdentity, _) => (
            "identity-exchanged",
            "Both peers exchanged canonical public identities over a real Iroh connection.",
        ),
        (Experiment::SignedMessage, true) => (
            "signature-verified",
            "The exact application message was verified against the exchanged Ed25519 identity.",
        ),
        (Experiment::TamperedMessage, false) => (
            "signature-invalid",
            "The message bytes changed after signing, so verification failed closed.",
        ),
        _ => (
            "unexpected-verification-result",
            "The experiment did not produce its expected verification result.",
        ),
    }
}

fn identity_view(identity: &PublicIdentity) -> IdentityView {
    IdentityView {
        principal: identity.principal().as_str().into(),
        public_key: hex::encode(identity.public_key()),
    }
}

fn validate_demo_message(message: &str) -> Result<(), ApiError> {
    if message.is_empty()
        || message.len() > MAX_DEMO_MESSAGE_BYTES
        || message.chars().any(char::is_control)
    {
        return Err(ApiError::bad_request(
            "message must be 1-256 display-safe bytes",
        ));
    }
    Ok(())
}

fn ephemeral_signing_key() -> Result<SigningKey, StartupError> {
    let mut seed = [0_u8; 32];
    getrandom::fill(&mut seed).map_err(|_| StartupError)?;
    Ok(SigningKey::from_bytes(&seed))
}

fn direct_target(endpoint: &Endpoint) -> Option<EndpointAddr> {
    let direct = endpoint.addr().ip_addrs().next().copied()?;
    Some(EndpointAddr::new(endpoint.id()).with_ip_addr(direct))
}

const fn path_name(path: PathObservation) -> &'static str {
    match path {
        PathObservation::Direct => "direct",
        PathObservation::Relayed => "relayed",
        PathObservation::MixedOrUnknown => "mixed-or-unknown",
    }
}

/// Startup failure deliberately omits sensitive operational detail.
#[derive(Clone, Copy, Debug)]
pub struct StartupError;

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("identity demo startup failed")
    }
}

impl std::error::Error for StartupError {}

struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
}

impl ApiError {
    const fn bad_request(detail: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad-request",
            detail,
        }
    }

    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal-error",
            detail: "the native identity exchange could not complete",
        }
    }

    const fn service_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "iroh-unavailable",
            detail: "the local Iroh endpoint is unavailable",
        }
    }

    const fn identity(_error: IdentityError) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "identity-exchange-failed",
            detail: "the bounded identity exchange failed",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
                "code": self.code,
                "detail": self.detail,
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
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn public_and_signed_identity_paths_use_real_iroh_without_authorization() {
        let router = app(AppConfig::test()).await.unwrap();
        for (experiment, expected_code, verified) in [
            ("public-identity", "identity-exchanged", false),
            ("signed-message", "signature-verified", true),
            ("tampered-message", "signature-invalid", false),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::post("/api/v1/exchanges")
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(
                            json!({"experiment": experiment, "message": "tampered bytes"})
                                .to_string(),
                        ))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 64 * 1024).await.unwrap())
                    .unwrap();
            assert_eq!(body["code"], expected_code);
            assert_eq!(body["signature_verified"], verified);
            assert_eq!(body["authorization_evaluated"], false);
            assert_eq!(body["capability_api_required"], false);
            assert_eq!(body["approval_api_required"], false);
            assert_eq!(
                body["transport"]["server_endpoint_id"],
                body["transport"]["client_observed_server_endpoint_id"]
            );
            assert_eq!(
                body["transport"]["client_endpoint_id"],
                body["transport"]["server_observed_client_endpoint_id"]
            );
        }
    }

    #[tokio::test]
    async fn browser_shell_exposes_the_layer_boundary() {
        let response = app(AppConfig::test())
            .await
            .unwrap()
            .oneshot(Request::get("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("No grants. No approvals."));
        assert!(html.contains("data-experiment=\"public-identity\""));
    }
}
