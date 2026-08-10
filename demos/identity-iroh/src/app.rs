use std::{env, net::SocketAddr, sync::Arc, time::Duration};

use auths_byte_channel::BoundedByteChannel;
use auths_identity::{
    IDENTITY_APPLICATION_PROTOCOL_V1, IdentityError, IdentityPacket, MAX_IDENTITY_PACKET_BYTES,
    PublicIdentity, SignedIdentityMessage, ValidatedIdentity,
};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_iroh::{IrohChannel, IrohConfig, IrohError, PathObservation, StreamInitiator};
use auths_signature_ed25519::{ED25519_V1, Ed25519Verifier};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{
        HeaderValue, Method, StatusCode,
        header::{CACHE_CONTROL, CONTENT_TYPE},
    },
    response::{IntoResponse, Response},
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
    server_identity: ValidatedIdentity,
    transport_config: IrohConfig,
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
    let server_identity = RawKeyIdentityMethod::identity(
        ED25519_V1,
        server_signing.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| StartupError)?;
    let transport_config = IrohConfig::new(
        Arc::<[u8]>::from(IDENTITY_APPLICATION_PROTOCOL_V1.as_bytes()),
        MAX_IDENTITY_PACKET_BYTES,
        Duration::from_secs(10),
        StreamInitiator::ConnectingEndpoint,
    )
    .map_err(|_| StartupError)?;
    let server_endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![IDENTITY_APPLICATION_PROTOCOL_V1.as_bytes().to_vec()])
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
        transport_config,
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

async fn index() -> Response {
    static_asset(
        include_str!("../web/index.html"),
        "text/html; charset=utf-8",
    )
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
    (
        [
            (CONTENT_TYPE, content_type),
            (CACHE_CONTROL, "no-store, max-age=0"),
        ],
        content,
    )
        .into_response()
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
    server_identity_method: String,
    server_signature_suite: String,
    server_public_key: String,
    server_iroh_endpoint_id: String,
    capability_api_required: bool,
    approval_api_required: bool,
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        schema: API_SCHEMA,
        server_principal: state.server_identity.identity_id().into(),
        server_identity_method: state.server_identity.method_id().into(),
        server_signature_suite: state.server_identity.suite_id().into(),
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
    method: String,
    suite: String,
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
    let client_identity = RawKeyIdentityMethod::identity(
        ED25519_V1,
        client_signing.verifying_key().to_bytes().to_vec(),
    )
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
    let config = state.transport_config.clone();
    let server_config = config.clone();

    let server_task = tokio::spawn(async move {
        let mut channel = IrohChannel::accept(&server_endpoint, server_config)
            .await
            .map_err(ChannelExchangeError::Transport)?;
        let peer_endpoint_id = *channel.peer_endpoint_id();
        let (packet, signature_verified) =
            serve_identity_channel(&mut channel, &server_signing, &server_identity).await?;
        Ok::<_, ChannelExchangeError<IrohError>>((peer_endpoint_id, packet, signature_verified))
    });

    let mut client = IrohChannel::connect(&client_endpoint, state.server_target.clone(), config)
        .await
        .map_err(ApiError::transport)?;
    let path = client.path_observation();
    let client_observed_server_endpoint_id = *client.peer_endpoint_id();
    let response_packet = request_identity_channel(&mut client, &outbound)
        .await
        .map_err(ApiError::exchange)?;
    let (server_observed_client_endpoint_id, server_packet, signature_verified) = server_task
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::exchange)?;
    let response_identity = response_packet.identity();
    let exchanged_identity = server_packet.identity();
    let (code, detail) = result_copy(experiment, signature_verified);
    let signature = match &server_packet {
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
            alpn: IDENTITY_APPLICATION_PROTOCOL_V1,
            path: path_name(path),
            client_endpoint_id: hex::encode(client_endpoint_id),
            server_endpoint_id: hex::encode(server_endpoint_id),
            server_observed_client_endpoint_id: hex::encode(server_observed_client_endpoint_id),
            client_observed_server_endpoint_id: hex::encode(client_observed_server_endpoint_id),
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

async fn serve_identity_channel<C>(
    channel: &mut C,
    signing: &SigningKey,
    identity: &ValidatedIdentity,
) -> Result<(IdentityPacket, bool), ChannelExchangeError<C::Error>>
where
    C: BoundedByteChannel + Send,
{
    let received = channel
        .receive_frame()
        .await
        .map_err(ChannelExchangeError::Transport)?;
    let packet = IdentityPacket::decode(&received).map_err(ChannelExchangeError::Identity)?;
    let signature_verified = verify_packet(&packet).map_err(ChannelExchangeError::Identity)?;
    let response = response_packet(signing, identity, signature_verified)
        .map_err(ChannelExchangeError::Identity)?;
    channel
        .send_frame(&response.encode().map_err(ChannelExchangeError::Identity)?)
        .await
        .map_err(ChannelExchangeError::Transport)?;
    channel
        .finish_send()
        .await
        .map_err(ChannelExchangeError::Transport)?;
    Ok((packet, signature_verified))
}

async fn request_identity_channel<C>(
    channel: &mut C,
    outbound: &IdentityPacket,
) -> Result<IdentityPacket, ChannelExchangeError<C::Error>>
where
    C: BoundedByteChannel + Send,
{
    channel
        .send_frame(&outbound.encode().map_err(ChannelExchangeError::Identity)?)
        .await
        .map_err(ChannelExchangeError::Transport)?;
    channel
        .finish_send()
        .await
        .map_err(ChannelExchangeError::Transport)?;
    let response = channel
        .receive_frame()
        .await
        .map_err(ChannelExchangeError::Transport)?;
    let packet = IdentityPacket::decode(&response).map_err(ChannelExchangeError::Identity)?;
    if !verify_packet(&packet).map_err(ChannelExchangeError::Identity)? {
        return Err(ChannelExchangeError::Identity(
            IdentityError::VerificationFailed,
        ));
    }
    Ok(packet)
}

fn packet_for_experiment(
    experiment: Experiment,
    signing: &SigningKey,
    identity: &ValidatedIdentity,
    message: &str,
) -> Result<IdentityPacket, ApiError> {
    if matches!(experiment, Experiment::PublicIdentity) {
        return Ok(IdentityPacket::PublicIdentity(
            identity.as_public_identity().clone(),
        ));
    }
    let signed_message = if matches!(experiment, Experiment::TamperedMessage) {
        let mut original = message.as_bytes().to_vec();
        original.extend_from_slice(b"\0before-tampering");
        let preimage =
            SignedIdentityMessage::signing_preimage(identity.as_public_identity(), &original)
                .map_err(ApiError::identity)?;
        SignedIdentityMessage::new(
            identity.as_public_identity().clone(),
            message.as_bytes().to_vec(),
            signing.sign(&preimage).to_bytes().to_vec(),
        )
    } else {
        let preimage = SignedIdentityMessage::signing_preimage(
            identity.as_public_identity(),
            message.as_bytes(),
        )
        .map_err(ApiError::identity)?;
        SignedIdentityMessage::new(
            identity.as_public_identity().clone(),
            message.as_bytes().to_vec(),
            signing.sign(&preimage).to_bytes().to_vec(),
        )
    }
    .map_err(ApiError::identity)?;
    Ok(IdentityPacket::SignedMessage(signed_message))
}

fn response_packet(
    signing: &SigningKey,
    identity: &ValidatedIdentity,
    request_verified: bool,
) -> Result<IdentityPacket, IdentityError> {
    let message = if request_verified {
        b"server verified the signed identity message".as_slice()
    } else {
        b"server received a public or unverified identity".as_slice()
    };
    let preimage = SignedIdentityMessage::signing_preimage(identity.as_public_identity(), message)?;
    Ok(IdentityPacket::SignedMessage(SignedIdentityMessage::new(
        identity.as_public_identity().clone(),
        message.to_vec(),
        signing.sign(&preimage).to_bytes().to_vec(),
    )?))
}

fn verify_packet(packet: &IdentityPacket) -> Result<bool, IdentityError> {
    match packet {
        IdentityPacket::PublicIdentity(identity) => {
            identity.validate(&RawKeyIdentityMethod)?;
            Ok(false)
        }
        IdentityPacket::SignedMessage(message) => {
            match message.verify(&RawKeyIdentityMethod, &Ed25519Verifier) {
                Ok(_) => Ok(true),
                Err(IdentityError::VerificationFailed) => Ok(false),
                Err(error) => Err(error),
            }
        }
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
        principal: identity.identity_id().into(),
        method: identity.method_id().into(),
        suite: identity.suite_id().into(),
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

#[derive(Debug)]
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

    const fn transport(_error: IrohError) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "iroh-exchange-failed",
            detail: "the bounded Iroh byte exchange failed",
        }
    }

    const fn exchange(error: ChannelExchangeError<IrohError>) -> Self {
        match error {
            ChannelExchangeError::Identity(error) => Self::identity(error),
            ChannelExchangeError::Transport(error) => Self::transport(error),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ChannelExchangeError<E> {
    Identity(IdentityError),
    Transport(E),
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
    use auths_byte_channel::{ChannelLimits, PeerObservation};
    use auths_byte_channel_memory::MemoryByteChannel;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use serde_json::Value;
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn identity_protocol_is_unchanged_over_the_memory_adapter() {
        let limits = ChannelLimits::new(MAX_IDENTITY_PACKET_BYTES, Duration::from_secs(1)).unwrap();
        let (mut client, mut server) = MemoryByteChannel::pair(
            limits,
            PeerObservation::Unauthenticated,
            PeerObservation::Unauthenticated,
        );
        let client_signing = SigningKey::from_bytes(&[21; 32]);
        let client_identity = RawKeyIdentityMethod::identity(
            ED25519_V1,
            client_signing.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let outbound = packet_for_experiment(
            Experiment::SignedMessage,
            &client_signing,
            &client_identity,
            "same identity protocol",
        )
        .unwrap();
        let server_signing = SigningKey::from_bytes(&[22; 32]);
        let server_identity = RawKeyIdentityMethod::identity(
            ED25519_V1,
            server_signing.verifying_key().to_bytes().to_vec(),
        )
        .unwrap();
        let server_task = tokio::spawn(async move {
            serve_identity_channel(&mut server, &server_signing, &server_identity).await
        });

        let response = request_identity_channel(&mut client, &outbound)
            .await
            .unwrap();
        let (received, verified) = server_task.await.unwrap().unwrap();
        assert_eq!(received, outbound);
        assert!(verified);
        assert!(verify_packet(&response).unwrap());
    }

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
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("No grants. No approvals."));
        assert!(html.contains("data-experiment=\"public-identity\""));
        assert!(html.contains("<script defer src=\"./app.js?v=2\"></script>"));
    }

    #[tokio::test]
    async fn browser_script_is_executable_javascript_and_never_cached() {
        let response = app(AppConfig::test())
            .await
            .unwrap()
            .oneshot(Request::get("/app.js?v=2").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            response.headers().get(CACHE_CONTROL).unwrap(),
            "no-store, max-age=0"
        );
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let javascript = std::str::from_utf8(&body).unwrap();
        assert!(javascript.contains("connect();"));
        assert!(javascript.contains("button.addEventListener(\"click\""));
    }

    #[test]
    fn structurally_canonical_public_identity_is_not_implicitly_trusted() {
        let forged = PublicIdentity::new(
            auths_identity_raw_key::RAW_KEY_V2,
            "key:sha256-v2:forged",
            ED25519_V1,
            vec![7; 32],
        )
        .unwrap();
        let packet =
            IdentityPacket::decode(&IdentityPacket::PublicIdentity(forged).encode().unwrap())
                .unwrap();
        assert_eq!(verify_packet(&packet), Err(IdentityError::InvalidIdentity));
    }
}
