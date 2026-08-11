use std::{
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use auths_iroh::{
    Endpoint, EndpointAddr, IrohChannel, IrohConfig, PathObservation, StreamInitiator,
};
use auths_raw_key::{RawKeyDescriptor, RawKeyType};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode},
    response::IntoResponse,
    routing::{get, post},
};
use ed25519_dalek::{Signer as _, SigningKey};
use iroh::{RelayMode, endpoint::presets};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tower_http::cors::{Any, CorsLayer};

const SCHEMA: &str = "auths-incident-demo/1";
const ALPN: &[u8] = b"/auths-incident-demo/edge-operation/1";
const MAX_ENVELOPE: usize = 16 * 1024;

#[derive(Clone)]
struct AppState {
    store: Arc<Mutex<EdgeState>>,
    path: PathBuf,
    cert_fingerprint: Arc<str>,
    endpoint: Endpoint,
    target: EndpointAddr,
    transport: IrohConfig,
}

#[derive(Clone, Serialize, Deserialize)]
struct EdgeState {
    cache_purged: bool,
    approvals: u64,
    provider_calls: u64,
    key_sequence: u64,
    current_seed: String,
    previous_principal: Option<String>,
    timeline: Vec<TimelineEvent>,
}

#[derive(Clone, Serialize, Deserialize)]
struct TimelineEvent {
    at: u64,
    event: String,
    detail: String,
}

#[derive(Deserialize)]
struct ApprovalInput {
    #[serde(rename = "requestId")]
    request_id: String,
    #[serde(rename = "transactionDigest")]
    transaction_digest: String,
    #[serde(rename = "planCommitment")]
    plan_commitment: String,
}

#[derive(Deserialize)]
struct CacheInput {
    #[serde(rename = "incidentId")]
    incident_id: String,
    region: String,
    operation: String,
}

#[derive(Deserialize)]
struct ExchangeInput {
    #[serde(rename = "envelopeHex")]
    envelope_hex: String,
}

#[derive(Serialize)]
struct ErrorBody {
    schema: &'static str,
    code: &'static str,
}

#[tokio::main]
async fn main() {
    if serve().await.is_err() {
        eprintln!("auths-incident-demo EdgeShield service terminated");
        std::process::exit(1);
    }
}

async fn serve() -> Result<(), ()> {
    let port = env::var("PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(7102);
    let path = PathBuf::from(
        env::var("EDGESHIELD_STATE_PATH")
            .unwrap_or_else(|_| "/tmp/auths-incident-demo/edgeshield.json".to_owned()),
    );
    let cert_fingerprint = env::var("EDGESHIELD_CLIENT_CERT_FINGERPRINT")
        .unwrap_or_else(|_| "local-client-certificate-fingerprint".to_owned());
    let store = load_or_create(&path).map_err(|_| ())?;
    let transport = IrohConfig::new(
        Arc::<[u8]>::from(ALPN),
        MAX_ENVELOPE,
        Duration::from_secs(10),
        StreamInitiator::ConnectingEndpoint,
    )
    .map_err(|_| ())?;
    let endpoint = Endpoint::builder(presets::N0)
        .alpns(vec![ALPN.to_vec()])
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|_| ())?;
    let direct = endpoint.addr().ip_addrs().next().copied().ok_or(())?;
    let target = EndpointAddr::new(endpoint.id()).with_ip_addr(direct);
    let state = AppState {
        store: Arc::new(Mutex::new(store)),
        path,
        cert_fingerprint: Arc::from(cert_fingerprint),
        endpoint,
        target,
        transport,
    };
    let router = Router::new()
        .route("/healthz", get(health))
        .route("/api/actors", get(actors))
        .route(
            "/api/certificate/authenticate",
            post(certificate_authenticate),
        )
        .route("/api/approve", post(approve))
        .route("/api/cache/purge", post(cache_purge))
        .route("/api/iroh/exchange", post(iroh_exchange))
        .route("/api/key/rotate", post(rotate))
        .route("/api/reset", post(reset))
        .layer(DefaultBodyLimit::max(MAX_ENVELOPE))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST])
                .allow_headers(Any),
        )
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .map_err(|_| ())?;
    println!("auths-incident-demo EdgeShield listening on {port}");
    axum::serve(listener, router).await.map_err(|_| ())
}

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok", "service": "edgeshield", "schema": SCHEMA }))
}

async fn actors(State(state): State<AppState>) -> Json<serde_json::Value> {
    let store = state.store.lock().await;
    let current =
        principal_for_seed(&store.current_seed).unwrap_or_else(|_| "unavailable".to_owned());
    Json(serde_json::json!({
        "actors": [
            {
                "id": "edgeshield-oncall",
                "name": "Rina Okafor",
                "role": "EdgeShield on-call engineer",
                "organization": "EdgeShield",
                "authentication": "client certificate challenge",
                "principal": current,
                "signingSuite": "ed25519-v1",
                "lifecycle": "active",
                "authority": "approve exact Northstar eu-west-2 cache operation"
            },
            {
                "id": "edgeshield-remediation-agent",
                "name": "EdgeShield Remediator",
                "role": "Remediation agent",
                "organization": "EdgeShield",
                "authentication": "distinct agent principal",
                "principal": "key:sha256:edgeshield-remediation-demo",
                "signingSuite": "ed25519-v1",
                "lifecycle": "active",
                "authority": "two exact operations in eu-west-2 for ten minutes; two uses"
            },
            {
                "id": "compromised-agent",
                "name": "Untrusted Runner",
                "role": "Attack-lab agent",
                "organization": "untrusted",
                "authentication": "untrusted agent principal",
                "principal": "key:sha256:compromised-agent-demo",
                "signingSuite": "ed25519-v1",
                "lifecycle": "compromised",
                "authority": "none"
            }
        ],
        "rotation": {
            "sequence": store.key_sequence,
            "previous": store.previous_principal,
            "current": current
        }
    }))
}

async fn certificate_authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !certificate_ok(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "client-certificate-required");
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": SCHEMA,
            "authenticated": true,
            "subject": "edgeshield-oncall",
            "method": "client-certificate-fingerprint"
        })),
    )
}

async fn approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ApprovalInput>,
) -> impl IntoResponse {
    if !certificate_ok(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "client-certificate-required");
    }
    if input.request_id.is_empty()
        || input.transaction_digest.len() != 64
        || input.plan_commitment.len() != 64
    {
        return error(StatusCode::BAD_REQUEST, "invalid-approval-request");
    }
    let mut store = state.store.lock().await;
    let Ok(seed) = hex::decode(&store.current_seed).and_then(|value| {
        <[u8; 32]>::try_from(value).map_err(|_| hex::FromHexError::InvalidStringLength)
    }) else {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "signing-key-unavailable");
    };
    let Ok(digest) = hex::decode(&input.transaction_digest) else {
        return error(StatusCode::BAD_REQUEST, "invalid-approval-request");
    };
    let signing = SigningKey::from_bytes(&seed);
    let signature = signing.sign(&digest);
    let principal =
        principal_for_seed(&store.current_seed).unwrap_or_else(|_| "unavailable".to_owned());
    store.approvals = store.approvals.saturating_add(1);
    push_event(
        &mut store,
        "approval",
        "EdgeShield on-call approved the exact plan commitment",
    );
    let _ = persist(&state.path, &store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": SCHEMA,
            "decision": "approved",
            "actor": "edgeshield-oncall",
            "requestId": input.request_id,
            "transactionDigest": input.transaction_digest,
            "principal": principal,
            "suite": "ed25519-v1",
            "publicKey": hex::encode(signing.verifying_key().to_bytes()),
            "signature": hex::encode(signature.to_bytes())
        })),
    )
}

async fn cache_purge(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CacheInput>,
) -> impl IntoResponse {
    if !certificate_ok(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "client-certificate-required");
    }
    if input.incident_id != "INC-2026-0811"
        || input.region != "eu-west-2"
        || input.operation != "execute"
    {
        return error(StatusCode::FORBIDDEN, "closed-operation-mismatch");
    }
    let mut store = state.store.lock().await;
    store.provider_calls = store.provider_calls.saturating_add(1);
    if store.cache_purged {
        return (
            StatusCode::CONFLICT,
            Json(
                serde_json::json!({ "schema": SCHEMA, "code": "already-purged", "providerCalls": store.provider_calls }),
            ),
        );
    }
    store.cache_purged = true;
    push_event(
        &mut store,
        "effect",
        "Northstar eu-west-2 cache generation purged",
    );
    let _ = persist(&state.path, &store);
    (
        StatusCode::OK,
        Json(
            serde_json::json!({ "schema": SCHEMA, "outcome": "executed", "generation": 992, "providerCalls": store.provider_calls, "observed": true }),
        ),
    )
}

async fn iroh_exchange(
    State(state): State<AppState>,
    Json(input): Json<ExchangeInput>,
) -> impl IntoResponse {
    let Ok(envelope) = hex::decode(&input.envelope_hex) else {
        return error(StatusCode::BAD_REQUEST, "iroh-envelope-outside-bounds");
    };
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE {
        return error(StatusCode::BAD_REQUEST, "iroh-envelope-outside-bounds");
    }
    match exchange_bytes(&state, &envelope).await {
        Ok((payload, client_peer, server_peer, path)) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "schema": SCHEMA,
                "delivered": true,
                "authorizationEvaluated": false,
                "payloadSha256": hex::encode(Sha256::digest(&payload)),
                "clientObservedPeer": client_peer,
                "serverObservedPeer": server_peer,
                "path": path,
                "alpn": String::from_utf8_lossy(ALPN)
            })),
        ),
        Err(()) => error(StatusCode::SERVICE_UNAVAILABLE, "iroh-exchange-failed"),
    }
}

async fn rotate(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !certificate_ok(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "client-certificate-required");
    }
    let mut store = state.store.lock().await;
    let previous = principal_for_seed(&store.current_seed).ok();
    let mut seed = [0_u8; 32];
    if getrandom::fill(&mut seed).is_err() {
        return error(StatusCode::INTERNAL_SERVER_ERROR, "entropy-unavailable");
    }
    store.previous_principal = previous.clone();
    store.current_seed = hex::encode(seed);
    store.key_sequence = store.key_sequence.saturating_add(1);
    let current =
        principal_for_seed(&store.current_seed).unwrap_or_else(|_| "unavailable".to_owned());
    push_event(
        &mut store,
        "rotation",
        "EdgeShield Ed25519 incident key rotated",
    );
    let _ = persist(&state.path, &store);
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "schema": SCHEMA,
            "previous": { "principal": previous, "state": "superseded" },
            "current": { "principal": current, "state": "active" },
            "sequence": store.key_sequence
        })),
    )
}

async fn reset(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if !certificate_ok(&state, &headers) {
        return error(StatusCode::UNAUTHORIZED, "client-certificate-required");
    }
    let mut store = state.store.lock().await;
    let seed = store.current_seed.clone();
    *store = EdgeState::new(seed);
    let _ = persist(&state.path, &store);
    (
        StatusCode::OK,
        Json(serde_json::json!({ "schema": SCHEMA, "reset": true })),
    )
}

async fn exchange_bytes(
    state: &AppState,
    payload: &[u8],
) -> Result<(Vec<u8>, String, String, &'static str), ()> {
    let client = Endpoint::builder(presets::N0)
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .map_err(|_| ())?;
    let server_endpoint = state.endpoint.clone();
    let server_config = state.transport.clone();
    let server = tokio::spawn(async move {
        let mut channel = IrohChannel::accept(&server_endpoint, server_config)
            .await
            .map_err(|_| ())?;
        let peer = hex::encode(channel.peer_endpoint_id());
        let received = channel.receive().await.map_err(|_| ())?;
        channel.send(received.payload()).await.map_err(|_| ())?;
        channel.finish_send_and_wait().await.map_err(|_| ())?;
        Ok::<_, ()>((received.into_payload(), peer))
    });
    let mut channel = IrohChannel::connect(&client, state.target.clone(), state.transport.clone())
        .await
        .map_err(|_| ())?;
    let path = match channel.path_observation() {
        PathObservation::Direct => "direct",
        PathObservation::Relayed => "relayed",
        PathObservation::MixedOrUnknown => "mixed-or-unknown",
    };
    let client_peer = hex::encode(channel.peer_endpoint_id());
    channel.send(payload).await.map_err(|_| ())?;
    channel.finish_send().map_err(|_| ())?;
    let echoed = channel.receive().await.map_err(|_| ())?.into_payload();
    let (received, server_peer) = server.await.map_err(|_| ())??;
    client.close().await;
    if received != payload || echoed != payload {
        return Err(());
    }
    Ok((received, client_peer, server_peer, path))
}

impl EdgeState {
    fn generate() -> Result<Self, ()> {
        let mut seed = [0_u8; 32];
        getrandom::fill(&mut seed).map_err(|_| ())?;
        Ok(Self::new(hex::encode(seed)))
    }

    fn new(seed: String) -> Self {
        Self {
            cache_purged: false,
            approvals: 0,
            provider_calls: 0,
            key_sequence: 1,
            current_seed: seed,
            previous_principal: None,
            timeline: Vec::new(),
        }
    }
}

fn load_or_create(path: &Path) -> Result<EdgeState, ()> {
    if path.exists() {
        let bytes = fs::read(path).map_err(|_| ())?;
        return serde_json::from_slice(&bytes).map_err(|_| ());
    }
    let state = EdgeState::generate()?;
    persist(path, &state)?;
    Ok(state)
}

fn persist(path: &Path, state: &EdgeState) -> Result<(), ()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| ())?;
    }
    let bytes = serde_json::to_vec_pretty(state).map_err(|_| ())?;
    fs::write(path, bytes).map_err(|_| ())
}

fn principal_for_seed(seed: &str) -> Result<String, ()> {
    let bytes: [u8; 32] = hex::decode(seed)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    let signing = SigningKey::from_bytes(&bytes);
    RawKeyDescriptor::new(
        RawKeyType::Ed25519,
        signing.verifying_key().to_bytes().to_vec(),
    )
    .map_err(|_| ())?
    .principal()
    .map(|value| value.to_string())
    .map_err(|_| ())
}

fn certificate_ok(state: &AppState, headers: &HeaderMap) -> bool {
    headers
        .get("x-auths-client-cert-sha256")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == state.cert_fingerprint.as_ref())
}

fn push_event(state: &mut EdgeState, event: &str, detail: &str) {
    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs());
    state.timeline.push(TimelineEvent {
        at,
        event: event.to_owned(),
        detail: detail.to_owned(),
    });
}

fn error(status: StatusCode, code: &'static str) -> (StatusCode, Json<serde_json::Value>) {
    let body = ErrorBody {
        schema: SCHEMA,
        code,
    };
    (
        status,
        Json(
            serde_json::to_value(body)
                .unwrap_or_else(|_| serde_json::json!({ "code": "serialization-failed" })),
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn real_iroh_delivery_is_semantics_free() {
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![ALPN.to_vec()])
            .relay_mode(RelayMode::Disabled)
            .bind()
            .await
            .unwrap();
        let direct = endpoint.addr().ip_addrs().next().copied().unwrap();
        let state = AppState {
            store: Arc::new(Mutex::new(EdgeState::generate().unwrap())),
            path: PathBuf::from("/tmp/auths-incident-demo-test-unused"),
            cert_fingerprint: Arc::from("test"),
            target: EndpointAddr::new(endpoint.id()).with_ip_addr(direct),
            endpoint,
            transport: IrohConfig::new(
                Arc::<[u8]>::from(ALPN),
                MAX_ENVELOPE,
                Duration::from_secs(5),
                StreamInitiator::ConnectingEndpoint,
            )
            .unwrap(),
        };
        let unauthorized = br#"{"authorized":false,"operation":"cache-purge"}"#;
        let (received, _, _, _) = exchange_bytes(&state, unauthorized).await.unwrap();
        assert_eq!(received, unauthorized);
        assert!(!state.store.lock().await.cache_purged);
    }
}
