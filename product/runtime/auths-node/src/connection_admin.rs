//! Privileged, peer-authenticated provider-connection administration.

#![forbid(unsafe_code)]
// The administration boundary intentionally keeps the bounded protocol
// handlers together so their peer-authentication and audit ordering remain
// reviewable as one unit.
#![allow(
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::too_many_lines
)]

use crate::{generated::profile_routes::RegisteredProvider, local_agent::PeerCredentials};
use auths_config::AgentConfig;
use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionProfile,
    ConnectionRecord, ConnectionState, PersistentCredentialStore, ProviderKind, SemanticId,
};
use auths_production_client::LOCAL_AGENT_CONTENT_TYPE;
use auths_stores::{PersistentConnectionStore, PersistentConnectionStoreError};
use axum::{
    Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, Extension, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use minicbor::{Decoder, Encoder};
use std::{
    collections::{BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::Write as _,
    num::NonZeroU64,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UnixListener;

const ADMIN_VERSION: u8 = 1;
const MAX_ADMIN_REQUEST_BYTES: usize = 131_072;
const MAX_ADMIN_RESPONSE_BYTES: usize = 16_777_216;
const MAX_PENDING: usize = 256;
const PENDING_LIFETIME: Duration = Duration::from_mins(5);
const MAX_AUDIT_BYTES: u64 = 268_435_456;

/// UIDs/GIDs admitted to the separate privileged administration listener.
#[derive(Clone, Debug)]
pub struct AdminPeerPolicy {
    allowed_uids: BTreeSet<u32>,
    allowed_gids: BTreeSet<u32>,
}

impl AdminPeerPolicy {
    /// Builds a nonempty exact operator policy.
    pub fn new(
        allowed_uids: impl IntoIterator<Item = u32>,
        allowed_gids: impl IntoIterator<Item = u32>,
    ) -> Result<Self, ConnectionAdminError> {
        let allowed_uids = allowed_uids.into_iter().collect::<BTreeSet<_>>();
        let allowed_gids = allowed_gids.into_iter().collect::<BTreeSet<_>>();
        Ok(Self {
            allowed_uids,
            allowed_gids,
        })
    }

    fn permits(&self, peer: PeerCredentials) -> bool {
        peer.uid == 0
            || self.allowed_uids.contains(&peer.uid)
            || self.allowed_gids.contains(&peer.gid)
    }
}

/// Complete privileged administration state.
#[derive(Clone)]
pub struct ConnectionAdminState {
    inner: Arc<ConnectionAdminInner>,
}

struct ConnectionAdminInner {
    peer_policy: AdminPeerPolicy,
    agent_config: AgentConfig,
    connections: Arc<PersistentConnectionStore>,
    credentials: Arc<PersistentCredentialStore>,
    pending: tokio::sync::Mutex<HashMap<String, PendingConnection>>,
    audit: AdminAuditLog,
}

struct PendingConnection {
    provider: RegisteredProvider,
    alias: ConnectionAlias,
    descriptor: Vec<u8>,
    account_commitment: [u8; 32],
    workloads: Vec<String>,
    profiles: Vec<ConnectionProfile>,
    defaults: Vec<String>,
    expires: Instant,
}

impl ConnectionAdminState {
    /// Constructs the administration service over persistent registry,
    /// credential, and audit stores.
    pub fn new(
        peer_policy: AdminPeerPolicy,
        agent_config: AgentConfig,
        connections: Arc<PersistentConnectionStore>,
        credentials: Arc<PersistentCredentialStore>,
        audit_path: impl Into<PathBuf>,
    ) -> Result<Self, ConnectionAdminError> {
        Ok(Self {
            inner: Arc::new(ConnectionAdminInner {
                peer_policy,
                agent_config,
                connections,
                credentials,
                pending: tokio::sync::Mutex::new(HashMap::new()),
                audit: AdminAuditLog::open(audit_path.into())?,
            }),
        })
    }
}

/// Builds the separate, statically registered privileged route tree.
pub fn connection_admin_app(state: ConnectionAdminState) -> Router {
    Router::new()
        .route("/v1/admin/connections", get(list_connections))
        .route(
            "/v1/admin/connections/{provider}/{alias}",
            get(inspect_connection),
        )
        .route(
            "/v1/admin/connections/{provider}/{alias}/disable",
            post(disable_connection),
        )
        .route(
            "/v1/admin/connections/{provider}/{alias}/enable",
            post(enable_connection),
        )
        .route(
            "/v1/admin/connections/{provider}/{alias}/rotate",
            post(rotate_connection),
        )
        .route(
            "/v1/admin/connections/{provider}/{alias}/revoke",
            post(revoke_connection),
        )
        .merge(crate::generated::profile_routes::built_in_connection_admin_routes())
        .fallback(admin_not_found)
        .layer(DefaultBodyLimit::max(MAX_ADMIN_REQUEST_BYTES))
        .with_state(state)
}

/// Serves the privileged router on its distinct POSIX socket.
#[cfg(unix)]
pub async fn serve_connection_admin(
    listener: UnixListener,
    state: ConnectionAdminState,
) -> std::io::Result<()> {
    axum::serve(
        listener,
        connection_admin_app(state).into_make_service_with_connect_info::<PeerCredentials>(),
    )
    .await
}

/// Builds the two exact onboarding routes for one generated provider arm.
pub(crate) fn provider_admin_routes(
    provider: RegisteredProvider,
    start_route: &'static str,
    complete_route: &'static str,
) -> Router<ConnectionAdminState> {
    Router::new()
        .route(start_route, post(start))
        .route(complete_route, post(complete))
        .layer(Extension(provider))
}

async fn start(
    State(state): State<ConnectionAdminState>,
    Extension(provider): Extension<RegisteredProvider>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if authorize_admin(&state, peer, &headers, true).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    let request = match decode_start_request(&body) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let account_commitment = match provider
        .validate_descriptor(&request.descriptor)
        .map_err(|_| ConnectionAdminError::Malformed)
    {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let provider_kind = ProviderKind::parse(provider.kind()).expect("registered provider");
    if state
        .inner
        .connections
        .load(&provider_kind, &request.alias)
        .ok()
        .flatten()
        .is_some()
        || validate_authorization(
            &state.inner.agent_config,
            provider,
            &request.alias,
            &request.workloads,
            &request.profiles,
        )
        .is_err()
    {
        return admin_failure(ConnectionAdminError::Conflict);
    }
    let defaults = default_workloads(
        &state.inner.agent_config,
        provider.kind(),
        request.alias.as_str(),
        &request.workloads,
    );
    let mut random = [0_u8; 16];
    if getrandom::fill(&mut random).is_err() {
        return admin_failure(ConnectionAdminError::Internal);
    }
    let token = format!("onb_{}", Base64UrlUnpadded::encode_string(&random));
    let mut pending = state.inner.pending.lock().await;
    let now = Instant::now();
    pending.retain(|_, value| value.expires > now);
    if pending.len() >= MAX_PENDING {
        return admin_failure(ConnectionAdminError::Capacity);
    }
    pending.insert(
        token.clone(),
        PendingConnection {
            provider,
            alias: request.alias,
            descriptor: request.descriptor,
            account_commitment,
            workloads: request.workloads,
            profiles: request.profiles,
            defaults,
            expires: now + PENDING_LIFETIME,
        },
    );
    admin_success(encode_start_response(request.request_id, &token))
}

async fn complete(
    State(state): State<ConnectionAdminState>,
    Extension(provider): Extension<RegisteredProvider>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if authorize_admin(&state, peer, &headers, true).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    let request = match decode_complete_request(&body) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let pending = {
        let mut values = state.inner.pending.lock().await;
        let Some(candidate) = values.remove(&request.onboarding) else {
            return admin_failure(ConnectionAdminError::NotFound);
        };
        if candidate.expires <= Instant::now() || candidate.provider.kind() != provider.kind() {
            return admin_failure(ConnectionAdminError::NotFound);
        }
        candidate
    };
    let descriptor = pending.descriptor.clone();
    let secret = match tokio::task::spawn_blocking(move || {
        provider.validate_onboarding(&descriptor, request.secret)
    })
    .await
    .map_err(|_| ConnectionAdminError::Internal)
    .and_then(|result| result.map_err(map_adapter))
    {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let connection_id = match ConnectionId::generate() {
        Ok(value) => value,
        Err(_) => return admin_failure(ConnectionAdminError::Internal),
    };
    let generation = NonZeroU64::new(1).expect("nonzero");
    let credential_commitment = match state
        .inner
        .credentials
        .install(&connection_id, generation, secret)
        .await
    {
        Ok(value) => *value.as_bytes(),
        Err(_) => return admin_failure(ConnectionAdminError::Internal),
    };
    let timestamp = unix_seconds();
    let record = match ConnectionRecord::new(
        ProviderKind::parse(provider.kind()).expect("registered provider"),
        pending.alias,
        connection_id.clone(),
        SemanticId::parse(provider.contract()).expect("registered contract"),
        SemanticId::parse(provider.descriptor_schema()).expect("registered descriptor"),
        pending.descriptor,
        pending.account_commitment,
        credential_commitment,
        generation,
        ConnectionState::Active,
        pending.workloads,
        pending.profiles,
        timestamp,
        timestamp,
        None,
    ) {
        Ok(value) => value,
        Err(_) => {
            let _ = state
                .inner
                .credentials
                .revoke(&connection_id, generation)
                .await;
            return admin_failure(ConnectionAdminError::Malformed);
        }
    };
    if state
        .inner
        .audit
        .append(
            peer,
            "complete",
            provider.kind(),
            record.alias().as_str(),
            generation,
        )
        .is_err()
    {
        let _ = state
            .inner
            .credentials
            .revoke(&connection_id, generation)
            .await;
        return admin_failure(ConnectionAdminError::Internal);
    }
    if let Err(error) = state
        .inner
        .connections
        .insert_with_defaults(record.clone(), &pending.defaults)
    {
        let _ = state
            .inner
            .credentials
            .revoke(&connection_id, generation)
            .await;
        return admin_failure(map_store(error));
    }
    admin_success(encode_record_response(request.request_id, &record))
}

async fn list_connections(
    State(state): State<ConnectionAdminState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    headers: HeaderMap,
) -> Response {
    if authorize_admin(&state, peer, &headers, false).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    match state.inner.connections.list() {
        Ok(records) => admin_success(encode_list_response(&records)),
        Err(error) => admin_failure(map_store(error)),
    }
}

async fn inspect_connection(
    State(state): State<ConnectionAdminState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path((provider, alias)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    if authorize_admin(&state, peer, &headers, false).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    let (provider, alias) = match parsed_key(&provider, &alias) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    match state.inner.connections.load(&provider, &alias) {
        Ok(Some(record)) => admin_success(encode_record_response([0; 16], &record)),
        Ok(None) => admin_failure(ConnectionAdminError::NotFound),
        Err(error) => admin_failure(map_store(error)),
    }
}

async fn disable_connection(
    state: State<ConnectionAdminState>,
    peer: ConnectInfo<PeerCredentials>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        state,
        peer,
        path,
        headers,
        body,
        ConnectionState::Disabled,
        "disable",
    )
    .await
}
async fn enable_connection(
    state: State<ConnectionAdminState>,
    peer: ConnectInfo<PeerCredentials>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        state,
        peer,
        path,
        headers,
        body,
        ConnectionState::Active,
        "enable",
    )
    .await
}
async fn revoke_connection(
    state: State<ConnectionAdminState>,
    peer: ConnectInfo<PeerCredentials>,
    path: Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    transition(
        state,
        peer,
        path,
        headers,
        body,
        ConnectionState::Revoked,
        "revoke",
    )
    .await
}

async fn transition(
    State(state): State<ConnectionAdminState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path((provider_text, alias_text)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
    next_state: ConnectionState,
    operation: &'static str,
) -> Response {
    if authorize_admin(&state, peer, &headers, true).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    let request = match decode_generation_request(&body) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let (provider, alias) = match parsed_key(&provider_text, &alias_text) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let record = match state.inner.connections.load(&provider, &alias) {
        Ok(Some(value)) if value.generation() == request.expected_generation => value,
        Ok(_) => return admin_failure(ConnectionAdminError::Conflict),
        Err(error) => return admin_failure(map_store(error)),
    };
    let next_generation = match NonZeroU64::new(record.generation().get().saturating_add(1)) {
        Some(value) if value.get() > record.generation().get() => value,
        _ => return admin_failure(ConnectionAdminError::Conflict),
    };
    let credential_commitment = match state.inner.credentials.advance_generation(
        record.connection_id(),
        record.generation(),
        next_generation,
    ) {
        Ok(value) => *value.as_bytes(),
        Err(_) => return admin_failure(ConnectionAdminError::Internal),
    };
    if state
        .inner
        .audit
        .append(
            peer,
            operation,
            provider.as_str(),
            alias.as_str(),
            record.generation(),
        )
        .is_err()
    {
        return admin_failure(ConnectionAdminError::Internal);
    }
    let replacement = match state.inner.connections.transition_state(
        &provider,
        &alias,
        record.generation(),
        next_state,
        credential_commitment,
        unix_seconds(),
    ) {
        Ok(value) => value,
        Err(error) => return admin_failure(map_store(error)),
    };
    if next_state == ConnectionState::Revoked {
        let _ = state
            .inner
            .credentials
            .revoke(record.connection_id(), record.generation())
            .await;
        let _ = state
            .inner
            .credentials
            .revoke(record.connection_id(), next_generation)
            .await;
    }
    admin_success(encode_record_response(request.request_id, &replacement))
}

async fn rotate_connection(
    State(state): State<ConnectionAdminState>,
    ConnectInfo(peer): ConnectInfo<PeerCredentials>,
    Path((provider_text, alias_text)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if authorize_admin(&state, peer, &headers, true).is_err() {
        return admin_failure(ConnectionAdminError::Unauthenticated);
    }
    let request = match decode_rotate_request(&body) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let registered = match RegisteredProvider::parse(&provider_text) {
        Some(value) => value,
        None => return admin_failure(ConnectionAdminError::NotFound),
    };
    let (provider, alias) = match parsed_key(&provider_text, &alias_text) {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let current = match state.inner.connections.load(&provider, &alias) {
        Ok(Some(value)) if value.generation() == request.expected_generation => value,
        Ok(_) => return admin_failure(ConnectionAdminError::Conflict),
        Err(error) => return admin_failure(map_store(error)),
    };
    let descriptor = current.descriptor().to_vec();
    let secret = match tokio::task::spawn_blocking(move || {
        registered.validate_onboarding(&descriptor, request.secret)
    })
    .await
    .map_err(|_| ConnectionAdminError::Internal)
    .and_then(|result| result.map_err(map_adapter))
    {
        Ok(value) => value,
        Err(error) => return admin_failure(error),
    };
    let next_generation = NonZeroU64::new(current.generation().get().saturating_add(1));
    let Some(next_generation) = next_generation.filter(|value| *value > current.generation())
    else {
        return admin_failure(ConnectionAdminError::Conflict);
    };
    let commitment = match state
        .inner
        .credentials
        .replace(
            current.connection_id(),
            current.generation(),
            next_generation,
            secret,
        )
        .await
    {
        Ok(value) => *value.as_bytes(),
        Err(_) => return admin_failure(ConnectionAdminError::Internal),
    };
    let replacement = match current.rotated(
        current.descriptor().to_vec(),
        *current.account_commitment(),
        commitment,
        unix_seconds(),
    ) {
        Ok(value) => value,
        Err(_) => return admin_failure(ConnectionAdminError::Conflict),
    };
    if state
        .inner
        .audit
        .append(
            peer,
            "rotate",
            provider.as_str(),
            alias.as_str(),
            current.generation(),
        )
        .is_err()
    {
        return admin_failure(ConnectionAdminError::Internal);
    }
    match state
        .inner
        .connections
        .replace(current.generation(), replacement.clone())
    {
        Ok(()) => admin_success(encode_record_response(request.request_id, &replacement)),
        Err(error) => admin_failure(map_store(error)),
    }
}

async fn admin_not_found() -> Response {
    admin_failure(ConnectionAdminError::NotFound)
}

fn authorize_admin(
    state: &ConnectionAdminState,
    peer: PeerCredentials,
    headers: &HeaderMap,
    body: bool,
) -> Result<(), ConnectionAdminError> {
    if !state.inner.peer_policy.permits(peer)
        || headers.len() > 64
        || headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::PROXY_AUTHORIZATION)
        || headers.contains_key(header::COOKIE)
        || headers.contains_key(header::TRANSFER_ENCODING)
        || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            != Some(LOCAL_AGENT_CONTENT_TYPE)
        || (body && headers.get(header::CONTENT_LENGTH).is_none())
    {
        return Err(ConnectionAdminError::Unauthenticated);
    }
    Ok(())
}

#[derive(Debug)]
struct StartRequest {
    request_id: [u8; 16],
    alias: ConnectionAlias,
    descriptor: Vec<u8>,
    workloads: Vec<String>,
    profiles: Vec<ConnectionProfile>,
}
#[derive(Debug)]
struct CompleteRequest {
    request_id: [u8; 16],
    onboarding: String,
    secret: Vec<u8>,
}
#[derive(Debug)]
struct GenerationRequest {
    request_id: [u8; 16],
    expected_generation: NonZeroU64,
}
#[derive(Debug)]
struct RotateRequest {
    request_id: [u8; 16],
    expected_generation: NonZeroU64,
    secret: Vec<u8>,
}

fn decode_start_request(bytes: &[u8]) -> Result<StartRequest, ConnectionAdminError> {
    let mut decoder = bounded_decoder(bytes)?;
    exact_map(&mut decoder, 6)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let request_id = exact_bytes(&mut decoder)?;
    key(&mut decoder, 3)?;
    let alias = ConnectionAlias::parse(decoder.str().map_err(malformed)?)
        .map_err(|_| ConnectionAdminError::Malformed)?;
    key(&mut decoder, 4)?;
    let descriptor = bounded_bytes(&mut decoder, 65_536)?;
    key(&mut decoder, 5)?;
    let workloads = text_array(&mut decoder, 256, 128)?;
    key(&mut decoder, 6)?;
    let profiles = profile_array(&mut decoder)?;
    finish(&decoder, bytes)?;
    let request = StartRequest {
        request_id,
        alias,
        descriptor,
        workloads,
        profiles,
    };
    if encode_start_request(&request).as_slice() != bytes {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(request)
}

fn encode_start_request(value: &StartRequest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&value.request_id).unwrap();
    encoder.u8(3).unwrap().str(value.alias.as_str()).unwrap();
    encoder.u8(4).unwrap().bytes(&value.descriptor).unwrap();
    encoder
        .u8(5)
        .unwrap()
        .array(value.workloads.len() as u64)
        .unwrap();
    for workload in &value.workloads {
        encoder.str(workload).unwrap();
    }
    encoder
        .u8(6)
        .unwrap()
        .array(value.profiles.len() as u64)
        .unwrap();
    for profile in &value.profiles {
        encoder
            .array(2)
            .unwrap()
            .str(profile.id().as_str())
            .unwrap()
            .u16(profile.version())
            .unwrap();
    }
    encoder.into_writer()
}

fn decode_complete_request(bytes: &[u8]) -> Result<CompleteRequest, ConnectionAdminError> {
    let mut decoder = bounded_decoder(bytes)?;
    exact_map(&mut decoder, 4)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let request_id = exact_bytes(&mut decoder)?;
    key(&mut decoder, 3)?;
    let onboarding = decoder.str().map_err(malformed)?.to_owned();
    if !onboarding_token(&onboarding) {
        return Err(ConnectionAdminError::Malformed);
    }
    key(&mut decoder, 4)?;
    let secret = bounded_bytes(&mut decoder, 65_536)?;
    finish(&decoder, bytes)?;
    let request = CompleteRequest {
        request_id,
        onboarding,
        secret,
    };
    if encode_complete_request(&request).as_slice() != bytes {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(request)
}

fn encode_complete_request(value: &CompleteRequest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&value.request_id).unwrap();
    encoder.u8(3).unwrap().str(&value.onboarding).unwrap();
    encoder.u8(4).unwrap().bytes(&value.secret).unwrap();
    encoder.into_writer()
}

fn decode_generation_request(bytes: &[u8]) -> Result<GenerationRequest, ConnectionAdminError> {
    let mut decoder = bounded_decoder(bytes)?;
    exact_map(&mut decoder, 3)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let request_id = exact_bytes(&mut decoder)?;
    key(&mut decoder, 3)?;
    let expected_generation = NonZeroU64::new(decoder.u64().map_err(malformed)?)
        .ok_or(ConnectionAdminError::Malformed)?;
    finish(&decoder, bytes)?;
    let request = GenerationRequest {
        request_id,
        expected_generation,
    };
    if encode_generation_request(&request).as_slice() != bytes {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(request)
}

fn encode_generation_request(value: &GenerationRequest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&value.request_id).unwrap();
    encoder
        .u8(3)
        .unwrap()
        .u64(value.expected_generation.get())
        .unwrap();
    encoder.into_writer()
}

fn decode_rotate_request(bytes: &[u8]) -> Result<RotateRequest, ConnectionAdminError> {
    let mut decoder = bounded_decoder(bytes)?;
    exact_map(&mut decoder, 4)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let request_id = exact_bytes(&mut decoder)?;
    key(&mut decoder, 3)?;
    let expected_generation = NonZeroU64::new(decoder.u64().map_err(malformed)?)
        .ok_or(ConnectionAdminError::Malformed)?;
    key(&mut decoder, 4)?;
    let secret = bounded_bytes(&mut decoder, 65_536)?;
    finish(&decoder, bytes)?;
    let request = RotateRequest {
        request_id,
        expected_generation,
        secret,
    };
    if encode_rotate_request(&request).as_slice() != bytes {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(request)
}

fn encode_rotate_request(value: &RotateRequest) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&value.request_id).unwrap();
    encoder
        .u8(3)
        .unwrap()
        .u64(value.expected_generation.get())
        .unwrap();
    encoder.u8(4).unwrap().bytes(&value.secret).unwrap();
    encoder.into_writer()
}

fn encode_start_response(request_id: [u8; 16], onboarding: &str) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap().str(onboarding).unwrap();
    encoder.into_writer()
}

fn encode_record_response(request_id: [u8; 16], record: &ConnectionRecord) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap();
    encode_record(&mut encoder, record);
    encoder.into_writer()
}

fn encode_list_response(records: &[ConnectionRecord]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().array(records.len() as u64).unwrap();
    for record in records {
        encode_record(&mut encoder, record);
    }
    encoder.into_writer()
}

fn encode_record(encoder: &mut Encoder<Vec<u8>>, record: &ConnectionRecord) {
    encoder.map(12).unwrap();
    encoder.u8(1).unwrap().u8(1).unwrap();
    encoder
        .u8(2)
        .unwrap()
        .str(record.provider_kind().as_str())
        .unwrap();
    encoder.u8(3).unwrap().str(record.alias().as_str()).unwrap();
    encoder
        .u8(4)
        .unwrap()
        .str(record.connection_id().as_str())
        .unwrap();
    encoder
        .u8(5)
        .unwrap()
        .str(record.contract().as_str())
        .unwrap();
    encoder
        .u8(6)
        .unwrap()
        .u64(record.generation().get())
        .unwrap();
    encoder
        .u8(7)
        .unwrap()
        .str(state_text(record.state()))
        .unwrap();
    encoder
        .u8(8)
        .unwrap()
        .bytes(record.descriptor_commitment())
        .unwrap();
    encoder
        .u8(9)
        .unwrap()
        .bytes(record.account_commitment())
        .unwrap();
    encoder
        .u8(10)
        .unwrap()
        .array(record.allowed_workloads().len() as u64)
        .unwrap();
    for value in record.allowed_workloads() {
        encoder.str(value).unwrap();
    }
    encoder
        .u8(11)
        .unwrap()
        .array(record.allowed_profiles().len() as u64)
        .unwrap();
    for profile in record.allowed_profiles() {
        encoder
            .array(2)
            .unwrap()
            .str(profile.id().as_str())
            .unwrap()
            .u16(profile.version())
            .unwrap();
    }
    encoder.u8(12).unwrap().array(3).unwrap();
    encoder.u64(record.created_at_unix_seconds()).unwrap();
    encoder.u64(record.updated_at_unix_seconds()).unwrap();
    match record.revoked_at_unix_seconds() {
        Some(value) => {
            encoder.u64(value).unwrap();
        }
        None => {
            encoder.null().unwrap();
        }
    }
}

fn validate_authorization(
    config: &AgentConfig,
    provider: RegisteredProvider,
    alias: &ConnectionAlias,
    workloads: &[String],
    profiles: &[ConnectionProfile],
) -> Result<(), ConnectionAdminError> {
    if workloads.is_empty()
        || profiles.is_empty()
        || !strictly_sorted(workloads)
        || !strictly_sorted(profiles)
    {
        return Err(ConnectionAdminError::Malformed);
    }
    for workload_id in workloads {
        let workload = config
            .workloads()
            .iter()
            .find(|value| value.id() == workload_id)
            .ok_or(ConnectionAdminError::Malformed)?;
        if !workload
            .connections()
            .iter()
            .any(|value| value.provider() == provider.kind() && value.alias() == alias.as_str())
        {
            return Err(ConnectionAdminError::Malformed);
        }
        for profile in profiles {
            let name = format!("{}/{}", profile.id().as_str(), profile.version());
            if workload.allowed_profiles().binary_search(&name).is_err() {
                return Err(ConnectionAdminError::Malformed);
            }
        }
    }
    Ok(())
}

fn default_workloads(
    config: &AgentConfig,
    provider: &str,
    alias: &str,
    allowed: &[String],
) -> Vec<String> {
    config
        .workloads()
        .iter()
        .filter(|workload| {
            allowed
                .binary_search_by(|value| value.as_str().cmp(workload.id()))
                .is_ok()
        })
        .filter(|workload| {
            workload.connections().iter().any(|value| {
                value.provider() == provider && value.alias() == alias && value.is_default()
            })
        })
        .map(|workload| workload.id().to_owned())
        .collect()
}

fn parsed_key(
    provider: &str,
    alias: &str,
) -> Result<(ProviderKind, ConnectionAlias), ConnectionAdminError> {
    RegisteredProvider::parse(provider).ok_or(ConnectionAdminError::NotFound)?;
    Ok((
        ProviderKind::parse(provider).map_err(|_| ConnectionAdminError::Malformed)?,
        ConnectionAlias::parse(alias).map_err(|_| ConnectionAdminError::Malformed)?,
    ))
}

fn bounded_decoder(bytes: &[u8]) -> Result<Decoder<'_>, ConnectionAdminError> {
    if bytes.is_empty() || bytes.len() > MAX_ADMIN_REQUEST_BYTES {
        return Err(ConnectionAdminError::Limit);
    }
    Ok(Decoder::new(bytes))
}
fn exact_map(decoder: &mut Decoder<'_>, count: u64) -> Result<(), ConnectionAdminError> {
    if decoder.map().map_err(malformed)? != Some(count) {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(())
}
fn version(decoder: &mut Decoder<'_>) -> Result<(), ConnectionAdminError> {
    key(decoder, 1)?;
    if decoder.u8().map_err(malformed)? != ADMIN_VERSION {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(())
}
fn key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), ConnectionAdminError> {
    if decoder.u8().map_err(malformed)? != expected {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(())
}
fn exact_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; SIZE], ConnectionAdminError> {
    decoder
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(|_| ConnectionAdminError::Malformed)
}
fn bounded_bytes(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<Vec<u8>, ConnectionAdminError> {
    let value = decoder.bytes().map_err(malformed)?;
    if value.is_empty() || value.len() > maximum {
        return Err(ConnectionAdminError::Limit);
    }
    Ok(value.to_vec())
}
fn text_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
    text_maximum: usize,
) -> Result<Vec<String>, ConnectionAdminError> {
    let count = decoder
        .array()
        .map_err(malformed)?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(ConnectionAdminError::Malformed)?;
    if count == 0 || count > maximum {
        return Err(ConnectionAdminError::Limit);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        let value = decoder.str().map_err(malformed)?.to_owned();
        if value.is_empty() || value.len() > text_maximum || !value.is_ascii() {
            return Err(ConnectionAdminError::Malformed);
        }
        values.push(value);
    }
    if !strictly_sorted(&values) {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(values)
}
fn profile_array(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<ConnectionProfile>, ConnectionAdminError> {
    let count = decoder
        .array()
        .map_err(malformed)?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(ConnectionAdminError::Malformed)?;
    if count == 0 || count > 32 {
        return Err(ConnectionAdminError::Limit);
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        if decoder.array().map_err(malformed)? != Some(2) {
            return Err(ConnectionAdminError::Malformed);
        }
        let id = SemanticId::parse(decoder.str().map_err(malformed)?)
            .map_err(|_| ConnectionAdminError::Malformed)?;
        let version = decoder.u16().map_err(malformed)?;
        values.push(
            ConnectionProfile::new(id, version).map_err(|_| ConnectionAdminError::Malformed)?,
        );
    }
    if !strictly_sorted(&values) {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(values)
}
fn finish(decoder: &Decoder<'_>, bytes: &[u8]) -> Result<(), ConnectionAdminError> {
    if decoder.position() != bytes.len() {
        return Err(ConnectionAdminError::Malformed);
    }
    Ok(())
}
fn malformed(_error: minicbor::decode::Error) -> ConnectionAdminError {
    ConnectionAdminError::Malformed
}
fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}
fn onboarding_token(value: &str) -> bool {
    value.strip_prefix("onb_").is_some_and(|encoded| {
        let mut bytes = [0_u8; 16];
        Base64UrlUnpadded::decode(encoded, &mut bytes).is_ok_and(|decoded| {
            decoded.len() == 16 && Base64UrlUnpadded::encode_string(decoded) == encoded
        })
    })
}
const fn state_text(state: ConnectionState) -> &'static str {
    match state {
        ConnectionState::Active => "active",
        ConnectionState::Disabled => "disabled",
        ConnectionState::Revoked => "revoked",
    }
}
fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_secs())
}

fn admin_success(body: Vec<u8>) -> Response {
    if body.is_empty() || body.len() > MAX_ADMIN_RESPONSE_BYTES {
        return admin_failure(ConnectionAdminError::Internal);
    }
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(LOCAL_AGENT_CONTENT_TYPE),
    );
    response
}
fn admin_failure(error: ConnectionAdminError) -> Response {
    let status = match error {
        ConnectionAdminError::Malformed => StatusCode::BAD_REQUEST,
        ConnectionAdminError::Limit | ConnectionAdminError::Capacity => {
            StatusCode::PAYLOAD_TOO_LARGE
        }
        ConnectionAdminError::Unauthenticated | ConnectionAdminError::NotFound => {
            StatusCode::NOT_FOUND
        }
        ConnectionAdminError::Conflict => StatusCode::CONFLICT,
        ConnectionAdminError::InvalidConfiguration | ConnectionAdminError::Internal => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    };
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(2).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().str(error.code()).unwrap();
    let mut response = (status, encoder.into_writer()).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(LOCAL_AGENT_CONTENT_TYPE),
    );
    response
}
fn map_store(error: PersistentConnectionStoreError) -> ConnectionAdminError {
    match error {
        PersistentConnectionStoreError::Conflict => ConnectionAdminError::Conflict,
        PersistentConnectionStoreError::Capacity => ConnectionAdminError::Capacity,
        PersistentConnectionStoreError::Unavailable => ConnectionAdminError::NotFound,
        PersistentConnectionStoreError::InvalidRecord
        | PersistentConnectionStoreError::Substitution
        | PersistentConnectionStoreError::Io => ConnectionAdminError::Internal,
    }
}

fn map_adapter(error: auths_connections::ConnectionAdapterError) -> ConnectionAdminError {
    match error {
        auths_connections::ConnectionAdapterError::InvalidDescriptor => {
            ConnectionAdminError::Malformed
        }
        auths_connections::ConnectionAdapterError::ScopeDenied
        | auths_connections::ConnectionAdapterError::CredentialUnavailable
        | auths_connections::ConnectionAdapterError::AccountSubstitution => {
            ConnectionAdminError::Conflict
        }
        auths_connections::ConnectionAdapterError::PreparationFailed => {
            ConnectionAdminError::Internal
        }
    }
}

/// Closed administration boundary error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionAdminError {
    Unauthenticated,
    InvalidConfiguration,
    Malformed,
    Limit,
    NotFound,
    Conflict,
    Capacity,
    Internal,
}
impl ConnectionAdminError {
    const fn code(self) -> &'static str {
        match self {
            Self::Unauthenticated => "unauthenticated",
            Self::InvalidConfiguration => "invalid-configuration",
            Self::Malformed => "malformed",
            Self::Limit => "limit",
            Self::NotFound => "not-found",
            Self::Conflict => "conflict",
            Self::Capacity => "capacity",
            Self::Internal => "internal",
        }
    }
}

struct AdminAuditLog {
    path: PathBuf,
    lock: Mutex<()>,
}
impl AdminAuditLog {
    fn open(path: PathBuf) -> Result<Self, ConnectionAdminError> {
        let parent = path
            .parent()
            .ok_or(ConnectionAdminError::InvalidConfiguration)?;
        let metadata =
            fs::symlink_metadata(parent).map_err(|_| ConnectionAdminError::InvalidConfiguration)?;
        if !metadata.file_type().is_dir() {
            return Err(ConnectionAdminError::InvalidConfiguration);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if metadata.permissions().mode() & 0o077 != 0 {
                return Err(ConnectionAdminError::InvalidConfiguration);
            }
        }
        if path.exists() {
            let metadata = fs::symlink_metadata(&path)
                .map_err(|_| ConnectionAdminError::InvalidConfiguration)?;
            if !metadata.file_type().is_file() || metadata.len() > MAX_AUDIT_BYTES {
                return Err(ConnectionAdminError::InvalidConfiguration);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                if metadata.permissions().mode() & 0o077 != 0 {
                    return Err(ConnectionAdminError::InvalidConfiguration);
                }
            }
        }
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }
    fn append(
        &self,
        peer: PeerCredentials,
        operation: &str,
        provider: &str,
        alias: &str,
        generation: NonZeroU64,
    ) -> Result<(), ConnectionAdminError> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| ConnectionAdminError::Internal)?;
        if fs::metadata(&self.path).is_ok_and(|value| value.len() >= MAX_AUDIT_BYTES) {
            return Err(ConnectionAdminError::Capacity);
        }
        let event = serde_json::json!({"schema":"auths.connection-admin-audit/1","at":unix_seconds(),"uid":peer.uid,"gid":peer.gid,"operation":operation,"provider":provider,"alias":alias,"expectedGeneration":generation.get()});
        let mut bytes =
            serde_json_canonicalizer::to_vec(&event).map_err(|_| ConnectionAdminError::Internal)?;
        bytes.push(b'\n');
        let mut options = OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|_| ConnectionAdminError::Internal)?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ConnectionAdminError::Internal)?;
        File::open(self.path.parent().expect("validated parent"))
            .and_then(|value| value.sync_all())
            .map_err(|_| ConnectionAdminError::Internal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_connections::RegistryLimits;
    use axum::{body::Body, extract::ConnectInfo, http::Request};
    use tower::ServiceExt as _;

    #[test]
    fn start_request_round_trips_canonically() {
        let request = StartRequest {
            request_id: [7; 16],
            alias: ConnectionAlias::parse("merchant-primary").unwrap(),
            descriptor: b"descriptor".to_vec(),
            workloads: vec!["payments-worker".into()],
            profiles: vec![
                ConnectionProfile::new(SemanticId::parse("auths.stripe.refund").unwrap(), 1)
                    .unwrap(),
            ],
        };
        let bytes = encode_start_request(&request);
        let decoded = decode_start_request(&bytes).unwrap();
        assert_eq!(decoded.alias.as_str(), "merchant-primary");
        assert_eq!(decoded.profiles[0].id().as_str(), "auths.stripe.refund");
    }

    #[test]
    fn request_decoder_rejects_trailing_or_unsorted_values() {
        let request = StartRequest {
            request_id: [7; 16],
            alias: ConnectionAlias::parse("merchant-primary").unwrap(),
            descriptor: b"descriptor".to_vec(),
            workloads: vec!["z".into(), "a".into()],
            profiles: vec![
                ConnectionProfile::new(SemanticId::parse("auths.stripe.refund").unwrap(), 1)
                    .unwrap(),
            ],
        };
        assert_eq!(
            decode_start_request(&encode_start_request(&request)).unwrap_err(),
            ConnectionAdminError::Malformed
        );
        let mut valid = encode_generation_request(&GenerationRequest {
            request_id: [1; 16],
            expected_generation: NonZeroU64::new(1).unwrap(),
        });
        valid.push(0);
        assert_eq!(
            decode_generation_request(&valid).unwrap_err(),
            ConnectionAdminError::Malformed
        );
    }

    #[tokio::test]
    async fn privileged_onboarding_persists_record_and_secret_without_disclosure() {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let authority_root = directory.path().join("authorities");
        fs::create_dir(&authority_root).unwrap();
        let authority = authority_root.join("payments.cbor");
        let config = format!(
            r#"[agent]
authority_root = "{}"

[agent.receipt_signing.decision]
algorithm = "Ed25519"
key_id = "decision-2026-01"
verification_method = "did:key:auths-receipt-decision#decision-2026-01"
public_key_base64url = "1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"
seed_file = "/var/lib/auths/receipt-decision.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.receipt_signing.execution]
algorithm = "Ed25519"
key_id = "execution-2026-01"
verification_method = "did:key:auths-receipt-execution#execution-2026-01"
public_key_base64url = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"
seed_file = "/var/lib/auths/receipt-execution.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.authority_sources.payments]
kind = "sealed-file-v1"
path = "{}"

[[agent.workloads]]
id = "payments-worker"
principal = "did:example:payments-worker"
authority_source = "payments"
allowed_profiles = ["auths.postgresql.bounded-update/1"]
connections = [{{ provider = "postgresql", alias = "database-primary", default = true }}]

[agent.workloads.selector]
kind = "posix"
uid = 1000
"#,
            authority_root.display(),
            authority.display()
        );
        let agent = AgentConfig::from_toml(&config, auths_config::AgentPlatform::Linux).unwrap();
        let connections = Arc::new(
            PersistentConnectionStore::open(
                directory.path().join("connections.cbor"),
                RegistryLimits::default(),
            )
            .unwrap(),
        );
        let credentials = Arc::new(
            PersistentCredentialStore::open(directory.path().join("credentials.cbor")).unwrap(),
        );
        let state = ConnectionAdminState::new(
            AdminPeerPolicy::new([1000], []).unwrap(),
            agent,
            Arc::clone(&connections),
            Arc::clone(&credentials),
            directory.path().join("admin-audit.jsonl"),
        )
        .unwrap();
        let app = connection_admin_app(state);
        let descriptor_fixture: serde_json::Value = serde_json::from_slice(include_bytes!(
            "../../../integrations/auths-postgresql/fixtures/connection/v1/valid.json"
        ))
        .unwrap();
        let descriptor = serde_json_canonicalizer::to_vec(&descriptor_fixture).unwrap();
        let start = StartRequest {
            request_id: [7; 16],
            alias: ConnectionAlias::parse("database-primary").unwrap(),
            descriptor,
            workloads: vec!["payments-worker".into()],
            profiles: vec![
                ConnectionProfile::new(
                    SemanticId::parse("auths.postgresql.bounded-update").unwrap(),
                    1,
                )
                .unwrap(),
            ],
        };
        let response = app
            .clone()
            .oneshot(admin_request(
                auths_postgresql::connection::admin_routes::START,
                encode_start_request(&start),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), MAX_ADMIN_RESPONSE_BYTES)
            .await
            .unwrap();
        let mut decoder = Decoder::new(&bytes);
        exact_map(&mut decoder, 3).unwrap();
        version(&mut decoder).unwrap();
        key(&mut decoder, 2).unwrap();
        assert_eq!(exact_bytes::<16>(&mut decoder).unwrap(), [7; 16]);
        key(&mut decoder, 3).unwrap();
        let onboarding = decoder.str().unwrap().to_owned();
        let complete = CompleteRequest {
            request_id: [8; 16],
            onboarding,
            secret: serde_json_canonicalizer::to_vec(&serde_json::json!({
                "schema": "auths.postgresql.connection-secret/1",
                "connectionString": "host=database.internal port=5432 dbname=app user=auths_executor password=development-only sslmode=require",
                "caPem": include_str!("../../../integrations/auths-postgresql/fixtures/connection/v1/test-ca.pem")
            }))
            .unwrap(),
        };
        let response = app
            .clone()
            .oneshot(admin_request(
                auths_postgresql::connection::admin_routes::COMPLETE,
                encode_complete_request(&complete),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_bytes = axum::body::to_bytes(response.into_body(), MAX_ADMIN_RESPONSE_BYTES)
            .await
            .unwrap();
        assert!(
            !response_bytes
                .windows(b"development-only".len())
                .any(|window| window == b"development-only")
        );

        let provider = ProviderKind::parse("postgresql").unwrap();
        let alias = ConnectionAlias::parse("database-primary").unwrap();
        let stored = connections.load(&provider, &alias).unwrap().unwrap();
        assert_eq!(stored.generation().get(), 1);
        assert_eq!(stored.allowed_workloads(), ["payments-worker"]);
        let profile = ConnectionProfile::new(
            SemanticId::parse("auths.postgresql.bounded-update").unwrap(),
            1,
        )
        .unwrap();
        assert!(
            connections
                .resolve(&provider, None, "payments-worker", &profile)
                .is_ok()
        );

        let response = app
            .oneshot(admin_get("/v1/admin/connections"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let listed = axum::body::to_bytes(response.into_body(), MAX_ADMIN_RESPONSE_BYTES)
            .await
            .unwrap();
        assert!(
            !listed
                .windows(b"development-only".len())
                .any(|window| window == b"development-only")
        );
    }

    fn admin_request(path: &str, body: Vec<u8>) -> Request<Body> {
        let mut request = Request::post(path)
            .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
            .header(header::CONTENT_LENGTH, body.len())
            .body(Body::from(body))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(1),
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                qualification_fault: None,
            }));
        request
    }

    fn admin_get(path: &str) -> Request<Body> {
        let mut request = Request::get(path)
            .header(header::CONTENT_TYPE, LOCAL_AGENT_CONTENT_TYPE)
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo(PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: Some(1),
                #[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
                qualification_fault: None,
            }));
        request
    }
}
