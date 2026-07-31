//! Native control plane and protected records HTTP adapter.

use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use auths_bounded_policy::{CommitmentDigest, UnitId};
use auths_lifecycle::{StoreError, WorkflowId};
use auths_proof_exchange_iroh::{IrohChannelConfig, IrohClientChannel, IrohServerChannel};
use auths_proof_exchange_model::{
    AUTHS_PROTOCOL_V1, ActionChallenge, ActionResponse, ActionSubmission, ChallengeNonce,
    ExchangeAudience, ExchangeMetrics, ExchangeOutcome, ExchangeProfileId, PeerObservation,
    ProfileBinding, RefusalKind,
};
use auths_proof_exchange_port::{
    ClientProofChannel as _, ProofExchangeService, ServiceError, serve_one,
};
use auths_records_api::{
    BoundedRecordApiPolicyV1, CREATE_OPERATION, CreateRecordProfile, CreateRecordV1,
    CustomerRecordV1, DeliveryAdapter, DeliveryReceipt, PersistentRecordsLedger,
    PresentationClaimsV1, READ_OPERATION, ReadField, ReadRecordProfile, ReadRecordV1,
    ReceiptBundle, RecordIdentifier, RecordsActionV1, RecordsApiVerifierConfigurationV1,
    RecordsExecutionRequest, RecordsLedger, RecordsLifecycleRegistry, RecordsLifecycleStore,
    RecordsPresentationV1, RecordsRequestEnvelopeV1, RecordsService, RecordsWorkflowOutcome,
    SdkRecordsProofVerifier, demo_configuration,
};
use auths_sdk::{RequestContext, Verifier};
use auths_stores::{LifecycleCapacityRuleV1, PersistentLifecycleStore};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use ed25519_dalek::SigningKey;
use iroh::{Endpoint, EndpointAddr, endpoint::presets};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::fixture::authorization_fixture;

const API_SCHEMA: &str = "auths-records-demo-api/1";
const SESSION_TTL_SECONDS: u64 = 10 * 60;

#[derive(Clone)]
pub struct AppConfig {
    pub bind: SocketAddr,
    pub allowed_origin: HeaderValue,
    pub state_path: PathBuf,
    pub executor_audience: String,
    pub public_base_url: String,
    pub iroh_endpoint: String,
    pub region: String,
    pub release: String,
}

impl AppConfig {
    /// Loads the native service configuration from environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError::Configuration`] when an address or origin is
    /// malformed.
    pub fn from_env() -> Result<Self, StartupError> {
        let port = env::var("PORT")
            .ok()
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(8080);
        let bind = env::var("AUTHS_RECORDS_BIND")
            .unwrap_or_else(|_| format!("0.0.0.0:{port}"))
            .parse()
            .map_err(|_| StartupError::Configuration)?;
        let public_base_url = env::var("AUTHS_RECORDS_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://localhost:{port}"));
        Ok(Self {
            bind,
            allowed_origin: HeaderValue::from_str(
                &env::var("AUTHS_RECORDS_ALLOWED_ORIGIN").unwrap_or_else(|_| "*".into()),
            )
            .map_err(|_| StartupError::Configuration)?,
            state_path: PathBuf::from(
                env::var("AUTHS_RECORDS_STATE_PATH")
                    .unwrap_or_else(|_| ".state/records/ledger-v2.json".into()),
            ),
            executor_audience: env::var("AUTHS_RECORDS_EXECUTOR_AUDIENCE")
                .unwrap_or_else(|_| "https://records-executor.auths.dev".into()),
            public_base_url,
            iroh_endpoint: env::var("AUTHS_RECORDS_IROH_ENDPOINT")
                .unwrap_or_else(|_| "starting".into()),
            region: env::var("FLY_REGION").unwrap_or_else(|_| "local".into()),
            release: env::var("FLY_IMAGE_REF").unwrap_or_else(|_| "development".into()),
        })
    }
}

#[derive(Clone)]
pub struct AppState {
    config: AppConfig,
    executed_configuration: RecordsApiVerifierConfigurationV1,
    ledger: Arc<dyn RecordsLedger>,
    lifecycles: Arc<DemoRecordsLifecycleRegistry>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
    iroh_target: Option<EndpointAddr>,
}

struct Session {
    created_at: u64,
    expires_at: u64,
    challenge: [u8; 32],
    policy: BoundedRecordApiPolicyV1,
    required_configuration: RecordsApiVerifierConfigurationV1,
    envelope: RecordsRequestEnvelopeV1,
    verifier: Arc<Verifier>,
    presenter: SigningKey,
    last_result: Option<RecordsWorkflowOutcome>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSessionRequest {
    #[serde(default = "default_experiment")]
    pub experiment: String,
    pub record_id: Option<String>,
    pub customer: Option<CustomerRecordV1>,
    pub source_session_id: Option<String>,
}

fn default_experiment() -> String {
    "exact-create".into()
}

fn demo_customer() -> CustomerRecordV1 {
    CustomerRecordV1 {
        age: 25,
        name: "Bob Martinez".into(),
        notes: "Interested in the enterprise analytics plan.".into(),
        occupation: "Sales manager".into(),
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    schema: String,
    session_id: String,
    created_at: u64,
    expires_at: u64,
    experiment: String,
    reusable_api_key_present: bool,
    operation_id: String,
    action: RecordsActionV1,
    policy: BoundedRecordApiPolicyV1,
    required_configuration: RecordsApiVerifierConfigurationV1,
    executed_configuration: RecordsApiVerifierConfigurationV1,
    proof_hex: String,
    presentation_hex: String,
    curl_command: String,
    iroh_command: String,
    iroh_endpoint: String,
    last_result: Option<RecordsWorkflowOutcome>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateBody {
    record_id: String,
    customer: CustomerRecordV1,
}

#[derive(Clone, Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid records demo configuration")]
    Configuration,
    #[error("records ledger is unavailable")]
    State,
}

struct DemoRecordsLifecycleStore {
    inner: PersistentLifecycleStore,
}

impl auths_lifecycle::LifecycleStore for DemoRecordsLifecycleStore {
    fn transact(
        &self,
        transaction: &auths_lifecycle::StoreTransactionV1,
    ) -> Result<auths_lifecycle::StoredTransitionV1, StoreError> {
        auths_lifecycle::LifecycleStore::transact(&self.inner, transaction)
    }
}

impl RecordsLifecycleStore for DemoRecordsLifecycleStore {
    fn load_records_lifecycle(
        &self,
        workflow: &WorkflowId,
    ) -> Result<Option<auths_lifecycle::LifecycleRecordV1>, StoreError> {
        self.inner.load(workflow)
    }
}

struct DemoRecordsLifecycleRegistry {
    directory: PathBuf,
    stores: Mutex<HashMap<String, Arc<DemoRecordsLifecycleStore>>>,
}

impl DemoRecordsLifecycleRegistry {
    fn new(directory: PathBuf) -> Self {
        Self {
            directory,
            stores: Mutex::new(HashMap::new()),
        }
    }
}

impl RecordsLifecycleRegistry for DemoRecordsLifecycleRegistry {
    fn for_policy(
        &self,
        policy: &BoundedRecordApiPolicyV1,
    ) -> Result<Arc<dyn RecordsLifecycleStore>, StoreError> {
        let policy_digest = policy.digest().map_err(|_| StoreError::Corrupt)?;
        let scope_bytes: [u8; 32] = hex::decode(&policy_digest)
            .map_err(|_| StoreError::Corrupt)?
            .try_into()
            .map_err(|_| StoreError::Corrupt)?;
        let scope = CommitmentDigest::new(scope_bytes);
        let mut stores = self.stores.lock().map_err(|_| StoreError::Unavailable)?;
        if let Some(store) = stores.get(&policy_digest) {
            let concrete = Arc::clone(store);
            let store: Arc<dyn RecordsLifecycleStore> = concrete;
            return Ok(store);
        }
        let store = Arc::new(DemoRecordsLifecycleStore {
            inner: PersistentLifecycleStore::open(
                self.directory.join(format!("{policy_digest}.lifecycle")),
                vec![
                    LifecycleCapacityRuleV1::Additive {
                        scope_digest: scope,
                        window_digest: None,
                        unit: UnitId::parse("create-unit").map_err(|_| StoreError::Corrupt)?,
                        ceiling: u64::from(policy.maximum_creates),
                    },
                    LifecycleCapacityRuleV1::Additive {
                        scope_digest: scope,
                        window_digest: None,
                        unit: UnitId::parse("created-bytes").map_err(|_| StoreError::Corrupt)?,
                        ceiling: policy.maximum_created_bytes,
                    },
                    LifecycleCapacityRuleV1::Additive {
                        scope_digest: scope,
                        window_digest: None,
                        unit: UnitId::parse("read-unit").map_err(|_| StoreError::Corrupt)?,
                        ceiling: u64::from(policy.maximum_reads),
                    },
                ],
                4096,
            )
            .map_err(|_| StoreError::Corrupt)?,
        });
        stores.insert(policy_digest, Arc::clone(&store));
        Ok(store)
    }
}

/// Builds the HTTPS application with its persistent records ledger.
///
/// # Errors
///
/// Returns an error when configuration validation or ledger initialization
/// fails.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    app_with_iroh(config, None).map(|(router, _)| router)
}

/// Builds the HTTPS application and optionally binds it to an Iroh endpoint.
///
/// # Errors
///
/// Returns an error when configuration validation or ledger initialization
/// fails.
pub fn app_with_iroh(
    config: AppConfig,
    iroh_target: Option<EndpointAddr>,
) -> Result<(Router, AppState), StartupError> {
    let mut executed_configuration = demo_configuration(&config.executor_audience);
    executed_configuration.trusted_https_origin_mappings = vec![config.public_base_url.clone()];
    executed_configuration.trusted_iroh_endpoint_mappings = vec![config.iroh_endpoint.clone()];
    executed_configuration
        .validate()
        .map_err(|_| StartupError::Configuration)?;
    let ledger = Arc::new(
        PersistentRecordsLedger::open(&config.state_path).map_err(|_| StartupError::State)?,
    );
    let lifecycles = Arc::new(DemoRecordsLifecycleRegistry::new(
        config.state_path.with_extension("lifecycles"),
    ));
    let allowed_origin = config.allowed_origin.clone();
    let state = AppState {
        config,
        executed_configuration,
        ledger,
        lifecycles,
        sessions: Arc::new(Mutex::new(HashMap::new())),
        iroh_target,
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
            .allow_headers(tower_http::cors::Any)
    };
    let router = Router::new()
        .route("/", get(index))
        .route("/app.js", get(javascript))
        .route("/styles.css", get(styles))
        .route("/healthz", get(health))
        .route("/readyz", get(health))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{id}", get(get_session))
        .route("/api/v1/sessions/{id}/envelope", get(get_iroh_envelope))
        .route(
            "/api/v1/sessions/{id}/execute-iroh",
            post(execute_iroh_route),
        )
        .route("/api/v1/receipts/{id}", get(get_receipt))
        .route("/receipts/{id}", get(receipt_page))
        .route("/v1/records", post(create_record))
        .route("/v1/records/{record_id}", get(read_record))
        .layer(cors)
        .with_state(state.clone());
    Ok((router, state))
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
    Response::builder()
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(content))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": state.config.region,
        "release": state.config.release,
        "https": true,
        "iroh": state.config.iroh_endpoint,
        "reusable_api_key_present": false
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "the demo keeps issuance, mutation experiments, and presentation binding visible"
)]
async fn create_session(
    State(state): State<AppState>,
    Json(input): Json<CreateSessionRequest>,
) -> Result<Json<SessionView>, ApiError> {
    let now = now()?;
    if input.experiment == "exact-read" && input.source_session_id.is_none() {
        return Err(ApiError::bad_request(
            "exact read requires a completed source session",
        ));
    }
    let session_id = random_id("session")?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::internal())?;
    let source = input
        .source_session_id
        .as_deref()
        .map(|id| source_material(&state, id))
        .transpose()?;
    let (presenter, namespace, source_policy, source_record) = if let Some(source) = source {
        source
    } else {
        let mut presenter_seed = [0_u8; 32];
        getrandom::fill(&mut presenter_seed).map_err(|_| ApiError::internal())?;
        let presenter = SigningKey::from_bytes(&presenter_seed);
        presenter_seed.fill(0);
        let namespace = RecordIdentifier::parse(format!("visitor-{}", &session_id[8..20]))
            .map_err(|_| ApiError::bad_request("invalid generated namespace"))?;
        (presenter, namespace, None, None)
    };
    let presenter_principal = format!(
        "key:ed25519:{}",
        hex::encode(presenter.verifying_key().to_bytes())
    );
    let record_id = RecordIdentifier::parse(input.record_id.unwrap_or_else(|| {
        if input.experiment == "exact-read" {
            source_record.as_ref().map_or_else(
                || format!("demo-{}", &session_id[8..16]),
                |record| record.as_str().to_string(),
            )
        } else {
            format!("demo-{}", &session_id[8..16])
        }
    }))
    .map_err(|_| ApiError::bad_request("invalid record identifier"))?;
    let mut required_configuration = state.executed_configuration.clone();
    if input.experiment == "configuration-mismatch" {
        required_configuration.maximum_response_bytes = 4097;
    }
    let policy = if let Some(policy) = source_policy {
        if policy.presenter_principal != presenter_principal
            || policy.namespace_id != namespace
            || policy.expires_at < now
        {
            return Err(ApiError::bad_request("source grant is no longer usable"));
        }
        policy
    } else {
        policy(
            &session_id,
            namespace.clone(),
            presenter_principal,
            &state.config.executor_audience,
            now,
            input.experiment == "bounded-create",
        )?
    };
    let action = action(
        &input.experiment,
        namespace,
        record_id,
        input.customer.unwrap_or_else(demo_customer),
        &policy,
        &required_configuration,
        now,
    )?;
    let action_bytes = action
        .canonical_bytes()
        .map_err(|_| ApiError::bad_request("action is invalid"))?;
    let fixture = match &action {
        RecordsActionV1::Create(_) => authorization_fixture(
            &CreateRecordProfile,
            &action_bytes,
            &state.config.executor_audience,
            policy.namespace_id.as_str(),
            now,
            challenge,
        ),
        RecordsActionV1::Read(_) => authorization_fixture(
            &ReadRecordProfile,
            &action_bytes,
            &state.config.executor_audience,
            policy.namespace_id.as_str(),
            now,
            challenge,
        ),
    };
    let mut proof = fixture.proof;
    if input.experiment == "invalid-proof" {
        let last = proof.last_mut().ok_or_else(ApiError::internal)?;
        *last ^= 1;
    }
    let action_digest = action.digest().map_err(|_| ApiError::internal())?;
    let presentation = RecordsPresentationV1::sign(
        &presenter,
        &proof,
        &PresentationClaimsV1 {
            operation_id: action.operation_id().into(),
            canonical_action_digest: action_digest,
            challenge,
            executor_audience: state.config.executor_audience.clone(),
            created_at: now,
            expires_at: now + 120,
            presentation_nonce: random_id("presentation")?,
        },
    )
    .map_err(|_| ApiError::internal())?;
    let envelope = RecordsRequestEnvelopeV1 {
        envelope_version: "auths.records-envelope/1".into(),
        operation_id: action.operation_id().into(),
        canonical_action: action,
        proof_hex: hex::encode(proof),
        presentation,
    };
    let session = Session {
        created_at: now,
        expires_at: now + SESSION_TTL_SECONDS,
        challenge,
        policy,
        required_configuration,
        envelope,
        verifier: Arc::new(fixture.verifier),
        presenter,
        last_result: None,
    };
    state
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .insert(session_id.clone(), session);
    session_view(&state, &session_id, &input.experiment).map(Json)
}

fn source_material(
    state: &AppState,
    id: &str,
) -> Result<
    (
        SigningKey,
        RecordIdentifier,
        Option<BoundedRecordApiPolicyV1>,
        Option<RecordIdentifier>,
    ),
    ApiError,
> {
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions
        .get(id)
        .ok_or_else(|| ApiError::not_found("source session not found"))?;
    let record = match &session.envelope.canonical_action {
        RecordsActionV1::Create(action) => Some(action.record_id.clone()),
        RecordsActionV1::Read(action) => Some(action.record_id.clone()),
    };
    Ok((
        session.presenter.clone(),
        session.policy.namespace_id.clone(),
        Some(session.policy.clone()),
        record,
    ))
}

async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SessionView>, ApiError> {
    session_view(&state, &id, "existing").map(Json)
}

fn session_view(
    state: &AppState,
    session_id: &str,
    experiment: &str,
) -> Result<SessionView, ApiError> {
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions
        .get(session_id)
        .ok_or_else(|| ApiError::not_found("session not found"))?;
    let presentation_json =
        serde_json::to_vec(&session.envelope.presentation).map_err(|_| ApiError::internal())?;
    let body = match &session.envelope.canonical_action {
        RecordsActionV1::Create(action) => serde_json::to_string(&json!({
            "record_id": action.record_id.as_str(),
            "customer": action.customer
        }))
        .map_err(|_| ApiError::internal())?,
        RecordsActionV1::Read(_) => String::new(),
    };
    let route = match &session.envelope.canonical_action {
        RecordsActionV1::Create(_) => "/v1/records".to_string(),
        RecordsActionV1::Read(action) => {
            format!("/v1/records/{}", action.record_id.as_str())
        }
    };
    let method = if matches!(
        session.envelope.canonical_action,
        RecordsActionV1::Create(_)
    ) {
        "POST"
    } else {
        "GET"
    };
    let data = if body.is_empty() {
        String::new()
    } else {
        format!(" --data '{body}'")
    };
    let curl_command = format!(
        "curl -X {method} '{}{route}' -H 'Content-Type: application/json' -H 'Auths-Session: {session_id}' -H 'Auths-Proof: {}' -H 'Auths-Presentation: {}'{data}",
        state.config.public_base_url,
        session.envelope.proof_hex,
        hex::encode(presentation_json)
    );
    Ok(SessionView {
        schema: API_SCHEMA.into(),
        session_id: session_id.into(),
        created_at: session.created_at,
        expires_at: session.expires_at,
        experiment: experiment.into(),
        reusable_api_key_present: false,
        operation_id: session.envelope.operation_id.clone(),
        action: session.envelope.canonical_action.clone(),
        policy: session.policy.clone(),
        required_configuration: session.required_configuration.clone(),
        executed_configuration: state.executed_configuration.clone(),
        proof_hex: session.envelope.proof_hex.clone(),
        presentation_hex: hex::encode(
            serde_json::to_vec(&session.envelope.presentation).map_err(|_| ApiError::internal())?,
        ),
        curl_command,
        iroh_command: format!(
            "curl -sS '{}/api/v1/sessions/{}/envelope' -o /tmp/auths-records-envelope.json && auths-records-demo send --endpoint '{}' --envelope /tmp/auths-records-envelope.json",
            state.config.public_base_url, session_id, state.config.iroh_endpoint
        ),
        iroh_endpoint: state.config.iroh_endpoint.clone(),
        last_result: session.last_result.clone(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IrohRecordsMessageV1 {
    pub schema: String,
    pub session_id: String,
    pub envelope: RecordsRequestEnvelopeV1,
}

async fn get_iroh_envelope(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<IrohRecordsMessageV1>, ApiError> {
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions
        .get(&id)
        .ok_or_else(|| ApiError::not_found("session not found"))?;
    Ok(Json(IrohRecordsMessageV1 {
        schema: "auths.records-iroh-message/1".into(),
        session_id: id,
        envelope: session.envelope.clone(),
    }))
}

async fn execute_iroh_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<RecordsWorkflowOutcome>, ApiError> {
    let message = get_iroh_message(&state, &id)?;
    send_via_iroh(&state, &message).await.map(Json)
}

fn get_iroh_message(state: &AppState, id: &str) -> Result<IrohRecordsMessageV1, ApiError> {
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions
        .get(id)
        .ok_or_else(|| ApiError::not_found("session not found"))?;
    Ok(IrohRecordsMessageV1 {
        schema: "auths.records-iroh-message/1".into(),
        session_id: id.into(),
        envelope: session.envelope.clone(),
    })
}

async fn send_via_iroh(
    state: &AppState,
    message: &IrohRecordsMessageV1,
) -> Result<RecordsWorkflowOutcome, ApiError> {
    let target = state
        .iroh_target
        .clone()
        .ok_or_else(|| ApiError::service_unavailable("Iroh endpoint is not configured"))?;
    let client_endpoint = Endpoint::bind(presets::N0)
        .await
        .map_err(|_| ApiError::service_unavailable("could not bind Iroh client"))?;
    let mut channel =
        IrohClientChannel::connect(&client_endpoint, target, IrohChannelConfig::default())
            .await
            .map_err(|_| ApiError::service_unavailable("could not connect to Iroh endpoint"))?;
    let challenge = channel
        .receive_challenge()
        .await
        .map_err(|_| ApiError::service_unavailable("Iroh challenge failed"))?;
    let body =
        auths_records_api::canonical::canonical_json(message).map_err(|_| ApiError::internal())?;
    let submission = ActionSubmission::new(
        body,
        message
            .envelope
            .proof()
            .map_err(|_| ApiError::bad_request("invalid proof carrier"))?,
        &challenge,
    )
    .map_err(|_| ApiError::bad_request("Iroh submission exceeds negotiated limits"))?;
    let response = channel
        .submit_action(submission)
        .await
        .map_err(|_| ApiError::service_unavailable("Iroh response failed"))?;
    client_endpoint.close().await;
    match response.outcome() {
        ExchangeOutcome::Completed { result } => {
            serde_json::from_slice(result).map_err(|_| ApiError::internal())
        }
        ExchangeOutcome::Refused { message, .. } => {
            Err(ApiError::owned_bad_request(message.clone()))
        }
    }
}

struct RecordsIrohService {
    state: AppState,
}

#[async_trait]
impl ProofExchangeService for RecordsIrohService {
    async fn issue_challenge(
        &self,
        _peer: &PeerObservation,
    ) -> Result<ActionChallenge, ServiceError> {
        let mut challenge = [0_u8; 32];
        getrandom::fill(&mut challenge).map_err(|_| ServiceError::ChallengeUnavailable)?;
        ActionChallenge::new(
            ChallengeNonce::new(challenge),
            ExchangeAudience::parse(&self.state.config.executor_audience)
                .map_err(|_| ServiceError::ChallengeUnavailable)?,
            now()
                .map_err(|_| ServiceError::ChallengeUnavailable)?
                .saturating_add(60),
            512 * 1024,
            self.state.executed_configuration.maximum_proof_bytes,
            ProfileBinding::new(
                AUTHS_PROTOCOL_V1,
                ExchangeProfileId::parse("auths.demo.records-envelope")
                    .map_err(|_| ServiceError::ChallengeUnavailable)?,
                1,
            )
            .map_err(|_| ServiceError::ChallengeUnavailable)?,
        )
        .map_err(|_| ServiceError::ChallengeUnavailable)
    }

    async fn handle_action(
        &self,
        peer: &PeerObservation,
        _challenge: &ActionChallenge,
        request: ActionSubmission,
    ) -> ActionResponse {
        let result = self.handle(peer, &request);
        match result {
            Ok(outcome) => {
                let action_digest = outcome.receipt.decision.action_digest.clone();
                let request_id = hex::decode(action_digest)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok());
                let bytes = serde_json::to_vec(&outcome).unwrap_or_default();
                let exchange = ExchangeOutcome::completed(bytes).unwrap_or_else(|_| {
                    ExchangeOutcome::refused(
                        RefusalKind::OversizedInput,
                        None,
                        "records result exceeded exchange limit",
                    )
                    .expect("fixed refusal")
                });
                ActionResponse::new(request_id, exchange, ExchangeMetrics::default())
            }
            Err(error) => ActionResponse::new(
                None,
                ExchangeOutcome::refused(
                    RefusalKind::ApplicationPolicy,
                    None,
                    error.detail_owned(),
                )
                .expect("bounded API error"),
                ExchangeMetrics::default(),
            ),
        }
    }
}

impl RecordsIrohService {
    fn handle(
        &self,
        peer: &PeerObservation,
        request: &ActionSubmission,
    ) -> Result<RecordsWorkflowOutcome, ApiError> {
        let message: IrohRecordsMessageV1 = serde_json::from_slice(request.body())
            .map_err(|_| ApiError::bad_request("malformed Iroh records message"))?;
        if message.schema != "auths.records-iroh-message/1"
            || message
                .envelope
                .proof()
                .map_err(|_| ApiError::bad_request("invalid proof"))?
                != request.proof()
        {
            return Err(ApiError::bad_request("Iroh carrier binding mismatch"));
        }
        with_session(&self.state, &message.session_id, |session| {
            if session.envelope != message.envelope {
                return Err(ApiError::bad_request(
                    "Iroh envelope differs from the issued semantic request",
                ));
            }
            let identity = match peer {
                PeerObservation::IrohEndpoint(id) => format!("iroh:{}", hex::encode(id)),
                _ => "iroh:unexpected-peer".into(),
            };
            execute_session(&self.state, session, DeliveryAdapter::Iroh, &identity)
        })
    }
}

pub async fn serve_iroh(endpoint: Endpoint, state: AppState) {
    let service = RecordsIrohService { state };
    loop {
        let Ok(mut channel) =
            IrohServerChannel::accept(&endpoint, IrohChannelConfig::default()).await
        else {
            break;
        };
        let _result = serve_one(&mut channel, &service).await;
    }
}

/// Sends a complete Auths records envelope over the native Iroh adapter.
///
/// # Errors
///
/// Returns a stable human-readable error when endpoint/envelope decoding,
/// connection, or exchange validation fails.
pub async fn send_envelope_file(
    endpoint_hex: &str,
    envelope_path: &std::path::Path,
) -> Result<RecordsWorkflowOutcome, String> {
    let endpoint_json = hex::decode(endpoint_hex).map_err(|_| "invalid endpoint encoding")?;
    let target: EndpointAddr =
        serde_json::from_slice(&endpoint_json).map_err(|_| "invalid endpoint address")?;
    let body = tokio::fs::read(envelope_path)
        .await
        .map_err(|_| "could not read envelope file")?;
    let message: IrohRecordsMessageV1 =
        serde_json::from_slice(&body).map_err(|_| "invalid envelope file")?;
    let client = Endpoint::bind(presets::N0)
        .await
        .map_err(|_| "could not bind Iroh client")?;
    let mut channel = IrohClientChannel::connect(&client, target, IrohChannelConfig::default())
        .await
        .map_err(|_| "could not connect to Iroh endpoint")?;
    let challenge = channel
        .receive_challenge()
        .await
        .map_err(|_| "could not receive Iroh challenge")?;
    let canonical = auths_records_api::canonical::canonical_json(&message)
        .map_err(|_| "could not encode envelope")?;
    let submission = ActionSubmission::new(
        canonical,
        message.envelope.proof().map_err(|_| "invalid proof")?,
        &challenge,
    )
    .map_err(|_| "envelope exceeds negotiated bounds")?;
    let response = channel
        .submit_action(submission)
        .await
        .map_err(|_| "Iroh submission failed")?;
    client.close().await;
    match response.outcome() {
        ExchangeOutcome::Completed { result } => {
            serde_json::from_slice(result).map_err(|_| "invalid records response".into())
        }
        ExchangeOutcome::Refused { message, .. } => Err(message.clone()),
    }
}

async fn create_record(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<CreateBody>,
) -> Result<Json<RecordsWorkflowOutcome>, ApiError> {
    let session_id = required_header(&headers, "auths-session")?;
    with_session(&state, &session_id, |session| {
        let RecordsActionV1::Create(action) = &session.envelope.canonical_action else {
            return Err(ApiError::bad_request("session is not a create action"));
        };
        if action.record_id.as_str() != body.record_id || action.customer != body.customer {
            return Err(ApiError::bad_request(
                "route input differs from the canonical action",
            ));
        }
        validate_carrier_headers(&headers, session)?;
        execute_session(&state, session, DeliveryAdapter::Https, "https")
    })
    .map(Json)
}

async fn read_record(
    State(state): State<AppState>,
    Path(record_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<RecordsWorkflowOutcome>, ApiError> {
    let session_id = required_header(&headers, "auths-session")?;
    with_session(&state, &session_id, |session| {
        let RecordsActionV1::Read(action) = &session.envelope.canonical_action else {
            return Err(ApiError::bad_request("session is not a read action"));
        };
        if action.record_id.as_str() != record_id {
            return Err(ApiError::bad_request(
                "route input differs from the canonical action",
            ));
        }
        validate_carrier_headers(&headers, session)?;
        execute_session(&state, session, DeliveryAdapter::Https, "https")
    })
    .map(Json)
}

fn with_session<T>(
    state: &AppState,
    session_id: &str,
    operation: impl FnOnce(&mut Session) -> Result<T, ApiError>,
) -> Result<T, ApiError> {
    let mut sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| ApiError::not_found("session not found"))?;
    if session.expires_at < now()? {
        return Err(ApiError::bad_request("session expired"));
    }
    operation(session)
}

fn validate_carrier_headers(headers: &HeaderMap, session: &Session) -> Result<(), ApiError> {
    if required_header(headers, "auths-proof")? != session.envelope.proof_hex {
        return Err(ApiError::bad_request(
            "proof carrier differs from session proof",
        ));
    }
    let presentation = hex::encode(
        serde_json::to_vec(&session.envelope.presentation).map_err(|_| ApiError::internal())?,
    );
    if required_header(headers, "auths-presentation")? != presentation {
        return Err(ApiError::bad_request(
            "presentation carrier differs from session presentation",
        ));
    }
    Ok(())
}

fn execute_session(
    state: &AppState,
    session: &mut Session,
    adapter: DeliveryAdapter,
    adapter_identity: &str,
) -> Result<RecordsWorkflowOutcome, ApiError> {
    let service = RecordsService::new(
        SdkRecordsProofVerifier::from_shared(Arc::clone(&session.verifier)),
        Arc::clone(&state.ledger),
        Arc::clone(&state.lifecycles),
        state.executed_configuration.clone(),
    );
    let request = RecordsExecutionRequest {
        envelope: session.envelope.clone(),
        policy: session.policy.clone(),
        required_configuration: session.required_configuration.clone(),
        auths_request: RequestContext::new(
            &state.config.executor_audience,
            session.challenge,
            session.created_at,
        )
        .map_err(|_| ApiError::internal())?,
        challenge: session.challenge,
        delivery: DeliveryReceipt {
            schema: "auths.records-delivery-receipt/1".into(),
            delivery_id: random_id("delivery")?,
            adapter,
            adapter_identity: adapter_identity.into(),
            protocol: "auths.records-api/1".into(),
            received_at: now()?,
        },
        now: now()?,
    };
    let outcome = service
        .execute(&request)
        .map_err(|_| ApiError::internal())?;
    session.last_result = Some(outcome.clone());
    Ok(outcome)
}

async fn get_receipt(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ReceiptBundle>, ApiError> {
    state
        .ledger
        .receipt(&id)
        .map_err(|_| ApiError::internal())?
        .map(Json)
        .ok_or_else(|| ApiError::not_found("receipt not found"))
}

async fn receipt_page(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Html<String>, ApiError> {
    let receipt = state
        .ledger
        .receipt(&id)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(|| ApiError::not_found("receipt not found"))?;
    let encoded = serde_json::to_string_pretty(&receipt).map_err(|_| ApiError::internal())?;
    Ok(Html(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Auths receipt</title><link rel=\"stylesheet\" href=\"/styles.css\"></head><body><main class=\"receipt-page\"><a href=\"/\">← Records demo</a><p class=\"eyebrow\">MACHINE-VERIFIABLE EVIDENCE</p><h1>Authorization receipt</h1><p>This page separates delivery, decision, effect, and observation facts. The raw canonical representation is shown in full below.</p><section class=\"receipt-summary\"><div><span>Verdict</span><strong>{:?}</strong></div><div><span>Stable code</span><strong>{}</strong></div><div><span>Transport</span><strong>{:?}</strong></div></section><pre>{}</pre></main></body></html>",
        receipt.decision.decision.class,
        escape(&receipt.decision.decision.code),
        receipt.delivery.adapter,
        escape(&encoded)
    )))
}

fn policy(
    session_id: &str,
    namespace_id: RecordIdentifier,
    presenter_principal: String,
    executor_audience: &str,
    now: u64,
    bounded: bool,
) -> Result<BoundedRecordApiPolicyV1, ApiError> {
    let policy = BoundedRecordApiPolicyV1 {
        policy_type: "auths.demo.bounded-record-api-policy".into(),
        policy_version: 1,
        policy_id: format!("policy-{session_id}"),
        namespace_id,
        presenter_principal,
        allowed_operations: vec![CREATE_OPERATION.into(), READ_OPERATION.into()],
        allowed_record_ids: Vec::new(),
        allowed_record_id_prefixes: vec!["demo-".into()],
        maximum_value_bytes: 1024,
        maximum_response_bytes: 4096,
        allowed_read_fields: vec![ReadField::Customer, ReadField::RecordId, ReadField::Version],
        maximum_creates: if bounded { 3 } else { 1 },
        maximum_reads: if bounded { 3 } else { 1 },
        maximum_created_bytes: if bounded { 3072 } else { 1024 },
        maximum_disclosed_bytes: if bounded { 12_288 } else { 4096 },
        fixed_and_rolling_budgets: Vec::new(),
        valid_from: now.saturating_sub(1),
        expires_at: now + 600,
        maximum_action_lifetime_seconds: 300,
        maximum_presentation_lifetime_seconds: 120,
        maximum_evidence_age_seconds: 60,
        executor_audience: executor_audience.into(),
    };
    policy
        .validate()
        .map_err(|_| ApiError::bad_request("invalid policy"))?;
    Ok(policy)
}

fn action(
    experiment: &str,
    namespace_id: RecordIdentifier,
    record_id: RecordIdentifier,
    customer: CustomerRecordV1,
    policy: &BoundedRecordApiPolicyV1,
    configuration: &RecordsApiVerifierConfigurationV1,
    now: u64,
) -> Result<RecordsActionV1, ApiError> {
    let policy_digest = policy.digest().map_err(|_| ApiError::internal())?;
    let configuration_digest = configuration.digest().map_err(|_| ApiError::internal())?;
    if experiment == "exact-read" || experiment == "read-extra-field" {
        let mut fields = vec![ReadField::Customer, ReadField::RecordId, ReadField::Version];
        if experiment == "read-extra-field" {
            fields.insert(0, ReadField::CreatedAt);
        }
        return Ok(RecordsActionV1::Read(ReadRecordV1 {
            profile: "auths.demo.records.read/1".into(),
            namespace_id,
            record_id,
            allowed_fields: fields,
            maximum_response_bytes: 4096,
            expected_record_version: 1,
            policy_digest,
            required_evaluator: "auths.records.read-evaluator/1".into(),
            required_configuration_digest: configuration_digest,
            executor_audience: policy.executor_audience.clone(),
            expires_at: now + 300,
            nonce: random_id("nonce")?,
        }));
    }
    Ok(RecordsActionV1::Create(CreateRecordV1 {
        profile: "auths.demo.records.create/1".into(),
        namespace_id,
        record_id,
        customer: if experiment == "value-too-large" {
            CustomerRecordV1 {
                notes: "x".repeat(1025),
                ..customer
            }
        } else {
            customer
        },
        value_encoding: "auths.demo.customer-record/1".into(),
        expected_absent: true,
        policy_digest,
        required_evaluator: "auths.records.create-evaluator/1".into(),
        required_configuration_digest: configuration_digest,
        executor_audience: if experiment == "wrong-audience" {
            "https://wrong-executor.invalid".into()
        } else {
            policy.executor_audience.clone()
        },
        expires_at: now + 300,
        nonce: random_id("nonce")?,
    }))
}

fn required_header(headers: &HeaderMap, name: &'static str) -> Result<String, ApiError> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
        .ok_or_else(|| ApiError::bad_request("required Auths carrier header is missing"))
}

fn random_id(prefix: &str) -> Result<String, ApiError> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(format!("{prefix}-{}", hex::encode(bytes)))
}

fn now() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal())
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[derive(Clone, Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: String,
}

impl ApiError {
    fn bad_request(detail: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad-request",
            detail: detail.into(),
        }
    }

    fn not_found(detail: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not-found",
            detail: detail.into(),
        }
    }

    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal-error",
            detail: "the native records service could not complete the request".into(),
        }
    }

    fn service_unavailable(detail: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "iroh-unavailable",
            detail: detail.into(),
        }
    }

    fn owned_bad_request(detail: String) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad-request",
            detail,
        }
    }

    fn detail_owned(&self) -> String {
        self.detail.clone()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
                "code": self.code,
                "detail": self.detail
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
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    use super::*;

    fn test_app() -> (Router, TempDir) {
        let (router, _, directory) = test_app_with_state();
        (router, directory)
    }

    fn test_app_with_state() -> (Router, AppState, TempDir) {
        let directory = TempDir::new().unwrap();
        let config = AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_origin: HeaderValue::from_static("*"),
            state_path: directory.path().join("ledger.json"),
            executor_audience: "https://records-executor.auths.dev".into(),
            public_base_url: "http://localhost:4180".into(),
            iroh_endpoint: "test".into(),
            region: "test".into(),
            release: "test".into(),
        };
        let (router, state) = app_with_iroh(config, None).unwrap();
        (router, state, directory)
    }

    struct FailAfterCreateLedger {
        inner: Arc<dyn RecordsLedger>,
        fail_create_once: Mutex<bool>,
        fail_completed_once: Mutex<bool>,
        create_calls: Mutex<u32>,
    }

    impl RecordsLedger for FailAfterCreateLedger {
        fn create(
            &self,
            command: auths_records_api::SealedCreateRecordCommand,
        ) -> Result<auths_records_api::CreateTransition, auths_records_api::RecordsError> {
            *self.create_calls.lock().unwrap() += 1;
            let result = self.inner.create(command)?;
            let mut fail = self.fail_create_once.lock().unwrap();
            if *fail {
                *fail = false;
                Err(auths_records_api::RecordsError::StateUnavailable)
            } else {
                Ok(result)
            }
        }

        fn read(
            &self,
            command: auths_records_api::SealedReadRecordCommand,
        ) -> Result<auths_records_api::ReadTransition, auths_records_api::RecordsError> {
            self.inner.read(command)
        }

        fn completed(
            &self,
            action_digest: &str,
        ) -> Result<
            Option<auths_records_api::CompletedRecordsAction>,
            auths_records_api::RecordsError,
        > {
            let mut fail = self.fail_completed_once.lock().unwrap();
            if *fail {
                *fail = false;
                Err(auths_records_api::RecordsError::StateUnavailable)
            } else {
                self.inner.completed(action_digest)
            }
        }

        fn append_receipt(
            &self,
            receipt: ReceiptBundle,
        ) -> Result<(), auths_records_api::RecordsError> {
            self.inner.append_receipt(receipt)
        }

        fn receipt(
            &self,
            receipt_id: &str,
        ) -> Result<Option<ReceiptBundle>, auths_records_api::RecordsError> {
            self.inner.receipt(receipt_id)
        }

        fn usage(
            &self,
            policy_digest: &str,
        ) -> Result<auths_records_api::Usage, auths_records_api::RecordsError> {
            self.inner.usage(policy_digest)
        }

        fn state_commitment(&self) -> Result<String, auths_records_api::RecordsError> {
            self.inner.state_commitment()
        }
    }

    async fn issue(router: &Router, experiment: &str) -> Value {
        issue_with_source(router, experiment, None).await
    }

    async fn issue_with_source(
        router: &Router,
        experiment: &str,
        source_session_id: Option<&str>,
    ) -> Value {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "experiment": experiment,
                            "source_session_id": source_session_id
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    async fn execute_create(router: &Router, session: &Value) -> Value {
        let action = &session["action"]["action"];
        let response = router
            .clone()
            .oneshot(
                Request::post("/v1/records")
                    .header(CONTENT_TYPE, "application/json")
                    .header("auths-session", session["session_id"].as_str().unwrap())
                    .header("auths-proof", session["proof_hex"].as_str().unwrap())
                    .header(
                        "auths-presentation",
                        session["presentation_hex"].as_str().unwrap(),
                    )
                    .body(Body::from(
                        serde_json::to_vec(&json!({
                            "record_id": action["record_id"],
                            "customer": action["customer"]
                        }))
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    async fn execute_read(router: &Router, session: &Value) -> Value {
        let record_id = session["action"]["action"]["record_id"].as_str().unwrap();
        let response = router
            .clone()
            .oneshot(
                Request::get(format!("/v1/records/{record_id}"))
                    .header("auths-session", session["session_id"].as_str().unwrap())
                    .header("auths-proof", session["proof_hex"].as_str().unwrap())
                    .header(
                        "auths-presentation",
                        session["presentation_hex"].as_str().unwrap(),
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(
            &to_bytes(response.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn exact_http_create_uses_real_auths_kernel_and_no_api_key() {
        let (router, _directory) = test_app();
        let session = issue(&router, "exact-create").await;
        assert_eq!(session["reusable_api_key_present"], false);
        let outcome = execute_create(&router, &session).await;
        assert_eq!(
            outcome["receipt"]["decision"]["decision"]["class"],
            "authorized"
        );
        assert_eq!(outcome["reusable_api_key_present"], false);
        assert_eq!(outcome["receipt"]["delivery"]["adapter"], "https");
        assert_eq!(
            outcome["receipt"]["decision"]["auths_decision"],
            "authorized"
        );
        assert_eq!(
            outcome["receipt"]["decision"]["protected_storage_accessed"],
            false
        );
        assert_eq!(outcome["receipt"]["execution"], "executed");
    }

    #[tokio::test]
    async fn configuration_drift_denies_before_proof_or_storage() {
        let (router, _directory) = test_app();
        let session = issue(&router, "configuration-mismatch").await;
        let outcome = execute_create(&router, &session).await;
        assert_eq!(
            outcome["receipt"]["decision"]["decision"]["code"],
            "verifier-configuration-mismatch"
        );
        assert_eq!(
            outcome["receipt"]["decision"]["protected_storage_accessed"],
            false
        );
        assert_eq!(outcome["receipt"]["decision"]["auths_decision"], "not-run");
        assert_eq!(
            outcome["receipt"]["decision"]["required_configuration"]["maximum_response_bytes"],
            4097
        );
        assert_eq!(
            outcome["receipt"]["decision"]["executed_configuration"]["maximum_response_bytes"],
            4096
        );
    }

    #[tokio::test]
    async fn one_changed_proof_byte_is_denied_before_storage() {
        let (router, _directory) = test_app();
        let session = issue(&router, "invalid-proof").await;
        let outcome = execute_create(&router, &session).await;
        assert_eq!(
            outcome["receipt"]["decision"]["decision"]["code"],
            "proof-invalid"
        );
        assert_eq!(
            outcome["receipt"]["decision"]["protected_storage_accessed"],
            false
        );
    }

    #[tokio::test]
    async fn exact_read_discloses_only_after_an_authorized_create() {
        let (router, _directory) = test_app();
        let create = issue(&router, "exact-create").await;
        let create_outcome = execute_create(&router, &create).await;
        assert_eq!(
            create_outcome["receipt"]["decision"]["decision"]["class"],
            "authorized"
        );
        let read = issue_with_source(&router, "exact-read", create["session_id"].as_str()).await;
        let read_outcome = execute_read(&router, &read).await;
        assert_eq!(
            read_outcome["receipt"]["decision"]["decision"]["class"],
            "authorized"
        );
        assert_eq!(read_outcome["response"]["customer"]["name"], "Bob Martinez");
        assert_eq!(read_outcome["response"]["customer"]["age"], 25);
        assert_eq!(
            read_outcome["response"]["customer"]["occupation"],
            "Sales manager"
        );
        assert_eq!(
            read_outcome["response"]["customer"]["notes"],
            "Interested in the enterprise analytics plan."
        );
        assert!(!read_outcome["receipt"].to_string().contains("Bob Martinez"));
        assert_eq!(read_outcome["receipt"]["effect"]["effect"], "read");
    }

    #[tokio::test]
    async fn oversized_customer_payload_is_a_policy_denial_not_a_malformed_action() {
        let (router, _directory) = test_app();
        let session = issue(&router, "value-too-large").await;
        let outcome = execute_create(&router, &session).await;
        assert_eq!(
            outcome["receipt"]["decision"]["decision"]["code"],
            "value-limit-exceeded"
        );
        assert_eq!(
            outcome["receipt"]["decision"]["protected_storage_accessed"],
            false
        );
        assert!(outcome["response"].is_null());
    }

    #[tokio::test]
    async fn bounded_grant_conserves_capacity_across_distinct_exact_actions() {
        let (router, _directory) = test_app();
        let mut session = issue(&router, "bounded-create").await;
        for expected in 1..=3 {
            let outcome = execute_create(&router, &session).await;
            assert_eq!(
                outcome["receipt"]["decision"]["decision"]["class"],
                "authorized"
            );
            assert_eq!(outcome["receipt"]["effect"]["create_units_after"], expected);
            session =
                issue_with_source(&router, "bounded-create", session["session_id"].as_str()).await;
        }
        let denied = execute_create(&router, &session).await;
        assert_eq!(
            denied["receipt"]["decision"]["decision"]["code"],
            "authorized"
        );
        assert_eq!(denied["receipt"]["execution"], "definite-non-effect");
        assert_eq!(
            denied["receipt"]["effect"]["code"],
            "shared-create-capacity-exhausted"
        );
    }

    #[tokio::test]
    async fn replay_gets_a_distinct_receipt_without_overwriting_authorization() {
        let (router, _directory) = test_app();
        let session = issue(&router, "exact-create").await;
        let authorized = execute_create(&router, &session).await;
        let replay = execute_create(&router, &session).await;
        let authorized_id = authorized["receipt"]["decision"]["receipt_id"]
            .as_str()
            .unwrap();
        let replay_id = replay["receipt"]["decision"]["receipt_id"]
            .as_str()
            .unwrap();

        assert_ne!(authorized_id, replay_id);
        assert_eq!(
            replay["receipt"]["decision"]["decision"]["code"],
            "authorized"
        );
        assert_eq!(replay["receipt"]["execution"], "replay-effect");

        for id in [authorized_id, replay_id] {
            let response = router
                .clone()
                .oneshot(
                    Request::get(format!("/api/v1/receipts/{id}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let receipt: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 2 * 1024 * 1024)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(receipt["decision"]["decision"]["code"], "authorized");
        }
    }

    #[tokio::test]
    async fn call_entry_failure_reconciles_without_provider_resubmission() {
        let (router, mut state, _directory) = test_app_with_state();
        let session = issue(&router, "exact-create").await;
        let fault = Arc::new(FailAfterCreateLedger {
            inner: Arc::clone(&state.ledger),
            fail_create_once: Mutex::new(true),
            fail_completed_once: Mutex::new(true),
            create_calls: Mutex::new(0),
        });
        let fault_ledger: Arc<dyn RecordsLedger> = fault.clone();
        state.ledger = fault_ledger;
        let session_id = session["session_id"].as_str().unwrap();

        let first = with_session(&state, session_id, |session| {
            execute_session(&state, session, DeliveryAdapter::Memory, "fault-injection")
        })
        .unwrap();
        assert_eq!(
            first.receipt.execution,
            auths_records_api::ExecutionClassification::OutcomeUnknown
        );
        let competing = issue_with_source(&router, "exact-create", Some(session_id)).await;
        let held = execute_create(&router, &competing).await;
        assert_eq!(held["receipt"]["execution"], "definite-non-effect");
        assert_eq!(
            held["receipt"]["effect"]["code"],
            "shared-create-capacity-exhausted"
        );
        let recovered = with_session(&state, session_id, |session| {
            execute_session(&state, session, DeliveryAdapter::Memory, "restart")
        })
        .unwrap();
        assert_eq!(
            recovered.receipt.execution,
            auths_records_api::ExecutionClassification::ReplayEffect
        );
        assert_eq!(*fault.create_calls.lock().unwrap(), 1);
    }

    #[tokio::test]
    #[ignore = "requires local UDP sockets for the real Iroh adapter"]
    async fn iroh_executes_and_https_replay_cannot_duplicate_the_effect() {
        let directory = TempDir::new().unwrap();
        let endpoint = Endpoint::builder(presets::N0)
            .alpns(vec![auths_proof_exchange_iroh::ALPN_V1.to_vec()])
            .bind()
            .await
            .unwrap();
        let target = endpoint.addr();
        let config = AppConfig {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_origin: HeaderValue::from_static("*"),
            state_path: directory.path().join("ledger.json"),
            executor_audience: "https://records-executor.auths.dev".into(),
            public_base_url: "http://localhost:4180".into(),
            iroh_endpoint: hex::encode(serde_json::to_vec(&target).unwrap()),
            region: "test".into(),
            release: "test".into(),
        };
        let (router, state) = app_with_iroh(config, Some(target)).unwrap();
        let server_endpoint = endpoint.clone();
        let server = tokio::spawn(serve_iroh(server_endpoint, state));
        let session = issue(&router, "exact-create").await;
        let id = session["session_id"].as_str().unwrap();
        let iroh_response = router
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{id}/execute-iroh"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(iroh_response.status(), StatusCode::OK);
        let iroh_outcome: Value = serde_json::from_slice(
            &to_bytes(iroh_response.into_body(), 2 * 1024 * 1024)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(iroh_outcome["receipt"]["delivery"]["adapter"], "iroh");
        assert_eq!(
            iroh_outcome["receipt"]["decision"]["decision"]["class"],
            "authorized"
        );

        let replay = execute_create(&router, &session).await;
        assert_eq!(
            replay["receipt"]["decision"]["decision"]["code"],
            "authorized"
        );
        assert_eq!(replay["receipt"]["execution"], "replay-effect");
        endpoint.close().await;
        server.abort();
    }
}
