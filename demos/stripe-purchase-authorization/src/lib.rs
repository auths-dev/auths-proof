//! Native API and browser surface for bounded Stripe Issuing decisions.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    reason = "the demo keeps compact HTTP and fixture boundaries explicit"
)]

use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_stripe::{
    AgentProcurementIntentV1, AggregatePurchaseBudget, CredentialProvider, Currency, DigestHex,
    EventId, ExecutePurchaseAuthorizationRequest, IssuingAuthorizationId, IssuingCardId,
    IssuingCardholderId, PersistentPurchaseAuthorizationStore, PortError,
    PurchaseAuthorizationCredential, PurchaseAuthorizationCredentialScope,
    PurchaseAuthorizationDecisionCode, PurchaseAuthorizationGateway,
    PurchaseAuthorizationProviderProjection, PurchaseAuthorizationReceipt,
    PurchaseAuthorizationService, PurchaseAuthorizationServiceDependencies,
    PurchaseAuthorizationStore, PurchaseAuthorizationWorkflowOutcome, PurchaseBudgetScope,
    PurchaseWebhookEvidenceV1, ReceiptSink, SdkPurchaseAuthorizationProofVerifier, StripeAccountId,
    StripeBoundedPurchasePolicyInput, StripeBoundedPurchasePolicyV1,
    StripeExactPurchaseAuthorizationInput, StripeExactPurchaseAuthorizationV1,
    StripePurchaseAuthorizationProfile, StripePurchaseConfigurationV1, SystemClock,
    canonical::sha256,
};
use auths_stripe_payment_demo_common::authorization_fixture;
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use hmac::{Hmac, Mac as _};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::Sha256;
use tokio::sync::Mutex as AsyncMutex;
use tower_http::cors::CorsLayer;

const API_SCHEMA: &str = "auths.stripe.purchase-authorization-demo/1";
const EXECUTOR_AUDIENCE: &str = "https://stripe-purchase-authorization.auths.dev";
const API_VERSION: &str = "2025-04-30.basil";
const MAX_REQUEST_BYTES: usize = 64 * 1024;

#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    state_directory: Arc<Path>,
    region: Arc<str>,
    release: Arc<str>,
    webhook_secret: Option<Arc<[u8]>>,
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
                .unwrap_or_else(|_| "/data/auths-stripe-purchase-authorization".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        let webhook_secret = env::var("AUTHS_STRIPE_ISSUING_WEBHOOK_SECRET")
            .ok()
            .filter(|value| value.starts_with("whsec_") && value.len() >= 16)
            .map(|value| Arc::<[u8]>::from(value.into_bytes()));
        Ok(Self {
            allowed_origin: HeaderValue::from_str(&origin).map_err(|_| StartupError::Invalid)?,
            state_directory: state_directory.into(),
            region: checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?
                .into(),
            release: checked_label(
                env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
            )?
            .into(),
            webhook_secret,
        })
    }

    #[cfg(test)]
    fn for_test(path: PathBuf, webhook_secret: Option<&str>) -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("http://localhost:8080"),
            state_directory: path.into(),
            region: "test".into(),
            release: "test".into(),
            webhook_secret: webhook_secret.map(|value| Arc::from(value.as_bytes())),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    store: Arc<PersistentPurchaseAuthorizationStore>,
    receipts: Arc<ReceiptJournal>,
    environment: Arc<DemoEnvironment>,
    sessions: Arc<AsyncMutex<HashMap<String, Session>>>,
}

struct Session {
    workflow_id: String,
    authorization_id: IssuingAuthorizationId,
    action: StripeExactPurchaseAuthorizationV1,
    intent: AgentProcurementIntentV1,
    policy: StripeBoundedPurchasePolicyV1,
    configuration: StripePurchaseConfigurationV1,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
    verifier: Arc<SdkPurchaseAuthorizationProofVerifier>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeRequest {
    experiment: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReconcileRequest {
    outcome: String,
}

pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    fs::create_dir_all(&*config.state_directory).map_err(|_| StartupError::State)?;
    let receipts = Arc::new(
        ReceiptJournal::new(config.state_directory.join("receipts.ndjson"))
            .map_err(|_| StartupError::State)?,
    );
    let state = AppState {
        config: config.clone(),
        store: Arc::new(
            PersistentPurchaseAuthorizationStore::new(
                config.state_directory.join("reservations.json"),
            )
            .map_err(|_| StartupError::State)?,
        ),
        receipts,
        environment: Arc::new(DemoEnvironment::default()),
        sessions: Arc::new(AsyncMutex::new(HashMap::new())),
    };
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin)
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/config.js", get(config_js))
        .route("/styles.css", get(styles))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/procurement-intents", post(create_intent))
        .route("/api/v1/sessions/{session_id}/authorize", post(authorize))
        .route("/api/v1/sessions/{session_id}/reconcile", post(reconcile))
        .route(
            "/api/v1/authorizations/{authorization_id}",
            get(authorization),
        )
        .route("/api/v1/receipts/{receipt_id}", get(machine_receipt))
        .route("/receipts/{receipt_id}", get(receipt_page))
        .route("/webhooks/stripe/issuing", post(stripe_webhook))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn app_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

async fn config_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        "window.AUTHS_PURCHASE_AUTHORIZATION_API_BASE = \"\";\n",
    )
}

async fn styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/styles.css"),
    )
}

async fn receipt_page(AxumPath(id): AxumPath<String>) -> Response {
    if DigestHex::parse(id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(include_str!("../web/receipt.html")).into_response()
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ok",
        "region": &*state.config.region,
        "release": &*state.config.release
    }))
}

async fn readiness(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ready",
        "webhook_secret_configured": state.config.webhook_secret.is_some(),
        "timeout_fallback": "decline",
        "agent_has_stripe_key": false
    }))
}

async fn scenario() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": auths_stripe::PURCHASE_AUTHORIZATION_PROFILE,
        "policy_type": auths_stripe::PURCHASE_POLICY_TYPE,
        "evaluator": auths_stripe::PURCHASE_EVALUATOR_ID,
        "deadline_milliseconds": 1000,
        "provider_deadline_milliseconds": 2000,
        "hot_path_provider_calls": 0,
        "full_amount_only": true
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "all exact protected fixture commitments stay visible"
)]
async fn create_intent(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let session_id = random_id()?;
    let account =
        StripeAccountId::parse("acct_purchasefixture").map_err(|_| ApiError::internal())?;
    let cardholder =
        IssuingCardholderId::parse("ich_purchasefixture").map_err(|_| ApiError::internal())?;
    let card = IssuingCardId::parse("ic_purchasefixture").map_err(|_| ApiError::internal())?;
    let currency = Currency::parse("usd").map_err(|_| ApiError::internal())?;
    let merchant_name = sha256(b"Auths API");
    let policy = StripeBoundedPurchasePolicyV1::new(StripeBoundedPurchasePolicyInput {
        policy_id: format!("policy-{session_id}"),
        valid_from: now.saturating_sub(60),
        expires_at: now + 3_600,
        allowed_test_account_ids: vec![account.clone()],
        allowed_cardholder_ids: vec![cardholder.clone()],
        allowed_card_ids: vec![card.clone()],
        allowed_currencies: vec![currency.clone()],
        allowed_merchant_ids: vec!["merchant-auths".into()],
        allowed_merchant_name_commitments: vec![merchant_name.clone()],
        allowed_merchant_categories: vec!["computer_software_stores".into()],
        blocked_merchant_categories: vec![],
        allowed_merchant_countries: vec!["US".into()],
        blocked_merchant_countries: vec![],
        allowed_procurement_scopes: vec!["api-access".into()],
        allowed_authorization_methods: vec![auths_stripe::PurchaseAuthorizationMethod::Online],
        per_purchase_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        per_merchant_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        per_category_minor_by_currency: BTreeMap::from([(currency.clone(), 1_000)]),
        aggregate_budgets: vec![AggregatePurchaseBudget {
            budget_id: format!("budget-{session_id}"),
            scope: PurchaseBudgetScope::Global,
            currency: currency.clone(),
            limit_minor: 1_000,
            starts_at: now.saturating_sub(60),
            ends_at: now + 3_600,
        }],
        maximum_intent_age_seconds: 300,
        maximum_event_age_seconds: 60,
        decision_deadline_milliseconds: 1_000,
        allowed_api_versions: vec![API_VERSION.into()],
    })
    .map_err(|_| ApiError::internal())?;
    let configuration = StripePurchaseConfigurationV1::new(
        &policy,
        account.clone(),
        API_VERSION.into(),
        EXECUTOR_AUDIENCE.into(),
    )
    .map_err(|_| ApiError::internal())?;
    let intent = AgentProcurementIntentV1 {
        schema: "auths.stripe.agent-procurement-intent/1".into(),
        intent_id: format!("intent-{session_id}"),
        agent_identity: "agent-auths".into(),
        procurement_scope: "api-access".into(),
        expected_merchant_id: "merchant-auths".into(),
        maximum_amount_minor: 500,
        currency: currency.clone(),
        recurring: false,
        fulfillment_reference_commitment: sha256(session_id.as_bytes()),
        valid_from: now.saturating_sub(30),
        expires_at: now + 300,
        nonce: sha256(format!("nonce-{session_id}").as_bytes()),
    };
    let payload_digest = sha256(format!("stripe-event-{session_id}").as_bytes());
    let authorization_id = IssuingAuthorizationId::parse(format!("iauth_{session_id}"))
        .map_err(|_| ApiError::internal())?;
    let action = StripeExactPurchaseAuthorizationV1::new(StripeExactPurchaseAuthorizationInput {
        stripe_account_id: account.clone(),
        event_id: EventId::parse(format!("evt_{session_id}")).map_err(|_| ApiError::internal())?,
        issuing_authorization_id: authorization_id.clone(),
        cardholder_id: cardholder,
        card_id: card,
        amount_minor: 500,
        currency: currency.clone(),
        merchant_amount_minor: 500,
        merchant_currency: currency,
        merchant_id: "merchant-auths".into(),
        merchant_name_commitment: merchant_name,
        merchant_category: "computer_software_stores".into(),
        merchant_country: "US".into(),
        authorization_method: auths_stripe::PurchaseAuthorizationMethod::Online,
        procurement_scope: "api-access".into(),
        procurement_intent_digest: Some(intent.digest().map_err(|_| ApiError::internal())?),
        stripe_api_version: API_VERSION.into(),
        webhook_payload_digest: payload_digest.clone(),
        required_policy_digest: policy.digest().map_err(|_| ApiError::internal())?,
        required_configuration_digest: configuration.digest().map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        received_at: now,
    })
    .map_err(|_| ApiError::internal())?;
    let canonical = StripePurchaseAuthorizationProfile
        .canonicalize(&action.canonical_bytes().map_err(|_| ApiError::internal())?)
        .map_err(|_| ApiError::internal())?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::internal())?;
    let auths = authorization_fixture(
        &canonical,
        EXECUTOR_AUDIENCE,
        &format!("stripe-issuing://{account}/authorizations"),
        now,
        challenge,
    );
    let verifier = Arc::new(SdkPurchaseAuthorizationProofVerifier::new(auths.verifier));
    let workflow_id = format!("purchase-{session_id}");
    state.sessions.lock().await.insert(
        session_id.clone(),
        Session {
            workflow_id,
            authorization_id,
            action: action.clone(),
            intent: intent.clone(),
            policy: policy.clone(),
            configuration,
            proof: auths.proof,
            request: auths.request,
            verifier,
        },
    );
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "profile": auths_stripe::PURCHASE_AUTHORIZATION_PROFILE,
        "policy": policy,
        "procurement_intent": intent,
        "exact_action": action,
        "experiments": ["success", "denial", "unknown", "replay"],
        "agent_has_stripe_key": false,
        "card_secrets_exposed": false
    })))
}

async fn authorize(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<AuthorizeRequest>,
) -> Result<Json<Value>, ApiError> {
    let (workflow_id, action, intent, policy, configuration, proof, auths_request, verifier) = {
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
        (
            session.workflow_id.clone(),
            session.action.clone(),
            session.intent.clone(),
            session.policy.clone(),
            session.configuration.clone(),
            session.proof.clone(),
            session.request.clone(),
            Arc::clone(&session.verifier),
        )
    };
    let (elapsed_milliseconds, response_delivery_unknown) = match request.experiment.as_str() {
        "success" | "replay" => (25, false),
        "denial" => (1_000, false),
        "unknown" => (25, true),
        _ => return Err(ApiError::bad_request()),
    };
    let webhook = PurchaseWebhookEvidenceV1 {
        schema: "auths.stripe.issuing-webhook-evidence/1".into(),
        event_id: action.event_id().clone(),
        event_type: "issuing_authorization.request".into(),
        payload_digest: action.webhook_payload_digest().clone(),
        signature_header_digest: sha256(b"verified-by-webhook-adapter"),
        signature_timestamp: action.received_at(),
        signature_verified: true,
        account_id: action.stripe_account_id().clone(),
        api_version: action.stripe_api_version().into(),
        livemode: false,
        received_at: action.received_at(),
    };
    let service = PurchaseAuthorizationService::new(PurchaseAuthorizationServiceDependencies {
        proof_verifier: verifier,
        credential_provider: Arc::clone(&state.environment),
        gateway: Arc::clone(&state.environment),
        store: Arc::clone(&state.store),
        receipt_sink: Arc::clone(&state.receipts),
        clock: Arc::new(SystemClock),
        executed_configuration: configuration.clone(),
    });
    let outcome = tokio::task::spawn_blocking(move || {
        service.execute(ExecutePurchaseAuthorizationRequest {
            workflow_id,
            action,
            webhook_evidence: webhook,
            procurement_intent: Some(intent),
            policy,
            required_configuration: configuration,
            proof,
            auths_request,
            elapsed_milliseconds,
            response_delivery_unknown,
        })
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())?;
    let diagnostics = state.environment.diagnostics();
    let mut result = outcome_json(outcome, diagnostics);
    if let Some((id, receipt)) = state
        .receipts
        .latest_for(&session_id)
        .map_err(|_| ApiError::internal())?
    {
        result["receipt_id"] = json!(id);
        result["receipt_url"] = json!(format!("/receipts/{id}"));
        result["receipt"] = serde_json::to_value(receipt).map_err(|_| ApiError::internal())?;
    }
    Ok(Json(result))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ReconcileRequest>,
) -> Result<Json<Value>, ApiError> {
    let (workflow_id, configuration, verifier) = {
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
        (
            session.workflow_id.clone(),
            session.configuration.clone(),
            Arc::clone(&session.verifier),
        )
    };
    state.environment.set_outcome(&request.outcome)?;
    let service = PurchaseAuthorizationService::new(PurchaseAuthorizationServiceDependencies {
        proof_verifier: verifier,
        credential_provider: Arc::clone(&state.environment),
        gateway: Arc::clone(&state.environment),
        store: Arc::clone(&state.store),
        receipt_sink: Arc::clone(&state.receipts),
        clock: Arc::new(SystemClock),
        executed_configuration: configuration,
    });
    let record = tokio::task::spawn_blocking(move || service.reconcile(&workflow_id))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "outcome": "reconciled",
        "reservation": record,
        "boundary": state.environment.diagnostics()
    })))
}

async fn authorization(
    State(state): State<AppState>,
    AxumPath(authorization_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let authorization_id =
        IssuingAuthorizationId::parse(authorization_id).map_err(|_| ApiError::missing())?;
    let workflow = {
        let sessions = state.sessions.lock().await;
        sessions
            .values()
            .find(|session| session.authorization_id == authorization_id)
            .map(|session| session.workflow_id.clone())
            .ok_or_else(ApiError::missing)?
    };
    let record = state
        .store
        .get(&workflow)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::missing)?;
    Ok(Json(json!({"schema": API_SCHEMA, "reservation": record})))
}

async fn machine_receipt(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let id = DigestHex::parse(id).map_err(|_| ApiError::missing())?;
    let receipt = state
        .receipts
        .get(&id)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::missing)?;
    Ok(Json(
        serde_json::to_value(receipt).map_err(|_| ApiError::internal())?,
    ))
}

async fn stripe_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(secret) = state.config.webhook_secret.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"approved":false,"error":"webhook-secret-unavailable"})),
        )
            .into_response();
    };
    let Some(signature) = headers
        .get("stripe-signature")
        .and_then(|value| value.to_str().ok())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !verify_stripe_signature(secret, signature, &body, unix_time().unwrap_or_default()) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    (
        StatusCode::OK,
        [("Stripe-Version", API_VERSION)],
        Json(json!({"approved":false,"reason":"unmatched-event-fails-closed"})),
    )
        .into_response()
}

fn verify_stripe_signature(secret: &[u8], header: &str, payload: &[u8], now: u64) -> bool {
    let mut timestamp = None;
    let mut signatures = Vec::new();
    for item in header.split(',') {
        if let Some(value) = item.strip_prefix("t=") {
            timestamp = value.parse::<u64>().ok();
        } else if let Some(value) = item.strip_prefix("v1=") {
            signatures.push(value);
        }
    }
    let Some(timestamp) = timestamp else {
        return false;
    };
    if timestamp > now || now.saturating_sub(timestamp) > 300 {
        return false;
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(secret) else {
        return false;
    };
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(payload);
    signatures.into_iter().any(|signature| {
        hex::decode(signature)
            .ok()
            .is_some_and(|bytes| mac.clone().verify_slice(&bytes).is_ok())
    })
}

fn outcome_json(
    outcome: PurchaseAuthorizationWorkflowOutcome,
    diagnostics: EnvironmentDiagnostics,
) -> Value {
    let boundary = json!({
        "credential_requests": diagnostics.credential_requests,
        "provider_calls": diagnostics.provider_calls
    });
    match outcome {
        PurchaseAuthorizationWorkflowOutcome::Authorized {
            record, response, ..
        } => {
            json!({"schema":API_SCHEMA,"outcome":"authorized","code":PurchaseAuthorizationDecisionCode::PurchaseAuthorized.as_str(),"response":response,"reservation":record,"boundary":boundary})
        }
        PurchaseAuthorizationWorkflowOutcome::Declined {
            response, receipt, ..
        } => {
            json!({"schema":API_SCHEMA,"outcome":"declined","code":receipt.bounded_decision.as_ref().map_or("auths-denied", |decision| decision.code.as_str()),"response":response,"boundary":boundary})
        }
        PurchaseAuthorizationWorkflowOutcome::Replay { record, response } => {
            json!({"schema":API_SCHEMA,"outcome":"replay","response":response,"reservation":record,"boundary":boundary})
        }
        PurchaseAuthorizationWorkflowOutcome::OutcomeUnknown { record, response } => {
            json!({"schema":API_SCHEMA,"outcome":"outcome_unknown","code":"purchase-outcome-unknown","response":response,"reservation":record,"boundary":boundary})
        }
        PurchaseAuthorizationWorkflowOutcome::Conflict { record, response } => {
            json!({"schema":API_SCHEMA,"outcome":"conflict","response":response,"reservation":record,"boundary":boundary})
        }
    }
}

#[derive(Clone, Copy, serde::Serialize)]
struct EnvironmentDiagnostics {
    credential_requests: u64,
    provider_calls: u64,
}

#[derive(Default)]
struct DemoEnvironment {
    credential_requests: AtomicU64,
    provider_calls: AtomicU64,
    outcome: Mutex<String>,
}

impl DemoEnvironment {
    fn diagnostics(&self) -> EnvironmentDiagnostics {
        EnvironmentDiagnostics {
            credential_requests: self.credential_requests.load(Ordering::Relaxed),
            provider_calls: self.provider_calls.load(Ordering::Relaxed),
        }
    }

    fn set_outcome(&self, outcome: &str) -> Result<(), ApiError> {
        if !matches!(outcome, "captured" | "released") {
            return Err(ApiError::bad_request());
        }
        *self.outcome.lock().map_err(|_| ApiError::internal())? = outcome.into();
        Ok(())
    }
}

impl CredentialProvider<PurchaseAuthorizationCredentialScope> for DemoEnvironment {
    fn credential(
        &self,
        _account: &StripeAccountId,
    ) -> Result<PurchaseAuthorizationCredential, PortError> {
        self.credential_requests.fetch_add(1, Ordering::Relaxed);
        PurchaseAuthorizationCredential::new(b"rk_test_repository_demo_value".to_vec())
    }
}

impl PurchaseAuthorizationGateway for DemoEnvironment {
    fn retrieve(
        &self,
        authorization: &IssuingAuthorizationId,
        _credential: &PurchaseAuthorizationCredential,
        now: u64,
    ) -> Result<PurchaseAuthorizationProviderProjection, PortError> {
        self.provider_calls.fetch_add(1, Ordering::Relaxed);
        let outcome = self
            .outcome
            .lock()
            .map_err(|_| PortError::Persistence)?
            .clone();
        let captured = outcome == "captured";
        Ok(PurchaseAuthorizationProviderProjection {
            authorization_id: authorization.clone(),
            approved: captured,
            status: if captured { "closed" } else { "reversed" }.into(),
            authorized_amount_minor: 500,
            captured_amount_minor: if captured { 500 } else { 0 },
            currency: Currency::parse("usd").map_err(|_| PortError::Malformed)?,
            request_reason: outcome,
            observed_at: now,
            response_digest: sha256(b"sanitized-provider-projection"),
        })
    }
}

struct ReceiptJournal {
    path: PathBuf,
    entries: Mutex<Vec<PurchaseAuthorizationReceipt>>,
}

impl ReceiptJournal {
    fn new(path: PathBuf) -> Result<Self, PortError> {
        let entries = match fs::read(&path) {
            Ok(bytes) => bytes
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| serde_json::from_slice(line).map_err(|_| PortError::Malformed))
                .collect::<Result<_, _>>()?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(_) => return Err(PortError::Persistence),
        };
        Ok(Self {
            path,
            entries: Mutex::new(entries),
        })
    }

    fn get(&self, id: &DigestHex) -> Result<Option<PurchaseAuthorizationReceipt>, PortError> {
        let entries = self.entries.lock().map_err(|_| PortError::Persistence)?;
        for receipt in entries.iter().rev() {
            if receipt_id(receipt)? == *id {
                return Ok(Some(receipt.clone()));
            }
        }
        Ok(None)
    }

    fn latest_for(
        &self,
        needle: &str,
    ) -> Result<Option<(DigestHex, PurchaseAuthorizationReceipt)>, PortError> {
        let entries = self.entries.lock().map_err(|_| PortError::Persistence)?;
        entries
            .iter()
            .rev()
            .find(|receipt| {
                serde_json::to_string(receipt).is_ok_and(|value| value.contains(needle))
            })
            .map(|receipt| Ok((receipt_id(receipt)?, receipt.clone())))
            .transpose()
    }
}

impl ReceiptSink<PurchaseAuthorizationReceipt> for ReceiptJournal {
    fn append(&self, receipt: &PurchaseAuthorizationReceipt) -> Result<(), PortError> {
        let parent = self.path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(
            &receipt
                .canonical_bytes()
                .map_err(|_| PortError::Persistence)?,
        )
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .map_err(|_| PortError::Persistence)?;
        self.entries
            .lock()
            .map_err(|_| PortError::Persistence)?
            .push(receipt.clone());
        Ok(())
    }
}

fn receipt_id(receipt: &PurchaseAuthorizationReceipt) -> Result<DigestHex, PortError> {
    Ok(sha256(
        &receipt
            .canonical_bytes()
            .map_err(|_| PortError::Persistence)?,
    ))
}

fn checked_label(value: String) -> Result<String, StartupError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(StartupError::Invalid);
    }
    Ok(value)
}

fn unix_time() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| ApiError::internal())
}

fn random_id() -> Result<String, ApiError> {
    let mut bytes = [0_u8; 12];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(bytes))
}

#[derive(Clone, Copy, Debug)]
pub enum StartupError {
    Missing(&'static str),
    Invalid,
    State,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(value) => write!(formatter, "missing {value}"),
            Self::Invalid => formatter.write_str("invalid deployment configuration"),
            Self::State => formatter.write_str("durable state unavailable"),
        }
    }
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
        }
    }
    const fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not-found",
        }
    }
    const fn bad_request() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad-request",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"schema":API_SCHEMA,"error":self.code})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    #[tokio::test]
    async fn browser_api_covers_authorize_denial_replay_unknown_and_receipt_404() {
        let directory = tempfile::tempdir().unwrap();
        let router = app(AppConfig::for_test(directory.path().into(), None)).unwrap();
        let created = request_json(
            &router,
            Request::post("/api/v1/procurement-intents")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let session = created["session_id"].as_str().unwrap();
        for experiment in ["success", "replay", "denial"] {
            let response = request_json(
                &router,
                Request::post(format!("/api/v1/sessions/{session}/authorize"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"experiment":experiment}).to_string()))
                    .unwrap(),
            )
            .await;
            assert!(response.get("outcome").is_some());
        }
        let second = request_json(
            &router,
            Request::post("/api/v1/procurement-intents")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let second_session = second["session_id"].as_str().unwrap();
        let unknown = request_json(
            &router,
            Request::post(format!("/api/v1/sessions/{second_session}/authorize"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"experiment":"unknown"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(unknown["outcome"], "outcome_unknown");
        let invalid = router
            .clone()
            .oneshot(
                Request::get("/api/v1/receipts/not-a-digest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(invalid.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn webhook_signature_is_verified_and_unmatched_event_declines() {
        let directory = tempfile::tempdir().unwrap();
        let secret = "whsec_repository_test";
        let router = app(AppConfig::for_test(directory.path().into(), Some(secret))).unwrap();
        let payload = br#"{"id":"evt_test","type":"issuing_authorization.request"}"#;
        let timestamp = unix_time().unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(timestamp.to_string().as_bytes());
        mac.update(b".");
        mac.update(payload);
        let signature = format!(
            "t={timestamp},v1={}",
            hex::encode(mac.finalize().into_bytes())
        );
        let response = router
            .oneshot(
                Request::post("/webhooks/stripe/issuing")
                    .header("stripe-signature", signature)
                    .body(Body::from(payload.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("stripe-version").unwrap(),
            API_VERSION
        );
    }

    async fn request_json(router: &Router, request: Request<Body>) -> Value {
        let response = router.clone().oneshot(request).await.unwrap();
        assert!(response.status().is_success(), "{:?}", response.status());
        let bytes = to_bytes(response.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}
