use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_stripe::{
    Currency, DigestHex, ExecutePaymentMandateRequest, MandateAmountType, MandateConnectAccount,
    MandateInterval, MandateUsage, PaymentConsentEvidenceInput, PaymentConsentEvidenceV1,
    PaymentMandateService, PaymentMandateServiceDependencies, PaymentMandateStore,
    PaymentMandateWorkflowOutcome, PersistentPaymentMandateStore, SdkPaymentMandateProofVerifier,
    StripeBoundedPaymentMandatePolicyInput, StripeBoundedPaymentMandatePolicyV1,
    StripeExactPaymentMandateInput, StripeExactPaymentMandateV1,
    StripePaymentMandateConfigurationV1, StripePaymentMandateProfile, SystemClock,
};
use auths_stripe_payment_demo_common::authorization_fixture;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{
        HeaderMap, HeaderValue, Method, StatusCode,
        header::{CONTENT_TYPE, COOKIE, SET_COOKIE},
    },
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{
    receipts::{ReceiptJournal, receipt_id},
    stripe::{DemoPaymentMandateEnvironment, LivePaymentMandateEnvironment},
};

const API_SCHEMA: &str = "auths.stripe.payment-mandate-demo/1";
const EXECUTOR_AUDIENCE: &str = "https://stripe-mandate-executor.auths.dev";
const TRUSTED_CONSENT_CONTEXT: &str = "auths-stripe-mandate-human-session-v1";
const TERMS: &str = "Synthetic test consent: save this repository-owned test card for off-session charges up to USD 5.00 monthly. No charge occurs now. Every future charge requires separate exact Auths authority and current bounded policy.";
const SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_SESSIONS: usize = 256;
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const AMOUNT_MINOR: u64 = 500;

/// Native mandate demo deployment configuration.
#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    state_directory: Arc<Path>,
    region: Arc<str>,
    release: Arc<str>,
    public_api_base: Arc<str>,
}

impl AppConfig {
    /// Loads strict local/cloud configuration.
    ///
    /// # Errors
    ///
    /// Rejects missing or unsafe deployment configuration.
    pub fn from_environment() -> Result<Self, StartupError> {
        let origin = env::var("AUTHS_STRIPE_ALLOWED_ORIGIN")
            .map_err(|_| StartupError::Missing("AUTHS_STRIPE_ALLOWED_ORIGIN"))?;
        if !(origin.starts_with("https://") || origin.starts_with("http://localhost:"))
            || origin.ends_with('/')
            || origin.len() > 256
        {
            return Err(StartupError::Invalid);
        }
        let allowed_origin = HeaderValue::from_str(&origin).map_err(|_| StartupError::Invalid)?;
        let state_directory = PathBuf::from(
            env::var("AUTHS_STRIPE_STATE_DIR")
                .unwrap_or_else(|_| "/data/auths-stripe-payment-mandate".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        let region = checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?;
        let release = checked_label(
            env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
        )?;
        let public_api_base = env::var("AUTHS_PAYMENT_MANDATE_PUBLIC_API_BASE").unwrap_or_default();
        if !public_api_base.is_empty()
            && (!(public_api_base.starts_with("https://")
                || public_api_base.starts_with("http://localhost:"))
                || public_api_base.ends_with('/')
                || public_api_base.len() > 256)
        {
            return Err(StartupError::Invalid);
        }
        Ok(Self {
            allowed_origin,
            state_directory: state_directory.into(),
            region: region.into(),
            release: release.into(),
            public_api_base: public_api_base.into(),
        })
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "used by route-level fixture environments")]
    pub(crate) fn for_test(path: PathBuf) -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("http://localhost:8080"),
            state_directory: path.into(),
            region: "test".into(),
            release: "test".into(),
            public_api_base: "".into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    environment: Arc<dyn DemoPaymentMandateEnvironment>,
    store: Arc<dyn PaymentMandateStore>,
    receipts: Arc<ReceiptJournal>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    workflow_id: String,
    human_token_digest: DigestHex,
    evidence: auths_stripe::PaymentMandateEvidenceV1,
    policy: StripeBoundedPaymentMandatePolicyV1,
    configuration: StripePaymentMandateConfigurationV1,
    consent: Option<PaymentConsentEvidenceV1>,
    exact: Option<Variant>,
    last_result: Option<Value>,
}

#[derive(Clone)]
struct Variant {
    action: StripeExactPaymentMandateV1,
    proof_verifier: Arc<SdkPaymentMandateProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentRequest {
    displayed_terms_digest: DigestHex,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    experiment: String,
}

/// Builds the real Stripe test-mode application.
///
/// # Errors
///
/// Returns an error when Stripe or durable state cannot initialize.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let environment = Arc::new(
        LivePaymentMandateEnvironment::from_environment().map_err(|_| StartupError::Stripe)?,
    );
    app_with_environment(config, environment)
}

/// Builds the application with an explicit mandate-only environment.
///
/// # Errors
///
/// Returns an error when durable state cannot initialize.
pub fn app_with_environment(
    config: AppConfig,
    environment: Arc<dyn DemoPaymentMandateEnvironment>,
) -> Result<Router, StartupError> {
    let store = Arc::new(
        PersistentPaymentMandateStore::new(config.state_directory.join("mandates.json"))
            .map_err(|_| StartupError::State)?,
    );
    let receipts = Arc::new(
        ReceiptJournal::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE])
        .allow_credentials(true);
    let state = AppState {
        config,
        environment,
        store,
        receipts,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    Ok(Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/config.js", get(config_js))
        .route("/styles.css", get(styles))
        .route("/receipt.js", get(receipt_js))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}", get(session_status))
        .route("/api/v1/sessions/{session_id}/consent", post(consent))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/sessions/{session_id}/reconcile", post(reconcile))
        .route(
            "/api/v1/sessions/{session_id}/setup-status",
            get(setup_status),
        )
        .route("/api/v1/receipts/{receipt_id}", get(machine_receipt))
        .route("/receipts/{receipt_id}", get(receipt_page))
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
async fn receipt_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/receipt.js"),
    )
}
async fn styles() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/css; charset=utf-8")],
        include_str!("../web/styles.css"),
    )
}

async fn config_js(State(state): State<AppState>) -> impl IntoResponse {
    let value =
        serde_json::to_string(&*state.config.public_api_base).unwrap_or_else(|_| "\"\"".into());
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        format!("window.AUTHS_PAYMENT_MANDATE_API_BASE = {value};\n"),
    )
}

async fn receipt_page(AxumPath(receipt_id): AxumPath<String>) -> Response {
    if DigestHex::parse(receipt_id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(include_str!("../web/receipt.html")).into_response()
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ok",
        "region": &*state.config.region,
        "release": &*state.config.release,
    }))
}

async fn readiness(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ready",
        "account_commitment": auths_stripe::canonical::sha256(
            state.environment.account_id().as_str().as_bytes()
        ),
        "api_version": state.environment.api_version(),
        "client_secret_exposed": false,
    }))
}

async fn scenario() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": auths_stripe::PAYMENT_MANDATE_PROFILE,
        "policy_type": auths_stripe::PAYMENT_MANDATE_POLICY_TYPE,
        "evaluator": auths_stripe::PAYMENT_MANDATE_EVALUATOR_ID,
        "effect": "setup-intent-create-confirm",
        "immediate_charge": false,
        "trusted_human_consent_required": true,
        "agent_has_stripe_key": false,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "one endpoint assembles all displayed trust inputs"
)]
async fn create_session(State(state): State<AppState>) -> Result<Response, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let session_id = random_id()?;
    let workflow_id = format!("mandate-{session_id}");
    let environment = Arc::clone(&state.environment);
    let seed = workflow_id.clone();
    let fixture = tokio::task::spawn_blocking(move || environment.seed_fixture(&seed, now))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::stripe_fixture())?;
    let policy = mandate_policy(&fixture, state.environment.as_ref(), now)?;
    let configuration = StripePaymentMandateConfigurationV1::new(
        &policy,
        state.environment.account_id().clone(),
        MandateConnectAccount::Platform,
        TRUSTED_CONSENT_CONTEXT.into(),
        state.environment.api_version().into(),
        EXECUTOR_AUDIENCE.into(),
    )
    .map_err(|_| ApiError::internal())?;
    let mut token = [0_u8; 32];
    getrandom::fill(&mut token).map_err(|_| ApiError::internal())?;
    let token_text = hex::encode(token);
    let token_digest = auths_stripe::canonical::sha256(token_text.as_bytes());
    let terms_digest = auths_stripe::canonical::sha256(TERMS.as_bytes());
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "profile": auths_stripe::PAYMENT_MANDATE_PROFILE,
        "terms": TERMS,
        "displayed_terms_digest": terms_digest,
        "consent": {"accepted": false, "authenticated_human_session": true},
        "future_scope": {
            "usage": "off_session",
            "amount_type": "maximum",
            "amount_minor": AMOUNT_MINOR,
            "currency": "usd",
            "interval": "monthly",
            "reference": format!("membership-{session_id}"),
        },
        "stripe_evidence": fixture.evidence,
        "policy": policy,
        "policy_digest": policy.digest().map_err(|_| ApiError::internal())?,
        "configuration": configuration,
        "experiments": [
            {"id":"success","label":"Exact mandate","detail":"Consent, then create and confirm one SetupIntent."},
            {"id":"denial","label":"Missing consent","detail":"Prove the exact action but omit trusted human consent; credential and Stripe counters stay zero."},
            {"id":"changed-configuration","label":"Changed configuration","detail":"Run a different implementation commitment; no decision or state is persisted."},
            {"id":"ambiguous","label":"Lost response","detail":"Create once, hold the capability slot as unknown, then retrieve it."},
            {"id":"replay","label":"Replay","detail":"Return durable capability state without another SetupIntent."}
        ],
        "no_immediate_charge": true,
        "agent_has_stripe_key": false,
        "client_secret_exposed": false,
    });
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, value| value.expires_at > now);
    if sessions.len() >= MAX_SESSIONS {
        return Err(ApiError::capacity());
    }
    sessions.insert(
        session_id.clone(),
        Session {
            expires_at: now + SESSION_TTL_SECONDS,
            workflow_id,
            human_token_digest: token_digest,
            evidence: fixture.evidence,
            policy,
            configuration,
            consent: None,
            exact: None,
            last_result: None,
        },
    );
    let cookie = format!(
        "auths_mandate_consent={token_text}; Path=/api/v1/sessions/{session_id}; HttpOnly; SameSite=Strict; Max-Age={SESSION_TTL_SECONDS}"
    );
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        HeaderValue::from_str(&cookie).map_err(|_| ApiError::internal())?,
    );
    Ok((headers, Json(response)).into_response())
}

async fn consent(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    headers: HeaderMap,
    Json(request): Json<ConsentRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions
        .get_mut(&session_id)
        .ok_or_else(ApiError::session_missing)?;
    if session.expires_at <= now || !human_cookie_matches(&headers, &session.human_token_digest) {
        return Err(ApiError::consent_required());
    }
    let expected_terms = auths_stripe::canonical::sha256(TERMS.as_bytes());
    if request.displayed_terms_digest != expected_terms {
        return Err(ApiError::consent_mismatch());
    }
    let consent = PaymentConsentEvidenceV1::new(PaymentConsentEvidenceInput {
        customer_id: session.evidence.customer_id().clone(),
        payment_method_commitment: auths_stripe::canonical::sha256(
            session.evidence.payment_method_id().as_str().as_bytes(),
        ),
        stripe_account_id: session.evidence.stripe_account_id().clone(),
        connect_account: session.evidence.connect_account().clone(),
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: AMOUNT_MINOR,
        currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
        interval: MandateInterval::Monthly,
        reference: format!("membership-{session_id}"),
        displayed_terms_digest: expected_terms,
        accepted_at: now,
        expires_at: session.expires_at,
        consent_principal: format!("trusted-human-{session_id}"),
        consent_assurance: 2,
        synthetic_test_consent: true,
    })
    .map_err(|_| ApiError::internal())?;
    let action = mandate_action(session, &consent, now, &session_id)?;
    let variant = proof_variant(&action, now)?;
    session.consent = Some(consent.clone());
    session.exact = Some(variant);
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "consent": consent,
        "exact_action": action,
        "accepted": true,
        "no_immediate_charge": true,
    })))
}

async fn execute(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let materials = {
        let sessions = state.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(ApiError::session_missing)?;
        execution_materials(session, &request.experiment)?
    };
    if request.experiment == "ambiguous" {
        state
            .environment
            .arm_ambiguous_once(&materials.workflow_id)
            .map_err(|_| ApiError::internal())?;
    }
    let before = state.environment.diagnostics();
    let environment = Arc::clone(&state.environment);
    let store = Arc::clone(&state.store);
    let receipts = Arc::clone(&state.receipts);
    let workflow_id = materials.workflow_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        PaymentMandateService::new(PaymentMandateServiceDependencies {
            proof_verifier: materials.variant.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            store,
            receipt_sink: receipts,
            clock: SystemClock,
            executed_configuration: materials.executed_configuration,
        })
        .execute(ExecutePaymentMandateRequest {
            workflow_id: materials.workflow_id,
            action: materials.variant.action,
            consent: materials.consent,
            evidence: materials.evidence,
            policy: materials.policy,
            required_configuration: materials.required_configuration,
            proof: materials.variant.proof,
            auths_request: materials.variant.request,
        })
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())?;
    let after = state.environment.diagnostics();
    let mut response = outcome_projection(
        outcome,
        after
            .credential_requests
            .saturating_sub(before.credential_requests),
        after.provider_calls.saturating_sub(before.provider_calls),
    );
    attach_latest_receipt(&state.receipts, &workflow_id, &mut response)?;
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_result = Some(response.clone());
    }
    Ok(Json(response))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let session = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&session_id)
            .ok_or_else(ApiError::session_missing)?
            .workflow_id
            .clone()
    };
    let materials = {
        let sessions = state.sessions.lock().await;
        execution_materials(
            sessions
                .get(&session_id)
                .ok_or_else(ApiError::session_missing)?,
            "success",
        )?
    };
    let before = state.environment.diagnostics();
    let environment = Arc::clone(&state.environment);
    let store = Arc::clone(&state.store);
    let receipts = Arc::clone(&state.receipts);
    let workflow_id = session.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        PaymentMandateService::new(PaymentMandateServiceDependencies {
            proof_verifier: materials.variant.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            store,
            receipt_sink: receipts,
            clock: SystemClock,
            executed_configuration: materials.executed_configuration,
        })
        .reconcile(&workflow_id)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())?;
    let after = state.environment.diagnostics();
    let mut response = outcome_projection(
        outcome,
        after
            .credential_requests
            .saturating_sub(before.credential_requests),
        after.provider_calls.saturating_sub(before.provider_calls),
    );
    attach_latest_receipt(&state.receipts, &session, &mut response)?;
    Ok(Json(response))
}

async fn session_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = state.sessions.lock().await;
    let session = sessions
        .get(&session_id)
        .ok_or_else(ApiError::session_missing)?;
    let active = state
        .store
        .active_count(
            session.evidence.stripe_account_id(),
            session.evidence.customer_id(),
        )
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "consent_accepted": session.consent.is_some(),
        "active_capability_slots": active,
        "last_result": session.last_result,
    })))
}

async fn setup_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    if !valid_session_id(&session_id) {
        return Err(ApiError::session_missing());
    }
    let workflow = format!("mandate-{session_id}");
    let record = state
        .store
        .get(&workflow)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::session_missing)?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "workflow_id": workflow,
        "capability": record,
        "no_immediate_charge": true,
        "client_secret_exposed": false,
        "agent_received_credential": false,
    })))
}

async fn machine_receipt(
    State(state): State<AppState>,
    AxumPath(receipt_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let receipt_id = DigestHex::parse(receipt_id).map_err(|_| ApiError::receipt_missing())?;
    let receipt = state
        .receipts
        .get(&receipt_id)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::receipt_missing)?;
    Ok(Json(json!({
        "schema": "auths.stripe.machine-readable-payment-mandate-receipt/1",
        "receipt_id": receipt_id,
        "receipt": receipt,
    })))
}

struct ExecutionMaterials {
    workflow_id: String,
    variant: Variant,
    consent: Option<PaymentConsentEvidenceV1>,
    evidence: auths_stripe::PaymentMandateEvidenceV1,
    policy: StripeBoundedPaymentMandatePolicyV1,
    required_configuration: StripePaymentMandateConfigurationV1,
    executed_configuration: StripePaymentMandateConfigurationV1,
}

fn execution_materials(
    session: &Session,
    experiment: &str,
) -> Result<ExecutionMaterials, ApiError> {
    let variant = session
        .exact
        .clone()
        .ok_or_else(ApiError::consent_required)?;
    let (workflow_id, consent, executed_configuration) = match experiment {
        "success" | "replay" | "ambiguous" => (
            session.workflow_id.clone(),
            session.consent.clone(),
            session.configuration.clone(),
        ),
        "denial" => (
            format!("{}-denied", session.workflow_id),
            None,
            session.configuration.clone(),
        ),
        "changed-configuration" => (
            format!("{}-configuration", session.workflow_id),
            session.consent.clone(),
            StripePaymentMandateConfigurationV1::new(
                &session.policy,
                session.evidence.stripe_account_id().clone(),
                MandateConnectAccount::Platform,
                "auths-stripe-mandate-changed-context-v1".into(),
                session.evidence.stripe_api_version().into(),
                EXECUTOR_AUDIENCE.into(),
            )
            .map_err(|_| ApiError::internal())?,
        ),
        _ => return Err(ApiError::unknown_experiment()),
    };
    Ok(ExecutionMaterials {
        workflow_id,
        variant,
        consent,
        evidence: session.evidence.clone(),
        policy: session.policy.clone(),
        required_configuration: session.configuration.clone(),
        executed_configuration,
    })
}

fn mandate_policy(
    fixture: &crate::stripe::MandateFixture,
    environment: &dyn DemoPaymentMandateEnvironment,
    now: u64,
) -> Result<StripeBoundedPaymentMandatePolicyV1, ApiError> {
    let currency = Currency::parse("usd").map_err(|_| ApiError::internal())?;
    StripeBoundedPaymentMandatePolicyV1::new(StripeBoundedPaymentMandatePolicyInput {
        valid_from: now.saturating_sub(60),
        expires_at: now + SESSION_TTL_SECONDS,
        allowed_test_account_ids: vec![environment.account_id().clone()],
        allowed_customer_ids: vec![fixture.customer_id.clone()],
        allowed_payment_method_ids: vec![fixture.payment_method_id.clone()],
        allowed_payment_method_types: vec!["card".into()],
        allowed_usage_modes: vec![MandateUsage::OffSession],
        allowed_currencies: vec![currency.clone()],
        allowed_intervals: vec![MandateInterval::Monthly],
        per_future_charge_minor_by_currency: BTreeMap::from([(currency, AMOUNT_MINOR)]),
        maximum_active_mandates_per_customer: 3,
        maximum_consent_age_seconds: SESSION_TTL_SECONDS,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: SESSION_TTL_SECONDS,
        required_consent_assurance: 2,
        allowed_api_versions: vec![environment.api_version().into()],
    })
    .map_err(|_| ApiError::internal())
}

fn mandate_action(
    session: &Session,
    consent: &PaymentConsentEvidenceV1,
    now: u64,
    nonce_material: &str,
) -> Result<StripeExactPaymentMandateV1, ApiError> {
    StripeExactPaymentMandateV1::new(StripeExactPaymentMandateInput {
        stripe_account_id: session.evidence.stripe_account_id().clone(),
        connect_account: session.evidence.connect_account().clone(),
        customer_id: session.evidence.customer_id().clone(),
        payment_method_id: session.evidence.payment_method_id().clone(),
        payment_method_type: session.evidence.payment_method_type().into(),
        usage: MandateUsage::OffSession,
        mandate_amount_type: MandateAmountType::Maximum,
        mandate_amount_minor: AMOUNT_MINOR,
        currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
        interval: MandateInterval::Monthly,
        reference: format!("membership-{nonce_material}"),
        consent_evidence_digest: consent.digest().map_err(|_| ApiError::internal())?,
        displayed_terms_digest: auths_stripe::canonical::sha256(TERMS.as_bytes()),
        on_behalf_of: None,
        return_url_commitment: None,
        stripe_api_version: session.evidence.stripe_api_version().into(),
        required_policy_digest: session.policy.digest().map_err(|_| ApiError::internal())?,
        required_configuration_digest: session
            .configuration
            .digest()
            .map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        expires_at: now + SESSION_TTL_SECONDS,
        nonce: auths_stripe::canonical::sha256(
            format!("auths-mandate-nonce-v1:{nonce_material}").as_bytes(),
        ),
    })
    .map_err(|_| ApiError::internal())
}

fn proof_variant(action: &StripeExactPaymentMandateV1, now: u64) -> Result<Variant, ApiError> {
    let canonical = StripePaymentMandateProfile
        .canonicalize(&action.canonical_bytes().map_err(|_| ApiError::internal())?)
        .map_err(|_| ApiError::internal())?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::internal())?;
    let namespace = format!("stripe-test://{}", action.stripe_account_id());
    let fixture = authorization_fixture(
        &canonical,
        action.executor_audience(),
        &namespace,
        now,
        challenge,
    );
    Ok(Variant {
        action: action.clone(),
        proof_verifier: Arc::new(SdkPaymentMandateProofVerifier::new(fixture.verifier)),
        proof: fixture.proof,
        request: fixture.request,
    })
}

fn outcome_projection(
    outcome: PaymentMandateWorkflowOutcome,
    credential_requests: u64,
    provider_calls: u64,
) -> Value {
    let boundary = json!({
        "credential_requests": credential_requests,
        "provider_calls": provider_calls,
        "agent_received_credential": false,
        "client_secret_exposed": false,
    });
    match outcome {
        PaymentMandateWorkflowOutcome::Rejected { receipt, persisted } => json!({
            "schema": API_SCHEMA, "outcome": "rejected", "decision": receipt,
            "persisted": persisted, "boundary": boundary, "no_immediate_charge": true,
        }),
        PaymentMandateWorkflowOutcome::Completed { code, record } => json!({
            "schema": API_SCHEMA, "outcome": "mandate-established", "code": code,
            "record": record, "boundary": boundary, "no_immediate_charge": true,
        }),
        PaymentMandateWorkflowOutcome::ProviderFailed { code, record } => json!({
            "schema": API_SCHEMA, "outcome": "provider-failed", "code": code,
            "record": record, "boundary": boundary, "no_immediate_charge": true,
        }),
        PaymentMandateWorkflowOutcome::CustomerActionRequired { record, projection } => json!({
            "schema": API_SCHEMA, "outcome": "customer-action-required", "record": record,
            "provider": projection, "boundary": boundary, "client_secret_exposed": false,
        }),
        PaymentMandateWorkflowOutcome::OutcomeUnknown { record, projection } => json!({
            "schema": API_SCHEMA, "outcome": "outcome-unknown", "record": record,
            "provider": projection, "boundary": boundary, "reconciliation_required": true,
        }),
        PaymentMandateWorkflowOutcome::Replay(record) => json!({
            "schema": API_SCHEMA, "outcome": "replay", "record": record,
            "boundary": boundary, "no_immediate_charge": true,
        }),
        PaymentMandateWorkflowOutcome::Conflict(record) => json!({
            "schema": API_SCHEMA, "outcome": "conflict", "record": record,
            "boundary": boundary,
        }),
    }
}

fn attach_latest_receipt(
    journal: &ReceiptJournal,
    workflow_id: &str,
    response: &mut Value,
) -> Result<(), ApiError> {
    let receipts = journal.read_all().map_err(|_| ApiError::internal())?;
    if let Some(receipt) = receipts
        .iter()
        .rev()
        .find(|receipt| receipt_workflow(receipt) == workflow_id)
    {
        let id = receipt_id(receipt).map_err(|_| ApiError::internal())?;
        response["receipt_id"] = json!(id);
        response["receipt_url"] = json!(format!("/receipts/{id}"));
        response["machine_receipt_url"] = json!(format!("/api/v1/receipts/{id}"));
        response["canonical_receipt"] =
            serde_json::to_value(receipt).map_err(|_| ApiError::internal())?;
    }
    Ok(())
}

fn receipt_workflow(receipt: &auths_stripe::PaymentMandateReceipt) -> &str {
    match receipt {
        auths_stripe::PaymentMandateReceipt::Decision(value) => &value.workflow_id,
        auths_stripe::PaymentMandateReceipt::Transition(value) => value.capability.workflow_id(),
        auths_stripe::PaymentMandateReceipt::Observation(value) => &value.workflow_id,
    }
}

fn human_cookie_matches(headers: &HeaderMap, expected: &DigestHex) -> bool {
    headers
        .get(COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookies| {
            cookies.split(';').find_map(|cookie| {
                cookie
                    .trim()
                    .strip_prefix("auths_mandate_consent=")
                    .map(str::to_owned)
            })
        })
        .is_some_and(|token| auths_stripe::canonical::sha256(token.as_bytes()) == *expected)
}

fn random_id() -> Result<String, ApiError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(random))
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn unix_time() -> Result<u64, StartupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StartupError::Clock)
}

fn checked_label(value: String) -> Result<String, StartupError> {
    if value.is_empty()
        || value.len() > 128
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
    {
        return Err(StartupError::Invalid);
    }
    Ok(value)
}

/// Closed startup failure without environment values.
#[derive(Debug)]
pub enum StartupError {
    Missing(&'static str),
    Invalid,
    Stripe,
    State,
    Clock,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => {
                write!(formatter, "missing required environment variable {name}")
            }
            Self::Invalid => formatter.write_str("invalid deployment configuration"),
            Self::Stripe => formatter.write_str("Stripe test-mode configuration is unavailable"),
            Self::State => formatter.write_str("durable payment-mandate state is unavailable"),
            Self::Clock => formatter.write_str("system clock is unavailable"),
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
            "internal-failure",
            "the protected payment-mandate service failed closed",
        )
    }
    const fn stripe_fixture() -> Self {
        Self::new(
            StatusCode::BAD_GATEWAY,
            "stripe-fixture-unavailable",
            "Stripe test mode could not prepare the synthetic Customer and PaymentMethod",
        )
    }
    const fn capacity() -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the mandate session pool is full",
        )
    }
    const fn session_missing() -> Self {
        Self::new(
            StatusCode::GONE,
            "session-unavailable",
            "the mandate session is missing or expired",
        )
    }
    const fn consent_required() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "payment-mandate-consent-required",
            "an authenticated trusted-human consent session is required",
        )
    }
    const fn consent_mismatch() -> Self {
        Self::new(
            StatusCode::CONFLICT,
            "payment-mandate-consent-mismatch",
            "displayed terms do not match the trusted terms commitment",
        )
    }
    const fn unknown_experiment() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "unknown-experiment",
            "the experiment identifier is not repository-owned",
        )
    }
    const fn receipt_missing() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "receipt-not-found",
            "the canonical payment-mandate receipt was not found",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error":{"code":self.code,"message":self.message}})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    };

    use auths_stripe::{
        CredentialProvider, CustomerId, PaymentMandateCapabilityRecord, PaymentMandateCredential,
        PaymentMandateCredentialScope, PaymentMandateEffect, PaymentMandateEvidenceInput,
        PaymentMandateEvidenceV1, PaymentMandateGateway, PaymentMandateProviderProjection,
        PaymentMandateReconciliationOutcome, PaymentMethodId, PortError, SetupAttemptId,
        SetupIntentId, StripeAccountId, VerifiedPaymentMandateCommand, canonical::sha256,
    };
    use axum::{
        body::{Body, to_bytes},
        http::{Request, header::SET_COOKIE},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::stripe::{EnvironmentDiagnostics, MandateFixture};

    struct FakeEnvironment {
        account: StripeAccountId,
        credentials: AtomicU64,
        calls: AtomicU64,
        ambiguous: StdMutex<bool>,
    }

    impl FakeEnvironment {
        fn new() -> Self {
            Self {
                account: StripeAccountId::parse("acct_1234567890").unwrap(),
                credentials: AtomicU64::new(0),
                calls: AtomicU64::new(0),
                ambiguous: StdMutex::new(false),
            }
        }

        fn projection(
            command: &VerifiedPaymentMandateCommand,
            status: &str,
        ) -> PaymentMandateProviderProjection {
            PaymentMandateProviderProjection {
                setup_intent_id: SetupIntentId::parse("seti_1234567890").unwrap(),
                latest_setup_attempt_id: Some(SetupAttemptId::parse("setatt_1234567890").unwrap()),
                mandate_id: None,
                customer_id: command.action().customer_id().clone(),
                payment_method_id: command.action().payment_method_id().clone(),
                usage: "off_session".into(),
                status: status.into(),
                livemode: false,
                stripe_request_id: Some("req_fixture".into()),
                response_digest: sha256(status.as_bytes()),
                observed_at: 2_000_000_000,
                source: "fake-provider".into(),
            }
        }
    }

    impl CredentialProvider<PaymentMandateCredentialScope> for FakeEnvironment {
        fn credential(
            &self,
            account: &StripeAccountId,
        ) -> Result<PaymentMandateCredential, PortError> {
            if account != &self.account {
                return Err(PortError::InvalidConfiguration);
            }
            self.credentials.fetch_add(1, Ordering::Relaxed);
            PaymentMandateCredential::new(b"sk_test_1234567890123456".to_vec())
        }
    }

    impl PaymentMandateGateway for FakeEnvironment {
        fn reread_critical_evidence(
            &self,
            command: &VerifiedPaymentMandateCommand,
            _credential: &PaymentMandateCredential,
            _now: u64,
        ) -> Result<PaymentMandateEvidenceV1, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(command.evidence().clone())
        }

        fn create_and_confirm(
            &self,
            command: &VerifiedPaymentMandateCommand,
            _credential: &PaymentMandateCredential,
            _now: u64,
        ) -> Result<PaymentMandateEffect, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let projection = Self::projection(command, "succeeded");
            if *self.ambiguous.lock().map_err(|_| PortError::Persistence)? {
                *self.ambiguous.lock().map_err(|_| PortError::Persistence)? = false;
                Ok(PaymentMandateEffect::OutcomeUnknown(Some(projection)))
            } else {
                Ok(PaymentMandateEffect::Succeeded(projection))
            }
        }

        fn reconcile(
            &self,
            capability: &PaymentMandateCapabilityRecord,
            _credential: &PaymentMandateCredential,
            now: u64,
        ) -> Result<PaymentMandateReconciliationOutcome, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut value = capability
                .provider()
                .cloned()
                .ok_or(PortError::EvidenceUnavailable)?;
            value.status = "succeeded".into();
            value.observed_at = now;
            value.source = "fake-retrieve".into();
            Ok(PaymentMandateReconciliationOutcome::Succeeded(value))
        }
    }

    impl DemoPaymentMandateEnvironment for FakeEnvironment {
        fn seed_fixture(&self, _workflow_id: &str, now: u64) -> Result<MandateFixture, PortError> {
            let customer = CustomerId::parse("cus_1234567890").unwrap();
            let method = PaymentMethodId::parse("pm_1234567890").unwrap();
            let evidence = PaymentMandateEvidenceV1::new(PaymentMandateEvidenceInput {
                stripe_account_id: self.account.clone(),
                connect_account: MandateConnectAccount::Platform,
                customer_id: customer.clone(),
                customer_exists: true,
                payment_method_id: method.clone(),
                payment_method_type: "card".into(),
                payment_method_customer_id: customer.clone(),
                existing_setup_intent_ids: Vec::new(),
                active_mandate_count: 0,
                duplicate_scope_exists: false,
                ambiguous_setup_exists: false,
                stripe_api_version: "2025-04-30.basil".into(),
                livemode: false,
                observed_at: now,
                source: "fake-stripe-evidence".into(),
                response_commitment: sha256(b"fake-evidence"),
            })
            .unwrap();
            Ok(MandateFixture {
                customer_id: customer,
                payment_method_id: method,
                evidence,
            })
        }

        fn arm_ambiguous_once(&self, _workflow_id: &str) -> Result<(), PortError> {
            *self.ambiguous.lock().map_err(|_| PortError::Persistence)? = true;
            Ok(())
        }

        fn account_id(&self) -> &StripeAccountId {
            &self.account
        }
        #[allow(
            clippy::unnecessary_literal_bound,
            reason = "the trait intentionally supports deployment-owned version strings"
        )]
        fn api_version(&self) -> &str {
            "2025-04-30.basil"
        }
        fn diagnostics(&self) -> EnvironmentDiagnostics {
            EnvironmentDiagnostics {
                credential_requests: self.credentials.load(Ordering::Relaxed),
                provider_calls: self.calls.load(Ordering::Relaxed),
            }
        }
    }

    async fn start(router: &Router) -> (String, String, DigestHex) {
        let response = router
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let cookie = response
            .headers()
            .get(SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        (
            body["session_id"].as_str().unwrap().into(),
            cookie,
            serde_json::from_value(body["displayed_terms_digest"].clone()).unwrap(),
        )
    }

    async fn accept(router: &Router, session: &str, cookie: &str, terms: &DigestHex) {
        let response = router
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session}/consent"))
                    .header(COOKIE, cookie)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"displayed_terms_digest": terms})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    async fn run(router: &Router, session: &str, experiment: &str) -> Value {
        let response = router
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"experiment": experiment})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn consent_requires_the_http_only_session_cookie() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().to_path_buf()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let (session, _cookie, terms) = start(&router).await;
        let response = router
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session}/consent"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        serde_json::to_vec(&json!({"displayed_terms_digest": terms})).unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn denial_precedes_credential_and_provider_access() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().to_path_buf()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let (session, cookie, terms) = start(&router).await;
        accept(&router, &session, &cookie, &terms).await;
        let body = run(&router, &session, "denial").await;
        assert_eq!(body["outcome"], "rejected");
        assert_eq!(body["boundary"]["credential_requests"], 0);
        assert_eq!(body["boundary"]["provider_calls"], 0);
    }

    #[tokio::test]
    async fn success_replay_and_ambiguity_never_expose_client_secret() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().to_path_buf()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let (session, cookie, terms) = start(&router).await;
        accept(&router, &session, &cookie, &terms).await;
        let success = run(&router, &session, "success").await;
        assert_eq!(success["outcome"], "mandate-established");
        assert_eq!(success["record"]["state"], "committed");
        assert!(!success.to_string().contains("\"client_secret\":"));
        let replay = run(&router, &session, "replay").await;
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["boundary"]["credential_requests"], 0);
        assert_eq!(replay["boundary"]["provider_calls"], 0);

        let (second, second_cookie, second_terms) = start(&router).await;
        accept(&router, &second, &second_cookie, &second_terms).await;
        let ambiguous = run(&router, &second, "ambiguous").await;
        assert_eq!(ambiguous["outcome"], "outcome-unknown");
        assert_eq!(ambiguous["record"]["state"], "outcome-unknown");
    }
}
