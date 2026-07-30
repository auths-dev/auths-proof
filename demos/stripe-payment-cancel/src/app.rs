use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_stripe::{
    Currency, DigestHex, ExecutePaymentCancelRequest, MERCHANT_EVALUATOR_ID,
    MERCHANT_EVALUATOR_VERSION, MERCHANT_POLICY_PROVENANCE, MerchantAggregateBudget,
    MerchantBudgetWindow, MerchantConnectAccount, MerchantOperation, MerchantPaymentStore,
    MerchantReservationIntent, MerchantReservationRecord, MerchantReservationState,
    PaymentCancelEvidenceInput, PaymentCancelEvidenceV1, PaymentCancelService,
    PaymentCancelServiceDependencies, PaymentCancelWorkflowOutcome, PaymentCancellationReason,
    PersistentMerchantPaymentStore, ReserveMerchantPaymentRequest, ReserveMerchantPaymentResult,
    SdkPaymentCancelProofVerifier, StripeBoundedMerchantPaymentPolicyInput,
    StripeBoundedMerchantPaymentPolicyV1, StripeExactPaymentAuthorizeInput,
    StripeExactPaymentAuthorizeV1, StripeExactPaymentCancelInput, StripeExactPaymentCancelV1,
    StripeMerchantEvaluatorConfigurationV1, StripePaymentCancelProfile, SystemClock,
    canonical::sha256, fixed_merchant_metadata_commitment,
    merchant_statement_descriptor_commitment,
};
use auths_stripe_payment_demo_common::authorization_fixture;
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{
    receipts::{ReceiptJournal, receipt_id},
    stripe::{CancellationFixture, DemoPaymentCancelEnvironment, LivePaymentCancelEnvironment},
};

const API_SCHEMA: &str = "auths.stripe.payment-cancel-demo/1";
const EXECUTOR_AUDIENCE: &str = "https://stripe-cancel-executor.auths.dev";
const SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_SESSIONS: usize = 256;
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const AUTHORIZED_AMOUNT_MINOR: u64 = 1_000;
const CANCEL_TARGET_AMOUNT_MINOR: u64 = 1_000;
const OPERATION_LIMIT_MINOR: u64 = 750;
const CUSTOMER_LIMIT_MINOR: u64 = 1_500;
const ORDER_LIMIT_MINOR: u64 = 1_000;
const FIXED_AGGREGATE_LIMIT_MINOR: u64 = 2_000;
const ROLLING_AGGREGATE_LIMIT_MINOR: u64 = 1_500;
const FIXTURE_AUTHORIZATION_AGGREGATE_LIMIT_MINOR: u64 = 256_000;

/// Native payment-cancellation demo deployment configuration.
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
    /// Returns an error for missing or unsafe deployment values.
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
                .unwrap_or_else(|_| "/data/auths-stripe-payment-cancel".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        let region = checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?;
        let release = checked_label(
            env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
        )?;
        let public_api_base = env::var("AUTHS_PAYMENT_CANCEL_PUBLIC_API_BASE").unwrap_or_default();
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
    environment: Arc<dyn DemoPaymentCancelEnvironment>,
    store: Arc<dyn MerchantPaymentStore>,
    receipts: Arc<ReceiptJournal>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    workflow_id: String,
    authorization_workflow_id: String,
    evidence: PaymentCancelEvidenceV1,
    policy: StripeBoundedMerchantPaymentPolicyV1,
    required_configuration: StripeMerchantEvaluatorConfigurationV1,
    exact: Variant,
    denied: Variant,
    changed_action: Variant,
    last_result: Option<Value>,
}

#[derive(Clone)]
struct Variant {
    action: StripeExactPaymentCancelV1,
    proof_verifier: Arc<SdkPaymentCancelProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
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
/// Returns an error when Stripe or durable-state configuration cannot initialize.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let environment = Arc::new(
        LivePaymentCancelEnvironment::from_environment().map_err(|_| StartupError::Stripe)?,
    );
    app_with_environment(config, environment)
}

/// Builds the application with an explicit cancel-only environment.
///
/// # Errors
///
/// Returns an error when durable state or the receipt journal cannot initialize.
pub fn app_with_environment(
    config: AppConfig,
    environment: Arc<dyn DemoPaymentCancelEnvironment>,
) -> Result<Router, StartupError> {
    let store = Arc::new(
        PersistentMerchantPaymentStore::open(config.state_directory.join("merchant-state.json"))
            .map_err(|_| StartupError::State)?,
    );
    let receipts = Arc::new(
        ReceiptJournal::open(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
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
        .route("/api/v1/sessions/{session_id}/cancel", get(cancel_status))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/sessions/{session_id}/reconcile", post(reconcile))
        .route("/api/v1/receipts/{receipt_id}", get(machine_receipt))
        .route("/receipts/{receipt_id}", get(receipt_page))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

async fn index() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn receipt_page(AxumPath(receipt_id): AxumPath<String>) -> Response {
    if DigestHex::parse(receipt_id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(include_str!("../web/receipt.html")).into_response()
}

async fn app_js() -> impl IntoResponse {
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        include_str!("../web/app.js"),
    )
}

async fn config_js(State(state): State<AppState>) -> impl IntoResponse {
    let value =
        serde_json::to_string(&*state.config.public_api_base).unwrap_or_else(|_| "\"\"".into());
    (
        [(CONTENT_TYPE, "text/javascript; charset=utf-8")],
        format!("window.AUTHS_PAYMENT_CANCEL_API_BASE = {value};\n"),
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
        "stripe_mode": state.environment.execution_mode(),
        "account_commitment": sha256(state.environment.account_id().as_str().as_bytes()),
        "api_version": state.environment.api_version(),
    }))
}

async fn scenario(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": auths_stripe::PAYMENT_CANCEL_PROFILE,
        "policy_type": auths_stripe::MERCHANT_POLICY_TYPE,
        "evaluator": MERCHANT_EVALUATOR_ID,
        "policy_provenance": MERCHANT_POLICY_PROVENANCE,
        "execution_mode": state.environment.execution_mode(),
        "authorized_amount_minor": AUTHORIZED_AMOUNT_MINOR,
        "cancel_target_amount_minor": CANCEL_TARGET_AMOUNT_MINOR,
        "currency": "usd",
        "agent_has_stripe_key": false,
        "terminal_cancellation": true,
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "session setup exposes the exact imported authorization and cancel side by side"
)]
async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let session_id = random_id()?;
    let workflow_id = format!("cancel-{session_id}");
    let authorization_workflow_id = format!("authorization-{session_id}");
    let order_scope = format!("order-{session_id}");
    let environment = Arc::clone(&state.environment);
    let seed_workflow = authorization_workflow_id.clone();
    let seed_order = order_scope.clone();
    let fixture = tokio::task::spawn_blocking(move || {
        environment.seed_cancel(&seed_workflow, &seed_order, now)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "stripe-fixture-unavailable",
            "Stripe test mode could not establish a manual-cancel authorization",
        )
    })?;
    let (authorization_action, authorization_record) = import_authorization_fixture(
        state.store.as_ref(),
        state.environment.as_ref(),
        &authorization_workflow_id,
        &fixture,
        now,
    )?;
    let evidence = cancel_evidence(
        state.environment.as_ref(),
        &fixture,
        &authorization_record,
        now,
    )
    .map_err(|_| setup_error("cancel-evidence-failed"))?;
    let policy = cancel_policy(&evidence, now).map_err(|_| setup_error("cancel-policy-failed"))?;
    let required_configuration = StripeMerchantEvaluatorConfigurationV1::for_cancel_policy(
        &policy,
        "stripe-cancel-demo-v1",
        state.environment.account_id().clone(),
        MerchantConnectAccount::Platform,
        state.environment.api_version(),
        EXECUTOR_AUDIENCE,
    )
    .map_err(|_| setup_error("cancel-configuration-failed"))?;
    let exact_action = cancel_action(
        &evidence,
        &policy,
        &required_configuration,
        PaymentCancellationReason::RequestedByCustomer,
        now,
        &session_id,
    )
    .map_err(|_| setup_error("cancel-exact-action-failed"))?;
    let denied_action = cancel_action(
        &evidence,
        &policy,
        &required_configuration,
        PaymentCancellationReason::Fraudulent,
        now,
        &format!("{session_id}01"),
    )
    .map_err(|_| setup_error("cancel-denied-action-failed"))?;
    let changed_action = cancel_action(
        &evidence,
        &policy,
        &required_configuration,
        PaymentCancellationReason::Duplicate,
        now,
        &session_id,
    )
    .map_err(|_| setup_error("cancel-changed-action-failed"))?;
    let exact =
        proof_variant(&exact_action, now).map_err(|_| setup_error("cancel-proof-failed"))?;
    let denied = proof_variant(&denied_action, now)
        .map_err(|_| setup_error("cancel-denied-proof-failed"))?;
    let changed_action = Variant {
        action: changed_action,
        proof_verifier: Arc::clone(&exact.proof_verifier),
        proof: exact.proof.clone(),
        request: exact.request.clone(),
    };
    let aggregate = state
        .store
        .snapshot(&policy, state.environment.account_id(), now)
        .map_err(|_| setup_error("cancel-snapshot-failed"))?;
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "profile": auths_stripe::PAYMENT_CANCEL_PROFILE,
        "operation": "cancel",
        "delegation": {
            "label": "immutable configured cancellation policy",
            "provenance": MERCHANT_POLICY_PROVENANCE,
            "policy": policy,
            "policy_digest": policy.digest().map_err(|_| setup_error("cancel-policy-digest-failed"))?,
            "evaluator_semantic_id": MERCHANT_EVALUATOR_ID,
            "evaluator_semantic_version": MERCHANT_EVALUATOR_VERSION,
            "allowed_reasons": ["duplicate", "requested_by_customer"],
            "hold_release_rule": "only after a fresh terminal canceled observation",
        },
        "authorization_fixture_receipt": {
            "schema": "auths.stripe.cancel-demo-authorization-import/1",
            "action": authorization_action,
            "record": authorization_record,
            "payment_intent_id": fixture.authorization_provider.payment_intent_id,
            "charge_id": fixture.authorization_provider.charge_id,
            "held_minor": fixture.authorization_provider.amount_capturable_minor,
            "canceled_minor": fixture.authorization_provider.amount_received_minor,
        },
        "agent_selected_exact_cancel": exact_action,
        "fresh_stripe_and_hold_evidence": evidence,
        "aggregate_claim_snapshot": aggregate,
        "required_configuration": required_configuration,
        "executed_configuration": required_configuration,
        "configuration_equal": true,
        "experiments": [
            {"id":"success","label":"Exact cancellation","detail":"Cancel the PaymentIntent; release the full $10.00 manual hold after observation."},
            {"id":"denial","label":"Reason denied","detail":"Request fraudulent when that reason is outside this configured policy."},
            {"id":"changed-action","label":"Changed action","detail":"Alter the cancellation reason after exact authorization."},
            {"id":"changed-configuration","label":"Changed configuration","detail":"Execute with a different runtime commitment."},
            {"id":"replay","label":"Replay","detail":"Submit the same cancel workflow without another provider cancel."},
            {"id":"ambiguous","label":"Lost response","detail":"Deliver once, retain both exposures, then reconcile without cancel again."}
        ],
        "agent_has_stripe_key": false,
    });
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the cancel session pool is full",
        ));
    }
    sessions.insert(
        session_id,
        Session {
            expires_at: now + SESSION_TTL_SECONDS,
            workflow_id,
            authorization_workflow_id,
            evidence,
            policy,
            required_configuration,
            exact,
            denied,
            changed_action,
            last_result: None,
        },
    );
    Ok(Json(response))
}

async fn execute(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    if request.experiment == "replay" {
        let session_available = state
            .sessions
            .lock()
            .await
            .get(&session_id)
            .is_some_and(|session| session.expires_at > now);
        if !session_available {
            return durable_replay(&state, &session_id);
        }
    }
    let materials = {
        let sessions = state.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(ApiError::session_missing)?;
        if session.expires_at <= now {
            return Err(ApiError::session_missing());
        }
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
    let executed_workflow = materials.workflow_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        PaymentCancelService::new(PaymentCancelServiceDependencies {
            proof_verifier: materials.variant.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            store,
            receipt_sink: receipts,
            clock: SystemClock,
            executed_configuration: materials.executed_configuration,
        })
        .execute(ExecutePaymentCancelRequest {
            workflow_id: materials.workflow_id,
            action: materials.variant.action,
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
    attach_latest_receipt(&state.receipts, &executed_workflow, &mut response)?;
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_result = Some(response.clone());
    }
    Ok(Json(response))
}

fn durable_replay(state: &AppState, session_id: &str) -> Result<Json<Value>, ApiError> {
    validate_session_id(session_id)?;
    let workflow_id = format!("cancel-{session_id}");
    let record = state
        .store
        .get(&workflow_id)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::session_missing)?;
    if !matches!(
        record.state(),
        MerchantReservationState::CancelCommitted
            | MerchantReservationState::ReconciledCancelCommitted
    ) {
        return Err(ApiError::session_missing());
    }
    let mut response = outcome_projection(PaymentCancelWorkflowOutcome::Replay { record }, 0, 0);
    attach_latest_receipt(&state.receipts, &workflow_id, &mut response)?;
    Ok(Json(response))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let (workflow_id, materials) = {
        let sessions = state.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(ApiError::session_missing)?;
        (
            session.workflow_id.clone(),
            execution_materials(session, "success")?,
        )
    };
    let before = state.environment.diagnostics();
    let environment = Arc::clone(&state.environment);
    let store = Arc::clone(&state.store);
    let receipts = Arc::clone(&state.receipts);
    let reconciliation_workflow = workflow_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        PaymentCancelService::new(PaymentCancelServiceDependencies {
            proof_verifier: materials.variant.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            store,
            receipt_sink: receipts,
            clock: SystemClock,
            executed_configuration: materials.executed_configuration,
        })
        .reconcile(&reconciliation_workflow)
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
    let aggregate = state
        .store
        .snapshot(
            &session.policy,
            state.environment.account_id(),
            unix_time().map_err(|_| ApiError::internal())?,
        )
        .map_err(|_| ApiError::internal())?;
    let authorization = state
        .store
        .get(&session.authorization_workflow_id)
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "aggregate_claim_snapshot": aggregate,
        "linked_authorization": authorization,
        "last_result": session.last_result,
    })))
}

async fn cancel_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    validate_session_id(&session_id)?;
    let workflow_id = format!("cancel-{session_id}");
    let record = state
        .store
        .get(&workflow_id)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::session_missing)?;
    let authorization = match record.authorization_workflow_id() {
        Some(workflow) => state
            .store
            .get(workflow)
            .map_err(|_| ApiError::internal())?,
        None => None,
    };
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "workflow_id": workflow_id,
        "cancel": record,
        "linked_authorization": authorization,
        "agent_received_credential": false,
        "client_secret_exposed": false,
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
        "schema": "auths.stripe.machine-readable-receipt/1",
        "receipt_id": receipt_id,
        "receipt": receipt,
    })))
}

struct ExecutionMaterials {
    workflow_id: String,
    variant: Variant,
    evidence: PaymentCancelEvidenceV1,
    policy: StripeBoundedMerchantPaymentPolicyV1,
    required_configuration: StripeMerchantEvaluatorConfigurationV1,
    executed_configuration: StripeMerchantEvaluatorConfigurationV1,
}

fn execution_materials(
    session: &Session,
    experiment: &str,
) -> Result<ExecutionMaterials, ApiError> {
    let (workflow_id, variant, executed_configuration) = match experiment {
        "success" | "replay" | "ambiguous" => (
            session.workflow_id.clone(),
            session.exact.clone(),
            session.required_configuration.clone(),
        ),
        "denial" => (
            format!("{}-denied", session.workflow_id),
            session.denied.clone(),
            session.required_configuration.clone(),
        ),
        "changed-action" => (
            session.workflow_id.clone(),
            session.changed_action.clone(),
            session.required_configuration.clone(),
        ),
        "changed-configuration" => (
            session.workflow_id.clone(),
            session.exact.clone(),
            StripeMerchantEvaluatorConfigurationV1::for_cancel_policy(
                &session.policy,
                "stripe-cancel-demo-changed-v1",
                session.required_configuration.stripe_account_id().clone(),
                session.required_configuration.connect_account().clone(),
                session.required_configuration.stripe_api_version(),
                session.required_configuration.executor_audience(),
            )
            .map_err(|_| ApiError::internal())?,
        ),
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "unknown-experiment",
                "the experiment identifier is not repository-owned",
            ));
        }
    };
    Ok(ExecutionMaterials {
        workflow_id,
        variant,
        evidence: session.evidence.clone(),
        policy: session.policy.clone(),
        required_configuration: session.required_configuration.clone(),
        executed_configuration,
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "fixture import deliberately exposes the complete durable authorization boundary"
)]
fn import_authorization_fixture(
    store: &dyn MerchantPaymentStore,
    environment: &dyn DemoPaymentCancelEnvironment,
    workflow_id: &str,
    fixture: &CancellationFixture,
    now: u64,
) -> Result<(StripeExactPaymentAuthorizeV1, MerchantReservationRecord), ApiError> {
    let policy = payment_policy(
        MerchantOperation::Authorize,
        environment.account_id(),
        &fixture.customer_id,
        Some(&fixture.payment_method_id),
        &fixture.order_scope,
        environment.api_version(),
        now,
    )
    .map_err(|_| setup_error("authorization-policy-failed"))?;
    let configuration = StripeMerchantEvaluatorConfigurationV1::for_authorize_policy(
        &policy,
        "stripe-cancel-demo-authorization-import-v1",
        environment.account_id().clone(),
        MerchantConnectAccount::Platform,
        environment.api_version(),
        EXECUTOR_AUDIENCE,
    )
    .map_err(|_| setup_error("authorization-configuration-failed"))?;
    let policy_digest = policy
        .digest()
        .map_err(|_| setup_error("authorization-policy-digest-failed"))?;
    let action = StripeExactPaymentAuthorizeV1::new(StripeExactPaymentAuthorizeInput {
        stripe_account_id: environment.account_id().clone(),
        connect_account: MerchantConnectAccount::Platform,
        customer_id: fixture.customer_id.clone(),
        payment_method_id: fixture.payment_method_id.clone(),
        payment_method_type: "card".into(),
        order_scope: fixture.order_scope.clone(),
        authorized_amount_minor: AUTHORIZED_AMOUNT_MINOR,
        currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            workflow_id,
            auths_stripe::PAYMENT_AUTHORIZE_PROFILE,
            &fixture.order_scope,
            &policy_digest,
        )
        .map_err(|_| ApiError::internal())?,
        stripe_api_version: environment.api_version().into(),
        required_policy_digest: policy_digest.clone(),
        required_configuration_digest: configuration.digest().map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        expires_at: now.checked_add(300).ok_or_else(ApiError::internal)?,
        nonce: sha256(format!("authorization-import:{workflow_id}").as_bytes()),
    })
    .map_err(|_| setup_error("authorization-action-failed"))?;
    let currency = Currency::parse("usd").map_err(|_| ApiError::internal())?;
    let action_digest = action.digest().map_err(|_| ApiError::internal())?;
    let configuration_digest = configuration.digest().map_err(|_| ApiError::internal())?;
    let reservation = store.reserve(ReserveMerchantPaymentRequest {
        workflow_id: workflow_id.into(),
        operation: MerchantOperation::Authorize,
        exact_action_profile: auths_stripe::PAYMENT_AUTHORIZE_PROFILE.into(),
        action_digest: action_digest.clone(),
        decision_receipt_digest: sha256(format!("fixture-decision:{workflow_id}").as_bytes()),
        policy_digest,
        evaluator_semantic_id: MERCHANT_EVALUATOR_ID.into(),
        evaluator_semantic_version: MERCHANT_EVALUATOR_VERSION,
        evidence_digest: fixture.authorization_provider.response_digest.clone(),
        required_configuration_digest: configuration_digest.clone(),
        executed_configuration_digest: configuration_digest,
        stripe_account_id: environment.account_id().clone(),
        connect_account: MerchantConnectAccount::Platform,
        customer_id: fixture.customer_id.clone(),
        order_scope: fixture.order_scope.clone(),
        currency: currency.clone(),
        amount_minor: AUTHORIZED_AMOUNT_MINOR,
        intents: policy
            .aggregate_budgets()
            .iter()
            .map(|budget| {
                Ok(MerchantReservationIntent {
                    budget_id: budget.budget_id().into(),
                    operation: MerchantOperation::Authorize,
                    currency: currency.clone(),
                    window: budget
                        .window()
                        .identity(now)
                        .map_err(|_| ApiError::internal())?,
                    limit_minor: budget.limit_minor(),
                    amount_minor: AUTHORIZED_AMOUNT_MINOR,
                    available_before_minor: budget.limit_minor(),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?,
        idempotency_key_digest: sha256(format!("fixture-idempotency:{workflow_id}").as_bytes()),
        now,
    });
    let (lease, _) = match reservation {
        ReserveMerchantPaymentResult::Reserved { lease, record } => (lease, record),
        ReserveMerchantPaymentResult::Replay(record) => return Ok((action, record)),
        ReserveMerchantPaymentResult::CapacityExceeded {
            budget_id,
            available_minor,
        } => {
            return Err(setup_error(if available_minor == 500 {
                "authorization-capacity-only-500"
            } else if budget_id.ends_with("-fixed") {
                "authorization-fixed-capacity-failed"
            } else {
                "authorization-rolling-capacity-failed"
            }));
        }
        ReserveMerchantPaymentResult::Conflict(_) => {
            return Err(setup_error("authorization-conflict"));
        }
        ReserveMerchantPaymentResult::Unavailable => {
            return Err(setup_error("authorization-reserve-failed"));
        }
    };
    store.claim_authorization(&lease, now).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authorization-claim-failed",
            "the authorization fixture claim could not be persisted",
        )
    })?;
    store
        .mark_authorization_attempting(&lease, now)
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authorization-attempt-failed",
                "the authorization fixture attempt could not be persisted",
            )
        })?;
    store
        .record_authorization_provider_accepted(&lease, fixture.authorization_provider.clone(), now)
        .map_err(|_| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "authorization-provider-failed",
                "the authorization fixture provider result could not be persisted",
            )
        })?;
    let record = store.commit_authorization(&lease, now).map_err(|_| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "authorization-commit-failed",
            "the authorization fixture could not be committed",
        )
    })?;
    Ok((action, record))
}

fn cancel_evidence(
    environment: &dyn DemoPaymentCancelEnvironment,
    fixture: &CancellationFixture,
    authorization: &MerchantReservationRecord,
    now: u64,
) -> Result<PaymentCancelEvidenceV1, ApiError> {
    let provider = &fixture.authorization_provider;
    PaymentCancelEvidenceV1::new(PaymentCancelEvidenceInput {
        stripe_account_id: environment.account_id().clone(),
        connect_account: MerchantConnectAccount::Platform,
        payment_intent_id: provider.payment_intent_id.clone(),
        latest_charge_id: provider.charge_id.clone(),
        customer_id: fixture.customer_id.clone(),
        order_scope: fixture.order_scope.clone(),
        amount_minor: provider.amount_minor,
        amount_capturable_minor: provider.amount_capturable_minor,
        currency: provider.currency.clone(),
        payment_intent_status: provider.status.clone(),
        cancellation_eligible: true,
        livemode: false,
        stripe_api_version: environment.api_version().into(),
        authorization_workflow_id: Some(authorization.workflow_id().into()),
        authorization_action_digest: Some(authorization.action_digest().clone()),
        authorization_reservation_id: Some(authorization.reservation_id().clone()),
        authorization_state: Some(authorization.state()),
        authorization_created_at: Some(authorization.created_at()),
        observed_at: now,
        source: "stripe-api-and-auths-store".into(),
        response_commitment: provider.response_digest.clone(),
    })
    .map_err(|_| ApiError::internal())
}

fn cancel_policy(
    evidence: &PaymentCancelEvidenceV1,
    now: u64,
) -> Result<StripeBoundedMerchantPaymentPolicyV1, ApiError> {
    payment_policy(
        MerchantOperation::Cancel,
        evidence.stripe_account_id(),
        evidence.customer_id(),
        None,
        evidence.order_scope(),
        evidence.stripe_api_version(),
        now,
    )
}

#[allow(clippy::too_many_arguments)]
#[allow(
    clippy::too_many_lines,
    reason = "the demo policy keeps every bounded dimension visible together"
)]
fn payment_policy(
    operation: MerchantOperation,
    account: &auths_stripe::StripeAccountId,
    customer: &auths_stripe::CustomerId,
    payment_method: Option<&auths_stripe::PaymentMethodId>,
    order_scope: &str,
    api_version: &str,
    now: u64,
) -> Result<StripeBoundedMerchantPaymentPolicyV1, ApiError> {
    let currency = Currency::parse("usd").map_err(|_| ApiError::internal())?;
    let money_operation = operation != MerchantOperation::Cancel;
    let valid_from = now.saturating_sub(60);
    let expires_at = now.checked_add(300).ok_or_else(ApiError::internal)?;
    let operation_limit = if operation == MerchantOperation::Authorize {
        AUTHORIZED_AMOUNT_MINOR
    } else {
        OPERATION_LIMIT_MINOR
    };
    let fixed_aggregate_limit = if operation == MerchantOperation::Authorize {
        FIXTURE_AUTHORIZATION_AGGREGATE_LIMIT_MINOR
    } else {
        FIXED_AGGREGATE_LIMIT_MINOR
    };
    let rolling_aggregate_limit = if operation == MerchantOperation::Authorize {
        FIXTURE_AUTHORIZATION_AGGREGATE_LIMIT_MINOR
    } else {
        ROLLING_AGGREGATE_LIMIT_MINOR
    };
    StripeBoundedMerchantPaymentPolicyV1::new(StripeBoundedMerchantPaymentPolicyInput {
        policy_id: format!(
            "{}-policy-{}",
            if operation == MerchantOperation::Cancel {
                "cancel"
            } else {
                "authorization-import"
            },
            &sha256(order_scope.as_bytes()).as_str()[..16]
        ),
        valid_from,
        expires_at,
        allowed_operations: vec![operation],
        allowed_test_account_ids: vec![account.clone()],
        allowed_connect_accounts: vec![MerchantConnectAccount::Platform],
        allowed_customer_ids: vec![customer.clone()],
        allowed_payment_method_ids: payment_method.cloned().into_iter().collect(),
        allowed_payment_method_types: payment_method.map_or_else(Vec::new, |_| vec!["card".into()]),
        allowed_currencies: money_operation
            .then(|| currency.clone())
            .into_iter()
            .collect(),
        allowed_order_scopes: vec![order_scope.into()],
        allowed_cancellation_reasons: if operation == MerchantOperation::Cancel {
            vec!["duplicate".into(), "requested_by_customer".into()]
        } else {
            Vec::new()
        },
        per_operation_absolute_minor_by_currency: if money_operation {
            BTreeMap::from([(
                operation,
                BTreeMap::from([(currency.clone(), operation_limit)]),
            )])
        } else {
            BTreeMap::new()
        },
        per_customer_minor_by_currency: if money_operation {
            BTreeMap::from([(currency.clone(), CUSTOMER_LIMIT_MINOR)])
        } else {
            BTreeMap::new()
        },
        per_order_minor_by_currency: if money_operation {
            BTreeMap::from([(currency.clone(), ORDER_LIMIT_MINOR)])
        } else {
            BTreeMap::new()
        },
        aggregate_budgets: if money_operation {
            vec![
                MerchantAggregateBudget::new(
                    format!("{}-fixed", operation_label(operation)),
                    operation,
                    currency.clone(),
                    fixed_aggregate_limit,
                    MerchantBudgetWindow::Fixed {
                        starts_at: valid_from,
                        ends_at: expires_at,
                    },
                    valid_from,
                )
                .map_err(|_| ApiError::internal())?,
                MerchantAggregateBudget::new(
                    format!("{}-rolling", operation_label(operation)),
                    operation,
                    currency,
                    rolling_aggregate_limit,
                    MerchantBudgetWindow::Rolling {
                        duration_seconds: 3_600,
                    },
                    valid_from,
                )
                .map_err(|_| ApiError::internal())?,
            ]
        } else {
            Vec::new()
        },
        maximum_authorization_age_seconds: if operation == MerchantOperation::Authorize {
            300
        } else {
            0
        },
        minimum_capture_window_seconds: if operation == MerchantOperation::Authorize {
            60
        } else {
            0
        },
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec![api_version.into()],
    })
    .map_err(|_| ApiError::internal())
}

fn operation_label(operation: MerchantOperation) -> &'static str {
    match operation {
        MerchantOperation::Authorize => "authorization",
        MerchantOperation::Cancel => "cancel",
        MerchantOperation::Collect => "collect",
        MerchantOperation::Capture => "capture",
    }
}

#[allow(clippy::too_many_arguments)]
fn cancel_action(
    evidence: &PaymentCancelEvidenceV1,
    policy: &StripeBoundedMerchantPaymentPolicyV1,
    configuration: &StripeMerchantEvaluatorConfigurationV1,
    cancellation_reason: PaymentCancellationReason,
    now: u64,
    nonce_material: &str,
) -> Result<StripeExactPaymentCancelV1, ApiError> {
    let policy_digest = policy.digest().map_err(|_| ApiError::internal())?;
    StripeExactPaymentCancelV1::new(StripeExactPaymentCancelInput {
        stripe_account_id: evidence.stripe_account_id().clone(),
        connect_account: evidence.connect_account().clone(),
        payment_intent_id: evidence.payment_intent_id().clone(),
        customer_id: evidence.customer_id().clone(),
        order_scope: evidence.order_scope().into(),
        current_status: evidence.payment_intent_status().into(),
        amount_minor: evidence.amount_minor(),
        amount_capturable_minor: evidence.amount_capturable_minor(),
        currency: evidence.currency().clone(),
        cancellation_reason,
        authorization_action_digest: evidence.authorization_action_digest().cloned(),
        authorization_reservation_id: evidence.authorization_reservation_id().cloned(),
        stripe_api_version: evidence.stripe_api_version().into(),
        required_policy_digest: policy_digest,
        required_configuration_digest: configuration.digest().map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        expires_at: now.checked_add(300).ok_or_else(ApiError::internal)?,
        nonce: sha256(format!("auths-cancel-nonce-v1:{nonce_material}").as_bytes()),
    })
    .map_err(|_| ApiError::internal())
}

fn proof_variant(action: &StripeExactPaymentCancelV1, now: u64) -> Result<Variant, ApiError> {
    let canonical = StripePaymentCancelProfile
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
        proof_verifier: Arc::new(SdkPaymentCancelProofVerifier::new(fixture.verifier)),
        proof: fixture.proof,
        request: fixture.request,
    })
}

fn outcome_projection(
    outcome: PaymentCancelWorkflowOutcome,
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
        PaymentCancelWorkflowOutcome::Rejected { receipt, persisted } => json!({
            "schema": API_SCHEMA,
            "outcome": "rejected",
            "decision": receipt,
            "persisted": persisted,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::Canceled { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "canceled",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::Replay { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "replay",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::Conflict { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "conflict",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::CapacityChanged {
            budget_id,
            available_minor,
        } => json!({
            "schema": API_SCHEMA,
            "outcome": "capacity-changed",
            "budget_id": budget_id,
            "available_minor": available_minor,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::CriticalEvidenceChanged { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "critical-evidence-changed",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::NotDelivered { code, record } => json!({
            "schema": API_SCHEMA,
            "outcome": "not-delivered",
            "code": code,
            "record": record,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::ProviderDeclined { code, record } => json!({
            "schema": API_SCHEMA,
            "outcome": "provider-declined",
            "code": code,
            "record": record,
            "boundary": boundary,
        }),
        PaymentCancelWorkflowOutcome::OutcomeUnknown { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "outcome-unknown",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
            "reconciliation_required": true,
        }),
        PaymentCancelWorkflowOutcome::CaptureConflict { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "capture-conflict",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
            "refund_reconciliation_required": true,
        }),
        PaymentCancelWorkflowOutcome::Reconciled { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "reconciled",
            "record": record,
            "transition": receipt,
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
        .find(|receipt| cancel_receipt_workflow(receipt) == workflow_id)
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

fn cancel_receipt_workflow(receipt: &auths_stripe::MerchantCancelReceipt) -> &str {
    match receipt {
        auths_stripe::MerchantCancelReceipt::Decision(receipt) => &receipt.workflow_id,
        auths_stripe::MerchantCancelReceipt::Transition(receipt) => {
            receipt.cancel_reservation.workflow_id()
        }
        auths_stripe::MerchantCancelReceipt::Observation(receipt) => &receipt.workflow_id,
    }
}

fn validate_session_id(session_id: &str) -> Result<(), ApiError> {
    if session_id.len() == 32 && session_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ApiError::session_missing())
    }
}

fn random_id() -> Result<String, ApiError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(random))
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

/// Closed startup failure that never includes environment values.
#[derive(Debug)]
pub enum StartupError {
    /// Required environment name.
    Missing(&'static str),
    /// Unsafe deployment input.
    Invalid,
    /// Stripe credentials/provider unavailable.
    Stripe,
    /// Durable state unavailable.
    State,
    /// System clock unavailable.
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
            Self::State => formatter.write_str("durable payment-cancellation state is unavailable"),
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

const fn setup_error(code: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        code,
        "the repository-owned cancel setup failed closed",
    )
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
            "the protected payment-cancellation service failed closed",
        )
    }

    const fn session_missing() -> Self {
        Self::new(
            StatusCode::GONE,
            "session-unavailable",
            "the payment-cancellation session is missing or expired",
        )
    }

    const fn receipt_missing() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "receipt-not-found",
            "the canonical payment-cancellation receipt was not found",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
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
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    };

    use auths_stripe::{
        ChargeId, CredentialProvider, CustomerId, MerchantProviderProjection,
        PaymentCancelCredential, PaymentCancelCredentialScope, PaymentCancelEffect,
        PaymentCancelGateway, PaymentCancelProviderProjection, PaymentCancelReconciliationOutcome,
        PaymentIntentId, PaymentMethodId, PortError, StripeAccountId, VerifiedPaymentCancelCommand,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::stripe::EnvironmentDiagnostics;

    struct MockEnvironment {
        account: StripeAccountId,
        evidence: StdMutex<Option<PaymentCancelEvidenceV1>>,
        ambiguous: AtomicBool,
        effect_mode: AtomicU64,
        credential_requests: AtomicU64,
        provider_calls: AtomicU64,
        cancel_calls: AtomicU64,
    }

    impl MockEnvironment {
        fn new() -> Self {
            Self {
                account: StripeAccountId::parse("acct_cancelmock0001").unwrap(),
                evidence: StdMutex::new(None),
                ambiguous: AtomicBool::new(false),
                effect_mode: AtomicU64::new(0),
                credential_requests: AtomicU64::new(0),
                provider_calls: AtomicU64::new(0),
                cancel_calls: AtomicU64::new(0),
            }
        }

        fn authorization_projection(now: u64) -> MerchantProviderProjection {
            MerchantProviderProjection {
                payment_intent_id: PaymentIntentId::parse("pi_cancelmock000000000001").unwrap(),
                charge_id: Some(ChargeId::parse("ch_cancelmock000000000001").unwrap()),
                status: "requires_capture".into(),
                amount_minor: AUTHORIZED_AMOUNT_MINOR,
                currency: Currency::parse("usd").unwrap(),
                amount_capturable_minor: AUTHORIZED_AMOUNT_MINOR,
                amount_received_minor: 0,
                capture_before: Some(now + 3_600),
                stripe_request_id: Some("req_cancelfixture0001".into()),
                response_digest: sha256(b"mock authorization fixture"),
                observed_at: now,
                source: "create-response".into(),
            }
        }

        fn canceled_projection(
            command: &VerifiedPaymentCancelCommand,
            now: u64,
            source: &str,
        ) -> PaymentCancelProviderProjection {
            PaymentCancelProviderProjection {
                payment_intent_id: command.action().payment_intent_id().clone(),
                latest_charge_id: command.evidence().latest_charge_id().cloned(),
                status: "canceled".into(),
                cancellation_reason: Some(command.action().cancellation_reason()),
                amount_minor: command.action().amount_minor(),
                currency: command.action().currency().clone(),
                amount_capturable_minor: 0,
                amount_received_minor: 0,
                charge_captured: Some(false),
                stripe_request_id: Some("req_cancelmock0001".into()),
                response_digest: sha256(format!("mock cancel {source}").as_bytes()),
                observed_at: now,
                source: source.into(),
            }
        }

        fn reconciled_projection(
            record: &MerchantReservationRecord,
            now: u64,
        ) -> PaymentCancelProviderProjection {
            PaymentCancelProviderProjection {
                payment_intent_id: record.cancel_payment_intent_id().unwrap().clone(),
                latest_charge_id: None,
                status: "canceled".into(),
                cancellation_reason: record.cancellation_reason(),
                amount_minor: record.cancel_amount_minor().unwrap(),
                currency: record.currency().clone(),
                amount_capturable_minor: 0,
                amount_received_minor: 0,
                charge_captured: Some(false),
                stripe_request_id: Some("req_cancelmockreconcile1".into()),
                response_digest: sha256(b"mock reconciled cancel"),
                observed_at: now,
                source: "retrieve".into(),
            }
        }
    }

    impl CredentialProvider<PaymentCancelCredentialScope> for MockEnvironment {
        fn credential(
            &self,
            account: &StripeAccountId,
        ) -> Result<PaymentCancelCredential, PortError> {
            if account != &self.account {
                return Err(PortError::InvalidConfiguration);
            }
            self.credential_requests.fetch_add(1, Ordering::Relaxed);
            PaymentCancelCredential::new(["sk", "test", "cancel_mock_runtime_only"].join("_"))
        }
    }

    impl DemoPaymentCancelEnvironment for MockEnvironment {
        fn seed_cancel(
            &self,
            _workflow_id: &str,
            order_scope: &str,
            now: u64,
        ) -> Result<CancellationFixture, PortError> {
            Ok(CancellationFixture {
                customer_id: CustomerId::parse("cus_cancelmock000000001")
                    .map_err(|_| PortError::Malformed)?,
                payment_method_id: PaymentMethodId::parse("pm_cancelmock0000000001")
                    .map_err(|_| PortError::Malformed)?,
                authorization_provider: Self::authorization_projection(now),
                order_scope: order_scope.into(),
            })
        }

        fn arm_ambiguous_once(&self, _workflow_id: &str) -> Result<(), PortError> {
            self.ambiguous.store(true, Ordering::Relaxed);
            Ok(())
        }

        fn account_id(&self) -> &StripeAccountId {
            &self.account
        }

        fn api_version(&self) -> &'static str {
            "2025-04-30.basil"
        }

        fn execution_mode(&self) -> &'static str {
            "deterministic-test-provider"
        }

        fn diagnostics(&self) -> EnvironmentDiagnostics {
            EnvironmentDiagnostics {
                credential_requests: self.credential_requests.load(Ordering::Relaxed),
                provider_calls: self.provider_calls.load(Ordering::Relaxed),
            }
        }
    }

    impl PaymentCancelGateway for MockEnvironment {
        fn reread_critical_evidence(
            &self,
            command: &VerifiedPaymentCancelCommand,
            _credential: &PaymentCancelCredential,
            now: u64,
        ) -> Result<PaymentCancelEvidenceV1, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            let original = command.evidence();
            let fresh = PaymentCancelEvidenceV1::new(PaymentCancelEvidenceInput {
                stripe_account_id: original.stripe_account_id().clone(),
                connect_account: original.connect_account().clone(),
                payment_intent_id: original.payment_intent_id().clone(),
                latest_charge_id: original.latest_charge_id().cloned(),
                customer_id: original.customer_id().clone(),
                order_scope: original.order_scope().into(),
                amount_minor: original.amount_minor(),
                amount_capturable_minor: original.amount_capturable_minor(),
                currency: original.currency().clone(),
                payment_intent_status: original.payment_intent_status().into(),
                cancellation_eligible: true,
                livemode: false,
                stripe_api_version: original.stripe_api_version().into(),
                authorization_workflow_id: original.authorization_workflow_id().map(str::to_owned),
                authorization_action_digest: original.authorization_action_digest().cloned(),
                authorization_reservation_id: original.authorization_reservation_id().cloned(),
                authorization_state: original.authorization_state(),
                authorization_created_at: original.authorization_created_at(),
                observed_at: now,
                source: "retrieve".into(),
                response_commitment: sha256(b"mock fresh cancel evidence"),
            })
            .map_err(|_| PortError::Malformed)?;
            *self.evidence.lock().map_err(|_| PortError::Persistence)? = Some(fresh.clone());
            Ok(fresh)
        }

        fn cancel(
            &self,
            command: &VerifiedPaymentCancelCommand,
            _credential: &PaymentCancelCredential,
            now: u64,
        ) -> Result<PaymentCancelEffect, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            self.cancel_calls.fetch_add(1, Ordering::Relaxed);
            let request = command.provider_request();
            assert_eq!(
                request.payment_intent_id(),
                command.action().payment_intent_id().as_str()
            );
            assert_eq!(
                request.cancellation_reason(),
                PaymentCancellationReason::RequestedByCustomer
            );
            assert_eq!(request.profile(), auths_stripe::PAYMENT_CANCEL_PROFILE);
            let mut projection = Self::canceled_projection(command, now, "cancel-response");
            match self.effect_mode.swap(0, Ordering::Relaxed) {
                1 => {
                    return Ok(PaymentCancelEffect::NotDelivered {
                        code: "connection-refused-before-send".into(),
                    });
                }
                2 => {
                    return Ok(PaymentCancelEffect::Declined {
                        code: "cancel-declined".into(),
                    });
                }
                3 => {
                    projection.status = "succeeded".into();
                    projection.cancellation_reason = None;
                    projection.amount_received_minor = command.action().amount_minor();
                    projection.charge_captured = Some(true);
                    return Ok(PaymentCancelEffect::CaptureConflict(projection));
                }
                _ => {}
            }
            if self.ambiguous.swap(false, Ordering::Relaxed) {
                Ok(PaymentCancelEffect::OutcomeUnknown(Some(projection)))
            } else {
                Ok(PaymentCancelEffect::Accepted(projection))
            }
        }

        fn observe(
            &self,
            command: &VerifiedPaymentCancelCommand,
            _credential: &PaymentCancelCredential,
            now: u64,
        ) -> Result<PaymentCancelProviderProjection, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            Ok(Self::canceled_projection(command, now, "retrieve"))
        }

        fn reconcile(
            &self,
            record: &MerchantReservationRecord,
            _credential: &PaymentCancelCredential,
            now: u64,
        ) -> Result<PaymentCancelReconciliationOutcome, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            Ok(PaymentCancelReconciliationOutcome::Canceled(
                Self::reconciled_projection(record, now),
            ))
        }
    }

    async fn json_request(
        router: &Router,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(path);
        if body.is_some() {
            builder = builder.header(CONTENT_TYPE, "application/json");
        }
        let request = builder
            .body(body.map_or_else(Body::empty, |body| Body::from(body.to_string())))
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    async fn session(router: &Router) -> Value {
        let (status, body) = json_request(router, "POST", "/api/v1/sessions", None).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    async fn execute_experiment(router: &Router, session: &Value, experiment: &str) -> Value {
        let session_id = session["session_id"].as_str().unwrap();
        let (status, body) = json_request(
            router,
            "POST",
            &format!("/api/v1/sessions/{session_id}/execute"),
            Some(json!({"experiment": experiment})),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        body
    }

    #[tokio::test]
    async fn denial_and_mismatch_stop_before_credentials_and_provider_io() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        for experiment in ["denial", "changed-action", "changed-configuration"] {
            let result = execute_experiment(&router, &session(&router).await, experiment).await;
            assert_eq!(result["outcome"], "rejected");
            assert_eq!(result["boundary"]["credential_requests"], 0);
            assert_eq!(result["boundary"]["provider_calls"], 0);
        }
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn exact_terminal_cancellation_releases_the_linked_hold_and_replays() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let fresh = session(&router).await;
        let canceled = execute_experiment(&router, &fresh, "success").await;
        assert_eq!(canceled["outcome"], "canceled");
        assert_eq!(canceled["record"]["amount_minor"], 0);
        assert_eq!(
            canceled["record"]["cancel_amount_minor"],
            CANCEL_TARGET_AMOUNT_MINOR
        );
        assert_eq!(
            canceled["record"]["authorization_release_minor"],
            AUTHORIZED_AMOUNT_MINOR
        );
        assert_eq!(canceled["record"]["state"], "cancel-committed");

        let replay = execute_experiment(&router, &fresh, "replay").await;
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["boundary"]["credential_requests"], 0);
        assert_eq!(replay["boundary"]["provider_calls"], 0);
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);

        let session_id = fresh["session_id"].as_str().unwrap();
        let (status, body) = json_request(
            &router,
            "GET",
            &format!("/api/v1/sessions/{session_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["linked_authorization"]["state"],
            "authorization-released-by-cancel"
        );
    }

    #[tokio::test]
    async fn concurrent_exact_cancel_has_one_provider_delivery() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let fresh = session(&router).await;
        let first = execute_experiment(&router, &fresh, "success");
        let second = execute_experiment(&router, &fresh, "success");
        let (first, second) = tokio::join!(first, second);
        assert!(matches!(
            first["outcome"].as_str(),
            Some("canceled" | "replay")
        ));
        assert!(matches!(
            second["outcome"].as_str(),
            Some("canceled" | "replay")
        ));
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ambiguous_delivery_retains_both_exposures_then_reconciles_without_recancel() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let fresh = session(&router).await;
        let unknown = execute_experiment(&router, &fresh, "ambiguous").await;
        assert_eq!(unknown["outcome"], "outcome-unknown");
        assert_eq!(unknown["record"]["state"], "outcome-unknown");
        let session_id = fresh["session_id"].as_str().unwrap();
        let (status, pending) = json_request(
            &router,
            "GET",
            &format!("/api/v1/sessions/{session_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(pending["linked_authorization"]["state"], "authorized");

        let (status, reconciled) = json_request(
            &router,
            "POST",
            &format!("/api/v1/sessions/{session_id}/reconcile"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["outcome"], "reconciled");
        assert_eq!(reconciled["record"]["state"], "reconciled-cancel-committed");
        assert_eq!(reconciled["transition"]["execution_attempted"], true);
        assert_eq!(reconciled["transition"]["reconciled_observation"], true);
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn capture_conflict_is_terminal_and_never_releases_the_hold() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let fresh = session(&router).await;
        environment.effect_mode.store(3, Ordering::Relaxed);
        let conflict = execute_experiment(&router, &fresh, "success").await;
        assert_eq!(conflict["outcome"], "capture-conflict");
        assert_eq!(conflict["record"]["state"], "cancel-capture-conflict");
        let session_id = fresh["session_id"].as_str().unwrap();
        let (_, status) = json_request(
            &router,
            "GET",
            &format!("/api/v1/sessions/{session_id}"),
            None,
        )
        .await;
        assert_eq!(status["linked_authorization"]["state"], "authorized");
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn durable_replay_survives_restart_without_credentials_or_provider_io() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let config = AppConfig::for_test(temp.path().to_path_buf());
        let first_router = app_with_environment(config.clone(), environment.clone()).unwrap();
        let fresh = session(&first_router).await;
        let session_id = fresh["session_id"].as_str().unwrap().to_owned();
        assert_eq!(
            execute_experiment(&first_router, &fresh, "success").await["outcome"],
            "canceled"
        );
        drop(first_router);

        let restarted = app_with_environment(config, environment.clone()).unwrap();
        let (status, replay) = json_request(
            &restarted,
            "POST",
            &format!("/api/v1/sessions/{session_id}/execute"),
            Some(json!({"experiment": "replay"})),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["boundary"]["credential_requests"], 0);
        assert_eq!(replay["boundary"]["provider_calls"], 0);
        assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn definite_provider_failures_release_only_the_cancellation_claim() {
        for (mode, expected) in [(1, "not-delivered"), (2, "provider-declined")] {
            let temp = tempfile::tempdir().unwrap();
            let environment = Arc::new(MockEnvironment::new());
            let router = app_with_environment(
                AppConfig::for_test(temp.path().to_path_buf()),
                environment.clone(),
            )
            .unwrap();
            let fresh = session(&router).await;
            environment.effect_mode.store(mode, Ordering::Relaxed);
            let result = execute_experiment(&router, &fresh, "success").await;
            assert_eq!(result["outcome"], expected);
            assert_eq!(result["record"]["state"], "released");
            let session_id = fresh["session_id"].as_str().unwrap();
            let (_, status) = json_request(
                &router,
                "GET",
                &format!("/api/v1/sessions/{session_id}"),
                None,
            )
            .await;
            assert_eq!(status["linked_authorization"]["state"], "authorized");
            assert_eq!(environment.cancel_calls.load(Ordering::Relaxed), 1);
        }
    }
}
