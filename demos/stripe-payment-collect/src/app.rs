use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_stripe::{
    Currency, DigestHex, ExecutePaymentCollectRequest, MERCHANT_POLICY_PROVENANCE,
    MerchantAggregateBudget, MerchantBudgetWindow, MerchantConnectAccount, MerchantOperation,
    MerchantPaymentStore, PaymentCollectService, PaymentCollectServiceDependencies,
    PaymentCollectWorkflowOutcome, PersistentMerchantPaymentStore, SdkPaymentCollectProofVerifier,
    StripeBoundedMerchantPaymentPolicyInput, StripeBoundedMerchantPaymentPolicyV1,
    StripeExactPaymentCollectInput, StripeExactPaymentCollectV1,
    StripeMerchantEvaluatorConfigurationV1, StripePaymentCollectProfile, SystemClock,
    fixed_merchant_metadata_commitment, merchant_statement_descriptor_commitment,
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
    stripe::{DemoPaymentCollectEnvironment, LivePaymentCollectEnvironment},
};

const API_SCHEMA: &str = "auths.stripe.payment-collect-demo/1";
const EXECUTOR_AUDIENCE: &str = "https://stripe-collect-executor.auths.dev";
const SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_SESSIONS: usize = 256;
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const AMOUNT_MINOR: u64 = 500;
const OPERATION_LIMIT_MINOR: u64 = 1_000;
const CUSTOMER_LIMIT_MINOR: u64 = 1_500;
const ORDER_LIMIT_MINOR: u64 = 750;
const FIXED_AGGREGATE_LIMIT_MINOR: u64 = 2_000;
const ROLLING_AGGREGATE_LIMIT_MINOR: u64 = 1_500;

/// Native collection demo deployment configuration.
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
                .unwrap_or_else(|_| "/data/auths-stripe-payment-collect".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        let region = checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?;
        let release = checked_label(
            env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
        )?;
        let public_api_base = env::var("AUTHS_PAYMENT_COLLECT_PUBLIC_API_BASE").unwrap_or_default();
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
    environment: Arc<dyn DemoPaymentCollectEnvironment>,
    store: Arc<dyn MerchantPaymentStore>,
    receipts: Arc<ReceiptJournal>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    workflow_id: String,
    evidence: auths_stripe::MerchantPaymentEvidenceV1,
    policy: StripeBoundedMerchantPaymentPolicyV1,
    required_configuration: StripeMerchantEvaluatorConfigurationV1,
    exact: Variant,
    denied: Variant,
    changed_action: Variant,
    last_result: Option<Value>,
}

#[derive(Clone)]
struct Variant {
    action: StripeExactPaymentCollectV1,
    proof_verifier: Arc<SdkPaymentCollectProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    experiment: String,
}

/// Builds the real Stripe test-mode application.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let environment = Arc::new(
        LivePaymentCollectEnvironment::from_environment().map_err(|_| StartupError::Stripe)?,
    );
    app_with_environment(config, environment)
}

/// Builds the application with an explicit collection-only environment.
pub fn app_with_environment(
    config: AppConfig,
    environment: Arc<dyn DemoPaymentCollectEnvironment>,
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
        format!("window.AUTHS_PAYMENT_COLLECT_API_BASE = {value};\n"),
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
        "account_commitment": auths_stripe::canonical::sha256(
            state.environment.account_id().as_str().as_bytes()
        ),
        "api_version": state.environment.api_version(),
    }))
}

async fn scenario(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": auths_stripe::PAYMENT_COLLECT_PROFILE,
        "policy_type": auths_stripe::MERCHANT_POLICY_TYPE,
        "evaluator": auths_stripe::MERCHANT_EVALUATOR_ID,
        "policy_provenance": MERCHANT_POLICY_PROVENANCE,
        "execution_mode": state.environment.execution_mode(),
        "amount_minor": AMOUNT_MINOR,
        "currency": "usd",
        "agent_has_stripe_key": false,
        "capture_method": "automatic",
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "the endpoint assembles one literal side-by-side collection experiment"
)]
async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let session_id = random_id()?;
    let workflow_id = format!("collect-{session_id}");
    let order_scope = format!("order-{session_id}");
    let environment = Arc::clone(&state.environment);
    let seed_workflow = workflow_id.clone();
    let seed_order = order_scope.clone();
    let fixture = tokio::task::spawn_blocking(move || {
        environment.seed_collection(&seed_workflow, &seed_order, now)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "stripe-fixture-unavailable",
            "Stripe test mode could not create the Customer and attached PaymentMethod",
        )
    })?;
    let policy = collection_policy(&fixture.evidence, now)?;
    let required_configuration = StripeMerchantEvaluatorConfigurationV1::for_collect_policy(
        &policy,
        "stripe-collect-demo-v1",
        state.environment.account_id().clone(),
        MerchantConnectAccount::Platform,
        state.environment.api_version(),
        EXECUTOR_AUDIENCE,
    )
    .map_err(|_| ApiError::internal())?;
    let exact_action = collection_action(
        &workflow_id,
        &fixture.evidence,
        &policy,
        &required_configuration,
        AMOUNT_MINOR,
        now,
        &session_id,
    )?;
    let denied_workflow = format!("{workflow_id}-denied");
    let denied_action = collection_action(
        &denied_workflow,
        &fixture.evidence,
        &policy,
        &required_configuration,
        OPERATION_LIMIT_MINOR + 1,
        now,
        &format!("{session_id}01"),
    )?;
    let changed_action = collection_action(
        &workflow_id,
        &fixture.evidence,
        &policy,
        &required_configuration,
        AMOUNT_MINOR + 1,
        now,
        &session_id,
    )?;
    let exact = proof_variant(&exact_action, now)?;
    let denied = proof_variant(&denied_action, now)?;
    let changed_action = Variant {
        action: changed_action,
        proof_verifier: Arc::clone(&exact.proof_verifier),
        proof: exact.proof.clone(),
        request: exact.request.clone(),
    };
    let aggregate = state
        .store
        .snapshot(&policy, state.environment.account_id(), now)
        .map_err(|_| ApiError::internal())?;
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "profile": auths_stripe::PAYMENT_COLLECT_PROFILE,
        "operation": "collect",
        "delegation": {
            "label": "immutable configured policy",
            "provenance": MERCHANT_POLICY_PROVENANCE,
            "policy": policy,
            "policy_digest": policy.digest().map_err(|_| ApiError::internal())?,
            "evaluator_semantic_id": auths_stripe::MERCHANT_EVALUATOR_ID,
            "evaluator_semantic_version": auths_stripe::MERCHANT_EVALUATOR_VERSION,
            "per_action_limit_minor": OPERATION_LIMIT_MINOR,
            "per_customer_limit_minor": CUSTOMER_LIMIT_MINOR,
            "per_order_limit_minor": ORDER_LIMIT_MINOR,
            "fixed_aggregate_limit_minor": FIXED_AGGREGATE_LIMIT_MINOR,
            "rolling_aggregate_limit_minor": ROLLING_AGGREGATE_LIMIT_MINOR,
        },
        "agent_selected_exact_payment": exact_action,
        "fresh_stripe_evidence": fixture.evidence,
        "aggregate_budget": aggregate,
        "required_configuration": required_configuration,
        "executed_configuration": required_configuration,
        "configuration_equal": true,
        "experiments": [
            {"id":"success","label":"Exact collection","detail":"Collect exactly $5.00 once."},
            {"id":"denial","label":"One past limit","detail":"Request $10.01 against a $10.00 per-action ceiling."},
            {"id":"changed-action","label":"Changed action","detail":"Alter the amount after exact authorization."},
            {"id":"changed-configuration","label":"Changed configuration","detail":"Execute with a different runtime commitment."},
            {"id":"replay","label":"Replay","detail":"Submit the same exact workflow again without another charge."},
            {"id":"ambiguous","label":"Lost response","detail":"Deliver once, retain capacity as unknown, then reconcile."}
        ],
        "agent_has_stripe_key": false,
    });
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the collection session pool is full",
        ));
    }
    sessions.insert(
        session_id,
        Session {
            expires_at: now + SESSION_TTL_SECONDS,
            workflow_id,
            evidence: fixture.evidence,
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
        PaymentCollectService::new(PaymentCollectServiceDependencies {
            proof_verifier: materials.variant.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            store,
            receipt_sink: receipts,
            clock: SystemClock,
            executed_configuration: materials.executed_configuration,
        })
        .execute(ExecutePaymentCollectRequest {
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
    .map_err(|_error| {
        #[cfg(test)]
        eprintln!("collection service failed: {_error:?}");
        ApiError::internal()
    })?;
    let after = state.environment.diagnostics();
    let mut response = outcome_projection(
        outcome,
        after
            .credential_requests
            .saturating_sub(before.credential_requests),
        after.provider_calls.saturating_sub(before.provider_calls),
    )?;
    attach_latest_receipt(&state.receipts, &executed_workflow, &mut response)?;
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_result = Some(response.clone());
    }
    Ok(Json(response))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let workflow_id = state
        .sessions
        .lock()
        .await
        .get(&session_id)
        .ok_or_else(ApiError::session_missing)?
        .workflow_id
        .clone();
    let before = state.environment.diagnostics();
    let materials = {
        let sessions = state.sessions.lock().await;
        let session = sessions
            .get(&session_id)
            .ok_or_else(ApiError::session_missing)?;
        execution_materials(session, "success")?
    };
    let environment = Arc::clone(&state.environment);
    let store = Arc::clone(&state.store);
    let receipts = Arc::clone(&state.receipts);
    let reconciliation_workflow = workflow_id.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        PaymentCollectService::new(PaymentCollectServiceDependencies {
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
    )?;
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
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "aggregate_budget": aggregate,
        "last_result": session.last_result,
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
    evidence: auths_stripe::MerchantPaymentEvidenceV1,
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
            StripeMerchantEvaluatorConfigurationV1::for_collect_policy(
                &session.policy,
                "stripe-collect-demo-changed-v1",
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

fn collection_policy(
    evidence: &auths_stripe::MerchantPaymentEvidenceV1,
    now: u64,
) -> Result<StripeBoundedMerchantPaymentPolicyV1, ApiError> {
    let currency = Currency::parse("usd").map_err(|_| ApiError::internal())?;
    let valid_from = now.saturating_sub(60);
    let expires_at = now.checked_add(300).ok_or_else(ApiError::internal)?;
    StripeBoundedMerchantPaymentPolicyV1::new(StripeBoundedMerchantPaymentPolicyInput {
        policy_id: format!(
            "collect-policy-{}",
            &evidence.response_commitment().as_str()[..16]
        ),
        valid_from,
        expires_at,
        allowed_operations: vec![MerchantOperation::Collect],
        allowed_test_account_ids: vec![evidence.stripe_account_id().clone()],
        allowed_connect_accounts: vec![evidence.connect_account().clone()],
        allowed_customer_ids: vec![evidence.customer_id().clone()],
        allowed_payment_method_ids: vec![evidence.payment_method_id().clone()],
        allowed_payment_method_types: vec![evidence.payment_method_type().into()],
        allowed_currencies: vec![currency.clone()],
        allowed_order_scopes: vec![evidence.order_scope().into()],
        allowed_cancellation_reasons: Vec::new(),
        per_operation_absolute_minor_by_currency: BTreeMap::from([(
            MerchantOperation::Collect,
            BTreeMap::from([(currency.clone(), OPERATION_LIMIT_MINOR)]),
        )]),
        per_customer_minor_by_currency: BTreeMap::from([(currency.clone(), CUSTOMER_LIMIT_MINOR)]),
        per_order_minor_by_currency: BTreeMap::from([(currency.clone(), ORDER_LIMIT_MINOR)]),
        aggregate_budgets: vec![
            MerchantAggregateBudget::new(
                "collect-fixed",
                MerchantOperation::Collect,
                currency.clone(),
                FIXED_AGGREGATE_LIMIT_MINOR,
                MerchantBudgetWindow::Fixed {
                    starts_at: valid_from,
                    ends_at: expires_at,
                },
                valid_from,
            )
            .map_err(|_| ApiError::internal())?,
            MerchantAggregateBudget::new(
                "collect-rolling",
                MerchantOperation::Collect,
                currency,
                ROLLING_AGGREGATE_LIMIT_MINOR,
                MerchantBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
                valid_from,
            )
            .map_err(|_| ApiError::internal())?,
        ],
        maximum_authorization_age_seconds: 0,
        minimum_capture_window_seconds: 0,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec![evidence.stripe_api_version().into()],
    })
    .map_err(|_| ApiError::internal())
}

#[allow(clippy::too_many_arguments)]
fn collection_action(
    workflow_id: &str,
    evidence: &auths_stripe::MerchantPaymentEvidenceV1,
    policy: &StripeBoundedMerchantPaymentPolicyV1,
    configuration: &StripeMerchantEvaluatorConfigurationV1,
    amount_minor: u64,
    now: u64,
    nonce_material: &str,
) -> Result<StripeExactPaymentCollectV1, ApiError> {
    let policy_digest = policy.digest().map_err(|_| ApiError::internal())?;
    StripeExactPaymentCollectV1::new(StripeExactPaymentCollectInput {
        stripe_account_id: evidence.stripe_account_id().clone(),
        connect_account: evidence.connect_account().clone(),
        customer_id: evidence.customer_id().clone(),
        payment_method_id: evidence.payment_method_id().clone(),
        payment_method_type: evidence.payment_method_type().into(),
        order_scope: evidence.order_scope().into(),
        amount_minor,
        currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
        statement_descriptor_commitment: merchant_statement_descriptor_commitment(),
        fixed_metadata_commitment: fixed_merchant_metadata_commitment(
            workflow_id,
            auths_stripe::PAYMENT_COLLECT_PROFILE,
            evidence.order_scope(),
            &policy_digest,
        )
        .map_err(|_| ApiError::internal())?,
        stripe_api_version: evidence.stripe_api_version().into(),
        required_policy_digest: policy_digest,
        required_configuration_digest: configuration.digest().map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        expires_at: now.checked_add(300).ok_or_else(ApiError::internal)?,
        nonce: auths_stripe::canonical::sha256(
            format!("auths-collect-nonce-v1:{nonce_material}").as_bytes(),
        ),
    })
    .map_err(|_| ApiError::internal())
}

fn proof_variant(action: &StripeExactPaymentCollectV1, now: u64) -> Result<Variant, ApiError> {
    let canonical = StripePaymentCollectProfile
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
        proof_verifier: Arc::new(SdkPaymentCollectProofVerifier::new(fixture.verifier)),
        proof: fixture.proof,
        request: fixture.request,
    })
}

fn outcome_projection(
    outcome: PaymentCollectWorkflowOutcome,
    credential_requests: u64,
    provider_calls: u64,
) -> Result<Value, ApiError> {
    let boundary = json!({
        "credential_requests": credential_requests,
        "provider_calls": provider_calls,
        "agent_received_credential": false,
        "client_secret_exposed": false,
    });
    Ok(match outcome {
        PaymentCollectWorkflowOutcome::Rejected { receipt, persisted } => json!({
            "schema": API_SCHEMA,
            "outcome": "rejected",
            "decision": receipt,
            "persisted": persisted,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::Collected { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "collected",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::Replay { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "replay",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::Conflict { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "conflict",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::CapacityChanged {
            budget_id,
            available_minor,
        } => json!({
            "schema": API_SCHEMA,
            "outcome": "capacity-changed",
            "budget_id": budget_id,
            "available_minor": available_minor,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::CriticalEvidenceChanged { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "critical-evidence-changed",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::NotDelivered { code, record } => json!({
            "schema": API_SCHEMA,
            "outcome": "not-delivered",
            "code": code,
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::ProviderDeclined { code, record } => json!({
            "schema": API_SCHEMA,
            "outcome": "provider-declined",
            "code": code,
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::CustomerActionRequired { record } => json!({
            "schema": API_SCHEMA,
            "outcome": "customer-action-required",
            "record": record,
            "boundary": boundary,
        }),
        PaymentCollectWorkflowOutcome::OutcomeUnknown { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "outcome-unknown",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
            "reconciliation_required": true,
        }),
        PaymentCollectWorkflowOutcome::Reconciled { record, receipt } => json!({
            "schema": API_SCHEMA,
            "outcome": "reconciled",
            "record": record,
            "transition": receipt,
            "boundary": boundary,
        }),
    })
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
        .find(|receipt| collection_receipt_workflow(receipt) == Some(workflow_id))
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

fn collection_receipt_workflow(receipt: &auths_stripe::StripeReceipt) -> Option<&str> {
    match receipt {
        auths_stripe::StripeReceipt::MerchantCollectionDecision(receipt) => {
            Some(&receipt.workflow_id)
        }
        auths_stripe::StripeReceipt::MerchantCollectionTransition(receipt) => {
            Some(receipt.reservation.workflow_id())
        }
        auths_stripe::StripeReceipt::MerchantCollectionObservation(receipt) => {
            Some(&receipt.workflow_id)
        }
        auths_stripe::StripeReceipt::BoundedDecision(_)
        | auths_stripe::StripeReceipt::Reservation(_)
        | auths_stripe::StripeReceipt::Decision(_)
        | auths_stripe::StripeReceipt::Execution(_)
        | auths_stripe::StripeReceipt::Observation(_) => None,
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
            Self::State => formatter.write_str("durable collection state is unavailable"),
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
            "the protected collection service failed closed",
        )
    }

    const fn session_missing() -> Self {
        Self::new(
            StatusCode::GONE,
            "session-unavailable",
            "the collection session is missing or expired",
        )
    }

    const fn receipt_missing() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "receipt-not-found",
            "the canonical collection receipt was not found",
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
        ChargeId, CredentialProvider, CustomerId, MerchantPaymentEvidenceInput,
        MerchantPaymentEvidenceV1, MerchantProviderProjection, MerchantReservationRecord,
        PaymentCollectEffect, PaymentCollectGateway, PaymentCollectReconciliationOutcome,
        PaymentIntentId, PaymentMethodId, PortError, StripeAccountId, StripeCredential,
        VerifiedPaymentCollectCommand,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::stripe::{CollectionFixture, EnvironmentDiagnostics};

    struct MockEnvironment {
        account: StripeAccountId,
        evidence: StdMutex<Option<MerchantPaymentEvidenceV1>>,
        ambiguous: AtomicBool,
        critical_evidence_changed: AtomicBool,
        effect_mode: AtomicU64,
        credential_requests: AtomicU64,
        provider_calls: AtomicU64,
        create_calls: AtomicU64,
    }

    impl MockEnvironment {
        fn new() -> Self {
            Self {
                account: StripeAccountId::parse("acct_collectmock01").unwrap(),
                evidence: StdMutex::new(None),
                ambiguous: AtomicBool::new(false),
                critical_evidence_changed: AtomicBool::new(false),
                effect_mode: AtomicU64::new(0),
                credential_requests: AtomicU64::new(0),
                provider_calls: AtomicU64::new(0),
                create_calls: AtomicU64::new(0),
            }
        }

        fn projection(&self, amount_minor: u64, now: u64) -> MerchantProviderProjection {
            MerchantProviderProjection {
                payment_intent_id: PaymentIntentId::parse("pi_collectmock0000000001").unwrap(),
                charge_id: Some(ChargeId::parse("ch_collectmock0000000001").unwrap()),
                status: "succeeded".into(),
                amount_minor,
                currency: Currency::parse("usd").unwrap(),
                amount_capturable_minor: 0,
                amount_received_minor: amount_minor,
                capture_before: None,
                stripe_request_id: Some("req_collectmock0001".into()),
                response_digest: auths_stripe::canonical::sha256(b"mock collection projection"),
                observed_at: now,
                source: "retrieve".into(),
            }
        }
    }

    impl CredentialProvider for MockEnvironment {
        fn mutation_credential(
            &self,
            account: &StripeAccountId,
        ) -> Result<StripeCredential, PortError> {
            if account != &self.account {
                return Err(PortError::InvalidConfiguration);
            }
            self.credential_requests.fetch_add(1, Ordering::Relaxed);
            StripeCredential::new(["sk", "test", "runtime_only_collect_mock"].join("_"))
        }
    }

    impl DemoPaymentCollectEnvironment for MockEnvironment {
        fn seed_collection(
            &self,
            _workflow_id: &str,
            order_scope: &str,
            now: u64,
        ) -> Result<CollectionFixture, PortError> {
            let customer =
                CustomerId::parse("cus_collectmock00000001").map_err(|_| PortError::Malformed)?;
            let evidence = MerchantPaymentEvidenceV1::new(MerchantPaymentEvidenceInput {
                stripe_account_id: self.account.clone(),
                connect_account: MerchantConnectAccount::Platform,
                customer_id: customer.clone(),
                payment_method_id: PaymentMethodId::parse("pm_collectmock000000001")
                    .map_err(|_| PortError::Malformed)?,
                payment_method_type: "card".into(),
                attached_customer_id: customer,
                livemode: false,
                stripe_api_version: "2025-04-30.basil".into(),
                order_scope: order_scope.into(),
                consent_order_commitment: auths_stripe::canonical::sha256(b"mock order consent"),
                supports_manual_capture: true,
                prior_payments: Vec::new(),
                observed_at: now,
                source: "stripe-api-and-order-store".into(),
                response_commitment: auths_stripe::canonical::sha256(b"mock sanitized evidence"),
            })
            .map_err(|_| PortError::Malformed)?;
            *self.evidence.lock().map_err(|_| PortError::Persistence)? = Some(evidence.clone());
            Ok(CollectionFixture {
                evidence,
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

        fn api_version(&self) -> &str {
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

    impl PaymentCollectGateway for MockEnvironment {
        fn reread_critical_evidence(
            &self,
            command: &VerifiedPaymentCollectCommand,
            _credential: &StripeCredential,
            now: u64,
        ) -> Result<MerchantPaymentEvidenceV1, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            let evidence = self
                .evidence
                .lock()
                .map_err(|_| PortError::Persistence)?
                .clone()
                .ok_or(PortError::EvidenceUnavailable)?;
            MerchantPaymentEvidenceV1::new(MerchantPaymentEvidenceInput {
                stripe_account_id: evidence.stripe_account_id().clone(),
                connect_account: evidence.connect_account().clone(),
                customer_id: evidence.customer_id().clone(),
                payment_method_id: evidence.payment_method_id().clone(),
                payment_method_type: evidence.payment_method_type().into(),
                attached_customer_id: evidence.customer_id().clone(),
                livemode: false,
                stripe_api_version: evidence.stripe_api_version().into(),
                order_scope: command.action().order_scope().into(),
                consent_order_commitment: if self
                    .critical_evidence_changed
                    .swap(false, Ordering::Relaxed)
                {
                    auths_stripe::canonical::sha256(b"changed order consent")
                } else {
                    evidence.consent_order_commitment().clone()
                },
                supports_manual_capture: true,
                prior_payments: Vec::new(),
                observed_at: now,
                source: "stripe-api-and-order-store".into(),
                response_commitment: evidence.response_commitment().clone(),
            })
            .map_err(|_| PortError::Malformed)
        }

        fn collect(
            &self,
            command: &VerifiedPaymentCollectCommand,
            _credential: &StripeCredential,
            now: u64,
        ) -> Result<PaymentCollectEffect, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            self.create_calls.fetch_add(1, Ordering::Relaxed);
            let request = command.provider_request();
            assert_eq!(
                (
                    request.amount_minor(),
                    request.currency(),
                    request.customer_id(),
                    request.payment_method_id(),
                    request.payment_method_type(),
                    request.confirmation_method(),
                    request.capture_method(),
                    request.statement_descriptor_suffix(),
                    request.profile(),
                    request.order_scope(),
                    request.policy_digest(),
                    request.workflow_id(),
                ),
                (
                    command.action().amount_minor(),
                    command.action().currency().as_str(),
                    command.action().customer_id().as_str(),
                    command.action().payment_method_id().as_str(),
                    "card",
                    "manual",
                    "automatic",
                    "AUTHS DEMO",
                    auths_stripe::PAYMENT_COLLECT_PROFILE,
                    command.action().order_scope(),
                    command.policy_digest().as_str(),
                    command.workflow_id(),
                )
            );
            let provider = self.projection(command.action().amount_minor(), now);
            match self.effect_mode.swap(0, Ordering::Relaxed) {
                1 => {
                    return Ok(PaymentCollectEffect::NotDelivered {
                        code: "connection-refused-before-send".into(),
                    });
                }
                2 => {
                    return Ok(PaymentCollectEffect::Declined {
                        code: "card-declined".into(),
                    });
                }
                3 => return Ok(PaymentCollectEffect::Processing(provider)),
                4 => return Ok(PaymentCollectEffect::CustomerActionRequired(provider)),
                _ => {}
            }
            if self.ambiguous.swap(false, Ordering::Relaxed) {
                Ok(PaymentCollectEffect::OutcomeUnknown(Some(provider)))
            } else {
                Ok(PaymentCollectEffect::Accepted(provider))
            }
        }

        fn observe(
            &self,
            command: &VerifiedPaymentCollectCommand,
            _credential: &StripeCredential,
            _payment_intent: &PaymentIntentId,
            now: u64,
        ) -> Result<MerchantProviderProjection, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.projection(command.action().amount_minor(), now))
        }

        fn reconcile(
            &self,
            record: &MerchantReservationRecord,
            _credential: &StripeCredential,
            now: u64,
        ) -> Result<PaymentCollectReconciliationOutcome, PortError> {
            self.provider_calls.fetch_add(1, Ordering::Relaxed);
            Ok(PaymentCollectReconciliationOutcome::Committed(
                self.projection(record.amount_minor(), now),
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
        assert_eq!(status, StatusCode::OK);
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
        assert_eq!(status, StatusCode::OK);
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
            let fresh = session(&router).await;
            let result = execute_experiment(&router, &fresh, experiment).await;
            assert_eq!(result["outcome"], "rejected");
            assert_eq!(result["boundary"]["credential_requests"], 0);
            assert_eq!(result["boundary"]["provider_calls"], 0);
        }
        assert_eq!(environment.create_calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn exact_collection_replay_never_creates_a_second_payment() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let fresh = session(&router).await;
        let collected = execute_experiment(&router, &fresh, "success").await;
        assert_eq!(collected["outcome"], "collected");
        assert_eq!(collected["record"]["state"], "committed");
        let replay = execute_experiment(&router, &fresh, "replay").await;
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["boundary"]["credential_requests"], 0);
        assert_eq!(replay["boundary"]["provider_calls"], 0);
        assert_eq!(environment.create_calls.load(Ordering::Relaxed), 1);
        let encoded = replay.to_string();
        assert!(!encoded.contains("\"client_secret\":"));
        assert_eq!(replay["boundary"]["client_secret_exposed"], false);
        assert!(!encoded.contains(&["sk", "test"].join("_")));
    }

    #[tokio::test]
    async fn verified_command_derives_the_exact_provider_request() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();
        let result = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(result["outcome"], "collected");
        assert_eq!(environment.create_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn ambiguous_delivery_retains_capacity_and_reconciles_without_create() {
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
        let (status, reconciled) = json_request(
            &router,
            "POST",
            &format!("/api/v1/sessions/{session_id}/reconcile"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(reconciled["outcome"], "reconciled");
        assert_eq!(reconciled["record"]["state"], "reconciled-committed");
        assert_eq!(environment.create_calls.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn receipt_api_is_machine_readable_and_public_link_is_designed_html() {
        let temp = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            Arc::new(MockEnvironment::new()),
        )
        .unwrap();
        let fresh = session(&router).await;
        let result = execute_experiment(&router, &fresh, "success").await;
        let receipt_id = result["receipt_id"].as_str().unwrap();
        let (status, machine) = json_request(
            &router,
            "GET",
            &format!("/api/v1/receipts/{receipt_id}"),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(machine["receipt_id"], receipt_id);
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/receipts/{receipt_id}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(CONTENT_TYPE).unwrap(),
            "text/html; charset=utf-8"
        );
    }

    #[tokio::test]
    async fn provider_failures_have_conservative_profile_specific_capacity_semantics() {
        let temp = tempfile::tempdir().unwrap();
        let environment = Arc::new(MockEnvironment::new());
        let router = app_with_environment(
            AppConfig::for_test(temp.path().to_path_buf()),
            environment.clone(),
        )
        .unwrap();

        environment.effect_mode.store(1, Ordering::Relaxed);
        let not_delivered = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(not_delivered["outcome"], "not-delivered");
        assert_eq!(not_delivered["record"]["state"], "released");

        environment.effect_mode.store(2, Ordering::Relaxed);
        let declined = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(declined["outcome"], "provider-declined");
        assert_eq!(declined["record"]["state"], "released");

        environment.effect_mode.store(3, Ordering::Relaxed);
        let processing = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(processing["outcome"], "outcome-unknown");
        assert_eq!(processing["record"]["state"], "outcome-unknown");

        environment.effect_mode.store(4, Ordering::Relaxed);
        let incompatible = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(incompatible["outcome"], "customer-action-required");
        assert_eq!(incompatible["record"]["state"], "outcome-unknown");

        environment
            .critical_evidence_changed
            .store(true, Ordering::Relaxed);
        let changed = execute_experiment(&router, &session(&router).await, "success").await;
        assert_eq!(changed["outcome"], "critical-evidence-changed");
        assert_eq!(changed["record"]["state"], "released");
    }
}
