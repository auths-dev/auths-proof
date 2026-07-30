use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_profile_api::ActionProfile as _;
use auths_stripe::{
    AggregateImmediateBudget, AggregateRecurringBudget, Currency, DigestHex,
    ExecuteSubscriptionModifyRequest, PersistentSubscriptionModificationStore,
    SUBSCRIPTION_MODIFY_PROFILE, SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA,
    SdkSubscriptionModifyProofVerifier, StripeBoundedSubscriptionPolicyInput,
    StripeBoundedSubscriptionPolicyV1, StripeExactSubscriptionModifyInput,
    StripeExactSubscriptionModifyV1, StripeSubscriptionConfigurationV1,
    StripeSubscriptionModifyProfile, SubscriptionConnectAccount, SubscriptionInterval,
    SubscriptionModificationStore, SubscriptionModifyItem, SubscriptionModifyService,
    SubscriptionModifyServiceDependencies, SubscriptionModifyWorkflowOutcome,
    SubscriptionOperation, SubscriptionPaymentBehavior, SubscriptionRecurringLimit, SystemClock,
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
    receipts::ReceiptJournal,
    stripe::{DemoSubscriptionModifyEnvironment, LiveSubscriptionModifyEnvironment},
};

const API_SCHEMA: &str = "auths.stripe.subscription-modify-demo/1";
const EXECUTOR_AUDIENCE: &str = "https://stripe-subscription-modify.auths.dev";
const SESSION_TTL_SECONDS: u64 = 10 * 60;
const MAX_SESSIONS: usize = 128;
const MAX_REQUEST_BYTES: usize = 2 * 1024;

#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    state_directory: Arc<Path>,
    region: Arc<str>,
    release: Arc<str>,
    public_api_base: Arc<str>,
}

impl AppConfig {
    /// Loads strict local or deployed configuration.
    ///
    /// # Errors
    ///
    /// Rejects missing, relative, or unsafe deployment values.
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
                .unwrap_or_else(|_| "/data/auths-stripe-subscription-modify".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        let public_api_base =
            env::var("AUTHS_SUBSCRIPTION_MODIFY_PUBLIC_API_BASE").unwrap_or_default();
        if !public_api_base.is_empty()
            && (!(public_api_base.starts_with("https://")
                || public_api_base.starts_with("http://localhost:"))
                || public_api_base.ends_with('/')
                || public_api_base.len() > 256)
        {
            return Err(StartupError::Invalid);
        }
        Ok(Self {
            allowed_origin: HeaderValue::from_str(&origin).map_err(|_| StartupError::Invalid)?,
            state_directory: state_directory.into(),
            region: checked_label(env::var("FLY_REGION").unwrap_or_else(|_| "local".into()))?
                .into(),
            release: checked_label(
                env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into()),
            )?
            .into(),
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
    environment: Arc<dyn DemoSubscriptionModifyEnvironment>,
    store: Arc<dyn SubscriptionModificationStore>,
    receipts: Arc<ReceiptJournal>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    workflow_base: String,
    last_workflow: Option<String>,
    action: StripeExactSubscriptionModifyV1,
    policy: StripeBoundedSubscriptionPolicyV1,
    evidence: auths_stripe::SubscriptionModifyEvidenceV1,
    configuration: StripeSubscriptionConfigurationV1,
    canonical_action: auths_model::CanonicalAction,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
    verifier: Arc<SdkSubscriptionModifyProofVerifier>,
    last_result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    experiment: String,
}

/// Builds the live Stripe test-mode router.
///
/// # Errors
///
/// Fails closed when Stripe or durable state cannot initialize.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let environment = Arc::new(
        LiveSubscriptionModifyEnvironment::from_environment().map_err(|_| StartupError::Stripe)?,
    );
    app_with_environment(config, environment)
}

/// Builds the router with an explicit closed provider environment.
///
/// # Errors
///
/// Fails closed when durable liability or receipt state cannot initialize.
pub fn app_with_environment(
    config: AppConfig,
    environment: Arc<dyn DemoSubscriptionModifyEnvironment>,
) -> Result<Router, StartupError> {
    let store = Arc::new(
        PersistentSubscriptionModificationStore::new(
            config.state_directory.join("modifications.json"),
        )
        .map_err(|_| StartupError::State)?,
    );
    let receipts = Arc::new(
        ReceiptJournal::new(config.state_directory.join("receipts.jsonl"))
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
        .route("/receipt.js", get(receipt_js))
        .route("/styles.css", get(styles))
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}", get(session_status))
        .route("/api/v1/sessions/{session_id}/preview", post(preview))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/sessions/{session_id}/reconcile", post(reconcile))
        .route(
            "/api/v1/sessions/{session_id}/advance-clock",
            post(advance_clock),
        )
        .route(
            "/api/v1/subscriptions/{subscription_id}/timeline",
            get(timeline),
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
        format!("window.AUTHS_SUBSCRIPTION_MODIFY_API_BASE = {value};\n"),
    )
}
async fn receipt_page(AxumPath(id): AxumPath<String>) -> Response {
    if DigestHex::parse(id).is_err() {
        return StatusCode::NOT_FOUND.into_response();
    }
    Html(include_str!("../web/receipt.html")).into_response()
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(
        json!({"schema":API_SCHEMA,"status":"ok","region":&*state.config.region,"release":&*state.config.release}),
    )
}
async fn readiness(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "status": "ready",
        "account_commitment": auths_stripe::canonical::sha256(state.environment.account_id().as_str().as_bytes()),
        "api_version": state.environment.api_version(),
        "client_secret_exposed": false
    }))
}
async fn scenario() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": SUBSCRIPTION_MODIFY_PROFILE,
        "policy_type": auths_stripe::SUBSCRIPTION_POLICY_TYPE,
        "evaluator": auths_stripe::SUBSCRIPTION_EVALUATOR_ID,
        "effect": "subscription-modify-pending-if-incomplete",
        "finite_term": true,
        "test_clock": true,
        "agent_has_stripe_key": false
    }))
}

#[allow(clippy::too_many_lines)]
async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let session_id = random_id()?;
    let workflow_base = format!("subscription-{session_id}");
    let environment = Arc::clone(&state.environment);
    let seed = workflow_base.clone();
    let fixture = tokio::task::spawn_blocking(move || environment.seed_fixture(&seed, now))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::stripe())?;
    let evidence = fixture.evidence;
    let catalog = evidence.catalog.first().ok_or_else(ApiError::internal)?;
    let mandate_digest = evidence.mandate_receipt_digest.clone();
    let policy = StripeBoundedSubscriptionPolicyV1::new(StripeBoundedSubscriptionPolicyInput {
        policy_id: format!("policy-{session_id}"),
        valid_from: now.saturating_sub(60),
        expires_at: now + 3_600,
        allowed_operations: vec![SubscriptionOperation::Create],
        allowed_test_account_ids: vec![state.environment.account_id().clone()],
        allowed_customer_ids: vec![evidence.customer_id.clone()],
        allowed_product_ids: vec![catalog.product_id.clone()],
        allowed_price_ids: vec![catalog.price_id.clone()],
        allowed_payment_method_ids: vec![evidence.payment_method_id.clone()],
        allowed_mandate_receipt_digests: vec![mandate_digest.clone()],
        allowed_currencies: vec![Currency::parse("usd").map_err(|_| ApiError::internal())?],
        allowed_intervals: vec![SubscriptionInterval::Week],
        allowed_payment_behaviors: vec![SubscriptionPaymentBehavior::ErrorIfIncomplete],
        maximum_quantity_by_price: BTreeMap::from([(catalog.price_id.clone(), 2)]),
        maximum_recurring_minor_by_currency_and_interval: vec![SubscriptionRecurringLimit {
            currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
            interval: SubscriptionInterval::Week,
            limit_minor: 1_000,
        }],
        maximum_first_invoice_minor_by_currency: BTreeMap::from([(
            Currency::parse("usd").map_err(|_| ApiError::internal())?,
            500,
        )]),
        maximum_term_seconds: 22 * 24 * 60 * 60,
        maximum_billing_cycles: 3,
        maximum_active_subscriptions_per_customer: 1,
        aggregate_recurring_budgets: vec![AggregateRecurringBudget {
            budget_id: format!("delta-{session_id}"),
            customer_id: evidence.customer_id.clone(),
            currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
            interval: SubscriptionInterval::Week,
            limit_minor: 1_000,
        }],
        aggregate_immediate_budgets: vec![AggregateImmediateBudget {
            budget_id: format!("proration-{session_id}"),
            currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
            limit_minor: evidence.proration_debit_minor,
            starts_at: now.saturating_sub(60),
            ends_at: now + 3_600,
        }],
        minimum_preview_validity_seconds: 30,
        maximum_evidence_age_seconds: 120,
        maximum_action_lifetime_seconds: 300,
        allowed_api_versions: vec![state.environment.api_version().into()],
    })
    .map_err(|_| ApiError::internal())?
    .with_modify_limits(BTreeMap::from([(
        Currency::parse("usd").map_err(|_| ApiError::internal())?,
        evidence.proration_debit_minor,
    )]))
    .map_err(|_| ApiError::internal())?;
    let configuration = StripeSubscriptionConfigurationV1::new(
        SUBSCRIPTION_MODIFY_PROFILE,
        SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA,
        &policy,
        state.environment.account_id().clone(),
        SubscriptionConnectAccount::Platform,
        evidence.test_clock_id.clone(),
        state.environment.api_version().into(),
        EXECUTOR_AUDIENCE.into(),
    )
    .map_err(|_| ApiError::internal())?;
    let action = StripeExactSubscriptionModifyV1::new(StripeExactSubscriptionModifyInput {
        stripe_account_id: state.environment.account_id().clone(),
        connect_account: SubscriptionConnectAccount::Platform,
        subscription_id: evidence.subscription_id.clone(),
        customer_id: evidence.customer_id.clone(),
        before_subscription_digest: evidence.before_subscription_digest.clone(),
        before_items: evidence.current_items.clone(),
        after_items: evidence
            .current_items
            .iter()
            .map(|item| {
                SubscriptionModifyItem::new(
                    item.subscription_item_id().clone(),
                    item.price_id().clone(),
                    item.product_id().clone(),
                    2,
                )
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| ApiError::internal())?,
        currency: Currency::parse("usd").map_err(|_| ApiError::internal())?,
        billing_cycle_anchor: evidence.billing_cycle_anchor,
        cancel_at: evidence.cancel_at,
        proration_date: evidence.proration_date,
        mandate_receipt_digest: mandate_digest,
        invoice_preview_digest: evidence.preview_digest.clone(),
        proration_debit_minor: evidence.proration_debit_minor,
        proration_credit_minor: evidence.proration_credit_minor,
        before_recurring_minor: evidence.before_recurring_minor,
        after_recurring_minor: evidence.after_recurring_minor,
        remaining_cycle_count: evidence.remaining_cycle_count,
        incremental_term_liability_minor: evidence
            .after_recurring_minor
            .checked_mul(u64::from(evidence.remaining_cycle_count))
            .and_then(|after| {
                evidence
                    .before_recurring_minor
                    .checked_mul(u64::from(evidence.remaining_cycle_count))
                    .map(|before| after.saturating_sub(before))
            })
            .ok_or_else(ApiError::internal)?,
        test_clock_id: evidence.test_clock_id.clone(),
        stripe_api_version: state.environment.api_version().into(),
        required_policy_digest: policy.digest().map_err(|_| ApiError::internal())?,
        required_configuration_digest: configuration.digest().map_err(|_| ApiError::internal())?,
        executor_audience: EXECUTOR_AUDIENCE.into(),
        expires_at: now + 300,
        nonce: auths_stripe::canonical::sha256(format!("nonce-{session_id}").as_bytes()),
    })
    .map_err(|_| ApiError::internal())?;
    let canonical_action = StripeSubscriptionModifyProfile
        .canonicalize(&action.canonical_bytes().map_err(|_| ApiError::internal())?)
        .map_err(|_| ApiError::internal())?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::internal())?;
    let fixture_auths = authorization_fixture(
        &canonical_action,
        EXECUTOR_AUDIENCE,
        &format!(
            "stripe-test://{}/subscriptions/{}",
            action.stripe_account_id(),
            action.subscription_id()
        ),
        now,
        challenge,
    );
    let verifier = Arc::new(SdkSubscriptionModifyProofVerifier::new(
        fixture_auths.verifier,
    ));
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "profile": SUBSCRIPTION_MODIFY_PROFILE,
        "policy": policy,
        "policy_digest": policy.digest().map_err(|_| ApiError::internal())?,
        "exact_action": action,
        "evidence": evidence,
        "liability": {
            "before_recurring_minor": evidence.before_recurring_minor,
            "after_recurring_minor": evidence.after_recurring_minor,
            "remaining_cycle_count": evidence.remaining_cycle_count,
            "incremental_term_liability_minor": action.incremental_term_liability_minor(),
            "proration_debit_minor": evidence.proration_debit_minor,
            "proration_credit_minor": evidence.proration_credit_minor
        },
        "experiments": [
            {"id":"success","label":"Exact upgrade","detail":"Apply one quantity upgrade with pending-if-incomplete and always-invoice."},
            {"id":"denial","label":"Configuration mismatch","detail":"Proof succeeds, but execution configuration differs; zero credential/provider calls."},
            {"id":"ambiguous","label":"Lost response","detail":"Update once, discard the response projection, then reconcile without another update."},
            {"id":"replay","label":"Replay","detail":"Return durable state without another Stripe update."}
        ],
        "agent_has_stripe_key": false,
        "client_secret_exposed": false
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
            workflow_base,
            last_workflow: None,
            action,
            policy,
            evidence,
            configuration,
            canonical_action,
            proof: fixture_auths.proof,
            request: fixture_auths.request,
            verifier,
            last_result: None,
        },
    );
    Ok(Json(response))
}

async fn preview(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = state.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "preview_digest": session.evidence.preview_digest,
        "preview_lines": session.evidence.preview_lines,
        "proration_debit_minor": session.evidence.proration_debit_minor,
        "proration_credit_minor": session.evidence.proration_credit_minor,
        "proration_date": session.evidence.proration_date,
        "mandate_receipt_digest": session.evidence.mandate_receipt_digest
    })))
}

#[allow(
    clippy::too_many_lines,
    reason = "ordered trust-boundary material stays explicit"
)]
async fn execute(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let (
        workflow,
        action,
        policy,
        evidence,
        required_configuration,
        executed_configuration,
        canonical_action,
        proof,
        auths_request,
        verifier,
    ) = {
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
        let workflow = match request.experiment.as_str() {
            "success" | "replay" => format!("{}-success", session.workflow_base),
            "denial" => format!("{}-denial", session.workflow_base),
            "ambiguous" => format!("{}-ambiguous", session.workflow_base),
            _ => return Err(ApiError::bad_request()),
        };
        let executed_configuration = if request.experiment == "denial" {
            StripeSubscriptionConfigurationV1::new(
                SUBSCRIPTION_MODIFY_PROFILE,
                SUBSCRIPTION_MODIFY_RECEIPT_SCHEMA,
                &session.policy,
                state.environment.account_id().clone(),
                SubscriptionConnectAccount::Platform,
                session.evidence.test_clock_id.clone(),
                state.environment.api_version().into(),
                "https://changed-subscription-executor.auths.dev".into(),
            )
            .map_err(|_| ApiError::internal())?
        } else {
            session.configuration.clone()
        };
        (
            workflow,
            session.action.clone(),
            session.policy.clone(),
            session.evidence.clone(),
            session.configuration.clone(),
            executed_configuration,
            session.canonical_action.clone(),
            session.proof.clone(),
            session.request.clone(),
            Arc::clone(&session.verifier),
        )
    };
    if request.experiment == "ambiguous" {
        state
            .environment
            .arm_ambiguous_once(&workflow)
            .map_err(|_| ApiError::internal())?;
    }
    let before = state.environment.diagnostics();
    let service = SubscriptionModifyService::new(
        SubscriptionModifyServiceDependencies {
            verifier,
            store: Arc::clone(&state.store),
            credentials: Arc::clone(&state.environment) as _,
            gateway: Arc::clone(&state.environment) as _,
            receipts: Arc::clone(&state.receipts) as _,
            clock: Arc::new(SystemClock),
        },
        executed_configuration,
    );
    let outcome = tokio::task::spawn_blocking(move || {
        service.execute(ExecuteSubscriptionModifyRequest {
            workflow_id: workflow.clone(),
            proof,
            canonical_action,
            request_context: auths_request,
            action,
            policy,
            evidence,
            required_configuration,
        })
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| ApiError::internal())?;
    let after = state.environment.diagnostics();
    let workflow = workflow_for_outcome(&outcome);
    let mut result = outcome_json(
        outcome,
        after
            .credential_requests
            .saturating_sub(before.credential_requests),
        after.provider_calls.saturating_sub(before.provider_calls),
    );
    if let Some((id, receipt)) = state
        .receipts
        .latest_for(&workflow)
        .map_err(|_| ApiError::internal())?
    {
        result["receipt_id"] = json!(id);
        result["receipt_url"] = json!(format!("/receipts/{id}"));
        result["receipt"] = serde_json::to_value(receipt).map_err(|_| ApiError::internal())?;
    }
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_workflow = Some(workflow);
        session.last_result = Some(result.clone());
    }
    Ok(Json(result))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let (workflow, configuration, verifier) = {
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
        (
            session
                .last_workflow
                .clone()
                .ok_or_else(ApiError::missing)?,
            session.configuration.clone(),
            Arc::clone(&session.verifier),
        )
    };
    let before = state.environment.diagnostics();
    let service = SubscriptionModifyService::new(
        SubscriptionModifyServiceDependencies {
            verifier,
            store: Arc::clone(&state.store),
            credentials: Arc::clone(&state.environment) as _,
            gateway: Arc::clone(&state.environment) as _,
            receipts: Arc::clone(&state.receipts) as _,
            clock: Arc::new(SystemClock),
        },
        configuration,
    );
    let query = workflow.clone();
    let outcome = tokio::task::spawn_blocking(move || service.reconcile(&query))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::internal())?;
    let after = state.environment.diagnostics();
    let mut result = outcome_json(
        outcome,
        after
            .credential_requests
            .saturating_sub(before.credential_requests),
        after.provider_calls.saturating_sub(before.provider_calls),
    );
    if let Some((id, receipt)) = state
        .receipts
        .latest_for(&workflow)
        .map_err(|_| ApiError::internal())?
    {
        result["receipt_id"] = json!(id);
        result["receipt_url"] = json!(format!("/receipts/{id}"));
        result["receipt"] = serde_json::to_value(receipt).map_err(|_| ApiError::internal())?;
    }
    Ok(Json(result))
}

async fn advance_clock(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let (clock, target) = {
        let sessions = state.sessions.lock().await;
        let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
        (
            session.evidence.test_clock_id.clone(),
            session
                .evidence
                .current_period_end
                .checked_add(60)
                .ok_or_else(ApiError::internal)?,
        )
    };
    let environment = Arc::clone(&state.environment);
    let value = tokio::task::spawn_blocking(move || environment.advance_clock(&clock, target))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::stripe())?;
    Ok(Json(
        json!({"schema":API_SCHEMA,"test_clock":value,"target":target}),
    ))
}

async fn timeline(
    State(state): State<AppState>,
    AxumPath(subscription_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let subscription = auths_stripe::SubscriptionId::parse(subscription_id)
        .map_err(|_| ApiError::bad_request())?;
    let workflows: Vec<String> = state
        .sessions
        .lock()
        .await
        .values()
        .filter_map(|session| session.last_workflow.clone())
        .collect();
    let workflow = workflows
        .iter()
        .find_map(|workflow| {
            state
                .store
                .get(workflow)
                .ok()
                .flatten()
                .and_then(|value| value.provider().cloned())
                .filter(|provider| provider.subscription_id == subscription)
                .map(|_| workflow.clone())
        })
        .ok_or_else(ApiError::missing)?;
    let now = unix_time()?;
    let environment = Arc::clone(&state.environment);
    let provider = tokio::task::spawn_blocking(move || environment.timeline(&subscription, now))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(|_| ApiError::stripe())?;
    let modification = state
        .store
        .get(&workflow)
        .map_err(|_| ApiError::internal())?
        .ok_or_else(ApiError::missing)?;
    Ok(Json(
        json!({"schema":API_SCHEMA,"subscription":provider,"modification":modification}),
    ))
}

async fn session_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = state.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(ApiError::missing)?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "last_result": session.last_result
    })))
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

fn workflow_for_outcome(outcome: &SubscriptionModifyWorkflowOutcome) -> String {
    match outcome {
        SubscriptionModifyWorkflowOutcome::PendingPayment(value)
        | SubscriptionModifyWorkflowOutcome::Applied(value)
        | SubscriptionModifyWorkflowOutcome::OutcomeUnknown(value)
        | SubscriptionModifyWorkflowOutcome::Released(value)
        | SubscriptionModifyWorkflowOutcome::Expired(value)
        | SubscriptionModifyWorkflowOutcome::Replay(value) => value.workflow_id().into(),
        SubscriptionModifyWorkflowOutcome::Denied { .. }
        | SubscriptionModifyWorkflowOutcome::Indeterminate { .. } => String::new(),
    }
}

fn outcome_json(
    outcome: SubscriptionModifyWorkflowOutcome,
    credentials: u64,
    provider_calls: u64,
) -> Value {
    let boundary = json!({"credential_requests":credentials,"provider_calls":provider_calls});
    match outcome {
        SubscriptionModifyWorkflowOutcome::Denied {
            code,
            decision_receipt_digest,
        } => {
            json!({"schema":API_SCHEMA,"outcome":"denied","code":code,"decision_receipt_digest":decision_receipt_digest,"boundary":boundary})
        }
        SubscriptionModifyWorkflowOutcome::Indeterminate {
            code,
            decision_receipt_digest,
        } => {
            json!({"schema":API_SCHEMA,"outcome":"indeterminate","code":code,"decision_receipt_digest":decision_receipt_digest,"boundary":boundary})
        }
        SubscriptionModifyWorkflowOutcome::Applied(record) => {
            json!({"schema":API_SCHEMA,"outcome":"applied","modification":record,"boundary":boundary})
        }
        SubscriptionModifyWorkflowOutcome::PendingPayment(record) => {
            json!({"schema":API_SCHEMA,"outcome":"pending_payment","modification":record,"boundary":boundary,"code":"subscription-update-payment-incomplete"})
        }
        SubscriptionModifyWorkflowOutcome::OutcomeUnknown(record) => {
            json!({"schema":API_SCHEMA,"outcome":"outcome_unknown","modification":record,"boundary":boundary,"code":"subscription-update-outcome-unknown"})
        }
        SubscriptionModifyWorkflowOutcome::Released(record) => {
            json!({"schema":API_SCHEMA,"outcome":"released","modification":record,"boundary":boundary})
        }
        SubscriptionModifyWorkflowOutcome::Expired(record) => {
            json!({"schema":API_SCHEMA,"outcome":"expired","modification":record,"boundary":boundary})
        }
        SubscriptionModifyWorkflowOutcome::Replay(record) => {
            json!({"schema":API_SCHEMA,"outcome":"replay","modification":record,"boundary":boundary})
        }
    }
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
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(bytes))
}

#[derive(Clone, Copy, Debug)]
pub enum StartupError {
    Missing(&'static str),
    Invalid,
    Stripe,
    State,
}
impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(value) => write!(formatter, "missing {value}"),
            Self::Invalid => formatter.write_str("invalid deployment configuration"),
            Self::Stripe => formatter.write_str("Stripe test environment unavailable"),
            Self::State => formatter.write_str("durable state unavailable"),
        }
    }
}

struct ApiError {
    status: StatusCode,
    code: &'static str,
}
impl ApiError {
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
        }
    }
    fn stripe() -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "stripe-unavailable",
        }
    }
    fn missing() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not-found",
        }
    }
    fn capacity() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "session-capacity",
        }
    }
    fn bad_request() -> Self {
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
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicU64, Ordering},
    };

    use auths_stripe::{
        CredentialProvider, PortError, SubscriptionId, SubscriptionModificationRecord,
        SubscriptionModifyCredential, SubscriptionModifyCredentialScope, SubscriptionModifyEffect,
        SubscriptionModifyGateway, SubscriptionModifyProviderProjection,
        SubscriptionModifyReconciliationOutcome, TestClockId, VerifiedSubscriptionModifyCommand,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::stripe::{EnvironmentDiagnostics, SubscriptionFixture};

    struct FakeEnvironment {
        account: auths_stripe::StripeAccountId,
        credentials: AtomicU64,
        calls: AtomicU64,
        ambiguous: StdMutex<bool>,
        applied: StdMutex<Option<SubscriptionModifyProviderProjection>>,
    }

    impl FakeEnvironment {
        fn new() -> Self {
            Self {
                account: auths_stripe::StripeAccountId::parse("acct_subscriptionfixture01")
                    .unwrap(),
                credentials: AtomicU64::new(0),
                calls: AtomicU64::new(0),
                ambiguous: StdMutex::new(false),
                applied: StdMutex::new(None),
            }
        }

        fn projection(
            items: Vec<SubscriptionModifyItem>,
            customer_id: auths_stripe::CustomerId,
            subscription_id: SubscriptionId,
            billing_cycle_anchor: u64,
            cancel_at: u64,
            now: u64,
        ) -> SubscriptionModifyProviderProjection {
            SubscriptionModifyProviderProjection {
                item_set_digest: auths_stripe::canonical::canonical_digest(&items).unwrap(),
                subscription_id,
                customer_id,
                items,
                pending_update_digest: None,
                latest_invoice_id: Some(
                    auths_stripe::InvoiceId::parse("in_subscriptionmodify001").unwrap(),
                ),
                payment_intent_id: Some(
                    auths_stripe::PaymentIntentId::parse("pi_subscriptionmodify001").unwrap(),
                ),
                invoice_status: Some("paid".into()),
                payment_status: Some("succeeded".into()),
                applied: true,
                payment_incomplete: false,
                amount_paid_minor: 250,
                billing_cycle_anchor,
                cancel_at,
                livemode: false,
                stripe_request_id: Some("req_subscriptionmodify".into()),
                response_digest: auths_stripe::canonical::sha256(b"fake-modify"),
                observed_at: now,
                source: "fake-subscription-modify".into(),
            }
        }
    }

    impl CredentialProvider<SubscriptionModifyCredentialScope> for FakeEnvironment {
        fn credential(
            &self,
            account: &auths_stripe::StripeAccountId,
        ) -> Result<SubscriptionModifyCredential, PortError> {
            if account != &self.account {
                return Err(PortError::InvalidConfiguration);
            }
            self.credentials.fetch_add(1, Ordering::Relaxed);
            SubscriptionModifyCredential::new(b"rk_test_repository_test_value".to_vec())
        }
    }

    impl SubscriptionModifyGateway for FakeEnvironment {
        fn reread_critical_evidence(
            &self,
            command: &VerifiedSubscriptionModifyCommand,
            _credential: &SubscriptionModifyCredential,
            _now: u64,
        ) -> Result<auths_stripe::SubscriptionModifyEvidenceV1, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(command.evidence().clone())
        }

        fn modify(
            &self,
            command: &VerifiedSubscriptionModifyCommand,
            _credential: &SubscriptionModifyCredential,
            now: u64,
        ) -> Result<SubscriptionModifyEffect, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let action = command.action();
            let provider = Self::projection(
                action.after_items().to_vec(),
                action.customer_id().clone(),
                action.subscription_id().clone(),
                action.billing_cycle_anchor(),
                action.cancel_at(),
                now,
            );
            *self.applied.lock().map_err(|_| PortError::Persistence)? = Some(provider.clone());
            let mut ambiguous = self.ambiguous.lock().map_err(|_| PortError::Persistence)?;
            if *ambiguous {
                *ambiguous = false;
                Ok(SubscriptionModifyEffect::OutcomeUnknown(None))
            } else {
                Ok(SubscriptionModifyEffect::Applied(provider))
            }
        }

        fn reconcile(
            &self,
            modification: &SubscriptionModificationRecord,
            _credential: &SubscriptionModifyCredential,
            now: u64,
        ) -> Result<SubscriptionModifyReconciliationOutcome, PortError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            let mut provider = self
                .applied
                .lock()
                .map_err(|_| PortError::Persistence)?
                .clone()
                .ok_or(PortError::EvidenceUnavailable)?;
            if provider.subscription_id != *modification.subscription_id() {
                return Err(PortError::Malformed);
            }
            provider.observed_at = now;
            provider.source = "fake-subscription-reconcile".into();
            Ok(SubscriptionModifyReconciliationOutcome::Applied(provider))
        }
    }

    impl DemoSubscriptionModifyEnvironment for FakeEnvironment {
        fn seed_fixture(
            &self,
            _workflow_id: &str,
            now: u64,
        ) -> Result<SubscriptionFixture, PortError> {
            let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../product/integrations/auths-stripe/fixtures/subscription-modify/v1");
            let mut evidence: auths_stripe::SubscriptionModifyEvidenceV1 = serde_json::from_slice(
                &std::fs::read(root.join("evidence.json")).map_err(|_| PortError::Persistence)?,
            )
            .map_err(|_| PortError::Malformed)?;
            evidence.observed_at = now;
            evidence.preview_valid_until = now + 120;
            Ok(SubscriptionFixture { evidence })
        }

        fn arm_ambiguous_once(&self, _workflow_id: &str) -> Result<(), PortError> {
            *self.ambiguous.lock().map_err(|_| PortError::Persistence)? = true;
            Ok(())
        }

        fn advance_clock(
            &self,
            test_clock: &TestClockId,
            frozen_time: u64,
        ) -> Result<Value, PortError> {
            Ok(json!({"id":test_clock,"frozen_time":frozen_time,"status":"advancing"}))
        }

        fn timeline(
            &self,
            subscription: &SubscriptionId,
            now: u64,
        ) -> Result<SubscriptionModifyProviderProjection, PortError> {
            let mut value = self
                .applied
                .lock()
                .map_err(|_| PortError::Persistence)?
                .clone()
                .ok_or(PortError::EvidenceUnavailable)?;
            if &value.subscription_id != subscription {
                return Err(PortError::Malformed);
            }
            value.observed_at = now;
            value.source = "fake-subscription-timeline".into();
            Ok(value)
        }

        fn account_id(&self) -> &auths_stripe::StripeAccountId {
            &self.account
        }
        #[allow(
            clippy::unnecessary_literal_bound,
            reason = "the fake implements the live environment trait's borrowed version accessor"
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

    async fn start(router: &Router) -> String {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/sessions")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        value["session_id"].as_str().unwrap().into()
    }

    async fn run(router: &Router, session: &str, experiment: &str) -> Value {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/sessions/{session}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(json!({"experiment":experiment}).to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap()
    }

    #[tokio::test]
    async fn denial_precedes_credentials_and_provider_io() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().into()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let session = start(&router).await;
        let value = run(&router, &session, "denial").await;
        assert_eq!(value["outcome"], "denied", "{value}");
        assert_eq!(value["boundary"]["credential_requests"], 0);
        assert_eq!(value["boundary"]["provider_calls"], 0);
    }

    #[tokio::test]
    async fn exact_update_and_replay_execute_once() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().into()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let session = start(&router).await;
        let applied = run(&router, &session, "success").await;
        assert_eq!(applied["outcome"], "applied", "{applied}");
        assert_eq!(applied["boundary"]["credential_requests"], 1);
        assert_eq!(applied["boundary"]["provider_calls"], 2);
        assert_eq!(
            applied["modification"]["incremental_term_liability_minor"],
            1_000
        );
        let replay = run(&router, &session, "replay").await;
        assert_eq!(replay["outcome"], "replay");
        assert_eq!(replay["boundary"]["credential_requests"], 0);
        assert_eq!(replay["boundary"]["provider_calls"], 0);
    }

    #[tokio::test]
    async fn ambiguous_update_reconciles_without_second_write() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().into()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let session = start(&router).await;
        let unknown = run(&router, &session, "ambiguous").await;
        assert_eq!(unknown["outcome"], "outcome_unknown", "{unknown}");
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/api/v1/sessions/{session}/reconcile"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        let value: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(value["outcome"], "applied", "{value}");
        assert_eq!(value["boundary"]["provider_calls"], 1);
    }

    #[tokio::test]
    async fn timeline_rejects_arbitrary_subscription_ids() {
        let directory = tempfile::tempdir().unwrap();
        let router = app_with_environment(
            AppConfig::for_test(directory.path().into()),
            Arc::new(FakeEnvironment::new()),
        )
        .unwrap();
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/api/v1/subscriptions/sub_notrepositoryowned/timeline")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
