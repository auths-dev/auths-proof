use std::{
    collections::{BTreeMap, HashMap},
    env, fmt,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_stripe::{
    AggregateBudgetSnapshot, AggregateRefundBudget, BoundedDecisionClass, BoundedEvaluationContext,
    BoundedRefundService, BoundedServiceDependencies, BoundedWorkflowOutcome,
    CONFIGURED_POLICY_PROVENANCE, ClaimStore, ConnectScope, Currency, ExactRefundActionInput,
    ExactRefundActionV1, ExecuteBoundedRefundRequest, Money, PersistentClaimStore,
    PersistentRefundReservationStore, ReceiptSink, ReconciledRefundOutcome, RefundBudgetWindow,
    RefundDenominator, RefundReservationStore, RelativeRefundLimit, ReservationReceipt,
    SdkProofVerifier, StripeBoundedEvaluatorConfigurationV1, StripeBoundedRefundPolicyInput,
    StripeBoundedRefundPolicyV1, StripeReceipt, StripeVerifierConfiguration,
    StripeVerifierConfigurationInput, SystemClock, evaluate_bounded_refund,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{
    fixture::authorization_fixture,
    stripe::{DemoStripeEnvironment, LiveStripeEnvironment},
};

const API_SCHEMA: &str = "auths-stripe-demo/v1";
const SESSION_TTL_SECONDS: u64 = 5 * 60;
const MAX_SESSIONS: usize = 512;
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const REFUND_AMOUNT_MINOR: u64 = 1_000;
const ABSOLUTE_REFUND_LIMIT_MINOR: u64 = 1_500;
const RELATIVE_REFUND_LIMIT_BPS: u16 = 5_000;
const AGGREGATE_REFUND_LIMIT_MINOR: u64 = 2_500;

/// Native demo startup configuration.
#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    region: Arc<str>,
    release: Arc<str>,
    state_directory: Arc<Path>,
}

impl AppConfig {
    /// Loads deployment configuration from the environment.
    ///
    /// # Errors
    ///
    /// Returns a closed startup failure for missing or malformed input.
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
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("AUTHS_STRIPE_RELEASE").unwrap_or_else(|_| "development".into());
        for value in [&region, &release] {
            if value.is_empty()
                || value.len() > 128
                || value
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')))
            {
                return Err(StartupError::Invalid);
            }
        }
        let state_directory = PathBuf::from(
            env::var("AUTHS_STRIPE_STATE_DIR").unwrap_or_else(|_| "/data/auths-stripe".into()),
        );
        if !state_directory.is_absolute() {
            return Err(StartupError::Invalid);
        }
        Ok(Self {
            allowed_origin,
            region: region.into(),
            release: release.into(),
            state_directory: state_directory.into(),
        })
    }

    #[cfg(test)]
    fn for_test(state_directory: PathBuf) -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: "test".into(),
            release: "test".into(),
            state_directory: state_directory.into(),
        }
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    environment: Arc<dyn DemoStripeEnvironment>,
    claim_store: Arc<dyn ClaimStore>,
    reservation_store: Arc<dyn RefundReservationStore>,
    receipt_sink: Arc<dyn ReceiptSink>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    action: ExactRefundActionV1,
    evidence: auths_stripe::RefundEvidenceV1,
    policy: StripeBoundedRefundPolicyV1,
    required_configuration: StripeVerifierConfiguration,
    required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
    principals: Principals,
    variants: Vec<Value>,
    last_result: Option<Value>,
}

struct Principals {
    human: String,
    workflow: String,
    agent: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the live native Stripe API.
///
/// # Errors
///
/// Fails closed unless real Stripe test-mode and durable-state configuration
/// are present.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let environment =
        Arc::new(LiveStripeEnvironment::from_environment().map_err(|_| StartupError::Stripe)?);
    let claim_store = Arc::new(
        PersistentClaimStore::open(config.state_directory.join("claims.json"))
            .map_err(|_| StartupError::State)?,
    );
    let receipt_sink = Arc::new(
        JsonlReceiptSink::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let reservation_store = Arc::new(
        PersistentRefundReservationStore::open(
            config.state_directory.join("bounded-reservations.json"),
        )
        .map_err(|_| StartupError::State)?,
    );
    Ok(app_with_stores(
        config,
        environment,
        claim_store,
        reservation_store,
        receipt_sink,
    ))
}

/// Builds the API from explicit dependencies for deterministic tests.
pub fn app_with_environment(
    config: AppConfig,
    environment: Arc<dyn DemoStripeEnvironment>,
    claim_store: Arc<dyn ClaimStore>,
    receipt_sink: Arc<dyn ReceiptSink>,
) -> Router {
    app_with_stores(
        config,
        environment,
        claim_store,
        Arc::new(auths_stripe::InMemoryRefundReservationStore::default()),
        receipt_sink,
    )
}

/// Builds the API with explicit exact-claim and aggregate-reservation stores.
pub fn app_with_stores(
    config: AppConfig,
    environment: Arc<dyn DemoStripeEnvironment>,
    claim_store: Arc<dyn ClaimStore>,
    reservation_store: Arc<dyn RefundReservationStore>,
    receipt_sink: Arc<dyn ReceiptSink>,
) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    let state = AppState {
        config,
        environment,
        claim_store,
        reservation_store,
        receipt_sink,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}", get(session_status))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/sessions/{session_id}/reconcile", post(reconcile))
        .route("/api/v1/receipts/{session_id}", get(session_receipts))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": &*state.config.region,
        "release": &*state.config.release,
    }))
}

async fn readiness(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ready",
        "schema": API_SCHEMA,
        "stripe_mode": state.environment.execution_mode(),
        "account_commitment": auths_stripe::service::identifier_commitment(
            state.environment.account_id().as_str()
        ),
        "api_version": state.environment.api_version(),
    }))
}

async fn scenario(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": "auths.stripe.exact-refund/1",
        "policy_type": "auths.stripe.bounded-refund-policy/1",
        "evaluator": "auths.stripe.bounded-refund-evaluator/1",
        "policy_provenance": CONFIGURED_POLICY_PROVENANCE,
        "region": &*state.config.region,
        "release": &*state.config.release,
        "execution_mode": state.environment.execution_mode(),
        "currency": "usd",
        "refund_amount_minor": REFUND_AMOUNT_MINOR,
        "agent_has_stripe_key": false,
        "session_setup": "POST /api/v1/sessions creates a fresh Stripe test payment",
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "the endpoint assembles one auditable, side-by-side bounded-refund projection"
)]
async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ApiError::internal())?;
    let session_id = hex::encode(random);
    let workflow_id = format!("stripe-demo-{session_id}");
    let environment = Arc::clone(&state.environment);
    let workflow_for_seed = workflow_id.clone();
    let evidence =
        tokio::task::spawn_blocking(move || environment.seed_payment(&workflow_for_seed, now))
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(|_| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "stripe-fixture-unavailable",
                    "Stripe test mode could not create the session payment",
                )
            })?;
    let required_configuration =
        configuration(&state.environment, evidence.refundable_amount_minor())
            .map_err(|_| ApiError::internal())?;
    let policy = bounded_policy(&evidence, now).map_err(|_| ApiError::internal())?;
    let required_bounded_configuration = StripeBoundedEvaluatorConfigurationV1::for_policy(
        &policy,
        "auths-stripe-demo-v1",
        required_configuration.executor_audience(),
    )
    .map_err(|_| ApiError::internal())?;
    let action = exact_action(
        &workflow_id,
        &required_configuration,
        &policy,
        &evidence,
        REFUND_AMOUNT_MINOR,
        &session_id,
    )
    .map_err(|_| ApiError::internal())?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| ApiError::internal())?;
    let fixture = authorization_fixture(&action, now, challenge);
    let variants = variant_projections(
        &action,
        &evidence,
        &policy,
        &required_configuration,
        &required_bounded_configuration,
        &AggregateBudgetSnapshot::default(),
        now,
        &session_id,
    )
    .map_err(|_| ApiError::internal())?;
    let principals = Principals {
        human: fixture.human_principal,
        workflow: fixture.workflow_principal,
        agent: fixture.agent_principal,
    };
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "execution_mode": state.environment.execution_mode(),
        "profile": "auths.stripe.exact-refund/1",
        "delegation": {
            "label": "immutable configured policy",
            "provenance": CONFIGURED_POLICY_PROVENANCE,
            "policy": policy,
            "policy_digest": policy.digest().map_err(|_| ApiError::internal())?,
            "evaluator_semantic_id": policy.evaluator_semantic_id(),
            "evaluator_semantic_version": policy.evaluator_semantic_version(),
            "absolute_limit_minor": policy.absolute_limit_minor(action.amount().currency()),
            "basis_points": policy.relative_limit().basis_points(),
            "denominator": policy.relative_limit().denominator(),
            "rounding": policy.relative_limit().rounding(),
        },
        "payment": payment_projection(&evidence),
        "refund": {
            "amount_minor": action.amount().amount_minor(),
            "currency": action.amount().currency(),
            "reason": action.reason(),
        },
        "required_configuration": required_configuration.digest().map_err(|_| ApiError::internal())?,
        "executed_configuration": required_configuration.digest().map_err(|_| ApiError::internal())?,
        "required_bounded_configuration": required_bounded_configuration,
        "executed_bounded_configuration": required_bounded_configuration,
        "aggregate_budget": aggregate_projection(&AggregateBudgetSnapshot::default(), &policy),
        "principals": {
            "human": principals.human,
            "workflow": principals.workflow,
            "agent": principals.agent,
        },
        "variants": variants,
    });
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the bounded session pool is full",
        ));
    }
    sessions.insert(
        session_id,
        Session {
            expires_at: now + SESSION_TTL_SECONDS,
            action,
            evidence,
            policy,
            required_configuration,
            required_bounded_configuration,
            proof_verifier: Arc::new(SdkProofVerifier::new(fixture.verifier)),
            proof: fixture.proof,
            request: fixture.request,
            principals,
            variants,
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
        let mut sessions = state.sessions.lock().await;
        let session = sessions.get_mut(&session_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::GONE,
                "session-unavailable",
                "the Stripe demo session is missing or expired",
            )
        })?;
        if session.expires_at <= now {
            sessions.remove(&session_id);
            return Err(ApiError::new(
                StatusCode::GONE,
                "session-expired",
                "the Stripe demo session expired",
            ));
        }
        execution_materials(session, &request.variant, &session_id, now)?
    };
    let environment = Arc::clone(&state.environment);
    let claim_store = Arc::clone(&state.claim_store);
    let reservation_store = Arc::clone(&state.reservation_store);
    let receipt_sink = Arc::clone(&state.receipt_sink);
    let result = tokio::task::spawn_blocking(move || {
        let service = BoundedRefundService::new(BoundedServiceDependencies {
            proof_verifier: materials.proof_verifier,
            credential_provider: Arc::clone(&environment),
            stripe_gateway: environment,
            claim_store,
            reservation_store,
            receipt_sink,
            clock: SystemClock,
            executed_exact_configuration: materials.executed_configuration,
            executed_bounded_configuration: materials.executed_bounded_configuration,
        });
        service.execute(ExecuteBoundedRefundRequest {
            action: materials.action,
            evidence: materials.evidence,
            policy: materials.policy,
            required_exact_configuration: materials.required_configuration,
            required_bounded_configuration: materials.required_bounded_configuration,
            proof: materials.proof,
            auths_request: materials.request,
        })
    })
    .await
    .map_err(|_| ApiError::internal())?;
    let response = outcome_projection(result)?;
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_result = Some(response.clone());
    }
    Ok(Json(response))
}

async fn session_status(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = state.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "session-not-found",
            "the Stripe demo session was not found",
        )
    })?;
    let aggregate = state
        .reservation_store
        .snapshot(
            &session.policy,
            session.evidence.stripe_account_id(),
            unix_time().map_err(|_| ApiError::internal())?,
        )
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "payment": payment_projection(&session.evidence),
        "delegation": {
            "label": "immutable configured policy",
            "provenance": CONFIGURED_POLICY_PROVENANCE,
            "policy": session.policy,
            "policy_digest": session.policy.digest().map_err(|_| ApiError::internal())?,
        },
        "aggregate_budget": aggregate_projection(&aggregate, &session.policy),
        "variants": session.variants,
        "principals": {
            "human": session.principals.human,
            "workflow": session.principals.workflow,
            "agent": session.principals.agent,
        },
        "last_result": session.last_result,
    })))
}

async fn reconcile(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let action = {
        let sessions = state.sessions.lock().await;
        sessions
            .get(&session_id)
            .ok_or_else(|| {
                ApiError::new(
                    StatusCode::NOT_FOUND,
                    "session-not-found",
                    "the Stripe demo session was not found",
                )
            })?
            .action
            .clone()
    };
    let environment = Arc::clone(&state.environment);
    let action_for_observation = action.clone();
    let observation = tokio::task::spawn_blocking(move || {
        environment.reconcile_refund(&action_for_observation, now)
    })
    .await
    .map_err(|_| ApiError::internal())?
    .map_err(|_| {
        ApiError::new(
            StatusCode::BAD_GATEWAY,
            "bounded-reconciliation-unavailable",
            "fresh Stripe reconciliation evidence is unavailable",
        )
    })?;
    let outcome = if let Some(result) = observation {
        let digest =
            auths_stripe::canonical::canonical_digest(&result).map_err(|_| ApiError::internal())?;
        ReconciledRefundOutcome::Committed {
            refund_id: result.refund_id,
            result_digest: digest,
        }
    } else {
        ReconciledRefundOutcome::Released
    };
    let record = state
        .reservation_store
        .reconcile(
            action.workflow_id(),
            &action.digest().map_err(|_| ApiError::internal())?,
            outcome,
            now,
        )
        .map_err(|_| {
            ApiError::new(
                StatusCode::CONFLICT,
                "bounded-reconciliation-required",
                "only an outcome-unknown exact refund can be reconciled",
            )
        })?;
    state
        .receipt_sink
        .append(&StripeReceipt::Reservation(Box::new(ReservationReceipt {
            schema: "auths.stripe.bounded-reservation-receipt/1".into(),
            decision_receipt_digest: record.decision_receipt_digest().clone(),
            reservation: record.clone(),
            credential_requested: false,
            stripe_called: false,
            recorded_at: now,
        })))
        .map_err(|_| ApiError::internal())?;
    let response = json!({
        "schema": API_SCHEMA,
        "decision": {
            "class": "authorized",
            "code": "bounded-reconciled",
            "detail": "fresh Stripe evidence reconciled the held aggregate capacity",
            "stage": "reconciliation",
        },
        "entered_executor": true,
        "credential_requested": false,
        "stripe_called": false,
        "reservation": {
            "id": record.reservation_id(),
            "state": record.state(),
            "refund_id": record.refund_id(),
        },
        "stages": [
            {"name": "authorized", "status": "previously proven"},
            {"name": "reserved", "status": "reconciled"},
            {"name": "credential", "status": "not requested"},
            {"name": "stripe", "status": "observed only"},
            {"name": "observed", "status": record.state()}
        ],
        "receipt_count": 1,
    });
    if let Some(session) = state.sessions.lock().await.get_mut(&session_id) {
        session.last_result = Some(response.clone());
    }
    Ok(Json(response))
}

async fn session_receipts(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    let sessions = state.sessions.lock().await;
    let session = sessions.get(&session_id).ok_or_else(|| {
        ApiError::new(
            StatusCode::NOT_FOUND,
            "receipt-not-found",
            "no receipt view exists for this session",
        )
    })?;
    let reservation = state
        .reservation_store
        .get(session.action.workflow_id())
        .map_err(|_| ApiError::internal())?;
    let aggregate = state
        .reservation_store
        .snapshot(
            &session.policy,
            session.evidence.stripe_account_id(),
            unix_time().map_err(|_| ApiError::internal())?,
        )
        .map_err(|_| ApiError::internal())?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "result": session.last_result,
        "action_digest": session.action.digest().map_err(|_| ApiError::internal())?,
        "evidence_digest": session.evidence.digest().map_err(|_| ApiError::internal())?,
        "policy": session.policy,
        "policy_digest": session.policy.digest().map_err(|_| ApiError::internal())?,
        "policy_provenance": CONFIGURED_POLICY_PROVENANCE,
        "evaluator": session.required_bounded_configuration,
        "required_configuration": session.required_configuration,
        "reservation": reservation,
        "aggregate_budget": aggregate_projection(&aggregate, &session.policy),
    })))
}

struct ExecutionMaterials {
    action: ExactRefundActionV1,
    evidence: auths_stripe::RefundEvidenceV1,
    policy: StripeBoundedRefundPolicyV1,
    required_configuration: StripeVerifierConfiguration,
    executed_configuration: StripeVerifierConfiguration,
    required_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    executed_bounded_configuration: StripeBoundedEvaluatorConfigurationV1,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
}

fn execution_materials(
    session: &Session,
    variant: &str,
    session_id: &str,
    now: u64,
) -> Result<ExecutionMaterials, ApiError> {
    let mut action = session.action.clone();
    let executed_configuration = session.required_configuration.clone();
    let mut executed_bounded_configuration = session.required_bounded_configuration.clone();
    match variant {
        "exact" => {}
        "amount-changed" => {
            action = exact_action(
                action.workflow_id(),
                &session.required_configuration,
                &session.policy,
                &session.evidence,
                action.amount().amount_minor() + 1,
                session_id,
            )
            .map_err(|_| ApiError::internal())?;
        }
        "charge-changed" => {
            let mut input = action_input(
                action.workflow_id(),
                &session.required_configuration,
                &session.policy,
                &session.evidence,
                action.amount().amount_minor(),
                session_id,
            )
            .map_err(|_| ApiError::internal())?;
            input.charge_id = auths_stripe::ChargeId::parse("ch_changed0000000001")
                .map_err(|_| ApiError::internal())?;
            action = ExactRefundActionV1::new(input).map_err(|_| ApiError::internal())?;
        }
        "configuration-changed" => {
            executed_bounded_configuration = StripeBoundedEvaluatorConfigurationV1::for_policy(
                &session.policy,
                "auths-stripe-demo-changed-build",
                session.required_configuration.executor_audience(),
            )
            .map_err(|_| ApiError::internal())?;
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "unknown-variant",
                "variant is not one of the repository-owned experiments",
            ));
        }
    }
    let _ = now;
    Ok(ExecutionMaterials {
        action,
        evidence: session.evidence.clone(),
        policy: session.policy.clone(),
        required_configuration: session.required_configuration.clone(),
        executed_configuration,
        required_bounded_configuration: session.required_bounded_configuration.clone(),
        executed_bounded_configuration,
        proof_verifier: Arc::clone(&session.proof_verifier),
        proof: session.proof.clone(),
        request: session.request.clone(),
    })
}

#[allow(
    clippy::too_many_lines,
    reason = "the public API projection keeps every security stage explicit and adjacent"
)]
fn outcome_projection(
    outcome: Result<BoundedWorkflowOutcome, auths_stripe::ServiceError>,
) -> Result<Value, ApiError> {
    match outcome {
        Ok(BoundedWorkflowOutcome::Rejected { receipt }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "credential_requested": false,
            "stripe_called": false,
            "decision": {
                "class": bounded_decision_class(receipt.bounded_decision.class),
                "code": receipt.bounded_decision.code,
                "detail": receipt.bounded_decision.detail,
                "stage": receipt.bounded_decision.stage,
                "auths_code": receipt.auths_code,
            },
            "policy_digest": receipt.policy_digest,
            "policy_provenance": receipt.policy_provenance,
            "required_configuration": receipt.required_bounded_configuration.digest().map_err(|_| ApiError::internal())?,
            "executed_configuration": receipt.executed_bounded_configuration.digest().map_err(|_| ApiError::internal())?,
            "configuration_equal": receipt.bounded_configuration_equal,
            "limits": receipt.bounded_decision.eligibility,
            "stages": [
                {"name": "authorized", "status": "stopped"},
                {"name": "reserved", "status": "not entered"},
                {"name": "credential", "status": "not requested"},
                {"name": "stripe", "status": "not called"}
            ],
            "receipt_count": 1,
        })),
        Ok(BoundedWorkflowOutcome::Replay { reservation }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "credential_requested": false,
            "stripe_called": false,
            "decision": {
                "class": "denied",
                "code": "bounded-replay",
                "detail": "this exact refund reservation already exists; Stripe was not called again",
                "stage": "reservation",
            },
            "reservation": {
                "id": reservation.reservation_id(),
                "state": reservation.state(),
                "refund_id": reservation.refund_id(),
            },
            "stages": [
                {"name": "authorized", "status": "proven"},
                {"name": "reserved", "status": "replay returned"},
                {"name": "credential", "status": "not requested"},
                {"name": "stripe", "status": "not called"}
            ],
            "receipt_count": 1,
        })),
        Ok(BoundedWorkflowOutcome::Conflict { reservation }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "credential_requested": false,
            "stripe_called": false,
            "decision": {
                "class": "denied",
                "code": "workflow-conflict",
                "detail": "the workflow is already bound to different action bytes",
                "stage": "reservation",
            },
            "reservation": {"state": reservation.state()},
            "receipt_count": 1,
        })),
        Ok(BoundedWorkflowOutcome::CapacityChanged {
            decision,
            budget_id,
            available_minor,
        }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "credential_requested": false,
            "stripe_called": false,
            "decision": {
                "class": "denied",
                "code": "bounded-aggregate-budget-exceeded",
                "detail": "aggregate capacity changed before the atomic reservation",
                "stage": "reservation",
            },
            "earlier_eligibility": decision.eligibility,
            "budget_id": budget_id,
            "available_minor": available_minor,
            "receipt_count": 1,
        })),
        Ok(BoundedWorkflowOutcome::OutcomeUnknown { reservation }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": true,
            "credential_requested": true,
            "stripe_called": true,
            "decision": {
                "class": "indeterminate",
                "code": "bounded-execution-outcome-unknown",
                "detail": "Stripe may have received the exact request; aggregate capacity remains held",
                "stage": "stripe-api",
            },
            "reservation": {
                "id": reservation.reservation_id(),
                "state": reservation.state(),
            },
            "stages": [
                {"name": "authorized", "status": "proven"},
                {"name": "reserved", "status": "durable"},
                {"name": "credential", "status": "requested after reservation"},
                {"name": "stripe", "status": "outcome unknown"},
                {"name": "observed", "status": "reconciliation required"}
            ],
            "receipt_count": 3,
        })),
        Ok(BoundedWorkflowOutcome::Executed {
            decision,
            reservation,
            execution,
            result,
        }) => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": true,
            "credential_requested": true,
            "stripe_called": true,
            "decision": {
                "class": "authorized",
                "code": "bounded-authorized",
                "detail": "Stripe test mode created the exact refund selected inside the configured policy",
                "stage": "stripe-api",
            },
            "policy_digest": decision.policy_digest,
            "policy_provenance": decision.policy_provenance,
            "required_configuration": decision.required_bounded_configuration.digest().map_err(|_| ApiError::internal())?,
            "executed_configuration": decision.executed_bounded_configuration.digest().map_err(|_| ApiError::internal())?,
            "configuration_equal": decision.bounded_configuration_equal,
            "limits": decision.bounded_decision.eligibility,
            "reservation": {
                "id": reservation.reservation_id(),
                "state": reservation.state(),
                "amount_minor": reservation.amount_minor(),
                "intents": reservation.intents(),
            },
            "refund": {
                "id": result.refund_id,
                "charge_id": result.charge_id,
                "amount_minor": result.amount.amount_minor(),
                "currency": result.amount.currency(),
                "status": result.status,
                "stripe_request_id": result.stripe_request_id,
            },
            "receipts": {
                "decision": decision.digest().map_err(|_| ApiError::internal())?,
                "execution": execution.digest().map_err(|_| ApiError::internal())?,
            },
            "stages": [
                {"name": "authorized", "status": "proven"},
                {"name": "reserved", "status": "durable before credential"},
                {"name": "credential", "status": "requested after reservation"},
                {"name": "stripe", "status": "refund created"},
                {"name": "observed", "status": result.status}
            ],
            "receipt_count": 4,
        })),
        Err(_) => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            "stripe-execution-failed",
            "the protected Stripe execution failed closed",
        )),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "all exact policy, evidence, and configuration inputs stay explicit in demo projections"
)]
fn variant_projections(
    action: &ExactRefundActionV1,
    evidence: &auths_stripe::RefundEvidenceV1,
    policy: &StripeBoundedRefundPolicyV1,
    configuration: &StripeVerifierConfiguration,
    bounded_configuration: &StripeBoundedEvaluatorConfigurationV1,
    aggregate_snapshot: &AggregateBudgetSnapshot,
    now: u64,
    session_id: &str,
) -> Result<Vec<Value>, StartupError> {
    let changed_amount = exact_action(
        action.workflow_id(),
        configuration,
        policy,
        evidence,
        action.amount().amount_minor() + 1,
        session_id,
    )
    .map_err(|_| StartupError::Fixture)?;
    let mut changed_charge_input = action_input(
        action.workflow_id(),
        configuration,
        policy,
        evidence,
        action.amount().amount_minor(),
        session_id,
    )
    .map_err(|_| StartupError::Fixture)?;
    changed_charge_input.charge_id =
        auths_stripe::ChargeId::parse("ch_changed0000000001").map_err(|_| StartupError::Fixture)?;
    let changed_charge =
        ExactRefundActionV1::new(changed_charge_input).map_err(|_| StartupError::Fixture)?;
    let changed_configuration = StripeBoundedEvaluatorConfigurationV1::for_policy(
        policy,
        "auths-stripe-demo-changed-build",
        configuration.executor_audience(),
    )
    .map_err(|_| StartupError::Fixture)?;
    let variants = [
        ("exact", action.clone(), bounded_configuration.clone()),
        (
            "amount-changed",
            changed_amount,
            bounded_configuration.clone(),
        ),
        (
            "charge-changed",
            changed_charge,
            bounded_configuration.clone(),
        ),
        (
            "configuration-changed",
            action.clone(),
            changed_configuration,
        ),
    ];
    variants
        .into_iter()
        .map(|(id, candidate, executed)| {
            let decision = evaluate_bounded_refund(&BoundedEvaluationContext {
                policy,
                action: &candidate,
                evidence,
                aggregate_snapshot,
                required_exact_configuration: configuration,
                executed_exact_configuration: configuration,
                required_bounded_configuration: bounded_configuration,
                executed_bounded_configuration: &executed,
                request_audience: configuration.executor_audience(),
                now,
            });
            Ok(json!({
                "id": id,
                "decision": {
                    "class": bounded_decision_class(decision.class),
                    "code": decision.code,
                    "detail": decision.detail,
                    "stage": decision.stage,
                },
                "limits": decision.eligibility,
                "amount_minor": candidate.amount().amount_minor(),
                "charge_id": candidate.charge_id(),
                "required_configuration": bounded_configuration.digest().map_err(|_| StartupError::Fixture)?,
                "executed_configuration": executed.digest().map_err(|_| StartupError::Fixture)?,
                "configuration_match": bounded_configuration == &executed,
            }))
        })
        .collect()
}

fn configuration(
    environment: &Arc<dyn DemoStripeEnvironment>,
    maximum_refund_minor: u64,
) -> Result<StripeVerifierConfiguration, StartupError> {
    configuration_with_limit(
        environment.account_id().clone(),
        environment.api_version(),
        maximum_refund_minor,
    )
}

fn configuration_with_limit(
    account: auths_stripe::StripeAccountId,
    api_version: &str,
    maximum_refund_minor: u64,
) -> Result<StripeVerifierConfiguration, StartupError> {
    let currency = Currency::parse("usd").map_err(|_| StartupError::Fixture)?;
    StripeVerifierConfiguration::new(StripeVerifierConfigurationInput {
        allowed_test_account_ids: vec![account],
        allowed_api_versions: vec![api_version.into()],
        allowed_currencies: vec![currency.clone()],
        maximum_refund_minor_by_currency: BTreeMap::from([(currency, maximum_refund_minor)]),
        allowed_reasons: vec!["requested_by_customer".into()],
        maximum_evidence_age_seconds: SESSION_TTL_SECONDS,
        maximum_authorization_lifetime_seconds: 300,
        allow_partial_refunds: true,
        allow_refund_application_fee: false,
        allow_reverse_transfer: false,
        allowed_metadata_keys: vec![
            "auths_action".into(),
            "auths_connect_account".into(),
            "auths_policy".into(),
            "auths_workflow".into(),
        ],
        executor_audience: "https://stripe-executor.auths.dev".into(),
        receipt_schema_version: "auths.stripe.receipt/1".into(),
    })
    .map_err(|_| StartupError::Fixture)
}

fn bounded_policy(
    evidence: &auths_stripe::RefundEvidenceV1,
    now: u64,
) -> Result<StripeBoundedRefundPolicyV1, StartupError> {
    let payment_intent = evidence
        .payment_intent_id()
        .cloned()
        .ok_or(StartupError::Fixture)?;
    StripeBoundedRefundPolicyV1::new(StripeBoundedRefundPolicyInput {
        policy_id: "stripe-demo-support-refunds".into(),
        valid_from: now.saturating_sub(30),
        expires_at: now + SESSION_TTL_SECONDS,
        allowed_test_account_ids: vec![evidence.stripe_account_id().clone()],
        allowed_currencies: vec![evidence.currency().clone()],
        allowed_reasons: vec!["requested_by_customer".into()],
        allowed_charge_ids: vec![evidence.charge_id().clone()],
        allowed_payment_intent_ids: vec![payment_intent],
        allowed_api_versions: vec![evidence.stripe_api_version().into()],
        connect_scope: ConnectScope::PlatformOnly,
        maximum_evidence_age_seconds: SESSION_TTL_SECONDS,
        per_refund_absolute_minor_by_currency: BTreeMap::from([(
            evidence.currency().clone(),
            ABSOLUTE_REFUND_LIMIT_MINOR,
        )]),
        relative_limit: RelativeRefundLimit::new(
            RELATIVE_REFUND_LIMIT_BPS,
            RefundDenominator::OriginalChargeAmount,
        )
        .map_err(|_| StartupError::Fixture)?,
        aggregate_budgets: vec![
            AggregateRefundBudget::new(
                "session-fixed",
                evidence.currency().clone(),
                AGGREGATE_REFUND_LIMIT_MINOR,
                RefundBudgetWindow::Fixed {
                    starts_at: now.saturating_sub(30),
                    ends_at: now + SESSION_TTL_SECONDS,
                },
            )
            .map_err(|_| StartupError::Fixture)?,
            AggregateRefundBudget::new(
                "rolling-hour",
                evidence.currency().clone(),
                AGGREGATE_REFUND_LIMIT_MINOR,
                RefundBudgetWindow::Rolling {
                    duration_seconds: 3_600,
                },
            )
            .map_err(|_| StartupError::Fixture)?,
        ],
    })
    .map_err(|_| StartupError::Fixture)
}

fn exact_action(
    workflow_id: &str,
    configuration: &StripeVerifierConfiguration,
    policy: &StripeBoundedRefundPolicyV1,
    evidence: &auths_stripe::RefundEvidenceV1,
    amount_minor: u64,
    session_id: &str,
) -> Result<ExactRefundActionV1, auths_stripe::types::ValidationError> {
    ExactRefundActionV1::new(action_input(
        workflow_id,
        configuration,
        policy,
        evidence,
        amount_minor,
        session_id,
    )?)
}

fn action_input(
    workflow_id: &str,
    configuration: &StripeVerifierConfiguration,
    policy: &StripeBoundedRefundPolicyV1,
    evidence: &auths_stripe::RefundEvidenceV1,
    amount_minor: u64,
    session_id: &str,
) -> Result<ExactRefundActionInput, auths_stripe::types::ValidationError> {
    Ok(ExactRefundActionInput {
        workflow_id: workflow_id.into(),
        executor_audience: configuration.executor_audience().into(),
        stripe_account_id: evidence.stripe_account_id().clone(),
        stripe_api_version: evidence.stripe_api_version().into(),
        livemode: evidence.livemode(),
        charge_id: evidence.charge_id().clone(),
        payment_intent_id: evidence.payment_intent_id().cloned(),
        amount: Money::new(evidence.currency().clone(), amount_minor)?,
        reason: Some("requested_by_customer".into()),
        metadata: BTreeMap::from([
            ("auths_action".into(), "exact-refund".into()),
            (
                "auths_connect_account".into(),
                evidence
                    .connect_account_id()
                    .map_or_else(|| "platform".into(), ToString::to_string),
            ),
            (
                "auths_policy".into(),
                policy
                    .digest()
                    .map_err(|_| auths_stripe::types::ValidationError::Canonicalization)?
                    .to_string(),
            ),
            ("auths_workflow".into(), workflow_id.into()),
        ]),
        refund_application_fee: false,
        reverse_transfer: false,
        expected_charge_amount_minor: evidence.charge_amount_minor(),
        expected_amount_refunded_minor: evidence.amount_refunded_minor(),
        expected_refundable_amount_minor: evidence.refundable_amount_minor(),
        evidence_digest: evidence
            .digest()
            .map_err(|_| auths_stripe::types::ValidationError::Canonicalization)?,
        required_configuration_digest: configuration
            .digest()
            .map_err(|_| auths_stripe::types::ValidationError::Canonicalization)?,
        observed_at: evidence.observed_at(),
        expires_at: evidence.observed_at() + 300,
        nonce: auths_stripe::canonical::sha256(session_id.as_bytes()),
    })
}

fn payment_projection(evidence: &auths_stripe::RefundEvidenceV1) -> Value {
    json!({
        "charge_id": evidence.charge_id(),
        "payment_intent_id": evidence.payment_intent_id(),
        "amount_minor": evidence.charge_amount_minor(),
        "captured_amount_minor": evidence.captured_amount_minor(),
        "amount_refunded_minor": evidence.amount_refunded_minor(),
        "refundable_amount_minor": evidence.refundable_amount_minor(),
        "currency": evidence.currency(),
        "livemode": evidence.livemode(),
        "paid": evidence.paid(),
        "captured": evidence.captured(),
    })
}

fn aggregate_projection(
    snapshot: &AggregateBudgetSnapshot,
    policy: &StripeBoundedRefundPolicyV1,
) -> Value {
    let budgets = policy
        .aggregate_budgets()
        .iter()
        .map(|budget| {
            let usage = snapshot
                .usages
                .iter()
                .find(|usage| usage.budget_id == budget.budget_id());
            let committed = usage.map_or(0, |value| value.committed_minor);
            let reserved = usage.map_or(0, |value| value.reserved_minor);
            let unknown = usage.map_or(0, |value| value.outcome_unknown_minor);
            let used = committed.saturating_add(reserved).saturating_add(unknown);
            json!({
                "budget_id": budget.budget_id(),
                "currency": budget.currency(),
                "limit_minor": budget.limit_minor(),
                "available_minor": budget.limit_minor().saturating_sub(used),
                "reserved_minor": reserved,
                "spent_minor": committed,
                "outcome_unknown_minor": unknown,
                "window": usage.map(|value| &value.window),
            })
        })
        .collect::<Vec<_>>();
    json!({"budgets": budgets})
}

const fn bounded_decision_class(class: BoundedDecisionClass) -> &'static str {
    match class {
        BoundedDecisionClass::Eligible => "authorized",
        BoundedDecisionClass::Denied => "denied",
        BoundedDecisionClass::Indeterminate => "indeterminate",
    }
}

fn unix_time() -> Result<u64, StartupError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StartupError::Invalid)
}

struct JsonlReceiptSink {
    path: PathBuf,
    write_lock: StdMutex<()>,
}

impl JsonlReceiptSink {
    fn new(path: PathBuf) -> Result<Self, StartupError> {
        path.parent().ok_or(StartupError::State)?;
        Ok(Self {
            path,
            write_lock: StdMutex::new(()),
        })
    }
}

impl ReceiptSink for JsonlReceiptSink {
    fn append(&self, receipt: &StripeReceipt) -> Result<(), auths_stripe::PortError> {
        let _guard = self
            .write_lock
            .lock()
            .map_err(|_| auths_stripe::PortError::Persistence)?;
        let parent = self
            .path
            .parent()
            .ok_or(auths_stripe::PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| auths_stripe::PortError::Persistence)?;
        let bytes = receipt
            .canonical_bytes()
            .map_err(|_| auths_stripe::PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| auths_stripe::PortError::Persistence)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| auths_stripe::PortError::Persistence)
    }
}

/// Demo startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    /// Required environment is missing.
    Missing(&'static str),
    /// Configuration is malformed.
    Invalid,
    /// Stripe test-mode configuration failed.
    Stripe,
    /// Durable state failed.
    State,
    /// Repository-owned Auths fixture failed.
    Fixture,
}

impl fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => {
                write!(formatter, "required environment variable {name} missing")
            }
            Self::Invalid => formatter.write_str("invalid Stripe demo configuration"),
            Self::Stripe => formatter.write_str("Stripe test-mode environment is unavailable"),
            Self::State => formatter.write_str("durable Stripe demo state is unavailable"),
            Self::Fixture => formatter.write_str("Stripe Auths fixture failed validation"),
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
            "internal-error",
            "the bounded native demo failed closed",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
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
    use std::sync::atomic::{AtomicUsize, Ordering};

    use auths_stripe::{
        ChargeId, CredentialProvider, InMemoryClaimStore, InMemoryRefundReservationStore,
        PaymentIntentId, PortError, RefundEvidenceInput, RefundEvidenceV1, RefundId, RefundResult,
        StripeAccountId, StripeCredential, StripeGateway, VerifiedRefundCommand, canonical::sha256,
    };
    use axum::{
        body::{Body, to_bytes},
        http::Request,
    };
    use tower::ServiceExt as _;

    use super::*;

    struct FakeStripe {
        account: StripeAccountId,
        calls: AtomicUsize,
        credentials: AtomicUsize,
        reservation_store: Arc<InMemoryRefundReservationStore>,
        credential_after_reservation: std::sync::atomic::AtomicBool,
        outcome_unknown: bool,
    }

    impl FakeStripe {
        fn new(reservation_store: Arc<InMemoryRefundReservationStore>) -> Self {
            Self {
                account: StripeAccountId::parse("acct_authsdemo01").unwrap(),
                calls: AtomicUsize::new(0),
                credentials: AtomicUsize::new(0),
                reservation_store,
                credential_after_reservation: std::sync::atomic::AtomicBool::new(false),
                outcome_unknown: false,
            }
        }

        fn outcome_unknown(reservation_store: Arc<InMemoryRefundReservationStore>) -> Self {
            Self {
                outcome_unknown: true,
                ..Self::new(reservation_store)
            }
        }
    }

    impl DemoStripeEnvironment for FakeStripe {
        fn seed_payment(&self, _: &str, now: u64) -> Result<RefundEvidenceV1, PortError> {
            RefundEvidenceV1::new(RefundEvidenceInput {
                stripe_account_id: self.account.clone(),
                stripe_api_version: "2025-04-30.basil".into(),
                livemode: false,
                charge_id: ChargeId::parse("ch_authsdemo00000001").unwrap(),
                payment_intent_id: Some(PaymentIntentId::parse("pi_authsdemo00000001").unwrap()),
                connect_account_id: None,
                currency: Currency::parse("usd").unwrap(),
                charge_amount_minor: 2_000,
                captured_amount_minor: 2_000,
                amount_refunded_minor: 0,
                paid: true,
                captured: true,
                charge_refunded: false,
                disputed: false,
                observed_at: now,
                response_commitment: sha256(b"fake Stripe response"),
            })
            .map_err(|_| PortError::Malformed)
        }

        fn account_id(&self) -> &StripeAccountId {
            &self.account
        }

        #[allow(
            clippy::unnecessary_literal_bound,
            reason = "the test double implements a trait whose production value is runtime configured"
        )]
        fn api_version(&self) -> &str {
            "2025-04-30.basil"
        }

        fn execution_mode(&self) -> &'static str {
            "stripe-test-double"
        }

        fn reconcile_refund(
            &self,
            action: &ExactRefundActionV1,
            now: u64,
        ) -> Result<Option<RefundResult>, PortError> {
            if !self.outcome_unknown {
                return Ok(None);
            }
            Ok(Some(RefundResult {
                refund_id: RefundId::parse("re_authsdemo00000002").unwrap(),
                charge_id: action.charge_id().clone(),
                payment_intent_id: action.payment_intent_id().cloned(),
                amount: action.amount().clone(),
                status: "succeeded".into(),
                stripe_request_id: "req_authsdemo00000002".into(),
                observed_at: now,
            }))
        }
    }

    impl CredentialProvider for FakeStripe {
        fn mutation_credential(&self, _: &StripeAccountId) -> Result<StripeCredential, PortError> {
            self.credentials.fetch_add(1, Ordering::SeqCst);
            self.credential_after_reservation.store(
                self.reservation_store.active_reservation_count() > 0,
                Ordering::SeqCst,
            );
            let test_credential = ["sk", "test", "auths_demo_credential"].join("_");
            StripeCredential::new(test_credential)
        }
    }

    impl StripeGateway for FakeStripe {
        fn create_refund(
            &self,
            command: &VerifiedRefundCommand,
            _: &StripeCredential,
            now: u64,
        ) -> Result<RefundResult, PortError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.outcome_unknown {
                return Err(PortError::OutcomeUnknown);
            }
            Ok(RefundResult {
                refund_id: RefundId::parse("re_authsdemo00000001").unwrap(),
                charge_id: command.action().charge_id().clone(),
                payment_intent_id: command.action().payment_intent_id().cloned(),
                amount: command.action().amount().clone(),
                status: "succeeded".into(),
                stripe_request_id: "req_authsdemo00000001".into(),
                observed_at: now,
            })
        }
    }

    #[derive(Default)]
    struct MemoryReceipts(StdMutex<Vec<StripeReceipt>>);

    impl ReceiptSink for MemoryReceipts {
        fn append(&self, receipt: &StripeReceipt) -> Result<(), PortError> {
            self.0
                .lock()
                .map_err(|_| PortError::Persistence)?
                .push(receipt.clone());
            Ok(())
        }
    }

    async fn create_test_session(app: &Router) -> (String, Value) {
        let response = app
            .clone()
            .oneshot(
                Request::post("/api/v1/sessions")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        (value["session_id"].as_str().unwrap().into(), value)
    }

    fn test_app(
        stripe: Arc<FakeStripe>,
        reservation_store: Arc<InMemoryRefundReservationStore>,
    ) -> Router {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.keep();
        app_with_stores(
            AppConfig::for_test(path),
            stripe,
            Arc::new(InMemoryClaimStore::default()),
            reservation_store,
            Arc::new(MemoryReceipts::default()),
        )
    }

    #[tokio::test]
    async fn denied_variant_never_reaches_stripe() {
        let reservation_store = Arc::new(InMemoryRefundReservationStore::default());
        let stripe = Arc::new(FakeStripe::new(Arc::clone(&reservation_store)));
        let app = test_app(Arc::clone(&stripe), reservation_store);
        let (session_id, _) = create_test_session(&app).await;
        let response = app
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"amount-changed"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(stripe.credentials.load(Ordering::SeqCst), 0);
        assert_eq!(stripe.calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn exact_refund_executes_once_and_replay_fails_closed() {
        let reservation_store = Arc::new(InMemoryRefundReservationStore::default());
        let stripe = Arc::new(FakeStripe::new(Arc::clone(&reservation_store)));
        let app = test_app(Arc::clone(&stripe), reservation_store);
        let (session_id, _) = create_test_session(&app).await;
        for expected_code in ["bounded-authorized", "bounded-replay"] {
            let response = app
                .clone()
                .oneshot(
                    Request::post(format!("/api/v1/sessions/{session_id}/execute"))
                        .header(CONTENT_TYPE, "application/json")
                        .body(Body::from(r#"{"variant":"exact"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["decision"]["code"], expected_code);
        }
        assert_eq!(stripe.credentials.load(Ordering::SeqCst), 1);
        assert_eq!(stripe.calls.load(Ordering::SeqCst), 1);
        assert!(
            stripe.credential_after_reservation.load(Ordering::SeqCst),
            "credential acquisition must observe a durable aggregate reservation"
        );
    }

    #[tokio::test]
    async fn ambiguous_stripe_response_holds_budget_until_reconciliation() {
        let reservation_store = Arc::new(InMemoryRefundReservationStore::default());
        let stripe = Arc::new(FakeStripe::outcome_unknown(Arc::clone(&reservation_store)));
        let app = test_app(Arc::clone(&stripe), Arc::clone(&reservation_store));
        let (session_id, _) = create_test_session(&app).await;
        let response = app
            .clone()
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(r#"{"variant":"exact"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            value["decision"]["code"],
            "bounded-execution-outcome-unknown"
        );
        assert_eq!(value["reservation"]["state"], "outcome-unknown");
        assert_eq!(reservation_store.active_reservation_count(), 1);

        let response = app
            .oneshot(
                Request::post(format!("/api/v1/sessions/{session_id}/reconcile"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), 128 * 1024).await.unwrap();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["reservation"]["state"], "reconciled-committed");
        assert_eq!(stripe.credentials.load(Ordering::SeqCst), 1);
        assert_eq!(stripe.calls.load(Ordering::SeqCst), 1);
    }
}
