use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex as StdMutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_kubernetes::{
    ClaimStore, DecisionClass, DecisionCode, ExecuteRolloutRequest, ImageDigestRef, KubernetesName,
    KubernetesReceipt, KubernetesRolloutProfile, KubernetesVerifierConfiguration,
    KubernetesWorkloadRolloutV1, PersistentClaimStore, PortError, ReceiptSink, RolloutService,
    SdkProofVerifier, ServiceDependencies, SystemClock, WorkflowOutcome,
    canonical::{canonical_json, sha256},
    receipts::decision_receipt,
};
use auths_profile_api::ActionProfile as _;
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
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
    kubernetes::{BackendError, KubernetesBackend, LiveKubernetesConfig, PreparedRollout},
};

const API_SCHEMA: &str = "auths-kubernetes-demo/v1";
const SESSION_TTL_SECONDS: u64 = 300;
const MAX_SESSIONS: usize = 128;

/// Native service configuration.
#[derive(Clone)]
pub struct AppConfig {
    allowed_origin: HeaderValue,
    region: String,
    release: String,
    state_directory: Arc<Path>,
    backend: KubernetesBackend,
}

impl AppConfig {
    /// Loads fail-closed production configuration.
    ///
    /// # Errors
    ///
    /// Returns [`StartupError`] when required environment values are absent
    /// or invalid, or the live Kubernetes client cannot be constructed.
    pub fn from_env() -> Result<Self, StartupError> {
        let allowed_origin = env::var("AUTHS_KUBERNETES_ALLOWED_ORIGIN")
            .map_err(|_| StartupError::Configuration)?
            .parse()
            .map_err(|_| StartupError::Configuration)?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("AUTHS_KUBERNETES_RELEASE").unwrap_or_else(|_| "development".into());
        let state_directory = PathBuf::from(
            env::var("AUTHS_KUBERNETES_STATE_DIR").unwrap_or_else(|_| ".state/kubernetes".into()),
        );
        let backend = KubernetesBackend::live(LiveKubernetesConfig {
            api_server: required_env("AUTHS_KUBERNETES_API_SERVER")?,
            ca_pem: required_env("AUTHS_KUBERNETES_CA_PEM")?.into_bytes(),
            evidence_token: required_env("AUTHS_KUBERNETES_EVIDENCE_TOKEN")?.into_bytes(),
            mutation_token: required_env("AUTHS_KUBERNETES_MUTATION_TOKEN")?.into_bytes(),
            cluster_audience: required_env("AUTHS_KUBERNETES_CLUSTER_AUDIENCE")?,
            namespace: KubernetesName::parse(required_env("AUTHS_KUBERNETES_NAMESPACE")?)
                .map_err(|_| StartupError::Configuration)?,
            deployment: KubernetesName::parse(required_env("AUTHS_KUBERNETES_DEPLOYMENT")?)
                .map_err(|_| StartupError::Configuration)?,
            container: KubernetesName::parse(required_env("AUTHS_KUBERNETES_CONTAINER")?)
                .map_err(|_| StartupError::Configuration)?,
            image_a: ImageDigestRef::parse(required_env("AUTHS_KUBERNETES_IMAGE_A")?)
                .map_err(|_| StartupError::Configuration)?,
            image_b: ImageDigestRef::parse(required_env("AUTHS_KUBERNETES_IMAGE_B")?)
                .map_err(|_| StartupError::Configuration)?,
            executor_audience: required_env("AUTHS_KUBERNETES_EXECUTOR_AUDIENCE")?,
        })
        .map_err(|_| StartupError::Kubernetes)?;
        Ok(Self {
            allowed_origin,
            region,
            release,
            state_directory: state_directory.into(),
            backend,
        })
    }

    #[cfg(test)]
    fn for_test(state_directory: PathBuf) -> Self {
        Self {
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: "test".into(),
            release: "test".into(),
            state_directory: state_directory.into(),
            backend: KubernetesBackend::fixture(),
        }
    }
}

fn required_env(name: &str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(StartupError::Configuration)
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    claim_store: Arc<dyn ClaimStore>,
    receipt_sink: Arc<dyn ReceiptSink>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct Session {
    expires_at: u64,
    action: KubernetesWorkloadRolloutV1,
    evidence: auths_kubernetes::KubernetesEvidenceV1,
    required_configuration: KubernetesVerifierConfiguration,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
    human_principal: String,
    agent_principal: String,
    last_result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the native production API.
///
/// # Errors
///
/// Returns [`StartupError`] when durable state or receipt storage cannot be
/// initialized.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    fs::create_dir_all(config.state_directory.as_ref()).map_err(|_| StartupError::State)?;
    let receipt_sink = Arc::new(
        JsonlReceiptSink::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let claim_store = Arc::new(
        PersistentClaimStore::open(config.state_directory.join("claims.json"))
            .map_err(|_| StartupError::State)?,
    );
    Ok(app_with_dependencies(config, claim_store, receipt_sink))
}

fn app_with_dependencies(
    config: AppConfig,
    claim_store: Arc<dyn ClaimStore>,
    receipt_sink: Arc<dyn ReceiptSink>,
) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    let state = AppState {
        config,
        claim_store,
        receipt_sink,
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/build", get(build))
        .route("/api/v1/scenarios", get(scenarios))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/receipts/{session_id}", get(receipts))
        .with_state(state)
        .layer(cors)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "region": state.config.region,
        "release": state.config.release,
    }))
}

async fn readiness(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let backend = state.config.backend.clone();
    tokio::task::spawn_blocking(move || backend.readiness())
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::backend)?;
    Ok(Json(json!({
        "status": "ready",
        "schema": API_SCHEMA,
        "cluster_mode": state.config.backend.mode(),
        "credential_boundary": "native-executor-only",
    })))
}

async fn build(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "profile": "auths.kubernetes.workload-rollout/1",
    }))
}

async fn scenarios(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "cluster_mode": state.config.backend.mode(),
        "variants": [
            {"id": "exact", "label": "Exact rollout", "description": "Image digest, Deployment UID, namespace, replicas, and policy match"},
            {"id": "image-changed", "label": "Image digest changed", "description": "The proposed digest changed after authorization"},
            {"id": "mutable-tag", "label": "Mutable tag substituted", "description": "A tag replaces the authorized immutable digest"},
            {"id": "replicas-exceed", "label": "Replicas exceed grant", "description": "The patch requests more replicas than policy allows"},
            {"id": "forbidden-field", "label": "Security context added", "description": "The patch adds a field outside the rollout profile"},
            {"id": "namespace-changed", "label": "Namespace changed", "description": "The exact target namespace no longer matches"},
            {"id": "resource-stale", "label": "Resource version stale", "description": "The Deployment changed after evidence was observed"},
            {"id": "configuration-changed", "label": "Verifier policy changed", "description": "The executor loaded a different replica ceiling"}
        ]
    }))
}

async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|_| ApiError::internal())?;
    let session_id = random_id().map_err(|_| ApiError::internal())?;
    let workflow_id = format!("k8s-{session_id}");
    let backend = state.config.backend.clone();
    let prepared = tokio::task::spawn_blocking(move || backend.prepare(now, &workflow_id))
        .await
        .map_err(|_| ApiError::internal())?
        .map_err(ApiError::backend)?;
    let fixture = authorization_fixture(&prepared.action, now, random_challenge()?);
    let variants = variant_projections(&prepared, now)?;
    let response = json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "cluster_mode": state.config.backend.mode(),
        "profile": "auths.kubernetes.workload-rollout/1",
        "agent_has_kubernetes_credential": false,
        "target": {
            "cluster": prepared.action.cluster_audience(),
            "namespace": prepared.action.namespace_name(),
            "deployment": prepared.action.resource_name(),
            "deployment_uid": prepared.action.resource_uid(),
            "resource_version": prepared.action.expected_resource_version(),
            "container": prepared.action.projection().container_name,
        },
        "before": {
            "image": prepared.action.projection().previous_image_digest,
            "replicas": prepared.action.projection().previous_replicas,
        },
        "after": {
            "image": prepared.action.projection().requested_image_digest,
            "replicas": prepared.action.projection().requested_replicas,
        },
        "principals": {
            "human": fixture.human_principal,
            "agent": fixture.agent_principal,
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
            action: prepared.action,
            evidence: prepared.evidence,
            required_configuration: prepared.configuration,
            proof_verifier: Arc::new(SdkProofVerifier::new(fixture.verifier)),
            proof: fixture.proof,
            request: fixture.request,
            human_principal: fixture.human_principal,
            agent_principal: fixture.agent_principal,
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
        let session = sessions.get(&session_id).ok_or_else(|| {
            ApiError::new(
                StatusCode::GONE,
                "session-unavailable",
                "the Kubernetes demo session is missing or expired",
            )
        })?;
        if session.expires_at <= now {
            return Err(ApiError::new(
                StatusCode::GONE,
                "session-expired",
                "the Kubernetes demo session expired",
            ));
        }
        execution_materials(session, &request.variant)?
    };

    let result = match materials {
        ExecutionMaterials::ProfileDenied { code, detail } => denied_result(&code, &detail),
        ExecutionMaterials::Service(materials) => {
            let backend = Arc::new(state.config.backend.clone());
            let claim_store = Arc::clone(&state.claim_store);
            let receipt_sink = Arc::clone(&state.receipt_sink);
            tokio::task::spawn_blocking(move || {
                let service = RolloutService::new(ServiceDependencies {
                    proof_verifier: materials.proof_verifier,
                    credential_provider: Arc::clone(&backend),
                    kubernetes_gateway: backend,
                    claim_store,
                    receipt_sink,
                    clock: SystemClock,
                    executed_configuration: materials.executed_configuration,
                });
                service.execute(ExecuteRolloutRequest {
                    action: materials.action,
                    evidence: materials.evidence,
                    required_configuration: materials.required_configuration,
                    proof: materials.proof,
                    auths_request: materials.request,
                })
            })
            .await
            .map_err(|_| ApiError::internal())?
            .map(workflow_result)
            .map_err(|error| {
                ApiError::new(
                    StatusCode::BAD_GATEWAY,
                    "native-execution-failed",
                    &error.to_string(),
                )
            })?
        }
    };
    let mut sessions = state.sessions.lock().await;
    if let Some(session) = sessions.get_mut(&session_id) {
        session.last_result = Some(result.clone());
    }
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "result": result,
    })))
}

async fn receipts(
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
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "result": session.last_result,
        "action_digest": session.action.digest().map_err(|_| ApiError::internal())?,
        "evidence_digest": session.evidence.digest().map_err(|_| ApiError::internal())?,
        "required_configuration": session.required_configuration,
        "human_principal": session.human_principal,
        "agent_principal": session.agent_principal,
    })))
}

enum ExecutionMaterials {
    ProfileDenied { code: String, detail: String },
    Service(Box<ServiceMaterials>),
}

struct ServiceMaterials {
    action: KubernetesWorkloadRolloutV1,
    evidence: auths_kubernetes::KubernetesEvidenceV1,
    required_configuration: KubernetesVerifierConfiguration,
    executed_configuration: KubernetesVerifierConfiguration,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    request: auths_sdk::RequestContext,
}

fn execution_materials(session: &Session, variant: &str) -> Result<ExecutionMaterials, ApiError> {
    let mut action = session.action.clone();
    let mut executed_configuration = session.required_configuration.clone();
    match variant {
        "exact" => {}
        "image-changed" => {
            action = mutate_action(&action, ActionMutation::ImageChanged)?;
        }
        "replicas-exceed" => {
            action = mutate_action(&action, ActionMutation::Replicas(10))?;
        }
        "namespace-changed" => {
            action = mutate_action(&action, ActionMutation::Namespace("other-demo"))?;
        }
        "resource-stale" => {
            action = mutate_action(&action, ActionMutation::ResourceVersion("stale-version"))?;
        }
        "configuration-changed" => {
            executed_configuration =
                configuration_with_maximum(&session.required_configuration, 4)?;
        }
        "mutable-tag" => {
            let bytes = mutate_raw_action(&action, ActionMutation::MutableTag)?;
            assert_profile_denial(&bytes)?;
            return Ok(ExecutionMaterials::ProfileDenied {
                code: "mutable-image-reference".into(),
                detail: "the proposed image uses a mutable tag instead of an immutable digest"
                    .into(),
            });
        }
        "forbidden-field" => {
            let bytes = mutate_raw_action(&action, ActionMutation::ForbiddenField)?;
            assert_profile_denial(&bytes)?;
            return Ok(ExecutionMaterials::ProfileDenied {
                code: "change-outside-profile".into(),
                detail: "the patch adds securityContext, which this rollout profile forbids".into(),
            });
        }
        _ => {
            return Err(ApiError::new(
                StatusCode::BAD_REQUEST,
                "unknown-variant",
                "variant is not one of the repository-owned experiments",
            ));
        }
    }
    Ok(ExecutionMaterials::Service(Box::new(ServiceMaterials {
        action,
        evidence: session.evidence.clone(),
        required_configuration: session.required_configuration.clone(),
        executed_configuration,
        proof_verifier: Arc::clone(&session.proof_verifier),
        proof: session.proof.clone(),
        request: session.request.clone(),
    })))
}

fn variant_projections(prepared: &PreparedRollout, now: u64) -> Result<Vec<Value>, ApiError> {
    let variants = [
        "exact",
        "image-changed",
        "mutable-tag",
        "replicas-exceed",
        "forbidden-field",
        "namespace-changed",
        "resource-stale",
        "configuration-changed",
    ];
    variants
        .into_iter()
        .map(|variant| predicted_variant(prepared, variant, now))
        .collect()
}

fn predicted_variant(
    prepared: &PreparedRollout,
    variant: &str,
    now: u64,
) -> Result<Value, ApiError> {
    if variant == "mutable-tag" {
        return Ok(predicted_profile_denial(
            variant,
            "mutable-image-reference",
            "profile",
            "a mutable image tag is forbidden",
            prepared,
        ));
    }
    if variant == "forbidden-field" {
        return Ok(predicted_profile_denial(
            variant,
            "change-outside-profile",
            "change-projection",
            "securityContext is outside the permitted rollout change",
            prepared,
        ));
    }
    let action = match variant {
        "exact" | "configuration-changed" => prepared.action.clone(),
        "image-changed" => mutate_action(&prepared.action, ActionMutation::ImageChanged)?,
        "replicas-exceed" => mutate_action(&prepared.action, ActionMutation::Replicas(10))?,
        "namespace-changed" => {
            mutate_action(&prepared.action, ActionMutation::Namespace("other-demo"))?
        }
        "resource-stale" => mutate_action(
            &prepared.action,
            ActionMutation::ResourceVersion("stale-version"),
        )?,
        _ => return Err(ApiError::internal()),
    };
    let executed_configuration = if variant == "configuration-changed" {
        configuration_with_maximum(&prepared.configuration, 4)?
    } else {
        prepared.configuration.clone()
    };
    let mut receipt = decision_receipt(
        &action,
        &prepared.evidence,
        &prepared.configuration,
        &executed_configuration,
        prepared.configuration.executor_audience(),
        now,
    )
    .map_err(|_| ApiError::internal())?;
    if variant == "image-changed" && receipt.decision.class == DecisionClass::Authorized {
        receipt.decision.class = DecisionClass::Denied;
        receipt.decision.code = DecisionCode::ActionBodyMismatch;
        receipt.decision.stage = "auths-kernel".into();
        receipt.decision.detail =
            "the exact action bytes changed after the proof was signed".into();
    }
    Ok(json!({
        "id": variant,
        "decision": receipt.decision,
        "required_configuration": prepared.configuration.digest().map_err(|_| ApiError::internal())?,
        "executed_configuration": executed_configuration.digest().map_err(|_| ApiError::internal())?,
        "configuration_match": prepared.configuration == executed_configuration,
        "image": action.projection().requested_image_digest,
        "replicas": action.projection().requested_replicas,
    }))
}

fn predicted_profile_denial(
    variant: &str,
    code: &str,
    stage: &str,
    detail: &str,
    prepared: &PreparedRollout,
) -> Value {
    json!({
        "id": variant,
        "decision": {
            "class": "denied",
            "code": code,
            "stage": stage,
            "detail": detail,
        },
        "required_configuration": prepared.configuration.digest().ok(),
        "executed_configuration": prepared.configuration.digest().ok(),
        "configuration_match": true,
        "image": prepared.action.projection().requested_image_digest,
        "replicas": prepared.action.projection().requested_replicas,
    })
}

#[derive(Clone, Copy)]
enum ActionMutation<'a> {
    ImageChanged,
    MutableTag,
    Replicas(u32),
    ForbiddenField,
    Namespace(&'a str),
    ResourceVersion(&'a str),
}

fn mutate_action(
    action: &KubernetesWorkloadRolloutV1,
    mutation: ActionMutation<'_>,
) -> Result<KubernetesWorkloadRolloutV1, ApiError> {
    let bytes = mutate_raw_action(action, mutation)?;
    serde_json::from_slice::<KubernetesWorkloadRolloutV1>(&bytes)
        .map_err(|_| ApiError::internal())
        .and_then(|action| {
            action.validate().map_err(|_| ApiError::internal())?;
            Ok(action)
        })
}

fn mutate_raw_action(
    action: &KubernetesWorkloadRolloutV1,
    mutation: ActionMutation<'_>,
) -> Result<Vec<u8>, ApiError> {
    let mut value = serde_json::to_value(action).map_err(|_| ApiError::internal())?;
    let mut patch: Value = serde_json::from_str(
        value
            .get("patch_bytes")
            .and_then(Value::as_str)
            .ok_or_else(ApiError::internal)?,
    )
    .map_err(|_| ApiError::internal())?;
    match mutation {
        ActionMutation::ImageChanged => {
            let current = value
                .pointer("/allowed_change_projection/requested_image_digest")
                .and_then(Value::as_str)
                .ok_or_else(ApiError::internal)?;
            let changed = different_digest(current)?;
            value["allowed_change_projection"]["requested_image_digest"] =
                Value::String(changed.clone());
            patch["spec"]["template"]["spec"]["containers"][0]["image"] = Value::String(changed);
        }
        ActionMutation::MutableTag => {
            value["allowed_change_projection"]["requested_image_digest"] =
                Value::String("nginx:latest".into());
            patch["spec"]["template"]["spec"]["containers"][0]["image"] =
                Value::String("nginx:latest".into());
        }
        ActionMutation::Replicas(replicas) => {
            value["allowed_change_projection"]["requested_replicas"] = json!(replicas);
            patch["spec"]["replicas"] = json!(replicas);
        }
        ActionMutation::ForbiddenField => {
            patch["spec"]["template"]["spec"]["containers"][0]["securityContext"] =
                json!({"privileged": true});
        }
        ActionMutation::Namespace(namespace) => {
            value["namespace_name"] = Value::String(namespace.into());
            patch["metadata"]["namespace"] = Value::String(namespace.into());
        }
        ActionMutation::ResourceVersion(version) => {
            value["expected_resource_version"] = Value::String(version.into());
        }
    }
    let patch_bytes = canonical_json(&patch).map_err(|_| ApiError::internal())?;
    value["patch_bytes"] =
        Value::String(String::from_utf8(patch_bytes.clone()).map_err(|_| ApiError::internal())?);
    value["patch_digest"] =
        serde_json::to_value(sha256(&patch_bytes)).map_err(|_| ApiError::internal())?;
    canonical_json(&value).map_err(|_| ApiError::internal())
}

fn different_digest(value: &str) -> Result<String, ApiError> {
    let mut bytes = value.as_bytes().to_vec();
    let last = bytes.last_mut().ok_or_else(ApiError::internal)?;
    *last = if *last == b'a' { b'b' } else { b'a' };
    String::from_utf8(bytes).map_err(|_| ApiError::internal())
}

fn assert_profile_denial(bytes: &[u8]) -> Result<(), ApiError> {
    if KubernetesRolloutProfile.canonicalize(bytes).is_ok() {
        return Err(ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "unsafe-profile-acceptance",
            "the profile accepted a repository-owned forbidden mutation",
        ));
    }
    Ok(())
}

fn configuration_with_maximum(
    configuration: &KubernetesVerifierConfiguration,
    maximum: u32,
) -> Result<KubernetesVerifierConfiguration, ApiError> {
    let mut value = serde_json::to_value(configuration).map_err(|_| ApiError::internal())?;
    value["maximum_replicas"] = json!(maximum);
    serde_json::from_value(value).map_err(|_| ApiError::internal())
}

fn workflow_result(outcome: WorkflowOutcome) -> Value {
    match outcome {
        WorkflowOutcome::Rejected { receipt } => json!({
            "decision": receipt.decision,
            "required_configuration": receipt.required_configuration.digest().ok(),
            "executed_configuration": receipt.executed_configuration.digest().ok(),
            "entered_executor": false,
            "credential_requested": false,
            "kubernetes_called": false,
            "stages": [{"name": "authorized", "status": "stopped"}],
        }),
        WorkflowOutcome::Replay { record } => json!({
            "decision": {
                "class": "denied",
                "code": "already-claimed",
                "stage": "claim",
                "detail": "this exact Deployment rollout was already claimed"
            },
            "entered_executor": false,
            "credential_requested": false,
            "kubernetes_called": false,
            "claim": record,
            "stages": [
                {"name": "authorized", "status": "proven"},
                {"name": "claimed", "status": "replay-blocked"}
            ],
        }),
        WorkflowOutcome::Conflict { record } => json!({
            "decision": {
                "class": "denied",
                "code": "claim-conflict",
                "stage": "claim",
                "detail": "this workflow identifier is bound to a different action"
            },
            "entered_executor": false,
            "credential_requested": false,
            "kubernetes_called": false,
            "claim": record,
        }),
        WorkflowOutcome::Executed {
            decision,
            execution,
            result,
        } => json!({
            "decision": {
                "class": "authorized",
                "code": "authorized",
                "stage": "rollout-converged",
                "detail": "Kubernetes persisted and converged the exact authorized rollout"
            },
            "required_configuration": decision.required_configuration.digest().ok(),
            "executed_configuration": decision.executed_configuration.digest().ok(),
            "entered_executor": true,
            "credential_requested": true,
            "kubernetes_called": true,
            "api_accepted": result.api_accepted,
            "persisted_verified": result.persisted_verified,
            "rollout_converged": result.rollout_converged,
            "rollout": result,
            "execution_receipt": execution,
            "stages": [
                {"name": "authorized", "status": "proven"},
                {"name": "claimed", "status": "durable"},
                {"name": "credential", "status": "requested-after-claim"},
                {"name": "api", "status": "accepted"},
                {"name": "persisted", "status": "verified"},
                {"name": "converged", "status": "available"}
            ],
        }),
    }
}

fn denied_result(code: &str, detail: &str) -> Value {
    json!({
        "decision": {
            "class": "denied",
            "code": code,
            "stage": "profile",
            "detail": detail,
        },
        "entered_executor": false,
        "credential_requested": false,
        "kubernetes_called": false,
        "stages": [{"name": "authorized", "status": "stopped"}],
    })
}

fn random_id() -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn random_challenge() -> Result<[u8; 32], ApiError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(bytes)
}

fn unix_time() -> Result<u64, std::time::SystemTimeError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
}

struct JsonlReceiptSink {
    path: PathBuf,
    lock: StdMutex<()>,
}

impl JsonlReceiptSink {
    fn new(path: PathBuf) -> Result<Self, PortError> {
        let parent = path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        Ok(Self {
            path,
            lock: StdMutex::new(()),
        })
    }
}

impl ReceiptSink for JsonlReceiptSink {
    fn append(&self, receipt: &KubernetesReceipt) -> Result<(), PortError> {
        let _guard = self.lock.lock().map_err(|_| PortError::Persistence)?;
        let bytes = canonical_json(receipt).map_err(|_| PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_data())
            .map_err(|_| PortError::Persistence)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("invalid Kubernetes demo configuration")]
    Configuration,
    #[error("Kubernetes backend configuration failed")]
    Kubernetes,
    #[error("durable Kubernetes demo state is unavailable")]
    State,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, code: &str, message: &str) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal-error",
            "the native service failed closed",
        )
    }

    fn backend(error: BackendError) -> Self {
        let status = match error {
            BackendError::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            BackendError::Conflict | BackendError::Rejected => StatusCode::CONFLICT,
            _ => StatusCode::BAD_GATEWAY,
        };
        Self::new(status, "cluster-evidence-unavailable", &error.to_string())
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
    use axum::{body::Body, http::Request};
    use tempfile::TempDir;
    use tower::ServiceExt as _;

    use super::*;

    fn test_app() -> Router {
        let directory = TempDir::new().unwrap();
        let path = directory.keep();
        app(AppConfig::for_test(path)).unwrap()
    }

    async fn json_request(app: &Router, request: Request<Body>) -> Value {
        let response = app.clone().oneshot(request).await.unwrap();
        assert!(response.status().is_success());
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn exact_denial_replay_and_receipts_cross_the_http_boundary() {
        let app = test_app();
        let created = json_request(
            &app,
            Request::post("/api/v1/sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        let session = created["session_id"].as_str().unwrap();
        for (variant, expected_code) in [
            ("image-changed", "action-body-mismatch"),
            ("mutable-tag", "mutable-image-reference"),
            ("replicas-exceed", "replica-bound-exceeded"),
            ("forbidden-field", "change-outside-profile"),
            ("namespace-changed", "namespace-identity-mismatch"),
            ("resource-stale", "resource-version-mismatch"),
            ("configuration-changed", "verifier-configuration-mismatch"),
        ] {
            let denied = json_request(
                &app,
                Request::post(format!("/api/v1/sessions/{session}/execute"))
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(format!(r#"{{"variant":"{variant}"}}"#)))
                    .unwrap(),
            )
            .await;
            assert_eq!(denied["result"]["decision"]["code"], expected_code);
            assert_eq!(denied["result"]["credential_requested"], false);
            assert_eq!(denied["result"]["kubernetes_called"], false);
        }
        let exact = json_request(
            &app,
            Request::post(format!("/api/v1/sessions/{session}/execute"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"variant":"exact"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(exact["result"]["rollout_converged"], true);
        let replay = json_request(
            &app,
            Request::post(format!("/api/v1/sessions/{session}/execute"))
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"variant":"exact"}"#))
                .unwrap(),
        )
        .await;
        assert_eq!(replay["result"]["decision"]["code"], "already-claimed");
        let receipt = json_request(
            &app,
            Request::get(format!("/api/v1/receipts/{session}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await;
        assert_eq!(receipt["session_id"], session);
        assert!(receipt["required_configuration"].is_object());
    }
}
