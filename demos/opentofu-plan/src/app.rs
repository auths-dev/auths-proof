//! Native HTTP API for the protected `OpenTofu` planner/executor.

use std::{
    collections::HashMap,
    env,
    fs::{self, OpenOptions},
    io::Write as _,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use auths_opentofu::{
    ExecuteSavedPlanRequest, FixedClock, MemoryPlanArtifactStore, MemoryReceiptSink,
    OpenTofuLifecycleStore, OpenTofuReceipt, OpenTofuSavedPlanApplyInput, OpenTofuSavedPlanApplyV1,
    OpenTofuStateEvidenceV1, OpenTofuVerifierConfigurationInput, OpenTofuVerifierConfigurationV1,
    PermittedChangeSummaryV1, PersistentPlanArtifactStore, PlanArtifactStore, PlanHandle,
    PortError, ReceiptSink, ResourceAction, SavedPlanArtifact, SavedPlanProjectionV1,
    SavedPlanService, SdkProofVerifier, ServiceDependencies, ServiceError, WorkflowOutcome,
    canonical::{canonical_digest, canonical_json, sha256},
    reservation_scope_digest,
    test_support::Fixture,
};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::cors::CorsLayer;

use crate::{
    fixture::{DemoVariant, demo_fixture, demo_fixture_from_product},
    opentofu::{OpenTofuBackend, OpenTofuFault, committed_variables, configuration_digest},
};

const API_SCHEMA: &str = "auths-opentofu-demo-api/1";
const SESSION_TTL_SECONDS: u64 = 10 * 60;

#[derive(Clone)]
#[allow(
    clippy::large_enum_variant,
    reason = "startup configuration is cloned rarely and remains easier to audit inline"
)]
enum BackendSettings {
    Fixture,
    Live {
        program: PathBuf,
        working_directory: PathBuf,
        timeout: Duration,
        tool_build: String,
        credential_json: Vec<u8>,
        session_variable: Option<String>,
        session_workspace: bool,
        fault: OpenTofuFault,
        evidence_seed: OpenTofuStateEvidenceV1,
        source_digest: auths_opentofu::DigestHex,
    },
}

/// Explicit deployment configuration.
#[derive(Clone)]
pub struct AppConfig {
    bind: SocketAddr,
    allowed_origin: HeaderValue,
    region: String,
    release: String,
    state_directory: Arc<Path>,
    configuration: OpenTofuVerifierConfigurationV1,
    backend: BackendSettings,
}

impl AppConfig {
    pub fn from_env() -> Result<Self, StartupError> {
        let bind = env::var("AUTHS_OPENTOFU_BIND")
            .unwrap_or_else(|_| "0.0.0.0:8080".into())
            .parse()
            .map_err(|_| StartupError::Configuration)?;
        let allowed_origin = HeaderValue::from_str(
            &env::var("AUTHS_OPENTOFU_ALLOWED_ORIGIN")
                .unwrap_or_else(|_| "http://localhost:3000".into()),
        )
        .map_err(|_| StartupError::Configuration)?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("FLY_IMAGE_REF").unwrap_or_else(|_| "development".into());
        let state_directory = PathBuf::from(
            env::var("AUTHS_OPENTOFU_STATE_DIR").unwrap_or_else(|_| ".state/opentofu".into()),
        );
        let mode = env::var("AUTHS_OPENTOFU_MODE").unwrap_or_else(|_| "fixture".into());
        if mode == "fixture" {
            return Ok(Self {
                bind,
                allowed_origin,
                region,
                release,
                state_directory: state_directory.into(),
                configuration: auths_opentofu::test_support::configuration(),
                backend: BackendSettings::Fixture,
            });
        }
        if mode != "live" {
            return Err(StartupError::Configuration);
        }
        let (configuration, backend) = live_settings()?;
        Ok(Self {
            bind,
            allowed_origin,
            region,
            release,
            state_directory: state_directory.into(),
            configuration,
            backend,
        })
    }

    #[cfg(test)]
    fn for_test(state_directory: PathBuf) -> Self {
        Self {
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_origin: HeaderValue::from_static("https://demo.example"),
            region: "test".into(),
            release: "test".into(),
            state_directory: state_directory.into(),
            configuration: auths_opentofu::test_support::configuration(),
            backend: BackendSettings::Fixture,
        }
    }
}

fn live_settings() -> Result<(OpenTofuVerifierConfigurationV1, BackendSettings), StartupError> {
    let program = absolute_path("AUTHS_OPENTOFU_BINARY")?;
    let working_directory = absolute_path("AUTHS_OPENTOFU_WORKING_DIRECTORY")?;
    let workspace = required_env("AUTHS_OPENTOFU_WORKSPACE")?;
    let backend_identity = required_env("AUTHS_OPENTOFU_BACKEND_IDENTITY")?;
    let executor_audience = required_env("AUTHS_OPENTOFU_EXECUTOR_AUDIENCE")?;
    let opentofu_version = required_env("AUTHS_OPENTOFU_VERSION")?;
    let provider_sources = csv("AUTHS_OPENTOFU_PROVIDER_SOURCES")?;
    let resource_types = csv("AUTHS_OPENTOFU_RESOURCE_TYPES")?;
    let configuration = OpenTofuVerifierConfigurationV1::new(OpenTofuVerifierConfigurationInput {
        allowed_opentofu_versions: vec![opentofu_version],
        allowed_backend_identities: vec![backend_identity.clone()],
        allowed_workspaces: vec![workspace.clone()],
        allowed_provider_sources: provider_sources,
        allowed_resource_types: resource_types,
        allowed_actions: vec![ResourceAction::Create, ResourceAction::Update],
        maximum_resource_changes: parse_env("AUTHS_OPENTOFU_MAX_CHANGES")?,
        maximum_plan_age_seconds: parse_env("AUTHS_OPENTOFU_MAX_PLAN_AGE_SECONDS")?,
        maximum_authorization_lifetime_seconds: parse_env(
            "AUTHS_OPENTOFU_MAX_AUTHORIZATION_SECONDS",
        )?,
        allow_sensitive_outputs: false,
        allow_destroy: false,
        allow_replacement: false,
        receipt_schema_version: "auths.opentofu.decision-receipt/1".into(),
        executor_audience,
    })
    .map_err(|_| StartupError::Configuration)?;
    let dependency_lock = fs::read(working_directory.join(".terraform.lock.hcl"))
        .map_err(|_| StartupError::Configuration)?;
    let module_manifest = required_env("AUTHS_OPENTOFU_MODULE_MANIFEST")?;
    let credential_json = required_env("AUTHS_OPENTOFU_CREDENTIAL_JSON")?.into_bytes();
    committed_variables(&credential_json).map_err(|_| StartupError::Configuration)?;
    let session_variable = env::var("AUTHS_OPENTOFU_SESSION_VARIABLE")
        .ok()
        .filter(|value| !value.trim().is_empty());
    if session_variable.as_deref().is_some_and(|name| {
        !name.starts_with("TF_VAR_")
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    }) {
        return Err(StartupError::Configuration);
    }
    let session_workspace =
        env::var("AUTHS_OPENTOFU_SESSION_WORKSPACE").map_or(Ok(false), |value| {
            value
                .parse::<bool>()
                .map_err(|_| StartupError::Configuration)
        })?;
    let fault = configured_fault()?;
    let source_digest =
        configuration_digest(&working_directory).map_err(|_| StartupError::Configuration)?;
    let evidence_seed = OpenTofuStateEvidenceV1 {
        backend_identity,
        workspace,
        state_lineage: "pending-protected-read".into(),
        state_serial: 0,
        state_digest: sha256(b"pending-protected-read"),
        lock_held: false,
        dependency_lock_digest: sha256(&dependency_lock),
        module_manifest_digest: sha256(module_manifest.as_bytes()),
        planner_build_identity: required_env("AUTHS_OPENTOFU_PLANNER_BUILD")?,
        observed_at: 0,
    };
    let backend = BackendSettings::Live {
        program,
        working_directory,
        timeout: Duration::from_secs(parse_env("AUTHS_OPENTOFU_TIMEOUT_SECONDS")?),
        tool_build: required_env("AUTHS_OPENTOFU_TOOL_BUILD")?,
        credential_json,
        session_variable,
        session_workspace,
        fault,
        evidence_seed,
        source_digest,
    };
    Ok((configuration, backend))
}

fn configured_fault() -> Result<OpenTofuFault, StartupError> {
    match env::var("AUTHS_OPENTOFU_FAULT")
        .unwrap_or_else(|_| "none".into())
        .as_str()
    {
        "none" => Ok(OpenTofuFault::None),
        "before-apply" => Ok(OpenTofuFault::BeforeApply),
        "after-apply-unknown" => Ok(OpenTofuFault::AfterApplyUnknown),
        "after-apply-unreconciled" => Ok(OpenTofuFault::AfterApplyUnreconciled),
        _ => Err(StartupError::Configuration),
    }
}

#[derive(Clone)]
struct AppState {
    config: AppConfig,
    lifecycles: Arc<OpenTofuLifecycleRegistry>,
    artifacts: Arc<dyn PlanArtifactStore>,
    durable_receipts: Arc<dyn ReceiptSink>,
    sessions: Arc<Mutex<HashMap<String, Session>>>,
}

struct DemoOpenTofuLifecycleStore {
    inner: auths_stores::PersistentLifecycleStore,
}

impl auths_lifecycle::LifecycleStore for DemoOpenTofuLifecycleStore {
    fn transact(
        &self,
        transaction: &auths_lifecycle::StoreTransactionV1,
    ) -> Result<auths_lifecycle::StoredTransitionV1, auths_lifecycle::StoreError> {
        self.inner.transact(transaction)
    }
}

impl OpenTofuLifecycleStore for DemoOpenTofuLifecycleStore {
    fn load_opentofu_lifecycle(
        &self,
        workflow: &auths_lifecycle::WorkflowId,
    ) -> Result<Option<auths_lifecycle::LifecycleRecordV1>, auths_lifecycle::StoreError> {
        self.inner.load(workflow)
    }
}

struct OpenTofuLifecycleRegistry {
    directory: PathBuf,
    stores: Mutex<HashMap<String, Arc<DemoOpenTofuLifecycleStore>>>,
}

impl OpenTofuLifecycleRegistry {
    fn new(directory: PathBuf) -> Result<Self, StartupError> {
        fs::create_dir_all(&directory).map_err(|_| StartupError::State)?;
        Ok(Self {
            directory,
            stores: Mutex::new(HashMap::new()),
        })
    }

    fn for_action(
        &self,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Result<Arc<DemoOpenTofuLifecycleStore>, PortError> {
        let scope = reservation_scope_digest(action).map_err(|_| PortError::Persistence)?;
        let scope_hex = hex::encode(scope.as_bytes());
        let mut stores = self.stores.lock().map_err(|_| PortError::Persistence)?;
        if let Some(store) = stores.get(&scope_hex) {
            return Ok(Arc::clone(store));
        }
        let store = Arc::new(DemoOpenTofuLifecycleStore {
            inner: auths_stores::PersistentLifecycleStore::open(
                self.directory.join(format!("{scope_hex}.lifecycle")),
                vec![auths_stores::LifecycleCapacityRuleV1::Exclusive {
                    scope_digest: scope,
                    window_digest: None,
                    retain_after_commit: false,
                }],
                4096,
            )
            .map_err(|_| PortError::Persistence)?,
        });
        stores.insert(scope_hex, Arc::clone(&store));
        Ok(store)
    }
}

struct Session {
    created_at: u64,
    expires_at: u64,
    challenge: [u8; 32],
    product: Fixture,
    variants: Vec<DemoVariant>,
    proof_verifier: Arc<SdkProofVerifier>,
    proof: Vec<u8>,
    auths_request: auths_sdk::RequestContext,
    backend: Arc<OpenTofuBackend>,
    artifacts: Arc<dyn PlanArtifactStore>,
    receipts: Arc<MemoryReceiptSink>,
    last_result: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedSession {
    schema: String,
    session_id: String,
    created_at: u64,
    expires_at: u64,
    challenge: [u8; 32],
    action: OpenTofuSavedPlanApplyV1,
    projection: SavedPlanProjectionV1,
    evidence: OpenTofuStateEvidenceV1,
    configuration: OpenTofuVerifierConfigurationV1,
    last_result: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the production API router.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    fs::create_dir_all(config.state_directory.as_ref()).map_err(|_| StartupError::State)?;
    if config.state_directory.join("claims.json").exists() {
        return Err(StartupError::State);
    }
    let lifecycles = Arc::new(OpenTofuLifecycleRegistry::new(
        config.state_directory.join("lifecycle"),
    )?);
    let artifacts: Arc<dyn PlanArtifactStore> =
        if matches!(config.backend, BackendSettings::Fixture) {
            Arc::new(MemoryPlanArtifactStore::default())
        } else {
            Arc::new(
                PersistentPlanArtifactStore::open(config.state_directory.join("saved-plans"))
                    .map_err(|_| StartupError::State)?,
            )
        };
    let durable_receipts = Arc::new(
        JsonlReceiptSink::new(config.state_directory.join("receipts.jsonl"))
            .map_err(|_| StartupError::State)?,
    );
    let sessions = restore_sessions(&config, &artifacts)?;
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route("/build", get(build))
        .route("/api/v1/scenarios", get(scenarios))
        .route("/api/v1/credential-probe", get(credential_probe))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .route("/api/v1/receipts/{session_id}", get(receipt))
        .with_state(AppState {
            config,
            lifecycles,
            artifacts,
            durable_receipts,
            sessions: Arc::new(Mutex::new(sessions)),
        })
        .layer(cors))
}

/// Serves until shutdown.
pub async fn serve(config: AppConfig) -> Result<(), StartupError> {
    let bind = config.bind;
    let router = app(config)?;
    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .map_err(|_| StartupError::Bind)?;
    axum::serve(listener, router)
        .await
        .map_err(|_| StartupError::Serve)
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
    if let BackendSettings::Live {
        program,
        working_directory,
        timeout,
        tool_build,
        credential_json,
        session_variable: _,
        session_workspace: _,
        fault: _,
        evidence_seed,
        source_digest,
    } = &state.config.backend
    {
        let variable_commitment = committed_variables(credential_json).map_err(ApiError::port)?;
        let backend = OpenTofuBackend::cli(
            program.clone(),
            working_directory.clone(),
            *timeout,
            tool_build.clone(),
            evidence_seed.clone(),
            credential_json.clone(),
            source_digest.clone(),
            variable_commitment,
        )
        .map_err(ApiError::port)?;
        tokio::task::spawn_blocking(move || backend.readiness())
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(ApiError::port)?;
    }
    Ok(Json(json!({
        "status": "ready",
        "schema": API_SCHEMA,
        "planner": backend_label(&state.config.backend),
        "credential_boundary": "native-executor-only",
    })))
}

async fn build(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "profile": "auths.opentofu.saved-plan-apply/1",
    }))
}

async fn scenarios(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "release": state.config.release,
        "region": state.config.region,
        "planner": backend_label(&state.config.backend),
        "variants": [
            {"id": "exact", "label": "Exact saved plan"},
            {"id": "swapped-plan", "label": "Saved plan substituted"},
            {"id": "source-changed", "label": "Source configuration changed"},
            {"id": "workspace-changed", "label": "Workspace changed"},
            {"id": "backend-changed", "label": "Backend changed"},
            {"id": "stale-state", "label": "State advanced"},
            {"id": "state-lock-held", "label": "State lock unavailable"},
            {"id": "destroy-added", "label": "Destroy added"},
            {"id": "dependency-changed", "label": "Provider lock changed"},
            {"id": "expired-plan", "label": "Plan expired"},
            {"id": "configuration-changed", "label": "Verifier policy changed"}
        ]
    }))
}

async fn credential_probe() -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "credential_access": "denied",
        "backend_credential_exposed": false,
        "provider_credential_exposed": false,
        "credential_provider_called": false,
        "detail": "the public API has no operation that returns or delegates protected credentials"
    }))
}

#[allow(
    clippy::too_many_lines,
    reason = "protected plan construction remains visible in one ordered function"
)]
async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let session_id = random_id()?;
    let challenge = random_challenge()?;
    let artifacts = Arc::clone(&state.artifacts);
    let (demo, backend) = match &state.config.backend {
        BackendSettings::Fixture => {
            let demo = demo_fixture(now, challenge);
            let handle = artifacts
                .put(SavedPlanArtifact::new(
                    auths_opentofu::test_support::PLAN_BYTES.to_vec(),
                )?)
                .map_err(ApiError::port)?;
            if &handle != demo.product.action.plan_handle() {
                return Err(ApiError::internal());
            }
            let backend = OpenTofuBackend::fixture(demo.product.evidence.clone());
            (demo, backend)
        }
        BackendSettings::Live {
            program,
            working_directory,
            timeout,
            tool_build,
            credential_json,
            session_variable,
            session_workspace,
            fault,
            evidence_seed,
            source_digest,
        } => {
            let workspace = if *session_workspace {
                format!("auths-{}", &session_id[..16])
            } else {
                evidence_seed.workspace.clone()
            };
            let session_configuration =
                configuration_for_workspace(&state.config.configuration, &workspace)?;
            let session_evidence = OpenTofuStateEvidenceV1 {
                workspace,
                ..evidence_seed.clone()
            };
            let credential_json =
                session_credential_json(credential_json, session_variable.as_deref(), &session_id)?;
            let variable_commitment =
                committed_variables(&credential_json).map_err(ApiError::port)?;
            let backend = OpenTofuBackend::cli(
                program.clone(),
                working_directory.clone(),
                *timeout,
                tool_build.clone(),
                session_evidence,
                credential_json.clone(),
                source_digest.clone(),
                variable_commitment.clone(),
            )
            .map_err(ApiError::port)?;
            let prepared = tokio::task::spawn_blocking({
                let backend = backend.clone();
                move || backend.prepare_live(now)
            })
            .await
            .map_err(|_| ApiError::internal())?
            .map_err(ApiError::port)?;
            // Protected planning replaced the startup seed with fresh backend
            // lineage, serial, and digest. The execution adapter must bind to
            // those exact observations.
            let backend = OpenTofuBackend::cli(
                program.clone(),
                working_directory.clone(),
                *timeout,
                tool_build.clone(),
                prepared.evidence.clone(),
                credential_json,
                source_digest.clone(),
                variable_commitment.clone(),
            )
            .map_err(ApiError::port)?;
            backend.set_fault(*fault);
            let projection =
                SavedPlanProjectionV1::from_show_json(&prepared.show_json, &session_configuration)
                    .map_err(|_| ApiError::internal())?;
            let plan_digest = sha256(&prepared.saved_plan_bytes);
            let plan_handle = artifacts
                .put(SavedPlanArtifact::new(prepared.saved_plan_bytes)?)
                .map_err(ApiError::port)?;
            let action = OpenTofuSavedPlanApplyV1::new(OpenTofuSavedPlanApplyInput {
                executor_audience: session_configuration.executor_audience().into(),
                opentofu_version: prepared.opentofu_version,
                platform: prepared.platform,
                backend_identity: prepared.evidence.backend_identity.clone(),
                workspace: prepared.evidence.workspace.clone(),
                state_lineage: prepared.evidence.state_lineage.clone(),
                state_serial: prepared.evidence.state_serial,
                state_digest: prepared.evidence.state_digest.clone(),
                configuration_bundle_digest: source_digest.clone(),
                variable_commitment: variable_commitment.clone(),
                dependency_lock_digest: prepared.evidence.dependency_lock_digest.clone(),
                module_manifest_digest: prepared.evidence.module_manifest_digest.clone(),
                opaque_plan_digest: plan_digest,
                plan_projection_digest: projection.digest().map_err(|_| ApiError::internal())?,
                plan_handle,
                permitted_change_summary: summarize(&projection),
                required_configuration: session_configuration.clone(),
                planned_at: now,
                expires_at: now
                    + state
                        .config
                        .configuration
                        .maximum_authorization_lifetime_seconds(),
                nonce: sha256(&challenge),
            })
            .map_err(|_| ApiError::internal())?;
            let product = Fixture {
                action,
                projection,
                evidence: prepared.evidence,
                configuration: session_configuration,
            };
            (demo_fixture_from_product(product, now, challenge), backend)
        }
    };
    let response = session_response(
        &session_id,
        now + SESSION_TTL_SECONDS,
        backend.mode(),
        &demo.variants,
        &demo.product,
    );
    let product = Fixture {
        action: demo.product.action.clone(),
        projection: demo.product.projection.clone(),
        evidence: demo.product.evidence.clone(),
        configuration: demo.product.configuration.clone(),
    };
    let session = Session {
        created_at: now,
        expires_at: now + SESSION_TTL_SECONDS,
        challenge,
        product,
        variants: demo.variants,
        proof_verifier: Arc::new(SdkProofVerifier::new(demo.auths.verifier)),
        proof: demo.auths.proof,
        auths_request: demo.auths.request,
        backend: Arc::new(backend),
        artifacts,
        receipts: Arc::new(MemoryReceiptSink::default()),
        last_result: None,
    };
    persist_session(&state.config, &session_id, &session)?;
    state
        .sessions
        .lock()
        .map_err(|_| ApiError::internal())?
        .insert(session_id, session);
    Ok(Json(response))
}

#[allow(
    clippy::too_many_lines,
    reason = "security-relevant verify-to-receipt ordering remains linear"
)]
async fn execute(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time()?;
    let (
        variant,
        verifier,
        proof,
        auths_request,
        backend,
        artifacts,
        receipts,
        before_credentials,
        before_applies,
    ) = {
        let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
        let session = sessions.get(&session_id).ok_or_else(ApiError::not_found)?;
        if now > session.expires_at {
            return Err(ApiError::expired());
        }
        let variant = session
            .variants
            .iter()
            .find(|variant| variant.id == request.variant)
            .cloned()
            .ok_or_else(ApiError::bad_variant)?;
        (
            variant,
            Arc::clone(&session.proof_verifier),
            session.proof.clone(),
            session.auths_request.clone(),
            Arc::clone(&session.backend),
            Arc::clone(&session.artifacts),
            Arc::clone(&session.receipts),
            session.backend.credential_calls(),
            session.backend.apply_calls(),
        )
    };
    let corrupt = variant.id == "swapped-plan";
    let action_digest = variant.action.digest().map_err(|_| ApiError::internal())?;
    let evidence_digest = canonical_digest(&variant.evidence).map_err(|_| ApiError::internal())?;
    let projection_digest = variant
        .projection
        .digest()
        .map_err(|_| ApiError::internal())?;
    let opaque_plan_digest = variant.action.opaque_plan_digest().clone();
    let artifact_store = RequestArtifactStore { artifacts, corrupt };
    let lifecycle_store = state
        .lifecycles
        .for_action(&variant.action)
        .map_err(ApiError::port)?;
    let service = SavedPlanService::new(ServiceDependencies {
        proof_verifier: verifier,
        artifact_store,
        credential_provider: Arc::clone(&backend),
        opentofu_gateway: Arc::clone(&backend),
        lifecycle_store,
        receipt_sink: DemoReceiptSink {
            memory: Arc::clone(&receipts),
            durable: Arc::clone(&state.durable_receipts),
        },
        clock: FixedClock(now),
        executed_configuration: variant.executed_configuration.clone(),
    });
    let outcome = service.execute(ExecuteSavedPlanRequest {
        action: variant.action,
        projection: variant.projection,
        evidence: variant.evidence,
        required_configuration: variant.required_configuration,
        proof,
        auths_request,
    });
    let credential_called = backend.credential_calls() > before_credentials;
    let opentofu_called = backend.apply_calls() > before_applies;
    let result = match outcome {
        Ok(outcome) => workflow_json(outcome, credential_called, opentofu_called),
        Err(ServiceError::Port(PortError::ArtifactMismatch)) => json!({
            "decision": {
                "class": "denied",
                "code": "plan-artifact-mismatch",
                "stage": "protected-artifact",
                "detail": "resolved saved-plan bytes differ from the authorized digest"
            },
            "credential_called": credential_called,
            "opentofu_called": opentofu_called,
            "stages": [
                {"name": "authorized", "status": "verified"},
                {"name": "claimed", "status": "claimed"},
                {"name": "artifact", "status": "stopped"}
            ]
        }),
        Err(error) => return Err(ApiError::service(&error)),
    };
    let receipt_payload = json!({
        "schema": "auths-opentofu-demo-receipt/1",
        "session_id": session_id,
        "action_digest": action_digest,
        "evidence_digest": evidence_digest,
        "plan_projection_digest": projection_digest,
        "opaque_plan_digest": opaque_plan_digest,
        "credential_boundary": {
            "agent_has_backend_credential": false,
            "agent_has_provider_credential": false,
            "credential_requested_during_execution": credential_called
        },
        "result": result,
        "receipts": receipts.receipts(),
    });
    {
        let mut sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(ApiError::not_found)?;
        session.last_result = Some(receipt_payload);
        persist_session(&state.config, &session_id, session)?;
    }
    Ok(Json(json!({"schema": API_SCHEMA, "result": result})))
}

async fn receipt(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> Result<Json<Value>, ApiError> {
    if !valid_session_id(&session_id) {
        return Err(ApiError::not_found());
    }
    let sessions = state.sessions.lock().map_err(|_| ApiError::internal())?;
    let receipt = sessions
        .get(&session_id)
        .and_then(|session| session.last_result.clone())
        .ok_or_else(ApiError::not_found)?;
    Ok(Json(receipt))
}

#[derive(Clone)]
struct RequestArtifactStore {
    artifacts: Arc<dyn PlanArtifactStore>,
    corrupt: bool,
}

struct DemoReceiptSink {
    memory: Arc<MemoryReceiptSink>,
    durable: Arc<dyn ReceiptSink>,
}

impl ReceiptSink for DemoReceiptSink {
    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), PortError> {
        self.durable.append(receipt)?;
        self.memory.append(receipt)
    }
}

impl PlanArtifactStore for RequestArtifactStore {
    fn put(&self, artifact: SavedPlanArtifact) -> Result<PlanHandle, PortError> {
        self.artifacts.put(artifact)
    }

    fn resolve(&self, handle: &PlanHandle) -> Result<SavedPlanArtifact, PortError> {
        if self.corrupt {
            let artifact = self.artifacts.resolve(handle)?;
            let mut bytes = artifact.bytes().to_vec();
            let first = bytes.first_mut().ok_or(PortError::ArtifactMismatch)?;
            *first ^= 0x01;
            return SavedPlanArtifact::new(bytes);
        }
        self.artifacts.resolve(handle)
    }
}

fn workflow_json(
    outcome: WorkflowOutcome,
    credential_called: bool,
    opentofu_called: bool,
) -> Value {
    match outcome {
        WorkflowOutcome::Rejected { receipt } => json!({
            "decision": receipt.decision,
            "required_configuration": receipt.required_configuration.digest().ok(),
            "executed_configuration": receipt.executed_configuration.digest().ok(),
            "credential_called": credential_called,
            "opentofu_called": opentofu_called,
            "stages": [{"name": "authorized", "status": "stopped"}],
        }),
        WorkflowOutcome::Replay { record } | WorkflowOutcome::Conflict { record } => json!({
            "decision": {
                "class": "denied",
                "code": "already-claimed",
                "stage": "claim",
                "detail": "the exact saved-plan action already has a durable claim"
            },
            "claim": record,
            "credential_called": credential_called,
            "opentofu_called": opentofu_called,
            "stages": [
                {"name": "authorized", "status": "verified"},
                {"name": "claimed", "status": "replay-blocked"}
            ],
        }),
        WorkflowOutcome::OutcomeUnknown { record } => json!({
            "decision": {
                "class": "indeterminate",
                "code": "execution-outcome-unknown",
                "stage": "reconciliation",
                "detail": "the apply may have committed and requires observation before any retry"
            },
            "claim": record,
            "credential_called": credential_called,
            "opentofu_called": opentofu_called,
            "stages": [
                {"name": "authorized", "status": "verified"},
                {"name": "claimed", "status": "claimed"},
                {"name": "apply", "status": "outcome-unknown"},
                {"name": "observed", "status": "pending"}
            ],
        }),
        WorkflowOutcome::Executed {
            decision,
            apply,
            observation,
            result,
        } => json!({
            "decision": decision.decision,
            "required_configuration": decision.required_configuration.digest().ok(),
            "executed_configuration": decision.executed_configuration.digest().ok(),
            "credential_called": credential_called,
            "opentofu_called": opentofu_called,
            "apply": apply,
            "observation": observation,
            "resulting_state": result,
            "stages": [
                {"name": "authorized", "status": "verified"},
                {"name": "claimed", "status": "claimed"},
                {"name": "artifact", "status": "verified"},
                {"name": "credential", "status": "acquired"},
                {"name": "state", "status": "rechecked"},
                {"name": "apply", "status": "committed"},
                {"name": "observed", "status": "converged"}
            ],
        }),
    }
}

fn session_response(
    session_id: &str,
    expires_at: u64,
    mode: &str,
    variants: &[DemoVariant],
    fixture: &Fixture,
) -> Value {
    json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": expires_at,
        "planner_mode": mode,
        "profile": "auths.opentofu.saved-plan-apply/1",
        "agent_has_backend_credential": false,
        "agent_has_provider_credential": false,
        "target": {
            "backend": fixture.action.backend_identity(),
            "workspace": fixture.action.workspace(),
            "state_lineage": fixture.action.state_lineage(),
            "state_serial": fixture.action.state_serial(),
            "saved_plan_digest": fixture.action.opaque_plan_digest(),
            "plan_projection_digest": fixture.action.plan_projection_digest(),
            "resource_changes": fixture.action.permitted_change_summary().total(),
        },
        "variants": variants,
    })
}

fn summarize(projection: &SavedPlanProjectionV1) -> PermittedChangeSummaryV1 {
    let mut summary = PermittedChangeSummaryV1 {
        creates: 0,
        updates: 0,
        reads: 0,
        no_ops: 0,
    };
    for action in projection
        .resource_changes
        .iter()
        .flat_map(|change| &change.actions)
    {
        match action {
            ResourceAction::Create => summary.creates += 1,
            ResourceAction::Update => summary.updates += 1,
            ResourceAction::Read => summary.reads += 1,
            ResourceAction::NoOp => summary.no_ops += 1,
            ResourceAction::Delete => {}
        }
    }
    summary
}

fn backend_label(settings: &BackendSettings) -> &'static str {
    match settings {
        BackendSettings::Fixture => "deterministic-fixture",
        BackendSettings::Live { .. } => "live-opentofu",
    }
}

fn unix_time() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ApiError::internal())
}

fn random_id() -> Result<String, ApiError> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(hex::encode(bytes))
}

fn random_challenge() -> Result<[u8; 32], ApiError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| ApiError::internal())?;
    Ok(bytes)
}

fn valid_session_id(value: &str) -> bool {
    value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn required_env(name: &str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(StartupError::Configuration)
}

fn absolute_path(name: &str) -> Result<PathBuf, StartupError> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute() {
        return Err(StartupError::Configuration);
    }
    Ok(path)
}

fn csv(name: &str) -> Result<Vec<String>, StartupError> {
    let values = required_env(name)?
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(StartupError::Configuration);
    }
    Ok(values)
}

fn parse_env<T: std::str::FromStr>(name: &str) -> Result<T, StartupError> {
    required_env(name)?
        .parse()
        .map_err(|_| StartupError::Configuration)
}

fn session_credential_json(
    base: &[u8],
    session_variable: Option<&str>,
    session_id: &str,
) -> Result<Vec<u8>, ApiError> {
    let mut environment: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(base).map_err(|_| ApiError::internal())?;
    if let Some(name) = session_variable {
        environment.insert(name.to_owned(), format!("session-{session_id}"));
    }
    canonical_json(&environment).map_err(|_| ApiError::internal())
}

fn restore_sessions(
    config: &AppConfig,
    artifacts: &Arc<dyn PlanArtifactStore>,
) -> Result<HashMap<String, Session>, StartupError> {
    if matches!(config.backend, BackendSettings::Fixture) {
        return Ok(HashMap::new());
    }
    let directory = config.state_directory.join("sessions");
    fs::create_dir_all(&directory).map_err(|_| StartupError::State)?;
    let mut paths = fs::read_dir(&directory)
        .map_err(|_| StartupError::State)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut sessions = HashMap::new();
    for path in paths {
        let bytes = fs::read(&path).map_err(|_| StartupError::State)?;
        let persisted: PersistedSession =
            serde_json::from_slice(&bytes).map_err(|_| StartupError::State)?;
        if canonical_json(&persisted).map_err(|_| StartupError::State)? != bytes
            || !valid_session_id(&persisted.session_id)
            || path.file_stem().and_then(|value| value.to_str())
                != Some(persisted.session_id.as_str())
        {
            return Err(StartupError::State);
        }
        let product = Fixture {
            action: persisted.action,
            projection: persisted.projection,
            evidence: persisted.evidence,
            configuration: persisted.configuration,
        };
        let demo = demo_fixture_from_product(
            Fixture {
                action: product.action.clone(),
                projection: product.projection.clone(),
                evidence: product.evidence.clone(),
                configuration: product.configuration.clone(),
            },
            persisted.created_at,
            persisted.challenge,
        );
        let backend = restore_backend(config, &persisted.session_id, &product.evidence)?;
        sessions.insert(
            persisted.session_id,
            Session {
                created_at: persisted.created_at,
                expires_at: persisted.expires_at,
                challenge: persisted.challenge,
                product,
                variants: demo.variants,
                proof_verifier: Arc::new(SdkProofVerifier::new(demo.auths.verifier)),
                proof: demo.auths.proof,
                auths_request: demo.auths.request,
                backend: Arc::new(backend),
                artifacts: Arc::clone(artifacts),
                receipts: Arc::new(MemoryReceiptSink::default()),
                last_result: persisted.last_result,
            },
        );
    }
    Ok(sessions)
}

fn restore_backend(
    config: &AppConfig,
    session_id: &str,
    evidence: &OpenTofuStateEvidenceV1,
) -> Result<OpenTofuBackend, StartupError> {
    let BackendSettings::Live {
        program,
        working_directory,
        timeout,
        tool_build,
        credential_json,
        session_variable,
        session_workspace: _,
        fault,
        source_digest,
        ..
    } = &config.backend
    else {
        return Err(StartupError::State);
    };
    let credential_json =
        session_credential_json(credential_json, session_variable.as_deref(), session_id)
            .map_err(|_| StartupError::State)?;
    let variable_commitment =
        committed_variables(&credential_json).map_err(|_| StartupError::State)?;
    let backend = OpenTofuBackend::cli(
        program.clone(),
        working_directory.clone(),
        *timeout,
        tool_build.clone(),
        evidence.clone(),
        credential_json,
        source_digest.clone(),
        variable_commitment,
    )
    .map_err(|_| StartupError::State)?;
    backend.set_fault(*fault);
    Ok(backend)
}

fn configuration_for_workspace(
    base: &OpenTofuVerifierConfigurationV1,
    workspace: &str,
) -> Result<OpenTofuVerifierConfigurationV1, ApiError> {
    OpenTofuVerifierConfigurationV1::new(OpenTofuVerifierConfigurationInput {
        allowed_opentofu_versions: base.allowed_opentofu_versions().to_vec(),
        allowed_backend_identities: base.allowed_backend_identities().to_vec(),
        allowed_workspaces: vec![workspace.to_owned()],
        allowed_provider_sources: base.allowed_provider_sources().to_vec(),
        allowed_resource_types: base.allowed_resource_types().to_vec(),
        allowed_actions: base.allowed_actions().to_vec(),
        maximum_resource_changes: base.maximum_resource_changes(),
        maximum_plan_age_seconds: base.maximum_plan_age_seconds(),
        maximum_authorization_lifetime_seconds: base.maximum_authorization_lifetime_seconds(),
        allow_sensitive_outputs: base.allow_sensitive_outputs(),
        allow_destroy: false,
        allow_replacement: false,
        receipt_schema_version: base.receipt_schema_version().into(),
        executor_audience: base.executor_audience().into(),
    })
    .map_err(|_| ApiError::internal())
}

fn persist_session(
    config: &AppConfig,
    session_id: &str,
    session: &Session,
) -> Result<(), ApiError> {
    if matches!(config.backend, BackendSettings::Fixture) {
        return Ok(());
    }
    let directory = config.state_directory.join("sessions");
    fs::create_dir_all(&directory).map_err(|_| ApiError::internal())?;
    let persisted = PersistedSession {
        schema: "auths-opentofu-demo-session/1".into(),
        session_id: session_id.into(),
        created_at: session.created_at,
        expires_at: session.expires_at,
        challenge: session.challenge,
        action: session.product.action.clone(),
        projection: session.product.projection.clone(),
        evidence: session.product.evidence.clone(),
        configuration: session.product.configuration.clone(),
        last_result: session.last_result.clone(),
    };
    let bytes = canonical_json(&persisted).map_err(|_| ApiError::internal())?;
    let mut temporary =
        tempfile::NamedTempFile::new_in(&directory).map_err(|_| ApiError::internal())?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| ApiError::internal())?;
    temporary
        .persist(directory.join(format!("{session_id}.json")))
        .map_err(|_| ApiError::internal())?;
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("OpenTofu demo configuration is incomplete")]
    Configuration,
    #[error("OpenTofu demo could not bind its listener")]
    Bind,
    #[error("OpenTofu demo server failed")]
    Serve,
    #[error("durable OpenTofu demo state is unavailable")]
    State,
}

struct JsonlReceiptSink {
    path: PathBuf,
    lock: Mutex<()>,
}

impl JsonlReceiptSink {
    fn new(path: PathBuf) -> Result<Self, PortError> {
        let parent = path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        Ok(Self {
            path,
            lock: Mutex::new(()),
        })
    }
}

impl ReceiptSink for JsonlReceiptSink {
    fn append(&self, receipt: &OpenTofuReceipt) -> Result<(), PortError> {
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

struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ApiError {
    fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal-error",
            message: "the native service failed closed".into(),
        }
    }
    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "receipt-not-found",
            message: "no verified receipt exists for this identifier".into(),
        }
    }
    fn expired() -> Self {
        Self {
            status: StatusCode::GONE,
            code: "session-expired",
            message: "the short-lived authorization session expired".into(),
        }
    }
    fn bad_variant() -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "unknown-experiment",
            message: "the requested experiment is not defined".into(),
        }
    }
    fn port(error: PortError) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "protected-boundary-unavailable",
            message: error.to_string(),
        }
    }
    fn service(error: &ServiceError) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "execution-failed",
            message: error.to_string(),
        }
    }
}

impl From<PortError> for ApiError {
    fn from(error: PortError) -> Self {
        Self::port(error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error": {"code": self.code, "message": self.message}})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use std::{sync::Barrier, thread};

    use axum::body::{Body, to_bytes};
    use tower::ServiceExt as _;

    use super::*;

    fn demo_with_nonce(nonce_byte: u8) -> crate::fixture::DemoFixture {
        let mut product = auths_opentofu::test_support::fixture();
        let mut action = serde_json::to_value(&product.action).unwrap();
        action["nonce"] = Value::String(format!("{nonce_byte:02x}").repeat(32));
        product.action = serde_json::from_value(action).unwrap();
        product.action.validate().unwrap();
        demo_fixture_from_product(product, auths_opentofu::test_support::NOW, [nonce_byte; 32])
    }

    fn fixture_lifecycle_store(
        path: &Path,
        action: &OpenTofuSavedPlanApplyV1,
    ) -> Arc<DemoOpenTofuLifecycleStore> {
        let scope = reservation_scope_digest(action).unwrap();
        Arc::new(DemoOpenTofuLifecycleStore {
            inner: auths_stores::PersistentLifecycleStore::open(
                path,
                vec![auths_stores::LifecycleCapacityRuleV1::Exclusive {
                    scope_digest: scope,
                    window_digest: None,
                    retain_after_commit: false,
                }],
                32,
            )
            .unwrap(),
        })
    }

    fn execute_fixture_workflow(
        lifecycle_store: Arc<DemoOpenTofuLifecycleStore>,
        artifacts: MemoryPlanArtifactStore,
        backend: Arc<OpenTofuBackend>,
        nonce_byte: u8,
    ) -> Result<WorkflowOutcome, ServiceError> {
        let demo = demo_with_nonce(nonce_byte);
        let handle = artifacts
            .put(SavedPlanArtifact::new(auths_opentofu::test_support::PLAN_BYTES.to_vec()).unwrap())
            .unwrap();
        assert_eq!(&handle, demo.product.action.plan_handle());
        SavedPlanService::new(ServiceDependencies {
            proof_verifier: SdkProofVerifier::new(demo.auths.verifier),
            artifact_store: artifacts,
            credential_provider: Arc::clone(&backend),
            opentofu_gateway: backend,
            lifecycle_store,
            receipt_sink: MemoryReceiptSink::default(),
            clock: FixedClock(auths_opentofu::test_support::NOW),
            executed_configuration: demo.product.configuration.clone(),
        })
        .execute(ExecuteSavedPlanRequest {
            action: demo.product.action,
            projection: demo.product.projection,
            evidence: demo.product.evidence,
            required_configuration: demo.product.configuration,
            proof: demo.auths.proof,
            auths_request: demo.auths.request,
        })
    }

    async fn request(
        router: &Router,
        method: Method,
        uri: &str,
        body: Value,
    ) -> (StatusCode, Value) {
        let response = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method(method)
                    .uri(uri)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap())
    }

    #[tokio::test]
    async fn exact_denial_replay_and_receipts_cross_the_http_boundary() {
        let state = tempfile::tempdir().unwrap();
        let router = app(AppConfig::for_test(state.path().to_path_buf())).unwrap();
        let (status, created) = request(&router, Method::POST, "/api/v1/sessions", json!({})).await;
        assert_eq!(status, StatusCode::OK);
        let session = created["session_id"].as_str().unwrap();

        let (_, exact) = request(
            &router,
            Method::POST,
            &format!("/api/v1/sessions/{session}/execute"),
            json!({"variant": "exact"}),
        )
        .await;
        assert_eq!(exact["result"]["decision"]["code"], "authorized");
        assert_eq!(exact["result"]["opentofu_called"], true);

        let (_, replay) = request(
            &router,
            Method::POST,
            &format!("/api/v1/sessions/{session}/execute"),
            json!({"variant": "exact"}),
        )
        .await;
        assert_eq!(replay["result"]["decision"]["code"], "already-claimed");
        assert_eq!(replay["result"]["opentofu_called"], false);

        let (_, receipt) = request(
            &router,
            Method::GET,
            &format!("/api/v1/receipts/{session}"),
            json!({}),
        )
        .await;
        assert_eq!(receipt["session_id"], session);

        let (_, denied_session) =
            request(&router, Method::POST, "/api/v1/sessions", json!({})).await;
        let denied_id = denied_session["session_id"].as_str().unwrap();
        let (_, denied) = request(
            &router,
            Method::POST,
            &format!("/api/v1/sessions/{denied_id}/execute"),
            json!({"variant": "configuration-changed"}),
        )
        .await;
        assert_eq!(
            denied["result"]["decision"]["code"],
            "verifier-configuration-mismatch"
        );
        assert_eq!(denied["result"]["credential_called"], false);
        assert_eq!(denied["result"]["opentofu_called"], false);
    }

    #[test]
    fn competing_same_scope_actions_execute_one_provider_effect() {
        for _ in 0..32 {
            let state = tempfile::tempdir().unwrap();
            let demo = demo_with_nonce(0x11);
            let lifecycle_store =
                fixture_lifecycle_store(&state.path().join("lifecycle"), &demo.product.action);
            let artifacts = MemoryPlanArtifactStore::default();
            let backend = Arc::new(OpenTofuBackend::fixture(demo.product.evidence));
            let barrier = Arc::new(Barrier::new(2));

            let handles = [0x11, 0x22]
                .into_iter()
                .map(|nonce_byte| {
                    let lifecycle_store = Arc::clone(&lifecycle_store);
                    let artifacts = artifacts.clone();
                    let backend = Arc::clone(&backend);
                    let barrier = Arc::clone(&barrier);
                    thread::spawn(move || {
                        barrier.wait();
                        execute_fixture_workflow(lifecycle_store, artifacts, backend, nonce_byte)
                    })
                })
                .collect::<Vec<_>>();
            let outcomes = handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>();

            assert_eq!(backend.apply_calls(), 1);
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| matches!(outcome, Ok(WorkflowOutcome::Executed { .. })))
                    .count(),
                1
            );
            assert_eq!(
                outcomes
                    .iter()
                    .filter(|outcome| {
                        matches!(
                            outcome,
                            Ok(WorkflowOutcome::Replay { .. } | WorkflowOutcome::Conflict { .. })
                                | Err(ServiceError::StateChanged)
                        )
                    })
                    .count(),
                1
            );
        }
    }

    #[test]
    fn restart_reconciles_unknown_apply_without_resubmission() {
        let state = tempfile::tempdir().unwrap();
        let lifecycle_path = state.path().join("lifecycle");
        let demo = demo_with_nonce(0x11);
        let artifacts = MemoryPlanArtifactStore::default();
        let backend = Arc::new(OpenTofuBackend::fixture(demo.product.evidence));
        backend.set_fault(OpenTofuFault::AfterApplyUnreconciled);

        let first_store = fixture_lifecycle_store(&lifecycle_path, &demo.product.action);
        let first = execute_fixture_workflow(
            Arc::clone(&first_store),
            artifacts.clone(),
            Arc::clone(&backend),
            0x11,
        );
        assert!(matches!(first, Ok(WorkflowOutcome::OutcomeUnknown { .. })));
        assert_eq!(backend.apply_calls(), 1);
        drop(first_store);

        let reopened_store = fixture_lifecycle_store(&lifecycle_path, &demo.product.action);
        let recovered =
            execute_fixture_workflow(reopened_store, artifacts, Arc::clone(&backend), 0x11);
        assert!(matches!(recovered, Ok(WorkflowOutcome::Executed { .. })));
        assert_eq!(backend.apply_calls(), 1);
    }

    #[test]
    fn obsolete_claim_database_is_rejected_at_startup() {
        let state = tempfile::tempdir().unwrap();
        fs::write(state.path().join("claims.json"), b"{}").unwrap();

        assert!(matches!(
            app(AppConfig::for_test(state.path().to_path_buf())),
            Err(StartupError::State)
        ));
    }
}
