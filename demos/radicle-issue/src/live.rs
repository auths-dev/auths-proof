use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use auths_radicle::{
    AuthorizeRequest, DecisionClass, RadicleIssueWorkflowService, ServiceDependencies,
    WorkflowOutcome,
    adapters::{
        JsonlReceiptSink, RadicleCliEvidenceSource, RadicleCliWriter,
        RadicleCliWriterConfiguration, SdkProofVerifier,
    },
    candidate::GitCandidateInspector,
    ports::EvidenceSource as _,
    workflow::{PersistentWorkflowStore, WorkflowStage},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{
    AppConfig, AuthorizationFixture, DeploymentMetadata, HttpPropagationObserver, RunningNode,
    app::variant_projection,
    fixture::authorization_fixture_with_seeds,
    scenario::{DemoVariant, live_configuration, live_grant, live_submission},
    storage_repository,
};

const API_SCHEMA: &str = "auths-radicle-demo/v1";
const MAX_REQUEST_BYTES: usize = 2 * 1024;
const MAX_SESSIONS: usize = 2_048;
const MAX_ATTEMPTS: u8 = 8;
const MAX_DAILY_PUBLICATIONS: u64 = 25;
const SESSION_TTL_SECONDS: u64 = 5 * 60;

/// Trusted deployment inputs for the real Radicle executor.
pub struct LiveAppConfig {
    pub node: Arc<RunningNode>,
    pub metadata: DeploymentMetadata,
    pub observer: HttpPropagationObserver,
    pub observer_node_id: auths_radicle::NodeId,
    pub git_executable: PathBuf,
    pub rad_executable: PathBuf,
    pub helper_path: PathBuf,
    pub expected_rad_version: String,
}

#[derive(Clone)]
struct LiveState {
    app: AppConfig,
    deployment: Arc<LiveDeployment>,
    sessions: Arc<Mutex<BTreeMap<String, LiveSession>>>,
}

struct LiveDeployment {
    node: Arc<RunningNode>,
    metadata: DeploymentMetadata,
    observer: HttpPropagationObserver,
    observer_node_id: auths_radicle::NodeId,
    git_executable: PathBuf,
    rad_executable: PathBuf,
    helper_path: PathBuf,
    expected_rad_version: String,
    publication_quota: std::sync::Mutex<()>,
}

struct LiveSession {
    expires_at: u64,
    attempts: u8,
    execution_claimed: bool,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DailyPublicationQuota {
    unix_day: u64,
    publications: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecuteRequest {
    variant: String,
}

/// Builds the public coordinator around a real protected Radicle node.
///
/// # Errors
///
/// Fails closed when persisted deployment facts or executable paths drift.
pub fn live_app(app: AppConfig, live: LiveAppConfig) -> Result<Router, LiveStartupError> {
    if live.metadata.executor_node_id != live.node.node_id
        || live.metadata.executor_signer_did != live.node.signer_did
        || live.observer_node_id == live.node.node_id
        || !live.git_executable.is_absolute()
        || !live.rad_executable.is_absolute()
        || !live.helper_path.is_absolute()
        || live.expected_rad_version.is_empty()
    {
        return Err(LiveStartupError);
    }
    let cors = CorsLayer::new()
        .allow_origin(app.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    let state = LiveState {
        app,
        deployment: Arc::new(LiveDeployment {
            node: live.node,
            metadata: live.metadata,
            observer: live.observer,
            observer_node_id: live.observer_node_id,
            git_executable: live.git_executable,
            rad_executable: live.rad_executable,
            helper_path: live.helper_path,
            expected_rad_version: live.expected_rad_version,
            publication_quota: std::sync::Mutex::new(()),
        }),
        sessions: Arc::new(Mutex::new(BTreeMap::new())),
    };
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/api/v1/scenario", get(scenario))
        .route("/api/v1/sessions", post(create_session))
        .route("/api/v1/sessions/{session_id}/execute", post(execute))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

async fn health(State(state): State<LiveState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "mode": "live-radicle",
        "region": &*state.app.region,
        "release": &*state.app.release,
        "executor_node_id": state.deployment.node.node_id,
        "executor_signer_did": state.deployment.node.signer_did,
        "observer_node_id": state.deployment.observer_node_id,
    }))
}

async fn scenario(State(state): State<LiveState>) -> Json<Value> {
    let configuration = live_configuration(
        state.deployment.node.signer_did.clone(),
        state.deployment.observer_node_id.clone(),
    )
    .expect("INVARIANT: startup validated real did:key identities");
    let configuration_digest = configuration
        .digest()
        .expect("INVARIANT: startup-validated canonical configuration");
    Json(json!({
        "schema": API_SCHEMA,
        "region": &*state.app.region,
        "release": &*state.app.release,
        "execution_mode": "live-radicle-1.9.1",
        "profile": "auths.radicle.issue-address/1",
        "human_principal": state.deployment.metadata.maintainer_did,
        "workflow_principal": "ephemeral-per-session",
        "agent_principal": "keyless-candidate-sandbox",
        "rid": state.deployment.metadata.rid,
        "issue_id": state.deployment.metadata.issue_id,
        "candidate_oid": Value::Null,
        "executor_signer_did": state.deployment.metadata.executor_signer_did,
        "executor_node_id": state.deployment.metadata.executor_node_id,
        "observer_node_id": state.deployment.observer_node_id,
        "canonical_base_oid": state.deployment.metadata.canonical_base_oid,
        "variants": [
            live_variant("exact", "authorized", "authorized", "auths-kernel", true, &configuration_digest),
            live_variant("request-changed", "denied", "patch-metadata-mismatch", "radicle-containment", true, &configuration_digest),
            live_variant("configuration-drift", "denied", "verifier-configuration-mismatch", "preflight", false, &configuration_digest),
            live_variant("issue-closed", "denied", "issue-not-open", "radicle-containment", true, &configuration_digest),
        ],
    }))
}

fn live_variant(
    id: &str,
    class: &str,
    code: &str,
    stage: &str,
    configuration_match: bool,
    configuration_digest: &auths_radicle::DigestHex,
) -> Value {
    json!({
        "id": id,
        "decision": {
            "class": class,
            "code": code,
            "detail": match class {
                "authorized" => "Every committed byte and boundary matches the human grant.",
                _ => "The selected change is stopped before the protected signer.",
            },
            "stage": stage,
        },
        "required_configuration": configuration_digest,
        "executed_configuration": if configuration_match {
            json!(configuration_digest)
        } else {
            json!("different-executed-configuration")
        },
        "configuration_match": configuration_match,
        "changed_files": 1,
        "changed_bytes": 96,
        "issue_open": id != "issue-closed",
        "signer_is_delegate": false,
    })
}

async fn create_session(State(state): State<LiveState>) -> Result<Json<Value>, LiveApiError> {
    let now = unix_time()?;
    let mut random = [0_u8; 12];
    getrandom::fill(&mut random).map_err(|_| LiveApiError::internal())?;
    let session_id = hex::encode(random);
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(LiveApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "session-capacity",
            "the bounded live session pool is full",
        ));
    }
    sessions.insert(
        session_id.clone(),
        LiveSession {
            expires_at: now + SESSION_TTL_SECONDS,
            attempts: 0,
            execution_claimed: false,
        },
    );
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "region": &*state.app.region,
    })))
}

async fn execute(
    State(state): State<LiveState>,
    Path(session_id): Path<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<Value>, LiveApiError> {
    let variant = DemoVariant::parse(&request.variant).ok_or_else(|| {
        LiveApiError::new(
            StatusCode::BAD_REQUEST,
            "unknown-variant",
            "variant is not one of the repository-owned experiments",
        )
    })?;
    validate_attempt(&state, &session_id, variant == DemoVariant::Exact).await?;
    if variant != DemoVariant::Exact {
        let projection = variant_projection(variant).map_err(|_| LiveApiError::internal())?;
        return Ok(Json(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "decision": projection["decision"],
            "executions": 0,
            "receipt_count": 1,
            "stages": [{"name": "authorized", "status": "stopped"}],
        })));
    }

    let deployment = Arc::clone(&state.deployment);
    let result = tokio::task::spawn_blocking(move || execute_exact(&deployment, &session_id))
        .await
        .map_err(|_| LiveApiError::internal())??;
    Ok(Json(result))
}

async fn validate_attempt(
    state: &LiveState,
    session_id: &str,
    claim_execution: bool,
) -> Result<(), LiveApiError> {
    let now = unix_time()?;
    let mut sessions = state.sessions.lock().await;
    let session = sessions.get_mut(session_id).ok_or_else(|| {
        LiveApiError::new(
            StatusCode::GONE,
            "session-unavailable",
            "the live session is missing or expired",
        )
    })?;
    if session.expires_at <= now {
        sessions.remove(session_id);
        return Err(LiveApiError::new(
            StatusCode::GONE,
            "session-expired",
            "the live session expired",
        ));
    }
    claim_session_attempt(session, claim_execution)
}

fn claim_session_attempt(
    session: &mut LiveSession,
    claim_execution: bool,
) -> Result<(), LiveApiError> {
    if session.attempts >= MAX_ATTEMPTS {
        return Err(LiveApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "attempt-limit",
            "the bounded session attempt limit was reached",
        ));
    }
    if claim_execution && session.execution_claimed {
        return Err(LiveApiError::new(
            StatusCode::CONFLICT,
            "execution-lease-consumed",
            "replay blocked: this live session already claimed its one execution",
        ));
    }
    session.attempts += 1;
    if claim_execution {
        session.execution_claimed = true;
    }
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "the live demo keeps exact pre-authoring and protected execution visibly ordered"
)]
fn execute_exact(deployment: &LiveDeployment, session_id: &str) -> Result<Value, LiveApiError> {
    let now = unix_time()?;
    {
        let _guard = deployment
            .publication_quota
            .lock()
            .map_err(|_| LiveApiError::internal())?;
        claim_daily_publication(
            &deployment
                .node
                .configuration
                .rad_home
                .join("auths-publication-quota.json"),
            now,
        )?;
    }
    let workflow_id = auths_radicle::WorkflowId::parse(format!("demo-{session_id}"))
        .map_err(|_| LiveApiError::internal())?;
    let configuration = live_configuration(
        deployment.node.signer_did.clone(),
        deployment.observer_node_id.clone(),
    )
    .map_err(|_| LiveApiError::internal())?;
    let grant = live_grant(
        &deployment.metadata,
        configuration.clone(),
        workflow_id,
        now,
    )
    .map_err(|_| LiveApiError::internal())?;
    let repository = storage_repository(
        &deployment.node.configuration.rad_home,
        &deployment.metadata.rid,
    )
    .map_err(|_| LiveApiError::internal())?;
    let submission = live_submission(
        &deployment.git_executable,
        &repository,
        &deployment.metadata.canonical_base_oid,
        grant.workflow_id(),
    )
    .map_err(|_| LiveApiError::internal())?;
    let inspector = GitCandidateInspector::new(deployment.git_executable.clone())
        .map_err(|_| LiveApiError::internal())?;
    let writer = RadicleCliWriter::new(writer_configuration(deployment))
        .map_err(|_| LiveApiError::internal())?;
    let evidence_source = RadicleCliEvidenceSource::new(writer.clone());
    let candidate = inspector
        .inspect(&submission, &configuration)
        .map_err(|_| LiveApiError::internal())?
        .facts()
        .clone();
    let evidence = evidence_source
        .observe(
            &deployment.metadata.rid,
            &deployment.metadata.issue_id,
            &configuration,
            now,
        )
        .map_err(|_| {
            LiveApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "evidence-unavailable",
                "the executor could not prove a fresh peer-synchronized Radicle view",
            )
        })?;
    let action = auths_radicle::derive_exact_action(
        &grant,
        &configuration,
        &submission,
        &candidate,
        &evidence,
    )
    .map_err(|_| LiveApiError::internal())?;
    let AuthorizationFixture {
        verifier,
        proof,
        request,
        ..
    } = live_authorization_fixture(&action, now)?;
    let service = RadicleIssueWorkflowService::new(ServiceDependencies {
        candidate_inspector: inspector,
        evidence_source,
        proof_verifier: SdkProofVerifier::new(verifier),
        workflow_store: PersistentWorkflowStore::open(
            deployment
                .node
                .configuration
                .rad_home
                .join("auths-workflows.json"),
        )
        .map_err(|_| LiveApiError::internal())?,
        radicle_writer: writer,
        propagation_observer: deployment.observer.clone(),
        receipt_sink: JsonlReceiptSink::new(
            deployment
                .node
                .configuration
                .rad_home
                .join("auths-receipts.jsonl"),
        )
        .map_err(|_| LiveApiError::internal())?,
        clock: FixedClock(now),
        executed_configuration: configuration.clone(),
    });
    match service
        .execute(AuthorizeRequest {
            workflow_grant: grant,
            required_configuration: configuration,
            candidate: submission,
            proof,
            auths_request: request,
        })
        .map_err(|_| LiveApiError::internal())?
    {
        WorkflowOutcome::Executed {
            stage,
            decision,
            execution,
            propagation,
        } => {
            let decision_digest = decision.digest().map_err(|_| LiveApiError::internal())?;
            let execution_digest = execution.digest().map_err(|_| LiveApiError::internal())?;
            let propagation_digest = propagation
                .as_ref()
                .map(|receipt| receipt.digest())
                .transpose()
                .map_err(|_| LiveApiError::internal())?;
            Ok(json!({
                "schema": API_SCHEMA,
                "entered_executor": true,
                "execution_mode": "live-radicle-1.9.1",
                "decision": {
                    "class": "authorized",
                    "code": "authorized",
                    "stage": "auths-kernel",
                },
                "publication": {
                    "rid": execution.publication.rid,
                    "patch_id": execution.publication.patch_id,
                    "revision_id": execution.publication.revision_id,
                    "candidate_oid": execution.publication.candidate_oid,
                    "signer_did": execution.publication.signer_did,
                    "executor_node_id": execution.publication.node_id,
                    "observer_node_id": propagation.as_ref().map(|receipt| &receipt.observer_node_id),
                    "canonical_updated": false,
                },
                "receipts": {
                    "decision": decision_digest,
                    "execution": execution_digest,
                    "propagation": propagation_digest,
                },
                "stages": stage_projection(stage),
                "executions": 1,
                "receipt_count": if propagation.is_some() { 3 } else { 2 },
            }))
        }
        WorkflowOutcome::Replay { record } => Err(LiveApiError::new(
            StatusCode::CONFLICT,
            "execution-lease-consumed",
            if record.patch_id().is_some() {
                "replay blocked: this exact workflow already published one patch"
            } else {
                "replay blocked: this exact workflow already holds the execution lease"
            },
        )),
        WorkflowOutcome::Conflict { .. } => Err(LiveApiError::new(
            StatusCode::CONFLICT,
            "workflow-action-conflict",
            "the workflow identifier is already bound to different exact bytes",
        )),
        WorkflowOutcome::Rejected { receipt } => Ok(json!({
            "schema": API_SCHEMA,
            "entered_executor": false,
            "decision": {
                "class": decision_class(receipt.product_decision.class),
                "code": receipt.product_decision.code,
                "stage": "radicle-containment",
            },
            "executions": 0,
            "receipt_count": 1,
        })),
    }
}

fn writer_configuration(deployment: &LiveDeployment) -> RadicleCliWriterConfiguration {
    RadicleCliWriterConfiguration {
        git_executable: deployment.git_executable.clone(),
        rad_executable: deployment.rad_executable.clone(),
        helper_path: deployment.helper_path.clone(),
        rad_home: deployment.node.configuration.rad_home.clone(),
        expected_rad_version: deployment.expected_rad_version.clone(),
        announce_timeout_seconds: 15,
        announce_replicas: 1,
    }
}

fn stage_projection(stage: WorkflowStage) -> Vec<Value> {
    let mut stages = vec![
        json!({"name": "authorized", "status": "proven"}),
        json!({"name": "claimed", "status": "durable"}),
        json!({"name": "stored", "status": "real Radicle"}),
    ];
    if stage >= WorkflowStage::Announced {
        stages.push(json!({"name": "announced", "status": "peer-to-peer"}));
    }
    if stage >= WorkflowStage::Replicated {
        stages.push(json!({"name": "replicated", "status": "independent node"}));
    }
    stages
}

fn random_challenge() -> Result<[u8; 32], LiveApiError> {
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge).map_err(|_| LiveApiError::internal())?;
    Ok(challenge)
}

fn live_authorization_fixture(
    action: &auths_radicle::OpenPatchActionV1,
    now: u64,
) -> Result<AuthorizationFixture, LiveApiError> {
    let mut human_seed = [0_u8; 32];
    let mut workflow_seed = [0_u8; 32];
    let mut agent_seed = [0_u8; 32];
    getrandom::fill(&mut human_seed).map_err(|_| LiveApiError::internal())?;
    getrandom::fill(&mut workflow_seed).map_err(|_| LiveApiError::internal())?;
    getrandom::fill(&mut agent_seed).map_err(|_| LiveApiError::internal())?;
    Ok(authorization_fixture_with_seeds(
        action,
        now,
        random_challenge()?,
        human_seed,
        workflow_seed,
        agent_seed,
    ))
}

fn claim_daily_publication(path: &std::path::Path, now: u64) -> Result<(), LiveApiError> {
    let unix_day = now / 86_400;
    let mut quota = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<DailyPublicationQuota>(&bytes)
            .map_err(|_| LiveApiError::internal())?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => DailyPublicationQuota {
            unix_day,
            publications: 0,
        },
        Err(_) => return Err(LiveApiError::internal()),
    };
    if quota.unix_day != unix_day {
        quota = DailyPublicationQuota {
            unix_day,
            publications: 0,
        };
    }
    if quota.publications >= MAX_DAILY_PUBLICATIONS {
        return Err(LiveApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "daily-publication-limit",
            "the public demo reached its server-enforced daily publication limit",
        ));
    }
    quota.publications += 1;
    let temporary = path.with_extension("json.tmp");
    let mut options = fs::OpenOptions::new();
    let file = options
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temporary)
        .map_err(|_| LiveApiError::internal())?;
    serde_json::to_writer(&file, &quota).map_err(|_| LiveApiError::internal())?;
    file.sync_all().map_err(|_| LiveApiError::internal())?;
    fs::rename(temporary, path).map_err(|_| LiveApiError::internal())?;
    let parent = path.parent().ok_or_else(LiveApiError::internal)?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| LiveApiError::internal())
}

fn unix_time() -> Result<u64, LiveApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LiveApiError::internal())
}

#[derive(Clone, Copy)]
struct FixedClock(u64);

impl auths_radicle::ports::Clock for FixedClock {
    fn now(&self) -> Result<u64, auths_radicle::ports::PortError> {
        Ok(self.0)
    }
}

const fn decision_class(class: DecisionClass) -> &'static str {
    match class {
        DecisionClass::Authorized => "authorized",
        DecisionClass::Denied => "denied",
        DecisionClass::Indeterminate => "indeterminate",
    }
}

/// Closed live-deployment startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("live Radicle demo configuration failed closed")]
pub struct LiveStartupError;

#[derive(Debug)]
struct LiveApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl LiveApiError {
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
            "the live Radicle boundary failed closed",
        )
    }
}

impl IntoResponse for LiveApiError {
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
    use super::{
        DailyPublicationQuota, LiveSession, MAX_ATTEMPTS, MAX_DAILY_PUBLICATIONS,
        claim_daily_publication, claim_session_attempt,
    };

    #[test]
    fn exact_execution_is_claimed_before_work_begins() {
        let mut session = LiveSession {
            expires_at: u64::MAX,
            attempts: 0,
            execution_claimed: false,
        };
        claim_session_attempt(&mut session, true).unwrap();
        let replay = claim_session_attempt(&mut session, true).unwrap_err();
        assert_eq!(replay.status, axum::http::StatusCode::CONFLICT);
        assert_eq!(replay.code, "execution-lease-consumed");
        assert_eq!(session.attempts, 1);
    }

    #[test]
    fn denied_experiments_remain_bounded_without_consuming_execution() {
        let mut session = LiveSession {
            expires_at: u64::MAX,
            attempts: 0,
            execution_claimed: false,
        };
        for _ in 0..MAX_ATTEMPTS {
            claim_session_attempt(&mut session, false).unwrap();
        }
        let limited = claim_session_attempt(&mut session, false).unwrap_err();
        assert_eq!(limited.status, axum::http::StatusCode::TOO_MANY_REQUESTS);
        assert!(!session.execution_claimed);
    }

    #[test]
    fn publication_quota_is_persistent_bounded_and_resets_next_day() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("quota.json");
        let first_day = 42 * 86_400;
        for _ in 0..MAX_DAILY_PUBLICATIONS {
            claim_daily_publication(&path, first_day).unwrap();
        }
        let limited = claim_daily_publication(&path, first_day).unwrap_err();
        assert_eq!(limited.status, axum::http::StatusCode::TOO_MANY_REQUESTS);
        let persisted: DailyPublicationQuota =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted.publications, MAX_DAILY_PUBLICATIONS);

        claim_daily_publication(&path, first_day + 86_400).unwrap();
        let reset: DailyPublicationQuota =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(reset.publications, 1);
        assert_eq!(reset.unix_day, 43);
    }
}
