use std::{
    collections::BTreeMap,
    env, fs,
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex as StdMutex},
    time::{SystemTime, UNIX_EPOCH},
};

use auths_github::{
    CandidateSubmission, DecisionCode, DigestHex, ExecuteWorkflowRequest, ExecutorAudience,
    GitCandidateInspector, GitHubIssueWorkflowService, GitOid, IssueEvidence, IssueResource,
    NodeId, PullRequestEvidence, RefEvidence, RefName, RepositoryEvidence, RepositoryName,
    RepositoryOwner, RepositoryResource, ServiceDependencies, VerifierConfiguration, WorkflowGrant,
    WorkflowId, WorkflowOutcome,
    adapters::{
        Ed25519JsonlReceiptSink, GitHubAppCredentialProvider, GitHubRestClient, SystemClock,
    },
    ports::{GitHubReadError, GitHubReadPort},
    workflow::PersistentWorkflowStore,
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;
use tower_http::cors::CorsLayer;

use crate::{
    EphemeralAuthsAuthorizer,
    scenario::{
        DemoVariant, build_candidate, candidate_policy, direct_push_is_rejected,
        verifier_configuration, workflow_grant,
    },
};

const API_SCHEMA: &str = "auths-github-demo/v1";
const SESSION_TTL_SECONDS: u64 = 15 * 60;
const MAX_SESSIONS: usize = 2_048;
const MAX_ATTEMPTS: u8 = 8;
const MAX_REQUEST_BYTES: usize = 4 * 1024;
const MAX_DAILY_PUBLICATIONS: u64 = 25;

type LiveWorkflowService = GitHubIssueWorkflowService<
    Arc<GitCandidateInspector>,
    Arc<VariantGitHubRead>,
    Arc<EphemeralAuthsAuthorizer>,
    Arc<PersistentWorkflowStore>,
    Arc<GitHubAppCredentialProvider>,
    Arc<GitHubRestClient>,
    Arc<Ed25519JsonlReceiptSink>,
    SystemClock,
>;

struct VariantGitHubRead {
    inner: Arc<GitHubRestClient>,
    variant: DemoVariant,
    base_ref: RefName,
}

impl GitHubReadPort for VariantGitHubRead {
    fn repository(
        &self,
        resource: &RepositoryResource,
    ) -> Result<RepositoryEvidence, GitHubReadError> {
        let mut evidence = self.inner.repository(resource)?;
        if self.variant == DemoVariant::RepositoryChanged {
            evidence.repository_id = evidence.repository_id.saturating_add(1);
        }
        Ok(evidence)
    }

    fn issue(&self, resource: &IssueResource) -> Result<IssueEvidence, GitHubReadError> {
        let mut evidence = self.inner.issue(resource)?;
        if self.variant == DemoVariant::IssueChanged {
            evidence.issue_number = evidence.issue_number.saturating_add(1);
        }
        Ok(evidence)
    }

    fn ref_state(
        &self,
        repository: &RepositoryResource,
        ref_name: &RefName,
    ) -> Result<RefEvidence, GitHubReadError> {
        let mut evidence = self.inner.ref_state(repository, ref_name)?;
        if self.variant == DemoVariant::BaseAdvanced
            && evidence.revision.is_some()
            && ref_name == &self.base_ref
        {
            evidence.revision = Some(changed_oid(
                evidence
                    .revision
                    .as_ref()
                    .ok_or(GitHubReadError::Malformed)?,
            )?);
        }
        Ok(evidence)
    }

    fn matching_pull_requests(
        &self,
        repository: &RepositoryResource,
        head: &RefName,
        base: &RefName,
    ) -> Result<Vec<PullRequestEvidence>, GitHubReadError> {
        self.inner.matching_pull_requests(repository, head, base)
    }
}

fn changed_oid(oid: &GitOid) -> Result<GitOid, GitHubReadError> {
    let mut bytes = oid.as_str().as_bytes().to_vec();
    let first = bytes.first_mut().ok_or(GitHubReadError::Malformed)?;
    *first = if *first == b'0' { b'1' } else { b'0' };
    GitOid::parse(String::from_utf8(bytes).map_err(|_| GitHubReadError::Malformed)?)
        .map_err(|_| GitHubReadError::Malformed)
}

/// Native deployment configuration.
pub struct AppConfig {
    allowed_origin: HeaderValue,
    region: Arc<str>,
    release: Arc<str>,
    repository: RepositoryResource,
    issue: IssueResource,
    base_ref: RefName,
    repository_url: Arc<str>,
    git_executable: PathBuf,
    verifier_configuration: VerifierConfiguration,
    receipt_view_base_url: Arc<str>,
    executor_identity: Arc<str>,
    github: Arc<GitHubRestClient>,
    credential_provider: Arc<GitHubAppCredentialProvider>,
    workflow_store: Arc<PersistentWorkflowStore>,
    receipt_sink: Arc<Ed25519JsonlReceiptSink>,
    quota_path: PathBuf,
}

impl AppConfig {
    /// Loads and validates all live deployment inputs.
    ///
    /// # Errors
    ///
    /// Fails closed for any missing secret, mutable identifier, endpoint,
    /// storage path, or version-pinned executor setting.
    #[allow(
        clippy::too_many_lines,
        reason = "security-sensitive startup binding stays linear and fail-closed"
    )]
    pub fn from_environment() -> Result<Self, StartupError> {
        let allowed_origin = required("AUTHS_GITHUB_ALLOWED_ORIGIN")?;
        if !(allowed_origin.starts_with("https://")
            || allowed_origin.starts_with("http://localhost:"))
            || allowed_origin.ends_with('/')
            || allowed_origin.len() > 256
        {
            return Err(StartupError);
        }
        let allowed_origin = HeaderValue::from_str(&allowed_origin).map_err(|_| StartupError)?;
        let region = env::var("FLY_REGION").unwrap_or_else(|_| "local".into());
        let release = env::var("AUTHS_GITHUB_RELEASE").unwrap_or_else(|_| "development".into());
        validate_label(&region)?;
        validate_label(&release)?;

        let repository_id = parse_required::<u64>("AUTHS_GITHUB_REPOSITORY_ID")?;
        let repository = RepositoryResource::new(
            repository_id,
            NodeId::parse(required("AUTHS_GITHUB_REPOSITORY_NODE_ID")?)
                .map_err(|_| StartupError)?,
            RepositoryOwner::parse(required("AUTHS_GITHUB_REPOSITORY_OWNER")?)
                .map_err(|_| StartupError)?,
            RepositoryName::parse(required("AUTHS_GITHUB_REPOSITORY_NAME")?)
                .map_err(|_| StartupError)?,
        )
        .map_err(|_| StartupError)?;
        let issue = IssueResource::new(
            repository_id,
            NodeId::parse(required("AUTHS_GITHUB_ISSUE_NODE_ID")?).map_err(|_| StartupError)?,
            parse_required("AUTHS_GITHUB_ISSUE_NUMBER")?,
        )
        .map_err(|_| StartupError)?;
        let base_ref =
            RefName::parse(required("AUTHS_GITHUB_BASE_REF")?).map_err(|_| StartupError)?;
        let repository_url = format!("https://github.com/{}.git", repository.slug());
        let git_executable =
            PathBuf::from(env::var("AUTHS_GITHUB_GIT").unwrap_or_else(|_| "/usr/bin/git".into()));
        if !git_executable.is_absolute() {
            return Err(StartupError);
        }
        let executor_audience =
            ExecutorAudience::parse(required("AUTHS_GITHUB_EXECUTOR_AUDIENCE")?)
                .map_err(|_| StartupError)?;
        let verifier_configuration = verifier_configuration(
            DigestHex::parse(required("AUTHS_GITHUB_AUTOMATION_POLICY_DIGEST")?)
                .map_err(|_| StartupError)?,
            executor_audience,
        )
        .map_err(|_| StartupError)?;
        let api_base =
            env::var("AUTHS_GITHUB_API_BASE").unwrap_or_else(|_| "https://api.github.com".into());
        let web_base =
            env::var("AUTHS_GITHUB_WEB_BASE").unwrap_or_else(|_| "https://github.com".into());
        let private_key = required("AUTHS_GITHUB_APP_PRIVATE_KEY")?.replace("\\n", "\n");
        let credential_provider = Arc::new(
            GitHubAppCredentialProvider::new(
                parse_required("AUTHS_GITHUB_APP_ID")?,
                parse_required("AUTHS_GITHUB_INSTALLATION_ID")?,
                &private_key,
                api_base.clone(),
            )
            .map_err(|_| StartupError)?,
        );
        let github = Arc::new(
            GitHubRestClient::new(
                repository.clone(),
                git_executable.clone(),
                api_base.clone(),
                web_base,
                Arc::clone(&credential_provider),
            )
            .map_err(|_| StartupError)?,
        );
        let data_directory = PathBuf::from(required("AUTHS_GITHUB_DATA_DIR")?);
        if !data_directory.is_absolute() {
            return Err(StartupError);
        }
        fs::create_dir_all(&data_directory).map_err(|_| StartupError)?;
        let workflow_store = Arc::new(
            PersistentWorkflowStore::open(data_directory.join("workflows.json"), MAX_SESSIONS)
                .map_err(|_| StartupError)?,
        );
        let receipt_seed = decode_seed(&required("AUTHS_GITHUB_RECEIPT_SEED")?)?;
        let receipt_sink = Arc::new(
            Ed25519JsonlReceiptSink::new(data_directory.join("receipts.jsonl"), &receipt_seed)
                .map_err(|_| StartupError)?,
        );
        let receipt_view_base_url = required("AUTHS_GITHUB_RECEIPT_VIEW_BASE_URL")?;
        if !receipt_view_base_url.starts_with("https://") || receipt_view_base_url.ends_with('/') {
            return Err(StartupError);
        }
        let executor_identity = required("AUTHS_GITHUB_EXECUTOR_IDENTITY")?;
        validate_label(&executor_identity)?;
        Ok(Self {
            allowed_origin,
            region: region.into(),
            release: release.into(),
            repository,
            issue,
            base_ref,
            repository_url: repository_url.into(),
            git_executable,
            verifier_configuration,
            receipt_view_base_url: receipt_view_base_url.into(),
            executor_identity: executor_identity.into(),
            github,
            credential_provider,
            workflow_store,
            receipt_sink,
            quota_path: data_directory.join("publication-quota.json"),
        })
    }
}

#[derive(Clone)]
struct AppState {
    config: Arc<AppConfig>,
    sessions: Arc<Mutex<BTreeMap<String, Session>>>,
    quota_lock: Arc<StdMutex<()>>,
}

#[derive(Clone)]
struct Session {
    expires_at: u64,
    attempts: u8,
    grant: WorkflowGrant,
    required_configuration: VerifierConfiguration,
    candidate: Option<CandidateSubmission>,
    variant: DemoVariant,
    human_seed: [u8; 32],
    workflow_seed: [u8; 32],
    agent_seed: [u8; 32],
    candidate_projection: Option<Value>,
    outcome: Option<Value>,
    receipts: Vec<Value>,
    executed_once: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidateRequest {
    experiment: String,
}

/// Builds the live GitHub demo API.
///
/// # Errors
///
/// Fails if trusted startup configuration cannot be composed.
pub fn app(config: AppConfig) -> Result<Router, StartupError> {
    let cors = CorsLayer::new()
        .allow_origin(config.allowed_origin.clone())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers([CONTENT_TYPE]);
    let state = AppState {
        config: Arc::new(config),
        sessions: Arc::new(Mutex::new(BTreeMap::new())),
        quota_lock: Arc::new(StdMutex::new(())),
    };
    Ok(Router::new()
        .route("/healthz", get(health))
        .route("/v1/demo/scenario", get(scenario))
        .route("/v1/demo/sessions", post(create_session))
        .route("/v1/demo/sessions/{session_id}", get(session_status))
        .route(
            "/v1/demo/sessions/{session_id}/candidate",
            post(submit_candidate),
        )
        .route("/v1/demo/sessions/{session_id}/execute", post(execute))
        .route("/v1/demo/sessions/{session_id}/replay", post(replay))
        .route("/v1/demo/sessions/{session_id}/reconcile", post(reconcile))
        .route("/v1/demo/sessions/{session_id}/receipts", get(receipts))
        .route("/v1/demo/receipts/{session_id}", get(persistent_receipts))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .layer(cors)
        .with_state(state))
}

/// Runs the configured service.
///
/// # Errors
///
/// Returns a startup failure if binding or serving fails.
pub async fn serve(config: AppConfig, address: SocketAddr) -> Result<(), StartupError> {
    let listener = tokio::net::TcpListener::bind(address)
        .await
        .map_err(|_| StartupError)?;
    axum::serve(listener, app(config)?)
        .await
        .map_err(|_| StartupError)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "status": "ok",
        "schema": API_SCHEMA,
        "mode": "live-github-app",
        "region": &*state.config.region,
        "release": &*state.config.release,
        "writer": "single-region",
    }))
}

async fn scenario(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "schema": API_SCHEMA,
        "profile": "auths.github.issue-address/1",
        "repository": state.config.repository.slug(),
        "repository_id": state.config.repository.repository_id(),
        "issue_number": state.config.issue.issue_number(),
        "base_ref": state.config.base_ref,
        "allowed_paths": candidate_policy().allowed_paths,
        "denied_paths": candidate_policy().denied_paths,
        "budgets": {"branches": 1, "draft_pull_requests": 1},
        "agent_credential_present": false,
        "region": &*state.config.region,
        "release": &*state.config.release,
        "experiments": experiment_projection(),
    }))
}

async fn create_session(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let base = state
        .config
        .github
        .ref_state(&state.config.repository, &state.config.base_ref)
        .map_err(|_| ApiError::unavailable("github-evidence", "GitHub base ref is unavailable"))?
        .revision
        .ok_or_else(|| ApiError::unavailable("base-missing", "configured base ref is missing"))?;
    let (session_id, workflow_id) = random_session_ids()?;
    let grant = workflow_grant(
        workflow_id,
        state.config.repository.clone(),
        state.config.issue.clone(),
        state.config.base_ref.clone(),
        base,
        state.config.verifier_configuration.clone(),
        now,
    )
    .map_err(|_| ApiError::internal())?;
    let mut human_seed = [0_u8; 32];
    let mut workflow_seed = [0_u8; 32];
    let mut agent_seed = [0_u8; 32];
    getrandom::fill(&mut human_seed).map_err(|_| ApiError::internal())?;
    getrandom::fill(&mut workflow_seed).map_err(|_| ApiError::internal())?;
    getrandom::fill(&mut agent_seed).map_err(|_| ApiError::internal())?;
    let session = Session {
        expires_at: now + SESSION_TTL_SECONDS,
        attempts: 0,
        grant: grant.clone(),
        required_configuration: state.config.verifier_configuration.clone(),
        candidate: None,
        variant: DemoVariant::Exact,
        human_seed,
        workflow_seed,
        agent_seed,
        candidate_projection: None,
        outcome: None,
        receipts: Vec::new(),
        executed_once: false,
    };
    let mut sessions = state.sessions.lock().await;
    sessions.retain(|_, session| session.expires_at > now);
    if sessions.len() >= MAX_SESSIONS || sessions.contains_key(&session_id) {
        return Err(ApiError::unavailable(
            "session-capacity",
            "the bounded session pool is full",
        ));
    }
    sessions.insert(session_id.clone(), session);
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": now + SESSION_TTL_SECONDS,
        "workflow_id": grant.workflow_id(),
        "base_revision": grant.base_revision(),
        "target_ref": grant.target_ref().map_err(|_| ApiError::internal())?,
        "required_configuration": grant.required_configuration().digest().map_err(|_| ApiError::internal())?,
        "executed_configuration": state.config.verifier_configuration.digest().map_err(|_| ApiError::internal())?,
    })))
}

async fn session_status(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let sessions = state.sessions.lock().await;
    let session = live_session(&sessions, &session_id, now)?;
    Ok(Json(session_projection(&session_id, session)))
}

async fn submit_candidate(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    Json(request): Json<CandidateRequest>,
) -> Result<Json<Value>, ApiError> {
    let variant = DemoVariant::parse(&request.experiment).ok_or_else(|| {
        ApiError::bad_request(
            "unknown-experiment",
            "experiment is not one of the server-owned fixtures",
        )
    })?;
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let (grant, attempts) = {
        let mut sessions = state.sessions.lock().await;
        let session = live_session_mut(&mut sessions, &session_id, now)?;
        session.attempts = session.attempts.saturating_add(1);
        if session.attempts > MAX_ATTEMPTS {
            return Err(ApiError::too_many());
        }
        (session.grant.clone(), session.attempts)
    };
    let candidate = build_candidate(
        &state.config.git_executable,
        &state.config.repository_url,
        grant.base_revision(),
        grant.workflow_id(),
        variant,
    )
    .map_err(|_| {
        ApiError::unavailable("candidate-build", "candidate fixture could not be built")
    })?;
    let inspector = GitCandidateInspector::new(state.config.git_executable.clone())
        .map_err(|_| ApiError::internal())?;
    let inspection = inspector.inspect(&candidate, grant.candidate_policy(), grant.object_format());
    let projection = match inspection {
        Ok(inspected) => {
            let direct_push_rejected = direct_push_is_rejected(
                &state.config.git_executable,
                &state.config.repository_url,
                inspected.repository_path(),
                inspected.evidence().candidate_revision(),
                grant.workflow_id(),
            )
            .unwrap_or(false);
            json!({
                "status": "inspected",
                "candidate_revision": inspected.evidence().candidate_revision(),
                "candidate_tree": inspected.evidence().candidate_tree(),
                "bundle_digest": inspected.evidence().bundle_digest(),
                "change_set_digest": inspected.evidence().change_set_digest(),
                "changed_paths": inspected.evidence().changed_paths(),
                "commit_count": inspected.evidence().commit_count(),
                "object_count": inspected.evidence().object_count(),
                "added_bytes": inspected.evidence().added_bytes(),
                "deleted_bytes": inspected.evidence().deleted_bytes(),
                "direct_push": {
                    "credential_present": false,
                    "result": if direct_push_rejected {
                        "authentication-rejected"
                    } else {
                        "unexpectedly-accepted"
                    },
                },
                "preview": variant_preview(variant),
            })
        }
        Err(error) => json!({
            "status": "denied",
            "error": error.to_string(),
            "preview": variant_preview(variant),
            "direct_push": {
                "credential_present": false,
                "result": "not-attempted",
            },
        }),
    };
    let mut sessions = state.sessions.lock().await;
    let session = live_session_mut(&mut sessions, &session_id, now)?;
    session.variant = variant;
    session.candidate = Some(candidate);
    session.candidate_projection = Some(projection.clone());
    session.outcome = None;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "attempt": attempts,
        "experiment": variant.as_str(),
        "candidate": projection,
    })))
}

async fn execute(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    execute_session(state, session_id, false).await
}

async fn replay(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    execute_session(state, session_id, true).await
}

async fn execute_session(
    state: AppState,
    session_id: String,
    replay_requested: bool,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let snapshot = {
        let mut sessions = state.sessions.lock().await;
        let session = live_session_mut(&mut sessions, &session_id, now)?;
        session.attempts = session.attempts.saturating_add(1);
        if session.attempts > MAX_ATTEMPTS {
            return Err(ApiError::too_many());
        }
        session.clone()
    };
    if replay_requested && !snapshot.executed_once {
        return Err(ApiError::bad_request(
            "nothing-to-replay",
            "publish the exact candidate before requesting replay",
        ));
    }
    let candidate = snapshot.candidate.clone().ok_or_else(|| {
        ApiError::bad_request(
            "candidate-required",
            "inspect the selected candidate before execution",
        )
    })?;
    if snapshot.variant == DemoVariant::Exact && !snapshot.executed_once {
        consume_publication_quota(&state)?;
    }
    let service = live_workflow_service(&state, &snapshot)?;
    let outcome = service
        .execute(ExecuteWorkflowRequest {
            workflow_grant: snapshot.grant,
            required_configuration: snapshot.required_configuration,
            candidate,
        })
        .map_err(|error| {
            eprintln!("auths-github-demo: execution failed: {error}");
            ApiError::unavailable(
                "execution-unavailable",
                "native executor could not complete the workflow",
            )
        })?;
    record_outcome(&state, &session_id, now, outcome).await
}

fn live_workflow_service(
    state: &AppState,
    session: &Session,
) -> Result<LiveWorkflowService, ApiError> {
    let authorizer = Arc::new(EphemeralAuthsAuthorizer::new(
        session.human_seed,
        session.workflow_seed,
        session.agent_seed,
    ));
    GitHubIssueWorkflowService::new(ServiceDependencies {
        candidate_inspector: Arc::new(
            GitCandidateInspector::new(state.config.git_executable.clone())
                .map_err(|_| ApiError::internal())?,
        ),
        github_read: Arc::new(VariantGitHubRead {
            inner: Arc::clone(&state.config.github),
            variant: session.variant,
            base_ref: state.config.base_ref.clone(),
        }),
        action_authorizer: authorizer,
        workflow_store: Arc::clone(&state.config.workflow_store),
        credential_provider: Arc::clone(&state.config.credential_provider),
        github_write: Arc::clone(&state.config.github),
        receipt_sink: Arc::clone(&state.config.receipt_sink),
        clock: SystemClock,
        executed_configuration: state.config.verifier_configuration.clone(),
        receipt_view_base_url: state.config.receipt_view_base_url.to_string(),
        executor_identity: state.config.executor_identity.to_string(),
    })
    .map_err(|_| ApiError::internal())
}

async fn reconcile(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let snapshot = {
        let mut sessions = state.sessions.lock().await;
        let session = live_session_mut(&mut sessions, &session_id, now)?;
        session.attempts = session.attempts.saturating_add(1);
        if session.attempts > MAX_ATTEMPTS {
            return Err(ApiError::too_many());
        }
        session.clone()
    };
    if snapshot.variant != DemoVariant::Exact {
        return Err(ApiError::bad_request(
            "exact-candidate-required",
            "only the exact candidate can have a claimed effect to reconcile",
        ));
    }
    let candidate = snapshot.candidate.clone().ok_or_else(|| {
        ApiError::bad_request(
            "candidate-required",
            "inspect the selected candidate before reconciliation",
        )
    })?;
    let service = live_workflow_service(&state, &snapshot)?;
    let outcome = service
        .reconcile(ExecuteWorkflowRequest {
            workflow_grant: snapshot.grant,
            required_configuration: snapshot.required_configuration,
            candidate,
        })
        .map_err(|error| {
            eprintln!("auths-github-demo: reconciliation failed: {error}");
            ApiError::unavailable(
                "reconciliation-unavailable",
                "native executor could not reconcile the claimed workflow",
            )
        })?;
    record_outcome(&state, &session_id, now, outcome).await
}

async fn record_outcome(
    state: &AppState,
    session_id: &str,
    now: u64,
    outcome: WorkflowOutcome,
) -> Result<Json<Value>, ApiError> {
    let (response, receipts, completed) = outcome_projection(session_id, outcome);
    let mut sessions = state.sessions.lock().await;
    let session = live_session_mut(&mut sessions, session_id, now)?;
    session.outcome = Some(response.clone());
    if !receipts.is_empty() {
        session.receipts = receipts;
    }
    session.executed_once |= completed;
    Ok(Json(response))
}

async fn receipts(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let sessions = state.sessions.lock().await;
    let session = live_session(&sessions, &session_id, now)?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "receipts": session.receipts,
    })))
}

async fn persistent_receipts(
    State(state): State<AppState>,
    Path(receipt_id): Path<String>,
) -> Result<Json<Value>, ApiError> {
    let session_id = receipt_id.strip_prefix("demo-").unwrap_or(&receipt_id);
    if session_id.len() != 32
        || !session_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ApiError::bad_request(
            "invalid-receipt-id",
            "receipt identifier must be 32 lowercase hexadecimal characters",
        ));
    }
    let workflow_id =
        WorkflowId::parse(format!("demo-{session_id}")).map_err(|_| ApiError::internal())?;
    let receipts = state
        .config
        .receipt_sink
        .receipts_for_workflow(&workflow_id)
        .map_err(|_| {
            ApiError::unavailable(
                "receipt-log-unavailable",
                "the signed receipt log could not be verified",
            )
        })?;
    if receipts.is_empty() {
        return Err(ApiError::not_found(
            "receipts-not-found",
            "no signed receipts exist for this workflow",
        ));
    }
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "workflow_id": workflow_id,
        "receipts": receipts,
    })))
}

#[allow(
    clippy::too_many_lines,
    reason = "the public projection keeps every closed workflow outcome explicit"
)]
fn outcome_projection(session_id: &str, outcome: WorkflowOutcome) -> (Value, Vec<Value>, bool) {
    match outcome {
        WorkflowOutcome::Completed {
            branch,
            pull_request,
            branch_decision,
            branch_execution,
            pull_request_decision,
            pull_request_execution,
        } => {
            let receipts = vec![
                json!({"type": "branch-decision", "receipt": branch_decision}),
                json!({"type": "branch-execution", "receipt": branch_execution}),
                json!({"type": "pull-request-decision", "receipt": pull_request_decision}),
                json!({"type": "pull-request-execution", "receipt": pull_request_execution}),
            ];
            (
                json!({
                    "schema": API_SCHEMA,
                    "session_id": session_id,
                    "entered_executor": true,
                    "credential_requests": 2,
                    "mutations": 2,
                    "decision": {"class": "authorized", "code": "authorized"},
                    "execution": {
                        "branch": "published",
                        "branch_ref": branch.branch_ref,
                        "branch_revision": branch.head_revision,
                        "pull_request": "opened",
                        "pull_request_number": pull_request.number,
                        "pull_request_url": pull_request.url,
                        "draft": pull_request.draft,
                        "replay": "not-attempted",
                    },
                    "receipt_count": receipts.len(),
                }),
                receipts,
                true,
            )
        }
        WorkflowOutcome::ResumedCompleted {
            branch,
            pull_request,
            branch_execution_receipt_digest,
            pull_request_decision,
            pull_request_execution,
        } => {
            let receipts = vec![
                json!({
                    "type": "branch-execution-reference",
                    "receipt_digest": branch_execution_receipt_digest,
                }),
                json!({"type": "pull-request-decision", "receipt": pull_request_decision}),
                json!({"type": "pull-request-execution", "receipt": pull_request_execution}),
            ];
            (
                json!({
                    "schema": API_SCHEMA,
                    "session_id": session_id,
                    "entered_executor": true,
                    "credential_requests": 1,
                    "mutations": 1,
                    "decision": {"class": "authorized", "code": "authorized-after-branch-recovery"},
                    "execution": {
                        "branch": "previously-published",
                        "branch_ref": branch.branch_ref,
                        "branch_revision": branch.head_revision,
                        "pull_request": "opened",
                        "pull_request_number": pull_request.number,
                        "pull_request_url": pull_request.url,
                        "draft": pull_request.draft,
                        "replay": "not-attempted",
                    },
                    "receipt_count": receipts.len(),
                }),
                receipts,
                true,
            )
        }
        WorkflowOutcome::Rejected { receipt } => {
            let response = json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": false,
                "credential_requests": 0,
                "mutations": 0,
                "decision": {
                    "class": receipt.product_decision.class,
                    "code": receipt.product_decision.code,
                    "detail": receipt.product_decision.detail,
                },
                "execution": {"branch": "not-attempted", "pull_request": "not-attempted"},
            });
            (
                response,
                vec![json!({"type": "decision", "receipt": receipt})],
                false,
            )
        }
        WorkflowOutcome::Replay {
            operation,
            receipt_digest,
        } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "credential_requests": 0,
                "mutations": 0,
                "decision": {"class": "authorized", "code": "action-replay"},
                "execution": {
                    "branch": "unchanged",
                    "pull_request": "unchanged",
                    "replay": "original-receipt-returned",
                    "operation": operation,
                    "receipt_digest": receipt_digest,
                },
            }),
            Vec::new(),
            true,
        ),
        WorkflowOutcome::Partial {
            branch,
            branch_decision,
            branch_execution,
            pull_request_decision,
        } => {
            let receipts = vec![
                json!({"type": "branch-decision", "receipt": branch_decision}),
                json!({"type": "branch-execution", "receipt": branch_execution}),
                json!({"type": "pull-request-decision", "receipt": pull_request_decision}),
            ];
            (
                json!({
                    "schema": API_SCHEMA,
                    "session_id": session_id,
                    "entered_executor": true,
                    "credential_requests": 1,
                    "mutations": 1,
                    "decision": {"class": "denied", "code": "pull-request-not-completed"},
                    "execution": {
                        "branch": "published",
                        "branch_ref": branch.branch_ref,
                        "pull_request": "not-opened",
                    },
                }),
                receipts,
                false,
            )
        }
        WorkflowOutcome::ResumedPartial {
            branch,
            branch_execution_receipt_digest,
            pull_request_decision,
        } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "credential_requests": 0,
                "mutations": 0,
                "decision": {
                    "class": pull_request_decision.product_decision.class,
                    "code": pull_request_decision.product_decision.code,
                },
                "execution": {
                    "branch": "previously-published",
                    "branch_ref": branch.branch_ref,
                    "pull_request": "not-opened",
                    "branch_execution_receipt_digest": branch_execution_receipt_digest,
                },
            }),
            vec![json!({"type": "pull-request-decision", "receipt": pull_request_decision})],
            false,
        ),
        WorkflowOutcome::Reconciled {
            operation,
            observed_state,
            receipt,
        } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "credential_requests": 0,
                "mutations": 0,
                "decision": {"class": "authorized", "code": "reconciled"},
                "execution": {
                    "operation": operation,
                    "status": "reconciled-without-repeat",
                    "observed_state": observed_state,
                },
            }),
            vec![json!({"type": "reconciliation-execution", "receipt": receipt})],
            true,
        ),
        WorkflowOutcome::ReconciliationRequired { operation } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "decision": {"class": "indeterminate", "code": "reconciliation-required"},
                "execution": {"operation": operation, "status": "reconciliation-required"},
            }),
            Vec::new(),
            false,
        ),
        WorkflowOutcome::ExecutionFailed { operation, receipt } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "decision": {"class": "indeterminate", "code": "github-rejected"},
                "execution": {"operation": operation, "status": receipt.result},
            }),
            vec![json!({"type": "execution", "receipt": receipt})],
            false,
        ),
    }
}

fn experiment_projection() -> Vec<Value> {
    [
        (
            DemoVariant::Exact,
            "Exact permitted candidate",
            "Nothing changes after authorization",
        ),
        (
            DemoVariant::ProhibitedPath,
            "Prohibited path",
            "Adds a file under .github/**",
        ),
        (
            DemoVariant::CandidateChanged,
            "Declared revision changed",
            "The submitted revision no longer matches the bundle",
        ),
        (
            DemoVariant::RepositoryChanged,
            "Repository changed",
            "Fresh evidence identifies another repository",
        ),
        (
            DemoVariant::IssueChanged,
            "Issue changed",
            "Fresh evidence identifies another issue",
        ),
        (
            DemoVariant::BaseAdvanced,
            "Base revision advanced",
            "The granted base is no longer current",
        ),
        (
            DemoVariant::MalformedBundle,
            "Malformed bundle",
            "The 17-byte bundle is not valid Git",
        ),
    ]
    .into_iter()
    .map(|(variant, title, description)| {
        json!({
            "id": variant.as_str(),
            "title": title,
            "description": description,
            "preview": variant_preview(variant),
        })
    })
    .collect()
}

fn variant_preview(variant: DemoVariant) -> Value {
    let (class, code, stage, credential) = match variant {
        DemoVariant::Exact => ("authorized", DecisionCode::Authorized, "auths-kernel", true),
        DemoVariant::ProhibitedPath => (
            "denied",
            DecisionCode::PathExplicitlyDenied,
            "candidate-inspection",
            false,
        ),
        DemoVariant::CandidateChanged | DemoVariant::MalformedBundle => (
            "denied",
            DecisionCode::CandidateBundleMalformed,
            "candidate-inspection",
            false,
        ),
        DemoVariant::RepositoryChanged => (
            "denied",
            DecisionCode::RepositoryMismatch,
            "github-evidence",
            false,
        ),
        DemoVariant::IssueChanged => (
            "denied",
            DecisionCode::IssueMismatch,
            "github-evidence",
            false,
        ),
        DemoVariant::BaseAdvanced => (
            "denied",
            DecisionCode::BaseRevisionMismatch,
            "github-evidence",
            false,
        ),
    };
    json!({
        "class": class,
        "code": code,
        "stage": stage,
        "credential_would_be_requested": credential,
    })
}

fn session_projection(session_id: &str, session: &Session) -> Value {
    json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "expires_at": session.expires_at,
        "workflow_id": session.grant.workflow_id(),
        "repository": session.grant.repository().slug(),
        "issue_number": session.grant.issue().issue_number(),
        "base_ref": session.grant.base_ref(),
        "base_revision": session.grant.base_revision(),
        "target_ref": session.grant.target_ref().ok(),
        "experiment": session.variant.as_str(),
        "candidate": session.candidate_projection,
        "outcome": session.outcome,
        "required_configuration": session.required_configuration.digest().ok(),
        "executed_configuration": session.grant.required_configuration().digest().ok(),
        "configuration_match": session.required_configuration == *session.grant.required_configuration(),
    })
}

fn live_session<'a>(
    sessions: &'a BTreeMap<String, Session>,
    session_id: &str,
    now: u64,
) -> Result<&'a Session, ApiError> {
    let session = sessions
        .get(session_id)
        .ok_or_else(|| ApiError::gone("session-unavailable", "session is missing or expired"))?;
    if session.expires_at <= now {
        return Err(ApiError::gone(
            "session-expired",
            "session expired; create a new one",
        ));
    }
    Ok(session)
}

fn live_session_mut<'a>(
    sessions: &'a mut BTreeMap<String, Session>,
    session_id: &str,
    now: u64,
) -> Result<&'a mut Session, ApiError> {
    let session = sessions
        .get_mut(session_id)
        .ok_or_else(|| ApiError::gone("session-unavailable", "session is missing or expired"))?;
    if session.expires_at <= now {
        return Err(ApiError::gone(
            "session-expired",
            "session expired; create a new one",
        ));
    }
    Ok(session)
}

fn random_session_ids() -> Result<(String, WorkflowId), ApiError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(|_| ApiError::internal())?;
    let encoded = hex::encode(random);
    let session_id = encoded.clone();
    let workflow_id =
        WorkflowId::parse(format!("demo-{encoded}")).map_err(|_| ApiError::internal())?;
    Ok((session_id, workflow_id))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DailyQuota {
    unix_day: u64,
    publications: u64,
}

fn consume_publication_quota(state: &AppState) -> Result<(), ApiError> {
    let _guard = state.quota_lock.lock().map_err(|_| ApiError::internal())?;
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let today = now / 86_400;
    let mut quota = if state.config.quota_path.exists() {
        serde_json::from_slice::<DailyQuota>(
            &fs::read(&state.config.quota_path).map_err(|_| ApiError::internal())?,
        )
        .map_err(|_| ApiError::internal())?
    } else {
        DailyQuota {
            unix_day: today,
            publications: 0,
        }
    };
    if quota.unix_day != today {
        quota = DailyQuota {
            unix_day: today,
            publications: 0,
        };
    }
    if quota.publications >= MAX_DAILY_PUBLICATIONS {
        return Err(ApiError::unavailable(
            "daily-publication-capacity",
            "today's public GitHub publication limit has been reached",
        ));
    }
    quota.publications += 1;
    let bytes = serde_json::to_vec(&quota).map_err(|_| ApiError::internal())?;
    let temporary = state.config.quota_path.with_extension("tmp");
    fs::write(&temporary, bytes).map_err(|_| ApiError::internal())?;
    fs::rename(temporary, &state.config.quota_path).map_err(|_| ApiError::internal())
}

fn required(name: &'static str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(StartupError)
}

fn parse_required<T: std::str::FromStr>(name: &'static str) -> Result<T, StartupError> {
    required(name)?.parse().map_err(|_| StartupError)
}

fn validate_label(value: &str) -> Result<(), StartupError> {
    if value.is_empty()
        || value.len() > 256
        || value.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.' | b'/'))
        })
    {
        return Err(StartupError);
    }
    Ok(())
}

fn decode_seed(value: &str) -> Result<[u8; 32], StartupError> {
    hex::decode(value)
        .map_err(|_| StartupError)?
        .try_into()
        .map_err(|_| StartupError)
}

fn unix_time() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

/// Closed startup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid GitHub demo startup configuration")]
pub struct StartupError;

struct ApiError {
    status: StatusCode,
    code: &'static str,
    detail: &'static str,
}

impl ApiError {
    const fn bad_request(code: &'static str, detail: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            detail,
        }
    }

    const fn gone(code: &'static str, detail: &'static str) -> Self {
        Self {
            status: StatusCode::GONE,
            code,
            detail,
        }
    }

    const fn not_found(code: &'static str, detail: &'static str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code,
            detail,
        }
    }

    const fn unavailable(code: &'static str, detail: &'static str) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code,
            detail,
        }
    }

    const fn too_many() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "attempt-limit",
            detail: "this session has reached its bounded attempt limit",
        }
    }

    const fn internal() -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            detail: "the native executor could not complete this request",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({
                "schema": API_SCHEMA,
                "error": self.code,
                "detail": self.detail,
            })),
        )
            .into_response()
    }
}
