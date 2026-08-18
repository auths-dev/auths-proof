use std::{
    collections::{BTreeMap, HashMap},
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
    lifecycle::{
        GitHubLifecycleRegistry, GitHubLifecycleStore, GitHubRecoveryRecordV1,
        reservation_scope_digest,
    },
    ports::{GitHubReadError, GitHubReadPort},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderName, HeaderValue, Method, StatusCode, header::CONTENT_TYPE},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
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

const API_SCHEMA: &str = "auths-github-agent/v1";
const SESSION_TTL_SECONDS: u64 = 15 * 60;
const MIN_SESSION_TTL_SECONDS: u64 = 60;
const MAX_SESSIONS: usize = 2_048;
const MAX_ATTEMPTS: u8 = 8;
// A two-MiB candidate bundle expands to less than three MiB as base64url. The
// product inspector still enforces the smaller decoded candidate-policy bound.
const MAX_REQUEST_BYTES: usize = 3 * 1024 * 1024;
const MAX_DAILY_PUBLICATIONS: u64 = 25;
const WEB_CONTENT_SECURITY_POLICY: &str = "default-src 'self'; connect-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

type LiveWorkflowService = GitHubIssueWorkflowService<
    Arc<GitCandidateInspector>,
    Arc<VariantGitHubRead>,
    Arc<EphemeralAuthsAuthorizer>,
    Arc<DemoGitHubLifecycleRegistry>,
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
    lifecycle_registry: Arc<DemoGitHubLifecycleRegistry>,
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
        reject_obsolete_workflow_state(&data_directory)?;
        let lifecycle_registry = Arc::new(
            DemoGitHubLifecycleRegistry::new(data_directory.join("lifecycles"))
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
            lifecycle_registry,
            receipt_sink,
            quota_path: data_directory.join("publication-quota.json"),
        })
    }
}

fn reject_obsolete_workflow_state(data_directory: &std::path::Path) -> Result<(), StartupError> {
    if data_directory.join("workflows.json").exists() {
        Err(StartupError)
    } else {
        Ok(())
    }
}

struct DemoGitHubLifecycleStore {
    inner: auths_stores::PersistentLifecycleStore,
}

#[cfg(test)]
mod lifecycle_startup_tests {
    use super::*;

    #[test]
    fn obsolete_workflow_store_is_rejected_instead_of_migrated() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("workflows.json"), b"{}").unwrap();

        assert!(reject_obsolete_workflow_state(directory.path()).is_err());
        assert!(directory.path().join("workflows.json").exists());
    }
}

impl auths_lifecycle::LifecycleStore for DemoGitHubLifecycleStore {
    fn transact(
        &self,
        transaction: &auths_lifecycle::StoreTransactionV1,
    ) -> Result<auths_lifecycle::StoredTransitionV1, auths_lifecycle::StoreError> {
        self.inner.transact(transaction)
    }
}

impl GitHubLifecycleStore for DemoGitHubLifecycleStore {
    fn load_github_lifecycle(
        &self,
        workflow: &auths_lifecycle::WorkflowId,
    ) -> Result<Option<auths_lifecycle::LifecycleRecordV1>, auths_lifecycle::StoreError> {
        self.inner.load(workflow)
    }
}

struct DemoGitHubLifecycleRegistry {
    directory: PathBuf,
    stores: StdMutex<HashMap<String, Arc<DemoGitHubLifecycleStore>>>,
    recovery_lock: StdMutex<()>,
}

impl DemoGitHubLifecycleRegistry {
    fn new(directory: PathBuf) -> Result<Self, auths_lifecycle::StoreError> {
        fs::create_dir_all(directory.join("recovery"))
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        Ok(Self {
            directory,
            stores: StdMutex::new(HashMap::new()),
            recovery_lock: StdMutex::new(()),
        })
    }

    fn recovery_path(
        &self,
        workflow_id: &WorkflowId,
        operation: auths_github::GitHubOperation,
    ) -> PathBuf {
        let operation = match operation {
            auths_github::GitHubOperation::PublishBranch => "branch",
            auths_github::GitHubOperation::OpenDraftPullRequest => "pull-request",
        };
        self.directory
            .join("recovery")
            .join(format!("{}-{operation}.json", workflow_id.as_str()))
    }
}

impl GitHubLifecycleRegistry for DemoGitHubLifecycleRegistry {
    fn for_action(
        &self,
        action: &auths_github::ExactGitHubAction,
    ) -> Result<Arc<dyn GitHubLifecycleStore>, auths_lifecycle::StoreError> {
        let scope =
            reservation_scope_digest(action).map_err(|_| auths_lifecycle::StoreError::Corrupt)?;
        let scope_hex = hex::encode(scope.as_bytes());
        let mut stores = self
            .stores
            .lock()
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        if let Some(store) = stores.get(&scope_hex) {
            let concrete = Arc::clone(store);
            let store: Arc<dyn GitHubLifecycleStore> = concrete;
            return Ok(store);
        }
        let store = Arc::new(DemoGitHubLifecycleStore {
            inner: auths_stores::PersistentLifecycleStore::open(
                self.directory.join(format!("{scope_hex}.lifecycle")),
                vec![auths_stores::LifecycleCapacityRuleV1::Exclusive {
                    scope_digest: scope,
                    window_digest: None,
                    retain_after_commit: true,
                }],
                MAX_SESSIONS,
            )
            .map_err(|_| auths_lifecycle::StoreError::Corrupt)?,
        });
        stores.insert(scope_hex, Arc::clone(&store));
        Ok(store)
    }

    fn persist_recovery(
        &self,
        record: &GitHubRecoveryRecordV1,
    ) -> Result<(), auths_lifecycle::StoreError> {
        record
            .validate()
            .map_err(|_| auths_lifecycle::StoreError::Corrupt)?;
        let _guard = self
            .recovery_lock
            .lock()
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        let path = self.recovery_path(&record.workflow_id, record.operation);
        let bytes = serde_json::to_vec(record).map_err(|_| auths_lifecycle::StoreError::Corrupt)?;
        if path.exists() {
            let existing = fs::read(&path).map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
            return if existing == bytes {
                Ok(())
            } else {
                Err(auths_lifecycle::StoreError::Conflict)
            };
        }
        let temporary = path.with_extension("json.tmp");
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        std::io::Write::write_all(&mut file, &bytes)
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        file.sync_all()
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        fs::rename(&temporary, &path).map_err(|_| auths_lifecycle::StoreError::Unavailable)
    }

    fn load_recovery(
        &self,
        workflow_id: &WorkflowId,
        operation: auths_github::GitHubOperation,
    ) -> Result<Option<GitHubRecoveryRecordV1>, auths_lifecycle::StoreError> {
        let _guard = self
            .recovery_lock
            .lock()
            .map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        let path = self.recovery_path(workflow_id, operation);
        if !path.exists() {
            return Ok(None);
        }
        let bytes = fs::read(path).map_err(|_| auths_lifecycle::StoreError::Unavailable)?;
        let record: GitHubRecoveryRecordV1 =
            serde_json::from_slice(&bytes).map_err(|_| auths_lifecycle::StoreError::Corrupt)?;
        record
            .validate()
            .map_err(|_| auths_lifecycle::StoreError::Corrupt)?;
        if serde_json::to_vec(&record).map_err(|_| auths_lifecycle::StoreError::Corrupt)? != bytes {
            return Err(auths_lifecycle::StoreError::Corrupt);
        }
        Ok(Some(record))
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
    agent_label: String,
    direct_push_safe: Option<bool>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TaskRequest {
    repository: String,
    issue_number: u64,
    base_ref: String,
    base_revision: String,
    allowed_paths: Vec<String>,
    protected_paths: Vec<String>,
    expires_in_seconds: u64,
    branch_budget: u8,
    draft_pull_request_budget: u8,
    agent_label: String,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum CandidateRequest {
    Fixture {
        experiment: String,
    },
    Bundle {
        #[serde(rename = "bundleBase64url")]
        bundle_base64url: String,
        #[serde(rename = "baseRevision")]
        base_revision: String,
        #[serde(rename = "candidateRevision")]
        candidate_revision: String,
    },
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
        .route("/", get(web_index))
        .route("/app.js", get(web_app_script))
        .route("/receipt.js", get(web_receipt_script))
        .route("/styles.css", get(web_styles))
        .route("/receipt", get(web_receipt))
        .route("/receipts/{session_id}", get(web_receipt))
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

async fn web_index() -> Response {
    web_asset(
        include_str!("../web/index.html"),
        "text/html; charset=utf-8",
    )
}

async fn web_receipt() -> Response {
    web_asset(
        include_str!("../web/receipt.html"),
        "text/html; charset=utf-8",
    )
}

async fn web_app_script() -> Response {
    web_asset(
        include_str!("../web/app.js"),
        "text/javascript; charset=utf-8",
    )
}

async fn web_receipt_script() -> Response {
    web_asset(
        include_str!("../web/receipt.js"),
        "text/javascript; charset=utf-8",
    )
}

async fn web_styles() -> Response {
    web_asset(include_str!("../web/styles.css"), "text/css; charset=utf-8")
}

fn web_asset(body: &'static str, content_type: &'static str) -> Response {
    let mut response = body.into_response();
    let headers = response.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(WEB_CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    response
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

async fn scenario(State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    let base_revision = current_base_revision(&state)?;
    Ok(Json(json!({
        "schema": API_SCHEMA,
        "profile": "auths.github.issue-address/1",
        "repository": state.config.repository.slug(),
        "repository_id": state.config.repository.repository_id(),
        "issue_number": state.config.issue.issue_number(),
        "base_ref": state.config.base_ref,
        "base_revision": base_revision,
        "allowed_paths": candidate_policy().allowed_paths,
        "denied_paths": candidate_policy().denied_paths,
        "budgets": {"branches": 1, "draft_pull_requests": 1},
        "expiry": {"minimum_seconds": MIN_SESSION_TTL_SECONDS, "maximum_seconds": SESSION_TTL_SECONDS},
        "agent_credential_present": false,
        "region": &*state.config.region,
        "release": &*state.config.release,
        "experiments": experiment_projection(),
    })))
}

async fn create_session(
    State(state): State<AppState>,
    Json(request): Json<TaskRequest>,
) -> Result<Json<Value>, ApiError> {
    let now = unix_time().map_err(|()| ApiError::internal())?;
    let base = current_base_revision(&state)?;
    validate_task_request(&state, &request, &base)?;
    let (session_id, workflow_id) = random_session_ids()?;
    let grant = workflow_grant(
        workflow_id,
        state.config.repository.clone(),
        state.config.issue.clone(),
        state.config.base_ref.clone(),
        base,
        state.config.verifier_configuration.clone(),
        now,
        request.expires_in_seconds,
    )
    .map_err(|_| ApiError::internal())?;
    let expires_at = grant.expires_at();
    let mut human_seed = [0_u8; 32];
    let mut workflow_seed = [0_u8; 32];
    let mut agent_seed = [0_u8; 32];
    getrandom::fill(&mut human_seed).map_err(|_| ApiError::internal())?;
    getrandom::fill(&mut workflow_seed).map_err(|_| ApiError::internal())?;
    getrandom::fill(&mut agent_seed).map_err(|_| ApiError::internal())?;
    let agent_principal = EphemeralAuthsAuthorizer::new(human_seed, workflow_seed, agent_seed)
        .agent_principal()
        .map_err(|_| ApiError::internal())?;
    let session = Session {
        expires_at,
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
        agent_label: request.agent_label,
        direct_push_safe: None,
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
        "expires_at": expires_at,
        "workflow_id": grant.workflow_id(),
        "base_revision": grant.base_revision(),
        "target_ref": grant.target_ref().map_err(|_| ApiError::internal())?,
        "agent_principal": agent_principal.as_str(),
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
    let (variant, submitted) = match request {
        CandidateRequest::Fixture { experiment } => {
            let variant = DemoVariant::parse(&experiment).ok_or_else(|| {
                ApiError::bad_request(
                    "unknown-experiment",
                    "experiment is not one of the server-owned fixtures",
                )
            })?;
            (variant, None)
        }
        CandidateRequest::Bundle {
            bundle_base64url,
            base_revision,
            candidate_revision,
        } => {
            let bundle = Base64UrlUnpadded::decode_vec(&bundle_base64url).map_err(|_| {
                ApiError::bad_request("candidate-malformed", "candidate bundle is not base64url")
            })?;
            let base_revision = GitOid::parse(base_revision).map_err(|_| {
                ApiError::bad_request("candidate-malformed", "base revision is invalid")
            })?;
            let candidate_revision = GitOid::parse(candidate_revision).map_err(|_| {
                ApiError::bad_request("candidate-malformed", "candidate revision is invalid")
            })?;
            (
                DemoVariant::Exact,
                Some(CandidateSubmission {
                    bundle,
                    base_revision,
                    candidate_revision,
                }),
            )
        }
    };
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
    let candidate = if let Some(candidate) = submitted {
        candidate
    } else {
        build_candidate(
            &state.config.git_executable,
            &state.config.repository_url,
            grant.base_revision(),
            grant.workflow_id(),
            variant,
        )
        .map_err(|_| {
            ApiError::unavailable("candidate-build", "candidate fixture could not be built")
        })?
    };
    let inspector = GitCandidateInspector::new(state.config.git_executable.clone())
        .map_err(|_| ApiError::internal())?;
    let inspection = inspector.inspect(&candidate, grant.candidate_policy(), grant.object_format());
    let (projection, direct_push_safe) = match inspection {
        Ok(inspected) => {
            let direct_push_rejected = direct_push_is_rejected(
                &state.config.git_executable,
                &state.config.repository_url,
                inspected.repository_path(),
                inspected.evidence().candidate_revision(),
                grant.workflow_id(),
            )
            .unwrap_or(false);
            let preview = if direct_push_rejected {
                variant_preview(variant)
            } else {
                json!({
                    "class": "denied",
                    "code": "credential-boundary-failed",
                    "stage": "credential-isolation",
                    "credential_would_be_requested": false,
                })
            };
            (
                json!({
                    "status": if direct_push_rejected { "inspected" } else { "denied" },
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
                            "refused-without-credential"
                        } else {
                            "unexpectedly-accepted"
                        },
                    },
                    "preview": preview,
                }),
                direct_push_rejected,
            )
        }
        Err(error) => (
            json!({
                "status": "denied",
                "error": error.to_string(),
                "preview": variant_preview(variant),
                "direct_push": {
                    "credential_present": false,
                    "result": "not-attempted",
                },
            }),
            true,
        ),
    };
    let mut sessions = state.sessions.lock().await;
    let session = live_session_mut(&mut sessions, &session_id, now)?;
    session.variant = variant;
    session.candidate = Some(candidate);
    session.direct_push_safe = Some(direct_push_safe);
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
    if snapshot.direct_push_safe == Some(false) {
        return Ok(Json(credential_boundary_denial(&session_id)));
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
            recovery_references: auths_github::GitHubRecoveryReferencesV1 {
                branch: auths_lifecycle::RecoveryReferenceDigest::new([71; 32]),
                pull_request: auths_lifecycle::RecoveryReferenceDigest::new([72; 32]),
            },
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

fn credential_boundary_denial(session_id: &str) -> Value {
    json!({
        "schema": API_SCHEMA,
        "session_id": session_id,
        "entered_executor": false,
        "credential_requests": 0,
        "mutations": 0,
        "decision": {
            "class": "denied",
            "code": "credential-boundary-failed",
            "detail": "the candidate environment accepted an unauthenticated direct push",
        },
        "execution": {"branch": "not-attempted", "pull_request": "not-attempted"},
    })
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
        lifecycle_registry: Arc::clone(&state.config.lifecycle_registry),
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
            recovery_references: auths_github::GitHubRecoveryReferencesV1 {
                branch: auths_lifecycle::RecoveryReferenceDigest::new([71; 32]),
                pull_request: auths_lifecycle::RecoveryReferenceDigest::new([72; 32]),
            },
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
        WorkflowOutcome::ReconciledNonEffect { operation, receipt } => (
            json!({
                "schema": API_SCHEMA,
                "session_id": session_id,
                "entered_executor": true,
                "credential_requests": 0,
                "mutations": 0,
                "decision": {"class": "authorized", "code": "reconciled-non-effect"},
                "execution": {
                    "operation": operation,
                    "status": "reconciled-non-effect",
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
        "agent_label": session.agent_label,
        "experiment": session.variant.as_str(),
        "candidate": session.candidate_projection,
        "outcome": session.outcome,
        "required_configuration": session.required_configuration.digest().ok(),
        "executed_configuration": session.grant.required_configuration().digest().ok(),
        "configuration_match": session.required_configuration == *session.grant.required_configuration(),
    })
}

fn current_base_revision(state: &AppState) -> Result<GitOid, ApiError> {
    state
        .config
        .github
        .ref_state(&state.config.repository, &state.config.base_ref)
        .map_err(|_| ApiError::unavailable("github-evidence", "GitHub base ref is unavailable"))?
        .revision
        .ok_or_else(|| ApiError::unavailable("base-missing", "configured base ref is missing"))
}

fn validate_task_request(
    state: &AppState,
    request: &TaskRequest,
    current_base: &GitOid,
) -> Result<(), ApiError> {
    validate_task_boundary(
        request,
        &state.config.repository.slug(),
        state.config.issue.issue_number(),
        &state.config.base_ref,
        current_base,
    )
}

fn validate_task_boundary(
    request: &TaskRequest,
    approved_repository: &str,
    approved_issue: u64,
    approved_base_ref: &RefName,
    current_base: &GitOid,
) -> Result<(), ApiError> {
    let policy = candidate_policy();
    let expected_base = GitOid::parse(&request.base_revision).map_err(|_| {
        ApiError::bad_request(
            "invalid-base-revision",
            "base revision is not a Git object id",
        )
    })?;
    if request.repository != approved_repository {
        return Err(ApiError::bad_request(
            "repository-not-approved",
            "task repository is not the operator-approved repository",
        ));
    }
    if request.issue_number != approved_issue {
        return Err(ApiError::bad_request(
            "issue-not-approved",
            "task issue is not the operator-approved issue",
        ));
    }
    if request.base_ref != approved_base_ref.as_str() || expected_base != *current_base {
        return Err(ApiError::bad_request(
            "base-not-current",
            "task base does not match the current operator-approved base",
        ));
    }
    if request.allowed_paths != policy.allowed_paths
        || request.protected_paths != policy.denied_paths
    {
        return Err(ApiError::bad_request(
            "path-policy-not-approved",
            "task paths do not exactly match the operator-approved policy",
        ));
    }
    if request.branch_budget != 1 || request.draft_pull_request_budget != 1 {
        return Err(ApiError::bad_request(
            "budget-not-approved",
            "the GitHub launch path permits exactly one branch and one draft pull request",
        ));
    }
    if !(MIN_SESSION_TTL_SECONDS..=SESSION_TTL_SECONDS).contains(&request.expires_in_seconds) {
        return Err(ApiError::bad_request(
            "expiry-not-approved",
            "task expiry is outside the bounded session window",
        ));
    }
    if request.agent_label.is_empty()
        || request.agent_label.len() > 64
        || !request
            .agent_label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ApiError::bad_request(
            "agent-label-invalid",
            "agent label is outside the bounded public vocabulary",
        ));
    }
    Ok(())
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
                "code": self.code,
                "detail": self.detail,
            })),
        )
            .into_response()
    }
}

#[cfg(test)]
mod launch_api_tests {
    use super::*;

    fn task() -> TaskRequest {
        let policy = candidate_policy();
        TaskRequest {
            repository: "auths-dev/example".into(),
            issue_number: 123,
            base_ref: "main".into(),
            base_revision: "a".repeat(40),
            allowed_paths: policy.allowed_paths,
            protected_paths: policy.denied_paths,
            expires_in_seconds: SESSION_TTL_SECONDS,
            branch_budget: 1,
            draft_pull_request_budget: 1,
            agent_label: "review-agent".into(),
        }
    }

    fn validates(request: &TaskRequest) -> bool {
        validate_task_boundary(
            request,
            "auths-dev/example",
            123,
            &RefName::parse("main").unwrap(),
            &GitOid::parse("a".repeat(40)).unwrap(),
        )
        .is_ok()
    }

    #[test]
    fn exact_operator_boundary_is_accepted() {
        assert!(validates(&task()));
    }

    #[test]
    fn every_task_widening_is_rejected_before_session_creation() {
        let mut request = task();
        request.repository = "attacker/example".into();
        assert!(!validates(&request));

        let mut request = task();
        request.issue_number += 1;
        assert!(!validates(&request));

        let mut request = task();
        request.base_revision = "b".repeat(40);
        assert!(!validates(&request));

        let mut request = task();
        request.allowed_paths.push("**".into());
        assert!(!validates(&request));

        let mut request = task();
        request.protected_paths.clear();
        assert!(!validates(&request));

        let mut request = task();
        request.branch_budget = 2;
        assert!(!validates(&request));

        let mut request = task();
        request.expires_in_seconds = SESSION_TTL_SECONDS + 1;
        assert!(!validates(&request));
    }

    #[test]
    fn candidate_api_is_closed_over_fixture_or_bounded_bundle_shapes() {
        let fixture: CandidateRequest = serde_json::from_value(json!({
            "kind": "fixture",
            "experiment": "prohibited-path",
        }))
        .unwrap();
        assert!(matches!(fixture, CandidateRequest::Fixture { .. }));

        let bundle: CandidateRequest = serde_json::from_value(json!({
            "kind": "bundle",
            "bundleBase64url": "YXV0aHM",
            "baseRevision": "a".repeat(40),
            "candidateRevision": "b".repeat(40),
        }))
        .unwrap();
        assert!(matches!(bundle, CandidateRequest::Bundle { .. }));

        assert!(
            serde_json::from_value::<CandidateRequest>(json!({
                "kind": "bundle",
                "bundleBase64url": "YXV0aHM",
                "baseRevision": "a".repeat(40),
                "candidateRevision": "b".repeat(40),
                "providerToken": "forbidden",
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<CandidateRequest>(json!({
                "kind": "arbitrary-json",
                "operation": "push",
            }))
            .is_err()
        );
    }

    #[test]
    fn unexpected_direct_push_acceptance_is_a_zero_effect_denial() {
        let denial = credential_boundary_denial("session");
        assert_eq!(denial["entered_executor"], false);
        assert_eq!(denial["credential_requests"], 0);
        assert_eq!(denial["mutations"], 0);
        assert_eq!(denial["decision"]["class"], "denied");
        assert_eq!(denial["decision"]["code"], "credential-boundary-failed");
    }

    #[test]
    fn native_service_embeds_the_interactive_web_shell() {
        let index = include_str!("../web/index.html");
        let script = include_str!("../web/app.js");

        assert!(index.contains("id=\"inspect\""));
        assert!(index.contains("id=\"execute\""));
        assert!(!index.contains("id=\"pull-request-link\" href=\"#\""));
        assert!(script.contains("window.location.origin"));
        assert!(script.contains("Explain selected case"));
        assert!(script.contains("pullRequestLink.removeAttribute(\"href\")"));
        assert!(!script.contains("auths-issue-workflow.fly.dev"));
    }
}
