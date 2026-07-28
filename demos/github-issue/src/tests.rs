use std::{
    fs,
    path::Path,
    process::Command,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

use auths_github::{
    CandidateSubmission, DigestHex, ExecuteWorkflowRequest, ExecutorAudience,
    GitCandidateInspector, GitHubIssueWorkflowService, GitHubOperation, GitOid, IssueEvidence,
    IssueResource, NodeId, OpenedPullRequest, PullRequestEvidence, RefEvidence, RefName,
    RepositoryEvidence, RepositoryName, RepositoryOwner, RepositoryResource, ServiceDependencies,
    VerifierConfiguration, VerifierConfigurationInput, WorkflowOutcome,
    adapters::InMemoryReceiptSink,
    candidate::QuarantinedCandidate,
    executor::{VerifiedOpenDraftPullRequest, VerifiedPublishBranch},
    ports::{
        Clock, ClockError, CredentialError, CredentialProvider, GitHubReadError, GitHubReadPort,
        GitHubWriteError, GitHubWritePort, ScopedCredential,
    },
    receipts::PublishedBranch,
    workflow::InMemoryWorkflowStore,
};

use crate::{
    EphemeralAuthsAuthorizer,
    scenario::{DemoVariant, build_candidate, verifier_configuration, workflow_grant},
};

const NOW: u64 = 1_900_000_000;

type TestService = GitHubIssueWorkflowService<
    Arc<GitCandidateInspector>,
    Arc<FakeGitHub>,
    Arc<EphemeralAuthsAuthorizer>,
    Arc<InMemoryWorkflowStore>,
    Arc<CountingCredentials>,
    Arc<FakeGitHub>,
    Arc<InMemoryReceiptSink>,
    FixedClock,
>;

#[test]
fn exact_flow_uses_real_auths_kernel_and_replay_mutates_nothing() {
    let fixture = Fixture::new();
    let service = fixture.service(fixture.configuration.clone());
    let request = fixture.request();
    let replay_request = ExecuteWorkflowRequest {
        workflow_grant: request.workflow_grant.clone(),
        required_configuration: request.required_configuration.clone(),
        candidate: request.candidate.clone(),
    };
    let outcome = service.execute(request).unwrap();
    match outcome {
        WorkflowOutcome::Completed {
            branch,
            pull_request,
            branch_decision,
            pull_request_decision,
            ..
        } => {
            assert_eq!(branch.head_revision, fixture.candidate.candidate_revision);
            assert!(pull_request.draft);
            assert_eq!(branch_decision.auths_code.as_deref(), Some("authorized"));
            assert_eq!(
                pull_request_decision.auths_code.as_deref(),
                Some("authorized")
            );
            assert_eq!(
                branch_decision.required_configuration,
                branch_decision.executed_configuration
            );
        }
        _ => panic!("exact workflow did not complete"),
    }
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 2);

    let replay = service.execute(replay_request).unwrap();
    assert!(matches!(
        replay,
        WorkflowOutcome::Replay {
            operation: GitHubOperation::OpenDraftPullRequest,
            ..
        }
    ));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn required_and_executed_configuration_mismatch_is_visible_and_never_gets_a_credential() {
    let fixture = Fixture::new();
    let executed_configuration = VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-bounded-v2".into(),
        github_adapter: "github-rest-2022-11-28".into(),
        canonical_reference: "jcs-rfc8785-v1".into(),
        repository_automation_policy_digest: fixture
            .configuration
            .repository_automation_policy_digest()
            .clone(),
        maximum_evidence_age_seconds: 30,
        executor_audience: fixture.configuration.executor_audience().clone(),
        receipt_schema: "auths-github-receipt-v1".into(),
    })
    .unwrap();
    let service = fixture.service(executed_configuration.clone());
    let outcome = service.execute(fixture.request()).unwrap();
    let WorkflowOutcome::Rejected { receipt } = outcome else {
        panic!("configuration drift must reject");
    };
    assert_eq!(
        receipt.product_decision.code.as_str(),
        "verifier-configuration-mismatch"
    );
    assert_eq!(receipt.required_configuration, fixture.configuration);
    assert_eq!(receipt.executed_configuration, executed_configuration);
    assert_ne!(
        receipt.required_configuration_digest,
        receipt.executed_configuration_digest
    );
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 0);
}

#[test]
fn every_negative_demo_variant_is_a_native_denial_before_credentials() {
    for (variant, expected_code) in [
        (DemoVariant::ProhibitedPath, "path-explicitly-denied"),
        (DemoVariant::CandidateChanged, "candidate-bundle-malformed"),
        (DemoVariant::RepositoryChanged, "repository-mismatch"),
        (DemoVariant::IssueChanged, "issue-mismatch"),
        (DemoVariant::BaseAdvanced, "base-revision-mismatch"),
        (DemoVariant::MalformedBundle, "candidate-bundle-malformed"),
    ] {
        let fixture = Fixture::new();
        fixture.github.set_variant(variant);
        let service = fixture.service(fixture.configuration.clone());
        let outcome = service
            .execute(fixture.request_with_variant(variant))
            .unwrap();
        let WorkflowOutcome::Rejected { receipt } = outcome else {
            panic!("{variant:?} did not produce a native denial");
        };
        assert_eq!(receipt.product_decision.code.as_str(), expected_code);
        assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 0);
        assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn crash_after_branch_publication_reconciles_without_a_second_push() {
    let fixture = Fixture::new();
    fixture
        .github
        .branch_ambiguous_once
        .store(true, Ordering::SeqCst);
    let service = fixture.service(fixture.configuration.clone());

    let first = service.execute(fixture.request()).unwrap();
    assert!(matches!(
        first,
        WorkflowOutcome::ExecutionFailed {
            operation: GitHubOperation::PublishBranch,
            ..
        }
    ));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 0);

    let recovered = service.reconcile(fixture.request()).unwrap();
    assert!(matches!(
        recovered,
        WorkflowOutcome::Reconciled {
            operation: GitHubOperation::PublishBranch,
            ..
        }
    ));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 1);

    let resumed = service.execute(fixture.request()).unwrap();
    assert!(matches!(resumed, WorkflowOutcome::ResumedCompleted { .. }));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 2);
}

#[test]
fn crash_after_pr_creation_reconciles_without_a_second_pr() {
    let fixture = Fixture::new();
    fixture
        .github
        .pull_ambiguous_once
        .store(true, Ordering::SeqCst);
    let service = fixture.service(fixture.configuration.clone());

    let first = service.execute(fixture.request()).unwrap();
    assert!(matches!(
        first,
        WorkflowOutcome::ExecutionFailed {
            operation: GitHubOperation::OpenDraftPullRequest,
            ..
        }
    ));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);

    let recovered = service.reconcile(fixture.request()).unwrap();
    assert!(matches!(
        recovered,
        WorkflowOutcome::Reconciled {
            operation: GitHubOperation::OpenDraftPullRequest,
            ..
        }
    ));
    assert_eq!(fixture.github.branch_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.credentials.calls.load(Ordering::SeqCst), 2);

    let replay = service.execute(fixture.request()).unwrap();
    assert!(matches!(
        replay,
        WorkflowOutcome::Replay {
            operation: GitHubOperation::OpenDraftPullRequest,
            ..
        }
    ));
    assert_eq!(fixture.github.pull_writes.load(Ordering::SeqCst), 1);
}

struct Fixture {
    source: tempfile::TempDir,
    repository: RepositoryResource,
    issue: IssueResource,
    base: GitOid,
    candidate: CandidateSubmission,
    configuration: VerifierConfiguration,
    github: Arc<FakeGitHub>,
    credentials: Arc<CountingCredentials>,
    store: Arc<InMemoryWorkflowStore>,
    receipts: Arc<InMemoryReceiptSink>,
}

impl Fixture {
    fn new() -> Self {
        let source = local_source();
        let base = GitOid::parse(git_output(source.path(), ["rev-parse", "HEAD"]).trim()).unwrap();
        let repository = RepositoryResource::new(
            42,
            NodeId::parse("R_node_123").unwrap(),
            RepositoryOwner::parse("auths-dev").unwrap(),
            RepositoryName::parse("auths-github-demo").unwrap(),
        )
        .unwrap();
        let issue = IssueResource::new(42, NodeId::parse("I_node_123").unwrap(), 42).unwrap();
        let audience = ExecutorAudience::parse("auths-github://test-executor").unwrap();
        let configuration =
            verifier_configuration(DigestHex::parse("7".repeat(64)).unwrap(), audience).unwrap();
        let candidate = build_candidate(
            Path::new("/usr/bin/git"),
            source.path().to_str().unwrap(),
            &base,
            &auths_github::WorkflowId::parse("workflow-1234567890").unwrap(),
            DemoVariant::Exact,
        )
        .unwrap();
        let github = Arc::new(FakeGitHub::new(
            repository.clone(),
            issue.clone(),
            base.clone(),
        ));
        Self {
            source,
            repository,
            issue,
            base,
            candidate,
            configuration,
            github,
            credentials: Arc::new(CountingCredentials::default()),
            store: Arc::new(InMemoryWorkflowStore::default()),
            receipts: Arc::new(InMemoryReceiptSink::default()),
        }
    }

    fn request(&self) -> ExecuteWorkflowRequest {
        self.request_with_variant(DemoVariant::Exact)
    }

    fn request_with_variant(&self, variant: DemoVariant) -> ExecuteWorkflowRequest {
        let grant = workflow_grant(
            auths_github::WorkflowId::parse("workflow-1234567890").unwrap(),
            self.repository.clone(),
            self.issue.clone(),
            RefName::parse("main").unwrap(),
            self.base.clone(),
            self.configuration.clone(),
            NOW,
        )
        .unwrap();
        ExecuteWorkflowRequest {
            workflow_grant: grant,
            required_configuration: self.configuration.clone(),
            candidate: if variant == DemoVariant::Exact {
                self.candidate.clone()
            } else {
                build_candidate(
                    Path::new("/usr/bin/git"),
                    self.source.path().to_str().unwrap(),
                    &self.base,
                    &auths_github::WorkflowId::parse("workflow-1234567890").unwrap(),
                    variant,
                )
                .unwrap()
            },
        }
    }

    fn service(&self, executed_configuration: VerifierConfiguration) -> TestService {
        GitHubIssueWorkflowService::new(ServiceDependencies {
            candidate_inspector: Arc::new(GitCandidateInspector::new("/usr/bin/git").unwrap()),
            github_read: Arc::clone(&self.github),
            action_authorizer: Arc::new(EphemeralAuthsAuthorizer::new(
                [0x51; 32], [0x53; 32], [0x52; 32],
            )),
            workflow_store: Arc::clone(&self.store),
            credential_provider: Arc::clone(&self.credentials),
            github_write: Arc::clone(&self.github),
            receipt_sink: Arc::clone(&self.receipts),
            clock: FixedClock,
            executed_configuration,
            receipt_view_base_url: "https://demo.example/receipts".into(),
            executor_identity: "auths-github-test-executor".into(),
        })
        .unwrap()
    }
}

struct FakeGitHub {
    repository: RepositoryResource,
    issue: IssueResource,
    base: GitOid,
    target: Mutex<Option<(RefName, GitOid)>>,
    pull_request: Mutex<Option<OpenedPullRequest>>,
    branch_writes: AtomicUsize,
    pull_writes: AtomicUsize,
    branch_ambiguous_once: AtomicBool,
    pull_ambiguous_once: AtomicBool,
    repository_changed: AtomicBool,
    issue_changed: AtomicBool,
    base_advanced: AtomicBool,
}

impl FakeGitHub {
    fn new(repository: RepositoryResource, issue: IssueResource, base: GitOid) -> Self {
        Self {
            repository,
            issue,
            base,
            target: Mutex::new(None),
            pull_request: Mutex::new(None),
            branch_writes: AtomicUsize::new(0),
            pull_writes: AtomicUsize::new(0),
            branch_ambiguous_once: AtomicBool::new(false),
            pull_ambiguous_once: AtomicBool::new(false),
            repository_changed: AtomicBool::new(false),
            issue_changed: AtomicBool::new(false),
            base_advanced: AtomicBool::new(false),
        }
    }

    fn set_variant(&self, variant: DemoVariant) {
        self.repository_changed
            .store(variant == DemoVariant::RepositoryChanged, Ordering::SeqCst);
        self.issue_changed
            .store(variant == DemoVariant::IssueChanged, Ordering::SeqCst);
        self.base_advanced
            .store(variant == DemoVariant::BaseAdvanced, Ordering::SeqCst);
    }
}

impl GitHubReadPort for FakeGitHub {
    fn repository(
        &self,
        resource: &RepositoryResource,
    ) -> Result<RepositoryEvidence, GitHubReadError> {
        if resource != &self.repository {
            return Err(GitHubReadError::NotFound);
        }
        let mut evidence = RepositoryEvidence {
            repository_id: self.repository.repository_id(),
            repository_node_id: self.repository.repository_node_id().clone(),
            owner: self.repository.owner().to_string(),
            name: self.repository.name().to_string(),
        };
        if self.repository_changed.load(Ordering::SeqCst) {
            evidence.repository_id = evidence.repository_id.saturating_add(1);
        }
        Ok(evidence)
    }

    fn issue(&self, resource: &IssueResource) -> Result<IssueEvidence, GitHubReadError> {
        if resource != &self.issue {
            return Err(GitHubReadError::NotFound);
        }
        let mut evidence = IssueEvidence {
            repository_id: self.issue.repository_id(),
            issue_node_id: self.issue.issue_node_id().clone(),
            issue_number: self.issue.issue_number(),
            open: true,
        };
        if self.issue_changed.load(Ordering::SeqCst) {
            evidence.issue_number = evidence.issue_number.saturating_add(1);
        }
        Ok(evidence)
    }

    fn ref_state(
        &self,
        repository: &RepositoryResource,
        ref_name: &RefName,
    ) -> Result<RefEvidence, GitHubReadError> {
        if repository != &self.repository {
            return Err(GitHubReadError::NotFound);
        }
        let revision = if ref_name.as_str() == "main" {
            Some(self.base.clone())
        } else {
            self.target
                .lock()
                .map_err(|_| GitHubReadError::Unavailable)?
                .as_ref()
                .filter(|(stored, _)| stored == ref_name)
                .map(|(_, revision)| revision.clone())
        };
        let revision = if self.base_advanced.load(Ordering::SeqCst) && ref_name.as_str() == "main" {
            revision.map(|revision| {
                let mut bytes = revision.as_str().as_bytes().to_vec();
                bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
                GitOid::parse(String::from_utf8(bytes).unwrap()).unwrap()
            })
        } else {
            revision
        };
        Ok(RefEvidence {
            ref_name: ref_name.clone(),
            revision,
        })
    }

    fn matching_pull_requests(
        &self,
        _repository: &RepositoryResource,
        _head: &RefName,
        _base: &RefName,
    ) -> Result<Vec<PullRequestEvidence>, GitHubReadError> {
        Ok(self
            .pull_request
            .lock()
            .map_err(|_| GitHubReadError::Unavailable)?
            .clone()
            .map(|pull| {
                vec![PullRequestEvidence {
                    node_id: pull.node_id,
                    number: pull.number,
                    url: pull.url,
                    base_ref: pull.base_ref,
                    head_ref: pull.head_ref,
                    head_revision: pull.head_revision,
                    draft: pull.draft,
                }]
            })
            .unwrap_or_default())
    }
}

impl GitHubWritePort for FakeGitHub {
    fn publish_branch(
        &self,
        command: &VerifiedPublishBranch,
        candidate: &QuarantinedCandidate,
        _credential: &ScopedCredential,
    ) -> Result<PublishedBranch, GitHubWriteError> {
        if candidate.evidence().candidate_revision() != command.candidate_revision() {
            return Err(GitHubWriteError::PostconditionMismatch);
        }
        self.branch_writes.fetch_add(1, Ordering::SeqCst);
        *self.target.lock().map_err(|_| GitHubWriteError::Adapter)? = Some((
            command.target_ref().clone(),
            command.candidate_revision().clone(),
        ));
        if self.branch_ambiguous_once.swap(false, Ordering::SeqCst) {
            return Err(GitHubWriteError::Ambiguous);
        }
        Ok(PublishedBranch {
            repository_id: self.repository.repository_id(),
            branch_ref: command.target_ref().clone(),
            head_revision: command.candidate_revision().clone(),
        })
    }

    fn open_draft_pull_request(
        &self,
        command: &VerifiedOpenDraftPullRequest,
        _credential: &ScopedCredential,
    ) -> Result<OpenedPullRequest, GitHubWriteError> {
        self.pull_writes.fetch_add(1, Ordering::SeqCst);
        let action = command.action();
        let pull = OpenedPullRequest {
            node_id: NodeId::parse("PR_node_123").unwrap(),
            number: 7,
            url: "https://github.com/auths-dev/auths-github-demo/pull/7".into(),
            base_ref: action.base_ref.clone(),
            head_ref: action.head_ref.clone(),
            head_revision: action.head_revision.clone(),
            draft: true,
        };
        *self
            .pull_request
            .lock()
            .map_err(|_| GitHubWriteError::Adapter)? = Some(pull.clone());
        if self.pull_ambiguous_once.swap(false, Ordering::SeqCst) {
            return Err(GitHubWriteError::Ambiguous);
        }
        Ok(pull)
    }
}

#[derive(Default)]
struct CountingCredentials {
    calls: AtomicUsize,
}

impl CredentialProvider for CountingCredentials {
    fn installation_credential(
        &self,
        _repository: &RepositoryResource,
        _operation: GitHubOperation,
    ) -> Result<ScopedCredential, CredentialError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        ScopedCredential::from_secret(b"short-lived-test-token".to_vec())
    }
}

#[derive(Clone, Copy)]
struct FixedClock;

impl Clock for FixedClock {
    fn now(&self) -> Result<u64, ClockError> {
        Ok(NOW)
    }
}

fn local_source() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    git(
        directory.path(),
        ["init", "--quiet", "--initial-branch=main"],
    );
    git(directory.path(), ["config", "user.name", "Auths Test"]);
    git(
        directory.path(),
        ["config", "user.email", "test@auths.invalid"],
    );
    fs::write(directory.path().join("README.txt"), b"demo base\n").unwrap();
    git(directory.path(), ["add", "README.txt"]);
    git(directory.path(), ["commit", "--quiet", "-m", "Demo base"]);
    directory
}

fn git<I, S>(current: &Path, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new("/usr/bin/git")
        .current_dir(current)
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "commit.gpgSign")
        .env("GIT_CONFIG_VALUE_1", "false")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output<I, S>(current: &Path, args: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new("/usr/bin/git")
        .current_dir(current)
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_0", "/dev/null")
        .env("GIT_CONFIG_KEY_1", "commit.gpgSign")
        .env("GIT_CONFIG_VALUE_1", "false")
        .args(args)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}
