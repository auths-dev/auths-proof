use std::{fs, path::Path, process::Command};

use auths_radicle::{
    CandidateFacts, CandidateSubmission, CobId, DigestHex, ExecutorAudience, GitOid,
    IssueAddressGrantV1, NodeId, OpenPatchActionV1, RadicleDid, RadicleEvidenceV1, Rid,
    VerifierConfiguration, WorkflowId,
    candidate::GitCandidateInspector,
    derive_exact_action,
    types::{IssueAddressGrantInput, RadicleEvidenceInput, VerifierConfigurationInput},
};

const DEMO_NOW: u64 = 1_800_000_000;
pub(crate) const RADICLE_ADAPTER_VERSION: &str = "radicle-cli-1.9.1";

/// Repository-owned bounded experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DemoVariant {
    /// Every committed input is exact.
    Exact,
    /// Patch body differs after authorization.
    RequestChanged,
    /// Required and loaded policies differ.
    ConfigurationDrift,
    /// Synchronized issue state is closed.
    IssueClosed,
}

impl DemoVariant {
    /// Parses a public API identifier.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "exact" => Some(Self::Exact),
            "request-changed" => Some(Self::RequestChanged),
            "configuration-drift" => Some(Self::ConfigurationDrift),
            "issue-closed" => Some(Self::IssueClosed),
            _ => None,
        }
    }

    /// Returns the stable public identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::RequestChanged => "request-changed",
            Self::ConfigurationDrift => "configuration-drift",
            Self::IssueClosed => "issue-closed",
        }
    }
}

/// Complete deterministic scenario inputs.
pub struct DemoScenario {
    /// Human workflow constraints.
    pub grant: IssueAddressGrantV1,
    /// Caller-required configuration.
    pub required_configuration: VerifierConfiguration,
    /// Executor-loaded configuration.
    pub executed_configuration: VerifierConfiguration,
    /// Request metadata.
    pub submission: CandidateSubmission,
    /// Trusted candidate facts.
    pub candidate: CandidateFacts,
    /// Synchronized Radicle evidence.
    pub evidence: RadicleEvidenceV1,
    /// Exact action committed before any mutation.
    pub action: OpenPatchActionV1,
    /// Evaluation time.
    pub now: u64,
}

impl DemoScenario {
    /// Builds one repository-owned bounded experiment.
    ///
    /// # Errors
    ///
    /// Returns a closed failure if Git or exact action derivation fails.
    pub fn new(variant: DemoVariant) -> Result<Self, ScenarioError> {
        let required_configuration = configuration(30);
        let executed_configuration = if variant == DemoVariant::ConfigurationDrift {
            configuration(60)
        } else {
            required_configuration.clone()
        };
        let mut submission = submission()?;
        let candidate = GitCandidateInspector::new("/usr/bin/git")
            .map_err(|_| ScenarioError)?
            .inspect(&submission, &required_configuration)
            .map_err(|_| ScenarioError)?
            .facts()
            .clone();
        let grant = grant(required_configuration.clone(), candidate.base_oid().clone());
        let issue_open = variant != DemoVariant::IssueClosed;
        let evidence = evidence(&grant, issue_open);
        let action = derive_exact_action(
            &grant,
            &required_configuration,
            &submission,
            &candidate,
            &evidence,
        )
        .map_err(|_| ScenarioError)?;
        if variant == DemoVariant::RequestChanged {
            submission.patch_body.push_str(" One byte changed: !");
        }
        Ok(Self {
            grant,
            required_configuration,
            executed_configuration,
            submission,
            candidate,
            evidence,
            action,
            now: DEMO_NOW,
        })
    }
}

fn configuration(maximum_evidence_age_seconds: u64) -> VerifierConfiguration {
    VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-2.51.0".into(),
        radicle_adapter: RADICLE_ADAPTER_VERSION.into(),
        canonical_reference: "radicle-canonical-v1".into(),
        observation_peers: vec![node('a'), node('b')],
        minimum_successful_peers: 2,
        maximum_evidence_age_seconds,
        synchronization_timeout_seconds: 9,
        maximum_bundle_bytes: 1024 * 1024,
        maximum_expanded_bytes: 4 * 1024 * 1024,
        maximum_objects: 1_000,
        maximum_tree_depth: 16,
        maximum_path_bytes: 256,
        expected_signer_did: RadicleDid::parse("did:key:zradicle-demo-executor").unwrap(),
        executor_audience: ExecutorAudience::parse("auths-radicle://demo-executor").unwrap(),
        receipt_schema: "auths-radicle-receipt-v1".into(),
    })
    .unwrap()
}

pub(crate) fn live_configuration(
    executor_signer_did: RadicleDid,
    observer_node_id: NodeId,
) -> Result<VerifierConfiguration, ScenarioError> {
    VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-bounded-v1".into(),
        radicle_adapter: RADICLE_ADAPTER_VERSION.into(),
        canonical_reference: "radicle-canonical-v1".into(),
        observation_peers: vec![observer_node_id],
        minimum_successful_peers: 1,
        maximum_evidence_age_seconds: 30,
        synchronization_timeout_seconds: 15,
        maximum_bundle_bytes: 1024 * 1024,
        maximum_expanded_bytes: 4 * 1024 * 1024,
        maximum_objects: 1_000,
        maximum_tree_depth: 16,
        maximum_path_bytes: 256,
        expected_signer_did: executor_signer_did,
        executor_audience: ExecutorAudience::parse("auths-radicle://demo-executor")
            .map_err(|_| ScenarioError)?,
        receipt_schema: "auths-radicle-receipt-v1".into(),
    })
    .map_err(|_| ScenarioError)
}

pub(crate) fn live_grant(
    metadata: &crate::DeploymentMetadata,
    configuration: VerifierConfiguration,
    workflow_id: WorkflowId,
    now: u64,
) -> Result<IssueAddressGrantV1, ScenarioError> {
    IssueAddressGrantV1::new(IssueAddressGrantInput {
        workflow_id,
        rid: metadata.rid.clone(),
        issue_id: metadata.issue_id.clone(),
        repository_identity_revision: metadata.repository_identity_revision.clone(),
        canonical_base_oid: metadata.canonical_base_oid.clone(),
        allowed_path_prefixes: vec!["demo/runs/".into()],
        denied_path_prefixes: Vec::new(),
        maximum_changed_files: 1,
        maximum_changed_bytes: 4_096,
        maximum_commits: 1,
        expected_signer_did: configuration.expected_signer_did().clone(),
        executor_audience: configuration.executor_audience().clone(),
        expires_at: now + 300,
        required_configuration: configuration,
    })
    .map_err(|_| ScenarioError)
}

pub(crate) fn live_submission(
    git_executable: &Path,
    storage_repository: &Path,
    base_oid: &GitOid,
    workflow_id: &WorkflowId,
) -> Result<CandidateSubmission, ScenarioError> {
    if !git_executable.is_absolute()
        || !storage_repository.is_absolute()
        || !storage_repository.is_dir()
    {
        return Err(ScenarioError);
    }
    let directory = tempfile::tempdir().map_err(|_| ScenarioError)?;
    let repository = directory.path().join("candidate");
    run_with(
        git_executable,
        directory.path(),
        [
            "clone",
            "--quiet",
            "--no-checkout",
            storage_repository.to_str().ok_or(ScenarioError)?,
            repository.to_str().ok_or(ScenarioError)?,
        ],
    )?;
    run_with(
        git_executable,
        &repository,
        ["checkout", "--quiet", "--detach", base_oid.as_str()],
    )?;
    run_with(
        git_executable,
        &repository,
        ["config", "user.name", "Untrusted Auths Demo Agent"],
    )?;
    run_with(
        git_executable,
        &repository,
        ["config", "user.email", "agent@auths.invalid"],
    )?;
    let relative_path = format!("demo/runs/{}.txt", workflow_id.as_str());
    let path = repository.join(&relative_path);
    fs::write(
        &path,
        format!(
            "Auths-authorized Radicle patch\nworkflow={}\n",
            workflow_id.as_str()
        ),
    )
    .map_err(|_| ScenarioError)?;
    run_with(git_executable, &repository, ["add", relative_path.as_str()])?;
    commit_with(git_executable, &repository, "Add one authorized demo run")?;
    let candidate_oid =
        GitOid::parse(output_with(git_executable, &repository, ["rev-parse", "HEAD"])?.trim())
            .map_err(|_| ScenarioError)?;
    run_with(
        git_executable,
        &repository,
        ["branch", "auths-candidate", "HEAD"],
    )?;
    let bundle = directory.path().join("candidate.bundle");
    run_with(
        git_executable,
        &repository,
        [
            "bundle",
            "create",
            bundle.to_str().ok_or(ScenarioError)?,
            "refs/heads/auths-candidate",
        ],
    )?;
    Ok(CandidateSubmission {
        bundle: fs::read(bundle).map_err(|_| ScenarioError)?,
        base_oid: base_oid.clone(),
        candidate_oid,
        patch_title: "Auths authorized one exact agent patch".into(),
        patch_body: "A keyless agent produced this candidate; the protected executor verified and published only these exact bytes.".into(),
    })
}

fn grant(configuration: VerifierConfiguration, canonical_base_oid: GitOid) -> IssueAddressGrantV1 {
    IssueAddressGrantV1::new(IssueAddressGrantInput {
        workflow_id: WorkflowId::parse("public-demo-workflow").unwrap(),
        rid: Rid::parse("rad:zAuthsDemo123456789").unwrap(),
        issue_id: CobId::parse("1".repeat(40)).unwrap(),
        repository_identity_revision: oid('2'),
        canonical_base_oid,
        allowed_path_prefixes: vec!["src/".into()],
        denied_path_prefixes: vec!["src/secrets/".into()],
        maximum_changed_files: 4,
        maximum_changed_bytes: 32_768,
        maximum_commits: 2,
        expected_signer_did: configuration.expected_signer_did().clone(),
        executor_audience: configuration.executor_audience().clone(),
        expires_at: DEMO_NOW + 300,
        required_configuration: configuration,
    })
    .unwrap()
}

fn submission() -> Result<CandidateSubmission, ScenarioError> {
    let directory = tempfile::tempdir().map_err(|_| ScenarioError)?;
    run(
        directory.path(),
        ["init", "--quiet", "--initial-branch=main"],
    )?;
    run(directory.path(), ["config", "user.name", "Auths Demo"])?;
    run(directory.path(), ["config", "user.email", "demo@auths.dev"])?;
    fs::create_dir_all(directory.path().join("src")).map_err(|_| ScenarioError)?;
    fs::write(
        directory.path().join("src/answer.rs"),
        b"pub fn answer() -> u8 { 41 }\n",
    )
    .map_err(|_| ScenarioError)?;
    run(directory.path(), ["add", "src/answer.rs"])?;
    commit(directory.path(), "fixture base")?;
    let base_oid = GitOid::parse(output(directory.path(), ["rev-parse", "HEAD"])?.trim())
        .map_err(|_| ScenarioError)?;
    fs::write(
        directory.path().join("src/answer.rs"),
        b"pub fn answer() -> u8 { 42 }\n",
    )
    .map_err(|_| ScenarioError)?;
    run(directory.path(), ["add", "src/answer.rs"])?;
    commit(directory.path(), "fixture candidate")?;
    let candidate_oid = GitOid::parse(output(directory.path(), ["rev-parse", "HEAD"])?.trim())
        .map_err(|_| ScenarioError)?;
    run(directory.path(), ["branch", "auths-candidate", "HEAD"])?;
    let bundle = directory.path().join("candidate.bundle");
    run(
        directory.path(),
        [
            "bundle",
            "create",
            bundle.to_str().ok_or(ScenarioError)?,
            "refs/heads/auths-candidate",
        ],
    )?;
    Ok(CandidateSubmission {
        bundle: fs::read(bundle).map_err(|_| ScenarioError)?,
        base_oid,
        candidate_oid,
        patch_title: "Address the Radicle issue".into(),
        patch_body: "The agent proposes this exact bounded source change.".into(),
    })
}

fn evidence(grant: &IssueAddressGrantV1, issue_open: bool) -> RadicleEvidenceV1 {
    RadicleEvidenceV1::new(RadicleEvidenceInput {
        rid: grant.rid().clone(),
        repository_identity_revision: grant.repository_identity_revision().clone(),
        delegates: vec![RadicleDid::parse("did:key:zradicle-demo-human").unwrap()],
        delegate_threshold: 1,
        default_branch: "main".into(),
        canonical_head_oid: grant.canonical_base_oid().clone(),
        canonical_derivation_digest: digest('7'),
        issue_id: grant.issue_id().clone(),
        issue_tip_ids: vec![oid('8')],
        issue_materialized_digest: digest(if issue_open { '9' } else { 'a' }),
        issue_open,
        issue_history_complete: true,
        executor_signer_did: grant.expected_signer_did().clone(),
        executor_node_id: node('c'),
        synchronized_peers: grant.required_configuration().observation_peers().to_vec(),
        synchronized_at: DEMO_NOW,
        adapter_version: grant.required_configuration().radicle_adapter().into(),
    })
    .unwrap()
}

fn oid(character: char) -> GitOid {
    GitOid::parse(character.to_string().repeat(40)).unwrap()
}

fn digest(character: char) -> DigestHex {
    DigestHex::parse(character.to_string().repeat(64)).unwrap()
}

fn node(character: char) -> NodeId {
    NodeId::parse(format!("z{}", character.to_string().repeat(31))).unwrap()
}

fn commit(repository: &Path, message: &str) -> Result<(), ScenarioError> {
    commit_with(Path::new("/usr/bin/git"), repository, message)
}

fn commit_with(
    git_executable: &Path,
    repository: &Path,
    message: &str,
) -> Result<(), ScenarioError> {
    run_with(
        git_executable,
        repository,
        [
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            message,
        ],
    )
}

fn run<const N: usize>(repository: &Path, arguments: [&str; N]) -> Result<(), ScenarioError> {
    run_with(Path::new("/usr/bin/git"), repository, arguments)
}

fn run_with<const N: usize>(
    git_executable: &Path,
    repository: &Path,
    arguments: [&str; N],
) -> Result<(), ScenarioError> {
    let status = Command::new(git_executable)
        .current_dir(repository)
        .args(arguments)
        .env("GIT_AUTHOR_DATE", "2025-01-01T00:00:00Z")
        .env("GIT_COMMITTER_DATE", "2025-01-01T00:00:00Z")
        .status()
        .map_err(|_| ScenarioError)?;
    if status.success() {
        Ok(())
    } else {
        Err(ScenarioError)
    }
}

fn output<const N: usize>(
    repository: &Path,
    arguments: [&str; N],
) -> Result<String, ScenarioError> {
    output_with(Path::new("/usr/bin/git"), repository, arguments)
}

fn output_with<const N: usize>(
    git_executable: &Path,
    repository: &Path,
    arguments: [&str; N],
) -> Result<String, ScenarioError> {
    let output = Command::new(git_executable)
        .current_dir(repository)
        .args(arguments)
        .output()
        .map_err(|_| ScenarioError)?;
    if !output.status.success() {
        return Err(ScenarioError);
    }
    String::from_utf8(output.stdout).map_err(|_| ScenarioError)
}

/// Fixed demo fixture construction failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("could not construct the bounded Radicle demo fixture")]
pub struct ScenarioError;

#[cfg(test)]
mod tests {
    use auths_profile_api::ActionProfile as _;
    use auths_radicle::{DecisionClass, EvaluationContext, RadiclePatchProfile, evaluate};
    use auths_sdk::VerifyResult;

    use super::*;
    use crate::authorization_fixture;

    #[test]
    fn human_delegation_authorizes_the_exact_agent_action_in_real_auths_kernel() {
        let scenario = DemoScenario::new(DemoVariant::Exact).unwrap();
        let fixture = authorization_fixture(&scenario.action, scenario.now, [0x71; 32]);
        let canonical = RadiclePatchProfile
            .canonicalize(&scenario.action.canonical_bytes().unwrap())
            .unwrap();

        let result = fixture
            .verifier
            .verify(
                &fixture.proof,
                &canonical,
                &fixture.request,
                &RadiclePatchProfile,
            )
            .unwrap();

        match result {
            VerifyResult::Authorized(_) => {}
            VerifyResult::Denied(explanation) => {
                panic!("Auths denied the exact fixture: {}", explanation.code())
            }
            VerifyResult::Indeterminate(explanation) => {
                panic!(
                    "Auths could not evaluate the exact fixture: {}",
                    explanation.code()
                )
            }
        }
        assert_ne!(fixture.human_principal, fixture.agent_principal);
        assert_ne!(fixture.human_principal, fixture.workflow_principal);
        assert_ne!(fixture.workflow_principal, fixture.agent_principal);
    }

    #[test]
    fn all_demo_mutations_fail_before_the_auths_kernel() {
        for variant in [
            DemoVariant::RequestChanged,
            DemoVariant::ConfigurationDrift,
            DemoVariant::IssueClosed,
        ] {
            let scenario = DemoScenario::new(variant).unwrap();
            let decision = evaluate(&EvaluationContext {
                grant: &scenario.grant,
                action: &scenario.action,
                submission: &scenario.submission,
                candidate: &scenario.candidate,
                evidence: &scenario.evidence,
                required_configuration: &scenario.required_configuration,
                executed_configuration: &scenario.executed_configuration,
                request_audience: scenario.required_configuration.executor_audience().as_str(),
                now: scenario.now,
            });
            assert_ne!(
                decision.class,
                DecisionClass::Authorized,
                "{} unexpectedly authorized",
                variant.as_str()
            );
        }
    }
}
