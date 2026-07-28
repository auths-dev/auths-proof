use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use auths_github::{
    CandidatePolicy, CandidateSubmission, GitOid, PublicationPolicy, RefName,
    VerifierConfiguration, VerifierConfigurationInput, WorkflowGrant, WorkflowGrantInput,
    WorkflowId,
};

/// Repository-owned public experiment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DemoVariant {
    /// Every fact matches.
    Exact,
    /// Candidate changes `.github/**`.
    ProhibitedPath,
    /// Candidate commit differs from the approved exact action.
    CandidateChanged,
    /// Repository identity differs.
    RepositoryChanged,
    /// Issue identity differs.
    IssueChanged,
    /// Current base ref differs.
    BaseAdvanced,
    /// Corrupt 17-byte bundle regression seed.
    MalformedBundle,
}

impl DemoVariant {
    /// Parses one public enum value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "exact" => Some(Self::Exact),
            "prohibited-path" => Some(Self::ProhibitedPath),
            "candidate-changed" => Some(Self::CandidateChanged),
            "repository-changed" => Some(Self::RepositoryChanged),
            "issue-changed" => Some(Self::IssueChanged),
            "base-advanced" => Some(Self::BaseAdvanced),
            "malformed-bundle" => Some(Self::MalformedBundle),
            _ => None,
        }
    }

    /// Stable public identifier.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::ProhibitedPath => "prohibited-path",
            Self::CandidateChanged => "candidate-changed",
            Self::RepositoryChanged => "repository-changed",
            Self::IssueChanged => "issue-changed",
            Self::BaseAdvanced => "base-advanced",
            Self::MalformedBundle => "malformed-bundle",
        }
    }
}

/// Builds the strict public-demo candidate policy.
#[must_use]
pub fn candidate_policy() -> CandidatePolicy {
    CandidatePolicy {
        allowed_paths: vec!["demo/runs/**".into(), "src/**".into(), "tests/**".into()],
        denied_paths: vec![
            ".github/**".into(),
            ".gitattributes".into(),
            ".gitmodules".into(),
            "CODEOWNERS".into(),
        ],
        maximum_changed_files: 2,
        maximum_added_bytes: 8 * 1024,
        maximum_deleted_bytes: 8 * 1024,
        maximum_candidate_bytes: 2 * 1024 * 1024,
        maximum_git_objects: 1_000,
        maximum_commits: 1,
        allow_executable_bit_changes: false,
        allow_symlinks: false,
        allow_submodules: false,
        allow_merge_commits: false,
        allow_non_utf8_paths: false,
        allow_git_attributes_changes: false,
        allow_gitmodules_changes: false,
        allow_repository_automation_changes: false,
    }
}

/// Builds one version-pinned verifier configuration.
pub fn verifier_configuration(
    automation_policy_digest: auths_github::DigestHex,
    executor_audience: auths_github::ExecutorAudience,
) -> Result<VerifierConfiguration, ScenarioError> {
    VerifierConfiguration::new(VerifierConfigurationInput {
        candidate_inspector: "git-cli-bounded-v1".into(),
        github_adapter: "github-rest-2022-11-28".into(),
        canonical_reference: "jcs-rfc8785-v1".into(),
        repository_automation_policy_digest: automation_policy_digest,
        maximum_evidence_age_seconds: 30,
        executor_audience,
        receipt_schema: "auths-github-receipt-v1".into(),
    })
    .map_err(|_| ScenarioError)
}

/// Builds one fifteen-minute workflow grant from the current exact base.
pub fn workflow_grant(
    workflow_id: WorkflowId,
    repository: auths_github::RepositoryResource,
    issue: auths_github::IssueResource,
    base_ref: RefName,
    base_revision: GitOid,
    configuration: VerifierConfiguration,
    now: u64,
) -> Result<WorkflowGrant, ScenarioError> {
    WorkflowGrant::new(WorkflowGrantInput {
        workflow_id,
        repository,
        issue,
        base_ref,
        base_revision,
        object_format: auths_github::ObjectFormat::Sha1,
        candidate_policy: candidate_policy(),
        publication_policy: PublicationPolicy::one_draft_pull_request(),
        executor_audience: configuration.executor_audience().clone(),
        issued_at: now,
        expires_at: now + 15 * 60,
        required_configuration: configuration,
    })
    .map_err(|_| ScenarioError)
}

/// Builds one fixed candidate without executing candidate content.
#[allow(
    clippy::too_many_lines,
    reason = "the secure Git fixture construction remains linear and auditable"
)]
pub fn build_candidate(
    git_executable: &Path,
    repository_url: &str,
    base_revision: &GitOid,
    workflow_id: &WorkflowId,
    variant: DemoVariant,
) -> Result<CandidateSubmission, ScenarioError> {
    if variant == DemoVariant::MalformedBundle {
        return Ok(CandidateSubmission {
            // Exact regression seed: malformed inputs at this small boundary
            // must be rejected before GitHub evidence or credentials.
            bundle: vec![0xa5; 17],
            base_revision: base_revision.clone(),
            candidate_revision: GitOid::parse("0".repeat(base_revision.as_str().len()))
                .map_err(|_| ScenarioError)?,
        });
    }
    let repository_source_allowed = repository_url.starts_with("https://github.com/")
        || (cfg!(test) && Path::new(repository_url).is_absolute());
    if !git_executable.is_absolute() || !repository_source_allowed || repository_url.len() > 512 {
        return Err(ScenarioError);
    }
    let directory = tempfile::tempdir().map_err(|_| ScenarioError)?;
    let repository = directory.path().join("candidate");
    git(
        git_executable,
        directory.path(),
        [
            "clone",
            "--quiet",
            "--no-checkout",
            repository_url,
            path_str(&repository)?,
        ],
    )?;
    git(
        git_executable,
        &repository,
        ["checkout", "--quiet", "--detach", base_revision.as_str()],
    )?;
    git(
        git_executable,
        &repository,
        ["config", "user.name", "Credential-less Auths Demo Agent"],
    )?;
    git(
        git_executable,
        &repository,
        ["config", "user.email", "agent@auths.invalid"],
    )?;
    let relative_path = if variant == DemoVariant::ProhibitedPath {
        format!(
            ".github/workflows/auths-{}.yml",
            &workflow_id.as_str()[..12]
        )
    } else {
        format!("demo/runs/{workflow_id}.txt")
    };
    let path = repository.join(&relative_path);
    let parent = path.parent().ok_or(ScenarioError)?;
    fs::create_dir_all(parent).map_err(|_| ScenarioError)?;
    fs::write(
        &path,
        format!("Auths-authorized GitHub candidate\nworkflow={workflow_id}\n"),
    )
    .map_err(|_| ScenarioError)?;
    git(
        git_executable,
        &repository,
        ["add", "--", relative_path.as_str()],
    )?;
    git(
        git_executable,
        &repository,
        [
            "commit",
            "--quiet",
            "-m",
            "Add one Auths-authorized demo run",
        ],
    )?;
    let candidate_revision =
        GitOid::parse(output(git_executable, &repository, ["rev-parse", "HEAD"])?.trim())
            .map_err(|_| ScenarioError)?;
    git(
        git_executable,
        &repository,
        ["branch", "auths-candidate", "HEAD"],
    )?;
    let bundle_path = directory.path().join("candidate.bundle");
    git(
        git_executable,
        &repository,
        [
            "bundle",
            "create",
            path_str(&bundle_path)?,
            "refs/heads/auths-candidate",
        ],
    )?;
    let declared_candidate_revision = if variant == DemoVariant::CandidateChanged {
        different_oid(&candidate_revision)?
    } else {
        candidate_revision
    };
    Ok(CandidateSubmission {
        bundle: fs::read(bundle_path).map_err(|_| ScenarioError)?,
        base_revision: base_revision.clone(),
        candidate_revision: declared_candidate_revision,
    })
}

fn different_oid(oid: &GitOid) -> Result<GitOid, ScenarioError> {
    let mut bytes = oid.as_str().as_bytes().to_vec();
    let first = bytes.first_mut().ok_or(ScenarioError)?;
    *first = if *first == b'0' { b'1' } else { b'0' };
    GitOid::parse(String::from_utf8(bytes).map_err(|_| ScenarioError)?).map_err(|_| ScenarioError)
}

/// Confirms the candidate sandbox has no credential by attempting a dry-run
/// push with all credential sources disabled.
pub fn direct_push_is_rejected(
    git_executable: &Path,
    repository_url: &str,
    repository_path: &Path,
    candidate_revision: &GitOid,
    workflow_id: &WorkflowId,
) -> Result<bool, ScenarioError> {
    let refspec = format!(
        "{}:refs/heads/auths-direct-{}",
        candidate_revision,
        &workflow_id.as_str()[..12]
    );
    let output = git_output(
        git_executable,
        repository_path,
        ["push", "--dry-run", repository_url, refspec.as_str()],
    )?;
    Ok(!output.status.success())
}

fn git<I, S>(executable: &Path, current: &Path, args: I) -> Result<(), ScenarioError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = git_output(executable, current, args)?;
    if output.status.success()
        && output.stdout.len() <= 1024 * 1024
        && output.stderr.len() <= 1024 * 1024
    {
        Ok(())
    } else {
        Err(ScenarioError)
    }
}

fn output<I, S>(executable: &Path, current: &Path, args: I) -> Result<String, ScenarioError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = git_output(executable, current, args)?;
    if !output.status.success() || output.stdout.len() > 1024 * 1024 {
        return Err(ScenarioError);
    }
    String::from_utf8(output.stdout).map_err(|_| ScenarioError)
}

fn git_output<I, S>(executable: &Path, current: &Path, args: I) -> Result<Output, ScenarioError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(executable)
        .current_dir(current)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", current)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "2")
        .env("GIT_CONFIG_KEY_0", "credential.helper")
        .env("GIT_CONFIG_VALUE_0", "")
        .env("GIT_CONFIG_KEY_1", "core.hooksPath")
        .env("GIT_CONFIG_VALUE_1", "/dev/null")
        .args(args)
        .output()
        .map_err(|_| ScenarioError)
}

fn path_str(path: &Path) -> Result<&str, ScenarioError> {
    path.to_str().ok_or(ScenarioError)
}

/// Closed deterministic scenario failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("could not build GitHub demo scenario")]
pub struct ScenarioError;
