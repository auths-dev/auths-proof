//! Bounded Git bundle inspection isolated from any executor checkout.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    process::{Command, ExitStatus, Stdio},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

use crate::{
    canonical::sha256,
    types::{
        CandidateFacts, CandidateSubmission, GitOid, PathChange, ValidationError,
        VerifierConfiguration,
    },
};

const CANDIDATE_REF: &str = "refs/heads/auths-candidate";
const MAX_PROCESS_OUTPUT_BYTES: u64 = 1024 * 1024;
const GIT_TIMEOUT: Duration = Duration::from_secs(15);

/// Candidate facts plus the isolated repository in which they were derived.
pub struct InspectedCandidate {
    facts: CandidateFacts,
    repository: TempDir,
}

impl InspectedCandidate {
    /// Returns trusted facts derived from the submitted bundle.
    #[must_use]
    pub const fn facts(&self) -> &CandidateFacts {
        &self.facts
    }

    /// Returns the isolated repository used by the eventual sealed executor.
    #[must_use]
    pub fn repository_path(&self) -> &Path {
        self.repository.path()
    }
}

/// Production candidate inspector using a fixed Git executable.
#[derive(Clone, Debug)]
pub struct GitCandidateInspector {
    git_executable: PathBuf,
}

impl GitCandidateInspector {
    /// Uses the supplied absolute Git executable.
    ///
    /// # Errors
    ///
    /// Rejects a relative executable so `PATH` cannot select an implementation.
    pub fn new(git_executable: impl Into<PathBuf>) -> Result<Self, CandidateError> {
        let git_executable = git_executable.into();
        if !git_executable.is_absolute() {
            return Err(CandidateError::InvalidConfiguration);
        }
        Ok(Self { git_executable })
    }

    /// Inspects one self-contained bundle under exact configuration limits.
    ///
    /// # Errors
    ///
    /// Returns a closed failure for malformed Git input, unexpected refs,
    /// history shape, object types, limits, I/O, or a timed-out subprocess.
    pub fn inspect(
        &self,
        submission: &CandidateSubmission,
        configuration: &VerifierConfiguration,
    ) -> Result<InspectedCandidate, CandidateError> {
        configuration
            .validate()
            .map_err(|_| CandidateError::InvalidConfiguration)?;
        let bundle_len =
            u64::try_from(submission.bundle.len()).map_err(|_| CandidateError::LimitExceeded)?;
        if submission.bundle.is_empty() || bundle_len > configuration.maximum_bundle_bytes() {
            return Err(CandidateError::LimitExceeded);
        }

        let (repository, commit_oids) = self.prepare_repository(submission, configuration)?;

        let changes = self.changed_paths(
            repository.path(),
            &submission.base_oid,
            &submission.candidate_oid,
            configuration,
        )?;
        let (expanded_bytes, object_count) = self.object_inventory(
            repository.path(),
            &submission.base_oid,
            &submission.candidate_oid,
            configuration,
        )?;
        let facts = CandidateFacts::new(
            submission.base_oid.clone(),
            submission.candidate_oid.clone(),
            commit_oids,
            changes,
            sha256(&submission.bundle),
            expanded_bytes,
            object_count,
        )
        .map_err(CandidateError::Validation)?;
        Ok(InspectedCandidate { facts, repository })
    }

    fn prepare_repository(
        &self,
        submission: &CandidateSubmission,
        configuration: &VerifierConfiguration,
    ) -> Result<(TempDir, Vec<GitOid>), CandidateError> {
        let repository = tempfile::tempdir().map_err(|_| CandidateError::Io)?;
        let bundle_path = repository.path().join("candidate.bundle");
        fs::write(&bundle_path, &submission.bundle).map_err(|_| CandidateError::Io)?;
        self.git(repository.path(), ["init", "--quiet"])?;
        let bundle = bundle_path
            .to_str()
            .ok_or(CandidateError::InvalidConfiguration)?;
        self.git(repository.path(), ["bundle", "verify", bundle])?;
        let heads = self.git(repository.path(), ["bundle", "list-heads", bundle])?;
        validate_bundle_head(&heads.stdout, &submission.candidate_oid)?;
        self.git(
            repository.path(),
            [
                "fetch",
                "--quiet",
                "--no-tags",
                bundle,
                "refs/heads/auths-candidate:refs/heads/auths-candidate",
            ],
        )?;
        self.validate_history(repository.path(), submission)?;
        let range = format!("{}..{}", submission.base_oid, submission.candidate_oid);
        let commits = self.git(repository.path(), ["rev-list", "--reverse", range.as_str()])?;
        let commit_oids = commits
            .stdout
            .lines()
            .map(GitOid::parse)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CandidateError::MalformedGitOutput)?;
        if commit_oids.is_empty()
            || commit_oids.len()
                > usize::try_from(configuration.maximum_objects()).unwrap_or(usize::MAX)
        {
            return Err(CandidateError::LimitExceeded);
        }
        Ok((repository, commit_oids))
    }

    fn validate_history(
        &self,
        repository: &Path,
        submission: &CandidateSubmission,
    ) -> Result<(), CandidateError> {
        let base = format!("{}^{{commit}}", submission.base_oid);
        self.git(repository, ["cat-file", "-e", base.as_str()])
            .map_err(|_| CandidateError::InvalidHistory)?;
        let candidate = self.git(
            repository,
            [
                "rev-parse",
                "--verify",
                "refs/heads/auths-candidate^{commit}",
            ],
        )?;
        if candidate.stdout.trim() != submission.candidate_oid.as_str() {
            return Err(CandidateError::InvalidHistory);
        }
        self.git(
            repository,
            [
                "merge-base",
                "--is-ancestor",
                submission.base_oid.as_str(),
                submission.candidate_oid.as_str(),
            ],
        )
        .map(|_| ())
        .map_err(|_| CandidateError::InvalidHistory)
    }

    fn changed_paths(
        &self,
        repository: &Path,
        base: &GitOid,
        candidate: &GitOid,
        configuration: &VerifierConfiguration,
    ) -> Result<Vec<PathChange>, CandidateError> {
        let output = self.git_bytes(
            repository,
            [
                "diff",
                "--raw",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                "--no-abbrev",
                base.as_str(),
                candidate.as_str(),
                "--",
            ],
        )?;
        let fields = output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.is_empty() || fields.len() % 2 != 0 {
            return Err(CandidateError::MalformedGitOutput);
        }
        let mut changes = Vec::with_capacity(fields.len() / 2);
        for pair in fields.chunks_exact(2) {
            let header =
                std::str::from_utf8(pair[0]).map_err(|_| CandidateError::MalformedGitOutput)?;
            let path =
                std::str::from_utf8(pair[1]).map_err(|_| CandidateError::MalformedGitOutput)?;
            if path.len() > usize::from(configuration.maximum_path_bytes())
                || path.split('/').count() > usize::from(configuration.maximum_tree_depth())
            {
                return Err(CandidateError::LimitExceeded);
            }
            let values = header
                .strip_prefix(':')
                .ok_or(CandidateError::MalformedGitOutput)?
                .split_ascii_whitespace()
                .collect::<Vec<_>>();
            if values.len() != 5 || !matches!(values[4], "A" | "M" | "D") {
                return Err(CandidateError::UnsupportedChange);
            }
            let old_mode = parse_mode(values[0])?;
            let new_mode = parse_mode(values[1])?;
            let old_oid = parse_optional_oid(values[2])?;
            let new_oid = parse_optional_oid(values[3])?;
            let changed_bytes = self
                .blob_size(repository, old_oid.as_ref())?
                .checked_add(self.blob_size(repository, new_oid.as_ref())?)
                .ok_or(CandidateError::LimitExceeded)?;
            changes.push(
                PathChange::new(path, old_oid, new_oid, old_mode, new_mode, changed_bytes)
                    .map_err(CandidateError::Validation)?,
            );
        }
        Ok(changes)
    }

    fn blob_size(&self, repository: &Path, oid: Option<&GitOid>) -> Result<u64, CandidateError> {
        let Some(oid) = oid else {
            return Ok(0);
        };
        let kind = self.git(repository, ["cat-file", "-t", oid.as_str()])?;
        if kind.stdout.trim() != "blob" {
            return Err(CandidateError::UnsupportedObject);
        }
        self.git(repository, ["cat-file", "-s", oid.as_str()])?
            .stdout
            .trim()
            .parse()
            .map_err(|_| CandidateError::MalformedGitOutput)
    }

    fn object_inventory(
        &self,
        repository: &Path,
        base: &GitOid,
        candidate: &GitOid,
        configuration: &VerifierConfiguration,
    ) -> Result<(u64, u32), CandidateError> {
        let output = self.git(
            repository,
            ["rev-list", "--objects", &format!("{base}..{candidate}")],
        )?;
        let mut objects = BTreeSet::new();
        for line in output.stdout.lines() {
            let oid = line
                .split_ascii_whitespace()
                .next()
                .ok_or(CandidateError::MalformedGitOutput)?;
            objects.insert(GitOid::parse(oid).map_err(|_| CandidateError::MalformedGitOutput)?);
            if objects.len()
                > usize::try_from(configuration.maximum_objects()).unwrap_or(usize::MAX)
            {
                return Err(CandidateError::LimitExceeded);
            }
        }
        if objects.is_empty() {
            return Err(CandidateError::InvalidHistory);
        }
        let mut expanded_bytes = 0_u64;
        for oid in &objects {
            let size = self
                .git(repository, ["cat-file", "-s", oid.as_str()])?
                .stdout
                .trim()
                .parse::<u64>()
                .map_err(|_| CandidateError::MalformedGitOutput)?;
            expanded_bytes = expanded_bytes
                .checked_add(size)
                .ok_or(CandidateError::LimitExceeded)?;
            if expanded_bytes > configuration.maximum_expanded_bytes() {
                return Err(CandidateError::LimitExceeded);
            }
        }
        Ok((
            expanded_bytes,
            u32::try_from(objects.len()).map_err(|_| CandidateError::LimitExceeded)?,
        ))
    }

    fn git<const N: usize>(
        &self,
        repository: &Path,
        arguments: [&str; N],
    ) -> Result<GitOutput, CandidateError> {
        let output = self.run_git(repository, arguments)?;
        String::from_utf8(output.stdout)
            .map(|stdout| GitOutput { stdout })
            .map_err(|_| CandidateError::MalformedGitOutput)
    }

    fn git_bytes<const N: usize>(
        &self,
        repository: &Path,
        arguments: [&str; N],
    ) -> Result<RawGitOutput, CandidateError> {
        self.run_git(repository, arguments)
    }

    fn run_git<const N: usize>(
        &self,
        repository: &Path,
        arguments: [&str; N],
    ) -> Result<RawGitOutput, CandidateError> {
        let stdout_path = repository.join("git.stdout");
        let stderr_path = repository.join("git.stderr");
        let stdout = File::create(&stdout_path).map_err(|_| CandidateError::Io)?;
        let stderr = File::create(&stderr_path).map_err(|_| CandidateError::Io)?;
        let mut command = Command::new(&self.git_executable);
        command
            .current_dir(repository)
            .args(arguments)
            .env_clear()
            .env("HOME", repository)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn().map_err(|_| CandidateError::Io)?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| CandidateError::Io)? {
                break status;
            }
            if started.elapsed() >= GIT_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(CandidateError::TimedOut);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let stdout = read_bounded(&stdout_path)?;
        let stderr = read_bounded(&stderr_path)?;
        if !status.success() {
            return Err(CandidateError::Git {
                status,
                stderr: String::from_utf8_lossy(&stderr).into_owned(),
            });
        }
        Ok(RawGitOutput { stdout })
    }
}

struct GitOutput {
    stdout: String,
}

struct RawGitOutput {
    stdout: Vec<u8>,
}

fn validate_bundle_head(output: &str, candidate_oid: &GitOid) -> Result<(), CandidateError> {
    let mut lines = output.lines();
    let Some(head) = lines.next() else {
        return Err(CandidateError::UnexpectedRef);
    };
    if lines.next().is_some() {
        return Err(CandidateError::UnexpectedRef);
    }
    let Some((head_oid, head_ref)) = head.split_once(' ') else {
        return Err(CandidateError::UnexpectedRef);
    };
    if head_ref != CANDIDATE_REF || head_oid != candidate_oid.as_str() {
        return Err(CandidateError::UnexpectedRef);
    }
    Ok(())
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, CandidateError> {
    let mut file = File::open(path).map_err(|_| CandidateError::Io)?;
    let length = file.metadata().map_err(|_| CandidateError::Io)?.len();
    if length > MAX_PROCESS_OUTPUT_BYTES {
        return Err(CandidateError::LimitExceeded);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| CandidateError::Io)?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| CandidateError::LimitExceeded)?);
    file.read_to_end(&mut bytes)
        .map_err(|_| CandidateError::Io)?;
    Ok(bytes)
}

fn parse_mode(value: &str) -> Result<Option<u32>, CandidateError> {
    if value == "000000" {
        return Ok(None);
    }
    u32::from_str_radix(value, 8)
        .map(Some)
        .map_err(|_| CandidateError::MalformedGitOutput)
}

fn parse_optional_oid(value: &str) -> Result<Option<GitOid>, CandidateError> {
    if value == "0000000000000000000000000000000000000000" {
        return Ok(None);
    }
    GitOid::parse(value)
        .map(Some)
        .map_err(|_| CandidateError::MalformedGitOutput)
}

/// Closed candidate inspection failure.
#[derive(Debug, thiserror::Error)]
pub enum CandidateError {
    /// Inspector configuration is unsafe.
    #[error("invalid candidate inspector configuration")]
    InvalidConfiguration,
    /// Input or derived output exceeds a hard limit.
    #[error("candidate inspection limit exceeded")]
    LimitExceeded,
    /// Bundle contains an unexpected or ambiguous reference.
    #[error("candidate bundle must contain exactly refs/heads/auths-candidate")]
    UnexpectedRef,
    /// Candidate is not a strict descendant of the base.
    #[error("candidate history does not descend from the granted base")]
    InvalidHistory,
    /// Git returned an unsupported output shape.
    #[error("malformed Git output")]
    MalformedGitOutput,
    /// Change status is outside the MVP.
    #[error("rename, copy, type change, or combined diff is unsupported")]
    UnsupportedChange,
    /// Candidate contains an unsupported Git object.
    #[error("candidate contains an unsupported object type")]
    UnsupportedObject,
    /// Validated profile fact construction failed.
    #[error("invalid inspected candidate: {0}")]
    Validation(ValidationError),
    /// A bounded local subprocess timed out.
    #[error("Git inspection timed out")]
    TimedOut,
    /// Filesystem or process I/O failed.
    #[error("candidate inspection I/O failed")]
    Io,
    /// Git rejected the candidate.
    #[error("Git rejected candidate with {status}: {stderr}")]
    Git {
        /// Git process status.
        status: ExitStatus,
        /// Bounded diagnostic output.
        stderr: String,
    },
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::{test_support::configuration, types::CandidateSubmission};

    #[test]
    fn real_bundle_is_inspected_without_trusting_declared_facts() {
        let fixture = GitFixture::new("auths-candidate");
        let submission = CandidateSubmission {
            bundle: fs::read(&fixture.bundle).unwrap(),
            base_oid: GitOid::parse(&fixture.base).unwrap(),
            candidate_oid: GitOid::parse(&fixture.candidate).unwrap(),
            patch_title: "Exact change".into(),
            patch_body: "A bounded candidate".into(),
        };
        let inspected = GitCandidateInspector::new("/usr/bin/git")
            .unwrap()
            .inspect(&submission, &configuration(30))
            .unwrap();

        assert_eq!(inspected.facts().base_oid().as_str(), fixture.base);
        assert_eq!(
            inspected.facts().candidate_oid().as_str(),
            fixture.candidate
        );
        assert_eq!(inspected.facts().commit_oids().len(), 1);
        assert_eq!(inspected.facts().changes()[0].path(), "src/lib.rs");
    }

    #[test]
    fn bundle_with_any_other_ref_is_rejected_before_fetch() {
        let fixture = GitFixture::new("not-the-candidate");
        let submission = CandidateSubmission {
            bundle: fs::read(&fixture.bundle).unwrap(),
            base_oid: GitOid::parse(&fixture.base).unwrap(),
            candidate_oid: GitOid::parse(&fixture.candidate).unwrap(),
            patch_title: "Exact change".into(),
            patch_body: "A bounded candidate".into(),
        };
        let error = GitCandidateInspector::new("/usr/bin/git")
            .unwrap()
            .inspect(&submission, &configuration(30))
            .err()
            .unwrap();

        assert!(matches!(error, CandidateError::UnexpectedRef));
    }

    struct GitFixture {
        _directory: TempDir,
        bundle: PathBuf,
        base: String,
        candidate: String,
    }

    impl GitFixture {
        fn new(branch: &str) -> Self {
            let directory = tempfile::tempdir().unwrap();
            run(
                directory.path(),
                ["init", "--quiet", "--initial-branch=main"],
            );
            run(directory.path(), ["config", "user.name", "Auths Tests"]);
            run(
                directory.path(),
                ["config", "user.email", "tests@auths.dev"],
            );
            fs::create_dir_all(directory.path().join("src")).unwrap();
            fs::write(
                directory.path().join("src/lib.rs"),
                b"pub fn value() -> u8 { 1 }\n",
            )
            .unwrap();
            run(directory.path(), ["add", "src/lib.rs"]);
            run(
                directory.path(),
                [
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "commit",
                    "--quiet",
                    "-m",
                    "base",
                ],
            );
            let base = output(directory.path(), ["rev-parse", "HEAD"]);

            fs::write(
                directory.path().join("src/lib.rs"),
                b"pub fn value() -> u8 { 2 }\n",
            )
            .unwrap();
            run(directory.path(), ["add", "src/lib.rs"]);
            run(
                directory.path(),
                [
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "core.hooksPath=/dev/null",
                    "commit",
                    "--quiet",
                    "-m",
                    "candidate",
                ],
            );
            let candidate = output(directory.path(), ["rev-parse", "HEAD"]);
            run(directory.path(), ["branch", branch, "HEAD"]);
            let bundle = directory.path().join("candidate.bundle");
            run(
                directory.path(),
                [
                    "bundle",
                    "create",
                    bundle.to_str().unwrap(),
                    &format!("refs/heads/{branch}"),
                ],
            );
            Self {
                _directory: directory,
                bundle,
                base,
                candidate,
            }
        }
    }

    fn run<const N: usize>(repository: &Path, arguments: [&str; N]) {
        assert!(
            Command::new("/usr/bin/git")
                .current_dir(repository)
                .args(arguments)
                .status()
                .unwrap()
                .success()
        );
    }

    fn output<const N: usize>(repository: &Path, arguments: [&str; N]) -> String {
        let output = Command::new("/usr/bin/git")
            .current_dir(repository)
            .args(arguments)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().into()
    }
}
