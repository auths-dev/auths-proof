//! Bounded Git-bundle inspection in a fresh bare quarantine.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::{
    canonical::{canonical_digest, sha256},
    policy::{PathDecision, evaluate_path, validate_tree_path},
    types::{
        CandidatePolicy, DigestHex, GitOid, HARD_MAX_CANDIDATE_BYTES, HARD_MAX_GIT_OBJECTS,
        HARD_MAX_PATH_BYTES, ObjectFormat,
    },
};

const CANDIDATE_REF: &str = "refs/heads/auths-candidate";
const QUARANTINE_REF: &str = "refs/auths/candidate";
const MAX_GIT_OUTPUT_BYTES: usize = 4 * 1024 * 1024;
const HARD_MAX_EXPANDED_BYTES: u64 = 64 * 1024 * 1024;

/// Hostile candidate transport.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CandidateSubmission {
    /// Bounded Git bundle bytes.
    pub bundle: Vec<u8>,
    /// Caller-declared exact base.
    pub base_revision: GitOid,
    /// Caller-declared exact candidate.
    pub candidate_revision: GitOid,
}

/// One changed path and its exact mode/byte accounting.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathChange {
    /// Repository-root-relative UTF-8 path.
    pub path: String,
    /// Old Git mode, or zero for an addition.
    pub old_mode: u32,
    /// New Git mode, or zero for a deletion.
    pub new_mode: u32,
    /// Added bytes reported by Git.
    pub added_bytes: u64,
    /// Deleted bytes reported by Git.
    pub deleted_bytes: u64,
}

/// Trusted facts derived without checking out or executing candidate content.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateEvidence {
    base_revision: GitOid,
    candidate_revision: GitOid,
    candidate_tree: GitOid,
    commit_count: u16,
    object_count: u32,
    expanded_object_bytes: u64,
    changed_paths: Vec<PathChange>,
    added_bytes: u64,
    deleted_bytes: u64,
    bundle_digest: DigestHex,
    change_set_digest: DigestHex,
}

impl CandidateEvidence {
    /// Exact base revision.
    #[must_use]
    pub const fn base_revision(&self) -> &GitOid {
        &self.base_revision
    }

    /// Exact candidate revision.
    #[must_use]
    pub const fn candidate_revision(&self) -> &GitOid {
        &self.candidate_revision
    }

    /// Exact candidate tree.
    #[must_use]
    pub const fn candidate_tree(&self) -> &GitOid {
        &self.candidate_tree
    }

    /// Introduced commit count.
    #[must_use]
    pub const fn commit_count(&self) -> u16 {
        self.commit_count
    }

    /// Parsed object count.
    #[must_use]
    pub const fn object_count(&self) -> u32 {
        self.object_count
    }

    /// Changed paths.
    #[must_use]
    pub fn changed_paths(&self) -> &[PathChange] {
        &self.changed_paths
    }

    /// Added byte total.
    #[must_use]
    pub const fn added_bytes(&self) -> u64 {
        self.added_bytes
    }

    /// Deleted byte total.
    #[must_use]
    pub const fn deleted_bytes(&self) -> u64 {
        self.deleted_bytes
    }

    /// Bundle commitment.
    #[must_use]
    pub const fn bundle_digest(&self) -> &DigestHex {
        &self.bundle_digest
    }

    /// Changed-tree commitment.
    #[must_use]
    pub const fn change_set_digest(&self) -> &DigestHex {
        &self.change_set_digest
    }

    /// Canonical evidence commitment.
    ///
    /// # Errors
    ///
    /// Returns a canonicalization failure.
    pub fn digest(&self) -> Result<DigestHex, crate::canonical::CanonicalError> {
        canonical_digest(self)
    }
}

/// Candidate evidence plus the isolated repository required for exact push.
pub struct QuarantinedCandidate {
    directory: TempDir,
    repository: PathBuf,
    evidence: CandidateEvidence,
}

impl QuarantinedCandidate {
    /// Isolated bare repository.
    #[must_use]
    pub fn repository_path(&self) -> &Path {
        &self.repository
    }

    /// Trusted candidate evidence.
    #[must_use]
    pub const fn evidence(&self) -> &CandidateEvidence {
        &self.evidence
    }

    /// Keeps the quarantine owned until this object drops.
    #[must_use]
    pub fn quarantine_path(&self) -> &Path {
        self.directory.path()
    }
}

/// Version-pinned local Git candidate inspector.
#[derive(Clone, Debug)]
pub struct GitCandidateInspector {
    git_executable: PathBuf,
}

impl GitCandidateInspector {
    /// Configures one absolute Git executable.
    ///
    /// # Errors
    ///
    /// Rejects relative paths.
    pub fn new(git_executable: impl Into<PathBuf>) -> Result<Self, CandidateError> {
        let git_executable = git_executable.into();
        if !git_executable.is_absolute() {
            return Err(CandidateError::InvalidConfiguration);
        }
        Ok(Self { git_executable })
    }

    /// Imports and inspects one bundle in a fresh bare quarantine.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed Git, unexpected refs, history/mode/path
    /// violations, and every hard or grant-selected limit.
    #[allow(
        clippy::too_many_lines,
        reason = "security-relevant Git inspection order remains linear and auditable"
    )]
    pub fn inspect(
        &self,
        submission: &CandidateSubmission,
        policy: &CandidatePolicy,
        object_format: ObjectFormat,
    ) -> Result<QuarantinedCandidate, CandidateError> {
        policy
            .validate()
            .map_err(|_| CandidateError::InvalidConfiguration)?;
        if submission.bundle.is_empty()
            || submission.bundle.len() as u64 > policy.maximum_candidate_bytes
            || submission.bundle.len() as u64 > HARD_MAX_CANDIDATE_BYTES
            || !object_format.matches(&submission.base_revision)
            || !object_format.matches(&submission.candidate_revision)
        {
            return Err(CandidateError::LimitExceeded);
        }

        let directory = tempfile::tempdir().map_err(|_| CandidateError::Io)?;
        let repository = directory.path().join("repository.git");
        let bundle_path = directory.path().join("candidate.bundle");
        fs::write(&bundle_path, &submission.bundle).map_err(|_| CandidateError::Io)?;
        self.git(
            directory.path(),
            ["init", "--bare", repository_arg(&repository)?],
        )?;

        let heads = self.git(
            &repository,
            ["bundle", "list-heads", repository_arg(&bundle_path)?],
        )?;
        let heads = utf8_output(&heads)?;
        let listed = heads
            .lines()
            .map(|line| line.split_whitespace().collect::<Vec<_>>())
            .collect::<Vec<_>>();
        if listed.len() != 1
            || listed[0].len() != 2
            || listed[0][1] != CANDIDATE_REF
            || listed[0][0] != submission.candidate_revision.as_str()
        {
            return Err(CandidateError::UnexpectedRef);
        }

        self.git(
            &repository,
            [
                "fetch",
                "--no-tags",
                repository_arg(&bundle_path)?,
                &format!("{CANDIDATE_REF}:{QUARANTINE_REF}"),
            ],
        )?;
        self.git(&repository, ["fsck", "--strict", "--no-dangling"])?;
        let imported = self.git(&repository, ["rev-parse", QUARANTINE_REF])?;
        if utf8_output(&imported)?.trim() != submission.candidate_revision.as_str() {
            return Err(CandidateError::InvalidHistory);
        }
        self.git(
            &repository,
            [
                "cat-file",
                "-e",
                &format!("{}^{{commit}}", submission.base_revision),
            ],
        )?;
        self.git(
            &repository,
            [
                "merge-base",
                "--is-ancestor",
                submission.base_revision.as_str(),
                submission.candidate_revision.as_str(),
            ],
        )?;

        let history = self.git(
            &repository,
            [
                "rev-list",
                "--parents",
                &format!(
                    "{}..{}",
                    submission.base_revision, submission.candidate_revision
                ),
            ],
        )?;
        let history = utf8_output(&history)?;
        let commit_lines = history
            .lines()
            .filter(|line| !line.trim().is_empty())
            .collect::<Vec<_>>();
        let commit_count =
            u16::try_from(commit_lines.len()).map_err(|_| CandidateError::LimitExceeded)?;
        if commit_count == 0 || commit_count > policy.maximum_commits {
            return Err(CandidateError::LimitExceeded);
        }
        if !policy.allow_merge_commits
            && commit_lines
                .iter()
                .any(|line| line.split_whitespace().count() > 2)
        {
            return Err(CandidateError::MergeCommitDenied);
        }

        let objects = self.git(
            &repository,
            [
                "rev-list",
                "--objects",
                submission.candidate_revision.as_str(),
                "--not",
                submission.base_revision.as_str(),
            ],
        )?;
        let objects = utf8_output(&objects)?;
        let object_ids = objects
            .lines()
            .filter_map(|line| line.split_whitespace().next())
            .collect::<Vec<_>>();
        let object_count =
            u32::try_from(object_ids.len()).map_err(|_| CandidateError::LimitExceeded)?;
        if object_count > policy.maximum_git_objects || object_count > HARD_MAX_GIT_OBJECTS {
            return Err(CandidateError::LimitExceeded);
        }
        let expanded_object_bytes = self.object_bytes(&repository, &object_ids)?;
        if expanded_object_bytes > HARD_MAX_EXPANDED_BYTES {
            return Err(CandidateError::LimitExceeded);
        }

        let tree = self.git(
            &repository,
            [
                "rev-parse",
                &format!("{}^{{tree}}", submission.candidate_revision),
            ],
        )?;
        let candidate_tree =
            GitOid::parse(utf8_output(&tree)?.trim()).map_err(|_| CandidateError::Malformed)?;
        if !object_format.matches(&candidate_tree) {
            return Err(CandidateError::Malformed);
        }

        let modes = self.git(
            &repository,
            [
                "diff",
                "--raw",
                "-z",
                "--no-renames",
                submission.base_revision.as_str(),
                submission.candidate_revision.as_str(),
            ],
        )?;
        let stats = self.git(
            &repository,
            [
                "diff",
                "--numstat",
                "-z",
                "--no-renames",
                submission.base_revision.as_str(),
                submission.candidate_revision.as_str(),
            ],
        )?;
        let mut changes = parse_modes(&modes.stdout)?;
        apply_stats(&mut changes, &stats.stdout)?;
        let changed_files =
            u32::try_from(changes.len()).map_err(|_| CandidateError::LimitExceeded)?;
        if changed_files == 0 || changed_files > policy.maximum_changed_files {
            return Err(CandidateError::LimitExceeded);
        }

        let mut added_bytes = 0_u64;
        let mut deleted_bytes = 0_u64;
        let mut ordered = Vec::with_capacity(changes.len());
        for (_, change) in changes {
            enforce_change(&change, policy)?;
            added_bytes = added_bytes
                .checked_add(change.added_bytes)
                .ok_or(CandidateError::LimitExceeded)?;
            deleted_bytes = deleted_bytes
                .checked_add(change.deleted_bytes)
                .ok_or(CandidateError::LimitExceeded)?;
            ordered.push(change);
        }
        if added_bytes > policy.maximum_added_bytes || deleted_bytes > policy.maximum_deleted_bytes
        {
            return Err(CandidateError::LimitExceeded);
        }

        let change_set_digest = canonical_digest(&(
            &submission.base_revision,
            &submission.candidate_revision,
            &candidate_tree,
            &ordered,
        ))
        .map_err(|_| CandidateError::Malformed)?;
        let evidence = CandidateEvidence {
            base_revision: submission.base_revision.clone(),
            candidate_revision: submission.candidate_revision.clone(),
            candidate_tree,
            commit_count,
            object_count,
            expanded_object_bytes,
            changed_paths: ordered,
            added_bytes,
            deleted_bytes,
            bundle_digest: sha256(&submission.bundle),
            change_set_digest,
        };
        Ok(QuarantinedCandidate {
            directory,
            repository,
            evidence,
        })
    }

    fn object_bytes(&self, repository: &Path, object_ids: &[&str]) -> Result<u64, CandidateError> {
        if object_ids.is_empty() {
            return Ok(0);
        }
        let mut child = self
            .command(repository)
            .args([
                "cat-file",
                "--batch-check=%(objectname) %(objecttype) %(objectsize)",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| CandidateError::Io)?;
        {
            let stdin = child.stdin.as_mut().ok_or(CandidateError::Io)?;
            for object in object_ids {
                writeln!(stdin, "{object}").map_err(|_| CandidateError::Io)?;
            }
        }
        let output = child.wait_with_output().map_err(|_| CandidateError::Io)?;
        ensure_output(&output)?;
        let output = utf8_output(&output)?;
        output.lines().try_fold(0_u64, |total, line| {
            let size = line
                .split_whitespace()
                .nth(2)
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(CandidateError::Malformed)?;
            total.checked_add(size).ok_or(CandidateError::LimitExceeded)
        })
    }

    fn command(&self, repository: &Path) -> Command {
        let mut command = Command::new(&self.git_executable);
        command
            .current_dir(repository)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", repository)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_CONFIG_COUNT", "4")
            .env("GIT_CONFIG_KEY_0", "credential.helper")
            .env("GIT_CONFIG_VALUE_0", "")
            .env("GIT_CONFIG_KEY_1", "core.hooksPath")
            .env("GIT_CONFIG_VALUE_1", "/dev/null")
            .env("GIT_CONFIG_KEY_2", "core.attributesFile")
            .env("GIT_CONFIG_VALUE_2", "/dev/null")
            .env("GIT_CONFIG_KEY_3", "diff.external")
            .env("GIT_CONFIG_VALUE_3", "");
        command
    }

    fn git<I, S>(&self, repository: &Path, args: I) -> Result<Output, CandidateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self
            .command(repository)
            .args(args)
            .output()
            .map_err(|_| CandidateError::Io)?;
        ensure_output(&output)?;
        Ok(output)
    }
}

fn repository_arg(path: &Path) -> Result<&str, CandidateError> {
    path.to_str().ok_or(CandidateError::InvalidConfiguration)
}

fn ensure_output(output: &Output) -> Result<(), CandidateError> {
    if output.stdout.len() > MAX_GIT_OUTPUT_BYTES || output.stderr.len() > MAX_GIT_OUTPUT_BYTES {
        return Err(CandidateError::LimitExceeded);
    }
    if !output.status.success() {
        return Err(CandidateError::Git);
    }
    Ok(())
}

fn utf8_output(output: &Output) -> Result<&str, CandidateError> {
    std::str::from_utf8(&output.stdout).map_err(|_| CandidateError::Malformed)
}

fn parse_modes(bytes: &[u8]) -> Result<BTreeMap<String, PathChange>, CandidateError> {
    let fields = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut changes = BTreeMap::new();
    let mut index = 0;
    while index < fields.len() {
        if fields[index].is_empty() {
            break;
        }
        let header = std::str::from_utf8(fields[index]).map_err(|_| CandidateError::NonUtf8Path)?;
        let path = fields.get(index + 1).ok_or(CandidateError::Malformed)?;
        let path = std::str::from_utf8(path).map_err(|_| CandidateError::NonUtf8Path)?;
        validate_tree_path(path).map_err(|_| CandidateError::Malformed)?;
        let mut parts = header.split_whitespace();
        let old_mode = parse_mode(parts.next().ok_or(CandidateError::Malformed)?)?;
        let new_mode = parse_mode(parts.next().ok_or(CandidateError::Malformed)?)?;
        let _old_oid = parts.next().ok_or(CandidateError::Malformed)?;
        let _new_oid = parts.next().ok_or(CandidateError::Malformed)?;
        let status = parts.next().ok_or(CandidateError::Malformed)?;
        if !matches!(status, "A" | "D" | "M" | "T") || parts.next().is_some() {
            return Err(CandidateError::UnsupportedChange);
        }
        if changes
            .insert(
                path.into(),
                PathChange {
                    path: path.into(),
                    old_mode,
                    new_mode,
                    added_bytes: 0,
                    deleted_bytes: 0,
                },
            )
            .is_some()
        {
            return Err(CandidateError::Malformed);
        }
        index += 2;
    }
    Ok(changes)
}

fn parse_mode(value: &str) -> Result<u32, CandidateError> {
    value
        .strip_prefix(':')
        .unwrap_or(value)
        .parse::<u32>()
        .map_err(|_| CandidateError::Malformed)
}

fn apply_stats(
    changes: &mut BTreeMap<String, PathChange>,
    bytes: &[u8],
) -> Result<(), CandidateError> {
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
    {
        let record = std::str::from_utf8(record).map_err(|_| CandidateError::NonUtf8Path)?;
        let mut fields = record.splitn(3, '\t');
        let added = parse_stat(fields.next().ok_or(CandidateError::Malformed)?)?;
        let deleted = parse_stat(fields.next().ok_or(CandidateError::Malformed)?)?;
        let path = fields.next().ok_or(CandidateError::Malformed)?;
        let change = changes.get_mut(path).ok_or(CandidateError::Malformed)?;
        change.added_bytes = added;
        change.deleted_bytes = deleted;
    }
    Ok(())
}

fn parse_stat(value: &str) -> Result<u64, CandidateError> {
    if value == "-" {
        return Err(CandidateError::UnsupportedChange);
    }
    value.parse().map_err(|_| CandidateError::Malformed)
}

fn enforce_change(change: &PathChange, policy: &CandidatePolicy) -> Result<(), CandidateError> {
    if change.path.len() > HARD_MAX_PATH_BYTES {
        return Err(CandidateError::LimitExceeded);
    }
    match evaluate_path(&change.path, &policy.allowed_paths, &policy.denied_paths) {
        PathDecision::Allowed => {}
        PathDecision::ExplicitlyDenied => return Err(CandidateError::PathExplicitlyDenied),
        PathDecision::NotAllowed => return Err(CandidateError::PathNotAllowed),
        PathDecision::Malformed => return Err(CandidateError::Malformed),
    }
    if (!policy.allow_git_attributes_changes && change.path == ".gitattributes")
        || (!policy.allow_gitmodules_changes && change.path == ".gitmodules")
        || (!policy.allow_repository_automation_changes
            && (change.path == "CODEOWNERS"
                || change.path.ends_with("/CODEOWNERS")
                || change.path.starts_with(".github/")))
    {
        return Err(CandidateError::PathExplicitlyDenied);
    }
    for mode in [change.old_mode, change.new_mode] {
        if mode == 0 || mode == 100_644 {
            continue;
        }
        if mode == 100_755 && policy.allow_executable_bit_changes {
            continue;
        }
        if mode == 120_000 && policy.allow_symlinks {
            continue;
        }
        if mode == 160_000 && policy.allow_submodules {
            continue;
        }
        return Err(CandidateError::FileModeDenied);
    }
    Ok(())
}

/// Closed candidate-inspection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CandidateError {
    /// Invalid trusted configuration.
    #[error("invalid candidate inspector configuration")]
    InvalidConfiguration,
    /// A hard or grant-selected limit was exceeded.
    #[error("candidate limit exceeded")]
    LimitExceeded,
    /// Bundle contains a ref other than the fixed candidate ref.
    #[error("unexpected bundle ref")]
    UnexpectedRef,
    /// Candidate is not a strict descendant of the bound base.
    #[error("candidate history is invalid")]
    InvalidHistory,
    /// Candidate includes a merge commit.
    #[error("merge commit denied")]
    MergeCommitDenied,
    /// A changed path is outside the allow set.
    #[error("path not allowed")]
    PathNotAllowed,
    /// A changed path is explicitly denied.
    #[error("path explicitly denied")]
    PathExplicitlyDenied,
    /// Candidate uses an unsupported file mode.
    #[error("file mode denied")]
    FileModeDenied,
    /// Candidate includes a non-UTF-8 path.
    #[error("non-UTF-8 path denied")]
    NonUtf8Path,
    /// Candidate includes a binary or otherwise unsupported change.
    #[error("unsupported candidate change")]
    UnsupportedChange,
    /// Git output or bundle structure is malformed.
    #[error("candidate bundle malformed")]
    Malformed,
    /// Local Git rejected the bundle.
    #[error("Git rejected the candidate")]
    Git,
    /// Quarantine I/O failed.
    #[error("candidate quarantine unavailable")]
    Io,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_bundle_bytes_never_panic() {
        let inspector = GitCandidateInspector::new("/usr/bin/git").unwrap();
        let policy = test_policy();
        for length in [0, 1, 17, 255, 4096, 4097] {
            let submission = CandidateSubmission {
                bundle: vec![0xa5; length],
                base_revision: GitOid::parse("1".repeat(40)).unwrap(),
                candidate_revision: GitOid::parse("2".repeat(40)).unwrap(),
            };
            let _ = inspector.inspect(&submission, &policy, ObjectFormat::Sha1);
        }
    }

    #[test]
    fn fixed_seventeen_byte_malformed_bundle_is_rejected() {
        const REGRESSION_SEED: [u8; 17] = *b"AUTHSGITBUNDLEBAD";
        let inspector = GitCandidateInspector::new("/usr/bin/git").unwrap();
        let submission = CandidateSubmission {
            bundle: REGRESSION_SEED.to_vec(),
            base_revision: GitOid::parse("1".repeat(40)).unwrap(),
            candidate_revision: GitOid::parse("2".repeat(40)).unwrap(),
        };
        assert!(matches!(
            inspector.inspect(&submission, &test_policy(), ObjectFormat::Sha1),
            Err(CandidateError::Malformed | CandidateError::Git)
        ));
    }

    fn test_policy() -> CandidatePolicy {
        CandidatePolicy {
            allowed_paths: vec!["src/**".into()],
            denied_paths: vec![".github/**".into()],
            maximum_changed_files: 4,
            maximum_added_bytes: 4096,
            maximum_deleted_bytes: 4096,
            maximum_candidate_bytes: 4096,
            maximum_git_objects: 100,
            maximum_commits: 2,
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
}
