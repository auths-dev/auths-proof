//! Concrete production adapters for local Git, Auths, receipts, and Radicle.

use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::Mutex,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use auths_sdk::{RequestContext, Verifier, VerifyResult};

use crate::{
    candidate::{GitCandidateInspector, InspectedCandidate},
    canonical::{canonical_digest, sha256},
    executor::{LocalPublication, VerifiedOpenPatchCommand},
    ports::{
        CandidateInspector, Clock, EvidenceSource, PortError, ProofDecision, ProofVerifier,
        PropagationObserver, RadicleWriter, ReceiptSink,
    },
    profile::RadiclePatchProfile,
    receipts::{RadiclePropagationReceipt, RadicleReceipt},
    types::{
        CandidateSubmission, CobId, GitOid, NodeId, RadicleDid, RadicleEvidenceInput,
        RadicleEvidenceV1, Rid, VerifierConfiguration,
    },
};

const MAX_COMMAND_OUTPUT_BYTES: u64 = 1024 * 1024;
const RADICLE_COMMAND_TIMEOUT: Duration = Duration::from_mins(1);

/// Candidate port backed by the bounded Git CLI inspector.
impl CandidateInspector for GitCandidateInspector {
    fn inspect(
        &self,
        submission: &CandidateSubmission,
        configuration: &VerifierConfiguration,
    ) -> Result<InspectedCandidate, PortError> {
        GitCandidateInspector::inspect(self, submission, configuration).map_err(|error| match error
        {
            crate::candidate::CandidateError::InvalidConfiguration => {
                PortError::InvalidConfiguration
            }
            crate::candidate::CandidateError::LimitExceeded => PortError::LimitExceeded,
            crate::candidate::CandidateError::UnexpectedRef
            | crate::candidate::CandidateError::InvalidHistory
            | crate::candidate::CandidateError::MalformedGitOutput
            | crate::candidate::CandidateError::UnsupportedChange
            | crate::candidate::CandidateError::UnsupportedObject
            | crate::candidate::CandidateError::Validation(_)
            | crate::candidate::CandidateError::Git { .. } => PortError::Malformed,
            crate::candidate::CandidateError::TimedOut | crate::candidate::CandidateError::Io => {
                PortError::EvidenceUnavailable
            }
        })
    }
}

/// Auths SDK adapter fixed to the Radicle patch profile.
pub struct SdkProofVerifier {
    verifier: Verifier,
    profile: RadiclePatchProfile,
}

impl SdkProofVerifier {
    /// Wraps an explicitly configured Auths verifier.
    #[must_use]
    pub const fn new(verifier: Verifier) -> Self {
        Self {
            verifier,
            profile: RadiclePatchProfile,
        }
    }
}

impl ProofVerifier for SdkProofVerifier {
    fn verify(
        &self,
        proof: &[u8],
        action: &auths_model::CanonicalAction,
        request: &RequestContext,
    ) -> Result<ProofDecision, PortError> {
        match self
            .verifier
            .verify(proof, action, request, &self.profile)
            .map_err(|_| PortError::Verification)?
        {
            VerifyResult::Authorized(authorized) => Ok(ProofDecision::Authorized(authorized)),
            VerifyResult::Denied(explanation) => Ok(ProofDecision::Denied {
                code: explanation.code().into(),
            }),
            VerifyResult::Indeterminate(explanation) => Ok(ProofDecision::Indeterminate {
                code: explanation.code().into(),
            }),
        }
    }
}

/// Trusted operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| PortError::InvalidConfiguration)
    }
}

/// Single-process append-only canonical JSONL receipt sink.
pub struct JsonlReceiptSink {
    path: PathBuf,
    write_lock: Mutex<()>,
}

impl JsonlReceiptSink {
    /// Configures one receipt log path.
    ///
    /// # Errors
    ///
    /// Rejects paths without a parent directory.
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, PortError> {
        let path = path.into();
        if path.parent().is_none() {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(Self {
            path,
            write_lock: Mutex::new(()),
        })
    }
}

impl ReceiptSink for JsonlReceiptSink {
    fn append(&self, receipt: &RadicleReceipt) -> Result<(), PortError> {
        let _guard = self.write_lock.lock().map_err(|_| PortError::Persistence)?;
        let parent = self.path.parent().ok_or(PortError::Persistence)?;
        fs::create_dir_all(parent).map_err(|_| PortError::Persistence)?;
        let bytes = receipt
            .canonical_bytes()
            .map_err(|_| PortError::Persistence)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| PortError::Persistence)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| PortError::Persistence)
    }
}

/// Version-pinned local Radicle writer.
#[derive(Clone, Debug)]
pub struct RadicleCliWriter {
    git_executable: PathBuf,
    rad_executable: PathBuf,
    helper_path: PathBuf,
    rad_home: PathBuf,
    expected_rad_version: String,
    announce_timeout_seconds: u16,
    announce_replicas: u16,
}

/// Version-pinned evidence adapter over a dedicated Radicle profile and node.
#[derive(Clone, Debug)]
pub struct RadicleCliEvidenceSource {
    cli: RadicleCliWriter,
}

impl RadicleCliEvidenceSource {
    /// Uses the same pinned CLI environment as the writer.
    #[must_use]
    pub const fn new(cli: RadicleCliWriter) -> Self {
        Self { cli }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "version-pinned Radicle evidence acquisition is kept linear for auditability"
    )]
    fn observe_inner(
        &self,
        rid: &Rid,
        issue_id: &CobId,
        configuration: &VerifierConfiguration,
        now: u64,
    ) -> Result<RadicleEvidenceV1, PortError> {
        let mut synchronized_peers = Vec::new();
        let timeout = format!("{}s", configuration.synchronization_timeout_seconds());
        for peer in configuration.observation_peers() {
            if self
                .cli
                .rad([
                    "sync",
                    rid.as_str(),
                    "--fetch",
                    "--seed",
                    peer.as_str(),
                    "--timeout",
                    timeout.as_str(),
                    "--replicas",
                    "1",
                ])
                .is_ok()
            {
                synchronized_peers.push(peer.clone());
            }
        }
        if synchronized_peers.len() < usize::from(configuration.minimum_successful_peers()) {
            return Err(PortError::EvidenceUnavailable);
        }
        let identity = self.cli.rad(["inspect", rid.as_str(), "--identity"])?;
        let identity: serde_json::Value =
            serde_json::from_slice(&identity.stdout).map_err(|_| PortError::Malformed)?;
        let delegates = identity
            .get("delegates")
            .and_then(serde_json::Value::as_array)
            .ok_or(PortError::Malformed)?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .ok_or(PortError::Malformed)
                    .and_then(|value| RadicleDid::parse(value).map_err(|_| PortError::Malformed))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let threshold = identity
            .get("threshold")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u16::try_from(value).ok())
            .ok_or(PortError::Malformed)?;
        let default_branch = identity
            .pointer("/payload/xyz.radicle.project/defaultBranch")
            .and_then(serde_json::Value::as_str)
            .ok_or(PortError::Malformed)?
            .to_owned();
        let history = normalized_output(&self.cli.rad(["inspect", rid.as_str(), "--history"])?);
        let identity_revision = history
            .lines()
            .find_map(|line| line.strip_prefix("commit "))
            .ok_or(PortError::Malformed)?;
        let repository = storage_repository(&self.cli.rad_home, rid)?;
        let canonical_head = normalized_output(&self.cli.git(
            &repository,
            ["rev-parse", &format!("refs/heads/{default_branch}")],
        )?);
        let issue_ref_suffix = format!("/refs/cobs/xyz.radicle.issue/{issue_id}");
        let refs = normalized_output(&self.cli.git(
            &repository,
            [
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/namespaces",
            ],
        )?);
        let issue_tip_ids = refs
            .lines()
            .filter_map(|line| line.split_once(' '))
            .filter(|(_, reference)| reference.ends_with(&issue_ref_suffix))
            .map(|(oid, _)| GitOid::parse(oid).map_err(|_| PortError::Malformed))
            .collect::<Result<Vec<_>, _>>()?;
        if issue_tip_ids.is_empty() {
            return Err(PortError::EvidenceUnavailable);
        }
        let issue = self.cli.rad([
            "issue",
            "show",
            "--repo",
            rid.as_str(),
            "--no-announce",
            "--header",
            issue_id.as_str(),
        ])?;
        let issue_bytes = normalized_combined_output(&issue);
        let issue_open = issue_bytes
            .lines()
            .any(|line| line.contains("Status") && line.contains("open"));
        let node = NodeId::parse(normalized_output(
            &self.cli.rad(["node", "status", "--only", "nid"])?,
        ))
        .map_err(|_| PortError::Malformed)?;
        let signer =
            RadicleDid::parse(format!("did:key:{node}")).map_err(|_| PortError::Malformed)?;
        let canonical_derivation = CanonicalDerivation {
            version: configuration.canonical_reference(),
            rid,
            identity_revision,
            default_branch: &default_branch,
            canonical_head: &canonical_head,
        };
        let canonical_derivation_digest =
            canonical_digest(&canonical_derivation).map_err(|_| PortError::Malformed)?;
        let repository_identity_revision =
            GitOid::parse(identity_revision).map_err(|_| PortError::Malformed)?;
        let canonical_head_oid =
            GitOid::parse(&canonical_head).map_err(|_| PortError::Malformed)?;
        RadicleEvidenceV1::new(RadicleEvidenceInput {
            rid: rid.clone(),
            repository_identity_revision,
            delegates,
            delegate_threshold: threshold,
            default_branch,
            canonical_head_oid,
            canonical_derivation_digest,
            issue_id: issue_id.clone(),
            issue_tip_ids,
            issue_materialized_digest: sha256(issue_bytes.as_bytes()),
            issue_open,
            issue_history_complete: true,
            executor_signer_did: signer,
            executor_node_id: node,
            synchronized_peers,
            synchronized_at: now,
            adapter_version: configuration.radicle_adapter().into(),
        })
        .map_err(|_| PortError::Malformed)
    }
}

impl EvidenceSource for RadicleCliEvidenceSource {
    fn observe(
        &self,
        rid: &Rid,
        issue_id: &CobId,
        configuration: &VerifierConfiguration,
        now: u64,
    ) -> Result<RadicleEvidenceV1, PortError> {
        self.observe_inner(rid, issue_id, configuration, now)
            .map_err(|error| match error {
                PortError::Execution => PortError::EvidenceUnavailable,
                error => error,
            })
    }
}

#[derive(serde::Serialize)]
struct CanonicalDerivation<'a> {
    version: &'a str,
    rid: &'a Rid,
    identity_revision: &'a str,
    default_branch: &'a str,
    canonical_head: &'a str,
}

/// Independent observer using a separate pinned Radicle profile/node.
#[derive(Clone, Debug)]
pub struct RadicleCliPropagationObserver {
    cli: RadicleCliWriter,
}

impl RadicleCliPropagationObserver {
    /// Configures a distinct observer environment.
    #[must_use]
    pub const fn new(cli: RadicleCliWriter) -> Self {
        Self { cli }
    }
}

impl PropagationObserver for RadicleCliPropagationObserver {
    fn observe(
        &self,
        publication: &LocalPublication,
        execution_receipt_digest: &crate::types::DigestHex,
        now: u64,
    ) -> Result<RadiclePropagationReceipt, PortError> {
        self.cli
            .rad([
                "sync",
                publication.rid.as_str(),
                "--fetch",
                "--timeout",
                &format!("{}s", self.cli.announce_timeout_seconds),
                "--replicas",
                &self.cli.announce_replicas.to_string(),
            ])
            .map_err(|_| PortError::Propagation)?;
        let observer_node = NodeId::parse(normalized_output(
            &self.cli.rad(["node", "status", "--only", "nid"])?,
        ))
        .map_err(|_| PortError::Malformed)?;
        if observer_node == publication.node_id {
            return Err(PortError::InvalidConfiguration);
        }
        let repository = storage_repository(&self.cli.rad_home, &publication.rid)?;
        let suffix = format!("/refs/heads/patches/{}", publication.patch_id);
        let refs = normalized_output(&self.cli.git(
            &repository,
            [
                "for-each-ref",
                "--format=%(objectname) %(refname)",
                "refs/namespaces",
            ],
        )?);
        let observed = refs.lines().any(|line| {
            line.split_once(' ').is_some_and(|(oid, reference)| {
                oid == publication.candidate_oid.as_str() && reference.ends_with(&suffix)
            })
        });
        if !observed {
            return Err(PortError::Propagation);
        }
        Ok(RadiclePropagationReceipt {
            schema: "auths-radicle-propagation-v1".into(),
            execution_receipt_digest: execution_receipt_digest.clone(),
            observer_node_id: observer_node,
            revision_id: publication.revision_id.clone(),
            candidate_oid: publication.candidate_oid.clone(),
            observed_at: now,
        })
    }
}

/// Explicit CLI writer configuration.
pub struct RadicleCliWriterConfiguration {
    /// Absolute Git executable.
    pub git_executable: PathBuf,
    /// Absolute `rad` executable.
    pub rad_executable: PathBuf,
    /// Exact `PATH` containing `git-remote-rad` and required system tools.
    pub helper_path: PathBuf,
    /// Dedicated executor `RAD_HOME`.
    pub rad_home: PathBuf,
    /// Exact expected `rad --version` output.
    pub expected_rad_version: String,
    /// Announce timeout.
    pub announce_timeout_seconds: u16,
    /// Required announce replicas.
    pub announce_replicas: u16,
}

impl RadicleCliWriter {
    /// Validates immutable executable, identity-home, and version inputs.
    ///
    /// # Errors
    ///
    /// Rejects relative paths, unsafe limits, or an unexpected Radicle build.
    pub fn new(configuration: RadicleCliWriterConfiguration) -> Result<Self, PortError> {
        if !configuration.git_executable.is_absolute()
            || !configuration.rad_executable.is_absolute()
            || !configuration.helper_path.is_absolute()
            || !configuration.rad_home.is_absolute()
            || configuration.expected_rad_version.is_empty()
            || configuration.announce_timeout_seconds == 0
            || configuration.announce_replicas == 0
        {
            return Err(PortError::InvalidConfiguration);
        }
        let writer = Self {
            git_executable: configuration.git_executable,
            rad_executable: configuration.rad_executable,
            helper_path: configuration.helper_path,
            rad_home: configuration.rad_home,
            expected_rad_version: configuration.expected_rad_version,
            announce_timeout_seconds: configuration.announce_timeout_seconds,
            announce_replicas: configuration.announce_replicas,
        };
        let version = writer.rad(["--version"])?;
        if normalized_output(&version) != writer.expected_rad_version {
            return Err(PortError::InvalidConfiguration);
        }
        Ok(writer)
    }

    fn rad<const N: usize>(&self, arguments: [&str; N]) -> Result<Output, PortError> {
        self.command(&self.rad_executable, None, arguments)
    }

    fn git<const N: usize>(
        &self,
        repository: &Path,
        arguments: [&str; N],
    ) -> Result<Output, PortError> {
        self.command(&self.git_executable, Some(repository), arguments)
    }

    fn command<const N: usize>(
        &self,
        executable: &Path,
        current_dir: Option<&Path>,
        arguments: [&str; N],
    ) -> Result<Output, PortError> {
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .env_clear()
            .env("HOME", &self.rad_home)
            .env("RAD_HOME", &self.rad_home)
            .env("PATH", &self.helper_path)
            .env("LC_ALL", "C")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null());
        if let Ok(passphrase) = std::env::var("RAD_PASSPHRASE") {
            command.env("RAD_PASSPHRASE", passphrase);
        }
        if let Some(current_dir) = current_dir {
            command.current_dir(current_dir);
        }
        let output_directory = tempfile::tempdir().map_err(|_| PortError::Execution)?;
        let stdout_path = output_directory.path().join("stdout");
        let stderr_path = output_directory.path().join("stderr");
        let stdout = fs::File::create(&stdout_path).map_err(|_| PortError::Execution)?;
        let stderr = fs::File::create(&stderr_path).map_err(|_| PortError::Execution)?;
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = command.spawn().map_err(|_| PortError::Execution)?;
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().map_err(|_| PortError::Execution)? {
                break status;
            }
            if started.elapsed() >= RADICLE_COMMAND_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(PortError::Execution);
            }
            thread::sleep(Duration::from_millis(10));
        };
        let output = Output {
            status,
            stdout: read_command_output(&stdout_path)?,
            stderr: read_command_output(&stderr_path)?,
        };
        if !output.status.success() {
            return Err(PortError::Execution);
        }
        Ok(output)
    }
}

impl RadicleWriter for RadicleCliWriter {
    #[allow(
        clippy::too_many_lines,
        reason = "the irreversible write and every postcondition remain linear for auditability"
    )]
    fn open_patch(
        &self,
        command: VerifiedOpenPatchCommand,
        now: u64,
    ) -> Result<(LocalPublication, crate::workflow::ExecutionLease), PortError> {
        let node = normalized_output(&self.rad(["node", "status", "--only", "nid"])?);
        let signer = format!("did:key:{node}");
        if signer != command.signer_did().as_str() || node != command.node_id().as_str() {
            return Err(PortError::InvalidConfiguration);
        }

        let repository = command.repository_path().to_path_buf();
        let expected_title = command.patch_title().to_owned();
        let expected_description = format!(
            "{}\n\nRadicle-Issue: {}\n\nAuths-Workflow: {}",
            command.patch_messages()[1],
            command.authorized_issue_id(),
            command.workflow_id(),
        );
        let expected_base = command.base_oid().clone();
        let expected_candidate = command.candidate_oid().clone();
        let expected_signer = command.signer_did().clone();
        let canonical_ref = format!("refs/heads/{}", command.default_branch());
        let rid = command
            .rid()
            .as_str()
            .strip_prefix("rad:")
            .ok_or(PortError::Malformed)?;
        let remote = format!("rad://{rid}/{}", command.node_id());
        self.git(&repository, ["remote", "add", "rad", remote.as_str()])?;
        self.git(
            &repository,
            ["symbolic-ref", "HEAD", "refs/heads/auths-candidate"],
        )?;
        let refspec = format!("{}:refs/patches", command.candidate_oid());
        let base_option = format!("patch.base={}", command.base_oid());
        let [title, body, issue, workflow] = command.patch_messages();
        let title_option = format!("patch.message={title}");
        let body_option = format!("patch.message={body}");
        let issue_option = format!("patch.message={issue}");
        let workflow_option = format!("patch.message={workflow}");
        let output = self.git(
            &repository,
            [
                "push",
                "rad",
                refspec.as_str(),
                "-o",
                "no-sync",
                "-o",
                base_option.as_str(),
                "-o",
                title_option.as_str(),
                "-o",
                body_option.as_str(),
                "-o",
                issue_option.as_str(),
                "-o",
                workflow_option.as_str(),
            ],
        )?;
        let diagnostic = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let patch_id = parse_opened_patch_id(&diagnostic)?;
        let remote_ref = format!("refs/heads/patches/{patch_id}");
        let remote = self.git(&repository, ["ls-remote", "rad", remote_ref.as_str()])?;
        let remote_output = normalized_output(&remote);
        let remote_oid = remote_output
            .split_ascii_whitespace()
            .next()
            .ok_or(PortError::Execution)?;
        if remote_oid != command.candidate_oid().as_str() {
            return Err(PortError::Execution);
        }
        let patch = self.rad([
            "cob",
            "show",
            "--repo",
            command.rid().as_str(),
            "--type",
            "xyz.radicle.patch",
            "--object",
            patch_id.as_str(),
            "--format",
            "json",
        ])?;
        validate_patch_postcondition(
            &patch.stdout,
            &patch_id,
            &expected_title,
            &expected_description,
            &expected_base,
            &expected_candidate,
            &expected_signer,
        )?;
        let executor_repository = storage_repository(&self.rad_home, command.rid())?;
        let canonical = normalized_output(
            &self.git(&executor_repository, ["rev-parse", canonical_ref.as_str()])?,
        );
        if canonical != expected_base.as_str() {
            return Err(PortError::Execution);
        }

        let materials = command.into_materials();
        let publication = LocalPublication {
            rid: materials.authorized.command().action().rid().clone(),
            patch_id: patch_id.clone(),
            revision_id: GitOid::parse(patch_id.as_str()).map_err(|_| PortError::Malformed)?,
            candidate_oid: materials.candidate.facts().candidate_oid().clone(),
            signer_did: materials.evidence.executor_signer_did().clone(),
            node_id: materials.evidence.executor_node_id().clone(),
            stored_at: now,
        };
        Ok((publication, materials.lease))
    }

    fn announce(&self, publication: &LocalPublication) -> Result<(), PortError> {
        self.rad([
            "sync",
            publication.rid.as_str(),
            "--announce",
            "--timeout",
            &format!("{}s", self.announce_timeout_seconds),
            "--replicas",
            &self.announce_replicas.to_string(),
        ])
        .map(|_| ())
    }
}

fn normalized_output(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

fn normalized_combined_output(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn read_command_output(path: &Path) -> Result<Vec<u8>, PortError> {
    let mut file = fs::File::open(path).map_err(|_| PortError::Execution)?;
    let length = file.metadata().map_err(|_| PortError::Execution)?.len();
    if length > MAX_COMMAND_OUTPUT_BYTES {
        return Err(PortError::LimitExceeded);
    }
    let mut bytes =
        Vec::with_capacity(usize::try_from(length).map_err(|_| PortError::LimitExceeded)?);
    file.read_to_end(&mut bytes)
        .map_err(|_| PortError::Execution)?;
    Ok(bytes)
}

fn storage_repository(rad_home: &Path, rid: &Rid) -> Result<PathBuf, PortError> {
    let storage_name = rid
        .as_str()
        .strip_prefix("rad:")
        .ok_or(PortError::Malformed)?;
    let repository = rad_home.join("storage").join(storage_name);
    if !repository.is_dir() {
        return Err(PortError::EvidenceUnavailable);
    }
    Ok(repository)
}

fn parse_opened_patch_id(output: &str) -> Result<CobId, PortError> {
    for line in output.lines() {
        let words = line.split_ascii_whitespace().collect::<Vec<_>>();
        for window in words.windows(3) {
            if window[0].eq_ignore_ascii_case("patch") && window[2].eq_ignore_ascii_case("opened") {
                return CobId::parse(
                    window[1].trim_matches(|character: char| !character.is_ascii_hexdigit()),
                )
                .map_err(|_| PortError::Malformed);
            }
        }
    }
    Err(PortError::Malformed)
}

fn validate_patch_postcondition(
    bytes: &[u8],
    patch_id: &CobId,
    expected_title: &str,
    expected_description: &str,
    expected_base: &GitOid,
    expected_candidate: &GitOid,
    expected_signer: &RadicleDid,
) -> Result<(), PortError> {
    let patch: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| PortError::Malformed)?;
    let revision = patch
        .get("revisions")
        .and_then(serde_json::Value::as_object)
        .filter(|revisions| revisions.len() == 1)
        .and_then(|revisions| revisions.get(patch_id.as_str()))
        .ok_or(PortError::Execution)?;
    let description = revision
        .get("description")
        .and_then(serde_json::Value::as_array)
        .filter(|description| description.len() == 1)
        .and_then(|description| description.first())
        .and_then(|description| description.get("body"))
        .and_then(serde_json::Value::as_str);
    let exact = patch.get("title").and_then(serde_json::Value::as_str) == Some(expected_title)
        && patch
            .pointer("/state/status")
            .and_then(serde_json::Value::as_str)
            == Some("open")
        && patch.get("target").and_then(serde_json::Value::as_str) == Some("delegates")
        && patch
            .pointer("/author/id")
            .and_then(serde_json::Value::as_str)
            == Some(expected_signer.as_str())
        && revision.get("id").and_then(serde_json::Value::as_str) == Some(patch_id.as_str())
        && revision.get("base").and_then(serde_json::Value::as_str) == Some(expected_base.as_str())
        && revision.get("oid").and_then(serde_json::Value::as_str)
            == Some(expected_candidate.as_str())
        && revision
            .pointer("/author/id")
            .and_then(serde_json::Value::as_str)
            == Some(expected_signer.as_str())
        && description == Some(expected_description);
    if exact {
        Ok(())
    } else {
        Err(PortError::Execution)
    }
}
