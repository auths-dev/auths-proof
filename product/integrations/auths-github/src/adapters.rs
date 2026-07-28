//! Production adapters for Git, GitHub App credentials, REST, time, and receipts.

use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    process::Command,
    sync::Mutex,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
use reqwest::blocking::{Client, Response};
use ring::{
    rand::SystemRandom,
    signature::{self, KeyPair as _},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    candidate::{CandidateSubmission, GitCandidateInspector, QuarantinedCandidate},
    evidence::{IssueEvidence, PullRequestEvidence, RefEvidence, RepositoryEvidence},
    executor::{VerifiedOpenDraftPullRequest, VerifiedPublishBranch},
    ports::{
        CandidateInspector, Clock, ClockError, CredentialError, CredentialProvider,
        GitHubReadError, GitHubReadPort, GitHubWriteError, GitHubWritePort, ReceiptError,
        ReceiptSink, ScopedCredential,
    },
    receipts::{GitHubReceipt, OpenedPullRequest, PublishedBranch, SignedGitHubReceipt},
    types::{
        GitHubOperation, GitOid, IssueResource, NodeId, RefName, RepositoryResource, WorkflowId,
    },
};

const MAX_HTTP_BODY_BYTES: u64 = 1024 * 1024;
const MAX_GIT_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_RECEIPT_LOG_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SIGNED_RECEIPT_BYTES: usize = 1024 * 1024;
const BRANCH_POSTCONDITION_DELAYS_MS: [u64; 5] = [0, 100, 250, 500, 1_000];
const RECEIPT_SIGNATURE_DOMAIN: &[u8] = b"AUTHS-GITHUB-RECEIPT\x00\x01";

impl CandidateInspector for GitCandidateInspector {
    fn inspect(
        &self,
        submission: &CandidateSubmission,
        policy: &crate::types::CandidatePolicy,
        object_format: crate::types::ObjectFormat,
    ) -> Result<QuarantinedCandidate, crate::candidate::CandidateError> {
        GitCandidateInspector::inspect(self, submission, policy, object_format)
    }
}

/// Trusted operating-system wall clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64, ClockError> {
        unix_time().map_err(|()| ClockError)
    }
}

/// Ed25519-signed append-only canonical JSONL receipt sink.
pub struct Ed25519JsonlReceiptSink {
    path: PathBuf,
    key: signature::Ed25519KeyPair,
    write_lock: Mutex<()>,
}

impl Ed25519JsonlReceiptSink {
    /// Constructs a sink from one executor-owned Ed25519 seed.
    ///
    /// # Errors
    ///
    /// Rejects invalid paths or key material.
    pub fn new(path: impl Into<PathBuf>, seed: &[u8; 32]) -> Result<Self, ReceiptError> {
        let path = path.into();
        if path.parent().is_none() {
            return Err(ReceiptError);
        }
        let key = signature::Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| ReceiptError)?;
        Ok(Self {
            path,
            key,
            write_lock: Mutex::new(()),
        })
    }

    /// Reads and verifies the signed envelopes durably associated with one workflow.
    ///
    /// Decision receipts carry the workflow identifier directly. Execution
    /// receipts are included only when their decision commitment belongs to a
    /// matching decision already present in the append-only log.
    ///
    /// # Errors
    ///
    /// Fails closed for an oversized, malformed, tampered, or unexpectedly
    /// signed receipt log.
    pub fn receipts_for_workflow(
        &self,
        workflow_id: &WorkflowId,
    ) -> Result<Vec<SignedGitHubReceipt>, ReceiptError> {
        let _guard = self.write_lock.lock().map_err(|_| ReceiptError)?;
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(ReceiptError),
        };
        if metadata.len() > MAX_RECEIPT_LOG_BYTES {
            return Err(ReceiptError);
        }
        let bytes = fs::read(&self.path).map_err(|_| ReceiptError)?;
        if bytes.len() as u64 > MAX_RECEIPT_LOG_BYTES {
            return Err(ReceiptError);
        }

        let expected_signer = hex::encode(self.key.public_key().as_ref());
        let mut matching_decisions = BTreeSet::new();
        let mut matching_receipts = Vec::new();
        for line in bytes.split(|byte| *byte == b'\n') {
            if line.is_empty() {
                continue;
            }
            if line.len() > MAX_SIGNED_RECEIPT_BYTES {
                return Err(ReceiptError);
            }
            let signed =
                serde_json::from_slice::<SignedGitHubReceipt>(line).map_err(|_| ReceiptError)?;
            verify_signed_receipt(&signed, &expected_signer)?;
            let envelope_receipt_digest = signed.receipt.digest().map_err(|_| ReceiptError)?;
            match &signed.receipt {
                GitHubReceipt::Decision(receipt) if &receipt.workflow_id == workflow_id => {
                    matching_decisions.insert(envelope_receipt_digest);
                    matching_receipts.push(signed);
                }
                GitHubReceipt::Execution(receipt)
                    if matching_decisions.contains(&receipt.decision_receipt_digest) =>
                {
                    matching_receipts.push(signed);
                }
                GitHubReceipt::Decision(_) | GitHubReceipt::Execution(_) => {}
            }
        }
        Ok(matching_receipts)
    }
}

fn verify_signed_receipt(
    signed: &SignedGitHubReceipt,
    expected_signer: &str,
) -> Result<(), ReceiptError> {
    if signed.signer_public_key != expected_signer {
        return Err(ReceiptError);
    }
    let public_key = hex::decode(&signed.signer_public_key).map_err(|_| ReceiptError)?;
    let signature_bytes = hex::decode(&signed.signature).map_err(|_| ReceiptError)?;
    let receipt_bytes = signed.receipt.canonical_bytes().map_err(|_| ReceiptError)?;
    let mut signing_input =
        Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + receipt_bytes.len());
    signing_input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
    signing_input.extend_from_slice(&receipt_bytes);
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(&signing_input, &signature_bytes)
        .map_err(|_| ReceiptError)
}

impl ReceiptSink for Ed25519JsonlReceiptSink {
    fn append(&self, receipt: &GitHubReceipt) -> Result<crate::types::DigestHex, ReceiptError> {
        let _guard = self.write_lock.lock().map_err(|_| ReceiptError)?;
        let receipt_bytes = receipt.canonical_bytes().map_err(|_| ReceiptError)?;
        let mut signing_input =
            Vec::with_capacity(RECEIPT_SIGNATURE_DOMAIN.len() + receipt_bytes.len());
        signing_input.extend_from_slice(RECEIPT_SIGNATURE_DOMAIN);
        signing_input.extend_from_slice(&receipt_bytes);
        let signed = SignedGitHubReceipt {
            receipt: receipt.clone(),
            signer_public_key: hex::encode(self.key.public_key().as_ref()),
            signature: hex::encode(self.key.sign(&signing_input).as_ref()),
        };
        let bytes = signed.canonical_bytes().map_err(|_| ReceiptError)?;
        let parent = self.path.parent().ok_or(ReceiptError)?;
        fs::create_dir_all(parent).map_err(|_| ReceiptError)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|_| ReceiptError)?;
        file.write_all(&bytes)
            .and_then(|()| file.write_all(b"\n"))
            .and_then(|()| file.sync_all())
            .map_err(|_| ReceiptError)?;
        receipt.digest().map_err(|_| ReceiptError)
    }
}

/// Bounded in-memory receipt sink for deterministic integration tests.
#[derive(Default)]
pub struct InMemoryReceiptSink {
    receipts: Mutex<Vec<GitHubReceipt>>,
}

impl InMemoryReceiptSink {
    /// Returns a snapshot of appended receipts.
    #[must_use]
    pub fn receipts(&self) -> Vec<GitHubReceipt> {
        self.receipts
            .lock()
            .map_or_else(|_| Vec::new(), |receipts| receipts.clone())
    }
}

impl ReceiptSink for InMemoryReceiptSink {
    fn append(&self, receipt: &GitHubReceipt) -> Result<crate::types::DigestHex, ReceiptError> {
        let digest = receipt.digest().map_err(|_| ReceiptError)?;
        self.receipts
            .lock()
            .map_err(|_| ReceiptError)?
            .push(receipt.clone());
        Ok(digest)
    }
}

/// GitHub App installation-token broker.
pub struct GitHubAppCredentialProvider {
    app_id: u64,
    installation_id: u64,
    private_key: signature::RsaKeyPair,
    api_base: String,
    client: Client,
}

impl GitHubAppCredentialProvider {
    /// Parses one RSA GitHub App private key.
    ///
    /// # Errors
    ///
    /// Rejects zero IDs, non-HTTPS production endpoints, malformed PEM, or
    /// invalid HTTP configuration.
    pub fn new(
        app_id: u64,
        installation_id: u64,
        private_key_pem: &str,
        api_base: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let api_base = api_base.into();
        if app_id == 0
            || installation_id == 0
            || (!api_base.starts_with("https://") && !api_base.starts_with("http://127.0.0.1:"))
            || api_base.ends_with('/')
        {
            return Err(CredentialError::Invalid);
        }
        let der = decode_pem(private_key_pem)?;
        let private_key = signature::RsaKeyPair::from_pkcs8(&der)
            .or_else(|_| signature::RsaKeyPair::from_der(&der))
            .map_err(|_| CredentialError::Invalid)?;
        let client = Client::builder()
            .user_agent("auths-github/0.1")
            .https_only(api_base.starts_with("https://"))
            .build()
            .map_err(|_| CredentialError::Invalid)?;
        Ok(Self {
            app_id,
            installation_id,
            private_key,
            api_base,
            client,
        })
    }

    fn jwt(&self) -> Result<String, CredentialError> {
        let now = unix_time().map_err(|()| CredentialError::Unavailable)?;
        let header = Base64UrlUnpadded::encode_string(br#"{"alg":"RS256","typ":"JWT"}"#);
        let claims = serde_json::to_vec(&json!({
            "iat": now.saturating_sub(60),
            "exp": now + 540,
            "iss": self.app_id.to_string(),
        }))
        .map_err(|_| CredentialError::Invalid)?;
        let claims = Base64UrlUnpadded::encode_string(&claims);
        let input = format!("{header}.{claims}");
        let random = SystemRandom::new();
        let mut signature_bytes = vec![0_u8; self.private_key.public().modulus_len()];
        self.private_key
            .sign(
                &signature::RSA_PKCS1_SHA256,
                &random,
                input.as_bytes(),
                &mut signature_bytes,
            )
            .map_err(|_| CredentialError::Unavailable)?;
        Ok(format!(
            "{input}.{}",
            Base64UrlUnpadded::encode_string(&signature_bytes)
        ))
    }

    /// Mints one repository-scoped read-only credential for fresh evidence.
    ///
    /// This credential cannot publish refs or open pull requests. It exists so
    /// evidence acquisition does not depend on GitHub's shared-IP anonymous
    /// rate limit.
    pub fn evidence_credential(
        &self,
        repository: &RepositoryResource,
    ) -> Result<ScopedCredential, CredentialError> {
        self.mint_installation_credential(
            repository,
            json!({
                "contents": "read",
                "issues": "read",
                "metadata": "read",
                "pull_requests": "read",
            }),
        )
    }

    fn mint_installation_credential(
        &self,
        repository: &RepositoryResource,
        permissions: serde_json::Value,
    ) -> Result<ScopedCredential, CredentialError> {
        let jwt = self.jwt()?;
        let response = self
            .client
            .post(format!(
                "{}/app/installations/{}/access_tokens",
                self.api_base, self.installation_id
            ))
            .bearer_auth(jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&json!({
                "repository_ids": [repository.repository_id()],
                "permissions": permissions,
            }))
            .send()
            .map_err(|_| CredentialError::Unavailable)?;
        if response.status().as_u16() == 401 || response.status().as_u16() == 403 {
            return Err(CredentialError::Rejected);
        }
        if !response.status().is_success() {
            return Err(CredentialError::Unavailable);
        }
        let body = bounded_body(response).map_err(|_| CredentialError::Unavailable)?;
        let token: InstallationToken =
            serde_json::from_slice(&body).map_err(|_| CredentialError::Unavailable)?;
        ScopedCredential::from_secret(token.token.into_bytes())
    }
}

impl CredentialProvider for GitHubAppCredentialProvider {
    fn installation_credential(
        &self,
        repository: &RepositoryResource,
        operation: GitHubOperation,
    ) -> Result<ScopedCredential, CredentialError> {
        let permissions = match operation {
            GitHubOperation::PublishBranch => json!({
                "contents": "write",
                "metadata": "read",
            }),
            GitHubOperation::OpenDraftPullRequest => json!({
                "contents": "read",
                "metadata": "read",
                "pull_requests": "write",
            }),
        };
        self.mint_installation_credential(repository, permissions)
    }
}

#[derive(Deserialize)]
struct InstallationToken {
    token: String,
}

/// GitHub REST evidence and write adapter bound to one repository.
#[derive(Clone)]
pub struct GitHubRestClient {
    repository: RepositoryResource,
    evidence_credentials: std::sync::Arc<GitHubAppCredentialProvider>,
    api_base: String,
    web_base: String,
    git_executable: PathBuf,
    client: Client,
}

impl GitHubRestClient {
    /// Constructs one version-pinned adapter.
    ///
    /// # Errors
    ///
    /// Rejects relative Git paths and non-HTTPS production endpoints.
    pub fn new(
        repository: RepositoryResource,
        git_executable: impl Into<PathBuf>,
        api_base: impl Into<String>,
        web_base: impl Into<String>,
        evidence_credentials: std::sync::Arc<GitHubAppCredentialProvider>,
    ) -> Result<Self, GitHubReadError> {
        let git_executable = git_executable.into();
        let api_base = api_base.into();
        let web_base = web_base.into();
        if !git_executable.is_absolute()
            || (!api_base.starts_with("https://") && !api_base.starts_with("http://127.0.0.1:"))
            || (!web_base.starts_with("https://") && !web_base.starts_with("http://127.0.0.1:"))
            || api_base.ends_with('/')
            || web_base.ends_with('/')
        {
            return Err(GitHubReadError::Malformed);
        }
        let client = Client::builder()
            .user_agent("auths-github/0.1")
            .https_only(api_base.starts_with("https://"))
            .build()
            .map_err(|_| GitHubReadError::Malformed)?;
        Ok(Self {
            repository,
            evidence_credentials,
            api_base,
            web_base,
            git_executable,
            client,
        })
    }

    fn get(&self, path: &str) -> Result<Vec<u8>, GitHubReadError> {
        let credential = self
            .evidence_credentials
            .evidence_credential(&self.repository)
            .map_err(|_| GitHubReadError::Unavailable)?;
        let response = self
            .client
            .get(format!("{}{}", self.api_base, path))
            .bearer_auth(
                credential
                    .expose()
                    .map_err(|_| GitHubReadError::Unavailable)?,
            )
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .send()
            .map_err(|_| GitHubReadError::Unavailable)?;
        if response.status().as_u16() == 404 {
            return Err(GitHubReadError::NotFound);
        }
        if !response.status().is_success() {
            return Err(GitHubReadError::Unavailable);
        }
        bounded_body(response)
    }

    fn repository_path(&self) -> String {
        format!(
            "/repos/{}/{}",
            self.repository.owner(),
            self.repository.name()
        )
    }
}

impl GitHubReadPort for GitHubRestClient {
    fn repository(
        &self,
        resource: &RepositoryResource,
    ) -> Result<RepositoryEvidence, GitHubReadError> {
        if resource != &self.repository {
            return Err(GitHubReadError::NotFound);
        }
        let body = self.get(&self.repository_path())?;
        let repository: RepositoryResponse =
            serde_json::from_slice(&body).map_err(|_| GitHubReadError::Malformed)?;
        Ok(RepositoryEvidence {
            repository_id: repository.id,
            repository_node_id: NodeId::parse(repository.node_id)
                .map_err(|_| GitHubReadError::Malformed)?,
            owner: repository.owner.login,
            name: repository.name,
        })
    }

    fn issue(&self, resource: &IssueResource) -> Result<IssueEvidence, GitHubReadError> {
        if resource.repository_id() != self.repository.repository_id() {
            return Err(GitHubReadError::NotFound);
        }
        let body = self.get(&format!(
            "{}/issues/{}",
            self.repository_path(),
            resource.issue_number()
        ))?;
        let issue: IssueResponse =
            serde_json::from_slice(&body).map_err(|_| GitHubReadError::Malformed)?;
        Ok(IssueEvidence {
            repository_id: self.repository.repository_id(),
            issue_node_id: NodeId::parse(issue.node_id).map_err(|_| GitHubReadError::Malformed)?,
            issue_number: issue.number,
            open: issue.state == "open" && issue.pull_request.is_none(),
        })
    }

    fn ref_state(
        &self,
        repository: &RepositoryResource,
        ref_name: &RefName,
    ) -> Result<RefEvidence, GitHubReadError> {
        if repository != &self.repository {
            return Err(GitHubReadError::NotFound);
        }
        match self.get(&format!(
            "{}/git/ref/heads/{}",
            self.repository_path(),
            ref_name
        )) {
            Ok(body) => {
                let reference: RefResponse =
                    serde_json::from_slice(&body).map_err(|_| GitHubReadError::Malformed)?;
                Ok(RefEvidence {
                    ref_name: ref_name.clone(),
                    revision: Some(
                        GitOid::parse(reference.object.sha)
                            .map_err(|_| GitHubReadError::Malformed)?,
                    ),
                })
            }
            Err(GitHubReadError::NotFound) => Ok(RefEvidence {
                ref_name: ref_name.clone(),
                revision: None,
            }),
            Err(error) => Err(error),
        }
    }

    fn matching_pull_requests(
        &self,
        repository: &RepositoryResource,
        head: &RefName,
        base: &RefName,
    ) -> Result<Vec<PullRequestEvidence>, GitHubReadError> {
        if repository != &self.repository {
            return Err(GitHubReadError::NotFound);
        }
        let body = self.get(&format!(
            "{}/pulls?state=all&head={}:{}&base={}&per_page=10",
            self.repository_path(),
            self.repository.owner(),
            head,
            base
        ))?;
        let pulls: Vec<PullResponse> =
            serde_json::from_slice(&body).map_err(|_| GitHubReadError::Malformed)?;
        pulls
            .into_iter()
            .map(pull_evidence)
            .collect::<Result<Vec<_>, _>>()
    }
}

impl GitHubWritePort for GitHubRestClient {
    fn publish_branch(
        &self,
        command: &VerifiedPublishBranch,
        candidate: &QuarantinedCandidate,
        credential: &ScopedCredential,
    ) -> Result<PublishedBranch, GitHubWriteError> {
        if command.repository() != &self.repository
            || candidate.evidence().candidate_revision() != command.candidate_revision()
        {
            return Err(GitHubWriteError::PostconditionMismatch);
        }
        let temporary = tempfile::tempdir().map_err(|_| GitHubWriteError::Adapter)?;
        let askpass = temporary.path().join("askpass");
        fs::write(
            &askpass,
            b"#!/bin/sh\ncase \"$1\" in *Username*) printf '%s\\n' x-access-token;; *) printf '%s\\n' \"$AUTHS_GITHUB_TOKEN\";; esac\n",
        )
        .map_err(|_| GitHubWriteError::Adapter)?;
        set_executable(&askpass)?;
        let remote = format!(
            "{}/{}/{}.git",
            self.web_base,
            self.repository.owner(),
            self.repository.name()
        );
        let refspec = format!(
            "{}:refs/heads/{}",
            command.candidate_revision(),
            command.target_ref()
        );
        let output = Command::new(&self.git_executable)
            .current_dir(candidate.repository_path())
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", temporary.path())
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", &askpass)
            .env(
                "AUTHS_GITHUB_TOKEN",
                credential.expose().map_err(|_| GitHubWriteError::Adapter)?,
            )
            .args([
                "push",
                "--porcelain",
                "--no-verify",
                remote.as_str(),
                refspec.as_str(),
            ])
            .output()
            .map_err(|_| GitHubWriteError::Ambiguous)?;
        if output.stdout.len() > MAX_GIT_OUTPUT_BYTES || output.stderr.len() > MAX_GIT_OUTPUT_BYTES
        {
            return Err(GitHubWriteError::Adapter);
        }
        if !output.status.success() {
            return Err(GitHubWriteError::Rejected);
        }
        for delay_ms in BRANCH_POSTCONDITION_DELAYS_MS {
            if delay_ms != 0 {
                thread::sleep(std::time::Duration::from_millis(delay_ms));
            }
            match self.ref_state(command.repository(), command.target_ref()) {
                Ok(observed)
                    if observed.revision.as_ref() == Some(command.candidate_revision()) =>
                {
                    return Ok(PublishedBranch {
                        repository_id: self.repository.repository_id(),
                        branch_ref: command.target_ref().clone(),
                        head_revision: command.candidate_revision().clone(),
                    });
                }
                Ok(observed) if observed.revision.is_none() => {}
                Ok(_) | Err(GitHubReadError::Malformed) => {
                    return Err(GitHubWriteError::PostconditionMismatch);
                }
                Err(GitHubReadError::NotFound | GitHubReadError::Unavailable) => {}
            }
        }
        Err(GitHubWriteError::Ambiguous)
    }

    fn open_draft_pull_request(
        &self,
        command: &VerifiedOpenDraftPullRequest,
        credential: &ScopedCredential,
    ) -> Result<OpenedPullRequest, GitHubWriteError> {
        if command.repository() != &self.repository {
            return Err(GitHubWriteError::PostconditionMismatch);
        }
        let action = command.action();
        let response = self
            .client
            .post(format!(
                "{}{}{}",
                self.api_base,
                self.repository_path(),
                "/pulls"
            ))
            .bearer_auth(credential.expose().map_err(|_| GitHubWriteError::Adapter)?)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .json(&json!({
                "title": action.exact_title,
                "body": command.exact_body(),
                "head": action.head_ref,
                "base": action.base_ref,
                "draft": true,
            }))
            .send()
            .map_err(|_| GitHubWriteError::Ambiguous)?;
        if response.status().as_u16() == 401
            || response.status().as_u16() == 403
            || response.status().as_u16() == 422
        {
            return Err(GitHubWriteError::Rejected);
        }
        if !response.status().is_success() {
            return Err(GitHubWriteError::Ambiguous);
        }
        let body = bounded_body(response).map_err(|_| GitHubWriteError::Ambiguous)?;
        let pull: PullResponse =
            serde_json::from_slice(&body).map_err(|_| GitHubWriteError::Adapter)?;
        let evidence = pull_evidence(pull).map_err(|_| GitHubWriteError::Adapter)?;
        if !evidence.draft
            || evidence.base_ref != action.base_ref
            || evidence.head_ref != action.head_ref
            || evidence.head_revision != action.head_revision
        {
            return Err(GitHubWriteError::PostconditionMismatch);
        }
        Ok(evidence.into())
    }
}

fn bounded_body(response: Response) -> Result<Vec<u8>, GitHubReadError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_HTTP_BODY_BYTES)
    {
        return Err(GitHubReadError::Malformed);
    }
    let body = response.bytes().map_err(|_| GitHubReadError::Unavailable)?;
    if body.len() as u64 > MAX_HTTP_BODY_BYTES {
        return Err(GitHubReadError::Malformed);
    }
    Ok(body.to_vec())
}

fn decode_pem(pem: &str) -> Result<Vec<u8>, CredentialError> {
    if pem.len() > 64 * 1024 {
        return Err(CredentialError::Invalid);
    }
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    Base64::decode_vec(&encoded).map_err(|_| CredentialError::Invalid)
}

fn unix_time() -> Result<u64, ()> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ())
}

#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), GitHubWriteError> {
    use std::os::unix::fs::PermissionsExt as _;

    let mut permissions = fs::metadata(path)
        .map_err(|_| GitHubWriteError::Adapter)?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions).map_err(|_| GitHubWriteError::Adapter)
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), GitHubWriteError> {
    Err(GitHubWriteError::Adapter)
}

#[derive(Deserialize)]
struct RepositoryResponse {
    id: u64,
    node_id: String,
    name: String,
    owner: OwnerResponse,
}

#[derive(Deserialize)]
struct OwnerResponse {
    login: String,
}

#[derive(Deserialize)]
struct IssueResponse {
    node_id: String,
    number: u64,
    state: String,
    pull_request: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct RefResponse {
    object: RefObjectResponse,
}

#[derive(Deserialize)]
struct RefObjectResponse {
    sha: String,
}

#[derive(Deserialize)]
struct PullResponse {
    node_id: String,
    number: u64,
    html_url: String,
    draft: bool,
    base: PullRefResponse,
    head: PullRefResponse,
}

#[derive(Deserialize)]
struct PullRefResponse {
    #[serde(rename = "ref")]
    ref_name: String,
    sha: String,
}

fn pull_evidence(pull: PullResponse) -> Result<PullRequestEvidence, GitHubReadError> {
    if pull.number == 0
        || !pull.html_url.starts_with("https://github.com/")
        || pull.html_url.len() > 512
    {
        return Err(GitHubReadError::Malformed);
    }
    Ok(PullRequestEvidence {
        node_id: NodeId::parse(pull.node_id).map_err(|_| GitHubReadError::Malformed)?,
        number: pull.number,
        url: pull.html_url,
        base_ref: RefName::parse(pull.base.ref_name).map_err(|_| GitHubReadError::Malformed)?,
        head_ref: RefName::parse(pull.head.ref_name).map_err(|_| GitHubReadError::Malformed)?,
        head_revision: GitOid::parse(pull.head.sha).map_err(|_| GitHubReadError::Malformed)?,
        draft: pull.draft,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_never_formats_secret() {
        let credential = ScopedCredential::from_secret(b"top-secret".to_vec()).unwrap();
        assert_eq!(format!("{credential}"), "[REDACTED]");
        assert_eq!(format!("{credential:?}"), "ScopedCredential([REDACTED])");
    }

    #[test]
    fn signed_receipts_do_not_contain_private_key_seed() {
        let directory = tempfile::tempdir().unwrap();
        let sink = Ed25519JsonlReceiptSink::new(directory.path().join("receipts.jsonl"), &[7; 32])
            .unwrap();
        assert_eq!(sink.key.public_key().as_ref().len(), 32);
    }

    #[test]
    fn signed_receipts_remain_queryable_by_workflow_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipts.jsonl");
        let sink = Ed25519JsonlReceiptSink::new(&path, &[7; 32]).unwrap();
        let workflow_id = WorkflowId::parse("demo-0123456789abcdef0123456789abcdef").unwrap();
        let decision = test_decision_receipt(workflow_id.as_str(), "a");
        let decision_digest = decision.digest().unwrap();
        sink.append(&decision).unwrap();
        sink.append(&test_execution_receipt(&decision_digest))
            .unwrap();
        sink.append(&test_decision_receipt(
            "demo-fedcba9876543210fedcba9876543210",
            "f",
        ))
        .unwrap();
        drop(sink);

        let reopened = Ed25519JsonlReceiptSink::new(path, &[7; 32]).unwrap();
        let receipts = reopened.receipts_for_workflow(&workflow_id).unwrap();
        assert_eq!(receipts.len(), 2);
        assert!(matches!(receipts[0].receipt, GitHubReceipt::Decision(_)));
        assert!(matches!(receipts[1].receipt, GitHubReceipt::Execution(_)));
    }

    #[test]
    fn durable_receipt_reader_rejects_a_tampered_log() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("receipts.jsonl");
        let sink = Ed25519JsonlReceiptSink::new(&path, &[7; 32]).unwrap();
        let workflow_id = WorkflowId::parse("demo-0123456789abcdef0123456789abcdef").unwrap();
        sink.append(&test_decision_receipt(workflow_id.as_str(), "a"))
            .unwrap();
        let mut bytes = fs::read(&path).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'a').unwrap();
        bytes[position] = b'b';
        fs::write(&path, bytes).unwrap();

        assert!(sink.receipts_for_workflow(&workflow_id).is_err());
    }

    fn test_decision_receipt(workflow_id: &str, digest_character: &str) -> GitHubReceipt {
        serde_json::from_value(json!({
            "type": "decision",
            "receipt": {
                "schema": "auths-github-receipt-v1",
                "workflow_id": workflow_id,
                "workflow_grant_digest": digest_character.repeat(64),
                "action_digest": "b".repeat(64),
                "proof_digest": "c".repeat(64),
                "trusted_context_digest": "d".repeat(64),
                "required_configuration": test_configuration(),
                "executed_configuration": test_configuration(),
                "required_configuration_digest": "e".repeat(64),
                "executed_configuration_digest": "e".repeat(64),
                "evidence_digest": "1".repeat(64),
                "product_decision": {
                    "class": "authorized",
                    "code": "authorized",
                    "detail": "exact action authorized"
                },
                "auths_code": "authorized",
                "executor_identity": "auths-github-test",
                "evaluated_at": 1_900_000_000_u64
            }
        }))
        .unwrap()
    }

    fn test_execution_receipt(decision_digest: &crate::types::DigestHex) -> GitHubReceipt {
        serde_json::from_value(json!({
            "type": "execution",
            "receipt": {
                "schema": "auths-github-receipt-v1",
                "decision_receipt_digest": decision_digest,
                "action_digest": "b".repeat(64),
                "claim_id": "2".repeat(64),
                "expected_prior_state": "candidate-accepted",
                "operation": "publish-branch",
                "observed_state": null,
                "repository_id": 42,
                "result": "succeeded",
                "executed_at": 1_900_000_001_u64,
                "reconciliation_history": []
            }
        }))
        .unwrap()
    }

    fn test_configuration() -> serde_json::Value {
        json!({
            "profile": "auths.github.issue-address/1",
            "candidate_inspector": "git-cli-bounded-v1",
            "github_adapter": "github-rest-2022-11-28",
            "canonical_reference": "jcs-rfc8785-v1",
            "repository_automation_policy_digest": "3".repeat(64),
            "maximum_evidence_age_seconds": 30,
            "executor_audience": "auths-github://test",
            "receipt_schema": "auths-github-receipt-v1"
        })
    }
}
