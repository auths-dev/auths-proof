use std::{
    fs,
    io::Write as _,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use auths_radicle::{CobId, GitOid, NodeId, RadicleDid, Rid};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;

const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_START_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Trusted executable and persistent-volume paths for one deployed node.
#[derive(Clone, Debug)]
pub struct NodeConfiguration {
    pub role: NodeRole,
    pub rad_executable: PathBuf,
    pub git_executable: PathBuf,
    pub helper_path: PathBuf,
    pub rad_home: PathBuf,
    pub listen: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeRole {
    Executor,
    Observer,
    Maintainer,
}

impl NodeRole {
    const fn alias(self) -> &'static str {
        match self {
            Self::Executor => "auths-radicle-executor",
            Self::Observer => "auths-radicle-observer",
            Self::Maintainer => "auths-demo-maintainer",
        }
    }
}

/// Persistent repository and identity facts created during first boot.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentMetadata {
    pub rid: Rid,
    pub issue_id: CobId,
    pub repository_identity_revision: GitOid,
    pub canonical_base_oid: GitOid,
    pub maintainer_did: RadicleDid,
    pub executor_signer_did: RadicleDid,
    pub executor_node_id: NodeId,
}

/// A running Radicle node whose child lifetime is tied to the API process.
pub struct RunningNode {
    pub configuration: NodeConfiguration,
    pub node_id: NodeId,
    pub signer_did: RadicleDid,
    child: Child,
}

impl RunningNode {
    /// Starts one dedicated profile and validates its live identity.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid paths, profile setup, node startup, or identity
    /// parsing.
    pub fn start(configuration: NodeConfiguration) -> Result<Self, DeploymentError> {
        validate_configuration(&configuration)?;
        fs::create_dir_all(&configuration.rad_home).map_err(|_| DeploymentError)?;
        ensure_profile(&configuration)?;
        let profile_signer_did = profile_did(&configuration)?;
        configure_node(&configuration)?;
        let mut child = Command::new(&configuration.rad_executable)
            .args(["node", "start", "--foreground"])
            .env_clear()
            .env("HOME", &configuration.rad_home)
            .env("RAD_HOME", &configuration.rad_home)
            .env("RAD_PASSPHRASE", "")
            .env("PATH", &configuration.helper_path)
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| DeploymentError)?;
        let started = Instant::now();
        let node_id = loop {
            if child.try_wait().map_err(|_| DeploymentError)?.is_some() {
                return Err(DeploymentError);
            }
            if let Ok(value) = rad_output(&configuration, ["node", "status", "--only", "nid"])
                && let Ok(node_id) = NodeId::parse(value.trim())
            {
                break node_id;
            }
            if started.elapsed() >= NODE_START_TIMEOUT {
                let _ = child.kill();
                let _ = child.wait();
                return Err(DeploymentError);
            }
            thread::sleep(Duration::from_millis(100));
        };
        let signer_did =
            RadicleDid::parse(format!("did:key:{node_id}")).map_err(|_| DeploymentError)?;
        if signer_did != profile_signer_did {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DeploymentError);
        }
        Ok(Self {
            configuration,
            node_id,
            signer_did,
            child,
        })
    }

    /// Connects to one explicitly configured peer.
    ///
    /// # Errors
    ///
    /// Fails closed for an invalid address or unsuccessful node connection.
    pub fn connect(&self, peer: &NodeId, address: &str) -> Result<(), DeploymentError> {
        if address.is_empty()
            || address.len() > 253
            || address
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':')))
        {
            return Err(DeploymentError);
        }
        let peer_address = format!("{peer}@{address}");
        rad(
            &self.configuration,
            ["node", "connect", peer_address.as_str(), "--timeout", "10s"],
        )
        .map(|_| ())
    }
}

impl Drop for RunningNode {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Loads or creates the append-only demo repository without retaining the
/// temporary maintainer key in the executor trust domain.
///
/// # Errors
///
/// Fails closed when persisted facts drift from the executor identity or any
/// bounded repository bootstrap step fails.
#[allow(
    clippy::too_many_lines,
    reason = "first-boot identity separation and repository facts remain linear for auditability"
)]
pub fn ensure_demo_repository(node: &RunningNode) -> Result<DeploymentMetadata, DeploymentError> {
    if node.configuration.role != NodeRole::Executor {
        return Err(DeploymentError);
    }
    let metadata_path = node.configuration.rad_home.join("auths-demo.json");
    if metadata_path.exists() {
        let bytes = fs::read(&metadata_path).map_err(|_| DeploymentError)?;
        let metadata: DeploymentMetadata =
            serde_json::from_slice(&bytes).map_err(|_| DeploymentError)?;
        if metadata.executor_node_id != node.node_id
            || metadata.executor_signer_did != node.signer_did
        {
            return Err(DeploymentError);
        }
        return Ok(metadata);
    }

    let temporary = tempfile::tempdir().map_err(|_| DeploymentError)?;
    let maintainer_home = temporary.path().join("maintainer");
    let repository = temporary.path().join("repository");
    fs::create_dir_all(repository.join("demo/runs")).map_err(|_| DeploymentError)?;
    let maintainer = NodeConfiguration {
        role: NodeRole::Maintainer,
        rad_executable: node.configuration.rad_executable.clone(),
        git_executable: node.configuration.git_executable.clone(),
        helper_path: node.configuration.helper_path.clone(),
        rad_home: maintainer_home,
        listen: available_local_address()?,
    };
    fs::create_dir_all(&maintainer.rad_home).map_err(|_| DeploymentError)?;
    ensure_profile_with_alias(&maintainer, "auths-demo-maintainer")?;
    fs::write(
        repository.join("demo/runs/README.txt"),
        b"Auths x Radicle public demonstration\n\nEvery patch here crossed the protected executor boundary after exact authorization.\n",
    )
    .map_err(|_| DeploymentError)?;
    git(
        &maintainer,
        &repository,
        ["init", "--quiet", "--initial-branch=main"],
    )?;
    git(
        &maintainer,
        &repository,
        ["config", "user.name", "Auths Radicle Demo"],
    )?;
    git(
        &maintainer,
        &repository,
        ["config", "user.email", "demo@auths.dev"],
    )?;
    git(&maintainer, &repository, ["add", "demo/runs/README.txt"])?;
    git(
        &maintainer,
        &repository,
        [
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "--quiet",
            "-m",
            "Initialize append-only Auths demo repository",
        ],
    )?;
    rad_in(
        &maintainer,
        &repository,
        [
            "init",
            "--name",
            "Auths-Authorization-Lab",
            "--description",
            "Append-only public fixtures proving exact Auths authorization for Radicle issue patches.",
            "--default-branch",
            "main",
            "--public",
            "--no-confirm",
            "--no-seed",
        ],
    )?;
    let rid_output = rad_output_in(&maintainer, &repository, ["inspect", "--rid"])?;
    let rid = Rid::parse(rid_output.trim()).map_err(|_| DeploymentError)?;
    let issue_output = rad_output_in(
        &maintainer,
        &repository,
        [
            "issue",
            "open",
            "--title",
            "Prove one exact authorized patch",
            "--description",
            "This append-only issue exists only for the public Auths demonstration. The protected executor may publish bounded patches under demo/runs/ and must never update canonical state.",
            "--no-announce",
        ],
    )?;
    let issue_id = issue_output
        .lines()
        .find(|line| line.split_whitespace().any(|field| field == "Issue"))
        .and_then(|line| {
            line.split_whitespace()
                .find_map(|field| CobId::parse(field).ok())
        })
        .ok_or(DeploymentError)?;
    let canonical_base_oid =
        GitOid::parse(git_output(&maintainer, &repository, ["rev-parse", "HEAD"])?.trim())
            .map_err(|_| DeploymentError)?;
    let identity_history = rad_output_in(&maintainer, &repository, ["inspect", "--history"])?;
    let repository_identity_revision = identity_history
        .lines()
        .find_map(|line| line.strip_prefix("commit "))
        .and_then(|value| GitOid::parse(value).ok())
        .ok_or(DeploymentError)?;
    let maintainer_signer_did = profile_did(&maintainer)?;
    let maintainer_node = RunningNode::start(maintainer.clone())?;
    rad(
        &maintainer_node.configuration,
        ["seed", rid.as_str(), "--no-fetch", "--scope", "all"],
    )?;
    node.connect(&maintainer_node.node_id, &maintainer.listen)?;
    rad(
        &node.configuration,
        [
            "seed",
            rid.as_str(),
            "--from",
            maintainer_node.node_id.as_str(),
            "--timeout",
            "15s",
            "--scope",
            "all",
        ],
    )?;
    let metadata = DeploymentMetadata {
        rid,
        issue_id,
        repository_identity_revision,
        canonical_base_oid,
        maintainer_did: maintainer_signer_did,
        executor_signer_did: node.signer_did.clone(),
        executor_node_id: node.node_id.clone(),
    };
    persist_json(&metadata_path, &metadata)?;
    Ok(metadata)
}

/// Resolves one validated RID to its local bare storage repository.
///
/// # Errors
///
/// Fails closed when the RID is malformed or its repository is absent.
pub fn storage_repository(rad_home: &Path, rid: &Rid) -> Result<PathBuf, DeploymentError> {
    let path = storage_repository_path(rad_home, rid)?;
    path.is_dir().then_some(path).ok_or(DeploymentError)
}

fn storage_repository_path(rad_home: &Path, rid: &Rid) -> Result<PathBuf, DeploymentError> {
    let storage_name = rid.as_str().strip_prefix("rad:").ok_or(DeploymentError)?;
    Ok(rad_home.join("storage").join(storage_name))
}

fn validate_configuration(configuration: &NodeConfiguration) -> Result<(), DeploymentError> {
    if configuration.role.alias().is_empty()
        || !configuration.rad_executable.is_absolute()
        || !configuration.git_executable.is_absolute()
        || !configuration.helper_path.is_absolute()
        || !configuration.rad_home.is_absolute()
        || configuration.listen.is_empty()
    {
        return Err(DeploymentError);
    }
    Ok(())
}

fn ensure_profile(configuration: &NodeConfiguration) -> Result<(), DeploymentError> {
    if profile_did(configuration).is_ok() {
        return Ok(());
    }
    ensure_profile_with_alias(configuration, configuration.role.alias())
}

fn ensure_profile_with_alias(
    configuration: &NodeConfiguration,
    alias: &str,
) -> Result<(), DeploymentError> {
    rad(configuration, ["auth", "--alias", alias])?;
    profile_did(configuration).map(|_| ())
}

fn profile_did(configuration: &NodeConfiguration) -> Result<RadicleDid, DeploymentError> {
    RadicleDid::parse(rad_output(configuration, ["self", "--did"])?.trim())
        .map_err(|_| DeploymentError)
}

fn configure_node(configuration: &NodeConfiguration) -> Result<(), DeploymentError> {
    let path = configuration.rad_home.join("config.json");
    let mut value = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
        .unwrap_or_else(|| serde_json::json!({}));
    value["node"]["alias"] = configuration.role.alias().into();
    value["node"]["listen"] = serde_json::json!([configuration.listen]);
    value["node"]["externalAddresses"] = serde_json::json!([]);
    value["node"]["seedingPolicy"] = serde_json::json!({"default": "block"});
    persist_json(&path, &value)?;
    rad(configuration, ["config"]).map(|_| ())
}

fn available_local_address() -> Result<String, DeploymentError> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| DeploymentError)?;
    let address = listener.local_addr().map_err(|_| DeploymentError)?;
    drop(listener);
    Ok(address.to_string())
}

fn persist_json(path: &Path, value: &impl Serialize) -> Result<(), DeploymentError> {
    let parent = path.parent().ok_or(DeploymentError)?;
    fs::create_dir_all(parent).map_err(|_| DeploymentError)?;
    let bytes = serde_json::to_vec(value).map_err(|_| DeploymentError)?;
    let mut temporary = NamedTempFile::new_in(parent).map_err(|_| DeploymentError)?;
    temporary
        .write_all(&bytes)
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| DeploymentError)?;
    temporary.persist(path).map_err(|_| DeploymentError)?;
    Ok(())
}

fn git<const N: usize>(
    configuration: &NodeConfiguration,
    repository: &Path,
    arguments: [&str; N],
) -> Result<Output, DeploymentError> {
    command(
        configuration,
        &configuration.git_executable,
        Some(repository),
        arguments,
    )
}

pub fn git_output<const N: usize>(
    configuration: &NodeConfiguration,
    repository: &Path,
    arguments: [&str; N],
) -> Result<String, DeploymentError> {
    output_string(git(configuration, repository, arguments)?)
}

fn rad<const N: usize>(
    configuration: &NodeConfiguration,
    arguments: [&str; N],
) -> Result<Output, DeploymentError> {
    command(
        configuration,
        &configuration.rad_executable,
        None,
        arguments,
    )
}

fn rad_in<const N: usize>(
    configuration: &NodeConfiguration,
    repository: &Path,
    arguments: [&str; N],
) -> Result<Output, DeploymentError> {
    command(
        configuration,
        &configuration.rad_executable,
        Some(repository),
        arguments,
    )
}

pub fn rad_output<const N: usize>(
    configuration: &NodeConfiguration,
    arguments: [&str; N],
) -> Result<String, DeploymentError> {
    output_string(rad(configuration, arguments)?)
}

fn rad_output_in<const N: usize>(
    configuration: &NodeConfiguration,
    repository: &Path,
    arguments: [&str; N],
) -> Result<String, DeploymentError> {
    output_string(rad_in(configuration, repository, arguments)?)
}

fn command<const N: usize>(
    configuration: &NodeConfiguration,
    executable: &Path,
    current_dir: Option<&Path>,
    arguments: [&str; N],
) -> Result<Output, DeploymentError> {
    let output_directory = tempfile::tempdir().map_err(|_| DeploymentError)?;
    let stdout_path = output_directory.path().join("stdout");
    let stderr_path = output_directory.path().join("stderr");
    let stdout = fs::File::create(&stdout_path).map_err(|_| DeploymentError)?;
    let stderr = fs::File::create(&stderr_path).map_err(|_| DeploymentError)?;
    let mut process = Command::new(executable);
    process
        .args(arguments)
        .env_clear()
        .env("HOME", &configuration.rad_home)
        .env("RAD_HOME", &configuration.rad_home)
        .env("RAD_PASSPHRASE", "")
        .env("PATH", &configuration.helper_path)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if let Some(current_dir) = current_dir {
        process.current_dir(current_dir);
    }
    let mut child = process.spawn().map_err(|_| DeploymentError)?;
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|_| DeploymentError)? {
            break status;
        }
        if started.elapsed() >= COMMAND_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(DeploymentError);
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = fs::read(stdout_path).map_err(|_| DeploymentError)?;
    let stderr = fs::read(stderr_path).map_err(|_| DeploymentError)?;
    if !status.success() || stdout.len() > MAX_OUTPUT_BYTES || stderr.len() > MAX_OUTPUT_BYTES {
        return Err(DeploymentError);
    }
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn output_string(output: Output) -> Result<String, DeploymentError> {
    String::from_utf8(output.stdout).map_err(|_| DeploymentError)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Radicle deployment bootstrap failed closed")]
pub struct DeploymentError;

#[cfg(test)]
mod tests {
    use std::{
        net::TcpListener,
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };

    use auths_radicle::{
        AuthorizeRequest, RadicleIssueWorkflowService, ServiceDependencies, WorkflowOutcome,
        adapters::{
            JsonlReceiptSink, RadicleCliEvidenceSource, RadicleCliWriter,
            RadicleCliWriterConfiguration, SdkProofVerifier,
        },
        candidate::GitCandidateInspector,
        ports::{Clock, EvidenceSource as _, PortError},
    };

    use crate::{
        HttpPropagationObserver, ObserverRuntime, authorization_fixture,
        lifecycle::DemoRadicleLifecycleRegistry,
        observer_app,
        scenario::{live_configuration, live_grant, live_submission},
    };

    use super::*;

    #[test]
    #[ignore = "requires the version-pinned Radicle and Git executables"]
    #[allow(
        clippy::too_many_lines,
        reason = "the real three-identity, two-node trust-boundary sequence stays explicit"
    )]
    fn stable_cli_executes_and_replicates_one_real_did_key_patch() {
        let rad_executable = PathBuf::from(
            std::env::var("AUTHS_RADICLE_TEST_RAD")
                .expect("AUTHS_RADICLE_TEST_RAD must name the pinned rad executable"),
        );
        let git_executable = PathBuf::from(
            std::env::var("AUTHS_RADICLE_TEST_GIT")
                .expect("AUTHS_RADICLE_TEST_GIT must name the pinned git executable"),
        );
        let helper_path = PathBuf::from(
            std::env::var("AUTHS_RADICLE_TEST_PATH")
                .expect("AUTHS_RADICLE_TEST_PATH must contain git-remote-rad"),
        );
        let temporary = tempfile::tempdir().expect("isolated Radicle deployment");
        let executor_address = available_address();
        let observer_address = available_address();
        let executor = RunningNode::start(NodeConfiguration {
            role: NodeRole::Executor,
            rad_executable: rad_executable.clone(),
            git_executable: git_executable.clone(),
            helper_path: helper_path.clone(),
            rad_home: temporary.path().join("executor"),
            listen: executor_address.clone(),
        })
        .expect("stable executor node");
        let observer = Arc::new(
            RunningNode::start(NodeConfiguration {
                role: NodeRole::Observer,
                rad_executable: rad_executable.clone(),
                git_executable: git_executable.clone(),
                helper_path: helper_path.clone(),
                rad_home: temporary.path().join("observer"),
                listen: observer_address.clone(),
            })
            .expect("stable observer node"),
        );
        let metadata = ensure_demo_repository(&executor).expect("real Radicle demo repository");

        assert!(executor.signer_did.as_str().starts_with("did:key:z"));
        assert!(observer.signer_did.as_str().starts_with("did:key:z"));
        assert!(metadata.maintainer_did.as_str().starts_with("did:key:z"));
        assert_ne!(metadata.maintainer_did, metadata.executor_signer_did);
        assert_ne!(observer.signer_did, metadata.executor_signer_did);
        assert_eq!(metadata.executor_signer_did, executor.signer_did);
        assert_eq!(
            format!("did:key:{}", metadata.executor_node_id),
            metadata.executor_signer_did.as_str()
        );
        let executor_repository =
            storage_repository(&executor.configuration.rad_home, &metadata.rid)
                .expect("executor repository");

        executor
            .connect(&observer.node_id, &observer_address)
            .expect("executor connects to observer");
        let observer_token = "test-observer-token-0000000000000000";
        let observer_http = TcpListener::bind("127.0.0.1:0").expect("observer HTTP port");
        let observer_http_address = observer_http.local_addr().expect("observer HTTP address");
        observer_http
            .set_nonblocking(true)
            .expect("nonblocking observer HTTP listener");
        let observer_router = observer_app(
            ObserverRuntime::new(Arc::clone(&observer), observer_token.into(), "test".into())
                .expect("observer runtime"),
        );
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let observer_server = std::thread::spawn(move || {
            let runtime = tokio::runtime::Runtime::new().expect("observer HTTP runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(observer_http)
                    .expect("observer HTTP listener");
                axum::serve(listener, observer_router)
                    .with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("observer HTTP server");
            });
        });
        let propagation_observer = HttpPropagationObserver::new(
            format!("http://{observer_http_address}"),
            observer_token.into(),
            executor_address,
            observer.node_id.clone(),
        )
        .expect("HTTP observer client");
        propagation_observer
            .prepare(&metadata, &executor.node_id)
            .expect("observer independently prepares repository and issue");

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("trusted test time")
            .as_secs();
        let workflow_id =
            auths_radicle::WorkflowId::parse(format!("demo-{now}")).expect("bounded workflow id");
        let configuration =
            live_configuration(executor.signer_did.clone(), observer.node_id.clone())
                .expect("live verifier configuration");
        let grant = live_grant(&metadata, configuration.clone(), workflow_id.clone(), now)
            .expect("live workflow grant");
        let submission = live_submission(
            &git_executable,
            &executor_repository,
            &metadata.canonical_base_oid,
            &workflow_id,
        )
        .expect("bounded keyless candidate");
        let inspector =
            GitCandidateInspector::new(git_executable.clone()).expect("pinned Git inspector");
        let expected_rad_version = command_version(&rad_executable);
        let executor_cli = RadicleCliWriter::new(RadicleCliWriterConfiguration {
            git_executable: git_executable.clone(),
            rad_executable: rad_executable.clone(),
            helper_path: helper_path.clone(),
            rad_home: executor.configuration.rad_home.clone(),
            expected_rad_version: expected_rad_version.clone(),
            announce_timeout_seconds: 15,
            announce_replicas: 1,
        })
        .expect("pinned executor CLI");
        let facts = inspector
            .inspect(&submission, &configuration)
            .expect("candidate quarantine")
            .facts()
            .clone();
        let evidence_source = RadicleCliEvidenceSource::new(executor_cli.clone());
        let evidence = evidence_source
            .observe(&metadata.rid, &metadata.issue_id, &configuration, now)
            .expect("synchronized Radicle evidence");
        let action = auths_radicle::derive_exact_action(
            &grant,
            &configuration,
            &submission,
            &facts,
            &evidence,
        )
        .expect("exact live action");
        let fixture = authorization_fixture(&action, now, [0x91; 32]);
        let state_path = temporary.path().join("executor/lifecycle");
        let obsolete_state_path = temporary.path().join("executor/workflows.json");
        let receipt_path = temporary.path().join("executor/receipts.jsonl");
        let service = RadicleIssueWorkflowService::new(ServiceDependencies {
            candidate_inspector: inspector,
            evidence_source,
            proof_verifier: SdkProofVerifier::new(fixture.verifier),
            workflow_store: DemoRadicleLifecycleRegistry::open(state_path, &obsolete_state_path)
                .expect("durable workflow store"),
            radicle_writer: executor_cli,
            propagation_observer,
            receipt_sink: JsonlReceiptSink::new(receipt_path).expect("append-only receipts"),
            clock: FixedClock(now),
            executed_configuration: configuration.clone(),
        });
        let outcome = service
            .execute(AuthorizeRequest {
                workflow_grant: grant,
                required_configuration: configuration,
                candidate: submission,
                proof: fixture.proof,
                auths_request: fixture.request,
            })
            .expect("real end-to-end workflow");
        let WorkflowOutcome::Executed {
            stage,
            execution,
            propagation,
            ..
        } = outcome
        else {
            panic!("exact action must publish")
        };
        assert_eq!(stage, auths_radicle::workflow::WorkflowStage::Replicated);
        assert_eq!(
            execution.publication.signer_did,
            metadata.executor_signer_did
        );
        assert_eq!(
            propagation.expect("independent receipt").observer_node_id,
            observer.node_id
        );
        assert_eq!(
            git_output(
                &executor.configuration,
                &executor_repository,
                ["rev-parse", "refs/heads/main"],
            )
            .expect("canonical branch")
            .trim(),
            metadata.canonical_base_oid.as_str()
        );
        let _ = shutdown_tx.send(());
        observer_server.join().expect("observer HTTP shutdown");
    }

    #[derive(Clone, Copy)]
    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now(&self) -> Result<u64, PortError> {
            Ok(self.0)
        }
    }

    fn available_address() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral test port");
        let address = listener.local_addr().expect("bound test address");
        drop(listener);
        address.to_string()
    }

    fn command_version(rad_executable: &Path) -> String {
        let output = Command::new(rad_executable)
            .arg("--version")
            .output()
            .expect("pinned rad --version");
        assert!(output.status.success());
        String::from_utf8(output.stdout)
            .expect("rad version UTF-8")
            .trim()
            .to_owned()
    }
}
