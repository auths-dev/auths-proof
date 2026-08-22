//! Privileged Auths deployment CLI.

#![forbid(unsafe_code)]

use auths_config::{AgentConfig, AgentPlatform};
#[cfg(all(
    unix,
    any(not(feature = "qualification-failpoints"), target_os = "linux")
))]
use auths_connections::RegistryLimits;
use auths_model::{ProfileId, ProfileRef};
#[cfg(all(unix, not(feature = "qualification-failpoints")))]
use auths_node::bind_local_control_plane;
#[cfg(unix)]
use auths_node::load_receipt_trust_anchors;
#[cfg(all(
    unix,
    any(not(feature = "qualification-failpoints"), target_os = "linux")
))]
use auths_node::{LocalAgentDeploymentConfig, LocalAgentResources};
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use auths_node::{
    QualificationClientBridgePolicy, QualificationCredentialBrokerPolicy,
    QualificationProviderProxyPolicy, bind_qualification_control_plane,
};
use auths_node::{WorkloadAuthoritySnapshot, pack_workload_authority};
use auths_production_client::LOCAL_AGENT_CONTENT_TYPE;
#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
use auths_profile_kit::{QualificationFailpoint, qualification_state_directory_commitment};
use auths_receipts::encode_receipt_trust_anchors;
use clap::{Args, Parser, Subcommand};
use minicbor::{Decoder, Encoder, data::Type};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
#[cfg(all(
    unix,
    any(not(feature = "qualification-failpoints"), target_os = "linux")
))]
use std::num::NonZeroUsize;
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt as _;
use std::{
    env,
    fs::{self, File},
    io::{IsTerminal as _, Read as _, Write as _},
    num::NonZeroU64,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::UnixStream,
};

const MAX_ADMIN_RESPONSE_BYTES: usize = 16_777_216;
const MAX_ADMIN_HEADER_BYTES: usize = 16_384;
const MAX_DESCRIPTOR_BYTES: usize = 65_536;
const MAX_SECRET_BYTES: usize = 65_536;

#[derive(Parser)]
#[command(name = "auths", version, about = "Auths deployment administration")]
struct Cli {
    /// Absolute path to the privileged local administration socket.
    #[arg(long, global = true)]
    admin_socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
// This is a one-shot CLI parse tree; boxing its larger branch would add
// indirection without reducing retained service state.
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Manage provider connections without exposing credentials to applications.
    Connections(Connections),
    /// Validate and package deployment-owned workload authority.
    Agent(Agent),
}

#[derive(Args)]
struct Agent {
    #[command(subcommand)]
    command: AgentCommand,
}

#[derive(Subcommand)]
// Qualification-only serve arguments enlarge this one-shot CLI parse tree.
#[allow(clippy::large_enum_variant)]
enum AgentCommand {
    /// Package already-issued proof and context into a sealed authority file.
    Authority(Authority),
    /// Validate workload mappings and every configured authority artifact.
    ValidateConfig { config: PathBuf },
    /// Start the workload and privileged local-agent sockets.
    Serve(ServeAgent),
    /// Export deployment-owned public portable-receipt trust.
    ReceiptAnchors(ReceiptAnchors),
}

#[derive(Args)]
struct ReceiptAnchors {
    #[command(subcommand)]
    command: ReceiptAnchorsCommand,
}

#[derive(Subcommand)]
enum ReceiptAnchorsCommand {
    /// Export canonical public anchors without exposing signing seeds.
    Export(ExportReceiptAnchors),
}

#[derive(Args)]
struct ExportReceiptAnchors {
    /// Exact local-agent configuration containing receipt signing policy.
    #[arg(long)]
    config: PathBuf,
    /// New canonical JSON output; existing paths are never overwritten.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct ServeAgent {
    /// Workload selector and sealed-authority configuration.
    #[arg(long)]
    config: PathBuf,
    /// Owner-only directory for sockets, journals, credentials, and recovery state.
    #[arg(long)]
    state_directory: PathBuf,
    /// Application socket; defaults to `STATE_DIRECTORY/agent.sock`.
    #[arg(long)]
    agent_socket: Option<PathBuf>,
    /// Privileged administration socket; defaults to `STATE_DIRECTORY/admin.sock`.
    #[arg(long)]
    admin_socket: Option<PathBuf>,
    /// Operating-system UID allowed to own agent state and sockets.
    #[arg(long)]
    agent_uid: Option<u32>,
    /// Additional UID allowed on the privileged administration socket.
    #[arg(long = "admin-uid")]
    admin_uids: Vec<u32>,
    /// Qualification-only inherited output descriptor for journal-boundary
    /// acknowledgements.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_journal_gate_output_fd: Option<u32>,
    /// Qualification-only inherited input descriptor for boundary releases.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_journal_gate_input_fd: Option<u32>,
    /// Qualification-only closed failpoint selected before startup.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_failpoint: Option<String>,
    /// Qualification-only nonzero deployment generation bound into evidence.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_agent_generation: Option<u32>,
    /// Qualification-only controller-minted launch identity.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_control_operation_id: Option<String>,
    /// Qualification-only controller nonce commitment.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_controller_nonce_sha256: Option<String>,
    /// Qualification-only direct controller parent process.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_controller_pid: Option<u32>,
    /// Qualification-only sealed configuration descriptor inherited from the
    /// protected launcher.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_config_fd: Option<u32>,
    /// Exact SHA-256 of the sealed qualification configuration bytes.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_config_sha256: Option<String>,
    /// Qualification-only pinned state-directory descriptor inherited from
    /// the protected launcher.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_state_directory_fd: Option<u32>,
    /// Exact inode-bound commitment to the qualification state directory.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_state_directory_sha256: Option<String>,
    /// Qualification-only protected `ClientProxy` reader UID.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_client_proxy_uid: Option<u32>,
    /// Exact protected `ClientProxy` reader executable digest.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_client_proxy_sha256: Option<String>,
    /// Qualification-only protected `CredentialBroker` socket.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_credential_broker_socket: Option<PathBuf>,
    /// Qualification-only protected `CredentialBroker` reader UID.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_credential_broker_uid: Option<u32>,
    /// Exact protected `CredentialBroker` reader executable digest.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_credential_broker_sha256: Option<String>,
    /// Qualification-only protected `ProviderProxy` socket.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_provider_proxy_socket: Option<PathBuf>,
    /// Qualification-only protected `ProviderProxy` reader UID.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_provider_proxy_uid: Option<u32>,
    /// Exact protected `ProviderProxy` reader executable digest.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_provider_proxy_sha256: Option<String>,
    /// Exact provider-row source-context commitment.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_source_context_sha256: Option<String>,
    /// Qualification-only recovery key identifier bound by the ledger plan.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_recovery_key_id: Option<String>,
    /// Qualification-only recovery public key bound by the ledger plan.
    #[cfg(feature = "qualification-failpoints")]
    #[arg(long, hide = true)]
    qualification_recovery_public_key_base64url: Option<String>,
}

#[derive(Args)]
struct Authority {
    #[command(subcommand)]
    command: AuthorityCommand,
}

#[derive(Subcommand)]
enum AuthorityCommand {
    /// Create a canonical auths.workload-authority-file/1 without overwriting.
    Pack(PackAuthority),
}

#[derive(Args)]
struct PackAuthority {
    #[arg(long)]
    principal: String,
    #[arg(long = "profile", required = true)]
    profiles: Vec<String>,
    #[arg(long)]
    proof_file: PathBuf,
    #[arg(long)]
    trusted_context_file: PathBuf,
    #[arg(long)]
    not_before: i64,
    #[arg(long)]
    expires_at: i64,
    #[arg(long)]
    artifact_id: String,
    #[arg(long)]
    output: PathBuf,
}

#[derive(Args)]
struct Connections {
    #[command(subcommand)]
    command: ConnectionCommand,
}

#[derive(Subcommand)]
enum ConnectionCommand {
    /// Install a provider/account connection from protected input.
    Add(AddConnection),
    /// List sanitized connection records.
    List,
    /// Inspect one sanitized connection record.
    Inspect { connection: String },
    /// Refuse new operations while preserving recovery.
    Disable { connection: String },
    /// Re-enable an existing non-revoked connection.
    Enable { connection: String },
    /// Install a successor credential generation.
    Rotate(RotateConnection),
    /// Permanently revoke a connection and its current credential.
    Revoke { connection: String },
}

#[derive(Args)]
struct AddConnection {
    provider: String,
    #[arg(long)]
    alias: String,
    /// Canonical provider descriptor file. This file never contains a secret.
    #[arg(long)]
    descriptor: PathBuf,
    #[arg(long = "allow-workload", required = true)]
    allow_workloads: Vec<String>,
    #[arg(long = "allow-profile", required = true)]
    allow_profiles: Vec<String>,
    /// Protected credential file. If omitted, bounded bytes are read from non-terminal stdin.
    #[arg(long)]
    secret_file: Option<PathBuf>,
}

#[derive(Args)]
struct RotateConnection {
    connection: String,
    /// Protected successor credential file; otherwise use non-terminal stdin.
    #[arg(long)]
    secret_file: Option<PathBuf>,
}

#[tokio::main]
pub(crate) async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths: {error}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Command::Connections(connections) => {
            let socket = discover_admin_socket(cli.admin_socket)?;
            match connections.command {
                ConnectionCommand::Add(arguments) => add_connection(&socket, arguments).await?,
                ConnectionCommand::List => {
                    let response = request(&socket, "GET", "/v1/admin/connections", &[]).await?;
                    print_json(decode_list(&response)?)?;
                }
                ConnectionCommand::Inspect { connection } => {
                    let (provider, alias) = connection_key(&connection)?;
                    let path = format!("/v1/admin/connections/{provider}/{alias}");
                    let response = request(&socket, "GET", &path, &[]).await?;
                    print_json(decode_record_response(&response)?)?;
                }
                ConnectionCommand::Disable { connection } => {
                    mutate_state(&socket, &connection, "disable").await?;
                }
                ConnectionCommand::Enable { connection } => {
                    mutate_state(&socket, &connection, "enable").await?;
                }
                ConnectionCommand::Revoke { connection } => {
                    mutate_state(&socket, &connection, "revoke").await?;
                }
                ConnectionCommand::Rotate(arguments) => {
                    rotate_connection(&socket, arguments).await?;
                }
            }
        }
        Command::Agent(agent) => match agent.command {
            AgentCommand::Authority(authority) => match authority.command {
                AuthorityCommand::Pack(arguments) => pack_authority(arguments)?,
            },
            AgentCommand::ValidateConfig { config } => validate_agent_config(&config)?,
            AgentCommand::Serve(arguments) => serve_agent(arguments).await?,
            AgentCommand::ReceiptAnchors(arguments) => match arguments.command {
                ReceiptAnchorsCommand::Export(arguments) => export_receipt_anchors(&arguments)?,
            },
        },
    }
    Ok(())
}

#[cfg(unix)]
fn export_receipt_anchors(
    arguments: &ExportReceiptAnchors,
) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bounded_regular_file(&arguments.config, 4 * 1024 * 1024, false)?;
    let source = std::str::from_utf8(&bytes)?;
    let platform = if cfg!(target_os = "linux") {
        AgentPlatform::Linux
    } else {
        AgentPlatform::Macos
    };
    let config = AgentConfig::from_toml(source, platform)?;
    let anchors = load_receipt_trust_anchors(config.receipt_signing())?;
    let encoded = encode_receipt_trust_anchors(&anchors)?;
    publish_owner_only(&arguments.output, &encoded)?;
    print_json(json!({
        "anchors": anchors.anchors().len(),
        "output": arguments.output,
        "schema": "auths.receipt-trust-anchors/1",
        "sha256": hex::encode(Sha256::digest(&encoded)),
    }))?;
    Ok(())
}

#[cfg(not(unix))]
fn export_receipt_anchors(
    _arguments: &ExportReceiptAnchors,
) -> Result<(), Box<dyn std::error::Error>> {
    Err("receipt-anchor export is currently qualified only on Unix platforms".into())
}

#[cfg(all(
    unix,
    any(not(feature = "qualification-failpoints"), target_os = "linux")
))]
#[allow(clippy::too_many_lines)]
async fn serve_agent(arguments: ServeAgent) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "qualification-failpoints")]
    let qualification_gate = match (
        arguments.qualification_failpoint.as_deref(),
        arguments.qualification_journal_gate_output_fd,
        arguments.qualification_journal_gate_input_fd,
        arguments.qualification_agent_generation,
        arguments.qualification_control_operation_id,
        arguments.qualification_controller_nonce_sha256,
        arguments.qualification_controller_pid,
    ) {
        (None, Some(1), Some(0), Some(generation), None, None, Some(controller_pid))
            if generation != 0 && controller_pid != 0 =>
        {
            Some((generation, None, None, None, controller_pid))
        }
        (
            Some(failpoint),
            Some(1),
            Some(0),
            Some(generation),
            Some(control_id),
            Some(nonce_sha256),
            Some(controller_pid),
        ) if generation != 0 && controller_pid != 0 => failpoint
            .strip_prefix("crash-")
            .and_then(QualificationFailpoint::from_token)
            .map(|failpoint| {
                (
                    generation,
                    Some(failpoint),
                    Some(control_id),
                    Some(nonce_sha256),
                    controller_pid,
                )
            }),
        _ => return Err("qualification failpoint selection is incomplete or unsupported".into()),
    };
    #[cfg(feature = "qualification-failpoints")]
    let qualification_gate = qualification_gate
        .map(
            |(generation, failpoint, control_id, nonce_sha256, controller_pid)| {
                let output = std::fs::File::from(rustix::io::dup(&std::io::stdout())?);
                let release = std::fs::File::from(rustix::io::dup(&std::io::stdin())?);
                rustix::io::fcntl_setfd(&output, rustix::io::FdFlags::CLOEXEC)?;
                rustix::io::fcntl_setfd(&release, rustix::io::FdFlags::CLOEXEC)?;
                let output_null = rustix::fs::open(
                    "/dev/null",
                    rustix::fs::OFlags::WRONLY | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )?;
                let input_null = rustix::fs::open(
                    "/dev/null",
                    rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )?;
                rustix::stdio::dup2_stdout(&output_null)?;
                rustix::stdio::dup2_stdin(&input_null)?;
                Ok::<_, Box<dyn std::error::Error>>((
                    output,
                    release,
                    generation,
                    failpoint,
                    control_id,
                    nonce_sha256,
                    controller_pid,
                ))
            },
        )
        .transpose()?;
    #[cfg(feature = "qualification-failpoints")]
    let qualification_config = match (
        arguments.qualification_config_fd,
        arguments.qualification_config_sha256.as_deref(),
    ) {
        (Some(fd @ 3..), Some(sha256)) => bounded_sealed_qualification_config(fd, sha256)?,
        _ => return Err("qualification agent requires its sealed configuration descriptor".into()),
    };
    #[cfg(feature = "qualification-failpoints")]
    let qualification_client_bridge = match (
        arguments.qualification_client_proxy_uid,
        arguments.qualification_client_proxy_sha256.as_deref(),
        arguments.qualification_source_context_sha256.as_deref(),
    ) {
        (Some(uid), Some(artifact), Some(source_context)) => QualificationClientBridgePolicy::new(
            uid,
            rustix::process::getegid().as_raw(),
            artifact,
            source_context,
        )
        .map_err(|_| "qualification ClientProxy policy is invalid")?,
        _ => return Err("qualification agent requires its protected ClientProxy policy".into()),
    };
    #[cfg(feature = "qualification-failpoints")]
    let qualification_credential_broker = match (
        arguments.qualification_credential_broker_socket,
        arguments.qualification_credential_broker_uid,
        arguments.qualification_credential_broker_sha256.as_deref(),
        arguments.qualification_source_context_sha256.as_deref(),
    ) {
        (Some(socket), Some(uid), Some(artifact), Some(source_context)) => {
            QualificationCredentialBrokerPolicy::new(socket, uid, artifact, source_context)
                .map_err(|_| "qualification CredentialBroker policy is invalid")?
        }
        _ => {
            return Err(
                "qualification agent requires its protected CredentialBroker policy".into(),
            );
        }
    };
    #[cfg(feature = "qualification-failpoints")]
    let qualification_provider_proxy = match (
        arguments.qualification_provider_proxy_socket,
        arguments.qualification_provider_proxy_uid,
        arguments.qualification_provider_proxy_sha256.as_deref(),
        arguments.qualification_source_context_sha256.as_deref(),
    ) {
        (Some(socket), Some(uid), Some(artifact), Some(source_context)) => {
            QualificationProviderProxyPolicy::new(socket, uid, artifact, source_context)
                .map_err(|_| "qualification ProviderProxy policy is invalid")?
        }
        _ => {
            return Err("qualification agent requires its protected ProviderProxy policy".into());
        }
    };
    let uid = arguments.agent_uid.unwrap_or(effective_uid()?);
    #[cfg(feature = "qualification-failpoints")]
    let state = match (
        arguments.qualification_state_directory_fd,
        arguments.qualification_state_directory_sha256.as_deref(),
    ) {
        (Some(fd @ 3..), Some(sha256)) if Some(fd) != arguments.qualification_config_fd => {
            prepare_pinned_qualification_state_directory(
                fd,
                sha256,
                &arguments.state_directory,
                uid,
            )?
        }
        _ => return Err("qualification agent requires its pinned state directory".into()),
    };
    #[cfg(not(feature = "qualification-failpoints"))]
    let state = prepare_state_directory(&arguments.state_directory, uid)?;
    #[cfg(feature = "qualification-failpoints")]
    let config_bytes = qualification_config;
    #[cfg(not(feature = "qualification-failpoints"))]
    let config_bytes = bounded_regular_file(&arguments.config, 4 * 1024 * 1024, false)?;
    let source = std::str::from_utf8(&config_bytes)?;
    let platform = if cfg!(target_os = "linux") {
        AgentPlatform::Linux
    } else {
        AgentPlatform::Macos
    };
    let agent_config = AgentConfig::from_toml(source, platform)?;
    let recovery_key = state.join("recovery.key");
    #[cfg(feature = "qualification-failpoints")]
    let (recovery_key_id, recovery_public_key_base64url) = match (
        arguments.qualification_recovery_key_id,
        arguments.qualification_recovery_public_key_base64url,
    ) {
        (Some(key_id), Some(public_key)) => (key_id, public_key),
        _ => return Err("qualification agent requires its reviewed recovery identity".into()),
    };
    #[cfg(not(feature = "qualification-failpoints"))]
    let recovery_key_id = {
        ensure_recovery_key(&recovery_key, uid)?;
        "local-agent-v1".to_owned()
    };
    let agent_socket = arguments
        .agent_socket
        .unwrap_or_else(|| state.join("agent.sock"));
    let admin_socket = arguments
        .admin_socket
        .unwrap_or_else(|| state.join("admin.sock"));
    let mut admin_uids = arguments.admin_uids;
    if !admin_uids.contains(&uid) {
        admin_uids.push(uid);
    }
    let deployment = LocalAgentDeploymentConfig::new(
        &agent_socket,
        &admin_socket,
        state.join("connections.cbor"),
        state.join("credentials.cbor"),
        state.join("operations.cbor"),
        recovery_key,
        recovery_key_id,
        state.join("admin-audit.jsonl"),
        uid,
        admin_uids,
        [],
        RegistryLimits {
            maximum_records: NonZeroUsize::new(10_000).ok_or("invalid registry limit")?,
            maximum_encoded_bytes: NonZeroUsize::new(268_435_456)
                .ok_or("invalid registry byte limit")?,
        },
    )?;
    #[cfg(not(all(feature = "qualification-failpoints", target_os = "linux")))]
    let resources = LocalAgentResources::open(&deployment, agent_config.receipt_signing())?;
    #[cfg(all(feature = "qualification-failpoints", target_os = "linux"))]
    let (output, release, generation, failpoint, control_id, nonce_sha256, controller_pid) =
        qualification_gate.ok_or("qualification journal gate is required")?;
    #[cfg(all(feature = "qualification-failpoints", target_os = "linux"))]
    let qualification_signing_directory = File::open(&state)?;
    #[cfg(all(feature = "qualification-failpoints", target_os = "linux"))]
    let resources = LocalAgentResources::open_qualification(
        &deployment,
        agent_config.receipt_signing(),
        &qualification_signing_directory,
        &recovery_public_key_base64url,
        output,
        release,
        generation,
        failpoint,
        control_id,
        nonce_sha256,
        controller_pid,
    )?;
    #[cfg(not(all(feature = "qualification-failpoints", target_os = "linux")))]
    let server = bind_local_control_plane(deployment, agent_config, resources)?;
    #[cfg(all(feature = "qualification-failpoints", target_os = "linux"))]
    let server = bind_qualification_control_plane(
        deployment,
        agent_config,
        resources,
        qualification_client_bridge,
        qualification_credential_broker,
        qualification_provider_proxy,
    )?;
    let readiness = json!({
        "adminSocket": admin_socket,
        "agentSocket": agent_socket,
        "stateDirectory": state,
        "status": "ready"
    });
    #[cfg(not(feature = "qualification-failpoints"))]
    print_json(readiness)?;
    #[cfg(feature = "qualification-failpoints")]
    eprintln!("{}", serde_json::to_string(&readiness)?);
    server.serve().await?;
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn bounded_sealed_qualification_config(
    fd: u32,
    expected_sha256: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rustix::fs::{SealFlags, fcntl_get_seals};
    use std::os::unix::fs::MetadataExt as _;

    let mut file = File::open(format!("/proc/self/fd/{fd}"))?;
    let metadata = file.metadata()?;
    let expected_seals = SealFlags::SEAL | SealFlags::SHRINK | SealFlags::GROW | SealFlags::WRITE;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > 4 * 1024 * 1024
        || fcntl_get_seals(&file)? != expected_seals
    {
        return Err("qualification configuration is not an exact sealed memfd".into());
    }
    let mut bytes = Vec::with_capacity(usize::try_from(metadata.len())?);
    std::io::Read::by_ref(&mut file)
        .take(4 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let after = file.metadata()?;
    if bytes.is_empty()
        || bytes.len() > 4 * 1024 * 1024
        || metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || after.len() != u64::try_from(bytes.len())?
        || hex::encode(Sha256::digest(&bytes)) != expected_sha256
    {
        return Err("sealed qualification configuration differs from its protected digest".into());
    }
    Ok(bytes)
}

#[cfg(all(target_os = "linux", feature = "qualification-failpoints"))]
fn prepare_pinned_qualification_state_directory(
    fd: u32,
    expected_sha256: &str,
    configured_path: &Path,
    uid: u32,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt as _;

    if !configured_path.is_absolute()
        || configured_path.as_os_str().as_encoded_bytes().len() > 1_024
        || configured_path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("qualification state directory path is not normalized".into());
    }
    let inherited = PathBuf::from(format!("/proc/self/fd/{fd}"));
    let file = File::open(&inherited)?;
    let access = rustix::fs::fcntl_getfl(&file)?;
    let metadata = file.metadata()?;
    let configured = configured_path
        .to_str()
        .ok_or("qualification state directory path is not UTF-8")?;
    let actual = qualification_state_directory_commitment(
        configured,
        metadata.dev(),
        metadata.ino(),
        metadata.uid(),
        metadata.mode() & 0o777,
    )?;
    if access & rustix::fs::OFlags::ACCMODE != rustix::fs::OFlags::RDONLY
        || !metadata.file_type().is_dir()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != 0o700
        || actual != expected_sha256
    {
        return Err("qualification state directory differs from its protected descriptor".into());
    }
    Ok(inherited)
}

#[cfg(all(unix, feature = "qualification-failpoints", not(target_os = "linux")))]
// The shared async dispatch remains identical across platform-gated binaries.
#[allow(clippy::unused_async)]
async fn serve_agent(_arguments: ServeAgent) -> Result<(), Box<dyn std::error::Error>> {
    Err("qualification agent is supported only on Linux".into())
}

#[cfg(not(unix))]
async fn serve_agent(_arguments: ServeAgent) -> Result<(), Box<dyn std::error::Error>> {
    Err("the local-agent service is currently qualified only on Unix platforms".into())
}

#[cfg(all(unix, not(feature = "qualification-failpoints")))]
fn prepare_state_directory(path: &Path, uid: u32) -> Result<PathBuf, Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 1_024
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("state directory must be a normalized absolute path".into());
    }
    if !path.exists() {
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        File::open(path.parent().ok_or("state directory has no parent")?)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("state directory is not owner-controlled".into());
    }
    Ok(path.to_owned())
}

#[cfg(all(unix, not(feature = "qualification-failpoints")))]
fn ensure_recovery_key(path: &Path, uid: u32) -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    if !path.exists() {
        let parent = path.parent().ok_or("recovery key has no parent")?;
        let mut key = [0_u8; 32];
        getrandom::fill(&mut key).map_err(|_| "operating-system randomness unavailable")?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        temporary.write_all(&key)?;
        temporary.as_file().sync_all()?;
        key.fill(0);
        temporary.persist_noclobber(path)?;
        File::open(parent)?.sync_all()?;
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.len() != 32
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != uid)
        || metadata.permissions().mode() & 0o077 != 0
    {
        return Err("recovery key is not owner-controlled".into());
    }
    Ok(())
}

fn pack_authority(mut arguments: PackAuthority) -> Result<(), Box<dyn std::error::Error>> {
    let profiles = arguments
        .profiles
        .iter()
        .map(|value| model_profile_ref(value))
        .collect::<Result<Vec<_>, _>>()?;
    let mut proof = bounded_regular_file(&arguments.proof_file, 262_144, true)?;
    let mut trusted_context =
        bounded_regular_file(&arguments.trusted_context_file, 2_097_152, true)?;
    let packed = pack_workload_authority(
        &arguments.principal,
        profiles,
        std::mem::take(&mut proof),
        std::mem::take(&mut trusted_context),
        arguments.not_before,
        arguments.expires_at,
        &arguments.artifact_id,
    );
    proof.fill(0);
    trusted_context.fill(0);
    let mut packed = packed?;
    let publish = publish_owner_only(&arguments.output, &packed);
    packed.fill(0);
    publish?;
    print_json(json!({
        "artifactId": arguments.artifact_id,
        "output": arguments.output,
        "profiles": arguments.profiles,
    }))?;
    arguments.principal.clear();
    Ok(())
}

fn validate_agent_config(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bytes = bounded_regular_file(path, 4 * 1024 * 1024, false)?;
    let source = std::str::from_utf8(&bytes)?;
    let platform = if cfg!(target_os = "linux") {
        AgentPlatform::Linux
    } else if cfg!(target_os = "macos") {
        AgentPlatform::Macos
    } else {
        AgentPlatform::Windows
    };
    let config = AgentConfig::from_toml(source, platform)?;
    #[cfg(unix)]
    WorkloadAuthoritySnapshot::load(&config, effective_uid()?)?;
    #[cfg(not(unix))]
    return Err("secure authority validation is not implemented on this platform".into());
    print_json(json!({
        "authoritySources": config.authority_sources().len(),
        "valid": true,
        "workloads": config.workloads().len(),
    }))?;
    Ok(())
}

fn model_profile_ref(value: &str) -> Result<ProfileRef, Box<dyn std::error::Error>> {
    let (id, version) = value.rsplit_once('/').ok_or("invalid profile reference")?;
    let version = version.parse::<u16>()?;
    Ok(ProfileRef::new(ProfileId::parse(id)?, version)?)
}

fn publish_owner_only(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
        || path.as_os_str().as_encoded_bytes().len() > 1_024
    {
        return Err("authority output must be a normalized absolute path".into());
    }
    let parent = path.parent().ok_or("authority output has no parent")?;
    let metadata = fs::symlink_metadata(parent)?;
    if !metadata.file_type().is_dir() {
        return Err("authority output parent is not a directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let uid = effective_uid()?;
        if (metadata.uid() != 0 && metadata.uid() != uid)
            || metadata.permissions().mode() & 0o022 != 0
        {
            return Err("authority output parent is not owner controlled".into());
        }
    }
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

async fn add_connection(
    socket: &Path,
    mut arguments: AddConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    lower_token(&arguments.provider)?;
    lower_token(&arguments.alias)?;
    arguments.allow_workloads.sort();
    arguments.allow_workloads.dedup();
    if arguments.allow_workloads.is_empty() || arguments.allow_workloads.len() > 256 {
        return Err("allow-workload must contain 1-256 unique values".into());
    }
    let mut profiles = arguments
        .allow_profiles
        .iter()
        .map(|value| profile_ref(value))
        .collect::<Result<Vec<_>, _>>()?;
    profiles.sort();
    profiles.dedup();
    if profiles.is_empty() || profiles.len() > 32 {
        return Err("allow-profile must contain 1-32 unique values".into());
    }
    let descriptor = bounded_regular_file(&arguments.descriptor, MAX_DESCRIPTOR_BYTES, false)?;
    let start_request_id = request_id()?;
    let start_body = encode_start(
        start_request_id,
        &arguments.alias,
        &descriptor,
        &arguments.allow_workloads,
        &profiles,
    );
    let start_path = format!(
        "/v1/admin/providers/{}/connections/start",
        arguments.provider
    );
    let start = request(socket, "POST", &start_path, &start_body).await?;
    let onboarding = decode_start(&start, start_request_id)?;
    let mut secret = read_secret(arguments.secret_file.as_deref())?;
    let mut complete_body = encode_complete(request_id()?, &onboarding, &secret);
    secret.fill(0);
    let complete_path = format!(
        "/v1/admin/providers/{}/connections/complete",
        arguments.provider
    );
    let complete = request(socket, "POST", &complete_path, &complete_body).await;
    complete_body.fill(0);
    let complete = complete?;
    print_json(decode_record_response(&complete)?)?;
    Ok(())
}

async fn mutate_state(
    socket: &Path,
    connection: &str,
    operation: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (provider, alias) = connection_key(connection)?;
    let inspect_path = format!("/v1/admin/connections/{provider}/{alias}");
    let current = request(socket, "GET", &inspect_path, &[]).await?;
    let generation = record_generation(&current)?;
    let body = encode_generation(request_id()?, generation);
    let path = format!("{inspect_path}/{operation}");
    let response = request(socket, "POST", &path, &body).await?;
    print_json(decode_record_response(&response)?)?;
    Ok(())
}

async fn rotate_connection(
    socket: &Path,
    arguments: RotateConnection,
) -> Result<(), Box<dyn std::error::Error>> {
    let (provider, alias) = connection_key(&arguments.connection)?;
    let inspect_path = format!("/v1/admin/connections/{provider}/{alias}");
    let current = request(socket, "GET", &inspect_path, &[]).await?;
    let generation = record_generation(&current)?;
    let mut secret = read_secret(arguments.secret_file.as_deref())?;
    let mut body = encode_rotate(request_id()?, generation, &secret);
    secret.fill(0);
    let response = request(socket, "POST", &format!("{inspect_path}/rotate"), &body).await;
    body.fill(0);
    let response = response?;
    print_json(decode_record_response(&response)?)?;
    Ok(())
}

fn discover_admin_socket(explicit: Option<PathBuf>) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = explicit
        .or_else(|| env::var_os("AUTHS_ADMIN_SOCKET").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/run/auths/admin.sock"));
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 1_024
        || path
            .components()
            .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
    {
        return Err("admin socket must be a normalized absolute local path".into());
    }
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_socket() {
        return Err("admin endpoint is not a Unix-domain socket".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let current = effective_uid()?;
        if !matches!(metadata.uid(), 0) && metadata.uid() != current {
            return Err("admin socket owner is not trusted".into());
        }
        if metadata.permissions().mode() & 0o002 != 0 {
            return Err("admin socket is writable by other users".into());
        }
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or("kernel process credentials are unavailable")?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or("kernel effective UID is unavailable")?
        .parse()
        .map_err(Into::into)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn effective_uid() -> Result<u32, Box<dyn std::error::Error>> {
    let output = std::process::Command::new("/usr/bin/id")
        .arg("-u")
        .output()?;
    if !output.status.success() || output.stdout.len() > 32 {
        return Err("effective UID is unavailable".into());
    }
    std::str::from_utf8(&output.stdout)?
        .trim()
        .parse()
        .map_err(Into::into)
}

async fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if body.len() > 131_072
        || !path.starts_with("/v1/admin/")
        || path.contains('%')
        || path.contains("//")
    {
        return Err("invalid administration request".into());
    }
    let mut stream = UnixStream::connect(socket).await?;
    let head = format!(
        "{method} {path} HTTP/1.1\r\nHost: auths.local\r\nContent-Type: {LOCAL_AGENT_CONTENT_TYPE}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    if !body.is_empty() {
        stream.write_all(body).await?;
    }
    stream.shutdown().await?;
    let mut response = Vec::new();
    stream
        .take((MAX_ADMIN_HEADER_BYTES + MAX_ADMIN_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .await?;
    parse_http_response(&response)
}

fn parse_http_response(response: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if response.len() > MAX_ADMIN_HEADER_BYTES + MAX_ADMIN_RESPONSE_BYTES {
        return Err("administration response exceeds its bound".into());
    }
    let boundary = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("malformed administration response")?;
    if boundary > MAX_ADMIN_HEADER_BYTES {
        return Err("administration response headers exceed their bound".into());
    }
    let headers = std::str::from_utf8(&response[..boundary])?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or("missing administration status")?;
    let status_code = status
        .split_ascii_whitespace()
        .nth(1)
        .ok_or("missing administration status")?
        .parse::<u16>()?;
    let mut length = None;
    let mut media_type = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or("malformed administration header")?;
        match name.to_ascii_lowercase().as_str() {
            "content-length" if length.is_none() => length = Some(value.trim().parse::<usize>()?),
            "content-type" if media_type.is_none() => media_type = Some(value.trim().to_owned()),
            "transfer-encoding" => return Err("chunked administration response refused".into()),
            _ => {}
        }
    }
    let body = &response[boundary + 4..];
    if length != Some(body.len())
        || body.is_empty()
        || body.len() > MAX_ADMIN_RESPONSE_BYTES
        || media_type.as_deref() != Some(LOCAL_AGENT_CONTENT_TYPE)
    {
        return Err("malformed administration response body".into());
    }
    if status_code != 200 {
        return Err(format!("administration request failed with HTTP {status_code}").into());
    }
    Ok(body.to_vec())
}

fn bounded_regular_file(
    path: &Path,
    maximum: usize,
    secret: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    #[cfg(unix)]
    let mut file: File = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )?
    .into();
    #[cfg(not(unix))]
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || usize::try_from(metadata.len()).map_or(true, |length| length > maximum)
    {
        return Err("input must be a bounded regular file".into());
    }
    #[cfg(unix)]
    if secret {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("secret file must not be accessible to group/other".into());
        }
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .min(maximum),
    );
    std::io::Read::by_ref(&mut file)
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("input exceeds its bound".into());
    }
    Ok(bytes)
}

fn read_secret(path: Option<&Path>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if let Some(path) = path {
        return bounded_regular_file(path, MAX_SECRET_BYTES, true);
    }
    let mut stdin = std::io::stdin();
    if stdin.is_terminal() {
        return Err("refusing to read a provider credential from an echoed terminal; use --secret-file or a pipe".into());
    }
    let mut bytes = Vec::new();
    stdin
        .by_ref()
        .take((MAX_SECRET_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_SECRET_BYTES {
        return Err("provider credential is empty or oversized".into());
    }
    Ok(bytes)
}

fn request_id() -> Result<[u8; 16], Box<dyn std::error::Error>> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| "operating-system randomness unavailable")?;
    Ok(bytes)
}

fn connection_key(value: &str) -> Result<(&str, &str), Box<dyn std::error::Error>> {
    let (provider, alias) = value
        .split_once('/')
        .ok_or("connection must be <provider>/<alias>")?;
    if alias.contains('/') {
        return Err("connection must be <provider>/<alias>".into());
    }
    lower_token(provider)?;
    lower_token(alias)?;
    Ok((provider, alias))
}

fn lower_token(value: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !(1..=64).contains(&value.len())
        || !value.as_bytes()[0].is_ascii_lowercase()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("provider/alias is not a lower token".into());
    }
    Ok(())
}

fn profile_ref(value: &str) -> Result<(String, u16), Box<dyn std::error::Error>> {
    let (id, version) = value.rsplit_once('/').ok_or("invalid profile reference")?;
    let version = version.parse::<u16>()?;
    if version == 0 || version.to_string() != value.rsplit_once('/').unwrap().1 {
        return Err("invalid profile version".into());
    }
    let mut parts = id.split('.');
    if parts.next() != Some("auths")
        || parts.next().is_none()
        || parts.next().is_none()
        || parts.next().is_some()
        || id.len() > 128
    {
        return Err("invalid profile identifier".into());
    }
    Ok((id.to_owned(), version))
}

fn encode_start(
    request_id: [u8; 16],
    alias: &str,
    descriptor: &[u8],
    workloads: &[String],
    profiles: &[(String, u16)],
) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(6).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap().str(alias).unwrap();
    encoder.u8(4).unwrap().bytes(descriptor).unwrap();
    encoder
        .u8(5)
        .unwrap()
        .array(workloads.len() as u64)
        .unwrap();
    for workload in workloads {
        encoder.str(workload).unwrap();
    }
    encoder.u8(6).unwrap().array(profiles.len() as u64).unwrap();
    for (id, version) in profiles {
        encoder
            .array(2)
            .unwrap()
            .str(id)
            .unwrap()
            .u16(*version)
            .unwrap();
    }
    encoder.into_writer()
}

fn encode_complete(request_id: [u8; 16], onboarding: &str, secret: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap().str(onboarding).unwrap();
    encoder.u8(4).unwrap().bytes(secret).unwrap();
    encoder.into_writer()
}

fn encode_generation(request_id: [u8; 16], generation: NonZeroU64) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(3).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap().u64(generation.get()).unwrap();
    encoder.into_writer()
}

fn encode_rotate(request_id: [u8; 16], generation: NonZeroU64, secret: &[u8]) -> Vec<u8> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(4).unwrap().u8(1).unwrap().u8(1).unwrap();
    encoder.u8(2).unwrap().bytes(&request_id).unwrap();
    encoder.u8(3).unwrap().u64(generation.get()).unwrap();
    encoder.u8(4).unwrap().bytes(secret).unwrap();
    encoder.into_writer()
}

fn decode_start(bytes: &[u8], request_id: [u8; 16]) -> Result<String, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 3)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    if exact_bytes::<16>(&mut decoder)? != request_id {
        return Err("start response request ID mismatch".into());
    }
    key(&mut decoder, 3)?;
    let onboarding = decoder.str()?.to_owned();
    if !onboarding.starts_with("onb_")
        || onboarding.len() != 26
        || decoder.position() != bytes.len()
    {
        return Err("invalid onboarding response".into());
    }
    Ok(onboarding)
}

fn record_generation(bytes: &[u8]) -> Result<NonZeroU64, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 3)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let _ = exact_bytes::<16>(&mut decoder)?;
    key(&mut decoder, 3)?;
    exact_map(&mut decoder, 12)?;
    for expected in 1..=5 {
        key(&mut decoder, expected)?;
        if expected == 1 {
            if decoder.u8()? != 1 {
                return Err("invalid connection response".into());
            }
        } else {
            let _ = decoder.str()?;
        }
    }
    key(&mut decoder, 6)?;
    NonZeroU64::new(decoder.u64()?).ok_or_else(|| "invalid connection generation".into())
}

fn decode_record_response(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 3)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let _ = exact_bytes::<16>(&mut decoder)?;
    key(&mut decoder, 3)?;
    let record = decode_record(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err("trailing administration response bytes".into());
    }
    Ok(record)
}

fn decode_list(bytes: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let mut decoder = Decoder::new(bytes);
    exact_map(&mut decoder, 2)?;
    version(&mut decoder)?;
    key(&mut decoder, 2)?;
    let count = definite_array(&mut decoder, 10_000)?;
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(decode_record(&mut decoder)?);
    }
    if decoder.position() != bytes.len() {
        return Err("trailing administration response bytes".into());
    }
    Ok(Value::Array(records))
}

fn decode_record(decoder: &mut Decoder<'_>) -> Result<Value, Box<dyn std::error::Error>> {
    exact_map(decoder, 12)?;
    key(decoder, 1)?;
    if decoder.u8()? != 1 {
        return Err("invalid connection record version".into());
    }
    key(decoder, 2)?;
    let provider = decoder.str()?.to_owned();
    key(decoder, 3)?;
    let alias = decoder.str()?.to_owned();
    key(decoder, 4)?;
    let id = decoder.str()?.to_owned();
    key(decoder, 5)?;
    let contract = decoder.str()?.to_owned();
    key(decoder, 6)?;
    let generation = decoder.u64()?;
    key(decoder, 7)?;
    let state = decoder.str()?.to_owned();
    key(decoder, 8)?;
    let descriptor_commitment = hex::encode(exact_bytes::<32>(decoder)?);
    key(decoder, 9)?;
    let account_commitment = hex::encode(exact_bytes::<32>(decoder)?);
    key(decoder, 10)?;
    let workload_count = definite_array(decoder, 256)?;
    let mut workloads = Vec::with_capacity(workload_count);
    for _ in 0..workload_count {
        workloads.push(decoder.str()?.to_owned());
    }
    key(decoder, 11)?;
    let profile_count = definite_array(decoder, 32)?;
    let mut profiles = Vec::with_capacity(profile_count);
    for _ in 0..profile_count {
        if decoder.array()? != Some(2) {
            return Err("invalid connection profile".into());
        }
        profiles.push(format!("{}/{}", decoder.str()?, decoder.u16()?));
    }
    key(decoder, 12)?;
    if decoder.array()? != Some(3) {
        return Err("invalid connection timestamps".into());
    }
    let created = decoder.u64()?;
    let updated = decoder.u64()?;
    let revoked = if decoder.datatype()? == Type::Null {
        decoder.null()?;
        Value::Null
    } else {
        json!(decoder.u64()?)
    };
    Ok(json!({
        "provider": provider,
        "alias": alias,
        "connectionId": id,
        "contract": contract,
        "generation": generation,
        "state": state,
        "descriptorCommitment": descriptor_commitment,
        "accountCommitment": account_commitment,
        "allowedWorkloads": workloads,
        "allowedProfiles": profiles,
        "createdAtUnixSeconds": created,
        "updatedAtUnixSeconds": updated,
        "revokedAtUnixSeconds": revoked
    }))
}

fn exact_map(decoder: &mut Decoder<'_>, count: u64) -> Result<(), Box<dyn std::error::Error>> {
    if decoder.map()? != Some(count) {
        return Err("invalid administration map".into());
    }
    Ok(())
}
fn version(decoder: &mut Decoder<'_>) -> Result<(), Box<dyn std::error::Error>> {
    key(decoder, 1)?;
    if decoder.u8()? != 1 {
        return Err("unsupported administration protocol".into());
    }
    Ok(())
}
fn key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), Box<dyn std::error::Error>> {
    if decoder.u8()? != expected {
        return Err("invalid administration field order".into());
    }
    Ok(())
}
fn exact_bytes<const SIZE: usize>(
    decoder: &mut Decoder<'_>,
) -> Result<[u8; SIZE], Box<dyn std::error::Error>> {
    Ok(decoder
        .bytes()?
        .try_into()
        .map_err(|_| "invalid fixed-width bytes")?)
}
fn definite_array(
    decoder: &mut Decoder<'_>,
    maximum: usize,
) -> Result<usize, Box<dyn std::error::Error>> {
    let count = decoder
        .array()?
        .and_then(|value| usize::try_from(value).ok())
        .ok_or("invalid indefinite administration array")?;
    if count > maximum {
        return Err("administration array exceeds bound".into());
    }
    Ok(count)
}
#[allow(clippy::needless_pass_by_value)]
fn print_json(value: Value) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_and_profile_inputs_are_closed() {
        assert_eq!(
            connection_key("stripe/merchant-primary").unwrap(),
            ("stripe", "merchant-primary")
        );
        assert!(connection_key("stripe/merchant/primary").is_err());
        assert_eq!(
            profile_ref("auths.stripe.refund/1").unwrap(),
            ("auths.stripe.refund".into(), 1)
        );
        assert!(profile_ref("auths.stripe.refund/01").is_err());
    }

    #[test]
    fn generated_start_body_is_canonical_and_bounded() {
        let body = encode_start(
            [1; 16],
            "merchant-primary",
            b"descriptor",
            &["payments-worker".into()],
            &[("auths.stripe.refund".into(), 1)],
        );
        let mut decoder = Decoder::new(&body);
        assert_eq!(decoder.map().unwrap(), Some(6));
        assert!(body.len() < 1_024);
    }
}
