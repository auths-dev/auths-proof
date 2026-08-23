//! Explicit disposable local agent for generated-SDK development tests.

#![forbid(unsafe_code)]

use auths_connections::RegistryLimits;
use auths_node::{
    LocalAgentDeploymentConfig, LocalAgentResources, bind_testkit_agent,
    provision_testkit_stripe_connection,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use clap::Parser;
use serde_json::json;
use std::{
    fs::{self, File},
    io::{Write as _, stdout},
    num::NonZeroUsize,
    path::{Component, Path, PathBuf},
    process::ExitCode,
};

#[derive(Parser)]
#[command(
    name = "auths-testkit-agent",
    version,
    about = "Disposable synthetic Auths local agent; never use in production"
)]
struct Arguments {
    /// Owner-only disposable directory for sockets and durable replay state.
    #[arg(long)]
    state_directory: PathBuf,
    /// Application socket; defaults to `STATE_DIRECTORY/agent.sock`.
    #[arg(long)]
    agent_socket: Option<PathBuf>,
    /// Non-secret generated-client connection alias.
    #[arg(long, default_value = "billing")]
    connection: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Arguments::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("auths-testkit-agent: {error}");
            ExitCode::from(1)
        }
    }
}

#[cfg(unix)]
async fn run(arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let uid = effective_uid()?;
    let state = prepare_state_directory(&arguments.state_directory, uid)?;
    let recovery_key = state.join("recovery.key");
    ensure_recovery_key(&recovery_key, uid)?;
    let agent_socket = arguments
        .agent_socket
        .unwrap_or_else(|| state.join("agent.sock"));
    let deployment = LocalAgentDeploymentConfig::new(
        &agent_socket,
        state.join("unused-admin.sock"),
        state.join("connections.cbor"),
        state.join("credentials.cbor"),
        state.join("operations.cbor"),
        recovery_key,
        "testkit-agent-v1",
        state.join("unused-admin-audit.jsonl"),
        uid,
        [uid],
        [],
        RegistryLimits {
            maximum_records: NonZeroUsize::new(8).ok_or("invalid registry limit")?,
            maximum_encoded_bytes: NonZeroUsize::new(1_048_576)
                .ok_or("invalid registry byte limit")?,
        },
    )?;
    let resources = LocalAgentResources::open_testkit(&deployment)?;
    provision_testkit_stripe_connection(&resources, &arguments.connection).await?;
    let receipt_anchors = resources.testkit_receipt_anchors().map(|anchor| {
        json!({
            "role": anchor.role,
            "principal": anchor.principal,
            "verificationMethod": anchor.verification_method,
            "suite": anchor.suite,
            "publicKeyBase64Url": Base64UrlUnpadded::encode_string(&anchor.public_key),
        })
    });
    let server = bind_testkit_agent(&deployment, &resources, &arguments.connection)?;
    serde_json::to_writer(
        stdout().lock(),
        &json!({
            "agentSocket": agent_socket,
            "connection": arguments.connection,
            "durability": "disposable-local",
            "profile": "auths.stripe.refund/1",
            "receiptTrustAnchors": receipt_anchors,
            "status": "ready",
            "warning": "synthetic testkit agent; never production"
        }),
    )?;
    writeln!(stdout().lock())?;
    stdout().lock().flush()?;
    tokio::select! {
        result = server.serve() => result?,
        result = tokio::signal::ctrl_c() => result?,
    }
    Ok(())
}

#[cfg(not(unix))]
async fn run(_arguments: Arguments) -> Result<(), Box<dyn std::error::Error>> {
    Err("the disposable testkit agent is currently qualified only on Unix platforms".into())
}

#[cfg(unix)]
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

#[cfg(unix)]
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

#[cfg(target_os = "linux")]
fn effective_uid() -> Result<u32, Box<dyn std::error::Error>> {
    let status = fs::read_to_string("/proc/self/status")?;
    let line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or("kernel process credentials are unavailable")?;
    line.split_ascii_whitespace()
        .nth(2)
        .ok_or_else(|| "kernel effective UID is unavailable".into())?
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
