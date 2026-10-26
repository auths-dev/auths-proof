//! Google grant custody sidecar for an operator-pinned AP-071 development task.

mod google_custody;

use auths_connections::StoredSecretLease;
use auths_gateway::{
    CredentialMaterializationContext, CredentialMaterializer, CredentialRequestKind,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use google_custody::{GoogleCustodyMaterializer, GoogleCustodyPins};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    task_id: String,
    operation_id: String,
    connection_id: String,
    connection_generation: u64,
    source_generation: u64,
    account_subject: String,
    recipe_digest: String,
    task_expires_at: u64,
    kind: String,
    source_base64: String,
}

#[derive(Serialize)]
struct Response<'a> {
    schema: &'static str,
    bearer_base64: &'a str,
    account_subject: &'a str,
    effective_authority_digest: String,
    valid_for_seconds: u64,
}

fn private_pins(path: &Path) -> Result<GoogleCustodyPins, &'static str> {
    if !path.is_absolute() {
        return Err("custody.invalid-pins");
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| "custody.invalid-pins")?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > 65_536
    {
        return Err("custody.invalid-pins");
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|_| "custody.invalid-pins")?);
    let pins: GoogleCustodyPins =
        serde_json::from_slice(&bytes).map_err(|_| "custody.invalid-pins")?;
    pins.validate().map_err(|_| "custody.invalid-pins")?;
    Ok(pins)
}

async fn execute() -> Result<(), &'static str> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 4 || args[2] != "--pins" {
        return Err("custody.invalid-command");
    }
    let operation = args[1].to_str().ok_or("custody.invalid-command")?;
    if !matches!(
        operation,
        "--validate" | "--describe" | "--probe" | "--materialize"
    ) {
        return Err("custody.invalid-command");
    }
    let pins = private_pins(Path::new(&args[3]))?;
    let adapter = GoogleCustodyMaterializer::new(pins).map_err(|_| "custody.invalid-pins")?;
    if operation == "--validate" {
        return Ok(());
    }
    if operation == "--describe" {
        let descriptor = serde_json::json!({
            "schema": "auths.custody-process-descriptor/1",
            "connection_id": adapter.connection_id(),
            "authority_digest": hex::encode(adapter.authority_digest()),
        });
        serde_json::to_writer(std::io::stdout(), &descriptor)
            .map_err(|_| "custody.descriptor-unavailable")?;
        return Ok(());
    }
    if operation == "--probe" {
        return adapter
            .probe_identity()
            .await
            .map_err(|_| "custody.probe-refused");
    }
    let mut input = Zeroizing::new(Vec::new());
    std::io::stdin()
        .take(16_385)
        .read_to_end(&mut input)
        .map_err(|_| "custody.invalid-request")?;
    if input.len() > 16_384 {
        return Err("custody.invalid-request");
    }
    let request: Request = serde_json::from_slice(&input).map_err(|_| "custody.invalid-request")?;
    let kind = match request.kind.as_str() {
        "read-release" => CredentialRequestKind::ReadRelease,
        "write-effect" => CredentialRequestKind::WriteEffect,
        _ => return Err("custody.invalid-request"),
    };
    if request.schema != "auths.custody-process-request/1" {
        return Err("custody.invalid-request");
    }
    let context = CredentialMaterializationContext {
        task_id: request.task_id,
        operation_id: request.operation_id,
        connection_id: request.connection_id,
        connection_generation: request.connection_generation,
        source_generation: request.source_generation,
        account_subject: request.account_subject,
        recipe_digest: request.recipe_digest,
        task_expires_at: request.task_expires_at,
        kind,
    };
    let source = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(&request.source_base64)
            .map_err(|_| "custody.invalid-request")?,
    );
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(30))
        .ok_or("custody.invalid-request")?;
    let lease = StoredSecretLease::from_store(source, deadline);
    let result = adapter
        .materialize(&context, &lease, deadline)
        .await
        .map_err(|_| "custody.materialization-refused")?;
    let token = result
        .lease
        .expose(Instant::now())
        .map_err(|_| "custody.materialization-refused")?;
    let bearer = Zeroizing::new(Base64UrlUnpadded::encode_string(token));
    let valid_for_seconds = result
        .lease
        .deadline()
        .saturating_duration_since(Instant::now())
        .as_secs();
    if valid_for_seconds == 0 {
        return Err("custody.materialization-refused");
    }
    let output = Response {
        schema: "auths.custody-process-response/1",
        bearer_base64: &bearer,
        account_subject: &result.account_subject,
        effective_authority_digest: hex::encode(result.effective_authority_digest),
        valid_for_seconds,
    };
    let output =
        Zeroizing::new(serde_json::to_vec(&output).map_err(|_| "custody.materialization-refused")?);
    std::io::stdout()
        .write_all(&output)
        .map_err(|_| "custody.materialization-refused")?;
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(code) = execute().await {
        eprintln!("{code}");
        std::process::exit(2);
    }
}
