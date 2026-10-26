//! Pinned, provider-neutral development custody process boundary.
//!
//! The sidecar receives only a task operation that the gateway has already
//! reserved. It may refresh a provider grant, but cannot choose a request or
//! an effect. The gateway still checks subject, authority, lifetime and
//! source-marker refusal before any provider transport.

use async_trait::async_trait;
use auths_connections::StoredSecretLease;
use auths_gateway::{
    CredentialMaterializationContext, CredentialMaterializationError, CredentialMaterializer,
    CredentialRequestKind, MATERIALIZER_SOURCE_PREFIX, MaterializedCredential,
};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq as _;
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    process::Command,
};
use zeroize::{Zeroize, Zeroizing};

const PINS_SCHEMA: &str = "auths.custody-process/1";
const RESPONSE_SCHEMA: &str = "auths.custody-process-response/1";
const MAX_RESPONSE: u64 = 65_536;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProcessCustodyPins {
    pub schema: String,
    pub connection_id: String,
    pub executable: PathBuf,
    pub executable_sha256: String,
    pub provider_pins: PathBuf,
    pub provider_pins_sha256: String,
    pub authority_digest: String,
}

impl ProcessCustodyPins {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema != PINS_SCHEMA
            || auths_connections::ConnectionId::parse(&self.connection_id).is_err()
            || !hex64(&self.executable_sha256)
            || !hex64(&self.provider_pins_sha256)
            || !hex64(&self.authority_digest)
        {
            return Err("gateway.materializer.invalid-process-pins");
        }
        checked_digest(&self.executable, &self.executable_sha256, false)?;
        checked_digest(&self.provider_pins, &self.provider_pins_sha256, true)?;
        Ok(())
    }

    pub fn authority_digest(&self) -> Result<[u8; 32], &'static str> {
        let bytes = hex::decode(&self.authority_digest)
            .map_err(|_| "gateway.materializer.invalid-process-pins")?;
        bytes
            .try_into()
            .map_err(|_| "gateway.materializer.invalid-process-pins")
    }
}

fn hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn checked_digest(path: &PathBuf, expected: &str, private: bool) -> Result<(), &'static str> {
    if !path.is_absolute() {
        return Err("gateway.materializer.unsafe-process-file");
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "gateway.materializer.process-file-unavailable")?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != rustix::process::geteuid().as_raw() && metadata.uid() != 0)
        || mode & 0o022 != 0
        || (private && mode & 0o077 != 0)
        || (!private && mode & 0o111 == 0)
        || metadata.len() > if private { 65_536 } else { 32 * 1024 * 1024 }
    {
        return Err("gateway.materializer.unsafe-process-file");
    }
    let bytes = Zeroizing::new(
        fs::read(path).map_err(|_| "gateway.materializer.process-file-unavailable")?,
    );
    let digest: [u8; 32] = Sha256::digest(&*bytes).into();
    let expected =
        hex::decode(expected).map_err(|_| "gateway.materializer.invalid-process-pins")?;
    if !bool::from(digest.ct_eq(expected.as_slice())) {
        return Err("gateway.materializer.process-file-changed");
    }
    Ok(())
}

#[derive(Serialize)]
struct MaterializeRequest<'a> {
    schema: &'static str,
    task_id: &'a str,
    operation_id: &'a str,
    connection_id: &'a str,
    connection_generation: u64,
    source_generation: u64,
    account_subject: &'a str,
    recipe_digest: &'a str,
    task_expires_at: u64,
    kind: &'static str,
    source_base64: String,
}

#[derive(Deserialize, Zeroize)]
#[zeroize(drop)]
#[serde(deny_unknown_fields)]
struct MaterializeResponse {
    schema: String,
    bearer_base64: String,
    account_subject: String,
    effective_authority_digest: String,
    valid_for_seconds: u64,
}

pub(super) struct ProcessCustodyMaterializer {
    pins: ProcessCustodyPins,
}

impl ProcessCustodyMaterializer {
    pub fn new(pins: ProcessCustodyPins) -> Result<Self, &'static str> {
        pins.validate()?;
        Ok(Self { pins })
    }

    pub fn connection_id(&self) -> &str {
        &self.pins.connection_id
    }

    pub fn authority_digest(&self) -> Result<[u8; 32], &'static str> {
        self.pins.authority_digest()
    }

    async fn invoke(
        &self,
        operation: &str,
        request: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, CredentialMaterializationError> {
        self.pins
            .validate()
            .map_err(|_| CredentialMaterializationError)?;
        let mut child = Command::new(&self.pins.executable)
            .arg(operation)
            .arg("--pins")
            .arg(&self.pins.provider_pins)
            .env_clear()
            .env("PYTHONNOUSERSITE", "1")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| CredentialMaterializationError)?;
        let mut stdin = child.stdin.take().ok_or(CredentialMaterializationError)?;
        let stdout = child.stdout.take().ok_or(CredentialMaterializationError)?;
        tokio::time::timeout(Duration::from_secs(20), async {
            stdin
                .write_all(request)
                .await
                .map_err(|_| CredentialMaterializationError)?;
            drop(stdin);
            let mut result = Zeroizing::new(Vec::new());
            stdout
                .take(MAX_RESPONSE + 1)
                .read_to_end(&mut result)
                .await
                .map_err(|_| CredentialMaterializationError)?;
            if result.len() as u64 > MAX_RESPONSE {
                return Err(CredentialMaterializationError);
            }
            let status = child
                .wait()
                .await
                .map_err(|_| CredentialMaterializationError)?;
            if !status.success() {
                return Err(CredentialMaterializationError);
            }
            Ok(result)
        })
        .await
        .map_err(|_| CredentialMaterializationError)?
    }

    pub async fn validate_source(&self) -> Result<(), CredentialMaterializationError> {
        let result = self.invoke("--validate", b"").await?;
        if !result.is_empty() {
            return Err(CredentialMaterializationError);
        }
        Ok(())
    }

    pub async fn probe_identity(&self) -> Result<(), CredentialMaterializationError> {
        let result = self.invoke("--probe", b"").await?;
        if !result.is_empty() {
            return Err(CredentialMaterializationError);
        }
        Ok(())
    }
}

#[async_trait]
impl CredentialMaterializer for ProcessCustodyMaterializer {
    async fn materialize(
        &self,
        context: &CredentialMaterializationContext,
        source: &StoredSecretLease,
        deadline: Instant,
    ) -> Result<MaterializedCredential, CredentialMaterializationError> {
        let raw = source
            .expose(Instant::now())
            .map_err(|_| CredentialMaterializationError)?;
        if raw.len() > 1_024 || !raw.starts_with(MATERIALIZER_SOURCE_PREFIX) {
            return Err(CredentialMaterializationError);
        }
        let request = MaterializeRequest {
            schema: "auths.custody-process-request/1",
            task_id: &context.task_id,
            operation_id: &context.operation_id,
            connection_id: &context.connection_id,
            connection_generation: context.connection_generation,
            source_generation: context.source_generation,
            account_subject: &context.account_subject,
            recipe_digest: &context.recipe_digest,
            task_expires_at: context.task_expires_at,
            kind: match context.kind {
                CredentialRequestKind::ReadRelease => "read-release",
                CredentialRequestKind::WriteEffect => "write-effect",
            },
            source_base64: Base64UrlUnpadded::encode_string(raw),
        };
        let request = Zeroizing::new(
            serde_json::to_vec(&request).map_err(|_| CredentialMaterializationError)?,
        );
        let response = self.invoke("--materialize", &request).await?;
        let response: MaterializeResponse =
            serde_json::from_slice(&response).map_err(|_| CredentialMaterializationError)?;
        if response.schema != RESPONSE_SCHEMA || !(1..=3_600).contains(&response.valid_for_seconds)
        {
            return Err(CredentialMaterializationError);
        }
        let authority = hex::decode(&response.effective_authority_digest)
            .map_err(|_| CredentialMaterializationError)?;
        let authority: [u8; 32] = authority
            .try_into()
            .map_err(|_| CredentialMaterializationError)?;
        let token = Zeroizing::new(
            Base64UrlUnpadded::decode_vec(&response.bearer_base64)
                .map_err(|_| CredentialMaterializationError)?,
        );
        let token_deadline = Instant::now()
            .checked_add(Duration::from_secs(response.valid_for_seconds))
            .ok_or(CredentialMaterializationError)?;
        Ok(MaterializedCredential {
            lease: StoredSecretLease::from_store(token, token_deadline.min(deadline)),
            account_subject: response.account_subject.clone(),
            effective_authority_digest: authority,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[tokio::test]
    async fn pinned_process_materializes_only_the_admitted_source_and_refuses_changed_code() {
        let root = tempfile::tempdir().expect("private fixture");
        let executable = root.path().join("fixture-custody");
        let pins_file = root.path().join("fixture-pins.json");
        let authority = "00".repeat(32);
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  --validate|--probe) exit 0 ;;\n  --materialize) /bin/cat >/dev/null; printf '%s' '{{\"schema\":\"auths.custody-process-response/1\",\"bearer_base64\":\"ZGVtby10b2tlbg\",\"account_subject\":\"subject\",\"effective_authority_digest\":\"{authority}\",\"valid_for_seconds\":20}}' ;;\n  *) exit 2 ;;\nesac\n"
        );
        fs::write(&executable, script.as_bytes()).expect("sidecar");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("executable mode");
        fs::write(&pins_file, b"{}\n").expect("fixture pins");
        fs::set_permissions(&pins_file, fs::Permissions::from_mode(0o600)).expect("pin mode");
        let digest = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
        let pins = ProcessCustodyPins {
            schema: PINS_SCHEMA.to_owned(),
            connection_id: "conn_AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
            executable: executable.clone(),
            executable_sha256: digest(script.as_bytes()),
            provider_pins: pins_file,
            provider_pins_sha256: digest(b"{}\n"),
            authority_digest: authority,
        };
        let adapter = ProcessCustodyMaterializer::new(pins.clone()).expect("pinned sidecar");
        adapter.validate_source().await.expect("source checked");
        adapter.probe_identity().await.expect("identity probed");
        let context = CredentialMaterializationContext {
            task_id: "task".to_owned(),
            operation_id: "read-1".to_owned(),
            connection_id: pins.connection_id,
            connection_generation: 1,
            source_generation: 1,
            account_subject: "subject".to_owned(),
            recipe_digest: "a".repeat(64),
            task_expires_at: u64::MAX,
            kind: CredentialRequestKind::ReadRelease,
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        let source = StoredSecretLease::from_store(
            Zeroizing::new(b"auths.materializer-source/1:fixture".to_vec()),
            deadline,
        );
        let result = adapter
            .materialize(&context, &source, deadline)
            .await
            .expect("admitted request");
        assert_eq!(result.account_subject, "subject");
        assert_eq!(
            result.lease.expose(Instant::now()).expect("lease"),
            b"demo-token"
        );
        fs::write(&executable, b"#!/bin/sh\nexit 0\n").expect("changed code");
        assert!(
            adapter
                .materialize(&context, &source, deadline)
                .await
                .is_err()
        );
    }
}
