//! Sealed deployment authority artifacts for authenticated local workloads.

#![forbid(unsafe_code)]

use auths_config::{AgentConfig, AuthoritySourceConfig};
use auths_model::{PrincipalId, ProfileId, ProfileRef};
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    fs::File,
    io::Read as _,
    path::{Component, Path},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const AUTHORITY_SCHEMA_VERSION: u8 = 1;
const AUTHORITY_FIELD_COUNT: u64 = 8;
const MAX_AUTHORITY_BYTES: usize = 2_363_392;
const MAX_PROOF_BYTES: usize = 262_144;
const MAX_CONTEXT_BYTES: usize = 2_097_152;
const MAX_PROFILES: usize = 32;

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// One fully validated `auths.workload-authority-file/1` capability.
///
/// Proof and trusted-context bytes are retained in redacted, zero-on-drop
/// storage. Construction is possible only through the bounded loader.
#[derive(Clone)]
pub struct WorkloadAuthority {
    principal: PrincipalId,
    profiles: Arc<[ProfileRef]>,
    proof: Arc<SecretBytes>,
    trusted_context: Arc<SecretBytes>,
    not_before_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    artifact_id: Arc<str>,
    artifact_commitment: [u8; 32],
}

impl fmt::Debug for WorkloadAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkloadAuthority")
            .field("principal", &self.principal)
            .field("profiles", &self.profiles)
            .field("proof", &"[REDACTED]")
            .field("trusted_context", &"[REDACTED]")
            .field("not_before_unix_seconds", &self.not_before_unix_seconds)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .field("artifact_id", &self.artifact_id)
            .field(
                "artifact_commitment",
                &hex::encode(self.artifact_commitment),
            )
            .finish()
    }
}

impl WorkloadAuthority {
    /// Returns the principal the deployment artifact is allowed to represent.
    #[must_use]
    pub const fn principal(&self) -> &PrincipalId {
        &self.principal
    }

    /// Returns the sorted, duplicate-free profile authority set.
    #[must_use]
    pub fn profiles(&self) -> &[ProfileRef] {
        &self.profiles
    }

    /// Returns retained canonical proof bytes to the Rust-owned verifier path.
    #[must_use]
    pub fn proof_bytes(&self) -> &[u8] {
        self.proof.expose()
    }

    /// Returns retained canonical trusted-context bytes to the Rust verifier.
    #[must_use]
    pub fn trusted_context_bytes(&self) -> &[u8] {
        self.trusted_context.expose()
    }

    /// Returns the deployment artifact identifier.
    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    /// Returns the SHA-256 commitment to the complete canonical artifact.
    #[must_use]
    pub const fn artifact_commitment(&self) -> [u8; 32] {
        self.artifact_commitment
    }

    /// Reports whether the authority is valid at the supplied whole second.
    #[must_use]
    pub const fn is_valid_at(&self, unix_seconds: i64) -> bool {
        unix_seconds >= self.not_before_unix_seconds && unix_seconds < self.expires_at_unix_seconds
    }

    /// Reports whether the artifact contains the exact profile reference.
    #[must_use]
    pub fn permits(&self, profile: &ProfileRef) -> bool {
        self.profiles.binary_search(profile).is_ok()
    }

    #[cfg(test)]
    pub(crate) fn for_test(principal: &str, profile: ProfileRef) -> Self {
        let fixture = auths_testkit::corpus().remove(0);
        Self {
            principal: PrincipalId::parse(principal).unwrap(),
            profiles: vec![profile].into(),
            proof: Arc::new(SecretBytes::new(fixture.proof_bytes().to_vec())),
            trusted_context: Arc::new(SecretBytes::new(fixture.context_bytes().to_vec())),
            not_before_unix_seconds: 0,
            expires_at_unix_seconds: i64::MAX,
            artifact_id: Arc::from("test-authority"),
            artifact_commitment: [0; 32],
        }
    }

    /// Creates an explicitly synthetic authority marker for the separately
    /// packaged disposable testkit agent. Production configuration and the
    /// sealed-file loader can never construct this value.
    #[cfg(feature = "testkit-agent")]
    pub(crate) fn for_testkit(principal: &str, profile: ProfileRef) -> Self {
        Self {
            principal: PrincipalId::parse(principal).expect("fixed testkit principal"),
            profiles: vec![profile].into(),
            proof: Arc::new(SecretBytes::new(vec![0])),
            trusted_context: Arc::new(SecretBytes::new(vec![0])),
            not_before_unix_seconds: 0,
            expires_at_unix_seconds: i64::MAX,
            artifact_id: Arc::from("auths-testkit-agent"),
            artifact_commitment: Sha256::digest(b"auths.testkit-authority/1").into(),
        }
    }
}

/// Builds one canonical sealed-file artifact from already issued proof and
/// trusted-context bytes. This function never creates authority or signs data.
///
/// # Errors
///
/// Rejects invalid principals/profiles, duplicate profiles, invalid validity,
/// malformed proof/context bytes, and every byte/count bound violation.
pub fn pack_workload_authority(
    principal: &str,
    mut profiles: Vec<ProfileRef>,
    proof: Vec<u8>,
    trusted_context: Vec<u8>,
    not_before_unix_seconds: i64,
    expires_at_unix_seconds: i64,
    artifact_id: &str,
) -> Result<Vec<u8>, WorkloadAuthorityError> {
    let principal =
        PrincipalId::parse(principal).map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    if profiles.is_empty() || profiles.len() > MAX_PROFILES {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    profiles.sort();
    if profiles.windows(2).any(|pair| pair[0] == pair[1])
        || !(1..=MAX_PROOF_BYTES).contains(&proof.len())
        || !(1..=MAX_CONTEXT_BYTES).contains(&trusted_context.len())
        || not_before_unix_seconds < 0
        || expires_at_unix_seconds <= not_before_unix_seconds
        || !registered_token(artifact_id)
    {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    let context = auths_codec::decode_verifier_context(&trusted_context)
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    if auths_verifier::decode_proof(&proof, &context).is_err() {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    let authority = WorkloadAuthority {
        principal,
        profiles: profiles.into(),
        proof: Arc::new(SecretBytes::new(proof)),
        trusted_context: Arc::new(SecretBytes::new(trusted_context)),
        not_before_unix_seconds,
        expires_at_unix_seconds,
        artifact_id: Arc::from(artifact_id),
        artifact_commitment: [0; 32],
    };
    let bytes = encode_authority(&authority)?;
    decode_authority(&bytes)?;
    Ok(bytes)
}

/// Immutable, all-or-nothing authority-source snapshot.
#[derive(Clone, Debug)]
pub struct WorkloadAuthoritySnapshot {
    authorities: Arc<BTreeMap<String, Arc<WorkloadAuthority>>>,
}

impl WorkloadAuthoritySnapshot {
    /// Loads every configured source relative to its preopened authority root.
    ///
    /// # Errors
    ///
    /// No snapshot is returned if any source, artifact, proof, context, or
    /// workload binding is unsafe, malformed, stale, or inconsistent.
    #[cfg(unix)]
    pub fn load(config: &AgentConfig, agent_uid: u32) -> Result<Self, WorkloadAuthorityError> {
        Self::load_at(config, agent_uid, current_unix_seconds()?)
    }

    #[cfg(unix)]
    fn load_at(
        config: &AgentConfig,
        agent_uid: u32,
        unix_seconds: i64,
    ) -> Result<Self, WorkloadAuthorityError> {
        let root_path = Path::new(config.authority_root());
        let root = open_root(root_path, agent_uid)?;
        let mut authorities = BTreeMap::new();
        for (source_id, source) in config.authority_sources() {
            let AuthoritySourceConfig::SealedFileV1 { path } = source;
            let relative = Path::new(path)
                .strip_prefix(root_path)
                .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
            let bytes = read_relative_secret(&root, relative, agent_uid)?;
            let authority = Arc::new(decode_authority(&bytes)?);
            if !authority.is_valid_at(unix_seconds)
                || authorities.insert(source_id.clone(), authority).is_some()
            {
                return Err(WorkloadAuthorityError::InvalidArtifact);
            }
        }
        for workload in config.workloads() {
            let authority = authorities
                .get(workload.authority_source())
                .ok_or(WorkloadAuthorityError::InvalidBinding)?;
            if authority.principal().as_str() != workload.principal() {
                return Err(WorkloadAuthorityError::InvalidBinding);
            }
            for profile in workload.allowed_profiles() {
                let parsed = parse_profile_ref(profile)?;
                if !authority.permits(&parsed) {
                    return Err(WorkloadAuthorityError::InvalidBinding);
                }
            }
        }
        Ok(Self {
            authorities: Arc::new(authorities),
        })
    }

    /// Returns one validated authority by its configured source ID.
    #[must_use]
    pub fn get(&self, source_id: &str) -> Option<Arc<WorkloadAuthority>> {
        self.authorities.get(source_id).cloned()
    }
}

/// Closed authority artifact and deployment storage failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum WorkloadAuthorityError {
    /// Root or descendant traversal is unsafe or unavailable.
    #[error("unsafe workload authority path")]
    UnsafePath,
    /// File ownership, link count, type, or access mode is unsafe.
    #[error("unsafe workload authority storage")]
    UnsafeStorage,
    /// Artifact shape, canonical encoding, proof, context, or validity is invalid.
    #[error("invalid workload authority artifact")]
    InvalidArtifact,
    /// Workload principal or profile scope does not match the artifact.
    #[error("invalid workload authority binding")]
    InvalidBinding,
    /// The platform has no implemented secure authority loader.
    #[error("workload authority loading is unsupported on this platform")]
    Unsupported,
}

fn decode_authority(bytes: &[u8]) -> Result<WorkloadAuthority, WorkloadAuthorityError> {
    if bytes.is_empty() || bytes.len() > MAX_AUTHORITY_BYTES {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    let mut decoder = Decoder::new(bytes);
    if decoder.map().map_err(malformed)? != Some(AUTHORITY_FIELD_COUNT) {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    expect_key(&mut decoder, 1)?;
    if decoder.u8().map_err(malformed)? != AUTHORITY_SCHEMA_VERSION {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    expect_key(&mut decoder, 2)?;
    let principal = PrincipalId::parse(decoder.str().map_err(malformed)?)
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    expect_key(&mut decoder, 3)?;
    let profile_count = decoder
        .array()
        .map_err(malformed)?
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| (1..=MAX_PROFILES).contains(value))
        .ok_or(WorkloadAuthorityError::InvalidArtifact)?;
    let mut profiles = Vec::with_capacity(profile_count);
    for _ in 0..profile_count {
        if decoder.array().map_err(malformed)? != Some(2) {
            return Err(WorkloadAuthorityError::InvalidArtifact);
        }
        let id = ProfileId::parse(decoder.str().map_err(malformed)?)
            .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
        let version = decoder.u16().map_err(malformed)?;
        profiles.push(
            ProfileRef::new(id, version).map_err(|_| WorkloadAuthorityError::InvalidArtifact)?,
        );
    }
    if profiles.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    expect_key(&mut decoder, 4)?;
    let proof = decoder.bytes().map_err(malformed)?.to_vec();
    if !(1..=MAX_PROOF_BYTES).contains(&proof.len()) {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    expect_key(&mut decoder, 5)?;
    let trusted_context = decoder.bytes().map_err(malformed)?.to_vec();
    if !(1..=MAX_CONTEXT_BYTES).contains(&trusted_context.len()) {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    expect_key(&mut decoder, 6)?;
    let not_before_unix_seconds = decoder.i64().map_err(malformed)?;
    expect_key(&mut decoder, 7)?;
    let expires_at_unix_seconds = decoder.i64().map_err(malformed)?;
    expect_key(&mut decoder, 8)?;
    let artifact_id = decoder.str().map_err(malformed)?.to_owned();
    if decoder.position() != bytes.len()
        || not_before_unix_seconds < 0
        || expires_at_unix_seconds <= not_before_unix_seconds
        || !registered_token(&artifact_id)
    {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    let decoded_context = auths_codec::decode_verifier_context(&trusted_context)
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    if auths_codec::encode_verifier_context(&decoded_context)
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?
        != trusted_context
        || auths_verifier::decode_proof(&proof, &decoded_context).is_err()
    {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    let authority = WorkloadAuthority {
        principal,
        profiles: profiles.into(),
        proof: Arc::new(SecretBytes::new(proof)),
        trusted_context: Arc::new(SecretBytes::new(trusted_context)),
        not_before_unix_seconds,
        expires_at_unix_seconds,
        artifact_id: Arc::from(artifact_id),
        artifact_commitment: Sha256::digest(bytes).into(),
    };
    if encode_authority(&authority)? != bytes {
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    Ok(authority)
}

fn encode_authority(authority: &WorkloadAuthority) -> Result<Vec<u8>, WorkloadAuthorityError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder
        .map(AUTHORITY_FIELD_COUNT)
        .and_then(|value| value.u8(1))
        .and_then(|value| value.u8(AUTHORITY_SCHEMA_VERSION))
        .and_then(|value| value.u8(2))
        .and_then(|value| value.str(authority.principal().as_str()))
        .and_then(|value| value.u8(3))
        .and_then(|value| value.array(authority.profiles().len() as u64))
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    for profile in authority.profiles() {
        encoder
            .array(2)
            .and_then(|value| value.str(profile.id().as_str()))
            .and_then(|value| value.u16(profile.version()))
            .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    }
    encoder
        .u8(4)
        .and_then(|value| value.bytes(authority.proof_bytes()))
        .and_then(|value| value.u8(5))
        .and_then(|value| value.bytes(authority.trusted_context_bytes()))
        .and_then(|value| value.u8(6))
        .and_then(|value| value.i64(authority.not_before_unix_seconds))
        .and_then(|value| value.u8(7))
        .and_then(|value| value.i64(authority.expires_at_unix_seconds))
        .and_then(|value| value.u8(8))
        .and_then(|value| value.str(authority.artifact_id()))
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?;
    Ok(encoder.into_writer())
}

fn expect_key(decoder: &mut Decoder<'_>, key: u8) -> Result<(), WorkloadAuthorityError> {
    if decoder.u8().map_err(malformed)? == key {
        Ok(())
    } else {
        Err(WorkloadAuthorityError::InvalidArtifact)
    }
}

fn malformed(_error: minicbor::decode::Error) -> WorkloadAuthorityError {
    WorkloadAuthorityError::InvalidArtifact
}

fn parse_profile_ref(value: &str) -> Result<ProfileRef, WorkloadAuthorityError> {
    let (id, version) = value
        .rsplit_once('/')
        .ok_or(WorkloadAuthorityError::InvalidBinding)?;
    let id = ProfileId::parse(id).map_err(|_| WorkloadAuthorityError::InvalidBinding)?;
    let version = version
        .parse::<u16>()
        .map_err(|_| WorkloadAuthorityError::InvalidBinding)?;
    ProfileRef::new(id, version).map_err(|_| WorkloadAuthorityError::InvalidBinding)
}

fn registered_token(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn current_unix_seconds() -> Result<i64, WorkloadAuthorityError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| WorkloadAuthorityError::InvalidArtifact)?
        .as_secs();
    i64::try_from(seconds).map_err(|_| WorkloadAuthorityError::InvalidArtifact)
}

#[cfg(unix)]
fn open_root(path: &Path, agent_uid: u32) -> Result<File, WorkloadAuthorityError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    let file: File = fd.into();
    let metadata = file
        .metadata()
        .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    let owner = metadata.uid();
    if !metadata.is_dir() || (owner != 0 && owner != agent_uid) || metadata.mode() & 0o022 != 0 {
        return Err(WorkloadAuthorityError::UnsafeStorage);
    }
    Ok(file)
}

#[cfg(unix)]
fn read_relative_secret(
    root: &File,
    relative: &Path,
    agent_uid: u32,
) -> Result<Vec<u8>, WorkloadAuthorityError> {
    use rustix::fs::{Mode, OFlags};
    use std::os::unix::fs::MetadataExt as _;

    let components = relative
        .components()
        .map(|component| match component {
            Component::Normal(value) => Ok(value),
            _ => Err(WorkloadAuthorityError::UnsafePath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if components.is_empty() {
        return Err(WorkloadAuthorityError::UnsafePath);
    }
    let mut directory = root
        .try_clone()
        .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    for component in &components[..components.len() - 1] {
        let fd = rustix::fs::openat(
            &directory,
            Path::new(component),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
        let next: File = fd.into();
        let metadata = next
            .metadata()
            .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
        let owner = metadata.uid();
        if !metadata.is_dir() || (owner != 0 && owner != agent_uid) || metadata.mode() & 0o022 != 0
        {
            return Err(WorkloadAuthorityError::UnsafeStorage);
        }
        directory = next;
    }
    let fd = rustix::fs::openat(
        &directory,
        Path::new(components[components.len() - 1]),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    let mut file: File = fd.into();
    let metadata = file
        .metadata()
        .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    let owner = metadata.uid();
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (owner != 0 && owner != agent_uid)
        || metadata.mode() & 0o066 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_AUTHORITY_BYTES as u64
    {
        return Err(WorkloadAuthorityError::UnsafeStorage);
    }
    let capacity =
        usize::try_from(metadata.len()).map_err(|_| WorkloadAuthorityError::UnsafeStorage)?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take((MAX_AUTHORITY_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| WorkloadAuthorityError::UnsafePath)?;
    if bytes.is_empty() || bytes.len() > MAX_AUTHORITY_BYTES {
        bytes.fill(0);
        return Err(WorkloadAuthorityError::InvalidArtifact);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{ProfileId, ProfileRef};
    use std::{
        fs,
        os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    };
    use tempfile::tempdir;

    fn authority_bytes(principal: &str, profile: &ProfileRef, now: i64) -> Vec<u8> {
        let fixture = auths_testkit::corpus().remove(0);
        pack_workload_authority(
            principal,
            vec![profile.clone()],
            fixture.proof_bytes().to_vec(),
            fixture.context_bytes().to_vec(),
            now - 60,
            now + 60,
            "payments-authority-v1",
        )
        .unwrap()
    }

    fn profile() -> ProfileRef {
        ProfileRef::new(ProfileId::parse("auths.stripe.refund").unwrap(), 1).unwrap()
    }

    #[test]
    fn loads_canonical_artifact_and_rejects_scope_mismatch() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let authority_path = directory.path().join("payments.cbor");
        let now = 1_800_000_000;
        fs::write(
            &authority_path,
            authority_bytes("did:example:payments", &profile(), now),
        )
        .unwrap();
        fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o600)).unwrap();
        let uid = fs::metadata(directory.path()).unwrap().uid();
        let config = AgentConfig::from_toml(
            &format!(
                r#"
[agent]
authority_root = "{}"

[agent.receipt_signing.decision]
algorithm = "Ed25519"
key_id = "decision-2026-01"
verification_method = "did:key:auths-receipt-decision#decision-2026-01"
public_key_base64url = "1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"
seed_file = "/var/lib/auths/receipt-decision.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.receipt_signing.execution]
algorithm = "Ed25519"
key_id = "execution-2026-01"
verification_method = "did:key:auths-receipt-execution#execution-2026-01"
public_key_base64url = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"
seed_file = "/var/lib/auths/receipt-execution.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800

[agent.authority_sources.payments]
kind = "sealed-file-v1"
path = "{}"

[[agent.workloads]]
id = "payments"
principal = "did:example:payments"
authority_source = "payments"
allowed_profiles = ["auths.stripe.refund/1"]

[agent.workloads.selector]
kind = "posix"
uid = {}
"#,
                directory.path().display(),
                authority_path.display(),
                uid
            ),
            auths_config::AgentPlatform::Linux,
        )
        .unwrap();
        let snapshot = WorkloadAuthoritySnapshot::load_at(&config, uid, now).unwrap();
        let loaded = snapshot.get("payments").unwrap();
        assert_eq!(loaded.principal().as_str(), "did:example:payments");
        assert!(loaded.permits(&profile()));

        let mismatched = AgentConfig::from_toml(
            &format!(
                r#"
[agent]
authority_root = "{}"
[agent.receipt_signing.decision]
algorithm = "Ed25519"
key_id = "decision-2026-01"
verification_method = "did:key:auths-receipt-decision#decision-2026-01"
public_key_base64url = "1UIH2hlJd9z0atv-wrwudbUtWopCGE_t_cAAJPDj6No"
seed_file = "/var/lib/auths/receipt-decision.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800
[agent.receipt_signing.execution]
algorithm = "Ed25519"
key_id = "execution-2026-01"
verification_method = "did:key:auths-receipt-execution#execution-2026-01"
public_key_base64url = "URw0oaLLUh3xa7JGuN6OeZfOI1x-drIqPXUDokgZ3Yo"
seed_file = "/var/lib/auths/receipt-execution.key"
not_before_unix_seconds = 1
not_after_unix_seconds = 4102444800
[agent.authority_sources.payments]
kind = "sealed-file-v1"
path = "{}"
[[agent.workloads]]
id = "payments"
principal = "did:example:other"
authority_source = "payments"
allowed_profiles = ["auths.stripe.refund/1"]
[agent.workloads.selector]
kind = "posix"
uid = {}
"#,
                directory.path().display(),
                authority_path.display(),
                uid
            ),
            auths_config::AgentPlatform::Linux,
        )
        .unwrap();
        assert_eq!(
            WorkloadAuthoritySnapshot::load_at(&mismatched, uid, now).unwrap_err(),
            WorkloadAuthorityError::InvalidBinding
        );
    }

    #[test]
    fn rejects_permissive_file_and_noncanonical_artifact() {
        let directory = tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let authority_path = directory.path().join("payments.cbor");
        fs::write(&authority_path, [0xa0]).unwrap();
        fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o644)).unwrap();
        let root = open_root(
            directory.path(),
            fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap();
        assert_eq!(
            read_relative_secret(
                &root,
                Path::new("payments.cbor"),
                fs::metadata(directory.path()).unwrap().uid()
            )
            .unwrap_err(),
            WorkloadAuthorityError::UnsafeStorage
        );
        fs::set_permissions(&authority_path, fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = read_relative_secret(
            &root,
            Path::new("payments.cbor"),
            fs::metadata(directory.path()).unwrap().uid(),
        )
        .unwrap();
        assert_eq!(
            decode_authority(&bytes).unwrap_err(),
            WorkloadAuthorityError::InvalidArtifact
        );
    }
}
