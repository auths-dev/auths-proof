//! Closed local-agent workload, authority, and connection selection configuration.

use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path},
};
use thiserror::Error;

const MAX_WORKLOADS: usize = 4_096;
const MAX_AUTHORITY_SOURCES: usize = 4_096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentDocument {
    agent: AgentConfig,
}

/// Local operating-system platform used for selector validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentPlatform {
    /// Linux peer credentials with optional cgroup evidence.
    Linux,
    /// macOS peer credentials without Linux cgroups.
    Macos,
    /// Windows named-pipe identity.
    Windows,
}

/// Complete closed `[agent]` configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    authority_root: String,
    authority_sources: BTreeMap<String, AuthoritySourceConfig>,
    receipt_signing: ReceiptSigningConfig,
    #[serde(default)]
    profile_configurations: BTreeMap<String, ProfileConfigurationSourceConfig>,
    workloads: Vec<WorkloadConfig>,
}

/// Deployment-owned, role-separated receipt signing and retained trust set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSigningConfig {
    decision: ReceiptSigningKeyConfig,
    execution: ReceiptSigningKeyConfig,
    #[serde(default)]
    prior: Vec<ReceiptPublicKeyConfig>,
}

/// One current owner-only Ed25519 receipt signing key.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptSigningKeyConfig {
    algorithm: String,
    key_id: String,
    verification_method: String,
    public_key_base64url: String,
    seed_file: String,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

/// One prior public receipt key retained for historical verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiptPublicKeyConfig {
    role: ReceiptSigningRole,
    algorithm: String,
    key_id: String,
    verification_method: String,
    public_key_base64url: String,
    not_before_unix_seconds: u64,
    not_after_unix_seconds: u64,
}

/// Closed receipt signing role.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReceiptSigningRole {
    Decision,
    Execution,
}

/// One sealed deployment authority artifact.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum AuthoritySourceConfig {
    /// `auths.workload-authority-file/1` loaded beneath the authority root.
    SealedFileV1 {
        /// Absolute, normalized secret file path.
        path: String,
    },
}

/// One deployment-owned, non-secret profile verifier configuration.
///
/// The local agent loads and validates these files before accepting traffic.
/// Domain code remains responsible for decoding the exact configuration bytes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileConfigurationSourceConfig {
    format: String,
    path: String,
    sha256: String,
    maximum_bytes: u32,
}

impl ProfileConfigurationSourceConfig {
    #[must_use]
    pub fn format(&self) -> &str {
        &self.format
    }
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    #[must_use]
    pub const fn maximum_bytes(&self) -> u32 {
        self.maximum_bytes
    }
}

/// Authenticated workload mapping.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadConfig {
    id: String,
    principal: String,
    authority_source: String,
    allowed_profiles: Vec<String>,
    #[serde(default)]
    connections: Vec<ConnectionSelection>,
    selector: WorkloadSelector,
}

/// One provider connection made visible to a workload.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectionSelection {
    provider: String,
    alias: String,
    #[serde(default)]
    default: bool,
}

/// OS peer selector. Optional fields are additional conjunctions.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum WorkloadSelector {
    /// POSIX UID with optional GID, executable digest, and Linux cgroup prefix.
    Posix {
        uid: u32,
        gid: Option<u32>,
        executable_sha256: Option<String>,
        linux_cgroup_prefix: Option<String>,
    },
    /// Windows SID with optional executable digest.
    Windows {
        sid: String,
        executable_sha256: Option<String>,
    },
}

impl AgentConfig {
    /// Parses a document containing one closed `[agent]` table.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed TOML or an invalid configuration.
    pub fn from_toml(input: &str, platform: AgentPlatform) -> Result<Self, AgentConfigError> {
        if input.is_empty() || input.len() > 4 * 1024 * 1024 {
            return Err(AgentConfigError::Limit);
        }
        let document: AgentDocument =
            toml::from_str(input).map_err(|_| AgentConfigError::Malformed)?;
        document.agent.validate(platform)?;
        Ok(document.agent)
    }

    /// Validates selectors, authority references, profile lists, connection
    /// defaults, and path containment before startup.
    ///
    /// # Errors
    ///
    /// Returns the first closed validation failure without accepting a partial configuration.
    pub fn validate(&self, platform: AgentPlatform) -> Result<(), AgentConfigError> {
        let root = normalized_absolute(&self.authority_root)?;
        if self.authority_sources.is_empty()
            || self.authority_sources.len() > MAX_AUTHORITY_SOURCES
            || self.workloads.is_empty()
            || self.workloads.len() > MAX_WORKLOADS
            || self.profile_configurations.len() > 256
        {
            return Err(AgentConfigError::Limit);
        }
        self.receipt_signing.validate()?;
        for (id, source) in &self.authority_sources {
            if !registered_token(id) {
                return Err(AgentConfigError::InvalidAuthoritySource);
            }
            let AuthoritySourceConfig::SealedFileV1 { path } = source;
            let source_path = normalized_absolute(path)?;
            if source_path.parent().is_none()
                || !source_path.starts_with(root)
                || source_path == root
            {
                return Err(AgentConfigError::PathEscape);
            }
        }

        let mut path_metadata = BTreeMap::new();
        for (profile, source) in &self.profile_configurations {
            if !profile_ref(profile)
                || !semantic_id(&source.format, 128)
                || normalized_absolute(&source.path).is_err()
                || !lower_hex_32(&source.sha256)
                || !(1..=524_288).contains(&source.maximum_bytes)
            {
                return Err(AgentConfigError::InvalidProfileConfiguration);
            }
            let metadata = (
                source.format.as_str(),
                source.sha256.as_str(),
                source.maximum_bytes,
            );
            if path_metadata
                .insert(source.path.as_str(), metadata)
                .is_some_and(|existing| existing != metadata)
            {
                return Err(AgentConfigError::InvalidProfileConfiguration);
            }
        }

        let mut ids = BTreeSet::new();
        let mut selectors = BTreeSet::new();
        for workload in &self.workloads {
            workload.validate(platform, &self.authority_sources)?;
            if !ids.insert(workload.id.as_str()) || !selectors.insert(&workload.selector) {
                return Err(AgentConfigError::AmbiguousSelector);
            }
        }
        Ok(())
    }

    /// Returns the normalized authority root text.
    #[must_use]
    pub fn authority_root(&self) -> &str {
        &self.authority_root
    }

    /// Returns configured authority sources in byte-sorted key order.
    #[must_use]
    pub const fn authority_sources(&self) -> &BTreeMap<String, AuthoritySourceConfig> {
        &self.authority_sources
    }

    /// Returns the deployment-owned receipt signing/trust configuration.
    #[must_use]
    pub const fn receipt_signing(&self) -> &ReceiptSigningConfig {
        &self.receipt_signing
    }

    /// Returns configured workloads.
    #[must_use]
    pub fn workloads(&self) -> &[WorkloadConfig] {
        &self.workloads
    }

    /// Returns profile configuration sources keyed by exact profile ref.
    #[must_use]
    pub const fn profile_configurations(
        &self,
    ) -> &BTreeMap<String, ProfileConfigurationSourceConfig> {
        &self.profile_configurations
    }
}

impl ReceiptSigningConfig {
    #[must_use]
    pub const fn decision(&self) -> &ReceiptSigningKeyConfig {
        &self.decision
    }

    #[must_use]
    pub const fn execution(&self) -> &ReceiptSigningKeyConfig {
        &self.execution
    }

    #[must_use]
    pub fn prior(&self) -> &[ReceiptPublicKeyConfig] {
        &self.prior
    }

    fn validate(&self) -> Result<(), AgentConfigError> {
        self.decision.validate()?;
        self.execution.validate()?;
        if self.prior.len() > 14
            || self.decision.key_id == self.execution.key_id
            || self.decision.verification_method == self.execution.verification_method
            || self.decision.seed_file == self.execution.seed_file
            || !self.prior.windows(2).all(|pair| {
                (pair[0].role, pair[0].key_id.as_bytes())
                    < (pair[1].role, pair[1].key_id.as_bytes())
            })
        {
            return Err(AgentConfigError::InvalidReceiptSigning);
        }
        let mut key_ids = BTreeSet::from([
            self.decision.key_id.as_str(),
            self.execution.key_id.as_str(),
        ]);
        let mut methods = BTreeSet::from([
            self.decision.verification_method.as_str(),
            self.execution.verification_method.as_str(),
        ]);
        let mut public_keys = BTreeSet::from([
            self.decision.public_key_base64url.as_str(),
            self.execution.public_key_base64url.as_str(),
        ]);
        if public_keys.len() != 2 {
            return Err(AgentConfigError::InvalidReceiptSigning);
        }
        for prior in &self.prior {
            prior.validate()?;
            if !key_ids.insert(prior.key_id.as_str())
                || !methods.insert(prior.verification_method.as_str())
                || !public_keys.insert(prior.public_key_base64url.as_str())
            {
                return Err(AgentConfigError::InvalidReceiptSigning);
            }
        }
        Ok(())
    }
}

impl ReceiptSigningKeyConfig {
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    #[must_use]
    pub fn seed_file(&self) -> &str {
        &self.seed_file
    }

    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }

    fn validate(&self) -> Result<(), AgentConfigError> {
        if self.algorithm != "Ed25519"
            || !registered_token(&self.key_id)
            || !bounded_graphic(&self.verification_method, 512)
            || !base64url_sha256(&self.public_key_base64url)
            || normalized_absolute(&self.seed_file).is_err()
            || self.not_before_unix_seconds >= self.not_after_unix_seconds
        {
            return Err(AgentConfigError::InvalidReceiptSigning);
        }
        Ok(())
    }
}

impl ReceiptPublicKeyConfig {
    #[must_use]
    pub const fn role(&self) -> ReceiptSigningRole {
        self.role
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn verification_method(&self) -> &str {
        &self.verification_method
    }

    #[must_use]
    pub fn public_key_base64url(&self) -> &str {
        &self.public_key_base64url
    }

    #[must_use]
    pub const fn not_before_unix_seconds(&self) -> u64 {
        self.not_before_unix_seconds
    }

    #[must_use]
    pub const fn not_after_unix_seconds(&self) -> u64 {
        self.not_after_unix_seconds
    }

    fn validate(&self) -> Result<(), AgentConfigError> {
        if self.algorithm != "Ed25519"
            || !registered_token(&self.key_id)
            || !bounded_graphic(&self.verification_method, 512)
            || !base64url_sha256(&self.public_key_base64url)
            || self.not_before_unix_seconds >= self.not_after_unix_seconds
        {
            return Err(AgentConfigError::InvalidReceiptSigning);
        }
        Ok(())
    }
}

impl WorkloadConfig {
    fn validate(
        &self,
        platform: AgentPlatform,
        authority_sources: &BTreeMap<String, AuthoritySourceConfig>,
    ) -> Result<(), AgentConfigError> {
        if !registered_token(&self.id)
            || !semantic_id(&self.principal, 512)
            || !registered_token(&self.authority_source)
            || !authority_sources.contains_key(&self.authority_source)
            || self.allowed_profiles.is_empty()
            || self.allowed_profiles.len() > 32
            || self.connections.len() > 256
            || !strictly_sorted_unique(&self.allowed_profiles)
            || self
                .allowed_profiles
                .iter()
                .any(|value| !profile_ref(value))
            || !strictly_sorted_unique(&self.connections)
        {
            return Err(AgentConfigError::InvalidWorkload);
        }
        let mut defaults = BTreeSet::new();
        for connection in &self.connections {
            if !lower_token(&connection.provider)
                || !lower_token(&connection.alias)
                || (connection.default && !defaults.insert(connection.provider.as_str()))
            {
                return Err(AgentConfigError::InvalidConnectionSelection);
            }
        }
        self.selector.validate(platform)
    }

    /// Returns the stable workload identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Returns the expected Auths principal.
    #[must_use]
    pub fn principal(&self) -> &str {
        &self.principal
    }
    /// Returns the deployment authority-source ID.
    #[must_use]
    pub fn authority_source(&self) -> &str {
        &self.authority_source
    }
    /// Returns byte-sorted allowed profile references.
    #[must_use]
    pub fn allowed_profiles(&self) -> &[String] {
        &self.allowed_profiles
    }
    /// Returns byte-sorted visible connections.
    #[must_use]
    pub fn connections(&self) -> &[ConnectionSelection] {
        &self.connections
    }
    /// Returns the exact peer selector.
    #[must_use]
    pub const fn selector(&self) -> &WorkloadSelector {
        &self.selector
    }
}

impl ConnectionSelection {
    /// Constructs one validated non-secret provider connection selection.
    ///
    /// # Errors
    ///
    /// Rejects a provider kind or alias outside the closed lower-token grammar.
    pub fn new(
        provider: impl Into<String>,
        alias: impl Into<String>,
        default: bool,
    ) -> Result<Self, AgentConfigError> {
        let value = Self {
            provider: provider.into(),
            alias: alias.into(),
            default,
        };
        if !lower_token(&value.provider) || !lower_token(&value.alias) {
            return Err(AgentConfigError::InvalidConnectionSelection);
        }
        Ok(value)
    }

    /// Returns the provider kind.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
    /// Returns the connection alias.
    #[must_use]
    pub fn alias(&self) -> &str {
        &self.alias
    }
    /// Reports whether this is the provider default for the workload.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        self.default
    }
}

impl WorkloadSelector {
    fn validate(&self, platform: AgentPlatform) -> Result<(), AgentConfigError> {
        match self {
            Self::Posix {
                executable_sha256,
                linux_cgroup_prefix,
                ..
            } => {
                if platform == AgentPlatform::Windows
                    || executable_sha256
                        .as_deref()
                        .is_some_and(|value| !lower_hex_32(value))
                    || linux_cgroup_prefix
                        .as_deref()
                        .is_some_and(|value| !cgroup_prefix(value))
                    || (platform == AgentPlatform::Macos && linux_cgroup_prefix.is_some())
                {
                    return Err(AgentConfigError::InvalidSelector);
                }
            }
            Self::Windows {
                sid,
                executable_sha256,
            } => {
                if platform != AgentPlatform::Windows
                    || !windows_sid_shape(sid)
                    || executable_sha256
                        .as_deref()
                        .is_some_and(|value| !lower_hex_32(value))
                {
                    return Err(AgentConfigError::InvalidSelector);
                }
            }
        }
        Ok(())
    }
}

/// Closed agent workload configuration error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AgentConfigError {
    /// Input is empty or exceeds its hard ceiling.
    #[error("agent configuration exceeds its bound")]
    Limit,
    /// TOML is malformed or contains unknown fields.
    #[error("agent configuration is malformed")]
    Malformed,
    /// Authority root or source path is malformed.
    #[error("invalid authority path")]
    InvalidPath,
    /// Authority source escapes the configured root.
    #[error("authority source escapes the configured root")]
    PathEscape,
    /// Authority source ID or shape is invalid.
    #[error("invalid authority source")]
    InvalidAuthoritySource,
    /// Workload identity, authority, profile set, or ordering is invalid.
    #[error("invalid workload mapping")]
    InvalidWorkload,
    /// Two workload entries have the same exact selector or ID.
    #[error("ambiguous workload selector")]
    AmbiguousSelector,
    /// Peer selector is unsupported or invalid on the selected platform.
    #[error("invalid workload selector")]
    InvalidSelector,
    /// Connection visibility or default selection is invalid.
    #[error("invalid workload connection selection")]
    InvalidConnectionSelection,
    /// A profile reference or its configured source is invalid.
    #[error("invalid profile configuration source")]
    InvalidProfileConfiguration,
    /// Receipt signing keys, roles, validity, or retained trust collide.
    #[error("invalid receipt signing configuration")]
    InvalidReceiptSigning,
}

fn normalized_absolute(value: &str) -> Result<&Path, AgentConfigError> {
    if value.is_empty() || value.len() > 1_024 || value.contains('\0') {
        return Err(AgentConfigError::InvalidPath);
    }
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(AgentConfigError::InvalidPath);
    }
    Ok(path)
}

fn registered_token(value: &str) -> bool {
    semantic_id(value, 128)
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn semantic_id(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
}

fn bounded_graphic(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.is_ascii()
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn base64url_sha256(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn profile_ref(value: &str) -> bool {
    let Some((id, version)) = value.rsplit_once('/') else {
        return false;
    };
    semantic_id(id, 128)
        && version.parse::<u16>().is_ok_and(|parsed| parsed > 0)
        && !version.starts_with('0')
}

fn lower_token(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn cgroup_prefix(value: &str) -> bool {
    (1..=512).contains(&value.len())
        && value.starts_with('/')
        && value.ends_with('/')
        && value
            .split('/')
            .filter(|component| !component.is_empty())
            .all(|component| component != "." && component != ".." && !component.contains('\0'))
}

fn windows_sid_shape(value: &str) -> bool {
    (1..=184).contains(&value.len())
        && value.is_ascii()
        && value.starts_with("S-1-")
        && value.split('-').skip(1).all(|component| {
            !component.is_empty() && component.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONFIG: &str = r#"
[agent]
authority_root = "/var/lib/auths/authorities"

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

[agent.authority_sources.payments-worker-authority]
kind = "sealed-file-v1"
path = "/var/lib/auths/authorities/payments-worker.cbor"

[[agent.workloads]]
id = "payments-worker"
principal = "did:example:payments-worker"
authority_source = "payments-worker-authority"
allowed_profiles = ["auths.stripe.refund/1"]
connections = [{ provider = "stripe", alias = "merchant-primary", default = true }]

[agent.workloads.selector]
kind = "posix"
uid = 10001
gid = 10001
executable_sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
linux_cgroup_prefix = "/payments.slice/"
"#;

    #[test]
    fn exact_agent_workload_configuration_parses() {
        let config = AgentConfig::from_toml(CONFIG, AgentPlatform::Linux).unwrap();
        assert_eq!(config.workloads()[0].id(), "payments-worker");
        assert!(config.workloads()[0].connections()[0].is_default());
    }

    #[test]
    fn duplicate_default_or_path_escape_fails_closed() {
        let duplicate = CONFIG.replace(
            "connections = [{ provider = \"stripe\", alias = \"merchant-primary\", default = true }]",
            "connections = [{ provider = \"stripe\", alias = \"a\", default = true }, { provider = \"stripe\", alias = \"b\", default = true }]",
        );
        assert_eq!(
            AgentConfig::from_toml(&duplicate, AgentPlatform::Linux).unwrap_err(),
            AgentConfigError::InvalidConnectionSelection
        );
        let escaped = CONFIG.replace(
            "/var/lib/auths/authorities/payments-worker.cbor",
            "/var/lib/auths/other.cbor",
        );
        assert_eq!(
            AgentConfig::from_toml(&escaped, AgentPlatform::Linux).unwrap_err(),
            AgentConfigError::PathEscape
        );
    }
}
