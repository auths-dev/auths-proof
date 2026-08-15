use auths_production_client::QualifiedProfile;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fs, net::SocketAddr, path::Path, time::Duration};

const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeploymentMode {
    Local,
    Production,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    contract_version: u16,
    mode: DeploymentMode,
    bind: SocketAddr,
    release: String,
    semantic_id: String,
    request_timeout_ms: u64,
    drain_timeout_seconds: u64,
    ingress_tls: bool,
    lifecycle: LifecycleConfig,
    custody: CustodyConfig,
    telemetry: TelemetryConfig,
    verification: VerificationConfig,
    profiles: ProfilesConfig,
}

/// The deployment's trust decision, stated as bytes rather than as code.
///
/// `trusted_context_path` names a file holding one canonical
/// `TrustedContext` (`auths_codec::encode_verifier_context`). It carries the
/// trust anchors, accepted registries, status snapshots, assurance policy, and
/// verifier limits every authorization decision is made against. A node without
/// one cannot decide anything, which is why this section is mandatory.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct VerificationConfig {
    trusted_context_path: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleConfig {
    url_env: String,
    ca_pem: String,
    server_name: String,
    maximum_records: usize,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
enum CustodyConfig {
    SoftwareFixture {
        seed_env: String,
    },
    Pkcs11 {
        module: String,
        token: String,
        object_hex: String,
        pin_env: String,
    },
    AwsKms {
        key_arn_env: String,
        region: String,
        account: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TelemetryConfig {
    otlp_endpoint: String,
    service_name: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
struct ProfilesConfig {
    opentofu_saved_plan_apply: bool,
    postgresql_bounded_update: bool,
    github_issue_address: bool,
    sandbox_providers: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeConfigSummary {
    pub contract_version: u16,
    pub mode: DeploymentMode,
    pub bind: SocketAddr,
    pub release: String,
    pub semantic_id: String,
    pub request_timeout_ms: u64,
    pub drain_timeout_seconds: u64,
    pub ingress_tls: bool,
    pub lifecycle_family: &'static str,
    pub lifecycle_tls: bool,
    pub custody_family: &'static str,
    pub telemetry_family: &'static str,
    pub profiles: Vec<&'static str>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorSection {
    pub name: &'static str,
    pub status: &'static str,
    pub detail: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorReport {
    pub ready: bool,
    pub sections: Vec<DoctorSection>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError {
    ConfigUnavailable,
    ConfigTooLarge,
    MalformedConfig,
    UnsupportedContract,
    UnsafeProductionConfig,
    InvalidBound,
    InvalidIdentifier,
    InvalidPath,
    InvalidEndpoint,
    MissingProfile,
}

impl NodeConfig {
    /// Loads a bounded node configuration from a regular file.
    ///
    /// # Errors
    ///
    /// Returns a startup error when the file is unavailable, oversized,
    /// malformed, or fails production safety checks.
    pub fn from_path(path: &Path) -> Result<Self, StartupError> {
        let metadata = fs::symlink_metadata(path).map_err(|_| StartupError::ConfigUnavailable)?;
        if !metadata.file_type().is_file() || metadata.len() > MAX_CONFIG_BYTES {
            return Err(if metadata.len() > MAX_CONFIG_BYTES {
                StartupError::ConfigTooLarge
            } else {
                StartupError::ConfigUnavailable
            });
        }
        let bytes = fs::read(path).map_err(|_| StartupError::ConfigUnavailable)?;
        let source = std::str::from_utf8(&bytes).map_err(|_| StartupError::MalformedConfig)?;
        Self::parse(source)
    }

    /// Parses and validates a bounded node configuration.
    ///
    /// # Errors
    ///
    /// Returns a startup error for malformed, unsupported, or unsafe values.
    pub fn parse(source: &str) -> Result<Self, StartupError> {
        if source.is_empty()
            || source.len() > usize::try_from(MAX_CONFIG_BYTES).unwrap_or(usize::MAX)
        {
            return Err(StartupError::MalformedConfig);
        }
        let value: Self = toml::from_str(source).map_err(|_| StartupError::MalformedConfig)?;
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), StartupError> {
        if self.contract_version != 1 {
            return Err(StartupError::UnsupportedContract);
        }
        if !valid_label(&self.release, 128) || !valid_label(&self.semantic_id, 128) {
            return Err(StartupError::InvalidIdentifier);
        }
        if !(100..=120_000).contains(&self.request_timeout_ms)
            || !(1..=300).contains(&self.drain_timeout_seconds)
            || self.lifecycle.maximum_records == 0
            || self.lifecycle.maximum_records > 1_000_000
        {
            return Err(StartupError::InvalidBound);
        }
        validate_env_slot(&self.lifecycle.url_env)?;
        if !Path::new(&self.lifecycle.ca_pem).is_absolute()
            || self.lifecycle.server_name.is_empty()
            || self.lifecycle.server_name.len() > 253
        {
            return Err(StartupError::InvalidPath);
        }
        if !Path::new(&self.verification.trusted_context_path).is_absolute() {
            return Err(StartupError::InvalidPath);
        }
        if !self.telemetry.otlp_endpoint.starts_with("http://")
            && !self.telemetry.otlp_endpoint.starts_with("https://")
        {
            return Err(StartupError::InvalidEndpoint);
        }
        if !valid_label(&self.telemetry.service_name, 96) {
            return Err(StartupError::InvalidIdentifier);
        }
        self.validate_custody()?;
        if self.enabled_profiles().is_empty() {
            return Err(StartupError::MissingProfile);
        }
        if self.mode == DeploymentMode::Production
            && (!self.ingress_tls
                || self.profiles.sandbox_providers
                || matches!(self.custody, CustodyConfig::SoftwareFixture { .. }))
        {
            return Err(StartupError::UnsafeProductionConfig);
        }
        Ok(())
    }

    fn validate_custody(&self) -> Result<(), StartupError> {
        match &self.custody {
            CustodyConfig::SoftwareFixture { seed_env } => validate_env_slot(seed_env),
            CustodyConfig::Pkcs11 {
                module,
                token,
                object_hex,
                pin_env,
            } => {
                validate_env_slot(pin_env)?;
                if !Path::new(module).is_absolute()
                    || !valid_label(token, 128)
                    || object_hex.is_empty()
                    || object_hex.len() > 256
                    || object_hex.len() % 2 != 0
                    || !object_hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                {
                    return Err(StartupError::InvalidPath);
                }
                Ok(())
            }
            CustodyConfig::AwsKms {
                key_arn_env,
                region,
                account,
            } => {
                validate_env_slot(key_arn_env)?;
                if region.is_empty()
                    || region.len() > 64
                    || !region.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
                    || account.len() != 12
                    || !account.bytes().all(|byte| byte.is_ascii_digit())
                {
                    return Err(StartupError::InvalidIdentifier);
                }
                Ok(())
            }
        }
    }

    #[must_use]
    pub const fn bind(&self) -> SocketAddr {
        self.bind
    }

    #[must_use]
    pub const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.request_timeout_ms)
    }

    #[must_use]
    pub const fn drain_timeout(&self) -> Duration {
        Duration::from_secs(self.drain_timeout_seconds)
    }

    #[must_use]
    pub fn release(&self) -> &str {
        &self.release
    }

    #[must_use]
    pub fn semantic_id(&self) -> &str {
        &self.semantic_id
    }

    #[must_use]
    pub const fn mode(&self) -> DeploymentMode {
        self.mode
    }

    #[must_use]
    pub fn enabled_profiles(&self) -> BTreeSet<QualifiedProfile> {
        let mut profiles = BTreeSet::new();
        if self.profiles.opentofu_saved_plan_apply {
            profiles.insert(QualifiedProfile::OpenTofuSavedPlanApply);
        }
        if self.profiles.postgresql_bounded_update {
            profiles.insert(QualifiedProfile::PostgreSqlBoundedUpdate);
        }
        if self.profiles.github_issue_address {
            profiles.insert(QualifiedProfile::GitHubIssueAddress);
        }
        profiles
    }

    #[must_use]
    pub fn sandbox_providers(&self) -> bool {
        self.profiles.sandbox_providers
    }

    #[must_use]
    pub fn fixture_seed_env(&self) -> Option<&str> {
        match &self.custody {
            CustodyConfig::SoftwareFixture { seed_env } => Some(seed_env),
            CustodyConfig::Pkcs11 { .. } | CustodyConfig::AwsKms { .. } => None,
        }
    }

    #[must_use]
    pub fn trusted_context_path(&self) -> &Path {
        Path::new(&self.verification.trusted_context_path)
    }

    #[must_use]
    pub fn lifecycle_url_env(&self) -> &str {
        &self.lifecycle.url_env
    }

    #[must_use]
    pub fn lifecycle_ca_pem(&self) -> &Path {
        Path::new(&self.lifecycle.ca_pem)
    }

    #[must_use]
    pub fn lifecycle_server_name(&self) -> &str {
        &self.lifecycle.server_name
    }

    #[must_use]
    pub const fn maximum_lifecycle_records(&self) -> usize {
        self.lifecycle.maximum_records
    }

    #[must_use]
    pub fn safe_summary(&self) -> SafeConfigSummary {
        SafeConfigSummary {
            contract_version: self.contract_version,
            mode: self.mode,
            bind: self.bind,
            release: self.release.clone(),
            semantic_id: self.semantic_id.clone(),
            request_timeout_ms: self.request_timeout_ms,
            drain_timeout_seconds: self.drain_timeout_seconds,
            ingress_tls: self.ingress_tls,
            lifecycle_family: "postgresql-v3",
            lifecycle_tls: true,
            custody_family: match self.custody {
                CustodyConfig::SoftwareFixture { .. } => "software-fixture",
                CustodyConfig::Pkcs11 { .. } => "pkcs11-p256-v1",
                CustodyConfig::AwsKms { .. } => "aws-kms-p256-v1",
            },
            telemetry_family: "otlp-v1",
            profiles: self
                .enabled_profiles()
                .into_iter()
                .map(QualifiedProfile::as_str)
                .collect(),
        }
    }

    #[must_use]
    pub fn doctor(&self, dependencies_ready: bool) -> DoctorReport {
        let profiles = self
            .enabled_profiles()
            .into_iter()
            .map(QualifiedProfile::as_str)
            .collect::<Vec<_>>()
            .join(" / ");
        DoctorReport {
            ready: dependencies_ready,
            sections: vec![
                DoctorSection {
                    name: "Configuration",
                    status: "PASS",
                    detail: format!("contract {} / {}", self.contract_version, self.semantic_id),
                },
                DoctorSection {
                    name: "Lifecycle DB",
                    status: if dependencies_ready { "PASS" } else { "FAIL" },
                    detail: "TLS / auths.lifecycle.postgresql/3".into(),
                },
                DoctorSection {
                    name: "Custody",
                    status: "PASS",
                    detail: self.safe_summary().custody_family.into(),
                },
                DoctorSection {
                    name: "Profiles",
                    status: "PASS",
                    detail: profiles,
                },
            ],
        }
    }
}

fn validate_env_slot(value: &str) -> Result<(), StartupError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(StartupError::InvalidIdentifier);
    }
    Ok(())
}

fn valid_label(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'/'))
}

impl std::fmt::Display for StartupError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConfigUnavailable => "configuration is unavailable",
            Self::ConfigTooLarge => "configuration exceeds the maximum size",
            Self::MalformedConfig => "configuration is malformed",
            Self::UnsupportedContract => "configuration contract is unsupported",
            Self::UnsafeProductionConfig => "production configuration selects an unsafe dependency",
            Self::InvalidBound => "configuration bound is invalid",
            Self::InvalidIdentifier => "configuration identifier is invalid",
            Self::InvalidPath => "configuration path is invalid",
            Self::InvalidEndpoint => "configuration endpoint is invalid",
            Self::MissingProfile => "at least one qualified profile is required",
        })
    }
}

impl std::error::Error for StartupError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(mode: &str, custody: &str, sandbox: bool, ingress_tls: bool) -> String {
        format!(
            r#"contract_version = 1
mode = "{mode}"
bind = "127.0.0.1:8080"
release = "candidate-1"
semantic_id = "auths.open-production/1"
request_timeout_ms = 10000
drain_timeout_seconds = 30
ingress_tls = {ingress_tls}

[lifecycle]
url_env = "AUTHS_POSTGRES_URL"
ca_pem = "/run/secrets/postgres-ca.pem"
server_name = "postgres"
maximum_records = 4096

{custody}

[telemetry]
otlp_endpoint = "http://otel:4317"
service_name = "auths-node"

[verification]
trusted_context_path = "/run/config/trusted-context.cbor"

[profiles]
opentofu_saved_plan_apply = true
postgresql_bounded_update = true
github_issue_address = true
sandbox_providers = {sandbox}
"#
        )
    }

    /// A node cannot decide anything without the deployment's trusted context,
    /// so a configuration that does not name one must not start.
    #[test]
    fn a_node_without_a_trusted_context_refuses_to_start() {
        let complete = source(
            "local",
            "[custody]\nkind = \"software-fixture\"\nseed_env = \"AUTHS_LOCAL_SEED\"",
            true,
            false,
        );
        let without = complete.replace(
            "[verification]\ntrusted_context_path = \"/run/config/trusted-context.cbor\"\n\n",
            "",
        );
        assert_ne!(without, complete, "the fixture must contain the section");
        assert_eq!(
            NodeConfig::parse(&without).unwrap_err(),
            StartupError::MalformedConfig
        );
        let relative = complete.replace(
            "\"/run/config/trusted-context.cbor\"",
            "\"trusted-context.cbor\"",
        );
        assert_eq!(
            NodeConfig::parse(&relative).unwrap_err(),
            StartupError::InvalidPath
        );
    }

    #[test]
    fn local_fixture_is_explicit_and_redacted() {
        let config = NodeConfig::parse(&source(
            "local",
            "[custody]\nkind = \"software-fixture\"\nseed_env = \"AUTHS_LOCAL_SEED\"",
            true,
            false,
        ))
        .unwrap();
        let summary = config.safe_summary();
        assert_eq!(summary.custody_family, "software-fixture");
        assert_eq!(summary.profiles.len(), 3);
        assert!(
            !serde_json::to_string(&summary)
                .unwrap()
                .contains("AUTHS_LOCAL_SEED")
        );
    }

    #[test]
    fn production_rejects_fixture_custody_and_sandbox_gateways() {
        let result = NodeConfig::parse(&source(
            "production",
            "[custody]\nkind = \"software-fixture\"\nseed_env = \"AUTHS_LOCAL_SEED\"",
            true,
            true,
        ));
        assert_eq!(result.unwrap_err(), StartupError::UnsafeProductionConfig);
    }

    #[test]
    fn production_accepts_external_custody_without_secret_values() {
        let config = NodeConfig::parse(&source(
            "production",
            "[custody]\nkind = \"aws-kms\"\nkey_arn_env = \"AUTHS_KMS_KEY_ARN\"\nregion = \"eu-west-2\"\naccount = \"123456789012\"",
            false,
            true,
        ))
        .unwrap();
        assert_eq!(config.mode(), DeploymentMode::Production);
        assert_eq!(config.safe_summary().custody_family, "aws-kms-p256-v1");
    }
}
