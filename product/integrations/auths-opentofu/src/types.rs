//! Closed OpenTofu identifiers, verifier policy, evidence, and outcomes.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    canonical::{canonical_digest, sha256},
    errors::{CanonicalError, ValidationError},
};

/// Exact OpenTofu profile identifier.
pub const PROFILE_ID: &str = "auths.opentofu.saved-plan-apply";
/// Exact OpenTofu profile version.
pub const PROFILE_VERSION: u16 = 1;
/// Exact saved-plan application capability.
pub const APPLY_CAPABILITY: &str = "opentofu.saved-plan/apply";
/// Canonical action media type.
pub const MEDIA_TYPE: &str = "application/vnd.auths.opentofu.saved-plan-apply.v1+json";
/// Maximum canonical action size.
pub const MAX_ACTION_BYTES: usize = 512 * 1024;
/// Hard maximum plan changes.
pub const HARD_MAX_RESOURCE_CHANGES: usize = 1_024;
/// Hard evidence age.
pub const HARD_MAX_PLAN_AGE_SECONDS: u64 = 24 * 60 * 60;
/// Hard authorization lifetime.
pub const HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS: u64 = 60 * 60;

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_handle(value: &str) -> bool {
    (16..=256).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

macro_rules! validated_string {
    ($name:ident, $validator:ident, $message:literal) => {
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, ValidationError> {
                let value = value.into();
                if !$validator(&value) {
                    return Err(ValidationError::Malformed);
                }
                Ok(Self(value))
            }

            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = ValidationError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::parse(value).map_err(|_| serde::de::Error::custom($message))
            }
        }
    };
}

validated_string!(DigestHex, valid_digest, "invalid lowercase SHA-256 digest");
validated_string!(
    PlanHandle,
    valid_handle,
    "invalid opaque protected plan handle"
);

impl DigestHex {
    #[must_use]
    pub fn from_digest_bytes(bytes: [u8; 32]) -> Self {
        Self(hex::encode(bytes))
    }
}

/// One permitted action in a plan projection.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceAction {
    NoOp,
    Create,
    Read,
    Update,
    Delete,
}

/// Exact backend and state facts observed by the protected planner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuStateEvidenceV1 {
    pub backend_identity: String,
    pub workspace: String,
    pub state_lineage: String,
    pub state_serial: u64,
    pub state_digest: DigestHex,
    pub lock_held: bool,
    pub dependency_lock_digest: DigestHex,
    pub module_manifest_digest: DigestHex,
    pub planner_build_identity: String,
    pub observed_at: u64,
}

impl OpenTofuStateEvidenceV1 {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.backend_identity.is_empty()
            || self.backend_identity.len() > 512
            || self.workspace.is_empty()
            || self.workspace.len() > 128
            || self.state_lineage.is_empty()
            || self.state_lineage.len() > 256
            || self.planner_build_identity.is_empty()
            || self.planner_build_identity.len() > 256
        {
            return Err(ValidationError::InvalidEvidence);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }
}

/// Closed policy loaded by the planner and executor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuVerifierConfigurationV1 {
    profile: String,
    canonicalization_version: String,
    allowed_opentofu_versions: Vec<String>,
    allowed_backend_identities: Vec<String>,
    allowed_workspaces: Vec<String>,
    allowed_provider_sources: Vec<String>,
    allowed_resource_types: Vec<String>,
    allowed_actions: Vec<ResourceAction>,
    maximum_resource_changes: u32,
    maximum_plan_age_seconds: u64,
    maximum_authorization_lifetime_seconds: u64,
    allow_sensitive_outputs: bool,
    allow_destroy: bool,
    allow_replacement: bool,
    receipt_schema_version: String,
    executor_audience: String,
}

/// Input for canonical verifier policy construction.
pub struct OpenTofuVerifierConfigurationInput {
    pub allowed_opentofu_versions: Vec<String>,
    pub allowed_backend_identities: Vec<String>,
    pub allowed_workspaces: Vec<String>,
    pub allowed_provider_sources: Vec<String>,
    pub allowed_resource_types: Vec<String>,
    pub allowed_actions: Vec<ResourceAction>,
    pub maximum_resource_changes: u32,
    pub maximum_plan_age_seconds: u64,
    pub maximum_authorization_lifetime_seconds: u64,
    pub allow_sensitive_outputs: bool,
    pub allow_destroy: bool,
    pub allow_replacement: bool,
    pub receipt_schema_version: String,
    pub executor_audience: String,
}

impl OpenTofuVerifierConfigurationV1 {
    pub fn new(mut input: OpenTofuVerifierConfigurationInput) -> Result<Self, ValidationError> {
        input.allowed_opentofu_versions.sort();
        input.allowed_opentofu_versions.dedup();
        input.allowed_backend_identities.sort();
        input.allowed_backend_identities.dedup();
        input.allowed_workspaces.sort();
        input.allowed_workspaces.dedup();
        input.allowed_provider_sources.sort();
        input.allowed_provider_sources.dedup();
        input.allowed_resource_types.sort();
        input.allowed_resource_types.dedup();
        input.allowed_actions.sort();
        input.allowed_actions.dedup();
        let configuration = Self {
            profile: format!("{PROFILE_ID}/{PROFILE_VERSION}"),
            canonicalization_version: "rfc8785-sha256-v1".into(),
            allowed_opentofu_versions: input.allowed_opentofu_versions,
            allowed_backend_identities: input.allowed_backend_identities,
            allowed_workspaces: input.allowed_workspaces,
            allowed_provider_sources: input.allowed_provider_sources,
            allowed_resource_types: input.allowed_resource_types,
            allowed_actions: input.allowed_actions,
            maximum_resource_changes: input.maximum_resource_changes,
            maximum_plan_age_seconds: input.maximum_plan_age_seconds,
            maximum_authorization_lifetime_seconds: input.maximum_authorization_lifetime_seconds,
            allow_sensitive_outputs: input.allow_sensitive_outputs,
            allow_destroy: input.allow_destroy,
            allow_replacement: input.allow_replacement,
            receipt_schema_version: input.receipt_schema_version,
            executor_audience: input.executor_audience,
        };
        configuration.validate()?;
        Ok(configuration)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.profile != format!("{PROFILE_ID}/{PROFILE_VERSION}")
            || self.canonicalization_version != "rfc8785-sha256-v1"
            || self.allowed_opentofu_versions.is_empty()
            || self.allowed_backend_identities.is_empty()
            || self.allowed_workspaces.is_empty()
            || self.allowed_provider_sources.is_empty()
            || self.allowed_resource_types.is_empty()
            || self.allowed_actions.is_empty()
            || self.maximum_resource_changes == 0
            || usize::try_from(self.maximum_resource_changes)
                .map_or(true, |value| value > HARD_MAX_RESOURCE_CHANGES)
            || self.maximum_plan_age_seconds == 0
            || self.maximum_plan_age_seconds > HARD_MAX_PLAN_AGE_SECONDS
            || self.maximum_authorization_lifetime_seconds == 0
            || self.maximum_authorization_lifetime_seconds > HARD_MAX_AUTHORIZATION_LIFETIME_SECONDS
            || self.receipt_schema_version.is_empty()
            || self.executor_audience.is_empty()
            || self.allow_destroy
            || self.allow_replacement
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        for values in [
            &self.allowed_opentofu_versions,
            &self.allowed_backend_identities,
            &self.allowed_workspaces,
            &self.allowed_provider_sources,
            &self.allowed_resource_types,
        ] {
            if values.iter().any(String::is_empty)
                || values.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(ValidationError::InvalidConfiguration);
            }
        }
        if self
            .allowed_actions
            .iter()
            .any(|action| matches!(action, ResourceAction::Delete))
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    pub fn digest(&self) -> Result<DigestHex, CanonicalError> {
        canonical_digest(self)
    }

    #[must_use]
    pub fn executor_audience(&self) -> &str {
        &self.executor_audience
    }
    #[must_use]
    pub fn allowed_opentofu_versions(&self) -> &[String] {
        &self.allowed_opentofu_versions
    }
    #[must_use]
    pub fn allowed_backend_identities(&self) -> &[String] {
        &self.allowed_backend_identities
    }
    #[must_use]
    pub fn allowed_workspaces(&self) -> &[String] {
        &self.allowed_workspaces
    }
    #[must_use]
    pub fn allowed_provider_sources(&self) -> &[String] {
        &self.allowed_provider_sources
    }
    #[must_use]
    pub fn allowed_resource_types(&self) -> &[String] {
        &self.allowed_resource_types
    }
    #[must_use]
    pub fn allowed_actions(&self) -> &[ResourceAction] {
        &self.allowed_actions
    }
    #[must_use]
    pub const fn maximum_resource_changes(&self) -> u32 {
        self.maximum_resource_changes
    }
    #[must_use]
    pub const fn maximum_plan_age_seconds(&self) -> u64 {
        self.maximum_plan_age_seconds
    }
    #[must_use]
    pub const fn maximum_authorization_lifetime_seconds(&self) -> u64 {
        self.maximum_authorization_lifetime_seconds
    }
    #[must_use]
    pub const fn allow_sensitive_outputs(&self) -> bool {
        self.allow_sensitive_outputs
    }
    #[must_use]
    pub fn receipt_schema_version(&self) -> &str {
        &self.receipt_schema_version
    }
}

/// Post-apply observation without secret plan or provider values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenTofuApplyResult {
    pub state_lineage: String,
    pub prior_state_serial: u64,
    pub resulting_state_serial: u64,
    pub resulting_state_digest: DigestHex,
    pub provider_object_commitment: DigestHex,
    pub tool_build: String,
    pub execution_log_digest: DigestHex,
    pub started_at: u64,
    pub finished_at: u64,
    pub state_committed: bool,
    pub postconditions_observed: bool,
    pub converged: bool,
}

impl OpenTofuApplyResult {
    #[must_use]
    pub fn synthetic(
        lineage: impl Into<String>,
        prior_serial: u64,
        resulting_serial: u64,
        at: u64,
    ) -> Self {
        Self {
            state_lineage: lineage.into(),
            prior_state_serial: prior_serial,
            resulting_state_serial: resulting_serial,
            resulting_state_digest: sha256(b"synthetic-resulting-state"),
            provider_object_commitment: sha256(b"synthetic-provider-object"),
            tool_build: "opentofu-fixture/1".into(),
            execution_log_digest: sha256(b"synthetic-execution-log"),
            started_at: at,
            finished_at: at.saturating_add(1),
            state_committed: true,
            postconditions_observed: true,
            converged: true,
        }
    }
}
