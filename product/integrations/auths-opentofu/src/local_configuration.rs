//! Deployment-owned OpenTofu verifier and planner configuration.

#![forbid(unsafe_code)]

use std::path::{Component, Path};

use crate::{
    DigestHex, OpenTofuVerifierConfigurationV1, ValidationError, canonical::canonical_json,
};
use auths_profile_runtime::ProfileConfigurationBinding;
use serde::{Deserialize, Serialize};

/// Exact pinned provider or module dependency.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenTofuDependencyPinV1 {
    source: String,
    version: String,
    digest: DigestHex,
}

/// Closed launch policy for the protected planner and apply executor.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenTofuPlannerPolicyV1 {
    binary_path: String,
    binary_sha256: DigestHex,
    platform: String,
    fixed_plan_argv: Vec<String>,
    fixed_apply_argv: Vec<String>,
    sandbox_identity: String,
    dependency_mirror: String,
    provider_pins: Vec<OpenTofuDependencyPinV1>,
    module_pins: Vec<OpenTofuDependencyPinV1>,
    prepared_plan_lifetime_seconds: u64,
}

/// Exact deployment artifact shared by planning and saved-plan application.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenTofuLocalAgentConfigurationV1 {
    schema: String,
    verifier: OpenTofuVerifierConfigurationV1,
    planner: OpenTofuPlannerPolicyV1,
}

impl OpenTofuLocalAgentConfigurationV1 {
    pub fn from_binding(binding: &ProfileConfigurationBinding) -> Result<Self, ValidationError> {
        if binding.format() != "auths.opentofu.verifier-configuration/1" {
            return Err(ValidationError::InvalidConfiguration);
        }
        Self::from_canonical_bytes(binding.canonical_bytes())
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ValidationError::InvalidConfiguration)?;
        value.validate()?;
        if canonical_json(&value).map_err(|_| ValidationError::InvalidConfiguration)? != bytes {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        self.verifier.validate()?;
        let planner = &self.planner;
        if self.schema != "auths.opentofu.verifier-configuration/1"
            || !safe_absolute_path(&planner.binary_path)
            || !token(&planner.platform, 64)
            || !token(&planner.sandbox_identity, 128)
            || !valid_network_mirror(&planner.dependency_mirror)
            || !argv(&planner.fixed_plan_argv)
            || !argv(&planner.fixed_apply_argv)
            || planner.fixed_plan_argv.as_slice()
                != [
                    "plan",
                    "-input=false",
                    "-lock=true",
                    "-refresh=true",
                    "-out",
                    "{protected-saved-plan}",
                ]
            || planner.fixed_apply_argv.as_slice()
                != [
                    "apply",
                    "-input=false",
                    "-auto-approve",
                    "{protected-saved-plan}",
                ]
            || planner.provider_pins.is_empty()
            || !planner.module_pins.is_empty()
            || planner.prepared_plan_lifetime_seconds == 0
            || planner.prepared_plan_lifetime_seconds
                > self.verifier.maximum_authorization_lifetime_seconds()
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        validate_pins(&planner.provider_pins)
    }

    #[must_use]
    pub const fn verifier(&self) -> &OpenTofuVerifierConfigurationV1 {
        &self.verifier
    }

    #[must_use]
    pub const fn planner(&self) -> &OpenTofuPlannerPolicyV1 {
        &self.planner
    }
}

impl OpenTofuPlannerPolicyV1 {
    #[must_use]
    pub fn binary_path(&self) -> &str {
        &self.binary_path
    }

    #[must_use]
    pub const fn binary_sha256(&self) -> &DigestHex {
        &self.binary_sha256
    }

    #[must_use]
    pub fn platform(&self) -> &str {
        &self.platform
    }

    #[must_use]
    pub fn fixed_plan_argv(&self) -> &[String] {
        &self.fixed_plan_argv
    }

    #[must_use]
    pub fn fixed_apply_argv(&self) -> &[String] {
        &self.fixed_apply_argv
    }

    #[must_use]
    pub fn sandbox_identity(&self) -> &str {
        &self.sandbox_identity
    }

    #[must_use]
    pub fn dependency_mirror(&self) -> &str {
        &self.dependency_mirror
    }

    #[must_use]
    pub fn provider_pins(&self) -> &[OpenTofuDependencyPinV1] {
        &self.provider_pins
    }

    #[must_use]
    pub fn module_pins(&self) -> &[OpenTofuDependencyPinV1] {
        &self.module_pins
    }

    #[must_use]
    pub const fn prepared_plan_lifetime_seconds(&self) -> u64 {
        self.prepared_plan_lifetime_seconds
    }
}

impl OpenTofuDependencyPinV1 {
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    #[must_use]
    pub const fn digest(&self) -> &DigestHex {
        &self.digest
    }
}

fn validate_pins(values: &[OpenTofuDependencyPinV1]) -> Result<(), ValidationError> {
    if values.len() > 256
        || values.iter().any(|pin| {
            pin.source.is_empty()
                || pin.source.len() > 256
                || pin.version.is_empty()
                || pin.version.len() > 128
        })
        || values
            .windows(2)
            .any(|pair| (&pair[0].source, &pair[0].version) >= (&pair[1].source, &pair[1].version))
    {
        return Err(ValidationError::InvalidConfiguration);
    }
    Ok(())
}

fn argv(values: &[String]) -> bool {
    (1..=32).contains(&values.len())
        && values
            .iter()
            .all(|value| !value.is_empty() && value.len() <= 256 && !value.contains('\0'))
}

fn token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn safe_absolute_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

fn valid_network_mirror(value: &str) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    value.len() <= 512
        && parsed.scheme() == "https"
        && parsed.host().is_some()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && !value.ends_with('/')
}

#[cfg(test)]
mod tests {
    use super::valid_network_mirror;

    #[test]
    fn dependency_mirror_is_one_canonical_https_endpoint() {
        assert!(valid_network_mirror("https://127.0.0.1:28443/v1"));
        for invalid in [
            "/tmp/mirror",
            "http://127.0.0.1:28443/v1",
            "https://user@127.0.0.1:28443/v1",
            "https://127.0.0.1:28443/v1/",
            "https://127.0.0.1:28443/v1?alternate=true",
            "not a url",
        ] {
            assert!(!valid_network_mirror(invalid), "accepted {invalid}");
        }
    }
}
