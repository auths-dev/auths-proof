//! Deployment-owned PostgreSQL profile configuration.

#![forbid(unsafe_code)]

use crate::{PostgresVerifierConfigurationV1, ValidationError, canonical::canonical_json};
use auths_profile_runtime::ProfileConfigurationBinding;
use serde::{Deserialize, Serialize};

/// Exact deployment artifact shared by update preflight and execution.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresLocalAgentConfigurationV1 {
    schema: String,
    verifier: PostgresVerifierConfigurationV1,
    prepared_update_lifetime_seconds: u64,
}

impl PostgresLocalAgentConfigurationV1 {
    /// Decodes, validates, and proves canonical equality with the deployment
    /// bytes. No caller or connection value can substitute for this artifact.
    pub fn from_binding(binding: &ProfileConfigurationBinding) -> Result<Self, ValidationError> {
        if binding.format() != "auths.postgresql.verifier-configuration/1" {
            return Err(ValidationError::InvalidConfiguration);
        }
        Self::from_canonical_bytes(binding.canonical_bytes())
    }

    pub(crate) fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| ValidationError::InvalidConfiguration)?;
        value.validate()?;
        if canonical_json(&value)? != bytes {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(value)
    }

    /// Validates the closed launch policy and its prepared-record lifetime.
    pub fn validate(&self) -> Result<(), ValidationError> {
        self.verifier.validate()?;
        if self.schema != "auths.postgresql.verifier-configuration/1"
            || self.prepared_update_lifetime_seconds == 0
            || self.prepared_update_lifetime_seconds
                > self.verifier.maximum_authorization_lifetime_seconds()
        {
            return Err(ValidationError::InvalidConfiguration);
        }
        Ok(())
    }

    #[must_use]
    pub const fn verifier(&self) -> &PostgresVerifierConfigurationV1 {
        &self.verifier
    }

    #[must_use]
    pub const fn prepared_update_lifetime_seconds(&self) -> u64 {
        self.prepared_update_lifetime_seconds
    }
}
