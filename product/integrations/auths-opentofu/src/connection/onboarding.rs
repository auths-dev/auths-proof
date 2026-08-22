use std::collections::BTreeMap;

use super::OpenTofuConnectionDescriptor;
use auths_connections::{ConnectionAdapterError, CredentialStoreError, SecretBytes};
use serde::{Deserialize, Serialize};

/// Exact protected OpenTofu credential and backend initialization material.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenTofuConnectionSecretV1 {
    schema: String,
    environment: BTreeMap<String, String>,
    backend_configuration: BTreeMap<String, String>,
}

impl OpenTofuConnectionSecretV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CredentialStoreError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(CredentialStoreError::InvalidSecret);
        }
        let value: Self =
            serde_json::from_slice(bytes).map_err(|_| CredentialStoreError::InvalidSecret)?;
        value.validate()?;
        if serde_json_canonicalizer::to_vec(&value)
            .map_err(|_| CredentialStoreError::InvalidSecret)?
            != bytes
        {
            return Err(CredentialStoreError::InvalidSecret);
        }
        Ok(value)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CredentialStoreError> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self).map_err(|_| CredentialStoreError::InvalidSecret)
    }

    #[must_use]
    pub const fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    #[must_use]
    pub const fn backend_configuration(&self) -> &BTreeMap<String, String> {
        &self.backend_configuration
    }

    fn validate(&self) -> Result<(), CredentialStoreError> {
        if self.schema != "auths.opentofu.connection-secret/1"
            || self.environment.is_empty()
            || self.environment.len() > 64
            || self.backend_configuration.is_empty()
            || self.backend_configuration.len() > 64
            || self.environment.iter().any(|(name, value)| {
                !environment_name(name)
                    || value.is_empty()
                    || value.len() > 16 * 1024
                    || name.starts_with("TF_VAR_")
                    || matches!(
                        name.as_str(),
                        "PATH"
                            | "HOME"
                            | "SHELL"
                            | "TF_CLI_ARGS"
                            | "TF_CLI_CONFIG_FILE"
                            | "TF_DATA_DIR"
                            | "TF_WORKSPACE"
                    )
            })
            || self.backend_configuration.iter().any(|(name, value)| {
                !backend_key(name) || value.is_empty() || value.len() > 16 * 1024
            })
        {
            return Err(CredentialStoreError::InvalidSecret);
        }
        Ok(())
    }
}

/// Validates a protected OpenTofu backend credential without interpreting it in shared code.
pub fn validate_backend_secret(bytes: Vec<u8>) -> Result<SecretBytes, CredentialStoreError> {
    OpenTofuConnectionSecretV1::from_canonical_bytes(&bytes)?;
    SecretBytes::new(bytes)
}

/// Validates the exact descriptor and protected backend credential shape.
pub fn validate_onboarding(
    descriptor: &[u8],
    bytes: Vec<u8>,
) -> Result<SecretBytes, ConnectionAdapterError> {
    let descriptor = OpenTofuConnectionDescriptor::from_canonical_bytes(descriptor)?;
    if descriptor.backend_kind() == "local" {
        return Err(ConnectionAdapterError::InvalidDescriptor);
    }
    validate_backend_secret(bytes).map_err(|_| ConnectionAdapterError::CredentialUnavailable)
}

fn environment_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn backend_key(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
