use auths_connections::{ConnectionAdapterError, ValidatedConnectionDescriptor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Canonical non-secret OpenTofu backend descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenTofuConnectionDescriptor {
    schema: String,
    backend_kind: String,
    backend_identity: String,
    workspace_prefix: String,
    allowed_scopes: Vec<String>,
}

impl OpenTofuConnectionDescriptor {
    /// Parses exact canonical descriptor bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, ConnectionAdapterError> {
        if bytes.is_empty() || bytes.len() > 65_536 {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        let descriptor: Self =
            serde_json::from_slice(bytes).map_err(|_| ConnectionAdapterError::InvalidDescriptor)?;
        descriptor.validate()?;
        if descriptor.canonical_bytes()?.as_slice() != bytes {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        Ok(descriptor)
    }

    /// Serializes canonical JCS bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ConnectionAdapterError> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ConnectionAdapterError::InvalidDescriptor)
    }

    /// Returns the byte-sorted permitted profile scopes.
    #[must_use]
    pub fn allowed_scopes(&self) -> &[String] {
        &self.allowed_scopes
    }

    #[must_use]
    pub fn backend_kind(&self) -> &str {
        &self.backend_kind
    }

    #[must_use]
    pub fn backend_identity(&self) -> &str {
        &self.backend_identity
    }

    #[must_use]
    pub fn workspace_prefix(&self) -> &str {
        &self.workspace_prefix
    }

    /// Returns the commitment to backend and workspace identity.
    #[must_use]
    pub fn account_commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"auths.opentofu.backend-account/1\0");
        for value in [
            &self.backend_kind,
            &self.backend_identity,
            &self.workspace_prefix,
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value.as_bytes());
        }
        digest.finalize().into()
    }

    /// Converts the provider-validated descriptor to the shared sealed projection.
    pub fn validated(&self) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError> {
        ValidatedConnectionDescriptor::from_adapter(
            self.canonical_bytes()?,
            self.account_commitment(),
        )
    }

    fn validate(&self) -> Result<(), ConnectionAdapterError> {
        if self.schema != "auths.opentofu.connection-descriptor/1"
            || !registered_token(&self.backend_kind, 64)
            || !bounded_graphic(&self.backend_identity, 512)
            || !workspace_prefix(&self.workspace_prefix)
            || self.allowed_scopes.is_empty()
            || self.allowed_scopes.len() > 32
            || !self.allowed_scopes.windows(2).all(|pair| pair[0] < pair[1])
            || self.allowed_scopes.as_slice()
                != [
                    "opentofu.plan-preflight.create/1",
                    "opentofu.saved-plan.apply/1",
                ]
        {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        Ok(())
    }
}

fn bounded_graphic(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

fn registered_token(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len())
        && value.is_ascii()
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn workspace_prefix(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widened_scope_set_is_rejected() {
        let mut value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../fixtures/connection/v1/valid.json"))
                .unwrap();
        value["allowedScopes"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::String("opentofu.unknown/1".into()));
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            OpenTofuConnectionDescriptor::from_canonical_bytes(&bytes),
            Err(ConnectionAdapterError::InvalidDescriptor)
        );
    }
}
