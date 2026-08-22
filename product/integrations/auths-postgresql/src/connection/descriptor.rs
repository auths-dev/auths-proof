use auths_connections::{ConnectionAdapterError, ValidatedConnectionDescriptor};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Canonical non-secret PostgreSQL deployment descriptor.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresConnectionDescriptor {
    schema: String,
    server_identity: String,
    database: String,
    executor_role: String,
    tls_server_name: String,
    allowed_scopes: Vec<String>,
}

impl PostgresConnectionDescriptor {
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
    pub fn server_identity(&self) -> &str {
        &self.server_identity
    }

    #[must_use]
    pub fn database(&self) -> &str {
        &self.database
    }

    #[must_use]
    pub fn executor_role(&self) -> &str {
        &self.executor_role
    }

    #[must_use]
    pub fn tls_server_name(&self) -> &str {
        &self.tls_server_name
    }

    /// Returns the committed server/database/role account identity.
    #[must_use]
    pub fn account_commitment(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"auths.postgresql.account/1\0");
        for value in [&self.server_identity, &self.database, &self.executor_role] {
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
        if self.schema != "auths.postgresql.connection-descriptor/1"
            || !bounded_graphic(&self.server_identity, 512)
            || !postgres_identifier(&self.database)
            || !postgres_identifier(&self.executor_role)
            || !dns_name(&self.tls_server_name)
            || self.allowed_scopes.is_empty()
            || self.allowed_scopes.len() > 32
            || !self.allowed_scopes.windows(2).all(|pair| pair[0] < pair[1])
            || self.allowed_scopes.as_slice()
                != [
                    "postgresql.bounded-update.execute/1",
                    "postgresql.update-preflight.create/1",
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
fn postgres_identifier(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
fn dns_name(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && !value.starts_with('.')
        && !value.ends_with('.')
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
            .push(serde_json::Value::String("postgresql.unknown/1".into()));
        let bytes = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            PostgresConnectionDescriptor::from_canonical_bytes(&bytes),
            Err(ConnectionAdapterError::InvalidDescriptor)
        );
    }
}
