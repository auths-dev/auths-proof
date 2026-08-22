use super::PostgresConnectionDescriptor;
use auths_connections::{ConnectionAdapterError, CredentialStoreError, SecretBytes};
use rustls_pki_types::{CertificateDer, pem::PemObject as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::str::FromStr as _;
use tokio_postgres::{
    Config,
    config::{Host, SslMode},
};

/// Closed protected PostgreSQL connection material.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PostgresConnectionSecretV1 {
    schema: String,
    connection_string: String,
    ca_pem: String,
}

impl PostgresConnectionSecretV1 {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CredentialStoreError> {
        if !(16..=65_536).contains(&bytes.len()) || bytes.contains(&0) {
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

    fn validate(&self) -> Result<(), CredentialStoreError> {
        let parsed = Config::from_str(&self.connection_string)
            .map_err(|_| CredentialStoreError::InvalidSecret)?;
        if self.schema != "auths.postgresql.connection-secret/1"
            || self.connection_string.len() > 32_768
            || parsed.get_ssl_mode() != SslMode::Require
            || self.ca_pem.is_empty()
            || self.ca_pem.len() > 32_768
        {
            return Err(CredentialStoreError::InvalidSecret);
        }
        let mut count = 0_usize;
        for certificate in CertificateDer::pem_slice_iter(self.ca_pem.as_bytes()) {
            certificate.map_err(|_| CredentialStoreError::InvalidSecret)?;
            count = count.saturating_add(1);
        }
        if count == 0 {
            return Err(CredentialStoreError::InvalidSecret);
        }
        Ok(())
    }

    #[must_use]
    pub fn connection_string(&self) -> &str {
        &self.connection_string
    }

    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// Proves that protected connection material names the exact public
    /// descriptor destination, database, and executor role.
    pub fn validate_for_descriptor(
        &self,
        descriptor: &PostgresConnectionDescriptor,
    ) -> Result<(), CredentialStoreError> {
        self.validate_destination_for_descriptor(descriptor, descriptor.executor_role())
    }

    /// Proves that qualification-only protected material names the descriptor
    /// destination while using the exact separately reviewed provider role.
    #[cfg(feature = "qualification")]
    pub fn validate_qualification_destination(
        &self,
        descriptor: &PostgresConnectionDescriptor,
        expected_role: &str,
    ) -> Result<(), CredentialStoreError> {
        self.validate_destination_for_descriptor(descriptor, expected_role)
    }

    fn validate_destination_for_descriptor(
        &self,
        descriptor: &PostgresConnectionDescriptor,
        expected_role: &str,
    ) -> Result<(), CredentialStoreError> {
        let parsed = Config::from_str(&self.connection_string)
            .map_err(|_| CredentialStoreError::InvalidSecret)?;
        let hosts = parsed.get_hosts();
        let ports = parsed.get_ports();
        let port = match ports {
            [] => 5432,
            [port] => *port,
            _ => return Err(CredentialStoreError::InvalidSecret),
        };
        if hosts != [Host::Tcp(descriptor.tls_server_name().to_owned())]
            || parsed.get_dbname() != Some(descriptor.database())
            || parsed.get_user() != Some(expected_role)
            || descriptor.server_identity()
                != format!("postgresql://{}:{port}", descriptor.tls_server_name())
            || hex::encode(Sha256::digest(self.ca_pem.as_bytes()))
                != descriptor.certificate_authority_sha256()
        {
            return Err(CredentialStoreError::InvalidSecret);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> PostgresConnectionDescriptor {
        let value: serde_json::Value =
            serde_json::from_slice(include_bytes!("../../fixtures/connection/v1/valid.json"))
                .unwrap();
        PostgresConnectionDescriptor::from_canonical_bytes(
            &serde_json_canonicalizer::to_vec(&value).unwrap(),
        )
        .unwrap()
    }

    fn secret(ca_pem: &str) -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "schema": "auths.postgresql.connection-secret/1",
            "connectionString": "host=database.internal port=5432 dbname=app user=auths_executor password=development-only sslmode=require",
            "caPem": ca_pem,
        }))
        .unwrap()
    }

    #[test]
    fn onboarding_binds_the_exact_private_certificate_authority() {
        let ca = include_str!("../../fixtures/connection/v1/test-ca.pem");
        let exact = PostgresConnectionSecretV1::from_canonical_bytes(&secret(ca)).unwrap();
        exact.validate_for_descriptor(&descriptor()).unwrap();

        let changed =
            PostgresConnectionSecretV1::from_canonical_bytes(&secret(&format!("{ca}\n"))).unwrap();
        assert!(changed.validate_for_descriptor(&descriptor()).is_err());

        let missing = serde_json_canonicalizer::to_vec(&serde_json::json!({
            "schema": "auths.postgresql.connection-secret/1",
            "connectionString": "host=database.internal port=5432 dbname=app user=auths_executor password=development-only sslmode=require",
        }))
        .unwrap();
        assert!(PostgresConnectionSecretV1::from_canonical_bytes(&missing).is_err());
    }
}

/// Validates a protected libpq service/credential blob without interpreting it in shared code.
pub fn validate_connection_secret(bytes: Vec<u8>) -> Result<SecretBytes, CredentialStoreError> {
    PostgresConnectionSecretV1::from_canonical_bytes(&bytes)?;
    SecretBytes::new(bytes)
}

/// Validates the exact descriptor and protected deployment credential shape.
pub fn validate_onboarding(
    descriptor: &[u8],
    bytes: Vec<u8>,
) -> Result<SecretBytes, ConnectionAdapterError> {
    let descriptor = PostgresConnectionDescriptor::from_canonical_bytes(descriptor)?;
    let secret = PostgresConnectionSecretV1::from_canonical_bytes(&bytes)
        .map_err(|_| ConnectionAdapterError::CredentialUnavailable)?;
    secret
        .validate_for_descriptor(&descriptor)
        .map_err(|_| ConnectionAdapterError::CredentialUnavailable)?;
    SecretBytes::new(bytes).map_err(|_| ConnectionAdapterError::CredentialUnavailable)
}
