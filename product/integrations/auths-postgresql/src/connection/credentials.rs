use super::descriptor::PostgresConnectionDescriptor;
use async_trait::async_trait;
use auths_connections::{
    ConnectionAdapterError, ConnectionBinding, ConnectionCredentialStore, CredentialScope,
    ProviderConnectionAdapter, ProviderCredentialLease, ValidatedConnectionDescriptor,
};
use std::{collections::BTreeMap, sync::RwLock, time::Instant};

/// Static PostgreSQL deployment connection adapter.
pub struct PostgresConnectionAdapter {
    descriptors: RwLock<BTreeMap<[u8; 32], PostgresConnectionDescriptor>>,
}

impl PostgresConnectionAdapter {
    /// Creates an adapter populated during validated configuration loading.
    #[must_use]
    pub fn new() -> Self {
        Self {
            descriptors: RwLock::new(BTreeMap::new()),
        }
    }
}
impl Default for PostgresConnectionAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderConnectionAdapter for PostgresConnectionAdapter {
    fn provider_kind(&self) -> &'static str {
        "postgresql"
    }
    fn contract_id(&self) -> &'static str {
        "auths.postgresql.connection/1"
    }
    fn descriptor_schema(&self) -> &'static str {
        "auths.postgresql.connection-descriptor/1"
    }
    fn validate_descriptor(
        &self,
        bytes: &[u8],
    ) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError> {
        let descriptor = PostgresConnectionDescriptor::from_canonical_bytes(bytes)?;
        let validated = descriptor.validated()?;
        self.descriptors
            .write()
            .map_err(|_| ConnectionAdapterError::PreparationFailed)?
            .insert(descriptor.account_commitment(), descriptor);
        Ok(validated)
    }
    fn permits_scope(
        &self,
        descriptor: &ValidatedConnectionDescriptor,
        profile_scope: &CredentialScope,
    ) -> Result<(), ConnectionAdapterError> {
        let parsed = PostgresConnectionDescriptor::from_canonical_bytes(descriptor.bytes())?;
        if parsed.account_commitment() != *descriptor.account_commitment()
            || parsed
                .allowed_scopes()
                .binary_search_by(|value| value.as_str().cmp(profile_scope.as_str()))
                .is_err()
        {
            return Err(ConnectionAdapterError::ScopeDenied);
        }
        Ok(())
    }
    async fn lease_credential<S: ConnectionCredentialStore + Sync>(
        &self,
        binding: &ConnectionBinding,
        profile_scope: &CredentialScope,
        secret_store: &S,
        deadline: Instant,
    ) -> Result<ProviderCredentialLease, ConnectionAdapterError> {
        {
            let descriptors = self
                .descriptors
                .read()
                .map_err(|_| ConnectionAdapterError::PreparationFailed)?;
            let descriptor = descriptors
                .get(binding.account_commitment())
                .ok_or(ConnectionAdapterError::AccountSubstitution)?;
            if descriptor
                .allowed_scopes()
                .binary_search_by(|value| value.as_str().cmp(profile_scope.as_str()))
                .is_err()
            {
                return Err(ConnectionAdapterError::ScopeDenied);
            }
        }
        let stored = secret_store
            .lease_secret(binding, deadline)
            .await
            .map_err(|_| ConnectionAdapterError::CredentialUnavailable)?;
        let bytes = stored
            .expose(Instant::now())
            .map_err(|_| ConnectionAdapterError::CredentialUnavailable)?;
        ProviderCredentialLease::from_adapter(bytes.to_vec(), deadline)
    }
}
