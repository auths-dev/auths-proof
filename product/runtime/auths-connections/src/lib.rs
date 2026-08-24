//! Bounded provider-connection state shared by product profiles.
//!
//! This crate owns connection identity, authorization, generation pinning, and
//! opaque secret storage. It deliberately does not understand provider scopes,
//! refresh flows, provider commands, effects, reconciliation, or receipts.

#![forbid(unsafe_code)]

/// Build-time sentinel used by the production agent to reject accidental
/// linkage of its qualification-only credential broker surface.
#[doc(hidden)]
pub const __QUALIFICATION_BROKER_ENABLED: bool = cfg!(feature = "qualification-broker");

#[cfg(feature = "qualification-broker")]
mod qualification;
#[cfg(feature = "qualification-broker")]
pub use qualification::{
    QualificationCredentialLeaseRequest, QualificationProviderCallKind,
    QualificationProviderCallRequest, QualificationProviderCallResponse,
};

mod credential;
mod model;
mod registry;

pub use credential::{
    ConnectionCredentialStore, CredentialReferenceCommitment, CredentialStoreError,
    InMemoryCredentialStore, PersistentCredentialStore, SecretBytes, StoredSecretLease,
};
pub use model::{
    ConnectionAlias, ConnectionBinding, ConnectionId, ConnectionProfile, ConnectionRecord,
    ConnectionRecordError, ConnectionState, ProviderKind, SemanticId,
};
pub use registry::{ConnectionRegistry, ConnectionRegistryError, RegistryLimits};

use async_trait::async_trait;
use std::time::Instant;
use zeroize::Zeroize as _;

/// Provider-owned credential-scope identifier.
pub type CredentialScope = SemanticId;

/// Error returned by one statically registered provider adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ConnectionAdapterError {
    /// The opaque descriptor is malformed or does not identify the committed account.
    #[error("connection descriptor is invalid")]
    InvalidDescriptor,
    /// The profile's immutable credential scope is not permitted.
    #[error("connection does not permit the profile credential scope")]
    ScopeDenied,
    /// Credential material is absent, expired, revoked, or otherwise unavailable.
    #[error("provider credential is unavailable")]
    CredentialUnavailable,
    /// Provider account discovery did not match the sealed connection binding.
    #[error("provider account identity changed")]
    AccountSubstitution,
    /// Provider-specific refresh or credential preparation failed before effect entry.
    #[error("provider credential preparation failed")]
    PreparationFailed,
}

/// Sealed, provider-specific validation result.
///
/// Only a concrete adapter can construct this value. Shared code retains the
/// exact bounded descriptor bytes and account commitment without interpreting
/// their provider meaning.
pub struct ValidatedConnectionDescriptor {
    bytes: Vec<u8>,
    account_commitment: [u8; 32],
}

impl ValidatedConnectionDescriptor {
    /// Constructs a validated descriptor inside a provider adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::InvalidDescriptor`] for an empty or
    /// oversized descriptor.
    pub fn from_adapter(
        bytes: Vec<u8>,
        account_commitment: [u8; 32],
    ) -> Result<Self, ConnectionAdapterError> {
        if !(1..=65_536).contains(&bytes.len()) {
            return Err(ConnectionAdapterError::InvalidDescriptor);
        }
        Ok(Self {
            bytes,
            account_commitment,
        })
    }

    /// Returns the provider-owned canonical descriptor bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the account identity commitment proven by the adapter.
    #[must_use]
    pub const fn account_commitment(&self) -> &[u8; 32] {
        &self.account_commitment
    }
}

/// Provider-ready credential lease passed only to the concrete profile gateway.
pub struct ProviderCredentialLease {
    bytes: Vec<u8>,
    deadline: Instant,
}

impl ProviderCredentialLease {
    /// Constructs a provider-ready lease inside a provider adapter.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::CredentialUnavailable`] for an empty
    /// or oversized credential.
    pub fn from_adapter(
        mut bytes: Vec<u8>,
        deadline: Instant,
    ) -> Result<Self, ConnectionAdapterError> {
        if !(1..=65_536).contains(&bytes.len()) {
            bytes.zeroize();
            return Err(ConnectionAdapterError::CredentialUnavailable);
        }
        Ok(Self { bytes, deadline })
    }

    /// Borrows the credential while the lease remains live.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::CredentialUnavailable`] after expiry.
    pub fn expose(&self, now: Instant) -> Result<&[u8], ConnectionAdapterError> {
        if now > self.deadline {
            return Err(ConnectionAdapterError::CredentialUnavailable);
        }
        Ok(&self.bytes)
    }
}

impl std::fmt::Debug for ProviderCredentialLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProviderCredentialLease([REDACTED])")
    }
}

impl Drop for ProviderCredentialLease {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Static provider adapter boundary.
///
/// Implementations own descriptor meaning, account discovery, scope rules,
/// refresh, and provider revocation. They cannot receive provider commands or
/// build effect results through this interface.
#[async_trait]
pub trait ProviderConnectionAdapter: Send + Sync {
    /// Immutable provider kind selected by the build-time roster.
    fn provider_kind(&self) -> &'static str;

    /// Immutable provider connection contract identifier.
    fn contract_id(&self) -> &'static str;

    /// Immutable descriptor schema identifier.
    fn descriptor_schema(&self) -> &'static str;

    /// Parses provider-owned canonical descriptor bytes and proves the account commitment.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::InvalidDescriptor`] when the bytes do
    /// not satisfy the provider's closed descriptor contract.
    fn validate_descriptor(
        &self,
        bytes: &[u8],
    ) -> Result<ValidatedConnectionDescriptor, ConnectionAdapterError>;

    /// Checks the immutable profile credential scope against the validated descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectionAdapterError::ScopeDenied`] when the descriptor does
    /// not permit the exact profile scope.
    fn permits_scope(
        &self,
        descriptor: &ValidatedConnectionDescriptor,
        profile_scope: &CredentialScope,
    ) -> Result<(), ConnectionAdapterError>;

    /// Produces a provider-ready credential after all shared connection checks pass.
    async fn lease_credential<S: ConnectionCredentialStore + Sync>(
        &self,
        binding: &ConnectionBinding,
        profile_scope: &CredentialScope,
        secret_store: &S,
        deadline: Instant,
    ) -> Result<ProviderCredentialLease, ConnectionAdapterError>;
}
