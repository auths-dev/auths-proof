//! The connection record every gateway process sharing one store reads.
//!
//! The canonical `auths.provider-connection/2` bytes live in the shared
//! gateway store as record kind `connection`, keyed by the SHA-256 of
//! `auths.gateway-connection/1`, NUL, provider, NUL, alias. Every change is a
//! compare-and-swap on the exact stored bytes through the registry's own
//! transition functions, so the format and its rules stay
//! `auths-connections`'. Secrets never enter the shared store: each process
//! keeps its own local credential store and takes a secret into it only when
//! the secret's reference commitment matches the shared record.

use crate::{GatewayAttemptError, GatewayAttemptKey, GatewayAttemptStore, GatewayRecordEntry};
use auths_connections::{
    ConnectionAlias, ConnectionCredentialStore as _, ConnectionId, ConnectionRecord,
    ConnectionRecordError, ConnectionState, CredentialStoreError, PersistentCredentialStore,
    ProviderKind, SecretBytes,
};
use sha2::{Digest as _, Sha256};
use std::num::NonZeroU64;
use std::sync::Arc;
use thiserror::Error;

/// The hash domain of the connection record's key.
const KEY_DOMAIN: &[u8] = b"auths.gateway-connection/1\0";

/// Why the shared connection record could not be read or changed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum SharedConnectionError {
    /// A record already exists for this provider and alias.
    #[error("a connection record already exists")]
    Exists,
    /// Another process replaced the record first; nothing was changed.
    #[error("the connection record changed concurrently")]
    Conflict,
    /// The stored record is a retired format; the state must be recreated.
    #[error("the connection record is obsolete state")]
    Obsolete,
    /// The stored record is malformed or names another connection.
    #[error("the connection record is corrupt")]
    Corrupt,
    /// The store could not be reached.
    #[error("the connection store is unavailable")]
    Unavailable,
}

/// One loaded record with its exact stored bytes, the value every later
/// compare-and-swap and unchanged check uses.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedConnection {
    record: ConnectionRecord,
    bytes: Vec<u8>,
}

impl LoadedConnection {
    /// The decoded record.
    #[must_use]
    pub const fn record(&self) -> &ConnectionRecord {
        &self.record
    }

    /// Whether `other` holds exactly the same stored bytes.
    #[must_use]
    pub fn unchanged(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}

/// The key of the connection record of `provider` and `alias`.
#[must_use]
pub fn connection_key(provider: &ProviderKind, alias: &ConnectionAlias) -> GatewayAttemptKey {
    let mut hash = Sha256::new();
    hash.update(KEY_DOMAIN);
    hash.update(provider.as_str().as_bytes());
    hash.update([0]);
    hash.update(alias.as_str().as_bytes());
    GatewayAttemptKey::from_bytes(hash.finalize().into())
}

/// The shared connection record of one installed provider and alias.
#[derive(Clone)]
pub struct SharedConnection {
    store: Arc<dyn GatewayAttemptStore>,
    provider: ProviderKind,
    alias: ConnectionAlias,
    key: GatewayAttemptKey,
}

impl SharedConnection {
    /// Names the record of `provider` and `alias` in `store`.
    #[must_use]
    pub fn new(
        store: Arc<dyn GatewayAttemptStore>,
        provider: ProviderKind,
        alias: ConnectionAlias,
    ) -> Self {
        let key = connection_key(&provider, &alias);
        Self {
            store,
            provider,
            alias,
            key,
        }
    }

    /// The installed provider.
    #[must_use]
    pub const fn provider(&self) -> &ProviderKind {
        &self.provider
    }

    /// The installed alias.
    #[must_use]
    pub const fn alias(&self) -> &ConnectionAlias {
        &self.alias
    }

    /// Loads the record off the async executor. A committed change is
    /// visible to every later load in every process sharing the store.
    ///
    /// # Errors
    /// Unreadable, obsolete, or foreign state is an error, never absence.
    pub async fn load(&self) -> Result<Option<LoadedConnection>, SharedConnectionError> {
        let store = Arc::clone(&self.store);
        let key = self.key;
        let bytes =
            blocking(move || store.load(crate::GatewayRecordKind::Connection, &key)).await?;
        bytes.map(|bytes| self.decode(bytes)).transpose()
    }

    /// Inserts the first record; a record already present is never
    /// replaced.
    ///
    /// # Errors
    /// Returns [`SharedConnectionError::Exists`] when a record is present.
    pub async fn insert(
        &self,
        record: &ConnectionRecord,
    ) -> Result<LoadedConnection, SharedConnectionError> {
        let loaded = self.encode(record)?;
        let store = Arc::clone(&self.store);
        let entry = GatewayRecordEntry {
            kind: crate::GatewayRecordKind::Connection,
            key: self.key,
            record: loaded.bytes.clone(),
            expires_at: None,
        };
        match blocking(move || store.insert(&entry)).await {
            Ok(()) => Ok(loaded),
            Err(SharedConnectionError::Conflict) => Err(SharedConnectionError::Exists),
            Err(error) => Err(error),
        }
    }

    /// Replaces `current` with `next` only while the store still holds
    /// exactly `current`'s bytes.
    ///
    /// # Errors
    /// Returns [`SharedConnectionError::Conflict`] when another process
    /// changed the record first.
    pub async fn replace(
        &self,
        current: &LoadedConnection,
        next: &ConnectionRecord,
    ) -> Result<LoadedConnection, SharedConnectionError> {
        let loaded = self.encode(next)?;
        let store = Arc::clone(&self.store);
        let key = self.key;
        let before = current.bytes.clone();
        let after = loaded.bytes.clone();
        blocking(move || {
            store.replace(crate::GatewayRecordKind::Connection, &key, &before, &after)
        })
        .await?;
        Ok(loaded)
    }

    fn encode(&self, record: &ConnectionRecord) -> Result<LoadedConnection, SharedConnectionError> {
        if record.provider_kind() != &self.provider || record.alias() != &self.alias {
            return Err(SharedConnectionError::Corrupt);
        }
        let bytes = record
            .to_canonical_cbor()
            .map_err(|_| SharedConnectionError::Corrupt)?;
        Ok(LoadedConnection {
            record: record.clone(),
            bytes,
        })
    }

    fn decode(&self, bytes: Vec<u8>) -> Result<LoadedConnection, SharedConnectionError> {
        let record = match ConnectionRecord::from_canonical_cbor(&bytes) {
            Ok(record) => record,
            Err(ConnectionRecordError::ObsoleteSchema) => {
                return Err(SharedConnectionError::Obsolete);
            }
            Err(_) => return Err(SharedConnectionError::Corrupt),
        };
        if record.provider_kind() != &self.provider || record.alias() != &self.alias {
            return Err(SharedConnectionError::Corrupt);
        }
        Ok(LoadedConnection { record, bytes })
    }
}

/// Installs the first record of a connection: stores `secret` in this
/// process's credential store at generation 1, then inserts the record that
/// commits to it. A record already present is never replaced, and the
/// secret stored for the refused install is deleted.
///
/// `draft` supplies every field of the record except the credential
/// reference commitment, which only the local store can compute.
///
/// # Errors
/// Returns `gateway.install.connection-exists` when a record is present,
/// and a credential-store or connection-store code otherwise.
pub async fn install_connection(
    shared: &SharedConnection,
    credentials: &PersistentCredentialStore,
    draft: impl FnOnce([u8; 32]) -> Result<ConnectionRecord, &'static str>,
    connection_id: &ConnectionId,
    secret: SecretBytes,
) -> Result<ConnectionRecord, &'static str> {
    let first = NonZeroU64::MIN;
    let reference = credentials
        .install(connection_id, first, secret)
        .await
        .map_err(|_| "gateway.install.credential-store-unavailable")?;
    let inserted = match draft(*reference.as_bytes()) {
        Ok(record) if record.connection_id() == connection_id => {
            shared.insert(&record).await.map_err(|error| match error {
                SharedConnectionError::Exists => "gateway.install.connection-exists",
                _ => "gateway.install.connection-store-unavailable",
            })
        }
        Ok(_) => Err("gateway.install.connection-invalid"),
        Err(code) => Err(code),
    };
    match inserted {
        Ok(loaded) => Ok(loaded.record().clone()),
        Err(code) => {
            let _ = credentials.revoke_connection(connection_id);
            Err(code)
        }
    }
}

/// Joins a further process to an installed connection: loads the shared
/// record, runs every credential check the recipe declares against the
/// record's account commitment, and stores `candidate` at the record's
/// credential generation only when its reference commitment there equals
/// the record's, compared in constant time. Because the commitment is bound
/// to the credential generation rather than the current generation, a join
/// after any number of disables and enables succeeds with the installed or
/// rotated secret.
///
/// # Errors
/// Returns `gateway.install.join-record-missing` without a record,
/// `gateway.install.join-commitment-mismatch` for another secret, the
/// onboarding codes of a refused candidate, and store codes otherwise.
pub async fn join_connection(
    shared: &SharedConnection,
    credentials: &PersistentCredentialStore,
    recipe: &crate::CompiledRecipe,
    candidate: &zeroize::Zeroizing<Vec<u8>>,
) -> Result<ConnectionRecord, &'static str> {
    let loaded = match shared.load().await {
        Ok(Some(loaded)) => loaded,
        Ok(None) => return Err("gateway.install.join-record-missing"),
        Err(_) => return Err("gateway.install.connection-store-unavailable"),
    };
    let record = loaded.record();
    if record.state() == ConnectionState::Revoked {
        return Err("gateway.install.connection-revoked");
    }
    crate::GatewayConnectionDescriptor::from_record(record, recipe)
        .map_err(|_| "gateway.install.join-recipe-mismatch")?;
    crate::onboarding::check_candidate_credential(
        recipe,
        recipe.review().credential(),
        candidate,
        crate::onboarding::OnboardingAccount::Commitment(*record.account_commitment()),
    )
    .await
    .map_err(crate::onboarding::OnboardingFailure::install_code)?;
    let secret =
        SecretBytes::new(candidate.to_vec()).map_err(|_| "gateway.install.invalid-credential")?;
    match credentials.store_confirmed(
        record.connection_id(),
        record.credential_generation(),
        record.credential_reference_commitment(),
        secret,
    ) {
        Ok(_) => Ok(record.clone()),
        Err(CredentialStoreError::Substitution) => Err("gateway.install.join-commitment-mismatch"),
        Err(_) => Err("gateway.install.credential-store-unavailable"),
    }
}

/// Whether `record` authorizes a new entry for the gateway's workload and
/// profile: active, and listing both.
#[must_use]
pub fn authorizes_entry(
    record: &ConnectionRecord,
    workload_id: &str,
    profile: &auths_connections::ConnectionProfile,
) -> bool {
    record.state() == ConnectionState::Active
        && record
            .allowed_workloads()
            .iter()
            .any(|allowed| allowed == workload_id)
        && record.allowed_profiles().contains(profile)
}

async fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, GatewayAttemptError> + Send + 'static,
) -> Result<T, SharedConnectionError> {
    match tokio::task::spawn_blocking(operation).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(GatewayAttemptError::Conflict | GatewayAttemptError::Replay)) => {
            Err(SharedConnectionError::Conflict)
        }
        Ok(Err(GatewayAttemptError::Corrupt)) => Err(SharedConnectionError::Corrupt),
        Ok(Err(_)) | Err(_) => Err(SharedConnectionError::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_key_separates_provider_and_alias() {
        let key = |provider: &str, alias: &str| {
            connection_key(
                &ProviderKind::parse(provider).expect("provider"),
                &ConnectionAlias::parse(alias).expect("alias"),
            )
        };
        assert_ne!(key("ab", "c"), key("a", "bc"));
        assert_eq!(key("stripe", "refunds"), key("stripe", "refunds"));
        let mut hash = Sha256::new();
        hash.update(b"auths.gateway-connection/1\0stripe\0refunds");
        assert_eq!(
            key("stripe", "refunds").as_bytes(),
            &<[u8; 32]>::from(hash.finalize())
        );
    }
}
