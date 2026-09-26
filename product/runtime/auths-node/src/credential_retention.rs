//! Deletion of superseded provider-connection credentials.
//!
//! The credential store keeps every rotated-away generation until something
//! decides it is no longer needed. Only the operation journal knows which
//! operations are unresolved, so the agent makes that decision here and the
//! store merely executes it.

use auths_connections::{
    ConnectionAlias, ConnectionState, CredentialStoreError, PersistentCredentialStore, ProviderKind,
};
use auths_stores::{
    OperationJournalError, PersistentConnectionStore, PersistentConnectionStoreError,
    PersistentOperationJournal,
};
use std::num::NonZeroU64;

/// Failure of one retention pass. A deletion is acknowledged only once the
/// credential store has persisted all of it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum CredentialRetentionError {
    /// The connection record could not be read.
    #[error("connection record unavailable")]
    Connections(PersistentConnectionStoreError),
    /// Unresolved operations could not be enumerated.
    #[error("operation journal unavailable")]
    Journal(OperationJournalError),
    /// The credential store could not be read or the deletion persisted.
    #[error("credential store unavailable")]
    Credentials(CredentialStoreError),
}

/// Deletes each stored credential generation of one connection that neither
/// its current record nor any unresolved operation still needs.
///
/// A revoked connection is left alone: revocation deletes every generation
/// itself. A generation newer than the current record's is never deleted,
/// because a concurrent rotation may be publishing it.
pub(crate) fn prune_superseded_credentials(
    journal: &PersistentOperationJournal,
    connections: &PersistentConnectionStore,
    credentials: &PersistentCredentialStore,
    provider: &ProviderKind,
    alias: &ConnectionAlias,
) -> Result<(), CredentialRetentionError> {
    let Some(record) = connections
        .load(provider, alias)
        .map_err(CredentialRetentionError::Connections)?
    else {
        return Ok(());
    };
    if record.state() == ConnectionState::Revoked
        || credentials
            .stored_generations(record.connection_id())
            .map_err(CredentialRetentionError::Credentials)?
            .len()
            < 2
    {
        return Ok(());
    }
    let mut needed = journal
        .unresolved_connection_generations(record.connection_id().as_str())
        .map_err(CredentialRetentionError::Journal)?
        .into_iter()
        .filter_map(NonZeroU64::new)
        .collect::<Vec<_>>();
    needed.push(record.generation());
    credentials
        .retain_generations(record.connection_id(), &needed)
        .map_err(CredentialRetentionError::Credentials)
}
