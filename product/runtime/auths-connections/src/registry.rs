use crate::{
    ConnectionAlias, ConnectionBinding, ConnectionProfile, ConnectionRecord, ConnectionState,
    ProviderKind,
};
use std::{
    collections::BTreeMap,
    num::{NonZeroU64, NonZeroUsize},
    sync::RwLock,
};
use thiserror::Error;

/// Fixed connection-registry admission limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegistryLimits {
    /// Maximum live and tombstoned connection records.
    pub maximum_records: NonZeroUsize,
    /// Maximum aggregate canonical-record bytes.
    pub maximum_encoded_bytes: NonZeroUsize,
}

impl Default for RegistryLimits {
    fn default() -> Self {
        Self {
            maximum_records: NonZeroUsize::new(10_000).expect("nonzero constant"),
            maximum_encoded_bytes: NonZeroUsize::new(268_435_456).expect("nonzero constant"),
        }
    }
}

type RecordKey = (ProviderKind, ConnectionAlias);
type DefaultKey = (String, ProviderKind);

struct RegistryState {
    records: BTreeMap<RecordKey, ConnectionRecord>,
    defaults: BTreeMap<DefaultKey, ConnectionAlias>,
    encoded_bytes: usize,
}

/// Thread-safe bounded provider-connection registry.
pub struct ConnectionRegistry {
    state: RwLock<RegistryState>,
    limits: RegistryLimits,
}

impl ConnectionRegistry {
    /// Creates an empty registry with fixed limits.
    #[must_use]
    pub fn new(limits: RegistryLimits) -> Self {
        Self {
            state: RwLock::new(RegistryState {
                records: BTreeMap::new(),
                defaults: BTreeMap::new(),
                encoded_bytes: 0,
            }),
            limits,
        }
    }

    /// Inserts a new unique provider/alias record before credential installation.
    ///
    /// # Errors
    ///
    /// Returns conflict or capacity errors without mutating existing state.
    pub fn insert(&self, record: ConnectionRecord) -> Result<(), ConnectionRegistryError> {
        let encoded_bytes = record
            .to_canonical_cbor()
            .map_err(|_| ConnectionRegistryError::InvalidRecord)?
            .len();
        let key = (record.provider_kind().clone(), record.alias().clone());
        let mut state = self
            .state
            .write()
            .map_err(|_| ConnectionRegistryError::Unavailable)?;
        if state.records.contains_key(&key) {
            return Err(ConnectionRegistryError::Conflict);
        }
        if state.records.len() >= self.limits.maximum_records.get()
            || state
                .encoded_bytes
                .checked_add(encoded_bytes)
                .is_none_or(|value| value > self.limits.maximum_encoded_bytes.get())
        {
            return Err(ConnectionRegistryError::Capacity);
        }
        state.encoded_bytes += encoded_bytes;
        state.records.insert(key, record);
        Ok(())
    }

    /// Assigns one default connection for an authenticated workload/provider pair.
    ///
    /// # Errors
    ///
    /// Returns unavailable when the record is absent, inactive, or does not
    /// authorize the workload. These cases intentionally share one error.
    pub fn set_default(
        &self,
        workload_id: &str,
        provider: &ProviderKind,
        alias: &ConnectionAlias,
    ) -> Result<(), ConnectionRegistryError> {
        validate_workload_id(workload_id)?;
        let mut state = self
            .state
            .write()
            .map_err(|_| ConnectionRegistryError::Unavailable)?;
        let record = state
            .records
            .get(&(provider.clone(), alias.clone()))
            .ok_or(ConnectionRegistryError::Unavailable)?;
        if record.state() != ConnectionState::Active
            || record
                .allowed_workloads()
                .binary_search_by(|candidate| candidate.as_str().cmp(workload_id))
                .is_err()
        {
            return Err(ConnectionRegistryError::Unavailable);
        }
        state
            .defaults
            .insert((workload_id.to_owned(), provider.clone()), alias.clone());
        Ok(())
    }

    /// Resolves and authorizes an explicit alias or authenticated-workload default.
    ///
    /// # Errors
    ///
    /// Missing, unauthorized, disabled, revoked, and unconfigured-default cases
    /// intentionally collapse to [`ConnectionRegistryError::Unavailable`].
    pub fn resolve(
        &self,
        provider: &ProviderKind,
        selected_alias: Option<&ConnectionAlias>,
        workload_id: &str,
        profile: &ConnectionProfile,
    ) -> Result<ConnectionBinding, ConnectionRegistryError> {
        validate_workload_id(workload_id)?;
        let state = self
            .state
            .read()
            .map_err(|_| ConnectionRegistryError::Unavailable)?;
        let alias = match selected_alias {
            Some(alias) => alias,
            None => state
                .defaults
                .get(&(workload_id.to_owned(), provider.clone()))
                .ok_or(ConnectionRegistryError::Unavailable)?,
        };
        let record = state
            .records
            .get(&(provider.clone(), alias.clone()))
            .ok_or(ConnectionRegistryError::Unavailable)?;
        authorize(record, workload_id, profile)?;
        Ok(binding(record))
    }

    /// Rereads all security-critical connection facts immediately before leasing.
    ///
    /// # Errors
    ///
    /// Returns unavailable when state or authorization changed, and substitution
    /// when an identity, generation, or commitment differs from the sealed binding.
    pub fn reread_before_lease(
        &self,
        binding: &ConnectionBinding,
        workload_id: &str,
        profile: &ConnectionProfile,
    ) -> Result<ConnectionRecord, ConnectionRegistryError> {
        validate_workload_id(workload_id)?;
        let state = self
            .state
            .read()
            .map_err(|_| ConnectionRegistryError::Unavailable)?;
        let record = state
            .records
            .get(&(binding.provider_kind().clone(), binding.alias().clone()))
            .ok_or(ConnectionRegistryError::Unavailable)?;
        authorize(record, workload_id, profile)?;
        if record.connection_id() != binding.connection_id()
            || record.contract() != binding.contract()
            || record.descriptor_schema() != binding.descriptor_schema()
            || record.generation() != binding.generation()
            || record.descriptor_commitment() != binding.descriptor_commitment()
            || record.account_commitment() != binding.account_commitment()
        {
            return Err(ConnectionRegistryError::Substitution);
        }
        Ok(record.clone())
    }

    /// Replaces one record only at its expected generation.
    ///
    /// # Errors
    ///
    /// Fails atomically on generation, identity, capacity, or validation conflict.
    pub fn replace(
        &self,
        expected_generation: NonZeroU64,
        replacement: ConnectionRecord,
    ) -> Result<(), ConnectionRegistryError> {
        let key = (
            replacement.provider_kind().clone(),
            replacement.alias().clone(),
        );
        let new_bytes = replacement
            .to_canonical_cbor()
            .map_err(|_| ConnectionRegistryError::InvalidRecord)?
            .len();
        let mut state = self
            .state
            .write()
            .map_err(|_| ConnectionRegistryError::Unavailable)?;
        let current = state
            .records
            .get(&key)
            .ok_or(ConnectionRegistryError::Unavailable)?;
        if current.generation() != expected_generation
            || replacement.connection_id() != current.connection_id()
            || replacement.created_at_unix_seconds() != current.created_at_unix_seconds()
            || replacement.generation().get()
                != expected_generation
                    .get()
                    .checked_add(1)
                    .ok_or(ConnectionRegistryError::Conflict)?
        {
            return Err(ConnectionRegistryError::Conflict);
        }
        let old_bytes = current
            .to_canonical_cbor()
            .map_err(|_| ConnectionRegistryError::InvalidRecord)?
            .len();
        let projected = state
            .encoded_bytes
            .checked_sub(old_bytes)
            .and_then(|value| value.checked_add(new_bytes))
            .ok_or(ConnectionRegistryError::Capacity)?;
        if projected > self.limits.maximum_encoded_bytes.get() {
            return Err(ConnectionRegistryError::Capacity);
        }
        state.records.insert(key, replacement);
        state.encoded_bytes = projected;
        Ok(())
    }

    /// Returns the number of live and tombstoned records.
    ///
    /// # Errors
    ///
    /// Returns unavailable if registry synchronization was poisoned.
    pub fn len(&self) -> Result<usize, ConnectionRegistryError> {
        self.state
            .read()
            .map(|state| state.records.len())
            .map_err(|_| ConnectionRegistryError::Unavailable)
    }

    /// Reports whether the registry is empty.
    ///
    /// # Errors
    ///
    /// Returns unavailable if registry synchronization was poisoned.
    pub fn is_empty(&self) -> Result<bool, ConnectionRegistryError> {
        self.len().map(|length| length == 0)
    }
}

/// Closed registry failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum ConnectionRegistryError {
    /// Record failed canonical validation.
    #[error("invalid connection record")]
    InvalidRecord,
    /// Authenticated lookup is absent, unauthorized, disabled, or revoked.
    #[error("connection unavailable")]
    Unavailable,
    /// Expected generation or immutable identity conflicted.
    #[error("connection state conflict")]
    Conflict,
    /// A sealed connection identity or commitment changed.
    #[error("connection substitution detected")]
    Substitution,
    /// Fixed registry capacity is exhausted.
    #[error("connection registry capacity exhausted")]
    Capacity,
    /// Workload identity is invalid before lookup.
    #[error("invalid workload identity")]
    InvalidWorkload,
}

fn validate_workload_id(value: &str) -> Result<(), ConnectionRegistryError> {
    if !(1..=128).contains(&value.len())
        || !value.is_ascii()
        || !value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
    {
        return Err(ConnectionRegistryError::InvalidWorkload);
    }
    Ok(())
}

fn authorize(
    record: &ConnectionRecord,
    workload_id: &str,
    profile: &ConnectionProfile,
) -> Result<(), ConnectionRegistryError> {
    if record.state() != ConnectionState::Active
        || record
            .allowed_workloads()
            .binary_search_by(|candidate| candidate.as_str().cmp(workload_id))
            .is_err()
        || record.allowed_profiles().binary_search(profile).is_err()
    {
        return Err(ConnectionRegistryError::Unavailable);
    }
    Ok(())
}

fn binding(record: &ConnectionRecord) -> ConnectionBinding {
    ConnectionBinding {
        provider_kind: record.provider_kind().clone(),
        alias: record.alias().clone(),
        connection_id: record.connection_id().clone(),
        contract: record.contract().clone(),
        descriptor_schema: record.descriptor_schema().clone(),
        descriptor: record.descriptor().to_vec(),
        generation: record.generation(),
        descriptor_commitment: *record.descriptor_commitment(),
        account_commitment: *record.account_commitment(),
        credential_reference_commitment: *record.credential_reference_commitment(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::tests::record;

    fn profile() -> ConnectionProfile {
        ConnectionProfile::new(crate::SemanticId::parse("auths.stripe.refund").unwrap(), 1).unwrap()
    }

    #[test]
    fn explicit_and_default_resolution_return_same_sealed_identity() {
        let registry = ConnectionRegistry::new(RegistryLimits::default());
        let record = record();
        registry.insert(record.clone()).unwrap();
        registry
            .set_default("workload-a", record.provider_kind(), record.alias())
            .unwrap();
        let explicit = registry
            .resolve(
                record.provider_kind(),
                Some(record.alias()),
                "workload-a",
                &profile(),
            )
            .unwrap();
        let default = registry
            .resolve(record.provider_kind(), None, "workload-a", &profile())
            .unwrap();
        assert_eq!(explicit, default);
    }

    #[test]
    fn missing_and_unauthorized_are_indistinguishable() {
        let registry = ConnectionRegistry::new(RegistryLimits::default());
        let record = record();
        registry.insert(record.clone()).unwrap();
        let unknown = ConnectionAlias::parse("missing").unwrap();
        assert_eq!(
            registry
                .resolve(
                    record.provider_kind(),
                    Some(&unknown),
                    "workload-a",
                    &profile()
                )
                .unwrap_err(),
            ConnectionRegistryError::Unavailable
        );
        assert_eq!(
            registry
                .resolve(
                    record.provider_kind(),
                    Some(record.alias()),
                    "workload-b",
                    &profile()
                )
                .unwrap_err(),
            ConnectionRegistryError::Unavailable
        );
    }

    #[test]
    fn capacity_refuses_before_mutation() {
        let registry = ConnectionRegistry::new(RegistryLimits {
            maximum_records: NonZeroUsize::new(1).unwrap(),
            maximum_encoded_bytes: NonZeroUsize::new(262_144).unwrap(),
        });
        let first = record();
        registry.insert(first.clone()).unwrap();
        let second = ConnectionRecord::new(
            first.provider_kind().clone(),
            ConnectionAlias::parse("other").unwrap(),
            first.connection_id().clone(),
            first.contract().clone(),
            first.descriptor_schema().clone(),
            first.descriptor().to_vec(),
            *first.account_commitment(),
            *first.credential_reference_commitment(),
            first.generation(),
            first.state(),
            first.allowed_workloads().to_vec(),
            first.allowed_profiles().to_vec(),
            first.created_at_unix_seconds(),
            first.updated_at_unix_seconds(),
            first.revoked_at_unix_seconds(),
        )
        .unwrap();
        assert_eq!(
            registry.insert(second).unwrap_err(),
            ConnectionRegistryError::Capacity
        );
        assert_eq!(registry.len().unwrap(), 1);
    }
}
