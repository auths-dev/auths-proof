//! Opaque gateway records in the qualified lifecycle database.
//!
//! This is a mechanism only: all-or-none insert-once batches, a
//! compare-and-swap replacement, and a bounded sweep of expired slots, over
//! bounded bytes tagged with one of four closed record kinds. The gateway
//! owns every record format, its stages, and which replacements are valid.

use crate::lifecycle::{PostgresLifecycleStore, map_postgres_error};
use auths_lifecycle::StoreError;
use postgres::IsolationLevel;
use sha2::{Digest as _, Sha256};

/// Largest gateway record the schema accepts.
pub const MAX_GATEWAY_RECORD_BYTES: usize = 262_144;

/// Largest number of records one batch may insert.
pub const MAX_GATEWAY_BATCH_ENTRIES: usize = 64;

/// The closed record kinds of the gateway store.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum GatewayRecordKind {
    /// One logical operation's attempt record; never collected.
    Attempt,
    /// One slot of a per-window count; expires.
    CountSlot,
    /// One slot of a per-window sum; expires.
    SumSlot,
    /// The shared connection record.
    Connection,
}

impl GatewayRecordKind {
    /// The stable spelling stored with each row.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Attempt => "attempt",
            Self::CountSlot => "count-slot",
            Self::SumSlot => "sum-slot",
            Self::Connection => "connection",
        }
    }

    /// Parses a stored spelling.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "attempt" => Some(Self::Attempt),
            "count-slot" => Some(Self::CountSlot),
            "sum-slot" => Some(Self::SumSlot),
            "connection" => Some(Self::Connection),
            _ => None,
        }
    }

    /// Whether records of this kind carry an expiry and may be swept.
    #[must_use]
    pub const fn expires(self) -> bool {
        matches!(self, Self::CountSlot | Self::SumSlot)
    }
}

/// One record to insert.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayRecordEntry {
    /// The record kind.
    pub kind: GatewayRecordKind,
    /// The record key.
    pub key: [u8; 32],
    /// The opaque record bytes.
    pub record: Vec<u8>,
    /// Gateway-clock seconds after which a slot may be swept; present
    /// exactly for slot kinds.
    pub expires_at: Option<u64>,
}

impl GatewayRecordEntry {
    /// Checks the bounds every store applies before touching storage.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LimitExceeded`] for empty or oversized bytes or
    /// an expiry that the database cannot hold, and [`StoreError::Corrupt`]
    /// when the expiry's presence disagrees with the kind.
    pub fn validate(&self) -> Result<(), StoreError> {
        bounded(&self.record)?;
        if self.kind.expires() != self.expires_at.is_some() {
            return Err(StoreError::Corrupt);
        }
        if let Some(expires_at) = self.expires_at {
            i64::try_from(expires_at).map_err(|_| StoreError::LimitExceeded)?;
        }
        Ok(())
    }
}

/// Checks a batch: 1 to [`MAX_GATEWAY_BATCH_ENTRIES`] valid entries with
/// distinct keys.
///
/// # Errors
///
/// Returns the first entry's bound failure, [`StoreError::LimitExceeded`] for
/// an empty or oversized batch, and [`StoreError::Corrupt`] for a repeated key.
pub fn validate_gateway_batch(entries: &[GatewayRecordEntry]) -> Result<(), StoreError> {
    if entries.is_empty() || entries.len() > MAX_GATEWAY_BATCH_ENTRIES {
        return Err(StoreError::LimitExceeded);
    }
    let mut keys = Vec::with_capacity(entries.len());
    for entry in entries {
        entry.validate()?;
        keys.push(entry.key);
    }
    keys.sort_unstable();
    if keys.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(StoreError::Corrupt);
    }
    Ok(())
}

/// Result of an all-or-none batch insert.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayRecordInsert {
    /// Every entry was inserted by this call; no other caller can.
    Inserted,
    /// The entry at `index` already existed, so nothing was inserted.
    Exists {
        /// The index, in the caller's order, of an entry whose key existed.
        index: usize,
    },
}

impl PostgresLifecycleStore {
    /// Inserts every entry, or none when any key already exists. Rows are
    /// inserted in ascending key order inside one transaction, so two
    /// concurrent batches cannot deadlock.
    ///
    /// # Errors
    ///
    /// Returns a bound failure before any database call, and a closed store
    /// error when the database is unavailable.
    pub fn insert_gateway_records(
        &self,
        entries: &[GatewayRecordEntry],
    ) -> Result<GatewayRecordInsert, StoreError> {
        validate_gateway_batch(entries)?;
        let mut order: Vec<usize> = (0..entries.len()).collect();
        order.sort_unstable_by_key(|index| entries[*index].key);
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let mut sql = client
            .build_transaction()
            .isolation_level(IsolationLevel::ReadCommitted)
            .start()
            .map_err(|error| map_postgres_error(&error))?;
        for index in order {
            let entry = &entries[index];
            let digest: [u8; 32] = Sha256::digest(&entry.record).into();
            let expires_at = entry
                .expires_at
                .map(i64::try_from)
                .transpose()
                .map_err(|_| StoreError::LimitExceeded)?;
            let inserted = sql
                .query_opt(
                    "INSERT INTO auths_gateway_records
                         (record_key, record_kind, expires_at, record_bytes, record_sha256)
                     VALUES ($1, $2, $3, $4, $5)
                     ON CONFLICT (record_key) DO NOTHING
                     RETURNING record_key",
                    &[
                        &&entry.key[..],
                        &entry.kind.as_str(),
                        &expires_at,
                        &entry.record,
                        &&digest[..],
                    ],
                )
                .map_err(|error| map_postgres_error(&error))?;
            if inserted.is_none() {
                sql.rollback().map_err(|error| map_postgres_error(&error))?;
                return Ok(GatewayRecordInsert::Exists { index });
            }
        }
        sql.commit().map_err(|error| map_postgres_error(&error))?;
        Ok(GatewayRecordInsert::Inserted)
    }

    /// Loads the digest-checked record of `kind` stored under `key`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when the row's bytes and digest
    /// differ, exceed the schema bound, or belong to another kind.
    pub fn load_gateway_record(
        &self,
        kind: GatewayRecordKind,
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let row = client
            .query_opt(
                "SELECT record_kind, record_bytes, record_sha256
                 FROM auths_gateway_records
                 WHERE record_key = $1",
                &[&&key[..]],
            )
            .map_err(|error| map_postgres_error(&error))?;
        row.map(|row| {
            let stored: String = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
            let record: Vec<u8> = row.try_get(1).map_err(|_| StoreError::Corrupt)?;
            let digest: Vec<u8> = row.try_get(2).map_err(|_| StoreError::Corrupt)?;
            if GatewayRecordKind::parse(&stored) != Some(kind)
                || bounded(&record).is_err()
                || Sha256::digest(&record).as_slice() != digest
            {
                return Err(StoreError::Corrupt);
            }
            Ok(record)
        })
        .transpose()
    }

    /// Replaces the record of `kind` under `key` with `next` only while it
    /// still holds exactly `current`. Slots are insert-only.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] when another writer replaced the row
    /// first or the row is absent, [`StoreError::Corrupt`] for a slot kind,
    /// and [`StoreError::LimitExceeded`] for empty or oversized bytes.
    pub fn replace_gateway_record(
        &self,
        kind: GatewayRecordKind,
        key: &[u8; 32],
        current: &[u8],
        next: &[u8],
    ) -> Result<(), StoreError> {
        if kind.expires() {
            return Err(StoreError::Corrupt);
        }
        bounded(current)?;
        bounded(next)?;
        let current_digest: [u8; 32] = Sha256::digest(current).into();
        let next_digest: [u8; 32] = Sha256::digest(next).into();
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let replaced = client
            .execute(
                "UPDATE auths_gateway_records
                 SET record_bytes = $4, record_sha256 = $5
                 WHERE record_key = $1 AND record_kind = $2 AND record_sha256 = $3",
                &[
                    &&key[..],
                    &kind.as_str(),
                    &&current_digest[..],
                    &next,
                    &&next_digest[..],
                ],
            )
            .map_err(|error| map_postgres_error(&error))?;
        if replaced == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }

    /// Deletes at most `limit` slots whose expiry is at or before `now`,
    /// through the expiry index, and returns how many were deleted. Attempts
    /// and connection records are never swept.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LimitExceeded`] for a time or limit the database
    /// cannot hold, and a closed store error when it is unavailable.
    pub fn sweep_expired_gateway_records(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<usize, StoreError> {
        let now = i64::try_from(now).map_err(|_| StoreError::LimitExceeded)?;
        let limit = i64::try_from(limit).map_err(|_| StoreError::LimitExceeded)?;
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let deleted = client
            .execute(
                "DELETE FROM auths_gateway_records
                 WHERE record_key IN (
                     SELECT record_key FROM auths_gateway_records
                     WHERE record_kind IN ('count-slot', 'sum-slot') AND expires_at <= $1
                     ORDER BY expires_at
                     LIMIT $2
                 )",
                &[&now, &limit],
            )
            .map_err(|error| map_postgres_error(&error))?;
        usize::try_from(deleted).map_err(|_| StoreError::Corrupt)
    }
}

const fn bounded(record: &[u8]) -> Result<(), StoreError> {
    if record.is_empty() || record.len() > MAX_GATEWAY_RECORD_BYTES {
        Err(StoreError::LimitExceeded)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(kind: GatewayRecordKind, key: u8, expires_at: Option<u64>) -> GatewayRecordEntry {
        GatewayRecordEntry {
            kind,
            key: [key; 32],
            record: vec![1],
            expires_at,
        }
    }

    #[test]
    fn gateway_records_are_bounded_before_any_database_call() {
        assert_eq!(bounded(&[]), Err(StoreError::LimitExceeded));
        assert_eq!(bounded(&[0; 1]), Ok(()));
        assert_eq!(bounded(&vec![0; MAX_GATEWAY_RECORD_BYTES]), Ok(()));
        assert_eq!(
            bounded(&vec![0; MAX_GATEWAY_RECORD_BYTES + 1]),
            Err(StoreError::LimitExceeded)
        );
        let schema = include_str!("../migrations/postgres_lifecycle_v5.sql");
        assert!(
            schema.contains("octet_length(record_bytes) BETWEEN 1 AND 262144"),
            "the schema bound and the Rust bound are the same"
        );
        for kind in ["attempt", "count-slot", "sum-slot", "connection"] {
            assert_eq!(
                GatewayRecordKind::parse(kind).map(GatewayRecordKind::as_str),
                Some(kind)
            );
            assert!(schema.contains(&format!("'{kind}'")));
        }
        assert!(!schema.contains("auths_gateway_attempts"));
    }

    #[test]
    fn expiry_is_present_exactly_for_slots_and_keys_are_distinct() {
        assert_eq!(
            entry(GatewayRecordKind::Attempt, 1, None).validate(),
            Ok(())
        );
        assert_eq!(
            entry(GatewayRecordKind::CountSlot, 1, Some(9)).validate(),
            Ok(())
        );
        assert_eq!(
            entry(GatewayRecordKind::Attempt, 1, Some(9)).validate(),
            Err(StoreError::Corrupt)
        );
        assert_eq!(
            entry(GatewayRecordKind::SumSlot, 1, None).validate(),
            Err(StoreError::Corrupt)
        );
        assert_eq!(
            entry(GatewayRecordKind::SumSlot, 1, Some(u64::MAX)).validate(),
            Err(StoreError::LimitExceeded)
        );
        assert_eq!(
            validate_gateway_batch(&[
                entry(GatewayRecordKind::Attempt, 1, None),
                entry(GatewayRecordKind::CountSlot, 1, Some(9)),
            ]),
            Err(StoreError::Corrupt)
        );
        assert_eq!(validate_gateway_batch(&[]), Err(StoreError::LimitExceeded));
    }
}
