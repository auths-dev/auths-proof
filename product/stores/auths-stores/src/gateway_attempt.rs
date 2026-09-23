//! Opaque one-use gateway attempt rows in the qualified lifecycle database.
//!
//! This is a mechanism only: an insert-once claim and a compare-and-swap
//! replacement over bounded canonical bytes. The gateway owns the record
//! format, its stages, and which replacements are valid.

use crate::lifecycle::{PostgresLifecycleStore, map_postgres_error};
use auths_lifecycle::StoreError;
use sha2::{Digest as _, Sha256};

/// Largest gateway attempt record the schema accepts.
pub const MAX_GATEWAY_ATTEMPT_BYTES: usize = 131_072;

/// Result of inserting a new gateway attempt row.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayAttemptInsert {
    /// This call created the row; no other caller can.
    Inserted,
    /// A row for the key already existed and was left unchanged.
    Exists,
}

impl PostgresLifecycleStore {
    /// Inserts `record` under `key` only when no row exists for `key`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::LimitExceeded`] for empty or oversized bytes and
    /// a closed store error when the database is unavailable.
    pub fn insert_gateway_attempt(
        &self,
        key: &[u8; 32],
        record: &[u8],
    ) -> Result<GatewayAttemptInsert, StoreError> {
        bounded(record)?;
        let digest: [u8; 32] = Sha256::digest(record).into();
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let inserted = client
            .execute(
                "INSERT INTO auths_gateway_attempts (attempt_key, record_bytes, record_sha256)
                 VALUES ($1, $2, $3)
                 ON CONFLICT (attempt_key) DO NOTHING",
                &[&&key[..], &record, &&digest[..]],
            )
            .map_err(|error| map_postgres_error(&error))?;
        Ok(match inserted {
            1 => GatewayAttemptInsert::Inserted,
            0 => GatewayAttemptInsert::Exists,
            _ => return Err(StoreError::Corrupt),
        })
    }

    /// Loads the digest-checked record stored under `key`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Corrupt`] when the row's bytes and digest differ
    /// or exceed the schema bound.
    pub fn load_gateway_attempt(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, StoreError> {
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let row = client
            .query_opt(
                "SELECT record_bytes, record_sha256
                 FROM auths_gateway_attempts
                 WHERE attempt_key = $1",
                &[&&key[..]],
            )
            .map_err(|error| map_postgres_error(&error))?;
        row.map(|row| {
            let record: Vec<u8> = row.try_get(0).map_err(|_| StoreError::Corrupt)?;
            let digest: Vec<u8> = row.try_get(1).map_err(|_| StoreError::Corrupt)?;
            if bounded(&record).is_err() || Sha256::digest(&record).as_slice() != digest {
                return Err(StoreError::Corrupt);
            }
            Ok(record)
        })
        .transpose()
    }

    /// Replaces the row under `key` with `next` only while it still holds
    /// exactly `current`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Conflict`] when another writer replaced the row
    /// first or the row is absent, and [`StoreError::LimitExceeded`] for
    /// empty or oversized bytes.
    pub fn replace_gateway_attempt(
        &self,
        key: &[u8; 32],
        current: &[u8],
        next: &[u8],
    ) -> Result<(), StoreError> {
        bounded(current)?;
        bounded(next)?;
        let current_digest: [u8; 32] = Sha256::digest(current).into();
        let next_digest: [u8; 32] = Sha256::digest(next).into();
        let mut client = self.pool.get().map_err(|_| StoreError::PoolExhausted)?;
        let replaced = client
            .execute(
                "UPDATE auths_gateway_attempts
                 SET record_bytes = $3, record_sha256 = $4
                 WHERE attempt_key = $1 AND record_sha256 = $2",
                &[&&key[..], &&current_digest[..], &next, &&next_digest[..]],
            )
            .map_err(|error| map_postgres_error(&error))?;
        if replaced == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }
}

const fn bounded(record: &[u8]) -> Result<(), StoreError> {
    if record.is_empty() || record.len() > MAX_GATEWAY_ATTEMPT_BYTES {
        Err(StoreError::LimitExceeded)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_attempt_records_are_bounded_before_any_database_call() {
        assert_eq!(bounded(&[]), Err(StoreError::LimitExceeded));
        assert_eq!(bounded(&[0; 1]), Ok(()));
        assert_eq!(bounded(&vec![0; MAX_GATEWAY_ATTEMPT_BYTES]), Ok(()));
        assert_eq!(
            bounded(&vec![0; MAX_GATEWAY_ATTEMPT_BYTES + 1]),
            Err(StoreError::LimitExceeded)
        );
        assert!(
            include_str!("../migrations/postgres_lifecycle_v4.sql")
                .contains("octet_length(record_bytes) BETWEEN 1 AND 131072"),
            "the schema bound and the Rust bound are the same"
        );
    }
}
