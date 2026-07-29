//! Canonical encoding and commitment helpers.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::schema::{DigestHex, ValidationError};

/// Serializes a value using RFC 8785 canonical JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, ValidationError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| ValidationError::Canonicalization)
}

/// Computes the canonical SHA-256 commitment for a value.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<DigestHex, ValidationError> {
    Ok(sha256(&canonical_json(value)?))
}

/// Computes lowercase SHA-256 over exact bytes.
#[must_use]
pub fn sha256(bytes: &[u8]) -> DigestHex {
    DigestHex::from_bytes(Sha256::digest(bytes).into())
}
