//! Canonical JSON and commitment helpers.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{errors::CanonicalError, types::DigestHex};

/// Serializes one value with RFC 8785 JSON canonicalization.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError::Serialize)
}

/// Computes a canonical SHA-256 commitment.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<DigestHex, CanonicalError> {
    Ok(sha256(&canonical_json(value)?))
}

/// Computes a lowercase SHA-256 commitment over exact bytes.
#[must_use]
pub fn sha256(bytes: &[u8]) -> DigestHex {
    DigestHex::from_digest_bytes(Sha256::digest(bytes).into())
}
