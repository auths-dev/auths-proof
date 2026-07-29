//! Canonical JSON and digest helpers for Kubernetes profile objects.

#![allow(
    clippy::missing_errors_doc,
    reason = "both helpers return the closed CanonicalError documented in this module"
)]

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::types::DigestHex;

/// Canonicalization failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CanonicalError {
    /// A value could not be represented as canonical JSON.
    #[error("Kubernetes profile canonicalization failed")]
    Serialize,
}

/// Encodes RFC 8785-style canonical JSON.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| CanonicalError::Serialize)
}

/// Digests one canonical serializable value.
pub fn canonical_digest<T: Serialize>(value: &T) -> Result<DigestHex, CanonicalError> {
    Ok(sha256(&canonical_json(value)?))
}

/// Digests exact bytes.
#[must_use]
pub fn sha256(bytes: &[u8]) -> DigestHex {
    DigestHex::from_digest_bytes(Sha256::digest(bytes).into())
}
