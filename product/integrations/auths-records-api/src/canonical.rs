//! Canonical encoding and commitment helpers.

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::RecordsError;

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, RecordsError> {
    serde_json_canonicalizer::to_vec(value).map_err(|_| RecordsError::Canonicalization)
}

pub fn canonical_digest<T: Serialize>(value: &T) -> Result<String, RecordsError> {
    Ok(sha256(&canonical_json(value)?))
}

#[must_use]
pub fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], RecordsError> {
    let bytes = hex::decode(value).map_err(|_| RecordsError::Malformed)?;
    bytes.try_into().map_err(|_| RecordsError::Malformed)
}
