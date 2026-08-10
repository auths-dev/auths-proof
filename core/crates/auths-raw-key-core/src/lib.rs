//! Canonical versioned raw-key descriptors and self-certifying identifiers.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use base64ct::{Base64UrlUnpadded, Encoding as _};
use core::fmt;
use sha2::{Digest as _, Sha256};

/// Frozen target-V1 raw-key method identifier.
pub const RAW_KEY_V1: &str = "raw-key-v1";
/// Generalized raw-key method identifier.
pub const RAW_KEY_V2: &str = "raw-key-v2";
/// Media type for frozen target-V1 descriptors.
pub const RAW_KEY_V1_MEDIA_TYPE: &str = "application/vnd.auths.raw-key.v1";
/// Media type for generalized V2 descriptors.
pub const RAW_KEY_V2_MEDIA_TYPE: &str = "application/vnd.auths.raw-key.v2";
/// Ed25519 signature-suite identifier.
pub const ED25519_V1: &str = "ed25519-v1";
/// P-256 with SHA-256 signature-suite identifier.
pub const P256_SHA256_V1: &str = "p256-sha256-v1";
/// Principal prefix reserved for frozen target-V1 descriptors.
pub const V1_PRINCIPAL_PREFIX: &str = "key:sha256:";
/// Principal prefix reserved for generalized V2 descriptors.
pub const V2_PRINCIPAL_PREFIX: &str = "key:sha256-v2:";
/// Maximum generalized verification-material size.
pub const MAX_RAW_KEY_BYTES: usize = 128 * 1024;
/// Maximum generalized signature-suite identifier size.
pub const MAX_SUITE_ID_BYTES: usize = 128;

const V1_DOMAIN: &[u8] = b"AUTHS-RAW-KEY\0\x01";
const V2_DOMAIN: &[u8] = b"AUTHS-RAW-KEY\0\x02";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Registered key shapes in the frozen target-V1 descriptor.
pub enum RawKeyTypeV1 {
    Ed25519,
    P256,
}

impl RawKeyTypeV1 {
    /// Returns the registered signature-suite identifier.
    #[must_use]
    pub const fn suite_id(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_V1,
            Self::P256 => P256_SHA256_V1,
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Ed25519 => 1,
            Self::P256 => 2,
        }
    }

    const fn key_length(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::P256 => 33,
        }
    }
}

/// Encodes the frozen target-V1 raw-key descriptor.
///
/// # Errors
///
/// Rejects a key whose exact length does not match its registered key type.
pub fn encode_v1(key_type: RawKeyTypeV1, public_key: &[u8]) -> Result<Vec<u8>, RawKeyError> {
    if public_key.len() != key_type.key_length() {
        return Err(RawKeyError::InvalidKey);
    }
    let mut output = Vec::with_capacity(V1_DOMAIN.len() + 3 + public_key.len());
    output.extend_from_slice(V1_DOMAIN);
    output.push(key_type.tag());
    output.extend_from_slice(
        &u16::try_from(public_key.len())
            .map_err(|_| RawKeyError::Limit)?
            .to_be_bytes(),
    );
    output.extend_from_slice(public_key);
    Ok(output)
}

/// Decodes one canonical target-V1 raw-key descriptor.
///
/// # Errors
///
/// Rejects unknown tags, invalid lengths, trailing data, and non-canonical bytes.
pub fn decode_v1(input: &[u8]) -> Result<(RawKeyTypeV1, Vec<u8>), RawKeyError> {
    if !input.starts_with(V1_DOMAIN) || input.len() < V1_DOMAIN.len() + 3 {
        return Err(RawKeyError::InvalidEncoding);
    }
    let offset = V1_DOMAIN.len();
    let key_type = match input[offset] {
        1 => RawKeyTypeV1::Ed25519,
        2 => RawKeyTypeV1::P256,
        _ => return Err(RawKeyError::InvalidEncoding),
    };
    let length = usize::from(u16::from_be_bytes([input[offset + 1], input[offset + 2]]));
    let public_key = input
        .get(offset + 3..)
        .ok_or(RawKeyError::InvalidEncoding)?;
    if public_key.len() != length || encode_v1(key_type, public_key)?.as_slice() != input {
        return Err(RawKeyError::InvalidEncoding);
    }
    Ok((key_type, public_key.to_vec()))
}

/// Derives the frozen target-V1 principal identifier.
///
/// # Errors
///
/// Rejects invalid target-V1 verification material.
pub fn identifier_v1(key_type: RawKeyTypeV1, public_key: &[u8]) -> Result<String, RawKeyError> {
    Ok(digest_identifier(
        V1_PRINCIPAL_PREFIX,
        &encode_v1(key_type, public_key)?,
    ))
}

/// Canonical generalized raw-key descriptor for caller-selected suites.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RawKeyDescriptorV2 {
    suite_id: String,
    public_key: Vec<u8>,
}

impl RawKeyDescriptorV2 {
    /// Constructs one bounded generalized raw-key descriptor.
    ///
    /// # Errors
    ///
    /// Rejects invalid suite identifiers and empty or oversized key material.
    pub fn new(suite_id: &str, public_key: Vec<u8>) -> Result<Self, RawKeyError> {
        if suite_id.is_empty()
            || suite_id.len() > MAX_SUITE_ID_BYTES
            || suite_id
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(RawKeyError::InvalidSuite);
        }
        if public_key.is_empty() || public_key.len() > MAX_RAW_KEY_BYTES {
            return Err(RawKeyError::InvalidKey);
        }
        Ok(Self {
            suite_id: suite_id.into(),
            public_key,
        })
    }

    #[must_use]
    /// Returns the descriptor's signature-suite identifier.
    pub fn suite_id(&self) -> &str {
        &self.suite_id
    }

    #[must_use]
    /// Returns the descriptor's opaque public verification material.
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    #[must_use]
    /// Encodes the descriptor in its canonical V2 representation.
    ///
    /// # Panics
    ///
    /// This cannot panic for a descriptor constructed or decoded by this crate; both fields are
    /// validated below the encoded integer bounds.
    pub fn encode(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(
            V2_DOMAIN.len() + 2 + self.suite_id.len() + 4 + self.public_key.len(),
        );
        output.extend_from_slice(V2_DOMAIN);
        output.extend_from_slice(
            &u16::try_from(self.suite_id.len())
                .expect("validated suite identifiers fit in u16")
                .to_be_bytes(),
        );
        output.extend_from_slice(self.suite_id.as_bytes());
        output.extend_from_slice(
            &u32::try_from(self.public_key.len())
                .expect("validated public keys fit in u32")
                .to_be_bytes(),
        );
        output.extend_from_slice(&self.public_key);
        output
    }

    /// Decodes one complete canonical V2 descriptor.
    ///
    /// # Errors
    ///
    /// Rejects invalid bounds, UTF-8, field values, and trailing data.
    pub fn decode(input: &[u8]) -> Result<Self, RawKeyError> {
        if !input.starts_with(V2_DOMAIN) {
            return Err(RawKeyError::InvalidEncoding);
        }
        let mut cursor = V2_DOMAIN.len();
        let suite_length = usize::from(read_u16(input, &mut cursor)?);
        let suite_bytes = take(input, &mut cursor, suite_length)?;
        let suite_id =
            core::str::from_utf8(suite_bytes).map_err(|_| RawKeyError::InvalidEncoding)?;
        let key_length =
            usize::try_from(read_u32(input, &mut cursor)?).map_err(|_| RawKeyError::Limit)?;
        let public_key = take(input, &mut cursor, key_length)?.to_vec();
        if cursor != input.len() {
            return Err(RawKeyError::InvalidEncoding);
        }
        let descriptor = Self::new(suite_id, public_key)?;
        if descriptor.encode().as_slice() != input {
            return Err(RawKeyError::InvalidEncoding);
        }
        Ok(descriptor)
    }

    #[must_use]
    /// Derives the V2 self-certifying principal identifier.
    pub fn identifier(&self) -> String {
        digest_identifier(V2_PRINCIPAL_PREFIX, &self.encode())
    }
}

fn digest_identifier(prefix: &str, descriptor: &[u8]) -> String {
    let digest: [u8; 32] = Sha256::digest(descriptor).into();
    format!("{prefix}{}", Base64UrlUnpadded::encode_string(&digest))
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, RawKeyError> {
    let value: [u8; 2] = take(input, cursor, 2)?
        .try_into()
        .map_err(|_| RawKeyError::InvalidEncoding)?;
    Ok(u16::from_be_bytes(value))
}

fn read_u32(input: &[u8], cursor: &mut usize) -> Result<u32, RawKeyError> {
    let value: [u8; 4] = take(input, cursor, 4)?
        .try_into()
        .map_err(|_| RawKeyError::InvalidEncoding)?;
    Ok(u32::from_be_bytes(value))
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8], RawKeyError> {
    let end = cursor.checked_add(length).ok_or(RawKeyError::Limit)?;
    let value = input
        .get(*cursor..end)
        .ok_or(RawKeyError::InvalidEncoding)?;
    *cursor = end;
    Ok(value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Canonical raw-key descriptor failure.
pub enum RawKeyError {
    /// The suite identifier is empty, malformed, or oversized.
    InvalidSuite,
    /// The public verification material has an invalid size.
    InvalidKey,
    /// The encoded descriptor is malformed or non-canonical.
    InvalidEncoding,
    /// A bounded decoding resource limit was exceeded.
    Limit,
}

impl fmt::Display for RawKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSuite => "invalid raw-key signature suite",
            Self::InvalidKey => "invalid raw-key verification material",
            Self::InvalidEncoding => "invalid canonical raw-key descriptor",
            Self::Limit => "raw-key resource limit exceeded",
        })
    }
}

impl core::error::Error for RawKeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v1_round_trip_preserves_the_frozen_identifier_family() {
        let key = [3; 32];
        let bytes = encode_v1(RawKeyTypeV1::Ed25519, &key).unwrap();
        assert_eq!(
            decode_v1(&bytes).unwrap(),
            (RawKeyTypeV1::Ed25519, key.to_vec())
        );
        assert!(
            identifier_v1(RawKeyTypeV1::Ed25519, &key)
                .unwrap()
                .starts_with(V1_PRINCIPAL_PREFIX)
        );
    }

    #[test]
    fn v2_round_trip_supports_arbitrary_bounded_key_shapes() {
        let descriptor = RawKeyDescriptorV2::new("example-pq-v1", alloc::vec![7; 4096]).unwrap();
        assert_eq!(
            RawKeyDescriptorV2::decode(&descriptor.encode()).unwrap(),
            descriptor
        );
        assert!(descriptor.identifier().starts_with(V2_PRINCIPAL_PREFIX));
    }

    #[test]
    fn versioned_families_cannot_be_confused() {
        let key = [7; 32];
        let v1 = identifier_v1(RawKeyTypeV1::Ed25519, &key).unwrap();
        let v2 = RawKeyDescriptorV2::new(ED25519_V1, key.to_vec())
            .unwrap()
            .identifier();
        assert_ne!(v1, v2);
        assert!(v1.starts_with("key:sha256:"));
        assert!(v2.starts_with("key:sha256-v2:"));
    }
}
