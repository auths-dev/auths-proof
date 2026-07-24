//! Closed-profile Multikey support shared by DID principal adapters.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};
use core::fmt;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256Key};

const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];
const MAX_MULTIBASE_LEN: usize = 128;

pub const ED25519_ALGORITHM: &str = "ed25519";
pub const P256_ALGORITHM: &str = "p256-sha256";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultikeyType {
    Ed25519,
    P256,
}

impl MultikeyType {
    pub const fn algorithm(self) -> &'static str {
        match self {
            Self::Ed25519 => ED25519_ALGORITHM,
            Self::P256 => P256_ALGORITHM,
        }
    }

    const fn multicodec(self) -> [u8; 2] {
        match self {
            Self::Ed25519 => ED25519_MULTICODEC,
            Self::P256 => P256_MULTICODEC,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::P256 => 33,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Multikey {
    encoded: String,
    key_type: MultikeyType,
    public_key: Vec<u8>,
}

impl Multikey {
    pub fn parse(encoded: &str) -> Result<Self, MultikeyError> {
        if encoded.len() < 2 || encoded.len() > MAX_MULTIBASE_LEN || !encoded.is_ascii() {
            return Err(MultikeyError::InvalidEncoding);
        }
        let payload = encoded
            .strip_prefix('z')
            .ok_or(MultikeyError::UnsupportedMultibase)?;
        let decoded = bs58::decode(payload)
            .into_vec()
            .map_err(|_| MultikeyError::InvalidEncoding)?;
        if decoded.len() < 2 {
            return Err(MultikeyError::InvalidEncoding);
        }
        let key_type = if decoded[..2] == ED25519_MULTICODEC {
            MultikeyType::Ed25519
        } else if decoded[..2] == P256_MULTICODEC {
            MultikeyType::P256
        } else {
            return Err(MultikeyError::UnsupportedMulticodec);
        };
        let public_key = decoded[2..].to_vec();
        if public_key.len() != key_type.key_len() {
            return Err(MultikeyError::InvalidKeyLength);
        }
        validate_public_key(key_type, &public_key)?;
        if Self::from_public_key(key_type, public_key.clone())?.encoded != encoded {
            return Err(MultikeyError::NonCanonical);
        }
        Ok(Self {
            encoded: encoded.into(),
            key_type,
            public_key,
        })
    }

    pub fn from_public_key(
        key_type: MultikeyType,
        public_key: Vec<u8>,
    ) -> Result<Self, MultikeyError> {
        if public_key.len() != key_type.key_len() {
            return Err(MultikeyError::InvalidKeyLength);
        }
        validate_public_key(key_type, &public_key)?;
        let mut bytes = Vec::with_capacity(2 + public_key.len());
        bytes.extend_from_slice(&key_type.multicodec());
        bytes.extend_from_slice(&public_key);
        Ok(Self {
            encoded: format!("z{}", bs58::encode(bytes).into_string()),
            key_type,
            public_key,
        })
    }

    pub fn encoded(&self) -> &str {
        &self.encoded
    }

    pub const fn key_type(&self) -> MultikeyType {
        self.key_type
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub fn verify(
        &self,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), MultikeyError> {
        if algorithm != self.key_type.algorithm() {
            return Err(MultikeyError::AlgorithmMismatch);
        }
        match self.key_type {
            MultikeyType::Ed25519 => {
                let bytes: [u8; 32] = self
                    .public_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| MultikeyError::InvalidKeyLength)?;
                let key =
                    Ed25519Key::from_bytes(&bytes).map_err(|_| MultikeyError::InvalidPublicKey)?;
                let signature = Ed25519Signature::from_slice(signature)
                    .map_err(|_| MultikeyError::InvalidSignature)?;
                key.verify_strict(message, &signature)
                    .map_err(|_| MultikeyError::InvalidSignature)
            }
            MultikeyType::P256 => {
                let key = P256Key::from_sec1_bytes(&self.public_key)
                    .map_err(|_| MultikeyError::InvalidPublicKey)?;
                let signature = P256Signature::from_slice(signature)
                    .map_err(|_| MultikeyError::InvalidSignature)?;
                if signature.normalize_s().is_some() {
                    return Err(MultikeyError::InvalidSignature);
                }
                key.verify(message, &signature)
                    .map_err(|_| MultikeyError::InvalidSignature)
            }
        }
    }
}

fn validate_public_key(key_type: MultikeyType, public_key: &[u8]) -> Result<(), MultikeyError> {
    match key_type {
        MultikeyType::Ed25519 => {
            let bytes: [u8; 32] = public_key
                .try_into()
                .map_err(|_| MultikeyError::InvalidKeyLength)?;
            Ed25519Key::from_bytes(&bytes).map_err(|_| MultikeyError::InvalidPublicKey)?;
        }
        MultikeyType::P256 => {
            P256Key::from_sec1_bytes(public_key).map_err(|_| MultikeyError::InvalidPublicKey)?;
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultikeyError {
    InvalidEncoding,
    UnsupportedMultibase,
    UnsupportedMulticodec,
    InvalidKeyLength,
    InvalidPublicKey,
    NonCanonical,
    AlgorithmMismatch,
    InvalidSignature,
}

impl fmt::Display for MultikeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidEncoding => "invalid Multikey encoding",
            Self::UnsupportedMultibase => "unsupported Multikey multibase",
            Self::UnsupportedMulticodec => "unsupported Multikey multicodec",
            Self::InvalidKeyLength => "invalid Multikey public-key length",
            Self::InvalidPublicKey => "invalid Multikey public key",
            Self::NonCanonical => "non-canonical Multikey encoding",
            Self::AlgorithmMismatch => "Multikey algorithm mismatch",
            Self::InvalidSignature => "invalid Multikey signature",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MultikeyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_official_ed25519_vector() {
        let key =
            Multikey::parse("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").expect("vector");
        assert_eq!(key.key_type(), MultikeyType::Ed25519);
        assert_eq!(key.public_key().len(), 32);
    }

    #[test]
    fn parses_official_p256_vector() {
        let key =
            Multikey::parse("zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv").expect("vector");
        assert_eq!(key.key_type(), MultikeyType::P256);
        assert_eq!(key.public_key().len(), 33);
    }

    #[test]
    fn rejects_non_base58btc_and_unknown_codec() {
        assert_eq!(
            Multikey::parse("uZm9v"),
            Err(MultikeyError::UnsupportedMultibase)
        );
        assert_eq!(
            Multikey::parse("z6LSj72tK8brWgZja8NLRwPigth2T9QRiG1uH9oKZuKjdh9p"),
            Err(MultikeyError::UnsupportedMulticodec)
        );
    }
}
