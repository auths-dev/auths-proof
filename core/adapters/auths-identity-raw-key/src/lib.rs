//! Self-certifying raw-key identity method for any registered signature suite.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::{format, vec::Vec};
use auths_identity::{IdentityError, IdentityMethod, PublicIdentity, ValidatedIdentity};
use base64ct::{Base64UrlUnpadded, Encoding};
use sha2::{Digest as _, Sha256};

pub const RAW_KEY_IDENTITY_V1: &str = "raw-key-identity-v1";
pub const PRINCIPAL_PREFIX: &str = "key:sha256:";
const DESCRIPTOR_DOMAIN: &[u8] = b"AUTHS-IDENTITY-RAW-KEY\0\x01";

pub struct RawKeyIdentityMethod;

impl RawKeyIdentityMethod {
    /// Derives one self-certifying identity for arbitrary suite and key bytes.
    ///
    /// # Errors
    ///
    /// Rejects invalid suite identifiers, empty keys, or oversized fields.
    pub fn identity(
        suite_id: &str,
        public_key: Vec<u8>,
    ) -> Result<ValidatedIdentity, IdentityError> {
        let identifier = derive_identifier(suite_id, &public_key)?;
        PublicIdentity::new(RAW_KEY_IDENTITY_V1, &identifier, suite_id, public_key)?.validate(&Self)
    }
}

impl IdentityMethod for RawKeyIdentityMethod {
    fn method_id(&self) -> &'static str {
        RAW_KEY_IDENTITY_V1
    }

    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
        if identity.method_id() != RAW_KEY_IDENTITY_V1 {
            return Err(IdentityError::UnsupportedIdentityMethod);
        }
        let expected = derive_identifier(identity.suite_id(), identity.public_key())?;
        if expected != identity.identity_id() {
            return Err(IdentityError::InvalidIdentity);
        }
        Ok(())
    }
}

fn derive_identifier(
    suite_id: &str,
    public_key: &[u8],
) -> Result<alloc::string::String, IdentityError> {
    if suite_id.is_empty() || public_key.is_empty() {
        return Err(IdentityError::InvalidIdentity);
    }
    let suite_length = u16::try_from(suite_id.len()).map_err(|_| IdentityError::Limit)?;
    let key_length = u32::try_from(public_key.len()).map_err(|_| IdentityError::Limit)?;
    let mut descriptor = Vec::new();
    descriptor.extend_from_slice(DESCRIPTOR_DOMAIN);
    descriptor.extend_from_slice(&suite_length.to_be_bytes());
    descriptor.extend_from_slice(suite_id.as_bytes());
    descriptor.extend_from_slice(&key_length.to_be_bytes());
    descriptor.extend_from_slice(public_key);
    let digest: [u8; 32] = Sha256::digest(descriptor).into();
    Ok(format!(
        "{PRINCIPAL_PREFIX}{}",
        Base64UrlUnpadded::encode_string(&digest)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_accepts_arbitrary_suite_and_key_shapes() {
        let method = RawKeyIdentityMethod;
        for (suite, length) in [
            ("ed25519-v1", 32),
            ("p256-sha256-v1", 33),
            ("example-pq-v1", 4096),
        ] {
            let identity = RawKeyIdentityMethod::identity(suite, alloc::vec![7; length]).unwrap();
            identity.as_public_identity().validate(&method).unwrap();
            assert_eq!(identity.suite_id(), suite);
        }
    }
}
