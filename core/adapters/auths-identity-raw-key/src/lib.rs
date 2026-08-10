//! Self-certifying raw-key identity method for any registered signature suite.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_identity::{IdentityError, IdentityMethod, PublicIdentity, ValidatedIdentity};
use auths_raw_key_core::RawKeyDescriptorV2;

pub use auths_raw_key_core::{RAW_KEY_V2, V2_PRINCIPAL_PREFIX as PRINCIPAL_PREFIX};

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
        let descriptor =
            RawKeyDescriptorV2::new(suite_id, public_key).map_err(map_raw_key_error)?;
        PublicIdentity::new(
            RAW_KEY_V2,
            &descriptor.identifier(),
            descriptor.suite_id(),
            descriptor.public_key().to_vec(),
        )?
        .validate(&Self)
    }
}

impl IdentityMethod for RawKeyIdentityMethod {
    fn method_id(&self) -> &'static str {
        RAW_KEY_V2
    }

    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
        if identity.method_id() != RAW_KEY_V2 {
            return Err(IdentityError::UnsupportedIdentityMethod);
        }
        let descriptor =
            RawKeyDescriptorV2::new(identity.suite_id(), identity.public_key().to_vec())
                .map_err(map_raw_key_error)?;
        let expected = descriptor.identifier();
        if expected != identity.identity_id() {
            return Err(IdentityError::InvalidIdentity);
        }
        Ok(())
    }
}

fn map_raw_key_error(error: auths_raw_key_core::RawKeyError) -> IdentityError {
    match error {
        auths_raw_key_core::RawKeyError::InvalidSuite
        | auths_raw_key_core::RawKeyError::InvalidEncoding => IdentityError::InvalidIdentity,
        auths_raw_key_core::RawKeyError::InvalidKey => IdentityError::InvalidPublicKey,
        auths_raw_key_core::RawKeyError::Limit => IdentityError::Limit,
    }
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
            assert!(identity.identity_id().starts_with(PRINCIPAL_PREFIX));
        }
    }
}
