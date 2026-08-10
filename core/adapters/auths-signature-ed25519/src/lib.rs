//! Standalone Ed25519 verifier for algorithm-neutral identity messages.

#![no_std]
#![forbid(unsafe_code)]

use auths_identity::{IdentityError, SignatureVerifier};
use ed25519_dalek::{Signature, VerifyingKey};

pub const ED25519_V1: &str = "ed25519-v1";

pub struct Ed25519Verifier;

impl SignatureVerifier for Ed25519Verifier {
    fn suite_id(&self) -> &'static str {
        ED25519_V1
    }

    fn verify(
        &self,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        let key_bytes: &[u8; 32] = public_key
            .try_into()
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        let key =
            VerifyingKey::from_bytes(key_bytes).map_err(|_| IdentityError::InvalidPublicKey)?;
        let signature =
            Signature::from_slice(signature).map_err(|_| IdentityError::InvalidSignature)?;
        key.verify_strict(preimage, &signature)
            .map_err(|_| IdentityError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_identity::SignatureVerifier;
    use ed25519_dalek::{Signer as _, SigningKey};

    #[test]
    fn verifies_exact_message() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signature = key.sign(b"exact");
        Ed25519Verifier
            .verify(
                key.verifying_key().as_bytes(),
                b"exact",
                &signature.to_bytes(),
            )
            .unwrap();
        assert_eq!(
            Ed25519Verifier.verify(
                key.verifying_key().as_bytes(),
                b"changed",
                &signature.to_bytes()
            ),
            Err(IdentityError::VerificationFailed)
        );
    }
}
