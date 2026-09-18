//! RSA PKCS#1 v1.5 with SHA-256 signature verification.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_model::{AdapterConfigurationId, ModelError, SignatureSuiteId};
use auths_ports::{SignatureError, SignatureInput, SignatureSuite};
use rsa::{RsaPublicKey, pkcs1::DecodeRsaPublicKey, pkcs1v15};
use sha2::Sha256;
use signature::Verifier as _;

pub const RSA_PKCS1_SHA256_V1: &str = "rsa-pkcs1-sha256-v1";

pub struct RsaPkcs1Sha256Suite {
    id: SignatureSuiteId,
}
impl RsaPkcs1Sha256Suite {
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: SignatureSuiteId::parse(RSA_PKCS1_SHA256_V1)?,
        })
    }
    fn key(bytes: &[u8]) -> Result<RsaPublicKey, SignatureError> {
        let key = RsaPublicKey::from_pkcs1_der(bytes).map_err(|_| SignatureError::InvalidKey)?;
        use rsa::traits::PublicKeyParts as _;
        if !matches!(key.n().bits(), 2048 | 3072 | 4096)
            || key.e() != &rsa::BigUint::from(65_537_u32)
        {
            return Err(SignatureError::InvalidKey);
        }
        Ok(key)
    }
}
impl SignatureSuite for RsaPkcs1Sha256Suite {
    fn id(&self) -> &SignatureSuiteId {
        &self.id
    }
    fn configuration_id(&self) -> AdapterConfigurationId {
        auths_ports::configuration_id(RSA_PKCS1_SHA256_V1.as_bytes(), core::iter::empty())
    }
    fn validate_key(&self, verification_key: &[u8]) -> Result<(), SignatureError> {
        Self::key(verification_key).map(|_| ())
    }
    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError> {
        let key = Self::key(input.verification_key)?;
        let signature = pkcs1v15::Signature::try_from(input.signature)
            .map_err(|_| SignatureError::InvalidSignatureEncoding)?;
        pkcs1v15::VerifyingKey::<Sha256>::new(key)
            .verify(input.signing_preimage, &signature)
            .map_err(|_| SignatureError::InvalidSignature)
    }
    fn work_units(&self) -> u64 {
        1_000
    }
}
