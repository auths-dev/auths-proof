//! RSA PKCS#1 v1.5 with SHA-256 signature verification.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

use auths_model::{AdapterConfigurationId, ModelError, SignatureSuiteId};
use auths_ports::{SignatureError, SignatureInput, SignatureSuite};
use ring::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};

pub const RSA_PKCS1_SHA256_V1: &str = "rsa-pkcs1-sha256-v1";

pub struct RsaPkcs1Sha256Suite {
    id: SignatureSuiteId,
}
impl RsaPkcs1Sha256Suite {
    /// Constructs the registered RSA PKCS#1 SHA-256 suite.
    ///
    /// # Errors
    ///
    /// Returns [`ModelError`] if the built-in suite identifier violates the
    /// model registry grammar.
    pub fn new() -> Result<Self, ModelError> {
        Ok(Self {
            id: SignatureSuiteId::parse(RSA_PKCS1_SHA256_V1)?,
        })
    }
    fn key(bytes: &[u8]) -> Result<usize, SignatureError> {
        let mut encoded = bytes;
        let mut fields = take_der_value(&mut encoded, 0x30)?;
        if !encoded.is_empty() {
            return Err(SignatureError::InvalidKey);
        }
        let modulus = take_positive_integer(&mut fields)?;
        let exponent = take_positive_integer(&mut fields)?;
        if !fields.is_empty()
            || !matches!(modulus.len(), 256 | 384 | 512)
            || modulus[0] & 0x80 == 0
            || exponent != [0x01, 0x00, 0x01]
        {
            return Err(SignatureError::InvalidKey);
        }
        Ok(modulus.len())
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
        let modulus_len = Self::key(input.verification_key)?;
        if input.signature.len() != modulus_len {
            return Err(SignatureError::InvalidSignatureEncoding);
        }
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, input.verification_key)
            .verify(input.signing_preimage, input.signature)
            .map_err(|_| SignatureError::InvalidSignature)
    }
    fn work_units(&self) -> u64 {
        1_000
    }
}

fn take_der_value<'a>(input: &mut &'a [u8], tag: u8) -> Result<&'a [u8], SignatureError> {
    if input.first().copied() != Some(tag) {
        return Err(SignatureError::InvalidKey);
    }
    *input = &input[1..];
    let len = take_der_len(input)?;
    if input.len() < len {
        return Err(SignatureError::InvalidKey);
    }
    let (value, remaining) = input.split_at(len);
    *input = remaining;
    Ok(value)
}

fn take_der_len(input: &mut &[u8]) -> Result<usize, SignatureError> {
    let Some(first) = input.first().copied() else {
        return Err(SignatureError::InvalidKey);
    };
    *input = &input[1..];
    if first & 0x80 == 0 {
        return Ok(usize::from(first));
    }
    let octets = usize::from(first & 0x7f);
    if octets == 0 || octets > core::mem::size_of::<usize>() || input.len() < octets {
        return Err(SignatureError::InvalidKey);
    }
    let (encoded, remaining) = input.split_at(octets);
    if encoded[0] == 0 {
        return Err(SignatureError::InvalidKey);
    }
    let len = encoded.iter().try_fold(0_usize, |len, byte| {
        len.checked_mul(256)?.checked_add(usize::from(*byte))
    });
    let Some(len) = len.filter(|len| *len >= 128) else {
        return Err(SignatureError::InvalidKey);
    };
    *input = remaining;
    Ok(len)
}

fn take_positive_integer<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], SignatureError> {
    let encoded = take_der_value(input, 0x02)?;
    let Some(first) = encoded.first().copied() else {
        return Err(SignatureError::InvalidKey);
    };
    if first & 0x80 != 0 {
        return Err(SignatureError::InvalidKey);
    }
    if first == 0 {
        if encoded.len() == 1 || encoded[1] & 0x80 == 0 {
            return Err(SignatureError::InvalidKey);
        }
        return Ok(&encoded[1..]);
    }
    Ok(encoded)
}
