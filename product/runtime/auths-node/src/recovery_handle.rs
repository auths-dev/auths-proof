//! Deployment-signed principal-bound operation recovery capabilities.

#![forbid(unsafe_code)]
#![allow(clippy::missing_errors_doc)]

use auths_lifecycle::{OperationIdV1, OperationProfileV1};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use minicbor::{Decoder, Encoder};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

const HANDLE_VERSION: u8 = 1;
const HANDLE_ALGORITHM: &str = "Ed25519";
const HANDLE_SEMANTIC_ID: &[u8] = b"auths.recovery-handle/1";
const MAX_HANDLE_BYTES: usize = 16 * 1024;

/// Verified recovery locator safe to use only for principal-bound lookup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRecoveryHandle {
    operation_id: OperationIdV1,
    profile: OperationProfileV1,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    key_id: String,
}

impl VerifiedRecoveryHandle {
    /// Returns the exact operation identity.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationIdV1 {
        &self.operation_id
    }

    /// Returns the exact profile identity and runtime digest known by the roster.
    #[must_use]
    pub const fn profile(&self) -> &OperationProfileV1 {
        &self.profile
    }

    /// Returns issuance time.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns optional terminal expiry.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> Option<u64> {
        self.expires_at_unix_seconds
    }

    /// Returns the verification key ID used by this capability.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
}

/// Current signer plus retained verification-only rotation keys.
pub struct RecoveryHandleSigner {
    key_id: String,
    signing: SigningKey,
    verification: BTreeMap<String, VerifyingKey>,
}

impl RecoveryHandleSigner {
    /// Constructs a deployment signer from protected key bytes.
    pub fn from_seed(
        key_id: impl Into<String>,
        seed: [u8; 32],
        previous: impl IntoIterator<Item = (String, VerifyingKey)>,
    ) -> Result<Self, RecoveryHandleError> {
        let key_id = key_id.into();
        if !registered_token(&key_id) || seed == [0; 32] {
            return Err(RecoveryHandleError::InvalidKey);
        }
        let signing = SigningKey::from_bytes(&seed);
        let mut verification = previous.into_iter().collect::<BTreeMap<_, _>>();
        if verification.keys().any(|value| !registered_token(value))
            || verification.len() > 32
            || verification
                .insert(key_id.clone(), signing.verifying_key())
                .is_some()
        {
            return Err(RecoveryHandleError::InvalidKey);
        }
        Ok(Self {
            key_id,
            signing,
            verification,
        })
    }

    /// Returns the current recovery verification key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Returns the current recovery Ed25519 verification key.
    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// Issues one nonterminal or terminal principal-bound capability.
    pub fn issue(
        &self,
        operation_id: &OperationIdV1,
        profile: &OperationProfileV1,
        principal: &str,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
    ) -> Result<Vec<u8>, RecoveryHandleError> {
        if !valid_principal(principal)
            || issued_at_unix_seconds == 0
            || expires_at_unix_seconds.is_some_and(|value| value < issued_at_unix_seconds)
        {
            return Err(RecoveryHandleError::InvalidHandle);
        }
        let mut nonce = [0_u8; 32];
        getrandom::fill(&mut nonce).map_err(|_| RecoveryHandleError::Unavailable)?;
        let principal = principal_commitment(principal);
        let unsigned = encode_unsigned(
            operation_id,
            profile,
            principal,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            nonce,
            &self.key_id,
        )?;
        let preimage = signature_preimage(&unsigned);
        let signature = self.signing.sign(&preimage).to_bytes();
        let bytes = encode_complete(
            operation_id,
            profile,
            principal,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            nonce,
            &self.key_id,
            signature,
        )?;
        if bytes.is_empty() || bytes.len() > MAX_HANDLE_BYTES {
            return Err(RecoveryHandleError::Limit);
        }
        Ok(bytes)
    }

    /// Validates framing, signature, time, principal, and profile identity.
    pub fn verify(
        &self,
        bytes: &[u8],
        expected_principal: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedRecoveryHandle, RecoveryHandleError> {
        if bytes.is_empty()
            || bytes.len() > MAX_HANDLE_BYTES
            || !valid_principal(expected_principal)
            || now_unix_seconds == 0
        {
            return Err(RecoveryHandleError::InvalidHandle);
        }
        let parsed = decode_handle(bytes)?;
        let profile = profile_from_roster(&parsed.profile_id, parsed.profile_version)?;
        let operation_id = OperationIdV1::parse(parsed.operation_id.clone())
            .map_err(|_| RecoveryHandleError::InvalidHandle)?;
        if parsed.principal_commitment != principal_commitment(expected_principal)
            || parsed.issued_at_unix_seconds > now_unix_seconds
            || parsed
                .expires_at_unix_seconds
                .is_some_and(|value| now_unix_seconds > value)
        {
            return Err(RecoveryHandleError::InvalidHandle);
        }
        let verifying = self
            .verification
            .get(&parsed.key_id)
            .ok_or(RecoveryHandleError::InvalidHandle)?;
        let unsigned = encode_unsigned(
            &operation_id,
            &profile,
            parsed.principal_commitment,
            parsed.issued_at_unix_seconds,
            parsed.expires_at_unix_seconds,
            parsed.nonce,
            &parsed.key_id,
        )?;
        verifying
            .verify(
                &signature_preimage(&unsigned),
                &Signature::from_bytes(&parsed.signature),
            )
            .map_err(|_| RecoveryHandleError::InvalidHandle)?;
        let canonical = encode_complete(
            &operation_id,
            &profile,
            parsed.principal_commitment,
            parsed.issued_at_unix_seconds,
            parsed.expires_at_unix_seconds,
            parsed.nonce,
            &parsed.key_id,
            parsed.signature,
        )?;
        if canonical != bytes {
            return Err(RecoveryHandleError::InvalidHandle);
        }
        Ok(VerifiedRecoveryHandle {
            operation_id,
            profile,
            issued_at_unix_seconds: parsed.issued_at_unix_seconds,
            expires_at_unix_seconds: parsed.expires_at_unix_seconds,
            key_id: parsed.key_id,
        })
    }
}

struct ParsedHandle {
    operation_id: String,
    profile_id: String,
    profile_version: u16,
    principal_commitment: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    nonce: [u8; 32],
    key_id: String,
    signature: [u8; 64],
}

#[allow(clippy::too_many_arguments)]
fn encode_unsigned(
    operation_id: &OperationIdV1,
    profile: &OperationProfileV1,
    principal_commitment: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    nonce: [u8; 32],
    key_id: &str,
) -> Result<Vec<u8>, RecoveryHandleError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(10).map_err(|_| RecoveryHandleError::Encoding)?;
    encode_fields(
        &mut encoder,
        operation_id,
        profile,
        principal_commitment,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        nonce,
        key_id,
    )?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_complete(
    operation_id: &OperationIdV1,
    profile: &OperationProfileV1,
    principal_commitment: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    nonce: [u8; 32],
    key_id: &str,
    signature: [u8; 64],
) -> Result<Vec<u8>, RecoveryHandleError> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.map(11).map_err(|_| RecoveryHandleError::Encoding)?;
    encode_fields(
        &mut encoder,
        operation_id,
        profile,
        principal_commitment,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        nonce,
        key_id,
    )?;
    pair_bytes(&mut encoder, 11, &signature)?;
    Ok(encoder.into_writer())
}

#[allow(clippy::too_many_arguments)]
fn encode_fields(
    encoder: &mut Encoder<Vec<u8>>,
    operation_id: &OperationIdV1,
    profile: &OperationProfileV1,
    principal_commitment: [u8; 32],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    nonce: [u8; 32],
    key_id: &str,
) -> Result<(), RecoveryHandleError> {
    pair_u8(encoder, 1, HANDLE_VERSION)?;
    pair_text(encoder, 2, operation_id.as_str())?;
    pair_text(encoder, 3, profile.id())?;
    encoder
        .u8(4)
        .and_then(|value| value.u16(profile.version()))
        .map_err(|_| RecoveryHandleError::Encoding)?;
    pair_bytes(encoder, 5, &principal_commitment)?;
    encoder
        .u8(6)
        .and_then(|value| value.u64(issued_at_unix_seconds))
        .map_err(|_| RecoveryHandleError::Encoding)?;
    encode_expiry(encoder, expires_at_unix_seconds)?;
    pair_bytes(encoder, 8, &nonce)?;
    pair_text(encoder, 9, HANDLE_ALGORITHM)?;
    pair_text(encoder, 10, key_id)
}

fn decode_handle(bytes: &[u8]) -> Result<ParsedHandle, RecoveryHandleError> {
    let mut decoder = Decoder::new(bytes);
    if decoder
        .map()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        != Some(11)
    {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    expect_key(&mut decoder, 1)?;
    if decoder
        .u8()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        != HANDLE_VERSION
    {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    expect_key(&mut decoder, 2)?;
    let operation_id = decoder
        .str()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        .to_owned();
    expect_key(&mut decoder, 3)?;
    let profile_id = decoder
        .str()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        .to_owned();
    expect_key(&mut decoder, 4)?;
    let profile_version = decoder
        .u16()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?;
    expect_key(&mut decoder, 5)?;
    let principal_commitment = exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 6)?;
    let issued_at_unix_seconds = decoder
        .u64()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?;
    expect_key(&mut decoder, 7)?;
    let expires_at_unix_seconds = if decoder
        .datatype()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        == minicbor::data::Type::Null
    {
        decoder
            .null()
            .map_err(|_| RecoveryHandleError::InvalidHandle)?;
        None
    } else {
        Some(
            decoder
                .u64()
                .map_err(|_| RecoveryHandleError::InvalidHandle)?,
        )
    };
    expect_key(&mut decoder, 8)?;
    let nonce = exact_bytes::<32>(&mut decoder)?;
    expect_key(&mut decoder, 9)?;
    if decoder
        .str()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        != HANDLE_ALGORITHM
    {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    expect_key(&mut decoder, 10)?;
    let key_id = decoder
        .str()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        .to_owned();
    if !registered_token(&key_id) {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    expect_key(&mut decoder, 11)?;
    let signature = exact_bytes::<64>(&mut decoder)?;
    if decoder.position() != bytes.len() {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    Ok(ParsedHandle {
        operation_id,
        profile_id,
        profile_version,
        principal_commitment,
        issued_at_unix_seconds,
        expires_at_unix_seconds,
        nonce,
        key_id,
        signature,
    })
}

fn profile_from_roster(
    profile_id: &str,
    version: u16,
) -> Result<OperationProfileV1, RecoveryHandleError> {
    let digest = match (profile_id, version) {
        ("auths.opentofu.saved-plan-apply", 1) => {
            auths_opentofu::generated::profile_routes::SAVED_PLANS_APPLY_RUNTIME_DIGEST
        }
        ("auths.postgresql.bounded-update", 1) => {
            auths_postgresql::generated::profile_routes::UPDATES_EXECUTE_RUNTIME_DIGEST
        }
        ("auths.stripe.refund", 1) => {
            auths_stripe::generated::profile_routes::REFUNDS_CREATE_RUNTIME_DIGEST
        }
        _ => return Err(RecoveryHandleError::InvalidHandle),
    };
    OperationProfileV1::new(profile_id, version, digest)
        .map_err(|_| RecoveryHandleError::InvalidHandle)
}

fn signature_preimage(unsigned: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HANDLE_SEMANTIC_ID.len() + 1 + unsigned.len());
    bytes.extend_from_slice(HANDLE_SEMANTIC_ID);
    bytes.push(0);
    bytes.extend_from_slice(unsigned);
    bytes
}

fn principal_commitment(principal: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"AUTHS-RECOVERY-PRINCIPAL\x00\x01");
    digest.update((principal.len() as u64).to_be_bytes());
    digest.update(principal.as_bytes());
    digest.finalize().into()
}

fn valid_principal(value: &str) -> bool {
    !value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control)
}

fn registered_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
}

fn encode_expiry(
    encoder: &mut Encoder<Vec<u8>>,
    expiry: Option<u64>,
) -> Result<(), RecoveryHandleError> {
    encoder.u8(7).map_err(|_| RecoveryHandleError::Encoding)?;
    match expiry {
        Some(value) => {
            encoder
                .u64(value)
                .map_err(|_| RecoveryHandleError::Encoding)?;
        }
        None => {
            encoder.null().map_err(|_| RecoveryHandleError::Encoding)?;
        }
    }
    Ok(())
}

fn pair_u8(encoder: &mut Encoder<Vec<u8>>, key: u8, value: u8) -> Result<(), RecoveryHandleError> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.u8(value))
        .map_err(|_| RecoveryHandleError::Encoding)?;
    Ok(())
}

fn pair_text(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: &str,
) -> Result<(), RecoveryHandleError> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.str(value))
        .map_err(|_| RecoveryHandleError::Encoding)?;
    Ok(())
}

fn pair_bytes(
    encoder: &mut Encoder<Vec<u8>>,
    key: u8,
    value: &[u8],
) -> Result<(), RecoveryHandleError> {
    encoder
        .u8(key)
        .and_then(|encoder| encoder.bytes(value))
        .map_err(|_| RecoveryHandleError::Encoding)?;
    Ok(())
}

fn expect_key(decoder: &mut Decoder<'_>, expected: u8) -> Result<(), RecoveryHandleError> {
    if decoder
        .u8()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        != expected
    {
        return Err(RecoveryHandleError::InvalidHandle);
    }
    Ok(())
}

fn exact_bytes<const N: usize>(decoder: &mut Decoder<'_>) -> Result<[u8; N], RecoveryHandleError> {
    decoder
        .bytes()
        .map_err(|_| RecoveryHandleError::InvalidHandle)?
        .try_into()
        .map_err(|_| RecoveryHandleError::InvalidHandle)
}

/// Closed recovery-capability failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RecoveryHandleError {
    /// Signing/verification key configuration is invalid.
    #[error("recovery signing key is invalid")]
    InvalidKey,
    /// Capability is malformed, forged, expired, or principal/profile mismatched.
    #[error("recovery handle is invalid")]
    InvalidHandle,
    /// Capability encoding failed.
    #[error("recovery handle encoding failed")]
    Encoding,
    /// Capability exceeded its fixed bound.
    #[error("recovery handle exceeds its bound")]
    Limit,
    /// Operating-system randomness is unavailable.
    #[error("recovery handle randomness is unavailable")]
    Unavailable,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> OperationProfileV1 {
        profile_from_roster("auths.opentofu.saved-plan-apply", 1).unwrap()
    }

    #[test]
    fn handle_is_principal_bound_and_canonical() {
        let signer = RecoveryHandleSigner::from_seed("recovery-v1", [7; 32], []).unwrap();
        let operation = OperationIdV1::from_random_bytes([8; 16]).unwrap();
        let bytes = signer
            .issue(&operation, &profile(), "did:key:alice", 1_000, None)
            .unwrap();
        let verified = signer.verify(&bytes, "did:key:alice", 1_001).unwrap();
        assert_eq!(verified.operation_id(), &operation);
        assert!(signer.verify(&bytes, "did:key:bob", 1_001).is_err());
        let mut changed = bytes;
        *changed.last_mut().unwrap() ^= 1;
        assert!(signer.verify(&changed, "did:key:alice", 1_001).is_err());
    }

    #[test]
    fn terminal_expiry_is_enforced() {
        let signer = RecoveryHandleSigner::from_seed("recovery-v1", [7; 32], []).unwrap();
        let operation = OperationIdV1::from_random_bytes([8; 16]).unwrap();
        let bytes = signer
            .issue(&operation, &profile(), "did:key:alice", 1_000, Some(2_000))
            .unwrap();
        assert!(signer.verify(&bytes, "did:key:alice", 2_001).is_err());
    }
}
