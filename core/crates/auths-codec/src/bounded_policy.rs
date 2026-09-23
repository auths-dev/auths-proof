//! Deterministic encoding of `bounded-policy-commitment-v1` extension bodies.

use crate::{
    CodecError,
    decode::{
        V1Decoder, bounded_bytes, digest_bytes, ensure_complete, is_null, key, map, null, text,
    },
    encode::{
        V1Encoder, bytes, encode_error, finish, key as encode_key, map as encode_map,
        text as encode_text,
    },
    hash::domain_commitment,
};
use alloc::vec::Vec;
use auths_model::{
    BOUNDED_POLICY_DIGEST_DOMAIN, BOUNDED_POLICY_LINK_DOMAIN, BoundedPolicyCommitment, Digest,
    MAX_BOUNDED_POLICY_BYTES, MAX_POLICY_CANONICALIZATION_BYTES, MAX_POLICY_IDENTIFIER_BYTES,
    PolicyCommitment, PolicyIdentifier,
};
use minicbor::Decoder;

fn encode_commitment(
    encoder: &mut V1Encoder,
    commitment: &PolicyCommitment,
) -> Result<(), CodecError> {
    encode_map(encoder, 5)?;
    encode_key(encoder, 0)?;
    encode_text(encoder, commitment.policy_type().as_str())?;
    encode_key(encoder, 1)?;
    encoder
        .u16(commitment.policy_version())
        .map_err(encode_error)?;
    encode_key(encoder, 2)?;
    encode_text(encoder, commitment.canonicalization_id().as_str())?;
    encode_key(encoder, 3)?;
    bytes(encoder, commitment.policy_digest().as_bytes())?;
    encode_key(encoder, 4)?;
    encode_text(encoder, commitment.evaluator_semantic_id().as_str())
}

fn commitment(decoder: &mut V1Decoder<'_>) -> Result<PolicyCommitment, CodecError> {
    map(decoder, 5)?;
    key(decoder, 0)?;
    let policy_type = PolicyIdentifier::parse(text(decoder)?, MAX_POLICY_IDENTIFIER_BYTES)?;
    key(decoder, 1)?;
    let policy_version = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 2)?;
    let canonicalization_id =
        PolicyIdentifier::parse(text(decoder)?, MAX_POLICY_CANONICALIZATION_BYTES)?;
    key(decoder, 3)?;
    let policy_digest = Digest::new(digest_bytes(decoder)?);
    key(decoder, 4)?;
    let evaluator_semantic_id =
        PolicyIdentifier::parse(text(decoder)?, MAX_POLICY_IDENTIFIER_BYTES)?;
    PolicyCommitment::new(
        policy_type,
        policy_version,
        canonicalization_id,
        policy_digest,
        evaluator_semantic_id,
    )
    .map_err(CodecError::from)
}

/// Encodes the canonical bytes of a `bounded-policy-commitment-v1` extension.
///
/// # Errors
///
/// Returns [`CodecError`] if the body cannot be represented.
pub fn encode_bounded_policy_commitment(
    body: &BoundedPolicyCommitment,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| {
        encode_map(encoder, 3)?;
        encode_key(encoder, 0)?;
        encode_commitment(encoder, body.commitment())?;
        encode_key(encoder, 1)?;
        bytes(encoder, body.policy())?;
        encode_key(encoder, 2)?;
        if let Some(parent) = body.parent() {
            bytes(encoder, parent.as_bytes())
        } else {
            encoder.null().map_err(encode_error)?;
            Ok(())
        }
    })
}

/// The digest a commitment's policy bytes must open to.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] only for an unrepresentable length.
pub fn bounded_policy_digest(policy: &[u8]) -> Result<Digest, CodecError> {
    domain_commitment(BOUNDED_POLICY_DIGEST_DOMAIN, policy)
}

/// The digest a child's body carries to link a parent's extension bytes.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] only for an unrepresentable length.
pub fn bounded_policy_link(parent_extension: &[u8]) -> Result<Digest, CodecError> {
    domain_commitment(BOUNDED_POLICY_LINK_DOMAIN, parent_extension)
}

/// Decodes and validates the exact bytes of a `bounded-policy-commitment-v1`
/// extension: the canonical shape, identifier syntax and bounds, and that the
/// carried policy bytes open to the committed digest.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above the extension or policy byte
/// bound, [`CodecError::DigestMismatch`] when the policy bytes do not open to
/// the commitment, and a typed error for malformed, non-canonical, or invalid
/// bytes.
pub fn decode_bounded_policy_commitment(
    input: &[u8],
) -> Result<BoundedPolicyCommitment, CodecError> {
    if input.len() > auths_model::HARD_MAX_EXTENSION_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    map(&mut decoder, 3)?;
    key(&mut decoder, 0)?;
    let commitment = commitment(&mut decoder)?;
    key(&mut decoder, 1)?;
    let policy = bounded_bytes(&mut decoder, MAX_BOUNDED_POLICY_BYTES, false)?;
    key(&mut decoder, 2)?;
    let parent = if is_null(&decoder)? {
        null(&mut decoder)?;
        None
    } else {
        Some(Digest::new(digest_bytes(&mut decoder)?))
    };
    ensure_complete(&decoder, input)?;
    let body =
        BoundedPolicyCommitment::new(commitment, policy, parent).map_err(|error| match error {
            auths_model::ModelError::CollectionLimitExceeded => CodecError::LimitExceeded,
            other => CodecError::Model(other),
        })?;
    if encode_bounded_policy_commitment(&body)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    if bounded_policy_digest(body.policy())? != body.commitment().policy_digest() {
        return Err(CodecError::DigestMismatch);
    }
    Ok(body)
}
