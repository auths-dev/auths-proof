//! Target V1 domain separation and content identifiers.

use crate::{
    CodecError,
    encode::{
        encode_evidence_content, encode_grant_status_statement, encode_principal_status_statement,
        encode_verification_result_digest_input,
    },
    encode_action_envelope, encode_action_signing_input, encode_authorization_plan, encode_bundle,
    encode_grant_signing_input, encode_grant_statement, encode_verifier_context,
};
use alloc::vec::Vec;
use auths_model::{
    ActionEnvelope, ActionId, AttachmentDigest, ContextDigest, Digest, EvidenceId, EvidenceObject,
    GrantId, GrantStatement, GrantStatusId, GrantStatusStatement, PROTOCOL_V1, PlanId,
    PortableVerificationResult, PrincipalStatusId, PrincipalStatusStatement, ProofBundle,
    SignatureDescriptor, TrustedContext, VerificationResultDigest,
};
use sha2::{Digest as _, Sha256};

const SIGNING_PREFIX: &[u8] = b"AUTHS";
const COMMITMENT_PREFIX: &[u8] = b"AUTHS-COMMITMENT";
const MAX_COMMITMENT_DOMAIN_BYTES: usize = 128;
const IDENTIFIER_PREFIX: &[u8] = b"AUTHS-ID";

#[derive(Clone, Copy)]
enum ObjectType {
    Grant = 1,
    Action = 2,
    PrincipalStatus = 3,
    GrantStatus = 4,
}

#[derive(Clone, Copy)]
enum IdentifierType {
    Grant = 1,
    Action = 2,
    Plan = 3,
    Evidence = 4,
    PrincipalStatus = 5,
    GrantStatus = 6,
    Context = 9,
}

fn raw_sha256(value: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(value);
    Digest::new(hasher.finalize().into())
}

/// Commits to already-canonical bytes under an explicit application domain.
///
/// The commitment is SHA-256 over the domain prefix, protocol version, the
/// length-framed domain, and the length-framed payload. Every SDK receives
/// this value from the core rather than restating the framing, so the same
/// input commits to the same digest in every language.
///
/// # Errors
///
/// Returns an error when the domain or payload exceeds protocol limits.
pub fn domain_commitment(domain: &str, canonical: &[u8]) -> Result<Digest, CodecError> {
    let domain_bytes = domain.as_bytes();
    if domain_bytes.is_empty() || domain_bytes.len() > MAX_COMMITMENT_DOMAIN_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let domain_length = u16::try_from(domain_bytes.len()).map_err(|_| CodecError::LimitExceeded)?;
    let payload_length = u64::try_from(canonical.len()).map_err(|_| CodecError::LimitExceeded)?;
    let mut hasher = Sha256::new();
    hasher.update(COMMITMENT_PREFIX);
    hasher.update(PROTOCOL_V1.to_be_bytes());
    hasher.update(domain_length.to_be_bytes());
    hasher.update(domain_bytes);
    hasher.update(payload_length.to_be_bytes());
    hasher.update(canonical);
    Ok(Digest::new(hasher.finalize().into()))
}

/// Returns the transaction binding for one external signing preimage.
///
/// The binding is SHA-256 over the exact domain-separated signing preimage.
/// Custody ports, approval prompts, and every language binding commit to this
/// value, so it is stated once here and never recomputed by a consumer.
#[must_use]
pub fn transaction_binding(signing_preimage: &[u8]) -> Digest {
    raw_sha256(signing_preimage)
}

fn domain_hash(identifier_type: IdentifierType, canonical: &[u8]) -> Result<Digest, CodecError> {
    let canonical_length = u64::try_from(canonical.len()).map_err(|_| CodecError::LimitExceeded)?;
    let mut hasher = Sha256::new();
    hasher.update(IDENTIFIER_PREFIX);
    hasher.update(PROTOCOL_V1.to_be_bytes());
    hasher.update((identifier_type as u16).to_be_bytes());
    hasher.update(canonical_length.to_be_bytes());
    hasher.update(canonical);
    Ok(Digest::new(hasher.finalize().into()))
}

fn signing_preimage(
    object_type: ObjectType,
    profile_id: &str,
    profile_version: u16,
    canonical_signing_object: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let profile_length = u16::try_from(profile_id.len()).map_err(|_| CodecError::LimitExceeded)?;
    let object_length =
        u64::try_from(canonical_signing_object.len()).map_err(|_| CodecError::LimitExceeded)?;
    let capacity = SIGNING_PREFIX
        .len()
        .checked_add(2 + 2 + 2 + 2 + 8)
        .and_then(|value| value.checked_add(profile_id.len()))
        .and_then(|value| value.checked_add(canonical_signing_object.len()))
        .ok_or(CodecError::LimitExceeded)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(SIGNING_PREFIX);
    output.extend_from_slice(&PROTOCOL_V1.to_be_bytes());
    output.extend_from_slice(&(object_type as u16).to_be_bytes());
    output.extend_from_slice(&profile_length.to_be_bytes());
    output.extend_from_slice(profile_id.as_bytes());
    output.extend_from_slice(&profile_version.to_be_bytes());
    output.extend_from_slice(&object_length.to_be_bytes());
    output.extend_from_slice(canonical_signing_object);
    Ok(output)
}

/// Derives the content identifier of a grant statement.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the statement fails.
pub fn grant_id(statement: &GrantStatement) -> Result<GrantId, CodecError> {
    Ok(GrantId::from_digest(domain_hash(
        IdentifierType::Grant,
        &encode_grant_statement(statement)?,
    )?))
}

/// Derives the content identifier of an action envelope.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the envelope fails.
pub fn action_id(envelope: &ActionEnvelope) -> Result<ActionId, CodecError> {
    Ok(ActionId::from_digest(domain_hash(
        IdentifierType::Action,
        &encode_action_envelope(envelope)?,
    )?))
}

/// Derives the content identifier of an authorization plan.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the plan fails.
pub fn plan_id(plan: &auths_model::AuthorizationPlan) -> Result<PlanId, CodecError> {
    Ok(PlanId::from_digest(domain_hash(
        IdentifierType::Plan,
        &encode_authorization_plan(plan)?,
    )?))
}

/// Derives the declared identifier of one evidence object's content.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the evidence fails.
pub fn evidence_id(evidence: &EvidenceObject) -> Result<EvidenceId, CodecError> {
    Ok(EvidenceId::from_digest(domain_hash(
        IdentifierType::Evidence,
        &encode_evidence_content(evidence)?,
    )?))
}

/// Derives the content identifier of a principal-status statement.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the statement fails.
pub fn principal_status_id(
    statement: &PrincipalStatusStatement,
) -> Result<PrincipalStatusId, CodecError> {
    Ok(PrincipalStatusId::from_digest(domain_hash(
        IdentifierType::PrincipalStatus,
        &encode_principal_status_statement(statement)?,
    )?))
}

/// Derives the content identifier of a grant-status statement.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the statement fails.
pub fn grant_status_id(statement: &GrantStatusStatement) -> Result<GrantStatusId, CodecError> {
    Ok(GrantStatusId::from_digest(domain_hash(
        IdentifierType::GrantStatus,
        &encode_grant_status_statement(statement)?,
    )?))
}

/// Hashes exact profile-canonical action bytes.
#[must_use]
pub fn body_digest(canonical_body: &[u8]) -> Digest {
    raw_sha256(canonical_body)
}

/// Hashes exact detached attachment bytes.
#[must_use]
pub fn attachment_digest(attachment: &[u8]) -> AttachmentDigest {
    AttachmentDigest::from_digest(raw_sha256(attachment))
}

/// Hashes exact deterministic proof-bundle bytes for receipts and caches.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the bundle fails.
pub fn proof_digest(bundle: &ProofBundle) -> Result<Digest, CodecError> {
    Ok(raw_sha256(&encode_bundle(bundle)?))
}

/// Derives the deterministic public trusted-context digest.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the context fails.
pub fn context_digest(context: &TrustedContext) -> Result<ContextDigest, CodecError> {
    Ok(ContextDigest::from_digest(domain_hash(
        IdentifierType::Context,
        &encode_verifier_context(context)?,
    )?))
}

/// Computes the digest of the canonical portable-result projection with the
/// self-digest field zeroed.
///
/// # Errors
///
/// Returns [`CodecError`] when the result cannot be encoded canonically.
pub fn verification_result_digest(
    result: &PortableVerificationResult,
) -> Result<VerificationResultDigest, CodecError> {
    Ok(VerificationResultDigest::from_digest(raw_sha256(
        &encode_verification_result_digest_input(result)?,
    )))
}

/// Constructs the exact domain-separated grant signing preimage.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn grant_signing_preimage(
    statement: &GrantStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::Grant,
        statement.profile().id().as_str(),
        statement.profile().version(),
        &encode_grant_signing_input(statement, descriptor)?,
    )
}

/// Constructs the exact domain-separated action signing preimage.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn action_signing_preimage(
    envelope: &ActionEnvelope,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::Action,
        envelope.profile().id().as_str(),
        envelope.profile().version(),
        &encode_action_signing_input(envelope, descriptor)?,
    )
}

/// Constructs the exact domain-separated principal-status signing preimage.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn principal_status_signing_preimage(
    statement: &PrincipalStatusStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::PrincipalStatus,
        "",
        0,
        &crate::encode_principal_status_signing_input(statement, descriptor)?,
    )
}

/// Constructs the exact domain-separated grant-status signing preimage.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn grant_status_signing_preimage(
    statement: &GrantStatusStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::GrantStatus,
        "",
        0,
        &crate::encode_grant_status_signing_input(statement, descriptor)?,
    )
}
