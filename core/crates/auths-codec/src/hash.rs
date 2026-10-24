//! Target V1 domain separation and content identifiers.

use crate::{
    CodecError,
    encode::{
        encode_bundle_value, encode_evidence_content, encode_grant_status_statement,
        encode_principal_status_statement, encode_verification_result_digest_input,
        encode_verifier_context_value,
    },
    encode_action_envelope, encode_action_signing_input, encode_authorization_plan,
    encode_grant_signing_input, encode_grant_statement,
};
use alloc::vec::Vec;
use auths_model::{
    ActionEnvelope, ActionId, ApprovalDigest, ApprovalRequirement, ApprovalRequirementId,
    ApprovalStatement, AttachmentDigest, ContextDigest, Digest, EvidenceId, EvidenceObject,
    GrantId, GrantStatement, GrantStatusId, GrantStatusStatement, ObservationRequirement,
    ObservationRequirementId, ObservationStatement, PROTOCOL_V1, PlanId,
    PortableVerificationResult, PrincipalStatusId, PrincipalStatusStatement, ProfileRef,
    ProofBundle, SignatureDescriptor, SignedApproval, TrustedContext, VerificationResultDigest,
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
    Observation = 9,
    Approval = 10,
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
    ObservationRequirement = 11,
    ApprovalRequirement = 12,
}

fn raw_sha256(value: &[u8]) -> Digest {
    Digest::new(Sha256::digest(value).into())
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
    Ok(raw_sha256(&commitment_preimage(domain, canonical)?))
}

fn preimage_buffer(capacity: usize) -> Result<Vec<u8>, CodecError> {
    // Vec's representable capacity is at most isize::MAX, even when the
    // checked unsigned sum fits usize. Allocation failure remains the same
    // standard-library/host boundary as the existing canonical encoders.
    let _ = isize::try_from(capacity).map_err(crate::error::limit_error)?;
    Ok(Vec::with_capacity(capacity))
}

fn commitment_preimage(domain: &str, canonical: &[u8]) -> Result<Vec<u8>, CodecError> {
    let domain_bytes = domain.as_bytes();
    if domain_bytes.is_empty() || domain_bytes.len() > MAX_COMMITMENT_DOMAIN_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let domain_length = u16::try_from(domain_bytes.len()).map_err(crate::error::limit_error)?;
    let payload_length = u64::try_from(canonical.len()).map_err(crate::error::limit_error)?;
    let capacity = COMMITMENT_PREFIX
        .len()
        .checked_add(2 + 2 + 8)
        .and_then(|size| size.checked_add(domain_bytes.len()))
        .and_then(|size| size.checked_add(canonical.len()))
        .ok_or(CodecError::LimitExceeded)?;
    let mut output = preimage_buffer(capacity)?;
    output.extend_from_slice(COMMITMENT_PREFIX);
    output.extend_from_slice(&PROTOCOL_V1.to_be_bytes());
    output.extend_from_slice(&domain_length.to_be_bytes());
    output.extend_from_slice(domain_bytes);
    output.extend_from_slice(&payload_length.to_be_bytes());
    output.extend_from_slice(canonical);
    Ok(output)
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
    Ok(raw_sha256(&identifier_preimage(
        identifier_type,
        canonical,
    )?))
}

fn identifier_preimage(
    identifier_type: IdentifierType,
    canonical: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let canonical_length = u64::try_from(canonical.len()).map_err(crate::error::limit_error)?;
    let capacity = IDENTIFIER_PREFIX
        .len()
        .checked_add(2 + 2 + 8)
        .and_then(|size| size.checked_add(canonical.len()))
        .ok_or(CodecError::LimitExceeded)?;
    let mut output = preimage_buffer(capacity)?;
    output.extend_from_slice(IDENTIFIER_PREFIX);
    output.extend_from_slice(&PROTOCOL_V1.to_be_bytes());
    output.extend_from_slice(&(identifier_type as u16).to_be_bytes());
    output.extend_from_slice(&canonical_length.to_be_bytes());
    output.extend_from_slice(canonical);
    Ok(output)
}

fn signing_preimage(
    object_type: ObjectType,
    profile_id: &str,
    profile_version: u16,
    canonical_signing_object: &[u8],
) -> Result<Vec<u8>, CodecError> {
    let profile_length = u16::try_from(profile_id.len()).map_err(crate::error::limit_error)?;
    let object_length =
        u64::try_from(canonical_signing_object.len()).map_err(crate::error::limit_error)?;
    let capacity = SIGNING_PREFIX
        .len()
        .checked_add(2 + 2 + 2 + 2 + 8)
        .ok_or(CodecError::LimitExceeded)?;
    let capacity = capacity
        .checked_add(profile_id.len())
        .ok_or(CodecError::LimitExceeded)?;
    let capacity = capacity
        .checked_add(canonical_signing_object.len())
        .ok_or(CodecError::LimitExceeded)?;
    let mut output = preimage_buffer(capacity)?;
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
    Ok(raw_sha256(&encode_bundle_value(bundle)?))
}

/// Derives the deterministic public trusted-context digest.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the context fails.
pub fn context_digest(context: &TrustedContext) -> Result<ContextDigest, CodecError> {
    let (digest, _) = context_digest_and_size(context)?;
    Ok(digest)
}

/// Derives the public context commitment and its exact encoded byte count.
///
/// Both results describe the same deterministic encoding. This borrowed path
/// uses the canonical encoder's writer once, without cloning model payloads or
/// requiring callers to normalize a second owned context just to account for
/// its encoded size. The digest is a commitment, not an authorization verdict.
///
/// # Errors
///
/// Returns [`CodecError`] if context encoding or commitment derivation fails.
pub fn context_digest_and_size(context: &TrustedContext) -> Result<(ContextDigest, usize), CodecError> {
    let encoded = encode_verifier_context_value(context)?;
    let digest = ContextDigest::from_digest(domain_hash(IdentifierType::Context, &encoded)?);
    Ok((digest, encoded.len()))
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

/// Constructs the exact domain-separated observation signing preimage.
///
/// Observations are profile-independent: the preimage uses the registered
/// observation object type, an empty profile identifier, and version zero.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn observation_signing_preimage(
    statement: &ObservationStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::Observation,
        "",
        0,
        &crate::encode_observation_signing_input(statement, descriptor)?,
    )
}

/// Derives the content identifier of one observation requirement.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the requirement fails.
pub fn observation_requirement_id(
    requirement: &ObservationRequirement,
) -> Result<ObservationRequirementId, CodecError> {
    Ok(ObservationRequirementId::from_digest(domain_hash(
        IdentifierType::ObservationRequirement,
        &crate::encode_observation_requirement(requirement)?,
    )?))
}

/// Derives the content identifier of one approval requirement.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding of the requirement fails.
pub fn approval_requirement_id(
    requirement: &ApprovalRequirement,
) -> Result<ApprovalRequirementId, CodecError> {
    Ok(ApprovalRequirementId::from_digest(domain_hash(
        IdentifierType::ApprovalRequirement,
        &crate::encode_approval_requirement(requirement)?,
    )?))
}

/// Constructs the exact domain-separated approval signing preimage.
///
/// An approval is signed with the approved action's profile identifier and
/// version, so an approval for one profile never verifies for another.
///
/// # Errors
///
/// Returns [`CodecError`] if deterministic encoding or bounded framing fails.
pub fn approval_signing_preimage(
    statement: &ApprovalStatement,
    descriptor: &SignatureDescriptor,
    profile: &ProfileRef,
) -> Result<Vec<u8>, CodecError> {
    signing_preimage(
        ObjectType::Approval,
        profile.id().as_str(),
        profile.version(),
        &crate::encode_approval_signing_input(statement, descriptor)?,
    )
}

/// Hashes the exact canonical bytes of one signed approval.
///
/// # Errors
///
/// Returns [`CodecError`] if the approval cannot be encoded.
pub fn approval_digest(approval: &SignedApproval) -> Result<ApprovalDigest, CodecError> {
    Ok(ApprovalDigest::from_digest(raw_sha256(
        &crate::approval::encode_signed_approval_value(approval)?,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;
    use proptest::prelude::*;

    fn signing_preimage_reference(
        object_type: ObjectType,
        profile_id: &str,
        profile_version: u16,
        canonical_signing_object: &[u8],
    ) -> Result<Vec<u8>, CodecError> {
        let profile_length =
            u16::try_from(profile_id.len()).map_err(|_| CodecError::LimitExceeded)?;
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

    fn object_types() -> [ObjectType; 6] {
        [
            ObjectType::Grant,
            ObjectType::Action,
            ObjectType::PrincipalStatus,
            ObjectType::GrantStatus,
            ObjectType::Observation,
            ObjectType::Approval,
        ]
    }

    fn identifier_types() -> [IdentifierType; 9] {
        [
            IdentifierType::Grant,
            IdentifierType::Action,
            IdentifierType::Plan,
            IdentifierType::Evidence,
            IdentifierType::PrincipalStatus,
            IdentifierType::GrantStatus,
            IdentifierType::Context,
            IdentifierType::ObservationRequirement,
            IdentifierType::ApprovalRequirement,
        ]
    }

    proptest! {
        #[test]
        fn signing_frame_preserves_bytes_and_errors(
            profile in any::<String>(), version in any::<u16>(),
            statement in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            for kind in object_types() {
                prop_assert_eq!(signing_preimage(kind, &profile, version, &statement),
                    signing_preimage_reference(kind, &profile, version, &statement));
            }
        }

        #[test]
        fn one_shot_hashes_preserve_independent_streaming_transcripts(
            domain in any::<String>(),
            payload in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            if domain.is_empty() || domain.len() > 128 {
                prop_assert_eq!(domain_commitment(&domain, &payload), Err(CodecError::LimitExceeded));
            } else {
                let mut reference = Sha256::new();
                reference.update(b"AUTHS-COMMITMENT");
                reference.update(1_u16.to_be_bytes());
                reference.update(u16::try_from(domain.len()).unwrap().to_be_bytes());
                reference.update(domain.as_bytes());
                reference.update(u64::try_from(payload.len()).unwrap().to_be_bytes());
                reference.update(&payload);
                prop_assert_eq!(domain_commitment(&domain, &payload),
                    Ok(Digest::new(reference.finalize().into())));
            }
            for kind in identifier_types() {
                let mut reference = Sha256::new();
                reference.update(b"AUTHS-ID");
                reference.update(1_u16.to_be_bytes());
                reference.update((kind as u16).to_be_bytes());
                reference.update(u64::try_from(payload.len()).unwrap().to_be_bytes());
                reference.update(&payload);
                prop_assert_eq!(domain_hash(kind, &payload),
                    Ok(Digest::new(reference.finalize().into())));
            }
        }
    }

    #[test]
    fn commitment_domain_bound_counts_utf8_bytes() {
        for (domain, accepted) in [
            (String::new(), false),
            ("a".repeat(128), true),
            ("a".repeat(129), false),
            ("λ".repeat(64), true),
            ("λ".repeat(64) + "a", false),
        ] {
            let actual = commitment_preimage(&domain, &[0, 255]);
            if accepted {
                assert_eq!(actual.as_ref().map(Vec::len), Ok(28 + domain.len() + 2));
            } else {
                assert_eq!(actual, Err(CodecError::LimitExceeded));
            }
        }
    }

    #[test]
    fn preimage_capacity_refuses_before_unrepresentable_allocation() {
        let first_unrepresentable = usize::try_from(isize::MAX).unwrap() + 1;
        assert_eq!(
            preimage_buffer(first_unrepresentable),
            Err(CodecError::LimitExceeded)
        );
        assert_eq!(preimage_buffer(usize::MAX), Err(CodecError::LimitExceeded));
        assert_eq!(preimage_buffer(0), Ok(Vec::new()));
        assert_eq!(preimage_buffer(32), Ok(Vec::new()));
    }

    #[test]
    fn signing_frame_profile_limit_counts_utf8_bytes_exactly() {
        for profile in [
            String::new(),
            "a".repeat(65535),
            "a".repeat(65536),
            "λ".repeat(32767) + "a",
            "λ".repeat(32768),
        ] {
            for kind in object_types() {
                let actual = signing_preimage(kind, &profile, u16::MAX, &[0, 255]);
                assert_eq!(
                    actual,
                    signing_preimage_reference(kind, &profile, u16::MAX, &[0, 255])
                );
                if profile.len() > usize::from(u16::MAX) {
                    assert_eq!(actual, Err(CodecError::LimitExceeded));
                } else {
                    assert_eq!(actual.as_ref().map(Vec::len), Ok(21 + profile.len() + 2));
                }
            }
        }
    }
}
