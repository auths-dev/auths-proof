// Frozen test-only protocol oracle from ce7f1f3c.
// Only module paths are relocated; do not update this copy with production refactors.
//! Deterministic encoding of approval requirements, approver anchors, signed
//! approvals, and reported approval satisfactions.

use super::cbor::Decoder;
use super::{
    CodecError,
    decode::{
        V1Decoder, array, digest_bytes, ensure_complete, evidence, is_null, key, map, null,
        optional_budget, parsed_texts, signature, status_policy, text,
    },
    encode::{
        V1Encoder, array as encode_array, bytes, encode_error, encode_evidence,
        encode_optional_budget, encode_signature, encode_signature_descriptor,
        encode_status_policy, finish, key as encode_key, map as encode_map, text as encode_text,
    },
};
use alloc::vec::Vec;
use auths_model::{
    ApprovalDigest, ApprovalRequirement, ApprovalRequirementId, ApprovalRequirements,
    ApprovalSatisfaction, ApprovalStatement, ApproverAnchor, Audience, Challenge, Digest,
    LimitKind, MAX_APPROVAL_EVIDENCE, MAX_APPROVAL_REQUIREMENTS_PER_GRANT,
    MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION, MAX_APPROVERS_PER_REQUIREMENT,
    MAX_SIGNED_APPROVAL_BYTES, MediaType, PrincipalId, PrincipalMethodId, ProtocolVersion,
    SignatureDescriptor, SignedApproval, Timestamp, ValidityWindow, VerifierLimits,
};

fn timestamp(decoder: &mut V1Decoder<'_>) -> Result<Timestamp, CodecError> {
    Ok(Timestamp::new(
        decoder.u64().map_err(|_| CodecError::Malformed)?,
    ))
}

pub(crate) fn encode_approval_requirement_to(
    encoder: &mut V1Encoder,
    requirement: &ApprovalRequirement,
) -> Result<(), CodecError> {
    encode_map(encoder, 2)?;
    encode_key(encoder, 0)?;
    encode_array(encoder, requirement.approvers().len())?;
    for approver in requirement.approvers() {
        encode_text(encoder, approver.as_str())?;
    }
    encode_key(encoder, 1)?;
    encoder.u16(requirement.threshold()).map_err(encode_error)?;
    Ok(())
}

fn approval_requirement(decoder: &mut V1Decoder<'_>) -> Result<ApprovalRequirement, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let approvers = parsed_texts(decoder, MAX_APPROVERS_PER_REQUIREMENT, PrincipalId::parse)?;
    key(decoder, 1)?;
    let threshold = decoder.u16().map_err(|_| CodecError::Malformed)?;
    ApprovalRequirement::new(approvers, threshold).map_err(CodecError::from)
}

/// Encodes one approval requirement as its canonical content bytes, the
/// input of its identifier.
///
/// # Errors
///
/// Returns [`CodecError`] if the requirement cannot be represented.
pub fn encode_approval_requirement(
    requirement: &ApprovalRequirement,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_approval_requirement_to(encoder, requirement))
}

/// Returns the requirements paired with their identifiers, in ascending
/// identifier order, the canonical order of every requirement list.
///
/// # Errors
///
/// Returns [`CodecError`] if an identifier cannot be derived.
pub fn sorted_approval_requirements(
    requirements: &[ApprovalRequirement],
) -> Result<Vec<(ApprovalRequirementId, &ApprovalRequirement)>, CodecError> {
    let mut sorted = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        sorted.push((super::approval_requirement_id(requirement)?, requirement));
    }
    sorted.sort_by_key(|(identifier, _)| *identifier);
    Ok(sorted)
}

fn encode_requirement_list_to(
    encoder: &mut V1Encoder,
    requirements: &[ApprovalRequirement],
) -> Result<(), CodecError> {
    let sorted = sorted_approval_requirements(requirements)?;
    encode_array(encoder, sorted.len())?;
    for (_, requirement) in sorted {
        encode_approval_requirement_to(encoder, requirement)?;
    }
    Ok(())
}

/// Encodes the exact bytes of an `approval-requirement-v1` extension, in
/// ascending identifier order.
///
/// # Errors
///
/// Returns [`CodecError`] if the requirements cannot be represented.
pub fn encode_approval_requirements(
    requirements: &ApprovalRequirements,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_requirement_list_to(encoder, requirements.as_slice()))
}

/// Decodes the exact bytes of an `approval-requirement-v1` extension.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above four requirements or sixteen
/// approvers, and a typed error for malformed, invalid, or non-canonical
/// bytes, including requirements out of identifier order.
pub fn decode_approval_requirements(input: &[u8]) -> Result<ApprovalRequirements, CodecError> {
    if input.len() > auths_model::HARD_MAX_EXTENSION_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let count = array(&mut decoder, MAX_APPROVAL_REQUIREMENTS_PER_GRANT)?;
    let mut requirements = Vec::with_capacity(count);
    for _ in 0..count {
        requirements.push(approval_requirement(&mut decoder)?);
    }
    let requirements = ApprovalRequirements::new(requirements).map_err(|error| match error {
        auths_model::ModelError::CollectionLimitExceeded => CodecError::LimitExceeded,
        other => CodecError::Model(other),
    })?;
    ensure_complete(&decoder, input)?;
    if encode_approval_requirements(&requirements)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(requirements)
}

pub(crate) fn encode_context_requirements(
    encoder: &mut V1Encoder,
    requirements: &[ApprovalRequirement],
) -> Result<(), CodecError> {
    encode_requirement_list_to(encoder, requirements)
}

pub(crate) fn context_requirements(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<ApprovalRequirement>, CodecError> {
    let count = array(decoder, limits.get(LimitKind::ApprovalRequirements))?;
    let mut requirements = Vec::with_capacity(count);
    for _ in 0..count {
        requirements.push(approval_requirement(decoder)?);
    }
    Ok(requirements)
}

pub(crate) fn encode_approver_anchors(
    encoder: &mut V1Encoder,
    anchors: &[ApproverAnchor],
) -> Result<(), CodecError> {
    encode_array(encoder, anchors.len())?;
    for anchor in anchors {
        encode_map(encoder, 5)?;
        encode_key(encoder, 0)?;
        encode_text(encoder, anchor.principal().as_str())?;
        encode_key(encoder, 1)?;
        encode_array(encoder, anchor.accepted_methods().len())?;
        for method in anchor.accepted_methods() {
            encode_text(encoder, method.as_str())?;
        }
        encode_key(encoder, 2)?;
        encoder
            .u64(anchor.validity().not_before().get())
            .map_err(encode_error)?;
        encode_key(encoder, 3)?;
        encoder
            .u64(anchor.validity().expires_at().get())
            .map_err(encode_error)?;
        encode_key(encoder, 4)?;
        encode_status_policy(encoder, anchor.status_policy())?;
    }
    Ok(())
}

pub(crate) fn approver_anchors(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<ApproverAnchor>, CodecError> {
    let count = array(decoder, limits.get(LimitKind::ApproverAnchors))?;
    let mut anchors = Vec::with_capacity(count);
    for _ in 0..count {
        map(decoder, 5)?;
        key(decoder, 0)?;
        let principal = PrincipalId::parse(text(decoder)?)?;
        key(decoder, 1)?;
        let methods = parsed_texts(
            decoder,
            limits.get(LimitKind::RegistryEntries),
            PrincipalMethodId::parse,
        )?;
        key(decoder, 2)?;
        let not_before = timestamp(decoder)?;
        key(decoder, 3)?;
        let expires_at = timestamp(decoder)?;
        key(decoder, 4)?;
        let status = status_policy(decoder)?;
        anchors.push(ApproverAnchor::new(
            principal,
            methods,
            ValidityWindow::new(not_before, expires_at)?,
            status,
        )?);
    }
    Ok(anchors)
}

pub(crate) fn encode_approval_statement_to(
    encoder: &mut V1Encoder,
    statement: &ApprovalStatement,
) -> Result<(), CodecError> {
    encode_map(encoder, 13)?;
    encode_key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    encode_key(encoder, 1)?;
    encode_text(encoder, statement.approver().as_str())?;
    encode_key(encoder, 2)?;
    bytes(encoder, statement.requirement().as_bytes())?;
    encode_key(encoder, 3)?;
    encode_text(encoder, statement.media_type().as_str())?;
    encode_key(encoder, 4)?;
    bytes(encoder, statement.body_digest().as_bytes())?;
    encode_key(encoder, 5)?;
    encode_text(encoder, statement.permission().capability().as_str())?;
    encode_key(encoder, 6)?;
    encode_text(encoder, statement.permission().resource().as_str())?;
    encode_key(encoder, 7)?;
    encode_optional_budget(encoder, statement.requested_budget())?;
    encode_key(encoder, 8)?;
    if let Some(attributes) = statement.attributes() {
        bytes(encoder, attributes.as_bytes())?;
    } else {
        encoder.null();
    }
    encode_key(encoder, 9)?;
    encode_text(encoder, statement.audience().as_str())?;
    encode_key(encoder, 10)?;
    bytes(encoder, statement.challenge().as_bytes())?;
    encode_key(encoder, 11)?;
    encoder
        .u64(statement.validity().not_before().get())
        .map_err(encode_error)?;
    encode_key(encoder, 12)?;
    encoder
        .u64(statement.validity().expires_at().get())
        .map_err(encode_error)?;
    Ok(())
}

fn approval_statement(decoder: &mut V1Decoder<'_>) -> Result<ApprovalStatement, CodecError> {
    map(decoder, 13)?;
    key(decoder, 0)?;
    ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let approver = PrincipalId::parse(text(decoder)?)?;
    key(decoder, 2)?;
    let requirement = ApprovalRequirementId::new(digest_bytes(decoder)?);
    key(decoder, 3)?;
    let media_type = MediaType::parse(text(decoder)?)?;
    key(decoder, 4)?;
    let body_digest = Digest::new(digest_bytes(decoder)?);
    key(decoder, 5)?;
    let capability = auths_model::CapabilityId::parse(text(decoder)?)?;
    key(decoder, 6)?;
    let resource = auths_model::ResourceId::parse(text(decoder)?)?;
    key(decoder, 7)?;
    let requested_budget = optional_budget(decoder)?;
    key(decoder, 8)?;
    let attributes = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(Digest::new(digest_bytes(decoder)?))
    };
    key(decoder, 9)?;
    let audience = Audience::parse(text(decoder)?)?;
    key(decoder, 10)?;
    let challenge = Challenge::new(digest_bytes(decoder)?);
    key(decoder, 11)?;
    let not_before = timestamp(decoder)?;
    key(decoder, 12)?;
    let expires_at = timestamp(decoder)?;
    Ok(ApprovalStatement::new(
        approver,
        requirement,
        media_type,
        body_digest,
        auths_model::Permission::new(capability, resource),
        requested_budget,
        attributes,
        audience,
        challenge,
        ValidityWindow::new(not_before, expires_at)?,
    ))
}

/// Encodes the canonical unsigned approval statement.
///
/// # Errors
///
/// Returns [`CodecError`] if the statement cannot be represented.
pub fn encode_approval_statement(statement: &ApprovalStatement) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_approval_statement_to(encoder, statement))
}

/// Encodes the canonical approval signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the statement cannot be represented.
pub fn encode_approval_signing_input(
    statement: &ApprovalStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| {
        encode_map(encoder, 2)?;
        encode_key(encoder, 0)?;
        encode_approval_statement_to(encoder, statement)?;
        encode_key(encoder, 1)?;
        encode_signature_descriptor(encoder, descriptor)
    })
}

pub(crate) fn encode_signed_approval_to(
    encoder: &mut V1Encoder,
    approval: &SignedApproval,
) -> Result<(), CodecError> {
    encode_map(encoder, 3)?;
    encode_key(encoder, 0)?;
    encode_approval_statement_to(encoder, approval.statement())?;
    encode_key(encoder, 1)?;
    encode_signature(encoder, approval.signature())?;
    encode_key(encoder, 2)?;
    encode_array(encoder, approval.evidence().len())?;
    for object in approval.evidence() {
        encode_evidence(encoder, object)?;
    }
    Ok(())
}

/// Encodes one signed approval.
///
/// # Errors
///
/// Returns [`CodecError`] if the approval cannot be represented.
pub fn encode_signed_approval(approval: &SignedApproval) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_signed_approval_to(encoder, approval))
}

/// Decodes one signed approval from inside a proof bundle and enforces its
/// 4 KiB bound over the bytes it occupies.
pub(crate) fn signed_approval(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignedApproval, CodecError> {
    let start = decoder.position();
    map(decoder, 3)?;
    key(decoder, 0)?;
    let statement = approval_statement(decoder)?;
    key(decoder, 1)?;
    let signature = signature(decoder, limits)?;
    key(decoder, 2)?;
    let count = array(decoder, MAX_APPROVAL_EVIDENCE)?;
    let mut objects = Vec::with_capacity(count);
    for _ in 0..count {
        objects.push(evidence(decoder, limits)?);
    }
    if decoder.position().saturating_sub(start) > MAX_SIGNED_APPROVAL_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    SignedApproval::new(statement, signature, objects).map_err(CodecError::from)
}

/// Decodes one standalone unsigned approval statement of at most 4 KiB, the
/// bound a signed approval carrying it obeys.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above the byte bound, and a typed
/// error for malformed, non-canonical, or invalid bytes.
pub fn decode_approval_statement(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<ApprovalStatement, CodecError> {
    limits.validate()?;
    if input.len() > MAX_SIGNED_APPROVAL_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let statement = approval_statement(&mut decoder)?;
    ensure_complete(&decoder, input)?;
    if encode_approval_statement(&statement)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(statement)
}

/// Decodes one standalone signed approval of at most 4 KiB.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above the byte or evidence bounds,
/// and a typed error for malformed, non-canonical, or invalid bytes.
pub fn decode_signed_approval(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<SignedApproval, CodecError> {
    limits.validate()?;
    if input.len() > MAX_SIGNED_APPROVAL_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let approval = signed_approval(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_signed_approval(&approval)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(approval)
}

pub(crate) fn encode_approval_satisfactions(
    encoder: &mut V1Encoder,
    satisfactions: &[ApprovalSatisfaction],
) -> Result<(), CodecError> {
    encode_array(encoder, satisfactions.len())?;
    for satisfaction in satisfactions {
        encode_map(encoder, 2)?;
        encode_key(encoder, 0)?;
        bytes(encoder, satisfaction.requirement().as_bytes())?;
        encode_key(encoder, 1)?;
        encode_array(encoder, satisfaction.approvals().len())?;
        for approval in satisfaction.approvals() {
            bytes(encoder, approval.as_bytes())?;
        }
    }
    Ok(())
}

pub(crate) fn approval_satisfactions(
    decoder: &mut V1Decoder<'_>,
) -> Result<Vec<ApprovalSatisfaction>, CodecError> {
    let count = array(decoder, MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION)?;
    let mut satisfactions = Vec::with_capacity(count);
    for _ in 0..count {
        map(decoder, 2)?;
        key(decoder, 0)?;
        let requirement = ApprovalRequirementId::new(digest_bytes(decoder)?);
        key(decoder, 1)?;
        let approvals_count = array(decoder, MAX_APPROVERS_PER_REQUIREMENT)?;
        let mut approvals = Vec::with_capacity(approvals_count);
        for _ in 0..approvals_count {
            approvals.push(ApprovalDigest::new(digest_bytes(decoder)?));
        }
        satisfactions.push(ApprovalSatisfaction::new(requirement, approvals)?);
    }
    Ok(satisfactions)
}

