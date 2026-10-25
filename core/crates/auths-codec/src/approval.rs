//! Deterministic encoding of approval requirements, approver anchors, signed
//! approvals, and reported approval satisfactions.

use crate::cbor::{Decoder, Encoder};
use crate::{
    CanonicalSignedApproval, CodecError,
    decode::{
        V1Decoder, array, digest_bytes, ensure_complete, evidence, is_null, key, map, null,
        optional_budget, signature, status_policy, text,
    },
    encode::{
        V1Encoder, array as encode_array, bytes, encode_error,
        encode_optional_budget, encode_signature, encode_signature_descriptor,
        encode_status_policy, key as encode_key, map as encode_map, text as encode_text,
    },
};
use alloc::vec::Vec;
use auths_model::{
    ApprovalDigest, ApprovalRequirement, ApprovalRequirementId, ApprovalRequirements,
    ApprovalSatisfaction, ApprovalStatement, ApproverAnchor, Audience, Challenge, Digest,
    LimitKind, MAX_APPROVAL_EVIDENCE, MAX_APPROVAL_REQUIREMENTS_PER_GRANT,
    MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION, MAX_APPROVERS_PER_REQUIREMENT,
    MAX_SIGNED_APPROVAL_BYTES, MediaType, PrincipalId, ProtocolVersion,
    SignatureDescriptor, SignedApproval, Timestamp, ValidityWindow, VerifierLimits,
};

// Keep the concrete borrowed sorting/array layouts within the formal native
// reference-capacity envelope. Payloads remain borrowed throughout encoding.
const _: () = {
    assert!(core::mem::size_of::<(ApprovalRequirementId, &ApprovalRequirement)>() <= 40);
    assert!(core::mem::size_of::<&ApprovalRequirement>() <= 8);
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
    crate::text_list::encode_principal_ids(encoder, requirement.approvers())?;
    encode_key(encoder, 1)?;
    encoder.u16(requirement.threshold()).map_err(encode_error)?;
    Ok(())
}

fn approval_requirement(decoder: &mut V1Decoder<'_>) -> Result<ApprovalRequirement, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let approvers = crate::text_list::principal_ids(decoder, MAX_APPROVERS_PER_REQUIREMENT)?;
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
    let mut encoder = Encoder::new(Vec::new());
    encode_approval_requirement_to(&mut encoder, requirement)?;
    Ok(encoder.into_writer())
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
    Ok(sort_requirement_ref_keys(derive_requirement_ref_keys(requirements)?))
}

fn derive_requirement_ref_keys(
    requirements: &[ApprovalRequirement],
) -> Result<Vec<(ApprovalRequirementId, &ApprovalRequirement)>, CodecError> {
    crate::collections::try_fold_items!(requirements,
        Vec::with_capacity(requirements.len()), current, _index, requirement =>
            push_keyed_requirement(current, requirement))
}

fn requirement_ref_sort_key(entry: &(ApprovalRequirementId, &ApprovalRequirement)) -> ApprovalRequirementId {
    entry.0
}

fn sort_requirement_ref_keys<'a>(
    mut values: Vec<(ApprovalRequirementId, &'a ApprovalRequirement)>,
) -> Vec<(ApprovalRequirementId, &'a ApprovalRequirement)> {
    values.sort_by_key(requirement_ref_sort_key);
    values
}

fn sorted_requirement_refs(requirements: &[ApprovalRequirement]) -> Result<Vec<&ApprovalRequirement>, CodecError> {
    Ok(crate::canonical_value::unkey_records(sorted_approval_requirements(requirements)?))
}

pub(crate) fn normalize_requirement_values(
    requirements: &[ApprovalRequirement],
    maximum: usize,
) -> Result<Vec<ApprovalRequirement>, CodecError> {
    if requirements.len() > maximum {
        return Err(CodecError::LimitExceeded);
    }
    let sorted = sorted_approval_requirements(requirements)?;
    let mut output = Vec::with_capacity(sorted.len());
    let mut position = 0;
    while position < sorted.len() {
        output.push(sorted[position].1.clone());
        position += 1;
    }
    Ok(output)
}

fn encode_requirement_values_to(
    encoder: &mut V1Encoder,
    requirements: &[ApprovalRequirement],
) -> Result<(), CodecError> {
    encode_array(encoder, requirements.len())?;
    crate::collections::write_items!(requirements, requirement => encode_approval_requirement_to(encoder, requirement))?;
    Ok(())
}

/// Encodes the exact bytes of an `approval-requirement-v1` extension, in
/// ascending identifier order.
///
/// # Errors
///
/// Returns [`CodecError`] if the canonical value cannot be represented. The
/// encoder writes its stored order and does not normalize a raw model value.
pub fn encode_approval_requirements(
    requirements: &crate::CanonicalApprovalRequirements,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_requirement_values_to(&mut encoder, requirements.as_slice())?;
    Ok(encoder.into_writer())
}

/// Decodes the exact bytes of an `approval-requirement-v1` extension.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above four requirements or sixteen
/// approvers, and a typed error for malformed, invalid, or non-canonical
/// bytes, including requirements out of identifier order.
pub fn decode_approval_requirements(input: &[u8]) -> Result<crate::CanonicalApprovalRequirements, CodecError> {
    if input.len() > auths_model::HARD_MAX_EXTENSION_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let count = array(&mut decoder, MAX_APPROVAL_REQUIREMENTS_PER_GRANT)?;
    let requirements = crate::collections::read_items!(count, approval_requirement(&mut decoder))?;
    let requirements = ApprovalRequirements::new(requirements).map_err(|error| match error {
        auths_model::ModelError::CollectionLimitExceeded => CodecError::LimitExceeded,
        other => CodecError::Model(other),
    })?;
    ensure_complete(&decoder, input)?;
    let requirements = crate::CanonicalApprovalRequirements::new(requirements)?;
    crate::canonical::accept(input, encode_approval_requirements(&requirements)?, requirements)
}

pub(crate) fn encode_context_requirements(
    encoder: &mut V1Encoder,
    requirements: &[ApprovalRequirement],
) -> Result<(), CodecError> {
    if requirements.len() > MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION {
        return Err(CodecError::LimitExceeded);
    }
    let ordered = sorted_requirement_refs(requirements)?;
    encode_requirement_refs(encoder, ordered)
}

fn encode_requirement_refs(encoder: &mut V1Encoder, requirements: Vec<&ApprovalRequirement>) -> Result<(), CodecError> {
    let requirements = requirements.as_slice();
    encode_array(encoder, requirements.len())?;
    crate::collections::write_items!(requirements, requirement => encode_approval_requirement_to(encoder, requirement))?;
    Ok(())
}

pub(crate) fn context_requirements(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<ApprovalRequirement>, CodecError> {
    let count = array(decoder, limits.get(LimitKind::ApprovalRequirements))?;
    let requirements = crate::collections::read_items!(count, approval_requirement(decoder))?;
    Ok(requirements)
}

pub(crate) fn encode_approver_anchors(
    encoder: &mut V1Encoder,
    anchors: &[ApproverAnchor],
) -> Result<(), CodecError> {
    encode_array(encoder, anchors.len())?;
    crate::collections::write_items!(anchors, anchor => encode_approver_anchor(encoder, anchor))?;
    Ok(())
}

pub(crate) fn approver_anchors(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<ApproverAnchor>, CodecError> {
    let count = array(decoder, limits.get(LimitKind::ApproverAnchors))?;
    let anchors = crate::collections::read_items!(count, approver_anchor(decoder, limits))?;
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
    let attributes = statement.attributes();
    let attribute_bytes = match attributes.as_ref() {
        Some(attributes) => Some(attributes.as_bytes()),
        None => None,
    };
    crate::encode::encode_optional_digest(encoder, attribute_bytes)?;
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
    let mut encoder = Encoder::new(Vec::new());
    encode_approval_statement_to(&mut encoder, statement)?;
    Ok(encoder.into_writer())
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
    let mut encoder = Encoder::new(Vec::new());
    encode_map(&mut encoder, 2)?;
    encode_key(&mut encoder, 0)?;
    encode_approval_statement_to(&mut encoder, statement)?;
    encode_key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
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
    crate::encode::encode_evidence_objects(encoder, approval.evidence())?;
    Ok(())
}

/// Encodes one signed approval.
/// Requires explicit canonical construction, including evidence content IDs.
///
/// # Errors
///
/// Returns [`CodecError`] if the approval cannot be represented.
pub fn encode_signed_approval(approval: &CanonicalSignedApproval) -> Result<Vec<u8>, CodecError> {
    encode_signed_approval_value(approval.as_value())
}

// The signed-object commitment uses this same borrowed writer. Hashing a raw
// model is not a claim that its evidence or signature has been authenticated.
pub(crate) fn encode_signed_approval_value(approval: &SignedApproval) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_approval_to(&mut encoder, approval)?;
    Ok(encoder.into_writer())
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
    let objects = crate::collections::read_items!(count, evidence(decoder, limits))?;
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
    crate::canonical::accept(input, encode_approval_statement(&statement)?, statement)
}

/// Decodes one standalone signed approval of at most 4 KiB.
/// Returns an immutable carrier with content-consistent evidence. The
/// signature and approver authority still require verification.
///
/// # Errors
///
/// Returns [`CodecError::LimitExceeded`] above the byte or evidence bounds,
/// and a typed error for malformed, non-canonical, or invalid bytes.
pub fn decode_signed_approval(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<CanonicalSignedApproval, CodecError> {
    limits.validate()?;
    if input.len() > MAX_SIGNED_APPROVAL_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let approval = signed_approval(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    let approval = crate::canonical_value::checked_signed_approval(approval)?;
    crate::canonical::accept(input, encode_signed_approval(&approval)?, approval)
}

pub(crate) fn encode_approval_satisfactions(
    encoder: &mut V1Encoder,
    satisfactions: &[ApprovalSatisfaction],
) -> Result<(), CodecError> {
    encode_array(encoder, satisfactions.len())?;
    crate::collections::write_items!(satisfactions, satisfaction => encode_approval_satisfaction(encoder, satisfaction))?;
    Ok(())
}

pub(crate) fn approval_satisfactions(
    decoder: &mut V1Decoder<'_>,
) -> Result<Vec<ApprovalSatisfaction>, CodecError> {
    let count = array(decoder, MAX_APPROVAL_REQUIREMENTS_PER_VERIFICATION)?;
    let satisfactions = crate::collections::read_items!(count, approval_satisfaction(decoder))?;
    Ok(satisfactions)
}

fn encode_approver_anchor(encoder: &mut V1Encoder, anchor: &ApproverAnchor) -> Result<(), CodecError> {
    encode_map(encoder, 5)?;
    encode_key(encoder, 0)?;
    encode_text(encoder, anchor.principal().as_str())?;
    encode_key(encoder, 1)?;
    crate::text_list::encode_principal_methods(encoder, anchor.accepted_methods())?;
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
    Ok(())
}

fn encode_approval_satisfaction(encoder: &mut V1Encoder, satisfaction: &ApprovalSatisfaction) -> Result<(), CodecError> {
    encode_map(encoder, 2)?;
    encode_key(encoder, 0)?;
    bytes(encoder, satisfaction.requirement().as_bytes())?;
    encode_key(encoder, 1)?;
    encode_approval_digests(encoder, satisfaction.approvals())?;
    Ok(())
}

fn encode_approval_digests(encoder: &mut V1Encoder, approvals: &[ApprovalDigest]) -> Result<(), CodecError> {
    encode_array(encoder, approvals.len())?;
    crate::collections::write_items!(approvals, approval => bytes(encoder, approval.as_bytes()))?;
    Ok(())
}

fn approval_digest(decoder: &mut V1Decoder<'_>) -> Result<ApprovalDigest, CodecError> {
    Ok(ApprovalDigest::new(digest_bytes(decoder)?))
}

fn approver_anchor(decoder: &mut V1Decoder<'_>, limits: &VerifierLimits) -> Result<ApproverAnchor, CodecError> {
    map(decoder, 5)?;
    key(decoder, 0)?;
    let principal = PrincipalId::parse(text(decoder)?)?;
    key(decoder, 1)?;
    let methods = crate::text_list::principal_methods(decoder, limits.get(LimitKind::RegistryEntries))?;
    key(decoder, 2)?;
    let not_before = timestamp(decoder)?;
    key(decoder, 3)?;
    let expires_at = timestamp(decoder)?;
    key(decoder, 4)?;
    let status = status_policy(decoder)?;
    Ok(ApproverAnchor::new(
        principal,
        methods,
        ValidityWindow::new(not_before, expires_at)?,
        status,
    )?)
}

fn approval_satisfaction(decoder: &mut V1Decoder<'_>) -> Result<ApprovalSatisfaction, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let requirement = ApprovalRequirementId::new(digest_bytes(decoder)?);
    key(decoder, 1)?;
    let approvals_count = array(decoder, MAX_APPROVERS_PER_REQUIREMENT)?;
    let approvals = crate::collections::read_items!(approvals_count, approval_digest(decoder))?;
    Ok(ApprovalSatisfaction::new(requirement, approvals)?)
}

fn push_keyed_requirement<'a>(
    mut keyed: Vec<(ApprovalRequirementId, &'a ApprovalRequirement)>,
    requirement: &'a ApprovalRequirement,
) -> Result<Vec<(ApprovalRequirementId, &'a ApprovalRequirement)>, CodecError> {
    keyed.push((crate::approval_requirement_id(requirement)?, requirement));
    Ok(keyed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic_and_accepted_bytes_are_canonical(
            input in proptest::collection::vec(any::<u8>(), 0..512)
        ) {
            if let Ok(requirements) = decode_approval_requirements(&input) {
                prop_assert_eq!(encode_approval_requirements(&requirements).unwrap(), input.clone());
            }
            if let Ok(approval) = decode_signed_approval(&input, &VerifierLimits::default()) {
                prop_assert_eq!(encode_signed_approval(&approval).unwrap(), input);
            }
        }
    }

    fn principal(index: usize) -> PrincipalId {
        PrincipalId::parse(&alloc::format!("test:approver-{index:02}")).unwrap()
    }

    fn requirement(first: usize, count: usize, threshold: u16) -> ApprovalRequirement {
        ApprovalRequirement::new((first..first + count).map(principal).collect(), threshold)
            .unwrap()
    }

    #[test]
    fn requirement_lists_encode_in_identifier_order_and_reject_other_orders() {
        let requirements = crate::CanonicalApprovalRequirements::new(
            ApprovalRequirements::new(vec![requirement(0, 3, 2), requirement(1, 3, 2)]).unwrap(),
        ).unwrap();
        let bytes = encode_approval_requirements(&requirements).unwrap();
        let decoded = decode_approval_requirements(&bytes).unwrap();
        assert_eq!(encode_approval_requirements(&decoded).unwrap(), bytes);
        let sorted = sorted_approval_requirements(requirements.as_slice()).unwrap();
        let mut reversed = vec![0x82];
        reversed.extend(encode_approval_requirement(sorted[1].1).unwrap());
        reversed.extend(encode_approval_requirement(sorted[0].1).unwrap());
        assert_eq!(
            decode_approval_requirements(&reversed),
            Err(CodecError::NonCanonical)
        );
    }

    #[test]
    fn requirement_bounds_fail_at_the_exact_boundary() {
        let at_limit: Vec<_> = (0..MAX_APPROVAL_REQUIREMENTS_PER_GRANT)
            .map(|index| requirement(index, 2, 1))
            .collect();
        let bytes =
            encode_approval_requirements(&crate::CanonicalApprovalRequirements::new(
                ApprovalRequirements::new(at_limit).unwrap(),
            ).unwrap()).unwrap();
        assert!(decode_approval_requirements(&bytes).is_ok());
        let mut over = bytes.clone();
        over[0] += 1;
        over.extend(encode_approval_requirement(&requirement(9, 2, 1)).unwrap());
        assert_eq!(
            decode_approval_requirements(&over),
            Err(CodecError::LimitExceeded)
        );
        let sixteen = encode_approval_requirement(&requirement(0, 16, 1)).unwrap();
        let mut list = vec![0x81];
        list.extend(&sixteen);
        assert!(decode_approval_requirements(&list).is_ok());
    }

    #[test]
    fn a_threshold_above_the_approver_count_does_not_decode() {
        let mut bytes = vec![0x81];
        bytes.extend(encode_approval_requirement(&requirement(0, 3, 3)).unwrap());
        let last = bytes.len() - 1;
        bytes[last] = 4;
        assert!(matches!(
            decode_approval_requirements(&bytes),
            Err(CodecError::Model(
                auths_model::ModelError::InvalidApprovalRequirement
            ))
        ));
    }
}
