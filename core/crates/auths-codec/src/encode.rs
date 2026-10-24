//! Deterministic target V1 encoders.

use crate::cbor::Encoder;
use crate::{
    CanonicalGrantStatusSnapshot, CanonicalPrincipalStatusSnapshot, CanonicalProofBundle,
    CanonicalTrustedContext, CanonicalVerificationResult, CodecError,
    hash::{grant_id, grant_status_id, principal_status_id},
};
use alloc::vec::Vec;
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, AssuranceClaim, AssuranceQuantifier,
    AssuranceSatisfaction, AttachmentDescriptor, AuthorizationPlan, AuthorizationPlanRef,
    BudgetCeiling, CanonicalAction, CompositionRequirement, ControlBinding, CriticalExtension,
    CriticalExtensions, EvidenceObject, GrantState, GrantStatement, GrantStatusSnapshot,
    GrantStatusStatement, LimitKind, ParticipantAssurance, ParticipantRole, Permission,
    PermissionSet, PortableVerificationResult, PrincipalState, PrincipalStatusSnapshot,
    PrincipalStatusStatement, ProfileRef, ProofBundle, SignatureDescriptor, SignatureEnvelope,
    SignedAction, SignedGrant, SignedGrantStatus, SignedPrincipalStatus, StatementRef,
    StatusPolicy, StatusScope, StatusTrustRule, TrustAnchor, TrustedContext, VerificationCode,
    VerificationDecision, VerificationResources, VerificationStage, VerifierLimits,
};

pub(crate) type V1Encoder = Encoder;

// The formal borrowed-key allocation envelope uses these conservative ABI
// bounds. Keep them executable for every supported native and WASM target.
const _: () = {
    assert!(core::mem::size_of::<(auths_model::GrantId, &SignedGrant)>() <= 40);
    assert!(core::mem::size_of::<(auths_model::PrincipalStatusId, &SignedPrincipalStatus)>() <= 40);
    assert!(core::mem::size_of::<(auths_model::GrantStatusId, &SignedGrantStatus)>() <= 40);
    assert!(core::mem::size_of::<&SignedGrant>() <= 8);
    assert!(core::mem::size_of::<&SignedPrincipalStatus>() <= 8);
    assert!(core::mem::size_of::<&SignedGrantStatus>() <= 8);
    assert!(core::mem::size_of::<&SignedAction>() <= 8);
    assert!(core::mem::size_of::<&EvidenceObject>() <= 8);
    assert!(core::mem::size_of::<&ControlBinding>() <= 8);
    assert!(core::mem::size_of::<&AttachmentDescriptor>() <= 8);
};

/// Shape version of the canonical portable verification result.
pub const PORTABLE_RESULT_ABI_VERSION: u16 = 4;

pub(crate) fn encode_error(_error: crate::cbor::Error) -> CodecError {
    CodecError::Malformed
}

pub(crate) fn length(value: usize) -> Result<u64, CodecError> {
    u64::try_from(value).map_err(crate::error::limit_error)
}

// Higher-order writer retained only for frozen test oracles. Production
// entry points call their typed writer directly for source extraction.
#[cfg(test)]
pub(crate) fn finish(
    encode: impl FnOnce(&mut V1Encoder) -> Result<(), CodecError>,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode(&mut encoder)?;
    Ok(encoder.into_writer())
}

pub(crate) fn map(encoder: &mut V1Encoder, entries: u64) -> Result<(), CodecError> {
    encoder.map(entries).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn array(encoder: &mut V1Encoder, entries: usize) -> Result<(), CodecError> {
    encoder.array(length(entries)?).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn key(encoder: &mut V1Encoder, value: u8) -> Result<(), CodecError> {
    encoder.u8(value).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn text(encoder: &mut V1Encoder, value: &str) -> Result<(), CodecError> {
    encoder.str(value).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn bytes(encoder: &mut V1Encoder, value: &[u8]) -> Result<(), CodecError> {
    encoder.bytes(value).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn encode_optional_digest(
    encoder: &mut V1Encoder,
    digest: Option<&[u8; 32]>,
) -> Result<(), CodecError> {
    if let Some(value) = digest {
        bytes(encoder, value)
    } else {
        encoder.null();
        Ok(())
    }
}

fn encode_profile_ref(encoder: &mut V1Encoder, profile: &ProfileRef) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, profile.id().as_str())?;
    key(encoder, 1)?;
    encoder.u16(profile.version()).map_err(encode_error)?;
    Ok(())
}

fn encode_permission(encoder: &mut V1Encoder, permission: &Permission) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, permission.capability().as_str())?;
    key(encoder, 1)?;
    text(encoder, permission.resource().as_str())?;
    Ok(())
}

fn encode_permission_set(
    encoder: &mut V1Encoder,
    permissions: &PermissionSet,
) -> Result<(), CodecError> {
    array(encoder, permissions.as_slice().len())?;
    crate::collections::write_items!(permissions.as_slice(), permission => encode_permission(encoder, permission))?;
    Ok(())
}

pub(crate) fn encode_status_policy(
    encoder: &mut V1Encoder,
    policy: &StatusPolicy,
) -> Result<(), CodecError> {
    match policy {
        StatusPolicy::ExpiryOnly => {
            map(encoder, 1)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(encode_error)?;
        }
        StatusPolicy::SnapshotRequired { method, max_age } => {
            map(encoder, 3)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(encode_error)?;
            key(encoder, 1)?;
            text(encoder, method.as_str())?;
            key(encoder, 2)?;
            encoder.u64(max_age.get()).map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_budget(encoder: &mut V1Encoder, budget: &BudgetCeiling) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, budget.algebra().as_str())?;
    key(encoder, 1)?;
    encoder.u64(budget.value()).map_err(encode_error)?;
    Ok(())
}

pub(crate) fn encode_optional_budget(
    encoder: &mut V1Encoder,
    budget: Option<&BudgetCeiling>,
) -> Result<(), CodecError> {
    if let Some(budget) = budget {
        encode_budget(encoder, budget)
    } else {
        encoder.null();
        Ok(())
    }
}

fn encode_constraint(
    encoder: &mut V1Encoder,
    constraint: &ActionConstraint,
) -> Result<(), CodecError> {
    match constraint {
        ActionConstraint::AnyBody => {
            map(encoder, 1)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(encode_error)?;
        }
        ActionConstraint::ExactBodyDigest(digest) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, digest.as_bytes())?;
        }
        ActionConstraint::AllowedBodyDigests(digests) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(2).map_err(encode_error)?;
            key(encoder, 1)?;
            encode_body_digests(encoder, digests.as_slice())?;
        }
    }
    Ok(())
}

fn encode_body_digests(encoder: &mut V1Encoder, values: &[auths_model::Digest]) -> Result<(), CodecError> {
    array(encoder, values.len())?;
    crate::collections::write_items!(values, digest => bytes(encoder, digest.as_bytes()))?;
    Ok(())
}

fn encode_extension(
    encoder: &mut V1Encoder,
    extension: &CriticalExtension,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, extension.id().as_str())?;
    key(encoder, 1)?;
    bytes(encoder, extension.bytes())?;
    Ok(())
}

fn encode_extensions(
    encoder: &mut V1Encoder,
    extensions: &CriticalExtensions,
) -> Result<(), CodecError> {
    array(encoder, extensions.as_slice().len())?;
    crate::collections::write_items!(extensions.as_slice(), extension => encode_extension(encoder, extension))?;
    Ok(())
}

pub(crate) fn encode_signature_descriptor(
    encoder: &mut V1Encoder,
    descriptor: &SignatureDescriptor,
) -> Result<(), CodecError> {
    map(encoder, 3)?;
    key(encoder, 0)?;
    text(encoder, descriptor.principal_method().as_str())?;
    key(encoder, 1)?;
    text(encoder, descriptor.verification_method().as_str())?;
    key(encoder, 2)?;
    text(encoder, descriptor.suite().as_str())?;
    Ok(())
}

pub(crate) fn encode_signature(
    encoder: &mut V1Encoder,
    signature: &SignatureEnvelope,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_signature_descriptor(encoder, signature.descriptor())?;
    key(encoder, 1)?;
    bytes(encoder, signature.signature().as_slice())?;
    Ok(())
}

pub(crate) fn encode_grant_statement_to(
    encoder: &mut V1Encoder,
    statement: &GrantStatement,
) -> Result<(), CodecError> {
    map(encoder, 16)?;
    key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, statement.issuer().as_str())?;
    key(encoder, 2)?;
    text(encoder, statement.subject().as_str())?;
    key(encoder, 3)?;
    text(encoder, statement.profile().id().as_str())?;
    key(encoder, 4)?;
    encoder
        .u16(statement.profile().version())
        .map_err(encode_error)?;
    key(encoder, 5)?;
    encode_permission_set(encoder, statement.permissions())?;
    key(encoder, 6)?;
    encoder
        .u64(statement.validity().not_before().get())
        .map_err(encode_error)?;
    key(encoder, 7)?;
    encoder
        .u64(statement.validity().expires_at().get())
        .map_err(encode_error)?;
    key(encoder, 8)?;
    crate::text_list::encode_audiences(encoder, statement.audiences().as_slice())?;
    key(encoder, 9)?;
    encode_constraint(encoder, statement.action_constraint())?;
    key(encoder, 10)?;
    encode_optional_budget(encoder, statement.budget_ceiling())?;
    key(encoder, 11)?;
    encoder
        .u16(statement.remaining_depth())
        .map_err(encode_error)?;
    key(encoder, 12)?;
    let parent = statement.parent();
    let parent_bytes = match parent.as_ref() {
        Some(parent) => Some(parent.as_bytes()),
        None => None,
    };
    encode_optional_digest(encoder, parent_bytes)?;
    key(encoder, 13)?;
    encode_status_policy(encoder, statement.status_policy())?;
    key(encoder, 14)?;
    text(encoder, statement.assurance_floor().as_str())?;
    key(encoder, 15)?;
    encode_extensions(encoder, statement.extensions())?;
    Ok(())
}

/// Encodes a grant statement using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_grant_statement(statement: &GrantStatement) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_grant_statement_to(&mut encoder, statement)?;
    Ok(encoder.into_writer())
}

fn encode_signed_grant_to(encoder: &mut V1Encoder, grant: &SignedGrant) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_grant_statement_to(encoder, grant.statement())?;
    key(encoder, 1)?;
    encode_signature(encoder, grant.signature())?;
    Ok(())
}

/// Encodes a signed grant using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_signed_grant(grant: &SignedGrant) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_grant_to(&mut encoder, grant)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_action_envelope_to(
    encoder: &mut V1Encoder,
    envelope: &ActionEnvelope,
) -> Result<(), CodecError> {
    map(encoder, 19)?;
    key(encoder, 0)?;
    encoder
        .u16(envelope.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, envelope.profile().id().as_str())?;
    key(encoder, 2)?;
    encoder
        .u16(envelope.profile().version())
        .map_err(encode_error)?;
    key(encoder, 3)?;
    text(encoder, envelope.body_media_type().as_str())?;
    key(encoder, 4)?;
    bytes(encoder, envelope.canonical_body_digest().as_bytes())?;
    key(encoder, 5)?;
    text(encoder, envelope.permission().capability().as_str())?;
    key(encoder, 6)?;
    text(encoder, envelope.permission().resource().as_str())?;
    key(encoder, 7)?;
    encode_optional_budget(encoder, envelope.requested_budget())?;
    key(encoder, 8)?;
    text(encoder, envelope.audience().as_str())?;
    key(encoder, 9)?;
    bytes(encoder, envelope.challenge().as_bytes())?;
    key(encoder, 10)?;
    encoder
        .u64(envelope.validity().not_before().get())
        .map_err(encode_error)?;
    key(encoder, 11)?;
    encoder
        .u64(envelope.validity().expires_at().get())
        .map_err(encode_error)?;
    key(encoder, 12)?;
    text(encoder, envelope.actor().as_str())?;
    key(encoder, 13)?;
    let terminal = envelope.terminal_grant();
    let terminal_bytes = match terminal.as_ref() {
        Some(grant) => Some(grant.as_bytes()),
        None => None,
    };
    encode_optional_digest(encoder, terminal_bytes)?;
    key(encoder, 14)?;
    bytes(encoder, envelope.authorization_plan().as_bytes())?;
    key(encoder, 15)?;
    text(encoder, envelope.channel_binding().as_str())?;
    key(encoder, 16)?;
    bytes(encoder, envelope.proof_ref().as_bytes())?;
    key(encoder, 17)?;
    encode_attachments(encoder, envelope.attachments())?;
    key(encoder, 18)?;
    encode_extensions(encoder, envelope.extensions())?;
    Ok(())
}

/// Encodes an action envelope using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_action_envelope(envelope: &ActionEnvelope) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_action_envelope_to(&mut encoder, envelope)?;
    Ok(encoder.into_writer())
}

/// Encodes the complete portable canonical-action verifier input.
///
/// # Errors
///
/// Returns [`CodecError`] if a length cannot be represented canonically.
pub fn encode_canonical_action(action: &CanonicalAction) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    map(&mut encoder, 6)?;
    key(&mut encoder, 0)?;
    encode_profile_ref(&mut encoder, action.profile())?;
    key(&mut encoder, 1)?;
    text(&mut encoder, action.media_type().as_str())?;
    key(&mut encoder, 2)?;
    bytes(&mut encoder, action.body())?;
    key(&mut encoder, 3)?;
    encode_permission(&mut encoder, action.permission())?;
    key(&mut encoder, 4)?;
    encode_optional_budget(&mut encoder, action.requested_budget())?;
    key(&mut encoder, 5)?;
    array(&mut encoder, action.detached_attachments().len())?;
    let mut state = Ok(encoder);
    for attachment in action.detached_attachments() {
        state = encode_canonical_attachment(state, attachment);
    }
    Ok(state?.into_writer())
}

fn encode_canonical_attachment(
    state: Result<V1Encoder, CodecError>,
    attachment: &auths_model::DetachedAttachment,
) -> Result<V1Encoder, CodecError> {
    let mut encoder = state?;
    map(&mut encoder, 2)?;
    key(&mut encoder, 0)?;
    bytes(&mut encoder, attachment.digest().as_bytes())?;
    key(&mut encoder, 1)?;
    bytes(&mut encoder, attachment.bytes())?;
    Ok(encoder)
}

fn encode_assurance_claim(
    encoder: &mut V1Encoder,
    claim: &AssuranceClaim,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    text(encoder, claim.kind().as_str())?;
    key(encoder, 1)?;
    encode_assurance_parameters(encoder, claim.parameters())?;
    key(encoder, 2)?;
    encode_optional_timestamp(encoder, claim.observed_at())?;
    key(encoder, 3)?;
    text(encoder, claim.source().as_str())?;
    Ok(())
}

fn encode_optional_timestamp(encoder: &mut V1Encoder, value: Option<auths_model::Timestamp>) -> Result<(), CodecError> {
    if let Some(observed_at) = value {
        encoder.u64(observed_at.get()).map_err(encode_error)?;
    } else {
        encoder.null();
    }
    Ok(())
}

fn encode_role(encoder: &mut V1Encoder, role: ParticipantRole) -> Result<(), CodecError> {
    encoder.u8(assurance_role_tag(role)).map_err(encode_error)?;
    Ok(())
}

fn encode_assurance_report(
    encoder: &mut V1Encoder,
    report: &ParticipantAssurance,
) -> Result<(), CodecError> {
    map(encoder, 6)?;
    key(encoder, 0)?;
    text(encoder, report.principal().as_str())?;
    key(encoder, 1)?;
    encode_role(encoder, report.role())?;
    key(encoder, 2)?;
    encode_assurance_claims(encoder, report.claims())?;
    key(encoder, 3)?;
    encode_evidence_ids(encoder, report.evidence())?;
    key(encoder, 4)?;
    text(encoder, report.adapter().as_str())?;
    key(encoder, 5)?;
    encoder
        .u16(report.adapter_version())
        .map_err(encode_error)?;
    Ok(())
}

fn encode_assurance_satisfaction(
    encoder: &mut V1Encoder,
    satisfaction: &AssuranceSatisfaction,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    encoder
        .u16(satisfaction.requirement_index())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, satisfaction.principal().as_str())?;
    key(encoder, 2)?;
    encode_assurance_claim(encoder, satisfaction.claim())?;
    key(encoder, 3)?;
    encode_evidence_ids(encoder, satisfaction.evidence())?;
    Ok(())
}

fn encode_assurance_claims(encoder: &mut V1Encoder, claims: &[AssuranceClaim]) -> Result<(), CodecError> {
    array(encoder, claims.len())?;
    crate::collections::write_items!(claims, claim => encode_assurance_claim(encoder, claim))?;
    Ok(())
}

fn encode_assurance_reports(encoder: &mut V1Encoder, reports: &[ParticipantAssurance]) -> Result<(), CodecError> {
    array(encoder, reports.len())?;
    crate::collections::write_items!(reports, report => encode_assurance_report(encoder, report))?;
    Ok(())
}

fn encode_assurance_satisfactions(encoder: &mut V1Encoder, satisfactions: &[AssuranceSatisfaction]) -> Result<(), CodecError> {
    array(encoder, satisfactions.len())?;
    crate::collections::write_items!(satisfactions, satisfaction => encode_assurance_satisfaction(encoder, satisfaction))?;
    Ok(())
}

fn encode_proof_refs(encoder: &mut V1Encoder, branches: &[auths_model::ProofRef]) -> Result<(), CodecError> {
    array(encoder, branches.len())?;
    crate::collections::write_items!(branches, branch => bytes(encoder, branch.as_bytes()))?;
    Ok(())
}

fn encode_verification_resources(
    encoder: &mut V1Encoder,
    resources: VerificationResources,
) -> Result<(), CodecError> {
    map(encoder, 7)?;
    encode_unsigned_entry(encoder, 0, resources.proof_bytes())?;
    encode_unsigned_entry(encoder, 1, resources.action_bytes())?;
    encode_unsigned_entry(encoder, 2, resources.context_bytes())?;
    encode_unsigned_entry(encoder, 3, resources.object_count())?;
    encode_unsigned_entry(encoder, 4, resources.plan_leaves())?;
    encode_unsigned_entry(encoder, 5, resources.plan_depth())?;
    encode_unsigned_entry(encoder, 6, resources.work_units())?;
    Ok(())
}

fn verification_decision_tag(decision: VerificationDecision) -> u8 {
    match decision {
        VerificationDecision::Authorized => 0,
        VerificationDecision::Denied => 1,
        VerificationDecision::Indeterminate => 2,
    }
}

fn verification_stage_tag(stage: VerificationStage) -> u8 {
    match stage {
        VerificationStage::Decode => 0,
        VerificationStage::Resolve => 1,
        VerificationStage::PrincipalControl => 2,
        VerificationStage::Authority => 3,
        VerificationStage::Complete => 4,
    }
}

fn verification_code_class(code: VerificationCode) -> u8 {
    match code {
        VerificationCode::Authorized => 0,
        VerificationCode::Denied(_) => 1,
        VerificationCode::Indeterminate(_) => 2,
    }
}

fn encode_verification_code(encoder: &mut V1Encoder, code: VerificationCode) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encoder.u8(verification_code_class(code)).map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, code.code())?;
    Ok(())
}

fn encode_result_digest(encoder: &mut V1Encoder, digest: auths_model::VerificationResultDigest, include: bool) -> Result<(), CodecError> {
    if include {
        bytes(encoder, digest.as_bytes())?;
    } else {
        bytes(encoder, &[0; 32])?;
    }
    Ok(())
}

fn encode_verification_result_to(
    encoder: &mut V1Encoder,
    result: &PortableVerificationResult,
    include_result_digest: bool,
) -> Result<(), CodecError> {
    map(encoder, 18)?;
    key(encoder, 0)?;
    encoder.u8(verification_decision_tag(result.decision())).map_err(encode_error)?;
    key(encoder, 1)?;
    encoder.u8(verification_stage_tag(result.stage())).map_err(encode_error)?;
    key(encoder, 2)?;
    encode_verification_code(encoder, result.code())?;
    key(encoder, 3)?;
    bytes(encoder, result.proof_digest().as_bytes())?;
    key(encoder, 4)?;
    bytes(encoder, result.action_digest().as_bytes())?;
    key(encoder, 5)?;
    bytes(encoder, result.context_digest().as_bytes())?;
    key(encoder, 6)?;
    let plan_id = result.plan_id();
    let plan_bytes = match plan_id.as_ref() {
        Some(plan) => Some(plan.as_bytes()),
        None => None,
    };
    encode_optional_digest(encoder, plan_bytes)?;
    key(encoder, 7)?;
    encode_result_digest(encoder, result.result_digest(), include_result_digest)?;
    key(encoder, 8)?;
    encode_proof_refs(encoder, result.authorized_branches())?;
    key(encoder, 9)?;
    encode_assurance_reports(encoder, result.assurance())?;
    key(encoder, 10)?;
    encode_assurance_satisfactions(encoder, result.assurance_satisfactions())?;
    key(encoder, 11)?;
    encode_verification_resources(encoder, result.resources())?;
    key(encoder, 12)?;
    bytes(encoder, result.registry_manifest().as_bytes())?;
    key(encoder, 13)?;
    let configuration = result.required_configuration();
    let configuration_bytes = match configuration.as_ref() {
        Some(configuration) => Some(configuration.as_bytes()),
        None => None,
    };
    encode_optional_digest(encoder, configuration_bytes)?;
    key(encoder, 14)?;
    bytes(encoder, result.local_configuration().as_bytes())?;
    key(encoder, 15)?;
    encoder
        .u16(PORTABLE_RESULT_ABI_VERSION)
        .map_err(encode_error)?;
    key(encoder, 16)?;
    crate::observation::encode_observation_satisfactions(
        encoder,
        result.observation_satisfactions(),
    )?;
    key(encoder, 17)?;
    crate::approval::encode_approval_satisfactions(encoder, result.approval_satisfactions())?;
    Ok(())
}

/// Encodes the complete portable verifier output.
/// Requires consistent decision/code tags and an exact self-binding digest.
///
/// # Errors
///
/// Returns [`CodecError`] if a result collection cannot be represented.
pub fn encode_verification_result(
    result: &CanonicalVerificationResult,
) -> Result<Vec<u8>, CodecError> {
    encode_verification_result_value(result.as_value())
}

pub(crate) fn encode_verification_result_value(
    result: &PortableVerificationResult,
) -> Result<Vec<u8>, CodecError> {
    encode_verification_result_projection(result, true)
}

/// Encodes the result projection used to derive its self-binding digest.
///
/// # Errors
///
/// Returns [`CodecError`] if a result collection cannot be represented.
pub fn encode_verification_result_digest_input(
    result: &PortableVerificationResult,
) -> Result<Vec<u8>, CodecError> {
    encode_verification_result_projection(result, false)
}

fn encode_verification_result_projection(
    result: &PortableVerificationResult,
    include_result_digest: bool,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_verification_result_to(&mut encoder, result, include_result_digest)?;
    Ok(encoder.into_writer())
}

fn encode_signed_action_to(
    encoder: &mut V1Encoder,
    action: &SignedAction,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_action_envelope_to(encoder, action.envelope())?;
    key(encoder, 1)?;
    encode_signature(encoder, action.signature())?;
    Ok(())
}

/// Encodes a signed action using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_signed_action(action: &SignedAction) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_action_to(&mut encoder, action)?;
    Ok(encoder.into_writer())
}

fn encode_plan_members(
    encoder: &mut V1Encoder,
    members: &[AuthorizationPlan],
) -> Result<(), CodecError> {
    array(encoder, members.len())?;
    crate::collections::write_items!(members, member => encode_authorization_plan_to(encoder, member))?;
    Ok(())
}

pub(crate) fn encode_authorization_plan_to(
    encoder: &mut V1Encoder,
    plan: &AuthorizationPlan,
) -> Result<(), CodecError> {
    match plan.as_ref() {
        AuthorizationPlanRef::Proof(reference) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, reference.as_bytes())?;
        }
        AuthorizationPlanRef::AllOf(members) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(encode_error)?;
            key(encoder, 1)?;
            encode_plan_members(encoder, members)?;
        }
        AuthorizationPlanRef::AnyOf(members) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(2).map_err(encode_error)?;
            key(encoder, 1)?;
            encode_plan_members(encoder, members)?;
        }
        AuthorizationPlanRef::KOfN { k, members } => {
            map(encoder, 3)?;
            key(encoder, 0)?;
            encoder.u8(3).map_err(encode_error)?;
            key(encoder, 1)?;
            encoder.u16(k).map_err(encode_error)?;
            key(encoder, 2)?;
            encode_plan_members(encoder, members)?;
        }
    }
    Ok(())
}

/// Encodes an authorization plan using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_authorization_plan(plan: &AuthorizationPlan) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_authorization_plan_to(&mut encoder, plan)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_evidence(
    encoder: &mut V1Encoder,
    evidence: &EvidenceObject,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    bytes(encoder, evidence.id().as_bytes())?;
    key(encoder, 1)?;
    text(encoder, evidence.evidence_type().as_str())?;
    key(encoder, 2)?;
    text(encoder, evidence.media_type().as_str())?;
    key(encoder, 3)?;
    bytes(encoder, evidence.bytes())?;
    Ok(())
}

pub(crate) fn encode_evidence_objects(
    encoder: &mut V1Encoder,
    objects: &[EvidenceObject],
) -> Result<(), CodecError> {
    array(encoder, objects.len())?;
    crate::collections::write_items!(objects, object => encode_evidence(encoder, object))?;
    Ok(())
}

pub(crate) fn encode_evidence_content_to(
    encoder: &mut V1Encoder,
    evidence: &EvidenceObject,
) -> Result<(), CodecError> {
    map(encoder, 3)?;
    key(encoder, 0)?;
    text(encoder, evidence.evidence_type().as_str())?;
    key(encoder, 1)?;
    text(encoder, evidence.media_type().as_str())?;
    key(encoder, 2)?;
    bytes(encoder, evidence.bytes())?;
    Ok(())
}

pub(crate) fn encode_evidence_content(evidence: &EvidenceObject) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_evidence_content_to(&mut encoder, evidence)?;
    Ok(encoder.into_writer())
}

fn encode_statement_ref(
    encoder: &mut V1Encoder,
    reference: StatementRef,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    match reference {
        StatementRef::Grant(identifier) => {
            encoder.u8(0).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, identifier.as_bytes())?;
        }
        StatementRef::Action(identifier) => {
            encoder.u8(1).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, identifier.as_bytes())?;
        }
        StatementRef::PrincipalStatus(identifier) => {
            encoder.u8(2).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, identifier.as_bytes())?;
        }
        StatementRef::GrantStatus(identifier) => {
            encoder.u8(3).map_err(encode_error)?;
            key(encoder, 1)?;
            bytes(encoder, identifier.as_bytes())?;
        }
    }
    Ok(())
}

fn encode_evidence_ids(
    encoder: &mut V1Encoder,
    evidence: &[auths_model::EvidenceId],
) -> Result<(), CodecError> {
    array(encoder, evidence.len())?;
    crate::collections::write_items!(evidence, identifier => bytes(encoder, identifier.as_bytes()))?;
    Ok(())
}

fn encode_binding(encoder: &mut V1Encoder, binding: &ControlBinding) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_statement_ref(encoder, binding.statement())?;
    key(encoder, 1)?;
    encode_evidence_ids(encoder, binding.evidence())?;
    Ok(())
}

pub(crate) fn encode_principal_status_statement_to(
    encoder: &mut V1Encoder,
    statement: &PrincipalStatusStatement,
) -> Result<(), CodecError> {
    map(encoder, 9)?;
    key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, statement.method().as_str())?;
    key(encoder, 2)?;
    text(encoder, statement.principal().as_str())?;
    key(encoder, 3)?;
    let state = match statement.state() {
        PrincipalState::Active => 0,
        PrincipalState::Revoked => 1,
        PrincipalState::Superseded => 2,
    };
    encoder.u8(state).map_err(encode_error)?;
    key(encoder, 4)?;
    encoder.u64(statement.sequence()).map_err(encode_error)?;
    key(encoder, 5)?;
    encoder
        .u64(statement.observed_at().get())
        .map_err(encode_error)?;
    key(encoder, 6)?;
    encoder
        .u64(statement.valid_until().get())
        .map_err(encode_error)?;
    key(encoder, 7)?;
    text(encoder, statement.issuer().as_str())?;
    key(encoder, 8)?;
    encode_extensions(encoder, statement.extensions())?;
    Ok(())
}

/// Encodes a principal-status statement using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_principal_status_statement(
    statement: &PrincipalStatusStatement,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_principal_status_statement_to(&mut encoder, statement)?;
    Ok(encoder.into_writer())
}

fn encode_signed_principal_status_to(
    encoder: &mut V1Encoder,
    status: &SignedPrincipalStatus,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_principal_status_statement_to(encoder, status.statement())?;
    key(encoder, 1)?;
    encode_signature(encoder, status.signature())?;
    Ok(())
}

/// Encodes a signed principal-status statement using deterministic target V1
/// CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_signed_principal_status(
    status: &SignedPrincipalStatus,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_principal_status_to(&mut encoder, status)?;
    Ok(encoder.into_writer())
}

pub(crate) fn encode_grant_status_statement_to(
    encoder: &mut V1Encoder,
    statement: &GrantStatusStatement,
) -> Result<(), CodecError> {
    map(encoder, 9)?;
    key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, statement.method().as_str())?;
    key(encoder, 2)?;
    bytes(encoder, statement.grant_id().as_bytes())?;
    key(encoder, 3)?;
    let state = match statement.state() {
        GrantState::Active => 0,
        GrantState::Revoked => 1,
        GrantState::Superseded => 2,
    };
    encoder.u8(state).map_err(encode_error)?;
    key(encoder, 4)?;
    encoder.u64(statement.sequence()).map_err(encode_error)?;
    key(encoder, 5)?;
    encoder
        .u64(statement.observed_at().get())
        .map_err(encode_error)?;
    key(encoder, 6)?;
    encoder
        .u64(statement.valid_until().get())
        .map_err(encode_error)?;
    key(encoder, 7)?;
    text(encoder, statement.issuer().as_str())?;
    key(encoder, 8)?;
    encode_extensions(encoder, statement.extensions())?;
    Ok(())
}

/// Encodes a grant-status statement using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_grant_status_statement(
    statement: &GrantStatusStatement,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_grant_status_statement_to(&mut encoder, statement)?;
    Ok(encoder.into_writer())
}

fn encode_signed_grant_status_to(
    encoder: &mut V1Encoder,
    status: &SignedGrantStatus,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_grant_status_statement_to(encoder, status.statement())?;
    key(encoder, 1)?;
    encode_signature(encoder, status.signature())?;
    Ok(())
}

/// Encodes a signed grant-status statement using deterministic target V1
/// CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_signed_grant_status(status: &SignedGrantStatus) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_signed_grant_status_to(&mut encoder, status)?;
    Ok(encoder.into_writer())
}

fn encode_attachments(encoder: &mut V1Encoder, values: &[AttachmentDescriptor]) -> Result<(), CodecError> {
    array(encoder, values.len())?;
    crate::collections::write_items!(values, attachment => encode_attachment(encoder, attachment))?;
    Ok(())
}

fn encode_attachment(
    encoder: &mut V1Encoder,
    attachment: &AttachmentDescriptor,
) -> Result<(), CodecError> {
    map(encoder, 7)?;
    key(encoder, 0)?;
    bytes(encoder, attachment.digest().as_bytes())?;
    key(encoder, 1)?;
    text(encoder, attachment.media_type().as_str())?;
    key(encoder, 2)?;
    encoder
        .u64(attachment.byte_length())
        .map_err(encode_error)?;
    key(encoder, 3)?;
    text(encoder, attachment.disposition().as_str())?;
    key(encoder, 4)?;
    encoder.bool(matches!(
        attachment.confidentiality(),
        auths_model::Confidentiality::Encrypted
    ));
    key(encoder, 5)?;
    encoder.bool(matches!(
        attachment.presence(),
        auths_model::Presence::Required
    ));
    key(encoder, 6)?;
    encoder.bool(matches!(
        attachment.opacity(),
        auths_model::Opacity::OpaqueAllowed
    ));
    Ok(())
}

fn derive_grant_ref_keys(
    records: &[SignedGrant],
) -> Result<Vec<(auths_model::GrantId, &SignedGrant)>, CodecError> {
    crate::collections::try_fold_items!(records,
        Vec::with_capacity(records.len()), current, _index, record =>
            push_keyed_grants(current, record))
}

fn grant_ref_sort_key(entry: &(auths_model::GrantId, &SignedGrant)) -> auths_model::GrantId {
    entry.0
}

fn sort_grant_ref_keys<'a>(
    mut keyed: Vec<(auths_model::GrantId, &'a SignedGrant)>,
) -> Vec<(auths_model::GrantId, &'a SignedGrant)> {
    keyed.sort_by_key(grant_ref_sort_key);
    keyed
}

fn derive_principal_status_ref_keys(
    records: &[SignedPrincipalStatus],
) -> Result<Vec<(auths_model::PrincipalStatusId, &SignedPrincipalStatus)>, CodecError> {
    crate::collections::try_fold_items!(records,
        Vec::with_capacity(records.len()), current, _index, record =>
            push_keyed_principal_status(current, record))
}

fn principal_status_ref_sort_key(entry: &(auths_model::PrincipalStatusId, &SignedPrincipalStatus)) -> auths_model::PrincipalStatusId {
    entry.0
}

fn sort_principal_status_ref_keys<'a>(
    mut keyed: Vec<(auths_model::PrincipalStatusId, &'a SignedPrincipalStatus)>,
) -> Vec<(auths_model::PrincipalStatusId, &'a SignedPrincipalStatus)> {
    keyed.sort_by_key(principal_status_ref_sort_key);
    keyed
}

fn derive_grant_status_ref_keys(
    records: &[SignedGrantStatus],
) -> Result<Vec<(auths_model::GrantStatusId, &SignedGrantStatus)>, CodecError> {
    crate::collections::try_fold_items!(records,
        Vec::with_capacity(records.len()), current, _index, record =>
            push_keyed_grant_status(current, record))
}

fn grant_status_ref_sort_key(entry: &(auths_model::GrantStatusId, &SignedGrantStatus)) -> auths_model::GrantStatusId {
    entry.0
}

fn sort_grant_status_ref_keys<'a>(
    mut keyed: Vec<(auths_model::GrantStatusId, &'a SignedGrantStatus)>,
) -> Vec<(auths_model::GrantStatusId, &'a SignedGrantStatus)> {
    keyed.sort_by_key(grant_status_ref_sort_key);
    keyed
}

fn sorted_grants(bundle: &ProofBundle) -> Result<Vec<&SignedGrant>, CodecError> {
    let keyed = sort_grant_ref_keys(derive_grant_ref_keys(bundle.grants())?);
    Ok(crate::canonical_value::unkey_records(keyed))
}

fn sorted_principal_status(values: &[SignedPrincipalStatus]) -> Result<Vec<&SignedPrincipalStatus>, CodecError> {
    let keyed = sort_principal_status_ref_keys(derive_principal_status_ref_keys(values)?);
    Ok(crate::canonical_value::unkey_records(keyed))
}

fn sorted_grant_status(values: &[SignedGrantStatus]) -> Result<Vec<&SignedGrantStatus>, CodecError> {
    let keyed = sort_grant_status_ref_keys(derive_grant_status_ref_keys(values)?);
    Ok(crate::canonical_value::unkey_records(keyed))
}

fn action_ref_sort_key(action: &&SignedAction) -> auths_model::ProofRef {
    action.envelope().proof_ref()
}

fn evidence_ref_sort_key(evidence: &&EvidenceObject) -> auths_model::EvidenceId {
    evidence.id()
}

fn binding_ref_sort_key(binding: &&ControlBinding) -> auths_model::StatementRef {
    binding.statement()
}

fn attachment_ref_sort_key(attachment: &&AttachmentDescriptor) -> auths_model::AttachmentDigest {
    attachment.digest()
}

fn sort_action_refs<'a>(mut records: Vec<&'a SignedAction>) -> Vec<&'a SignedAction> {
    records.sort_by_key(action_ref_sort_key);
    records
}

fn sorted_action_refs(records: &[SignedAction]) -> Vec<&SignedAction> {
    let borrowed = crate::collections::borrowed_items!(records);
    sort_action_refs(borrowed)
}

fn sort_evidence_refs<'a>(mut records: Vec<&'a EvidenceObject>) -> Vec<&'a EvidenceObject> {
    records.sort_by_key(evidence_ref_sort_key);
    records
}

fn sorted_evidence_refs(records: &[EvidenceObject]) -> Vec<&EvidenceObject> {
    let borrowed = crate::collections::borrowed_items!(records);
    sort_evidence_refs(borrowed)
}

fn sort_binding_refs<'a>(mut records: Vec<&'a ControlBinding>) -> Vec<&'a ControlBinding> {
    records.sort_by_key(binding_ref_sort_key);
    records
}

fn sorted_binding_refs(records: &[ControlBinding]) -> Vec<&ControlBinding> {
    let borrowed = crate::collections::borrowed_items!(records);
    sort_binding_refs(borrowed)
}

fn sort_attachment_refs<'a>(mut records: Vec<&'a AttachmentDescriptor>) -> Vec<&'a AttachmentDescriptor> {
    records.sort_by_key(attachment_ref_sort_key);
    records
}

fn sorted_attachment_refs(records: &[AttachmentDescriptor]) -> Vec<&AttachmentDescriptor> {
    let borrowed = crate::collections::borrowed_items!(records);
    sort_attachment_refs(borrowed)
}

fn encode_bundle_header(
    encoder: &mut V1Encoder,
    header: &auths_model::BundleHeader,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encoder
        .u16(header.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    encoder.u64(header.flags()).map_err(encode_error)?;
    Ok(())
}

fn encode_grant_refs(
    encoder: &mut V1Encoder,
    records: Vec<&SignedGrant>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_signed_grant_to(encoder, record))?;
    Ok(())
}

fn encode_action_refs(
    encoder: &mut V1Encoder,
    records: Vec<&SignedAction>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_signed_action_to(encoder, record))?;
    Ok(())
}

fn encode_evidence_refs(
    encoder: &mut V1Encoder,
    records: Vec<&EvidenceObject>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_evidence(encoder, record))?;
    Ok(())
}

fn encode_binding_refs(
    encoder: &mut V1Encoder,
    records: Vec<&ControlBinding>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_binding(encoder, record))?;
    Ok(())
}

fn encode_principal_status_refs(
    encoder: &mut V1Encoder,
    records: Vec<&SignedPrincipalStatus>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_signed_principal_status_to(encoder, record))?;
    Ok(())
}

fn encode_grant_status_refs(
    encoder: &mut V1Encoder,
    records: Vec<&SignedGrantStatus>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_signed_grant_status_to(encoder, record))?;
    Ok(())
}

fn encode_attachment_refs(
    encoder: &mut V1Encoder,
    records: Vec<&AttachmentDescriptor>,
) -> Result<(), CodecError> {
    let values = records.as_slice();
    array(encoder, values.len())?;
    crate::collections::write_items!(values, record => encode_attachment(encoder, record))?;
    Ok(())
}

fn encode_signed_approvals(
    encoder: &mut V1Encoder,
    records: &[auths_model::SignedApproval],
) -> Result<(), CodecError> {
    array(encoder, records.len())?;
    crate::collections::write_items!(records, record => crate::approval::encode_signed_approval_to(encoder, record))?;
    Ok(())
}

fn encode_optional_body(
    encoder: &mut V1Encoder,
    body: Option<&[u8]>,
) -> Result<(), CodecError> {
    match body {
        Some(body) => bytes(encoder, body)?,
        None => { encoder.null(); }
    }
    Ok(())
}

fn encode_bundle_to(encoder: &mut V1Encoder, bundle: &ProofBundle) -> Result<(), CodecError> {
    map(encoder, 11)?;
    key(encoder, 0)?;
    encode_bundle_header(encoder, bundle.header())?;

    key(encoder, 1)?;
    let grants = sorted_grants(bundle)?;
    encode_grant_refs(encoder, grants)?;

    key(encoder, 2)?;
    let actions = sorted_action_refs(bundle.actions());
    encode_action_refs(encoder, actions)?;

    key(encoder, 3)?;
    encode_authorization_plan_to(encoder, bundle.plan())?;

    key(encoder, 4)?;
    let evidence = sorted_evidence_refs(bundle.evidence());
    encode_evidence_refs(encoder, evidence)?;

    key(encoder, 5)?;
    let bindings = sorted_binding_refs(bundle.bindings());
    encode_binding_refs(encoder, bindings)?;

    key(encoder, 6)?;
    let principal_status = sorted_principal_status(bundle.principal_status())?;
    encode_principal_status_refs(encoder, principal_status)?;

    key(encoder, 7)?;
    let grant_status = sorted_grant_status(bundle.grant_status())?;
    encode_grant_status_refs(encoder, grant_status)?;

    key(encoder, 8)?;
    let attachments = sorted_attachment_refs(bundle.attachments());
    encode_attachment_refs(encoder, attachments)?;

    key(encoder, 9)?;
    encode_optional_body(encoder, bundle.canonical_body())?;

    key(encoder, 10)?;
    encode_signed_approvals(encoder, bundle.approvals())?;
    Ok(())
}

/// Encodes a complete proof bundle using deterministic target V1 CBOR.
/// Construct [`CanonicalProofBundle`] explicitly from an owned model first.
/// Encoding preserves its complete canonical value and establishes no authority.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_bundle(bundle: &CanonicalProofBundle) -> Result<Vec<u8>, CodecError> {
    encode_bundle_value(bundle.as_value())
}

// Hashing a borrowed model uses the same authoritative writer as the public
// canonical encoder. It needs no deep clone of the proof's payloads.
pub(crate) fn encode_bundle_value(bundle: &ProofBundle) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_bundle_to(&mut encoder, bundle)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical grant signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_grant_signing_input(
    statement: &GrantStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    map(&mut encoder, 2)?;
    key(&mut encoder, 0)?;
    encode_grant_statement_to(&mut encoder, statement)?;
    key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical action signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_action_signing_input(
    envelope: &ActionEnvelope,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    map(&mut encoder, 2)?;
    key(&mut encoder, 0)?;
    encode_action_envelope_to(&mut encoder, envelope)?;
    key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical principal-status signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_principal_status_signing_input(
    statement: &PrincipalStatusStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    map(&mut encoder, 2)?;
    key(&mut encoder, 0)?;
    encode_principal_status_statement_to(&mut encoder, statement)?;
    key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
}

/// Encodes the canonical grant-status signing object.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_grant_status_signing_input(
    statement: &GrantStatusStatement,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    map(&mut encoder, 2)?;
    key(&mut encoder, 0)?;
    encode_grant_status_statement_to(&mut encoder, statement)?;
    key(&mut encoder, 1)?;
    encode_signature_descriptor(&mut encoder, descriptor)?;
    Ok(encoder.into_writer())
}

fn encode_assurance_policy(
    encoder: &mut V1Encoder,
    policy: &auths_model::AssurancePolicy,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, policy.id().as_str())?;
    key(encoder, 1)?;
    encode_assurance_requirements(encoder, policy.requirements())?;
    Ok(())
}

fn encode_assurance_requirements(
    encoder: &mut V1Encoder,
    requirements: &[auths_model::AssuranceRequirement],
) -> Result<(), CodecError> {
    array(encoder, requirements.len())?;
    crate::collections::write_items!(requirements, requirement => encode_assurance_requirement(encoder, requirement))?;
    Ok(())
}

fn encode_profiles(encoder: &mut V1Encoder, profiles: &[ProfileRef]) -> Result<(), CodecError> {
    array(encoder, profiles.len())?;
    crate::collections::write_items!(profiles, profile => encode_profile_ref(encoder, profile))?;
    Ok(())
}

fn encode_trust_anchors(encoder: &mut V1Encoder, anchors: &[TrustAnchor]) -> Result<(), CodecError> {
    array(encoder, anchors.len())?;
    crate::collections::write_items!(anchors, anchor => encode_anchor(encoder, anchor))?;
    Ok(())
}

fn encode_anchor(encoder: &mut V1Encoder, anchor: &TrustAnchor) -> Result<(), CodecError> {
    map(encoder, 13)?;
    key(encoder, 0)?;
    text(encoder, anchor.id().as_str())?;
    key(encoder, 1)?;
    text(encoder, anchor.principal().as_str())?;
    key(encoder, 2)?;
    crate::text_list::encode_principal_methods(encoder, anchor.accepted_methods())?;
    key(encoder, 3)?;
    encode_profiles(encoder, anchor.profiles())?;
    key(encoder, 4)?;
    encode_permission_set(encoder, anchor.permissions())?;
    key(encoder, 5)?;
    crate::text_list::encode_resource_ids(encoder, anchor.resource_namespaces())?;
    key(encoder, 6)?;
    crate::text_list::encode_audiences(encoder, anchor.audiences().as_slice())?;
    key(encoder, 7)?;
    encoder
        .u64(anchor.validity().not_before().get())
        .map_err(encode_error)?;
    key(encoder, 8)?;
    encoder
        .u64(anchor.validity().expires_at().get())
        .map_err(encode_error)?;
    key(encoder, 9)?;
    encode_optional_budget(encoder, anchor.budget_ceiling())?;
    key(encoder, 10)?;
    encoder
        .u16(anchor.max_delegation_depth())
        .map_err(encode_error)?;
    key(encoder, 11)?;
    text(encoder, anchor.assurance_policy().as_str())?;
    key(encoder, 12)?;
    encode_status_policy(encoder, anchor.status_policy())?;
    Ok(())
}


fn encode_registries(
    encoder: &mut V1Encoder,
    registries: &AcceptedRegistries,
) -> Result<(), CodecError> {
    map(encoder, 14)?;
    key(encoder, 0)?;
    bytes(encoder, registries.manifest_id().as_bytes())?;
    key(encoder, 1)?;
    crate::text_list::encode_principal_methods(encoder, registries.principal_methods())?;
    key(encoder, 2)?;
    crate::text_list::encode_signature_suites(encoder, registries.signature_suites())?;
    key(encoder, 3)?;
    crate::text_list::encode_evidence_types(encoder, registries.evidence_types())?;
    key(encoder, 4)?;
    crate::text_list::encode_status_methods(encoder, registries.principal_status_methods())?;
    key(encoder, 5)?;
    crate::text_list::encode_status_methods(encoder, registries.grant_status_methods())?;
    key(encoder, 6)?;
    crate::text_list::encode_assurance_claims(encoder, registries.assurance_claims())?;
    key(encoder, 7)?;
    crate::text_list::encode_assurance_implications(encoder, registries.assurance_implications())?;
    key(encoder, 8)?;
    crate::text_list::encode_resource_matchers(encoder, registries.resource_matchers())?;
    key(encoder, 9)?;
    crate::text_list::encode_budget_algebras(encoder, registries.budget_algebras())?;
    key(encoder, 10)?;
    crate::text_list::encode_extension_ids(encoder, registries.critical_extensions())?;
    key(encoder, 11)?;
    encode_profiles(encoder, registries.profiles())?;
    key(encoder, 12)?;
    crate::text_list::encode_profile_policies(encoder, registries.profile_policies())?;
    key(encoder, 13)?;
    encode_profiles(encoder, registries.budget_free_profiles())?;
    Ok(())
}

fn encode_status_trust(
    encoder: &mut V1Encoder,
    rules: &[StatusTrustRule],
) -> Result<(), CodecError> {
    array(encoder, rules.len())?;
    crate::collections::write_items!(rules, rule => encode_status_trust_rule(encoder, rule))?;
    Ok(())
}

fn encode_status_scope(encoder: &mut V1Encoder, scope: &StatusScope) -> Result<(), CodecError> {
    match scope {
        StatusScope::OwnAnchor => {
            map(encoder, 1)?;
            key(encoder, 0)?;
            encoder.u8(0).map_err(encode_error)?;
        }
        StatusScope::Anchors(anchors) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(1).map_err(encode_error)?;
            key(encoder, 1)?;
            crate::text_list::encode_trust_anchor_ids(encoder, anchors.ids())?;
        }
        StatusScope::AnyAnchor => {
            map(encoder, 1)?;
            key(encoder, 0)?;
            encoder.u8(2).map_err(encode_error)?;
        }
    }
    Ok(())
}

fn encode_principal_snapshot(
    encoder: &mut V1Encoder,
    snapshot: &PrincipalStatusSnapshot,
) -> Result<(), CodecError> {
    map(encoder, 6)?;
    key(encoder, 0)?;
    bytes(encoder, snapshot.id().as_bytes())?;
    key(encoder, 1)?;
    encoder
        .u64(snapshot.observed_at().get())
        .map_err(encode_error)?;
    key(encoder, 2)?;
    encoder
        .u64(snapshot.valid_until().get())
        .map_err(encode_error)?;
    key(encoder, 3)?;
    let statuses = sorted_principal_status(snapshot.statements())?;
    encode_principal_status_refs(encoder, statuses)?;
    key(encoder, 4)?;
    encode_evidence_ids(encoder, snapshot.checkpoints())?;
    key(encoder, 5)?;
    encode_status_trust(encoder, snapshot.trust())?;
    Ok(())
}

fn encode_grant_snapshot(
    encoder: &mut V1Encoder,
    snapshot: &GrantStatusSnapshot,
) -> Result<(), CodecError> {
    map(encoder, 6)?;
    key(encoder, 0)?;
    bytes(encoder, snapshot.id().as_bytes())?;
    key(encoder, 1)?;
    encoder
        .u64(snapshot.observed_at().get())
        .map_err(encode_error)?;
    key(encoder, 2)?;
    encoder
        .u64(snapshot.valid_until().get())
        .map_err(encode_error)?;
    key(encoder, 3)?;
    let statuses = sorted_grant_status(snapshot.statements())?;
    encode_grant_status_refs(encoder, statuses)?;
    key(encoder, 4)?;
    encode_evidence_ids(encoder, snapshot.checkpoints())?;
    key(encoder, 5)?;
    encode_status_trust(encoder, snapshot.trust())?;
    Ok(())
}

/// Encodes one canonical principal-status snapshot.
/// Requires the codec-owned carrier, including normalized model-order ties.
///
/// # Errors
///
/// Returns a codec error if a collection length cannot be represented canonically.
pub fn encode_principal_status_snapshot(
    snapshot: &CanonicalPrincipalStatusSnapshot,
) -> Result<Vec<u8>, CodecError> {
    encode_principal_status_snapshot_value(snapshot.as_value())
}

pub(crate) fn encode_principal_status_snapshot_value(
    snapshot: &PrincipalStatusSnapshot,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_principal_snapshot(&mut encoder, snapshot)?;
    Ok(encoder.into_writer())
}

/// Encodes one canonical grant-status snapshot.
/// Requires the codec-owned carrier, including normalized model-order ties.
///
/// # Errors
///
/// Returns a codec error if a collection length cannot be represented canonically.
pub fn encode_grant_status_snapshot(snapshot: &CanonicalGrantStatusSnapshot) -> Result<Vec<u8>, CodecError> {
    encode_grant_status_snapshot_value(snapshot.as_value())
}

pub(crate) fn encode_grant_status_snapshot_value(
    snapshot: &GrantStatusSnapshot,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_grant_snapshot(&mut encoder, snapshot)?;
    Ok(encoder.into_writer())
}

fn encode_limits(encoder: &mut V1Encoder, limits: &VerifierLimits) -> Result<(), CodecError> {
    map(encoder, 30)?;
    encode_limit_entry(encoder, 0, LimitKind::BundleBytes, limits)?;
    encode_limit_entry(encoder, 1, LimitKind::ActionBytes, limits)?;
    encode_limit_entry(encoder, 2, LimitKind::ContextBytes, limits)?;
    encode_limit_entry(encoder, 3, LimitKind::Grants, limits)?;
    encode_limit_entry(encoder, 4, LimitKind::Actions, limits)?;
    encode_limit_entry(encoder, 5, LimitKind::PlanLeaves, limits)?;
    encode_limit_entry(encoder, 6, LimitKind::PlanDepth, limits)?;
    encode_limit_entry(encoder, 7, LimitKind::PlanBranching, limits)?;
    encode_limit_entry(encoder, 8, LimitKind::EvidenceObjects, limits)?;
    encode_limit_entry(encoder, 9, LimitKind::EvidenceBytes, limits)?;
    encode_limit_entry(encoder, 10, LimitKind::ControlBindings, limits)?;
    encode_limit_entry(encoder, 11, LimitKind::PrincipalStatusStatements, limits)?;
    encode_limit_entry(encoder, 12, LimitKind::GrantStatusStatements, limits)?;
    encode_limit_entry(encoder, 13, LimitKind::Attachments, limits)?;
    encode_limit_entry(encoder, 14, LimitKind::AttachmentBytes, limits)?;
    encode_limit_entry(encoder, 15, LimitKind::Signatures, limits)?;
    encode_limit_entry(encoder, 16, LimitKind::SignatureBytes, limits)?;
    encode_limit_entry(encoder, 17, LimitKind::Permissions, limits)?;
    encode_limit_entry(encoder, 18, LimitKind::Audiences, limits)?;
    encode_limit_entry(encoder, 19, LimitKind::CriticalExtensions, limits)?;
    encode_limit_entry(encoder, 20, LimitKind::CriticalExtensionBytes, limits)?;
    encode_limit_entry(encoder, 21, LimitKind::AllowedBodyDigests, limits)?;
    encode_limit_entry(encoder, 22, LimitKind::BindingEvidence, limits)?;
    encode_limit_entry(encoder, 23, LimitKind::CanonicalBodyBytes, limits)?;
    encode_limit_entry(encoder, 24, LimitKind::RegistryEntries, limits)?;
    encode_limit_entry(encoder, 25, LimitKind::TrustAnchors, limits)?;
    key(encoder, 26)?;
    encoder.u64(limits.max_work_units()).map_err(encode_error)?;
    encode_limit_entry(encoder, 27, LimitKind::Approvals, limits)?;
    encode_limit_entry(encoder, 28, LimitKind::ApproverAnchors, limits)?;
    encode_limit_entry(encoder, 29, LimitKind::ApprovalRequirements, limits)?;
    Ok(())
}

fn encode_composition_requirement(
    encoder: &mut V1Encoder,
    requirement: CompositionRequirement,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    let expected_plan = requirement.expected_plan();
    let expected_plan_bytes = match expected_plan.as_ref() {
        Some(plan) => Some(plan.as_bytes()),
        None => None,
    };
    encode_optional_digest(encoder, expected_plan_bytes)?;
    key(encoder, 1)?;
    encoder
        .u16(requirement.minimum_authorized_branches())
        .map_err(encode_error)?;
    key(encoder, 2)?;
    encoder
        .u16(requirement.minimum_distinct_actors())
        .map_err(encode_error)?;
    key(encoder, 3)?;
    encoder
        .u16(requirement.minimum_distinct_roots())
        .map_err(encode_error)?;
    Ok(())
}

fn encode_verifier_context_to(
    encoder: &mut V1Encoder,
    context: &TrustedContext,
) -> Result<(), CodecError> {
    map(encoder, 17)?;
    key(encoder, 0)?;
    encode_limits(encoder, context.limits())?;
    key(encoder, 1)?;
    bytes(encoder, context.configuration().as_bytes())?;
    key(encoder, 2)?;
    encode_composition_requirement(encoder, context.composition())?;
    key(encoder, 3)?;
    encode_trust_anchors(encoder, context.trust_anchors())?;
    key(encoder, 4)?;
    encode_registries(encoder, context.accepted_registries())?;
    key(encoder, 5)?;
    text(encoder, context.expected_audience().as_str())?;
    key(encoder, 6)?;
    bytes(encoder, context.expected_challenge().as_bytes())?;
    key(encoder, 7)?;
    encoder
        .u64(context.evaluation_time().get())
        .map_err(encode_error)?;
    key(encoder, 8)?;
    encode_assurance_policy(encoder, context.assurance_policy())?;
    key(encoder, 9)?;
    encode_principal_snapshot(encoder, context.principal_status_snapshot())?;
    key(encoder, 10)?;
    encode_grant_snapshot(encoder, context.grant_status_snapshot())?;
    key(encoder, 11)?;
    text(encoder, context.resource_matcher().as_str())?;
    key(encoder, 12)?;
    text(encoder, context.profile_policy().as_str())?;
    key(encoder, 13)?;
    text(encoder, context.channel_policy().as_str())?;
    key(encoder, 14)?;
    crate::observation::encode_observer_anchors(encoder, context.observer_anchors())?;
    key(encoder, 15)?;
    crate::approval::encode_approver_anchors(encoder, context.approver_anchors())?;
    key(encoder, 16)?;
    crate::approval::encode_context_requirements(encoder, context.approval_requirements())?;
    Ok(())
}

/// Encodes the deterministic public trusted-context projection.
/// Requires explicit canonical construction of the context and its nested
/// snapshots and approval requirements.
///
/// # Errors
///
/// Returns [`CodecError`] if the context exceeds a protocol encoding bound.
pub fn encode_verifier_context(context: &CanonicalTrustedContext) -> Result<Vec<u8>, CodecError> {
    encode_verifier_context_value(context.as_value())
}

pub(crate) fn encode_verifier_context_value(context: &TrustedContext) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode_verifier_context_to(&mut encoder, context)?;
    Ok(encoder.into_writer())
}


fn encode_assurance_requirement(encoder: &mut V1Encoder, requirement: &auths_model::AssuranceRequirement) -> Result<(), CodecError> {
    map(encoder, 8)?;
    key(encoder, 0)?;
    encoder.u8(assurance_role_tag(requirement.role())).map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, requirement.claim_kind().as_str())?;
    key(encoder, 2)?;
    encode_assurance_parameters(encoder, requirement.parameters())?;
    key(encoder, 3)?;
    encode_assurance_source(encoder, requirement.source())?;
    key(encoder, 4)?;
    encode_assurance_adapter(encoder, requirement.adapter())?;
    key(encoder, 5)?;
    encode_assurance_version(encoder, requirement.adapter_version())?;
    key(encoder, 6)?;
    encode_assurance_maximum_age(encoder, requirement.maximum_age())?;
    key(encoder, 7)?;
    encoder.u8(assurance_quantifier_tag(requirement.quantifier())).map_err(encode_error)?;
    Ok(())
}

fn assurance_role_tag(role: ParticipantRole) -> u8 {
    match role {
        ParticipantRole::Root => 0,
        ParticipantRole::Intermediate => 1,
        ParticipantRole::Actor => 2,
        ParticipantRole::ExternalIssuer => 3,
    }
}

fn assurance_quantifier_tag(quantifier: AssuranceQuantifier) -> u8 {
    match quantifier {
        AssuranceQuantifier::Any => 0,
        AssuranceQuantifier::Every => 1,
    }
}

fn encode_assurance_parameters(
    encoder: &mut V1Encoder,
    parameters: &[(auths_model::ClaimParameterId, auths_model::ClaimParameterId)],
) -> Result<(), CodecError> {
    array(encoder, parameters.len())?;
    crate::collections::write_items!(parameters, parameter => encode_claim_parameter(encoder, parameter))?;
    Ok(())
}

fn encode_assurance_source(
    encoder: &mut V1Encoder,
    source: Option<&auths_model::EvidenceSourceId>,
) -> Result<(), CodecError> {
    if let Some(source) = source {
        text(encoder, source.as_str())?;
    } else {
        encoder.null();
    }
    Ok(())
}

fn encode_assurance_adapter(
    encoder: &mut V1Encoder,
    adapter: Option<&auths_model::AdapterId>,
) -> Result<(), CodecError> {
    if let Some(adapter) = adapter {
        text(encoder, adapter.as_str())?;
    } else {
        encoder.null();
    }
    Ok(())
}

fn encode_assurance_version(
    encoder: &mut V1Encoder,
    version: Option<u16>,
) -> Result<(), CodecError> {
    if let Some(version) = version {
        encoder.u16(version).map_err(encode_error)?;
    } else {
        encoder.null();
    }
    Ok(())
}

fn encode_assurance_maximum_age(
    encoder: &mut V1Encoder,
    maximum_age: Option<auths_model::FreshnessLimit>,
) -> Result<(), CodecError> {
    if let Some(maximum_age) = maximum_age {
        encoder.u64(maximum_age.get()).map_err(encode_error)?;
    } else {
        encoder.null();
    }
    Ok(())
}

fn encode_status_trust_rule(encoder: &mut V1Encoder, rule: &StatusTrustRule) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    text(encoder, rule.method().as_str())?;
    key(encoder, 1)?;
    text(encoder, rule.issuer().as_str())?;
    key(encoder, 2)?;
    encoder.u64(rule.sequence_floor()).map_err(encode_error)?;
    key(encoder, 3)?;
    encode_status_scope(encoder, rule.scope())?;
    Ok(())
}

fn encode_claim_parameter(
    encoder: &mut V1Encoder,
    parameter: &(auths_model::ClaimParameterId, auths_model::ClaimParameterId),
) -> Result<(), CodecError> {
    array(encoder, 2)?;
    text(encoder, parameter.0.as_str())?;
    text(encoder, parameter.1.as_str())?;
    Ok(())
}


fn encode_unsigned_entry(
    encoder: &mut V1Encoder,
    index: u8,
    value: u64,
) -> Result<(), CodecError> {
    key(encoder, index)?;
    encoder.u64(value).map_err(encode_error)?;
    Ok(())
}

fn encode_limit_entry(
    encoder: &mut V1Encoder,
    index: u8,
    kind: LimitKind,
    limits: &VerifierLimits,
) -> Result<(), CodecError> {
    key(encoder, index)?;
    encoder.u64(length(limits.get(kind))?).map_err(encode_error)?;
    Ok(())
}


fn push_keyed_grants<'a>(
    mut keyed: Vec<(auths_model::GrantId, &'a SignedGrant)>,
    grant: &'a SignedGrant,
) -> Result<Vec<(auths_model::GrantId, &'a SignedGrant)>, CodecError> {
    keyed.push((grant_id(grant.statement())?, grant));
    Ok(keyed)
}

fn push_keyed_principal_status<'a>(
    mut keyed: Vec<(auths_model::PrincipalStatusId, &'a SignedPrincipalStatus)>,
    status: &'a SignedPrincipalStatus,
) -> Result<Vec<(auths_model::PrincipalStatusId, &'a SignedPrincipalStatus)>, CodecError> {
    keyed.push((principal_status_id(status.statement())?, status));
    Ok(keyed)
}

fn push_keyed_grant_status<'a>(
    mut keyed: Vec<(auths_model::GrantStatusId, &'a SignedGrantStatus)>,
    status: &'a SignedGrantStatus,
) -> Result<Vec<(auths_model::GrantStatusId, &'a SignedGrantStatus)>, CodecError> {
    keyed.push((grant_status_id(status.statement())?, status));
    Ok(keyed)
}

// The former implementation is retained only as a refactor-equivalence oracle.
#[cfg(test)]
pub(crate) fn encode_canonical_action_reference(
    action: &CanonicalAction,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| {
        map(encoder, 6)?;
        key(encoder, 0)?;
        encode_profile_ref(encoder, action.profile())?;
        key(encoder, 1)?;
        text(encoder, action.media_type().as_str())?;
        key(encoder, 2)?;
        bytes(encoder, action.body())?;
        key(encoder, 3)?;
        encode_permission(encoder, action.permission())?;
        key(encoder, 4)?;
        encode_optional_budget(encoder, action.requested_budget())?;
        key(encoder, 5)?;
        array(encoder, action.detached_attachments().len())?;
        for attachment in action.detached_attachments() {
            map(encoder, 2)?;
            key(encoder, 0)?;
            bytes(encoder, attachment.digest().as_bytes())?;
            key(encoder, 1)?;
            bytes(encoder, attachment.bytes())?;
        }
        Ok(())
    })
}
