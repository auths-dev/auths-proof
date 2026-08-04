//! Deterministic target V1 encoders.

use crate::{
    CodecError,
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
    StatusPolicy, StatusTrustRule, TrustAnchor, VerificationCode, VerificationDecision,
    VerificationResources, VerificationStage, VerifierContext, VerifierLimits,
};
use minicbor::Encoder;

type V1Encoder = Encoder<Vec<u8>>;

fn encode_error<T>(_error: minicbor::encode::Error<T>) -> CodecError {
    CodecError::Malformed
}

fn length(value: usize) -> Result<u64, CodecError> {
    u64::try_from(value).map_err(|_| CodecError::LimitExceeded)
}

pub(crate) fn finish(
    encode: impl FnOnce(&mut V1Encoder) -> Result<(), CodecError>,
) -> Result<Vec<u8>, CodecError> {
    let mut encoder = Encoder::new(Vec::new());
    encode(&mut encoder)?;
    Ok(encoder.into_writer())
}

fn map(encoder: &mut V1Encoder, entries: u64) -> Result<(), CodecError> {
    encoder.map(entries).map_err(encode_error)?;
    Ok(())
}

fn array(encoder: &mut V1Encoder, entries: usize) -> Result<(), CodecError> {
    encoder.array(length(entries)?).map_err(encode_error)?;
    Ok(())
}

fn key(encoder: &mut V1Encoder, value: u8) -> Result<(), CodecError> {
    encoder.u8(value).map_err(encode_error)?;
    Ok(())
}

fn text(encoder: &mut V1Encoder, value: &str) -> Result<(), CodecError> {
    encoder.str(value).map_err(encode_error)?;
    Ok(())
}

fn bytes(encoder: &mut V1Encoder, value: &[u8]) -> Result<(), CodecError> {
    encoder.bytes(value).map_err(encode_error)?;
    Ok(())
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
    for permission in permissions.as_slice() {
        encode_permission(encoder, permission)?;
    }
    Ok(())
}

fn encode_status_policy(encoder: &mut V1Encoder, policy: &StatusPolicy) -> Result<(), CodecError> {
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

fn encode_optional_budget(
    encoder: &mut V1Encoder,
    budget: Option<&BudgetCeiling>,
) -> Result<(), CodecError> {
    if let Some(budget) = budget {
        encode_budget(encoder, budget)
    } else {
        encoder.null().map_err(encode_error)?;
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
            array(encoder, digests.as_slice().len())?;
            for digest in digests.as_slice() {
                bytes(encoder, digest.as_bytes())?;
            }
        }
    }
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
    for extension in extensions.as_slice() {
        encode_extension(encoder, extension)?;
    }
    Ok(())
}

fn encode_signature_descriptor(
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

fn encode_signature(
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
    array(encoder, statement.audiences().as_slice().len())?;
    for audience in statement.audiences().as_slice() {
        text(encoder, audience.as_str())?;
    }
    key(encoder, 9)?;
    encode_constraint(encoder, statement.action_constraint())?;
    key(encoder, 10)?;
    encode_optional_budget(encoder, statement.budget_ceiling())?;
    key(encoder, 11)?;
    encoder
        .u16(statement.remaining_depth())
        .map_err(encode_error)?;
    key(encoder, 12)?;
    if let Some(parent) = statement.parent() {
        bytes(encoder, parent.as_bytes())?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
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
    finish(|encoder| encode_grant_statement_to(encoder, statement))
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
    finish(|encoder| encode_signed_grant_to(encoder, grant))
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
    if let Some(grant) = envelope.terminal_grant() {
        bytes(encoder, grant.as_bytes())?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    key(encoder, 14)?;
    bytes(encoder, envelope.authorization_plan().as_bytes())?;
    key(encoder, 15)?;
    text(encoder, envelope.channel_binding().as_str())?;
    key(encoder, 16)?;
    bytes(encoder, envelope.proof_ref().as_bytes())?;
    key(encoder, 17)?;
    array(encoder, envelope.attachments().len())?;
    for attachment in envelope.attachments() {
        encode_attachment(encoder, attachment)?;
    }
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
    finish(|encoder| encode_action_envelope_to(encoder, envelope))
}

/// Encodes the complete portable canonical-action verifier input.
///
/// # Errors
///
/// Returns [`CodecError`] if a length cannot be represented canonically.
pub fn encode_canonical_action(action: &CanonicalAction) -> Result<Vec<u8>, CodecError> {
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

fn encode_assurance_claim(
    encoder: &mut V1Encoder,
    claim: &AssuranceClaim,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    text(encoder, claim.kind().as_str())?;
    key(encoder, 1)?;
    array(encoder, claim.parameters().len())?;
    for (name, value) in claim.parameters() {
        array(encoder, 2)?;
        text(encoder, name.as_str())?;
        text(encoder, value.as_str())?;
    }
    key(encoder, 2)?;
    if let Some(observed_at) = claim.observed_at() {
        encoder.u64(observed_at.get()).map_err(encode_error)?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    key(encoder, 3)?;
    text(encoder, claim.source().as_str())?;
    Ok(())
}

fn encode_role(encoder: &mut V1Encoder, role: ParticipantRole) -> Result<(), CodecError> {
    encoder
        .u8(match role {
            ParticipantRole::Root => 0,
            ParticipantRole::Intermediate => 1,
            ParticipantRole::Actor => 2,
            ParticipantRole::ExternalIssuer => 3,
        })
        .map_err(encode_error)?;
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
    array(encoder, report.claims().len())?;
    for claim in report.claims() {
        encode_assurance_claim(encoder, claim)?;
    }
    key(encoder, 3)?;
    array(encoder, report.evidence().len())?;
    for evidence in report.evidence() {
        bytes(encoder, evidence.as_bytes())?;
    }
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
    array(encoder, satisfaction.evidence().len())?;
    for evidence in satisfaction.evidence() {
        bytes(encoder, evidence.as_bytes())?;
    }
    Ok(())
}

fn encode_verification_resources(
    encoder: &mut V1Encoder,
    resources: VerificationResources,
) -> Result<(), CodecError> {
    map(encoder, 7)?;
    for (key_value, value) in [
        resources.proof_bytes(),
        resources.action_bytes(),
        resources.context_bytes(),
        resources.object_count(),
        resources.plan_leaves(),
        resources.plan_depth(),
        resources.work_units(),
    ]
    .into_iter()
    .enumerate()
    {
        key(
            encoder,
            u8::try_from(key_value).map_err(|_| CodecError::LimitExceeded)?,
        )?;
        encoder.u64(value).map_err(encode_error)?;
    }
    Ok(())
}

fn encode_verification_result_to(
    encoder: &mut V1Encoder,
    result: &PortableVerificationResult,
    include_result_digest: bool,
) -> Result<(), CodecError> {
    map(encoder, 16)?;
    key(encoder, 0)?;
    encoder
        .u8(match result.decision() {
            VerificationDecision::Authorized => 0,
            VerificationDecision::Denied => 1,
            VerificationDecision::Indeterminate => 2,
        })
        .map_err(encode_error)?;
    key(encoder, 1)?;
    encoder
        .u8(match result.stage() {
            VerificationStage::Decode => 0,
            VerificationStage::Resolve => 1,
            VerificationStage::PrincipalControl => 2,
            VerificationStage::Authority => 3,
            VerificationStage::Complete => 4,
        })
        .map_err(encode_error)?;
    key(encoder, 2)?;
    map(encoder, 2)?;
    key(encoder, 0)?;
    let class = match result.code() {
        VerificationCode::Authorized => 0,
        VerificationCode::Denied(_) => 1,
        VerificationCode::Indeterminate(_) => 2,
    };
    encoder.u8(class).map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, result.code().code())?;
    key(encoder, 3)?;
    bytes(encoder, result.proof_digest().as_bytes())?;
    key(encoder, 4)?;
    bytes(encoder, result.action_digest().as_bytes())?;
    key(encoder, 5)?;
    bytes(encoder, result.context_digest().as_bytes())?;
    key(encoder, 6)?;
    if let Some(plan_id) = result.plan_id() {
        bytes(encoder, plan_id.as_bytes())?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    key(encoder, 7)?;
    if include_result_digest {
        bytes(encoder, result.result_digest().as_bytes())?;
    } else {
        bytes(encoder, &[0; 32])?;
    }
    key(encoder, 8)?;
    array(encoder, result.authorized_branches().len())?;
    for branch in result.authorized_branches() {
        bytes(encoder, branch.as_bytes())?;
    }
    key(encoder, 9)?;
    array(encoder, result.assurance().len())?;
    for report in result.assurance() {
        encode_assurance_report(encoder, report)?;
    }
    key(encoder, 10)?;
    array(encoder, result.assurance_satisfactions().len())?;
    for satisfaction in result.assurance_satisfactions() {
        encode_assurance_satisfaction(encoder, satisfaction)?;
    }
    key(encoder, 11)?;
    encode_verification_resources(encoder, result.resources())?;
    key(encoder, 12)?;
    bytes(encoder, result.registry_manifest().as_bytes())?;
    key(encoder, 13)?;
    if let Some(configuration) = result.required_configuration() {
        bytes(encoder, configuration.as_bytes())?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    key(encoder, 14)?;
    bytes(encoder, result.local_configuration().as_bytes())?;
    key(encoder, 15)?;
    encoder.u16(2).map_err(encode_error)?;
    Ok(())
}

/// Encodes the complete portable verifier output.
///
/// # Errors
///
/// Returns [`CodecError`] if a result collection cannot be represented.
pub fn encode_verification_result(
    result: &PortableVerificationResult,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_verification_result_to(encoder, result, true))
}

/// Encodes the result projection used to derive its self-binding digest.
///
/// # Errors
///
/// Returns [`CodecError`] if a result collection cannot be represented.
pub fn encode_verification_result_digest_input(
    result: &PortableVerificationResult,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_verification_result_to(encoder, result, false))
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
    finish(|encoder| encode_signed_action_to(encoder, action))
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
            array(encoder, members.len())?;
            for member in members {
                encode_authorization_plan_to(encoder, member)?;
            }
        }
        AuthorizationPlanRef::AnyOf(members) => {
            map(encoder, 2)?;
            key(encoder, 0)?;
            encoder.u8(2).map_err(encode_error)?;
            key(encoder, 1)?;
            array(encoder, members.len())?;
            for member in members {
                encode_authorization_plan_to(encoder, member)?;
            }
        }
        AuthorizationPlanRef::KOfN { k, members } => {
            map(encoder, 3)?;
            key(encoder, 0)?;
            encoder.u8(3).map_err(encode_error)?;
            key(encoder, 1)?;
            encoder.u16(k).map_err(encode_error)?;
            key(encoder, 2)?;
            array(encoder, members.len())?;
            for member in members {
                encode_authorization_plan_to(encoder, member)?;
            }
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
    finish(|encoder| encode_authorization_plan_to(encoder, plan))
}

fn encode_evidence(encoder: &mut V1Encoder, evidence: &EvidenceObject) -> Result<(), CodecError> {
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
    finish(|encoder| encode_evidence_content_to(encoder, evidence))
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

fn encode_binding(encoder: &mut V1Encoder, binding: &ControlBinding) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    encode_statement_ref(encoder, binding.statement())?;
    key(encoder, 1)?;
    array(encoder, binding.evidence().len())?;
    for evidence in binding.evidence() {
        bytes(encoder, evidence.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn encode_principal_status_statement_to(
    encoder: &mut V1Encoder,
    statement: &PrincipalStatusStatement,
) -> Result<(), CodecError> {
    map(encoder, 10)?;
    key(encoder, 0)?;
    encoder
        .u16(statement.version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    text(encoder, statement.method().as_str())?;
    key(encoder, 2)?;
    text(encoder, statement.principal().as_str())?;
    key(encoder, 3)?;
    text(encoder, statement.purpose().as_str())?;
    key(encoder, 4)?;
    let state = match statement.state() {
        PrincipalState::Active => 0,
        PrincipalState::Revoked => 1,
        PrincipalState::Superseded => 2,
    };
    encoder.u8(state).map_err(encode_error)?;
    key(encoder, 5)?;
    encoder.u64(statement.sequence()).map_err(encode_error)?;
    key(encoder, 6)?;
    encoder
        .u64(statement.observed_at().get())
        .map_err(encode_error)?;
    key(encoder, 7)?;
    encoder
        .u64(statement.valid_until().get())
        .map_err(encode_error)?;
    key(encoder, 8)?;
    text(encoder, statement.issuer().as_str())?;
    key(encoder, 9)?;
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
    finish(|encoder| encode_principal_status_statement_to(encoder, statement))
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
    finish(|encoder| encode_signed_principal_status_to(encoder, status))
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
    finish(|encoder| encode_grant_status_statement_to(encoder, statement))
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
    finish(|encoder| encode_signed_grant_status_to(encoder, status))
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
    encoder.bool(attachment.encrypted()).map_err(encode_error)?;
    key(encoder, 5)?;
    encoder.bool(attachment.required()).map_err(encode_error)?;
    key(encoder, 6)?;
    encoder
        .bool(attachment.opaque_allowed())
        .map_err(encode_error)?;
    Ok(())
}

fn sorted_grants(bundle: &ProofBundle) -> Result<Vec<&SignedGrant>, CodecError> {
    let mut keyed = Vec::with_capacity(bundle.grants().len());
    for grant in bundle.grants() {
        keyed.push((grant_id(grant.statement())?, grant));
    }
    keyed.sort_by_key(|(identifier, _)| *identifier);
    Ok(keyed.into_iter().map(|(_, grant)| grant).collect())
}

fn sorted_principal_status(
    values: &[SignedPrincipalStatus],
) -> Result<Vec<&SignedPrincipalStatus>, CodecError> {
    let mut keyed = Vec::with_capacity(values.len());
    for status in values {
        keyed.push((principal_status_id(status.statement())?, status));
    }
    keyed.sort_by_key(|(identifier, _)| *identifier);
    Ok(keyed.into_iter().map(|(_, status)| status).collect())
}

fn sorted_grant_status(
    values: &[SignedGrantStatus],
) -> Result<Vec<&SignedGrantStatus>, CodecError> {
    let mut keyed = Vec::with_capacity(values.len());
    for status in values {
        keyed.push((grant_status_id(status.statement())?, status));
    }
    keyed.sort_by_key(|(identifier, _)| *identifier);
    Ok(keyed.into_iter().map(|(_, status)| status).collect())
}

fn encode_bundle_to(encoder: &mut V1Encoder, bundle: &ProofBundle) -> Result<(), CodecError> {
    map(encoder, 10)?;
    key(encoder, 0)?;
    map(encoder, 2)?;
    key(encoder, 0)?;
    encoder
        .u16(bundle.header().version().get())
        .map_err(encode_error)?;
    key(encoder, 1)?;
    encoder.u64(bundle.header().flags()).map_err(encode_error)?;

    key(encoder, 1)?;
    let grants = sorted_grants(bundle)?;
    array(encoder, grants.len())?;
    for grant in grants {
        encode_signed_grant_to(encoder, grant)?;
    }

    key(encoder, 2)?;
    let mut actions: Vec<_> = bundle.actions().iter().collect();
    actions.sort_by_key(|action| action.envelope().proof_ref());
    array(encoder, actions.len())?;
    for action in actions {
        encode_signed_action_to(encoder, action)?;
    }

    key(encoder, 3)?;
    encode_authorization_plan_to(encoder, bundle.plan())?;

    key(encoder, 4)?;
    let mut evidence: Vec<_> = bundle.evidence().iter().collect();
    evidence.sort_by_key(|item| item.id());
    array(encoder, evidence.len())?;
    for item in evidence {
        encode_evidence(encoder, item)?;
    }

    key(encoder, 5)?;
    let mut bindings: Vec<_> = bundle.bindings().iter().collect();
    bindings.sort_by_key(|binding| binding.statement());
    array(encoder, bindings.len())?;
    for binding in bindings {
        encode_binding(encoder, binding)?;
    }

    key(encoder, 6)?;
    let principal_status = sorted_principal_status(bundle.principal_status())?;
    array(encoder, principal_status.len())?;
    for status in principal_status {
        encode_signed_principal_status_to(encoder, status)?;
    }

    key(encoder, 7)?;
    let grant_status = sorted_grant_status(bundle.grant_status())?;
    array(encoder, grant_status.len())?;
    for status in grant_status {
        encode_signed_grant_status_to(encoder, status)?;
    }

    key(encoder, 8)?;
    let mut attachments: Vec<_> = bundle.attachments().iter().collect();
    attachments.sort_by_key(|attachment| attachment.digest());
    array(encoder, attachments.len())?;
    for attachment in attachments {
        encode_attachment(encoder, attachment)?;
    }

    key(encoder, 9)?;
    if let Some(body) = bundle.canonical_body() {
        bytes(encoder, body)?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
    Ok(())
}

/// Encodes a complete proof bundle using deterministic target V1 CBOR.
///
/// # Errors
///
/// Returns [`CodecError`] if the value exceeds a protocol encoding bound.
pub fn encode_bundle(bundle: &ProofBundle) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_bundle_to(encoder, bundle))
}

fn encode_signing_input(
    statement: impl FnOnce(&mut V1Encoder) -> Result<(), CodecError>,
    descriptor: &SignatureDescriptor,
) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| {
        map(encoder, 2)?;
        key(encoder, 0)?;
        statement(encoder)?;
        key(encoder, 1)?;
        encode_signature_descriptor(encoder, descriptor)
    })
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
    encode_signing_input(
        |encoder| encode_grant_statement_to(encoder, statement),
        descriptor,
    )
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
    encode_signing_input(
        |encoder| encode_action_envelope_to(encoder, envelope),
        descriptor,
    )
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
    encode_signing_input(
        |encoder| encode_principal_status_statement_to(encoder, statement),
        descriptor,
    )
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
    encode_signing_input(
        |encoder| encode_grant_status_statement_to(encoder, statement),
        descriptor,
    )
}

fn encode_assurance_policy(
    encoder: &mut V1Encoder,
    policy: &auths_model::AssurancePolicy,
) -> Result<(), CodecError> {
    map(encoder, 2)?;
    key(encoder, 0)?;
    text(encoder, policy.id().as_str())?;
    key(encoder, 1)?;
    array(encoder, policy.requirements().len())?;
    for requirement in policy.requirements() {
        map(encoder, 8)?;
        key(encoder, 0)?;
        let role = match requirement.role() {
            ParticipantRole::Root => 0,
            ParticipantRole::Intermediate => 1,
            ParticipantRole::Actor => 2,
            ParticipantRole::ExternalIssuer => 3,
        };
        encoder.u8(role).map_err(encode_error)?;
        key(encoder, 1)?;
        text(encoder, requirement.claim_kind().as_str())?;
        key(encoder, 2)?;
        array(encoder, requirement.parameters().len())?;
        for (name, value) in requirement.parameters() {
            array(encoder, 2)?;
            text(encoder, name.as_str())?;
            text(encoder, value.as_str())?;
        }
        key(encoder, 3)?;
        if let Some(source) = requirement.source() {
            text(encoder, source.as_str())?;
        } else {
            encoder.null().map_err(encode_error)?;
        }
        key(encoder, 4)?;
        if let Some(adapter) = requirement.adapter() {
            text(encoder, adapter.as_str())?;
        } else {
            encoder.null().map_err(encode_error)?;
        }
        key(encoder, 5)?;
        if let Some(version) = requirement.adapter_version() {
            encoder.u16(version).map_err(encode_error)?;
        } else {
            encoder.null().map_err(encode_error)?;
        }
        key(encoder, 6)?;
        if let Some(maximum_age) = requirement.maximum_age() {
            encoder.u64(maximum_age.get()).map_err(encode_error)?;
        } else {
            encoder.null().map_err(encode_error)?;
        }
        key(encoder, 7)?;
        encoder
            .u8(match requirement.quantifier() {
                AssuranceQuantifier::Any => 0,
                AssuranceQuantifier::Every => 1,
            })
            .map_err(encode_error)?;
    }
    Ok(())
}

fn encode_anchor(encoder: &mut V1Encoder, anchor: &TrustAnchor) -> Result<(), CodecError> {
    map(encoder, 13)?;
    key(encoder, 0)?;
    text(encoder, anchor.id().as_str())?;
    key(encoder, 1)?;
    text(encoder, anchor.principal().as_str())?;
    key(encoder, 2)?;
    array(encoder, anchor.accepted_methods().len())?;
    for method in anchor.accepted_methods() {
        text(encoder, method.as_str())?;
    }
    key(encoder, 3)?;
    array(encoder, anchor.profiles().len())?;
    for profile in anchor.profiles() {
        encode_profile_ref(encoder, profile)?;
    }
    key(encoder, 4)?;
    encode_permission_set(encoder, anchor.permissions())?;
    key(encoder, 5)?;
    array(encoder, anchor.resource_namespaces().len())?;
    for resource in anchor.resource_namespaces() {
        text(encoder, resource.as_str())?;
    }
    key(encoder, 6)?;
    array(encoder, anchor.audiences().as_slice().len())?;
    for audience in anchor.audiences().as_slice() {
        text(encoder, audience.as_str())?;
    }
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

fn encode_registry_ids<T>(
    encoder: &mut V1Encoder,
    identifiers: &[T],
    as_str: impl for<'a> Fn(&'a T) -> &'a str,
) -> Result<(), CodecError> {
    array(encoder, identifiers.len())?;
    for identifier in identifiers {
        text(encoder, as_str(identifier))?;
    }
    Ok(())
}

fn encode_registries(
    encoder: &mut V1Encoder,
    registries: &AcceptedRegistries,
) -> Result<(), CodecError> {
    map(encoder, 13)?;
    key(encoder, 0)?;
    bytes(encoder, registries.manifest_id().as_bytes())?;
    key(encoder, 1)?;
    encode_registry_ids(encoder, registries.principal_methods(), |id| id.as_str())?;
    key(encoder, 2)?;
    encode_registry_ids(encoder, registries.signature_suites(), |id| id.as_str())?;
    key(encoder, 3)?;
    encode_registry_ids(encoder, registries.evidence_types(), |id| id.as_str())?;
    key(encoder, 4)?;
    encode_registry_ids(encoder, registries.principal_status_methods(), |id| {
        id.as_str()
    })?;
    key(encoder, 5)?;
    encode_registry_ids(encoder, registries.grant_status_methods(), |id| id.as_str())?;
    key(encoder, 6)?;
    encode_registry_ids(encoder, registries.assurance_claims(), |id| id.as_str())?;
    key(encoder, 7)?;
    encode_registry_ids(encoder, registries.assurance_implications(), |id| {
        id.as_str()
    })?;
    key(encoder, 8)?;
    encode_registry_ids(encoder, registries.resource_matchers(), |id| id.as_str())?;
    key(encoder, 9)?;
    encode_registry_ids(encoder, registries.budget_algebras(), |id| id.as_str())?;
    key(encoder, 10)?;
    encode_registry_ids(encoder, registries.critical_extensions(), |id| id.as_str())?;
    key(encoder, 11)?;
    array(encoder, registries.profiles().len())?;
    for profile in registries.profiles() {
        encode_profile_ref(encoder, profile)?;
    }
    key(encoder, 12)?;
    encode_registry_ids(encoder, registries.profile_policies(), |id| id.as_str())?;
    Ok(())
}

fn encode_status_trust(
    encoder: &mut V1Encoder,
    rules: &[StatusTrustRule],
) -> Result<(), CodecError> {
    array(encoder, rules.len())?;
    for rule in rules {
        map(encoder, 3)?;
        key(encoder, 0)?;
        text(encoder, rule.method().as_str())?;
        key(encoder, 1)?;
        text(encoder, rule.issuer().as_str())?;
        key(encoder, 2)?;
        encoder.u64(rule.sequence_floor()).map_err(encode_error)?;
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
    array(encoder, statuses.len())?;
    for status in statuses {
        encode_signed_principal_status_to(encoder, status)?;
    }
    key(encoder, 4)?;
    array(encoder, snapshot.checkpoints().len())?;
    for checkpoint in snapshot.checkpoints() {
        bytes(encoder, checkpoint.as_bytes())?;
    }
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
    array(encoder, statuses.len())?;
    for status in statuses {
        encode_signed_grant_status_to(encoder, status)?;
    }
    key(encoder, 4)?;
    array(encoder, snapshot.checkpoints().len())?;
    for checkpoint in snapshot.checkpoints() {
        bytes(encoder, checkpoint.as_bytes())?;
    }
    key(encoder, 5)?;
    encode_status_trust(encoder, snapshot.trust())?;
    Ok(())
}

fn encode_limits(encoder: &mut V1Encoder, limits: &VerifierLimits) -> Result<(), CodecError> {
    const LIMITS: [LimitKind; 26] = [
        LimitKind::BundleBytes,
        LimitKind::ActionBytes,
        LimitKind::ContextBytes,
        LimitKind::Grants,
        LimitKind::Actions,
        LimitKind::PlanLeaves,
        LimitKind::PlanDepth,
        LimitKind::PlanBranching,
        LimitKind::EvidenceObjects,
        LimitKind::EvidenceBytes,
        LimitKind::ControlBindings,
        LimitKind::PrincipalStatusStatements,
        LimitKind::GrantStatusStatements,
        LimitKind::Attachments,
        LimitKind::AttachmentBytes,
        LimitKind::Signatures,
        LimitKind::SignatureBytes,
        LimitKind::Permissions,
        LimitKind::Audiences,
        LimitKind::CriticalExtensions,
        LimitKind::CriticalExtensionBytes,
        LimitKind::AllowedBodyDigests,
        LimitKind::BindingEvidence,
        LimitKind::CanonicalBodyBytes,
        LimitKind::RegistryEntries,
        LimitKind::TrustAnchors,
    ];
    map(encoder, 27)?;
    for (index, kind) in LIMITS.into_iter().enumerate() {
        key(
            encoder,
            u8::try_from(index).map_err(|_| CodecError::LimitExceeded)?,
        )?;
        encoder
            .u64(length(limits.get(kind))?)
            .map_err(encode_error)?;
    }
    key(encoder, 26)?;
    encoder.u64(limits.max_work_units()).map_err(encode_error)?;
    Ok(())
}

fn encode_composition_requirement(
    encoder: &mut V1Encoder,
    requirement: CompositionRequirement,
) -> Result<(), CodecError> {
    map(encoder, 4)?;
    key(encoder, 0)?;
    if let Some(plan) = requirement.expected_plan() {
        bytes(encoder, plan.as_bytes())?;
    } else {
        encoder.null().map_err(encode_error)?;
    }
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
    context: &VerifierContext,
) -> Result<(), CodecError> {
    map(encoder, 14)?;
    key(encoder, 0)?;
    encode_limits(encoder, context.limits())?;
    key(encoder, 1)?;
    bytes(encoder, context.configuration().as_bytes())?;
    key(encoder, 2)?;
    encode_composition_requirement(encoder, context.composition())?;
    key(encoder, 3)?;
    array(encoder, context.trust_anchors().len())?;
    for anchor in context.trust_anchors() {
        encode_anchor(encoder, anchor)?;
    }
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
    Ok(())
}

/// Encodes the deterministic public verifier-context projection.
///
/// # Errors
///
/// Returns [`CodecError`] if the context exceeds a protocol encoding bound.
pub fn encode_verifier_context(context: &VerifierContext) -> Result<Vec<u8>, CodecError> {
    finish(|encoder| encode_verifier_context_to(encoder, context))
}
