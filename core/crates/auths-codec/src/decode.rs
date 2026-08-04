//! Strict, bounded target V1 decoders.

use crate::{
    CodecError,
    encode::{
        encode_action_envelope, encode_bundle, encode_grant_statement,
        encode_grant_status_statement, encode_principal_status_statement,
        encode_verifier_context,
    },
    hash::evidence_id,
};
use alloc::vec::Vec;
use auths_model::{
    AcceptedRegistries, ActionConstraint, ActionEnvelope, ActionId, AdapterId, AssuranceClaim,
    AssuranceClaimId, AssuranceImplicationId, AssurancePolicy, AssurancePolicyId,
    AssuranceQuantifier, AssuranceRequirement, AssuranceSatisfaction, AttachmentDescriptor,
    AttachmentDigest, Audience, AudienceSet, AuthorizationPlan, BudgetAlgebraId, BudgetCeiling,
    BundleHeader, CanonicalAction, CapabilityId, Challenge, ChannelBindingId,
    CompositionRequirement, ControlBinding, CriticalExtension, CriticalExtensions,
    DetachedAttachment, Digest, DispositionId, EvidenceId, EvidenceObject, EvidenceSourceId,
    EvidenceTypeId, ExtensionId, FreshnessLimit, GrantId, GrantState, GrantStatement,
    GrantStatusId, GrantStatusSnapshot, GrantStatusStatement, LimitKind, MediaType,
    ParticipantAssurance, Permission, PermissionSet, PlanId, PortableVerificationResult,
    PrincipalId, PrincipalMethodId, PrincipalState, PrincipalStatusId, PrincipalStatusSnapshot,
    PrincipalStatusStatement, ProfileId, ProfilePolicyId, ProfileRef, ProofBundle, ProofRef,
    ProtocolVersion, PurposeId, RegistryManifestId, ResourceId, ResourceMatcherId, SignatureBytes,
    SignatureDescriptor, SignatureEnvelope, SignatureSuiteId, SignedAction, SignedGrant,
    SignedGrantStatus, SignedPrincipalStatus, StatementRef, StatusMethodId, StatusPolicy,
    StatusSnapshotId, StatusTrustRule, Timestamp, TrustAnchor, TrustAnchorId, ValidityWindow,
    VerificationCode, VerificationDecision, VerificationMethod, VerificationResources,
    VerificationResultDigest, VerificationStage, VerifierConfigurationId, VerifierContext,
    VerifierLimits,
};
use minicbor::{Decoder, data::Type};

type V1Decoder<'a> = Decoder<'a>;

fn map(decoder: &mut V1Decoder<'_>, expected: u64) -> Result<(), CodecError> {
    if decoder.map().unwrap_or(None) == Some(expected) {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

fn array(decoder: &mut V1Decoder<'_>, maximum: usize) -> Result<usize, CodecError> {
    let length = decoder.array().map_err(|_| CodecError::Malformed)?;
    let length = length.ok_or(CodecError::Malformed)?;
    let length = usize::try_from(length).map_err(|_| CodecError::LimitExceeded)?;
    if length > maximum {
        return Err(CodecError::LimitExceeded);
    }
    Ok(length)
}

fn array_exact(decoder: &mut V1Decoder<'_>, expected: u64) -> Result<(), CodecError> {
    if decoder.array().map_err(|_| CodecError::Malformed)? == Some(expected) {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

fn key(decoder: &mut V1Decoder<'_>, expected: u8) -> Result<(), CodecError> {
    if decoder.u8().map_err(|_| CodecError::Malformed)? == expected {
        Ok(())
    } else {
        Err(CodecError::NonCanonical)
    }
}

fn text<'a>(decoder: &mut V1Decoder<'a>) -> Result<&'a str, CodecError> {
    decoder.str().map_err(|_| CodecError::Malformed)
}

fn bounded_bytes(
    decoder: &mut V1Decoder<'_>,
    maximum: usize,
    non_empty: bool,
) -> Result<Vec<u8>, CodecError> {
    let bytes = decoder.bytes().map_err(|_| CodecError::Malformed)?;
    if bytes.len() > maximum || (non_empty && bytes.is_empty()) {
        return Err(CodecError::LimitExceeded);
    }
    Ok(bytes.to_vec())
}

fn digest_bytes(decoder: &mut V1Decoder<'_>) -> Result<[u8; 32], CodecError> {
    decoder
        .bytes()
        .map_err(|_| CodecError::Malformed)?
        .try_into()
        .map_err(|_| CodecError::Malformed)
}

fn is_null(decoder: &V1Decoder<'_>) -> Result<bool, CodecError> {
    Ok(decoder.datatype().map_err(|_| CodecError::Malformed)? == Type::Null)
}

fn null(decoder: &mut V1Decoder<'_>) -> Result<(), CodecError> {
    decoder.null().map_err(|_| CodecError::Malformed)
}

macro_rules! parse_text {
    ($decoder:expr, $kind:ty) => {
        <$kind>::parse(text($decoder)?).map_err(CodecError::from)
    };
}

macro_rules! digest_id {
    ($decoder:expr, $kind:ty) => {
        Ok::<$kind, CodecError>(<$kind>::new(digest_bytes($decoder)?))
    };
}

fn profile_ref(decoder: &mut V1Decoder<'_>) -> Result<ProfileRef, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let id = parse_text!(decoder, ProfileId)?;
    key(decoder, 1)?;
    let version = decoder.u16().map_err(|_| CodecError::Malformed)?;
    ProfileRef::new(id, version).map_err(CodecError::from)
}

fn permission(decoder: &mut V1Decoder<'_>) -> Result<Permission, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let capability = parse_text!(decoder, CapabilityId)?;
    key(decoder, 1)?;
    let resource = parse_text!(decoder, ResourceId)?;
    Ok(Permission::new(capability, resource))
}

fn permissions(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<PermissionSet, CodecError> {
    let length = array(decoder, limits.get(LimitKind::Permissions))?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(permission(decoder)?);
    }
    PermissionSet::new(values).map_err(CodecError::from)
}

fn audiences(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<AudienceSet, CodecError> {
    let length = array(decoder, limits.get(LimitKind::Audiences))?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(parse_text!(decoder, Audience)?);
    }
    AudienceSet::new(values).map_err(CodecError::from)
}

fn status_policy(decoder: &mut V1Decoder<'_>) -> Result<StatusPolicy, CodecError> {
    let entries = decoder
        .map()
        .map_err(|_| CodecError::Malformed)?
        .ok_or(CodecError::Malformed)?;
    key(decoder, 0)?;
    match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 if entries == 1 => Ok(StatusPolicy::ExpiryOnly),
        1 if entries == 3 => {
            key(decoder, 1)?;
            let method = parse_text!(decoder, StatusMethodId)?;
            key(decoder, 2)?;
            let max_age = FreshnessLimit::new(decoder.u64().map_err(|_| CodecError::Malformed)?)?;
            Ok(StatusPolicy::SnapshotRequired { method, max_age })
        }
        _ => Err(CodecError::Malformed),
    }
}

fn budget(decoder: &mut V1Decoder<'_>) -> Result<BudgetCeiling, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let algebra = parse_text!(decoder, BudgetAlgebraId)?;
    key(decoder, 1)?;
    let value = decoder.u64().map_err(|_| CodecError::Malformed)?;
    Ok(BudgetCeiling::new(algebra, value))
}

fn optional_budget(decoder: &mut V1Decoder<'_>) -> Result<Option<BudgetCeiling>, CodecError> {
    if is_null(decoder)? {
        null(decoder)?;
        Ok(None)
    } else {
        Ok(Some(budget(decoder)?))
    }
}

fn constraint(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<ActionConstraint, CodecError> {
    let entries = decoder
        .map()
        .map_err(|_| CodecError::Malformed)?
        .ok_or(CodecError::Malformed)?;
    key(decoder, 0)?;
    match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 if entries == 1 => Ok(ActionConstraint::AnyBody),
        1 if entries == 2 => {
            key(decoder, 1)?;
            Ok(ActionConstraint::ExactBodyDigest(Digest::new(
                digest_bytes(decoder)?,
            )))
        }
        2 if entries == 2 => {
            key(decoder, 1)?;
            let length = array(decoder, limits.get(LimitKind::AllowedBodyDigests))?;
            let mut digests = Vec::with_capacity(length);
            for _ in 0..length {
                digests.push(Digest::new(digest_bytes(decoder)?));
            }
            ActionConstraint::allowed_body_digests(digests).map_err(CodecError::from)
        }
        _ => Err(CodecError::Malformed),
    }
}

fn extensions(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<CriticalExtensions, CodecError> {
    let length = array(decoder, limits.get(LimitKind::CriticalExtensions))?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        map(decoder, 2)?;
        key(decoder, 0)?;
        let id = parse_text!(decoder, ExtensionId)?;
        key(decoder, 1)?;
        let bytes = bounded_bytes(
            decoder,
            limits.get(LimitKind::CriticalExtensionBytes),
            false,
        )?;
        values.push(CriticalExtension::new(id, bytes)?);
    }
    CriticalExtensions::new(values).map_err(CodecError::from)
}

fn signature_descriptor(decoder: &mut V1Decoder<'_>) -> Result<SignatureDescriptor, CodecError> {
    map(decoder, 3)?;
    key(decoder, 0)?;
    let principal_method = parse_text!(decoder, PrincipalMethodId)?;
    key(decoder, 1)?;
    let verification_method = parse_text!(decoder, VerificationMethod)?;
    key(decoder, 2)?;
    let suite = parse_text!(decoder, SignatureSuiteId)?;
    Ok(SignatureDescriptor::new(
        principal_method,
        verification_method,
        suite,
    ))
}

fn signature(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignatureEnvelope, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let descriptor = signature_descriptor(decoder)?;
    key(decoder, 1)?;
    let bytes = bounded_bytes(decoder, limits.get(LimitKind::SignatureBytes), true)?;
    Ok(SignatureEnvelope::new(
        descriptor,
        SignatureBytes::new(bytes)?,
    ))
}

fn grant_statement(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<GrantStatement, CodecError> {
    map(decoder, 16)?;
    key(decoder, 0)?;
    ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let issuer = parse_text!(decoder, PrincipalId)?;
    key(decoder, 2)?;
    let subject = parse_text!(decoder, PrincipalId)?;
    key(decoder, 3)?;
    let profile_id = parse_text!(decoder, ProfileId)?;
    key(decoder, 4)?;
    let profile = ProfileRef::new(
        profile_id,
        decoder.u16().map_err(|_| CodecError::Malformed)?,
    )?;
    key(decoder, 5)?;
    let permissions = permissions(decoder, limits)?;
    key(decoder, 6)?;
    let not_before = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 7)?;
    let expires_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    let validity = ValidityWindow::new(not_before, expires_at)?;
    key(decoder, 8)?;
    let audiences = audiences(decoder, limits)?;
    key(decoder, 9)?;
    let action_constraint = constraint(decoder, limits)?;
    key(decoder, 10)?;
    let budget_ceiling = optional_budget(decoder)?;
    key(decoder, 11)?;
    let remaining_depth = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 12)?;
    let parent = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(digest_id!(decoder, GrantId)?)
    };
    key(decoder, 13)?;
    let status_policy = status_policy(decoder)?;
    key(decoder, 14)?;
    let assurance_floor = parse_text!(decoder, AssurancePolicyId)?;
    key(decoder, 15)?;
    let extensions = extensions(decoder, limits)?;
    Ok(GrantStatement::new(
        issuer,
        subject,
        profile,
        permissions,
        validity,
        audiences,
        action_constraint,
        budget_ceiling,
        remaining_depth,
        parent,
        status_policy,
        assurance_floor,
        extensions,
    ))
}

fn signed_grant(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignedGrant, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let statement = grant_statement(decoder, limits)?;
    key(decoder, 1)?;
    let signature = signature(decoder, limits)?;
    Ok(SignedGrant::new(statement, signature))
}

fn action_envelope(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<ActionEnvelope, CodecError> {
    map(decoder, 19)?;
    key(decoder, 0)?;
    ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let profile_id = parse_text!(decoder, ProfileId)?;
    key(decoder, 2)?;
    let profile = ProfileRef::new(
        profile_id,
        decoder.u16().map_err(|_| CodecError::Malformed)?,
    )?;
    key(decoder, 3)?;
    let body_media_type = parse_text!(decoder, MediaType)?;
    key(decoder, 4)?;
    let canonical_body_digest = Digest::new(digest_bytes(decoder)?);
    key(decoder, 5)?;
    let capability = parse_text!(decoder, CapabilityId)?;
    key(decoder, 6)?;
    let resource = parse_text!(decoder, ResourceId)?;
    let permission = Permission::new(capability, resource);
    key(decoder, 7)?;
    let requested_budget = optional_budget(decoder)?;
    key(decoder, 8)?;
    let audience = parse_text!(decoder, Audience)?;
    key(decoder, 9)?;
    let challenge = Challenge::new(digest_bytes(decoder)?);
    key(decoder, 10)?;
    let not_before = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 11)?;
    let expires_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    let validity = ValidityWindow::new(not_before, expires_at)?;
    key(decoder, 12)?;
    let actor = parse_text!(decoder, PrincipalId)?;
    key(decoder, 13)?;
    let terminal_grant = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(digest_id!(decoder, GrantId)?)
    };
    key(decoder, 14)?;
    let authorization_plan = digest_id!(decoder, PlanId)?;
    key(decoder, 15)?;
    let channel_binding = parse_text!(decoder, ChannelBindingId)?;
    key(decoder, 16)?;
    let proof_ref = digest_id!(decoder, ProofRef)?;
    key(decoder, 17)?;
    let attachment_count = array(decoder, limits.get(LimitKind::Attachments))?;
    let mut attachment_descriptors = Vec::with_capacity(attachment_count);
    for _ in 0..attachment_count {
        attachment_descriptors.push(attachment(decoder)?);
    }
    key(decoder, 18)?;
    let extensions = extensions(decoder, limits)?;
    Ok(ActionEnvelope::new(
        profile,
        body_media_type,
        canonical_body_digest,
        permission,
        requested_budget,
        audience,
        challenge,
        validity,
        actor,
        terminal_grant,
        authorization_plan,
        channel_binding,
        proof_ref,
        attachment_descriptors,
        extensions,
    ))
}

fn signed_action(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignedAction, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let envelope = action_envelope(decoder, limits)?;
    key(decoder, 1)?;
    let signature = signature(decoder, limits)?;
    Ok(SignedAction::new(envelope, signature))
}

fn authorization_plan(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
    depth: usize,
) -> Result<AuthorizationPlan, CodecError> {
    if depth > limits.get(LimitKind::PlanDepth) {
        return Err(CodecError::LimitExceeded);
    }
    let entries = decoder
        .map()
        .map_err(|_| CodecError::Malformed)?
        .ok_or(CodecError::Malformed)?;
    key(decoder, 0)?;
    match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 if entries == 2 => {
            key(decoder, 1)?;
            Ok(AuthorizationPlan::proof(digest_id!(decoder, ProofRef)?))
        }
        operator @ (1 | 2) if entries == 2 => {
            key(decoder, 1)?;
            let length = array(decoder, limits.get(LimitKind::PlanBranching))?;
            let mut members = Vec::with_capacity(length);
            for _ in 0..length {
                members.push(authorization_plan(decoder, limits, depth + 1)?);
            }
            if operator == 1 {
                AuthorizationPlan::all_of(members).map_err(CodecError::from)
            } else {
                AuthorizationPlan::any_of(members).map_err(CodecError::from)
            }
        }
        3 if entries == 3 => {
            key(decoder, 1)?;
            let k = decoder.u16().map_err(|_| CodecError::Malformed)?;
            key(decoder, 2)?;
            let length = array(decoder, limits.get(LimitKind::PlanBranching))?;
            let mut members = Vec::with_capacity(length);
            for _ in 0..length {
                members.push(authorization_plan(decoder, limits, depth + 1)?);
            }
            AuthorizationPlan::k_of_n(k, members).map_err(CodecError::from)
        }
        _ => Err(CodecError::Malformed),
    }
}

fn evidence(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<EvidenceObject, CodecError> {
    map(decoder, 4)?;
    key(decoder, 0)?;
    let id = digest_id!(decoder, EvidenceId)?;
    key(decoder, 1)?;
    let evidence_type = parse_text!(decoder, EvidenceTypeId)?;
    key(decoder, 2)?;
    let media_type = parse_text!(decoder, MediaType)?;
    key(decoder, 3)?;
    let bytes = bounded_bytes(decoder, limits.get(LimitKind::EvidenceBytes), true)?;
    let object = EvidenceObject::new(id, evidence_type, media_type, bytes)?;
    if evidence_id(&object)? != id {
        return Err(CodecError::DigestMismatch);
    }
    Ok(object)
}

fn statement_ref(decoder: &mut V1Decoder<'_>) -> Result<StatementRef, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let kind = decoder.u8().map_err(|_| CodecError::Malformed)?;
    key(decoder, 1)?;
    match kind {
        0 => Ok(StatementRef::Grant(digest_id!(decoder, GrantId)?)),
        1 => Ok(StatementRef::Action(digest_id!(decoder, ActionId)?)),
        2 => Ok(StatementRef::PrincipalStatus(digest_id!(
            decoder,
            PrincipalStatusId
        )?)),
        3 => Ok(StatementRef::GrantStatus(digest_id!(
            decoder,
            GrantStatusId
        )?)),
        _ => Err(CodecError::Malformed),
    }
}

fn binding(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<ControlBinding, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let statement = statement_ref(decoder)?;
    key(decoder, 1)?;
    let length = array(decoder, limits.get(LimitKind::BindingEvidence))?;
    let mut evidence = Vec::with_capacity(length);
    for _ in 0..length {
        evidence.push(digest_id!(decoder, EvidenceId)?);
    }
    ControlBinding::new(statement, evidence).map_err(CodecError::from)
}

fn principal_status_statement(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<PrincipalStatusStatement, CodecError> {
    map(decoder, 10)?;
    key(decoder, 0)?;
    ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let method = parse_text!(decoder, StatusMethodId)?;
    key(decoder, 2)?;
    let principal = parse_text!(decoder, PrincipalId)?;
    key(decoder, 3)?;
    let purpose = parse_text!(decoder, PurposeId)?;
    key(decoder, 4)?;
    let state = match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 => PrincipalState::Active,
        1 => PrincipalState::Revoked,
        2 => PrincipalState::Superseded,
        _ => return Err(CodecError::Malformed),
    };
    key(decoder, 5)?;
    let sequence = decoder.u64().map_err(|_| CodecError::Malformed)?;
    key(decoder, 6)?;
    let observed_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 7)?;
    let valid_until = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 8)?;
    let issuer = parse_text!(decoder, PrincipalId)?;
    key(decoder, 9)?;
    let extensions = extensions(decoder, limits)?;
    PrincipalStatusStatement::new(
        method,
        principal,
        purpose,
        state,
        sequence,
        observed_at,
        valid_until,
        issuer,
        extensions,
    )
    .map_err(CodecError::from)
}

fn signed_principal_status(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignedPrincipalStatus, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let statement = principal_status_statement(decoder, limits)?;
    key(decoder, 1)?;
    let signature = signature(decoder, limits)?;
    Ok(SignedPrincipalStatus::new(statement, signature))
}

fn grant_status_statement(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<GrantStatusStatement, CodecError> {
    map(decoder, 9)?;
    key(decoder, 0)?;
    ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let method = parse_text!(decoder, StatusMethodId)?;
    key(decoder, 2)?;
    let grant_id = digest_id!(decoder, GrantId)?;
    key(decoder, 3)?;
    let state = match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 => GrantState::Active,
        1 => GrantState::Revoked,
        2 => GrantState::Superseded,
        _ => return Err(CodecError::Malformed),
    };
    key(decoder, 4)?;
    let sequence = decoder.u64().map_err(|_| CodecError::Malformed)?;
    key(decoder, 5)?;
    let observed_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 6)?;
    let valid_until = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 7)?;
    let issuer = parse_text!(decoder, PrincipalId)?;
    key(decoder, 8)?;
    let extensions = extensions(decoder, limits)?;
    GrantStatusStatement::new(
        method,
        grant_id,
        state,
        sequence,
        observed_at,
        valid_until,
        issuer,
        extensions,
    )
    .map_err(CodecError::from)
}

fn signed_grant_status(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<SignedGrantStatus, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let statement = grant_status_statement(decoder, limits)?;
    key(decoder, 1)?;
    let signature = signature(decoder, limits)?;
    Ok(SignedGrantStatus::new(statement, signature))
}

fn attachment(decoder: &mut V1Decoder<'_>) -> Result<AttachmentDescriptor, CodecError> {
    map(decoder, 7)?;
    key(decoder, 0)?;
    let digest = digest_id!(decoder, AttachmentDigest)?;
    key(decoder, 1)?;
    let media_type = parse_text!(decoder, MediaType)?;
    key(decoder, 2)?;
    let byte_length = decoder.u64().map_err(|_| CodecError::Malformed)?;
    key(decoder, 3)?;
    let disposition = parse_text!(decoder, DispositionId)?;
    key(decoder, 4)?;
    let encrypted = decoder.bool().map_err(|_| CodecError::Malformed)?;
    key(decoder, 5)?;
    let required = decoder.bool().map_err(|_| CodecError::Malformed)?;
    key(decoder, 6)?;
    let opaque_allowed = decoder.bool().map_err(|_| CodecError::Malformed)?;
    Ok(AttachmentDescriptor::new(
        digest,
        media_type,
        byte_length,
        disposition,
        encrypted,
        required,
        opaque_allowed,
    ))
}

fn bundle_from(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<ProofBundle, CodecError> {
    map(decoder, 10)?;
    key(decoder, 0)?;
    map(decoder, 2)?;
    key(decoder, 0)?;
    let version = ProtocolVersion::new(decoder.u16().map_err(|_| CodecError::Malformed)?)?;
    key(decoder, 1)?;
    let header = BundleHeader::new(version, decoder.u64().map_err(|_| CodecError::Malformed)?)?;

    key(decoder, 1)?;
    let length = array(decoder, limits.get(LimitKind::Grants))?;
    let mut grants = Vec::with_capacity(length);
    for _ in 0..length {
        grants.push(signed_grant(decoder, limits)?);
    }

    key(decoder, 2)?;
    let length = array(decoder, limits.get(LimitKind::Actions))?;
    let mut actions = Vec::with_capacity(length);
    for _ in 0..length {
        actions.push(signed_action(decoder, limits)?);
    }

    key(decoder, 3)?;
    let plan = authorization_plan(decoder, limits, 1)?;
    plan.validate(limits)?;

    key(decoder, 4)?;
    let length = array(decoder, limits.get(LimitKind::EvidenceObjects))?;
    let mut evidence_objects = Vec::with_capacity(length);
    for _ in 0..length {
        evidence_objects.push(evidence(decoder, limits)?);
    }

    key(decoder, 5)?;
    let length = array(decoder, limits.get(LimitKind::ControlBindings))?;
    let mut bindings = Vec::with_capacity(length);
    for _ in 0..length {
        bindings.push(binding(decoder, limits)?);
    }

    key(decoder, 6)?;
    let length = array(decoder, limits.get(LimitKind::PrincipalStatusStatements))?;
    let mut principal_status = Vec::with_capacity(length);
    for _ in 0..length {
        principal_status.push(signed_principal_status(decoder, limits)?);
    }

    key(decoder, 7)?;
    let length = array(decoder, limits.get(LimitKind::GrantStatusStatements))?;
    let mut grant_status = Vec::with_capacity(length);
    for _ in 0..length {
        grant_status.push(signed_grant_status(decoder, limits)?);
    }

    let signature_count = grants
        .len()
        .checked_add(actions.len())
        .and_then(|count| count.checked_add(principal_status.len()))
        .and_then(|count| count.checked_add(grant_status.len()))
        .ok_or(CodecError::LimitExceeded)?;
    if signature_count > limits.get(LimitKind::Signatures) {
        return Err(CodecError::LimitExceeded);
    }

    key(decoder, 8)?;
    let length = array(decoder, limits.get(LimitKind::Attachments))?;
    let mut attachments = Vec::with_capacity(length);
    for _ in 0..length {
        attachments.push(attachment(decoder)?);
    }

    key(decoder, 9)?;
    let canonical_body = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(bounded_bytes(
            decoder,
            limits.get(LimitKind::CanonicalBodyBytes),
            false,
        )?)
    };

    ProofBundle::new(
        header,
        grants,
        actions,
        plan,
        evidence_objects,
        bindings,
        principal_status,
        grant_status,
        attachments,
        canonical_body,
    )
    .map_err(CodecError::from)
}

fn role(decoder: &mut V1Decoder<'_>) -> Result<auths_model::ParticipantRole, CodecError> {
    match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 => Ok(auths_model::ParticipantRole::Root),
        1 => Ok(auths_model::ParticipantRole::Intermediate),
        2 => Ok(auths_model::ParticipantRole::Actor),
        3 => Ok(auths_model::ParticipantRole::ExternalIssuer),
        _ => Err(CodecError::Malformed),
    }
}

fn assurance_policy(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<AssurancePolicy, CodecError> {
    map(decoder, 2)?;
    key(decoder, 0)?;
    let id = parse_text!(decoder, AssurancePolicyId)?;
    key(decoder, 1)?;
    let length = array(decoder, limits.get(LimitKind::EvidenceObjects))?;
    let mut requirements = Vec::with_capacity(length);
    for _ in 0..length {
        map(decoder, 8)?;
        key(decoder, 0)?;
        let role = role(decoder)?;
        key(decoder, 1)?;
        let claim_kind = parse_text!(decoder, AssuranceClaimId)?;
        key(decoder, 2)?;
        let parameter_count = array(decoder, limits.get(LimitKind::CriticalExtensions))?;
        let mut parameters = Vec::with_capacity(parameter_count);
        for _ in 0..parameter_count {
            array_exact(decoder, 2)?;
            parameters.push((
                parse_text!(decoder, auths_model::ClaimParameterId)?,
                parse_text!(decoder, auths_model::ClaimParameterId)?,
            ));
        }
        key(decoder, 3)?;
        let source = if is_null(decoder)? {
            null(decoder)?;
            None
        } else {
            Some(parse_text!(decoder, EvidenceSourceId)?)
        };
        key(decoder, 4)?;
        let adapter = if is_null(decoder)? {
            null(decoder)?;
            None
        } else {
            Some(parse_text!(decoder, AdapterId)?)
        };
        key(decoder, 5)?;
        let adapter_version = if is_null(decoder)? {
            null(decoder)?;
            None
        } else {
            Some(decoder.u16().map_err(|_| CodecError::Malformed)?)
        };
        key(decoder, 6)?;
        let maximum_age = if is_null(decoder)? {
            null(decoder)?;
            None
        } else {
            Some(FreshnessLimit::new(
                decoder.u64().map_err(|_| CodecError::Malformed)?,
            )?)
        };
        key(decoder, 7)?;
        let quantifier = match decoder.u8().map_err(|_| CodecError::Malformed)? {
            0 => AssuranceQuantifier::Any,
            1 => AssuranceQuantifier::Every,
            _ => return Err(CodecError::Malformed),
        };
        requirements.push(AssuranceRequirement::constrained(
            role,
            quantifier,
            claim_kind,
            parameters,
            source,
            adapter,
            adapter_version,
            maximum_age,
        )?);
    }
    AssurancePolicy::new(id, requirements).map_err(CodecError::from)
}

fn profile_refs(
    decoder: &mut V1Decoder<'_>,
    maximum: usize,
) -> Result<Vec<ProfileRef>, CodecError> {
    let length = array(decoder, maximum)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(profile_ref(decoder)?);
    }
    Ok(values)
}

fn parsed_texts<T>(
    decoder: &mut V1Decoder<'_>,
    maximum: usize,
    parse: impl Fn(&str) -> Result<T, auths_model::ModelError>,
) -> Result<Vec<T>, CodecError> {
    let length = array(decoder, maximum)?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(parse(text(decoder)?)?);
    }
    Ok(values)
}

fn anchor(decoder: &mut V1Decoder<'_>, limits: &VerifierLimits) -> Result<TrustAnchor, CodecError> {
    map(decoder, 13)?;
    key(decoder, 0)?;
    let id = parse_text!(decoder, TrustAnchorId)?;
    key(decoder, 1)?;
    let principal = parse_text!(decoder, PrincipalId)?;
    key(decoder, 2)?;
    let accepted_methods = parsed_texts(
        decoder,
        limits.get(LimitKind::RegistryEntries),
        PrincipalMethodId::parse,
    )?;
    key(decoder, 3)?;
    let profiles = profile_refs(decoder, limits.get(LimitKind::RegistryEntries))?;
    key(decoder, 4)?;
    let permissions = permissions(decoder, limits)?;
    key(decoder, 5)?;
    let resource_namespaces = parsed_texts(
        decoder,
        limits.get(LimitKind::Permissions),
        ResourceId::parse,
    )?;
    key(decoder, 6)?;
    let audiences = audiences(decoder, limits)?;
    key(decoder, 7)?;
    let not_before = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 8)?;
    let expires_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    let validity = ValidityWindow::new(not_before, expires_at)?;
    key(decoder, 9)?;
    let budget_ceiling = optional_budget(decoder)?;
    key(decoder, 10)?;
    let max_delegation_depth = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 11)?;
    let assurance_policy = parse_text!(decoder, AssurancePolicyId)?;
    key(decoder, 12)?;
    let status_policy = status_policy(decoder)?;
    TrustAnchor::new(
        id,
        principal,
        accepted_methods,
        profiles,
        permissions,
        resource_namespaces,
        audiences,
        validity,
        budget_ceiling,
        max_delegation_depth,
        assurance_policy,
        status_policy,
    )
    .map_err(CodecError::from)
}

fn registries(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<AcceptedRegistries, CodecError> {
    let maximum = limits.get(LimitKind::RegistryEntries);
    map(decoder, 13)?;
    key(decoder, 0)?;
    let manifest_id = digest_id!(decoder, RegistryManifestId)?;
    key(decoder, 1)?;
    let principal_methods = parsed_texts(decoder, maximum, PrincipalMethodId::parse)?;
    key(decoder, 2)?;
    let signature_suites = parsed_texts(decoder, maximum, SignatureSuiteId::parse)?;
    key(decoder, 3)?;
    let evidence_types = parsed_texts(decoder, maximum, EvidenceTypeId::parse)?;
    key(decoder, 4)?;
    let principal_status_methods = parsed_texts(decoder, maximum, StatusMethodId::parse)?;
    key(decoder, 5)?;
    let grant_status_methods = parsed_texts(decoder, maximum, StatusMethodId::parse)?;
    key(decoder, 6)?;
    let assurance_claims = parsed_texts(decoder, maximum, AssuranceClaimId::parse)?;
    key(decoder, 7)?;
    let assurance_implications = parsed_texts(decoder, maximum, AssuranceImplicationId::parse)?;
    key(decoder, 8)?;
    let resource_matchers = parsed_texts(decoder, maximum, ResourceMatcherId::parse)?;
    key(decoder, 9)?;
    let budget_algebras = parsed_texts(decoder, maximum, BudgetAlgebraId::parse)?;
    key(decoder, 10)?;
    let critical_extensions = parsed_texts(decoder, maximum, ExtensionId::parse)?;
    key(decoder, 11)?;
    let profiles = profile_refs(decoder, maximum)?;
    key(decoder, 12)?;
    let profile_policies = parsed_texts(decoder, maximum, ProfilePolicyId::parse)?;
    AcceptedRegistries::new(
        manifest_id,
        principal_methods,
        signature_suites,
        evidence_types,
        principal_status_methods,
        grant_status_methods,
        assurance_claims,
        assurance_implications,
        resource_matchers,
        budget_algebras,
        critical_extensions,
        profiles,
        profile_policies,
    )
    .map_err(CodecError::from)
}

fn checkpoints(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<EvidenceId>, CodecError> {
    let length = array(decoder, limits.get(LimitKind::EvidenceObjects))?;
    let mut values = Vec::with_capacity(length);
    for _ in 0..length {
        values.push(digest_id!(decoder, EvidenceId)?);
    }
    Ok(values)
}

fn status_trust(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<Vec<StatusTrustRule>, CodecError> {
    let length = array(decoder, limits.get(LimitKind::RegistryEntries))?;
    let mut rules = Vec::with_capacity(length);
    for _ in 0..length {
        map(decoder, 3)?;
        key(decoder, 0)?;
        let method = parse_text!(decoder, StatusMethodId)?;
        key(decoder, 1)?;
        let issuer = parse_text!(decoder, PrincipalId)?;
        key(decoder, 2)?;
        let sequence_floor = decoder.u64().map_err(|_| CodecError::Malformed)?;
        rules.push(StatusTrustRule::new(method, issuer, sequence_floor));
    }
    Ok(rules)
}

fn principal_snapshot(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<PrincipalStatusSnapshot, CodecError> {
    map(decoder, 6)?;
    key(decoder, 0)?;
    let id = digest_id!(decoder, StatusSnapshotId)?;
    key(decoder, 1)?;
    let observed_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 2)?;
    let valid_until = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 3)?;
    let length = array(decoder, limits.get(LimitKind::PrincipalStatusStatements))?;
    let mut statements = Vec::with_capacity(length);
    for _ in 0..length {
        statements.push(signed_principal_status(decoder, limits)?);
    }
    key(decoder, 4)?;
    let checkpoints = checkpoints(decoder, limits)?;
    key(decoder, 5)?;
    let trust = status_trust(decoder, limits)?;
    PrincipalStatusSnapshot::with_trust(
        id,
        observed_at,
        valid_until,
        statements,
        checkpoints,
        trust,
    )
    .map_err(CodecError::from)
}

fn grant_snapshot(
    decoder: &mut V1Decoder<'_>,
    limits: &VerifierLimits,
) -> Result<GrantStatusSnapshot, CodecError> {
    map(decoder, 6)?;
    key(decoder, 0)?;
    let id = digest_id!(decoder, StatusSnapshotId)?;
    key(decoder, 1)?;
    let observed_at = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 2)?;
    let valid_until = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 3)?;
    let length = array(decoder, limits.get(LimitKind::GrantStatusStatements))?;
    let mut statements = Vec::with_capacity(length);
    for _ in 0..length {
        statements.push(signed_grant_status(decoder, limits)?);
    }
    key(decoder, 4)?;
    let checkpoints = checkpoints(decoder, limits)?;
    key(decoder, 5)?;
    let trust = status_trust(decoder, limits)?;
    GrantStatusSnapshot::with_trust(id, observed_at, valid_until, statements, checkpoints, trust)
        .map_err(CodecError::from)
}

const LIMIT_KINDS: [LimitKind; 26] = [
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

fn verifier_limits(decoder: &mut V1Decoder<'_>) -> Result<VerifierLimits, CodecError> {
    map(decoder, 27)?;
    let mut limits = VerifierLimits::hard();
    for (index, kind) in LIMIT_KINDS.into_iter().enumerate() {
        key(
            decoder,
            u8::try_from(index).map_err(|_| CodecError::LimitExceeded)?,
        )?;
        let value = decoder.u64().map_err(|_| CodecError::Malformed)?;
        let value = usize::try_from(value).map_err(|_| CodecError::LimitExceeded)?;
        limits = limits.with_limit(kind, value)?;
    }
    key(decoder, 26)?;
    limits
        .with_work_units(decoder.u64().map_err(|_| CodecError::Malformed)?)
        .map_err(CodecError::from)
}

fn context_from(decoder: &mut V1Decoder<'_>) -> Result<VerifierContext, CodecError> {
    map(decoder, 14)?;
    key(decoder, 0)?;
    let limits = verifier_limits(decoder)?;
    key(decoder, 1)?;
    let configuration = digest_id!(decoder, VerifierConfigurationId)?;
    key(decoder, 2)?;
    map(decoder, 4)?;
    key(decoder, 0)?;
    let expected_plan = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(digest_id!(decoder, PlanId)?)
    };
    key(decoder, 1)?;
    let minimum_authorized_branches = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 2)?;
    let minimum_distinct_actors = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 3)?;
    let minimum_distinct_roots = decoder.u16().map_err(|_| CodecError::Malformed)?;
    let composition = CompositionRequirement::new(
        expected_plan,
        minimum_authorized_branches,
        minimum_distinct_actors,
        minimum_distinct_roots,
    )?;
    key(decoder, 3)?;
    let length = array(decoder, limits.get(LimitKind::TrustAnchors))?;
    let mut trust_anchors = Vec::with_capacity(length);
    for _ in 0..length {
        trust_anchors.push(anchor(decoder, &limits)?);
    }
    key(decoder, 4)?;
    let accepted_registries = registries(decoder, &limits)?;
    key(decoder, 5)?;
    let expected_audience = parse_text!(decoder, Audience)?;
    key(decoder, 6)?;
    let expected_challenge = Challenge::new(digest_bytes(decoder)?);
    key(decoder, 7)?;
    let evaluation_time = Timestamp::new(decoder.u64().map_err(|_| CodecError::Malformed)?);
    key(decoder, 8)?;
    let assurance_policy = assurance_policy(decoder, &limits)?;
    key(decoder, 9)?;
    let principal_status_snapshot = principal_snapshot(decoder, &limits)?;
    key(decoder, 10)?;
    let grant_status_snapshot = grant_snapshot(decoder, &limits)?;
    key(decoder, 11)?;
    let resource_matcher = parse_text!(decoder, ResourceMatcherId)?;
    key(decoder, 12)?;
    let profile_policy = parse_text!(decoder, ProfilePolicyId)?;
    key(decoder, 13)?;
    let channel_policy = parse_text!(decoder, ChannelBindingId)?;
    VerifierContext::new(
        configuration,
        composition,
        trust_anchors,
        accepted_registries,
        expected_audience,
        expected_challenge,
        evaluation_time,
        assurance_policy,
        principal_status_snapshot,
        grant_status_snapshot,
        resource_matcher,
        profile_policy,
        channel_policy,
        limits,
    )
    .map_err(CodecError::from)
}

fn ensure_complete(decoder: &V1Decoder<'_>, input: &[u8]) -> Result<(), CodecError> {
    if decoder.position() == input.len() {
        Ok(())
    } else {
        Err(CodecError::Malformed)
    }
}

/// Decodes a complete proof bundle under explicit deployment limits.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_bundle(input: &[u8], limits: &VerifierLimits) -> Result<ProofBundle, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::BundleBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let bundle = bundle_from(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_bundle(&bundle)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(bundle)
}

/// Decodes one canonical unsigned grant statement under explicit limits.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_grant_statement(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<GrantStatement, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::BundleBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let statement = grant_statement(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_grant_statement(&statement)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(statement)
}

/// Decodes one canonical unsigned action envelope under explicit limits.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_action_envelope(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<ActionEnvelope, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::ActionBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let envelope = action_envelope(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_action_envelope(&envelope)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(envelope)
}

/// Decodes one canonical unsigned principal-status statement.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_principal_status_statement(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<PrincipalStatusStatement, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::BundleBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let statement = principal_status_statement(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_principal_status_statement(&statement)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(statement)
}

/// Decodes one canonical unsigned grant-status statement.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_grant_status_statement(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<GrantStatusStatement, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::BundleBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let statement = grant_status_statement(&mut decoder, limits)?;
    ensure_complete(&decoder, input)?;
    if encode_grant_status_statement(&statement)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(statement)
}

/// Decodes the complete portable canonical-action verifier input.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, duplicate, or
/// over-limit action and detached-attachment bytes.
pub fn decode_canonical_action(
    input: &[u8],
    limits: &VerifierLimits,
) -> Result<CanonicalAction, CodecError> {
    limits.validate()?;
    if input.len() > limits.get(LimitKind::ActionBytes) {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    map(&mut decoder, 6)?;
    key(&mut decoder, 0)?;
    let profile = profile_ref(&mut decoder)?;
    key(&mut decoder, 1)?;
    let media_type = parse_text!(&mut decoder, MediaType)?;
    key(&mut decoder, 2)?;
    let body = bounded_bytes(
        &mut decoder,
        limits.get(LimitKind::CanonicalBodyBytes),
        true,
    )?;
    key(&mut decoder, 3)?;
    let permission = permission(&mut decoder)?;
    key(&mut decoder, 4)?;
    let requested_budget = optional_budget(&mut decoder)?;
    key(&mut decoder, 5)?;
    let count = array(&mut decoder, limits.get(LimitKind::Attachments))?;
    let mut attachments = Vec::with_capacity(count);
    let mut attachment_bytes = 0usize;
    for _ in 0..count {
        map(&mut decoder, 2)?;
        key(&mut decoder, 0)?;
        let digest = digest_id!(&mut decoder, AttachmentDigest)?;
        key(&mut decoder, 1)?;
        let bytes = bounded_bytes(&mut decoder, limits.get(LimitKind::AttachmentBytes), true)?;
        attachment_bytes = attachment_bytes
            .checked_add(bytes.len())
            .ok_or(CodecError::LimitExceeded)?;
        if attachment_bytes > limits.get(LimitKind::AttachmentBytes) {
            return Err(CodecError::LimitExceeded);
        }
        attachments.push(DetachedAttachment::new(digest, bytes)?);
    }
    let action = CanonicalAction::new(profile, media_type, body, permission, requested_budget)?
        .with_detached_attachments(attachments)?;
    ensure_complete(&decoder, input)?;
    if crate::encode::encode_canonical_action(&action)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(action)
}

fn assurance_claim(decoder: &mut V1Decoder<'_>) -> Result<AssuranceClaim, CodecError> {
    map(decoder, 4)?;
    key(decoder, 0)?;
    let kind = parse_text!(decoder, AssuranceClaimId)?;
    key(decoder, 1)?;
    let length = array(decoder, auths_model::HARD_MAX_EXTENSIONS)?;
    let mut parameters = Vec::with_capacity(length);
    for _ in 0..length {
        array_exact(decoder, 2)?;
        parameters.push((
            parse_text!(decoder, auths_model::ClaimParameterId)?,
            parse_text!(decoder, auths_model::ClaimParameterId)?,
        ));
    }
    key(decoder, 2)?;
    let observed_at = if is_null(decoder)? {
        null(decoder)?;
        None
    } else {
        Some(Timestamp::new(
            decoder.u64().map_err(|_| CodecError::Malformed)?,
        ))
    };
    key(decoder, 3)?;
    let source = parse_text!(decoder, EvidenceSourceId)?;
    AssuranceClaim::new(kind, parameters, observed_at, source).map_err(CodecError::from)
}

fn evidence_ids(
    decoder: &mut V1Decoder<'_>,
    maximum: usize,
) -> Result<Vec<EvidenceId>, CodecError> {
    let length = array(decoder, maximum)?;
    let mut evidence = Vec::with_capacity(length);
    for _ in 0..length {
        evidence.push(digest_id!(decoder, EvidenceId)?);
    }
    Ok(evidence)
}

fn assurance_report(decoder: &mut V1Decoder<'_>) -> Result<ParticipantAssurance, CodecError> {
    map(decoder, 6)?;
    key(decoder, 0)?;
    let principal = parse_text!(decoder, PrincipalId)?;
    key(decoder, 1)?;
    let participant_role = role(decoder)?;
    key(decoder, 2)?;
    let claim_count = array(decoder, auths_model::HARD_MAX_EVIDENCE)?;
    let mut claims = Vec::with_capacity(claim_count);
    for _ in 0..claim_count {
        claims.push(assurance_claim(decoder)?);
    }
    key(decoder, 3)?;
    let evidence = evidence_ids(decoder, auths_model::HARD_MAX_EVIDENCE)?;
    key(decoder, 4)?;
    let adapter = parse_text!(decoder, AdapterId)?;
    key(decoder, 5)?;
    let adapter_version = decoder.u16().map_err(|_| CodecError::Malformed)?;
    ParticipantAssurance::new(
        principal,
        participant_role,
        claims,
        evidence,
        adapter,
        adapter_version,
    )
    .map_err(CodecError::from)
}

fn assurance_satisfaction(
    decoder: &mut V1Decoder<'_>,
) -> Result<AssuranceSatisfaction, CodecError> {
    map(decoder, 4)?;
    key(decoder, 0)?;
    let requirement_index = decoder.u16().map_err(|_| CodecError::Malformed)?;
    key(decoder, 1)?;
    let principal = parse_text!(decoder, PrincipalId)?;
    key(decoder, 2)?;
    let claim = assurance_claim(decoder)?;
    key(decoder, 3)?;
    let evidence = evidence_ids(decoder, auths_model::HARD_MAX_EVIDENCE)?;
    Ok(AssuranceSatisfaction::new(
        requirement_index,
        principal,
        claim,
        evidence,
    ))
}

fn verification_resources(
    decoder: &mut V1Decoder<'_>,
) -> Result<VerificationResources, CodecError> {
    map(decoder, 7)?;
    let mut values = [0u64; 7];
    for (index, value) in values.iter_mut().enumerate() {
        key(
            decoder,
            u8::try_from(index).map_err(|_| CodecError::LimitExceeded)?,
        )?;
        *value = decoder.u64().map_err(|_| CodecError::Malformed)?;
    }
    Ok(VerificationResources::new(
        values[0], values[1], values[2], values[3], values[4], values[5], values[6],
    ))
}

/// Decodes a complete portable verifier output.
///
/// # Errors
///
/// Returns a typed error for malformed, non-canonical, inconsistent, or
/// self-digest-mismatched result bytes.
#[allow(clippy::too_many_lines)]
pub fn decode_verification_result(input: &[u8]) -> Result<PortableVerificationResult, CodecError> {
    if input.len() > auths_model::HARD_MAX_BUNDLE_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    map(&mut decoder, 16)?;
    key(&mut decoder, 0)?;
    let decision = match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 => VerificationDecision::Authorized,
        1 => VerificationDecision::Denied,
        2 => VerificationDecision::Indeterminate,
        _ => return Err(CodecError::Malformed),
    };
    key(&mut decoder, 1)?;
    let stage = match decoder.u8().map_err(|_| CodecError::Malformed)? {
        0 => VerificationStage::Decode,
        1 => VerificationStage::Resolve,
        2 => VerificationStage::PrincipalControl,
        3 => VerificationStage::Authority,
        4 => VerificationStage::Complete,
        _ => return Err(CodecError::Malformed),
    };
    key(&mut decoder, 2)?;
    map(&mut decoder, 2)?;
    key(&mut decoder, 0)?;
    let class = decoder.u8().map_err(|_| CodecError::Malformed)?;
    key(&mut decoder, 1)?;
    let code_text = text(&mut decoder)?;
    let code = match class {
        0 if code_text == "authorized" => VerificationCode::Authorized,
        1 => VerificationCode::Denied(
            auths_model::DenialReason::from_code(code_text).ok_or(CodecError::Malformed)?,
        ),
        2 => VerificationCode::Indeterminate(
            auths_model::Requirement::from_code(code_text).ok_or(CodecError::Malformed)?,
        ),
        _ => return Err(CodecError::Malformed),
    };
    if !matches!(
        (decision, code),
        (
            VerificationDecision::Authorized,
            VerificationCode::Authorized
        ) | (VerificationDecision::Denied, VerificationCode::Denied(_))
            | (
                VerificationDecision::Indeterminate,
                VerificationCode::Indeterminate(_)
            )
    ) {
        return Err(CodecError::Malformed);
    }
    key(&mut decoder, 3)?;
    let proof_digest = Digest::new(digest_bytes(&mut decoder)?);
    key(&mut decoder, 4)?;
    let action_digest = Digest::new(digest_bytes(&mut decoder)?);
    key(&mut decoder, 5)?;
    let context_digest = auths_model::ContextDigest::new(digest_bytes(&mut decoder)?);
    key(&mut decoder, 6)?;
    let plan_id = if is_null(&decoder)? {
        null(&mut decoder)?;
        None
    } else {
        Some(digest_id!(&mut decoder, PlanId)?)
    };
    key(&mut decoder, 7)?;
    let result_digest = digest_id!(&mut decoder, VerificationResultDigest)?;
    key(&mut decoder, 8)?;
    let branch_count = array(&mut decoder, auths_model::HARD_MAX_PLAN_LEAVES)?;
    let mut branches = Vec::with_capacity(branch_count);
    for _ in 0..branch_count {
        branches.push(digest_id!(&mut decoder, ProofRef)?);
    }
    key(&mut decoder, 9)?;
    let report_count = array(&mut decoder, auths_model::HARD_MAX_EVIDENCE)?;
    let mut reports = Vec::with_capacity(report_count);
    for _ in 0..report_count {
        reports.push(assurance_report(&mut decoder)?);
    }
    key(&mut decoder, 10)?;
    let satisfaction_count = array(&mut decoder, auths_model::HARD_MAX_EVIDENCE)?;
    let mut satisfactions = Vec::with_capacity(satisfaction_count);
    for _ in 0..satisfaction_count {
        satisfactions.push(assurance_satisfaction(&mut decoder)?);
    }
    key(&mut decoder, 11)?;
    let resources = verification_resources(&mut decoder)?;
    key(&mut decoder, 12)?;
    let registry_manifest = digest_id!(&mut decoder, RegistryManifestId)?;
    key(&mut decoder, 13)?;
    let required_configuration = if is_null(&decoder)? {
        null(&mut decoder)?;
        None
    } else {
        Some(digest_id!(&mut decoder, VerifierConfigurationId)?)
    };
    key(&mut decoder, 14)?;
    let local_configuration = digest_id!(&mut decoder, VerifierConfigurationId)?;
    key(&mut decoder, 15)?;
    if decoder.u16().map_err(|_| CodecError::Malformed)? != 2 {
        return Err(CodecError::Malformed);
    }
    let result = PortableVerificationResult::new(
        decision,
        stage,
        code,
        proof_digest,
        action_digest,
        context_digest,
        plan_id,
        branches,
        reports,
        satisfactions,
        resources,
        registry_manifest,
        required_configuration,
        local_configuration,
    )
    .with_result_digest(result_digest);
    ensure_complete(&decoder, input)?;
    if crate::encode::encode_verification_result(&result)?.as_slice() != input
        || crate::hash::verification_result_digest(&result)? != result.result_digest()
    {
        return Err(CodecError::DigestMismatch);
    }
    Ok(result)
}

/// Decodes the deterministic public verifier-context projection.
///
/// # Errors
///
/// Returns a typed codec error for malformed, non-canonical, over-limit, or
/// semantically invalid input.
pub fn decode_verifier_context(input: &[u8]) -> Result<VerifierContext, CodecError> {
    if input.len() > auths_model::HARD_MAX_CONTEXT_BYTES {
        return Err(CodecError::LimitExceeded);
    }
    let mut decoder = Decoder::new(input);
    let context = context_from(&mut decoder)?;
    if input.len() > context.limits().get(LimitKind::ContextBytes) {
        return Err(CodecError::LimitExceeded);
    }
    ensure_complete(&decoder, input)?;
    if encode_verifier_context(&context)?.as_slice() != input {
        return Err(CodecError::NonCanonical);
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::{encode_bundle, encode_canonical_action, encode_verifier_context};
    use proptest::prelude::*;

    fn identifier(bytes: u8) -> [u8; 32] {
        [bytes; 32]
    }

    fn minimal_signature() -> SignatureEnvelope {
        SignatureEnvelope::new(
            SignatureDescriptor::new(
                PrincipalMethodId::parse("did-key").unwrap(),
                VerificationMethod::parse("did:example:actor#key-1").unwrap(),
                SignatureSuiteId::parse("eddsa-ed25519").unwrap(),
            ),
            SignatureBytes::new(vec![7; 64]).unwrap(),
        )
    }

    fn minimal_bundle() -> ProofBundle {
        let proof_ref = ProofRef::new(identifier(1));
        let action = ActionEnvelope::new(
            ProfileRef::new(ProfileId::parse("test").unwrap(), 1).unwrap(),
            MediaType::parse("application/test").unwrap(),
            Digest::new(identifier(2)),
            Permission::new(
                CapabilityId::parse("read").unwrap(),
                ResourceId::parse("urn:test:item").unwrap(),
            ),
            None,
            Audience::parse("urn:test:verifier").unwrap(),
            Challenge::new(identifier(3)),
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(20)).unwrap(),
            PrincipalId::parse("did:example:actor").unwrap(),
            None,
            PlanId::new(identifier(4)),
            ChannelBindingId::parse("none").unwrap(),
            proof_ref,
            Vec::new(),
            CriticalExtensions::empty(),
        );
        ProofBundle::new(
            BundleHeader::v1(),
            Vec::new(),
            vec![SignedAction::new(action, minimal_signature())],
            AuthorizationPlan::proof(proof_ref),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        )
        .unwrap()
    }

    fn minimal_context() -> VerifierContext {
        let profile = ProfileRef::new(ProfileId::parse("test").unwrap(), 1).unwrap();
        let method = PrincipalMethodId::parse("did-key").unwrap();
        let policy_id = AssurancePolicyId::parse("baseline").unwrap();
        let registries = AcceptedRegistries::new(
            RegistryManifestId::new(identifier(5)),
            vec![method.clone()],
            vec![SignatureSuiteId::parse("eddsa-ed25519").unwrap()],
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            vec![ResourceMatcherId::parse("uri-namespace-v1").unwrap()],
            Vec::new(),
            Vec::new(),
            vec![profile.clone()],
            vec![ProfilePolicyId::parse("exact").unwrap()],
        )
        .unwrap();
        let anchor = TrustAnchor::new(
            TrustAnchorId::parse("root").unwrap(),
            PrincipalId::parse("did:example:root").unwrap(),
            vec![method],
            vec![profile],
            PermissionSet::new(vec![Permission::new(
                CapabilityId::parse("read").unwrap(),
                ResourceId::parse("urn:test:item").unwrap(),
            )])
            .unwrap(),
            vec![ResourceId::parse("urn:test").unwrap()],
            AudienceSet::new(vec![Audience::parse("urn:test:verifier").unwrap()]).unwrap(),
            ValidityWindow::new(Timestamp::new(0), Timestamp::new(100)).unwrap(),
            None,
            4,
            policy_id.clone(),
            StatusPolicy::ExpiryOnly,
        )
        .unwrap();
        VerifierContext::new(
            VerifierConfigurationId::new(identifier(8)),
            CompositionRequirement::exact(PlanId::new(identifier(4))),
            vec![anchor],
            registries,
            Audience::parse("urn:test:verifier").unwrap(),
            Challenge::new(identifier(3)),
            Timestamp::new(50),
            AssurancePolicy::new(policy_id, Vec::new()).unwrap(),
            PrincipalStatusSnapshot::new(
                StatusSnapshotId::new(identifier(6)),
                Timestamp::new(0),
                Timestamp::new(100),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            GrantStatusSnapshot::new(
                StatusSnapshotId::new(identifier(7)),
                Timestamp::new(0),
                Timestamp::new(100),
                Vec::new(),
                Vec::new(),
            )
            .unwrap(),
            ResourceMatcherId::parse("uri-namespace-v1").unwrap(),
            ProfilePolicyId::parse("exact").unwrap(),
            ChannelBindingId::parse("none").unwrap(),
            VerifierLimits::default(),
        )
        .unwrap()
    }

    fn minimal_canonical_action() -> CanonicalAction {
        CanonicalAction::new(
            ProfileRef::new(ProfileId::parse("test").unwrap(), 1).unwrap(),
            MediaType::parse("application/octet-stream").unwrap(),
            vec![1, 2, 3],
            Permission::new(
                CapabilityId::parse("read").unwrap(),
                ResourceId::parse("urn:test:item").unwrap(),
            ),
            None,
        )
        .unwrap()
    }

    fn minimal_grant_statement() -> GrantStatement {
        GrantStatement::new(
            PrincipalId::parse("did:example:root").unwrap(),
            PrincipalId::parse("did:example:actor").unwrap(),
            ProfileRef::new(ProfileId::parse("test").unwrap(), 1).unwrap(),
            PermissionSet::new(vec![Permission::new(
                CapabilityId::parse("read").unwrap(),
                ResourceId::parse("urn:test:item").unwrap(),
            )])
            .unwrap(),
            ValidityWindow::new(Timestamp::new(10), Timestamp::new(20)).unwrap(),
            AudienceSet::new(vec![Audience::parse("urn:test:verifier").unwrap()]).unwrap(),
            ActionConstraint::AnyBody,
            None,
            1,
            None,
            StatusPolicy::ExpiryOnly,
            AssurancePolicyId::parse("baseline").unwrap(),
            CriticalExtensions::empty(),
        )
    }

    fn minimal_principal_status_statement() -> PrincipalStatusStatement {
        PrincipalStatusStatement::new(
            StatusMethodId::parse("status-test-v1").unwrap(),
            PrincipalId::parse("did:example:actor").unwrap(),
            PurposeId::parse("signing").unwrap(),
            PrincipalState::Active,
            1,
            Timestamp::new(10),
            Timestamp::new(20),
            PrincipalId::parse("did:example:root").unwrap(),
            CriticalExtensions::empty(),
        )
        .unwrap()
    }

    fn minimal_grant_status_statement() -> GrantStatusStatement {
        GrantStatusStatement::new(
            StatusMethodId::parse("status-test-v1").unwrap(),
            GrantId::new(identifier(9)),
            GrantState::Active,
            1,
            Timestamp::new(10),
            Timestamp::new(20),
            PrincipalId::parse("did:example:root").unwrap(),
            CriticalExtensions::empty(),
        )
        .unwrap()
    }

    #[test]
    fn bundle_round_trip_is_unique() {
        let bundle = minimal_bundle();
        let encoded = encode_bundle(&bundle).unwrap();
        assert_eq!(
            decode_bundle(&encoded, &VerifierLimits::default()).unwrap(),
            bundle
        );
    }

    #[test]
    fn isolated_authoring_statements_round_trip_canonically() {
        let limits = VerifierLimits::default_deployment();
        let grant = minimal_grant_statement();
        let grant_bytes = crate::encode::encode_grant_statement(&grant).unwrap();
        assert_eq!(decode_grant_statement(&grant_bytes, &limits).unwrap(), grant);

        let action = minimal_bundle().actions()[0].envelope().clone();
        let action_bytes = crate::encode::encode_action_envelope(&action).unwrap();
        assert_eq!(
            decode_action_envelope(&action_bytes, &limits).unwrap(),
            action
        );

        let principal_status = minimal_principal_status_statement();
        let principal_status_bytes =
            crate::encode::encode_principal_status_statement(&principal_status).unwrap();
        assert_eq!(
            decode_principal_status_statement(&principal_status_bytes, &limits).unwrap(),
            principal_status
        );

        let grant_status = minimal_grant_status_statement();
        let grant_status_bytes =
            crate::encode::encode_grant_status_statement(&grant_status).unwrap();
        assert_eq!(
            decode_grant_status_statement(&grant_status_bytes, &limits).unwrap(),
            grant_status
        );
    }

    #[test]
    fn isolated_authoring_decoders_reject_trailing_bytes() {
        let limits = VerifierLimits::default_deployment();
        let mut bytes =
            crate::encode::encode_grant_statement(&minimal_grant_statement()).unwrap();
        bytes.push(0);
        assert_eq!(
            decode_grant_statement(&bytes, &limits),
            Err(CodecError::Malformed)
        );
    }

    #[test]
    fn verifier_context_round_trip_is_unique() {
        let context = minimal_context();
        let encoded = encode_verifier_context(&context).unwrap();
        assert_eq!(decode_verifier_context(&encoded).unwrap(), context);
    }

    #[test]
    fn portable_input_byte_limits_enforce_exact_boundaries() {
        let action = minimal_canonical_action();
        let encoded_action = encode_canonical_action(&action).unwrap();
        let exact_action = VerifierLimits::default()
            .with_limit(LimitKind::ActionBytes, encoded_action.len())
            .unwrap();
        assert_eq!(
            decode_canonical_action(&encoded_action, &exact_action).unwrap(),
            action
        );
        let short_action = exact_action
            .with_limit(LimitKind::ActionBytes, encoded_action.len() - 1)
            .unwrap();
        assert_eq!(
            decode_canonical_action(&encoded_action, &short_action),
            Err(CodecError::LimitExceeded)
        );

        let provisional = minimal_context()
            .with_limits(
                VerifierLimits::default()
                    .with_limit(LimitKind::ContextBytes, 65_535)
                    .unwrap(),
            )
            .unwrap();
        let provisional_length = encode_verifier_context(&provisional).unwrap().len();
        let exact_context = provisional
            .with_limits(
                provisional
                    .limits()
                    .clone()
                    .with_limit(LimitKind::ContextBytes, provisional_length)
                    .unwrap(),
            )
            .unwrap();
        let encoded_context = encode_verifier_context(&exact_context).unwrap();
        assert_eq!(encoded_context.len(), provisional_length);
        assert_eq!(
            decode_verifier_context(&encoded_context).unwrap(),
            exact_context
        );
        let short_context = exact_context
            .with_limits(
                exact_context
                    .limits()
                    .clone()
                    .with_limit(LimitKind::ContextBytes, encoded_context.len() - 1)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            decode_verifier_context(&encode_verifier_context(&short_context).unwrap()),
            Err(CodecError::LimitExceeded)
        );
    }

    #[test]
    fn detached_attachment_limit_is_aggregate() {
        let action = minimal_canonical_action()
            .with_detached_attachments(vec![
                DetachedAttachment::new(AttachmentDigest::new([1; 32]), vec![1, 2]).unwrap(),
                DetachedAttachment::new(AttachmentDigest::new([2; 32]), vec![3, 4]).unwrap(),
            ])
            .unwrap();
        let encoded = encode_canonical_action(&action).unwrap();
        let exact = VerifierLimits::default()
            .with_limit(LimitKind::AttachmentBytes, 4)
            .unwrap();
        assert_eq!(decode_canonical_action(&encoded, &exact).unwrap(), action);
        let short = exact.with_limit(LimitKind::AttachmentBytes, 3).unwrap();
        assert_eq!(
            decode_canonical_action(&encoded, &short),
            Err(CodecError::LimitExceeded)
        );
    }

    #[test]
    fn equivalent_non_minimal_integer_is_rejected() {
        let encoded = encode_bundle(&minimal_bundle()).unwrap();
        let mut non_canonical = vec![encoded[0], 0x18, 0x00];
        non_canonical.extend_from_slice(&encoded[2..]);
        assert_eq!(
            decode_bundle(&non_canonical, &VerifierLimits::default()),
            Err(CodecError::NonCanonical)
        );
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut encoded = encode_bundle(&minimal_bundle()).unwrap();
        encoded.push(0);
        assert_eq!(
            decode_bundle(&encoded, &VerifierLimits::default()),
            Err(CodecError::Malformed)
        );
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(
            bytes in proptest::collection::vec(any::<u8>(), 0..4096)
        ) {
            let _ = decode_bundle(&bytes, &VerifierLimits::default());
            let _ = decode_verifier_context(&bytes);
        }
    }
}
