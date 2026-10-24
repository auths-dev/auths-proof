//! Frozen pre-cutover reference/control stages. Test-only oracle.
//! Uses the same protocol carriers and primitive adapters, while retaining the
//! old independent stage loops, refusal ordering and evidence selection.
use super::*;

/// Resolves and validates the complete digest/reference graph.
///
/// # Errors
///
/// Returns a stable denial for missing, duplicate, cyclic, mismatched,
/// ambiguous, or unused critical references.
pub(crate) fn resolve_proof(
    decoded: DecodedProof,
    context: &TrustedContext,
) -> Result<ResolvedProof, VerificationFailure> {
    let bundle = decoded.bundle();
    let computed_plan_id = plan_id(bundle.plan()).map_err(codec_failure)?;
    require_expected_plan(context, computed_plan_id)?;
    let mut grants = Vec::with_capacity(bundle.grants().len());
    for (index, grant) in bundle.grants().iter().enumerate() {
        grants.push(GrantRecord {
            id: grant_id(grant.statement()).map_err(codec_failure)?,
            index,
        });
    }
    grants.sort_by_key(|record| record.id);
    if grants.windows(2).any(|window| window[0].id == window[1].id) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    let mut actions = Vec::with_capacity(bundle.actions().len());
    let mut proof_refs = OrderedSet::new();
    for (index, action) in bundle.actions().iter().enumerate() {
        if action.envelope().authorization_plan() != computed_plan_id {
            return Err(VerificationFailure::Denied(
                DenialReason::PlanActionMismatch,
            ));
        }
        if !proof_refs.insert(action.envelope().proof_ref()) {
            return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
        }
        actions.push(ActionRecord {
            id: action_id(action.envelope()).map_err(codec_failure)?,
            index,
        });
    }
    actions.sort_by_key(|record| record.id);
    if actions
        .windows(2)
        .any(|window| window[0].id == window[1].id)
    {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }

    let shape = bundle
        .plan()
        .validate(context.limits())
        .map_err(|_| VerificationFailure::Denied(DenialReason::AuthorizationPlanInvalid))?;
    if shape.leaves().len() != bundle.actions().len()
        || shape.leaves().iter().any(|reference| {
            !bundle
                .actions()
                .iter()
                .any(|action| action.envelope().proof_ref() == *reference)
        })
    {
        return Err(VerificationFailure::Denied(DenialReason::MissingReference));
    }

    let evidence_ids = OrderedSet::from_vec(bundle.evidence().iter().map(EvidenceObject::id).collect());
    if evidence_ids.len() != bundle.evidence().len() {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }

    let principal_status = principal_status_records(context)?;
    let grant_status = grant_status_records(context)?;
    let mut bound_statements = OrderedSet::new();
    for binding in bundle.bindings() {
        if !bound_statements.insert(binding.statement()) {
            return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
        }
        if !statement_exists(
            binding.statement(),
            &grants,
            &actions,
            &principal_status,
            &grant_status,
        ) || binding
            .evidence()
            .iter()
            .any(|id| !evidence_ids.contains(id))
        {
            return Err(VerificationFailure::Denied(DenialReason::MissingReference));
        }
    }

    let mut used_grants = OrderedSet::new();
    for action in bundle.actions() {
        resolve_chain(bundle, &grants, action, &mut used_grants)?;
    }
    if used_grants.len() != grants.len() {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalEvidence,
        ));
    }

    reject_duplicate_attachments(bundle)?;
    validate_carried_status(bundle, context)?;
    Ok(ResolvedProof {
        decoded,
        plan_id: computed_plan_id,
        grants,
        actions,
    })
}

fn require_expected_plan(
    context: &TrustedContext,
    actual: PlanId,
) -> Result<(), VerificationFailure> {
    if context
        .composition()
        .expected_plan()
        .is_some_and(|expected| expected != actual)
    {
        Err(VerificationFailure::Denied(
            DenialReason::CompositionRequirementNotMet,
        ))
    } else {
        Ok(())
    }
}

fn principal_status_records(
    context: &TrustedContext,
) -> Result<Vec<PrincipalStatusId>, VerificationFailure> {
    let mut values = Vec::new();
    for status in context.principal_status_snapshot().statements() {
        values.push(principal_status_id(status.statement()).map_err(codec_failure)?);
    }
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    Ok(values)
}

fn grant_status_records(
    context: &TrustedContext,
) -> Result<Vec<GrantStatusId>, VerificationFailure> {
    let mut values = Vec::new();
    for status in context.grant_status_snapshot().statements() {
        values.push(grant_status_id(status.statement()).map_err(codec_failure)?);
    }
    values.sort();
    if values.windows(2).any(|window| window[0] == window[1]) {
        return Err(VerificationFailure::Denied(DenialReason::DuplicateObject));
    }
    Ok(values)
}

fn statement_exists(
    statement: StatementRef,
    grants: &[GrantRecord],
    actions: &[ActionRecord],
    principal_status: &[PrincipalStatusId],
    grant_status: &[GrantStatusId],
) -> bool {
    match statement {
        StatementRef::Grant(id) => grants.binary_search_by_key(&id, |record| record.id).is_ok(),
        StatementRef::Action(id) => actions
            .binary_search_by_key(&id, |record| record.id)
            .is_ok(),
        StatementRef::PrincipalStatus(id) => principal_status.binary_search(&id).is_ok(),
        StatementRef::GrantStatus(id) => grant_status.binary_search(&id).is_ok(),
    }
}

fn resolve_chain(
    bundle: &ProofBundle,
    grants: &[GrantRecord],
    action: &SignedAction,
    used: &mut OrderedSet<GrantId>,
) -> Result<(), VerificationFailure> {
    let mut cursor = action.envelope().terminal_grant();
    let mut branch = OrderedSet::new();
    while let Some(id) = cursor {
        if !branch.insert(id) {
            return Err(VerificationFailure::Denied(DenialReason::ReferenceCycle));
        }
        let position = grants
            .binary_search_by_key(&id, |record| record.id)
            .map_err(|_| VerificationFailure::Denied(DenialReason::MissingReference))?;
        let grant = &bundle.grants()[grants[position].index];
        cursor = grant.statement().parent();
        used.insert(id);
    }
    Ok(())
}

fn reject_duplicate_attachments(bundle: &ProofBundle) -> Result<(), VerificationFailure> {
    if bundle
        .attachments()
        .windows(2)
        .any(|window| window[0].digest() == window[1].digest())
    {
        Err(VerificationFailure::Denied(
            DenialReason::DuplicateAttachment,
        ))
    } else {
        Ok(())
    }
}

/// Rejects a proof-carried status statement that the snapshot supersedes or
/// does not hold, in two passes: every rollback check (principal-status
/// statements, then grant-status statements) before any holding check.
///
/// Rollback compares only statements with the carried statement's subject,
/// method, and issuer. A sequence number orders one issuer's statements under
/// one method, so a statement from another issuer, which may be out of scope
/// for every branch, never supersedes the holder's own.
fn validate_carried_status(
    bundle: &ProofBundle,
    context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    if bundle.principal_status().iter().any(|carried| {
        let carried = carried.statement();
        context
            .principal_status_snapshot()
            .statements()
            .iter()
            .map(SignedPrincipalStatus::statement)
            .any(|current| {
                current.principal() == carried.principal()
                    && current.method() == carried.method()
                    && current.issuer() == carried.issuer()
                    && current.sequence() > carried.sequence()
            })
    }) || bundle.grant_status().iter().any(|carried| {
        let carried = carried.statement();
        context
            .grant_status_snapshot()
            .statements()
            .iter()
            .map(SignedGrantStatus::statement)
            .any(|current| {
                current.grant_id() == carried.grant_id()
                    && current.method() == carried.method()
                    && current.issuer() == carried.issuer()
                    && current.sequence() > carried.sequence()
            })
    }) {
        return Err(VerificationFailure::Denied(
            DenialReason::StatusSequenceRollback,
        ));
    }
    if bundle.principal_status().iter().any(|carried| {
        !context
            .principal_status_snapshot()
            .statements()
            .contains(carried)
    }) || bundle.grant_status().iter().any(|carried| {
        !context
            .grant_status_snapshot()
            .statements()
            .contains(carried)
    }) {
        Err(VerificationFailure::Denied(DenialReason::DigestMismatch))
    } else {
        Ok(())
    }
}

/// Verifies exact principal methods, exact signature suites, and all supplied
/// signed statements.
///
/// # Errors
///
/// Returns a stable denial or indeterminate requirement. Work is charged
/// before the configured maximum can be exceeded.
pub(crate) fn verify_principal_control<R: RegistryAccess + ?Sized>(
    resolved: ResolvedProof,
    context: &TrustedContext,
    registries: &R,
) -> Result<ControlVerifiedProof, VerificationFailure> {
    if context.accepted_registries().manifest_id() != registries.manifest_id() {
        return Err(VerificationFailure::Denied(
            DenialReason::RegistryManifestMismatch,
        ));
    }
    if context.configuration() != registries.configuration_id() {
        return Err(VerificationFailure::Denied(
            DenialReason::VerifierConfigurationMismatch,
        ));
    }
    let mut controls = Vec::new();
    let mut meter = WorkMeter::new(context.limits().max_work_units());
    let bundle = resolved.decoded.bundle();

    for record in &resolved.grants {
        let grant = &bundle.grants()[record.index];
        let preimage = grant_signing_preimage(grant.statement(), grant.signature().descriptor())
            .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::Grant(record.id),
            grant.statement().issuer(),
            grant.signature(),
            &preimage,
            ControlPurpose::CapabilityDelegation,
            grant.statement().validity().not_before(),
            bundle,
            context,
            registries,
            &mut meter,
        )?;
        controls.push(control);
    }
    for record in &resolved.actions {
        let action = &bundle.actions()[record.index];
        let preimage = action_signing_preimage(action.envelope(), action.signature().descriptor())
            .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::Action(record.id),
            action.envelope().actor(),
            action.signature(),
            &preimage,
            ControlPurpose::CapabilityInvocation,
            action.envelope().validity().not_before(),
            bundle,
            context,
            registries,
            &mut meter,
        )?;
        controls.push(control);
    }
    verify_status_controls(bundle, context, registries, &mut meter, &mut controls)?;
    for control in &controls {
        let Ok(evidence) = &control.result else {
            continue;
        };
        let bound = OrderedSet::from_vec(bundle
            .bindings()
            .iter()
            .find(|binding| binding.statement() == control.statement)
            .map(auths_model::ControlBinding::evidence)
            .unwrap_or_default()
            .iter()
            .copied()
            .collect());
        let consumed = OrderedSet::from_vec(evidence.consumed_evidence().iter().copied().collect());
        if bound != consumed {
            return Err(VerificationFailure::Denied(
                DenialReason::UnusedCriticalEvidence,
            ));
        }
    }
    let consumed = OrderedSet::from_vec(bundle
        .bindings()
        .iter()
        .flat_map(auths_model::ControlBinding::evidence)
        .copied()
        .chain(
            context
                .principal_status_snapshot()
                .checkpoints()
                .iter()
                .chain(context.grant_status_snapshot().checkpoints())
                .copied(),
        )
        .collect());
    if bundle
        .evidence()
        .iter()
        .any(|evidence| !consumed.contains(&evidence.id()))
    {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalEvidence,
        ));
    }
    Ok(ControlVerifiedProof {
        resolved,
        controls,
        work_units: meter.used,
    })
}

fn verify_status_controls<R: RegistryAccess + ?Sized>(
    bundle: &ProofBundle,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
    controls: &mut Vec<VerifiedControl>,
) -> Result<(), VerificationFailure> {
    for status in context.principal_status_snapshot().statements() {
        let id = principal_status_id(status.statement()).map_err(codec_failure)?;
        let preimage =
            principal_status_signing_preimage(status.statement(), status.signature().descriptor())
                .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::PrincipalStatus(id),
            status.statement().issuer(),
            status.signature(),
            &preimage,
            ControlPurpose::Assertion,
            status.statement().observed_at(),
            bundle,
            context,
            registries,
            meter,
        )?;
        controls.push(control);
    }
    for status in context.grant_status_snapshot().statements() {
        let id = grant_status_id(status.statement()).map_err(codec_failure)?;
        let preimage =
            grant_status_signing_preimage(status.statement(), status.signature().descriptor())
                .map_err(codec_failure)?;
        let control = verify_signed(
            StatementRef::GrantStatus(id),
            status.statement().issuer(),
            status.signature(),
            &preimage,
            ControlPurpose::Assertion,
            status.statement().observed_at(),
            bundle,
            context,
            registries,
            meter,
        )?;
        controls.push(control);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_signed<R: RegistryAccess + ?Sized>(
    statement: StatementRef,
    principal: &PrincipalId,
    signature: &SignatureEnvelope,
    signing_preimage: &[u8],
    purpose: ControlPurpose,
    asserted_signing_time: Timestamp,
    bundle: &ProofBundle,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<VerifiedControl, VerificationFailure> {
    let result = evaluate_signature(
        principal,
        signature,
        signing_preimage,
        purpose,
        asserted_signing_time,
        || bound_evidence(bundle, statement),
        context,
        registries,
        meter,
    );
    if result
        == Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ))
    {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    Ok(VerifiedControl {
        statement,
        principal: principal.clone(),
        result,
    })
}

/// Establishes principal control over one signature: the registered principal
/// method and signature suite, the control evidence `evidence` returns, whose
/// types the context must accept, and work reserved before evaluation. Every
/// failure is returned, resource exhaustion included; the caller decides
/// which failures stop the verification.
#[allow(clippy::too_many_arguments)]
pub(super) fn evaluate_signature<'e, R: RegistryAccess + ?Sized>(
    principal: &PrincipalId,
    signature: &SignatureEnvelope,
    signing_preimage: &[u8],
    purpose: ControlPurpose,
    asserted_signing_time: Timestamp,
    evidence: impl FnOnce() -> Result<Vec<&'e EvidenceObject>, VerificationFailure>,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<ControlEvidence, VerificationFailure> {
    let descriptor = signature.descriptor();
    let method = registries
        .principal_method(context.accepted_registries(), descriptor.principal_method())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedPrincipalMethod,
        ))?;
    let suite = registries
        .signature_suite(context.accepted_registries(), descriptor.suite())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedSignatureSuite,
        ))?;
    let evidence = evidence()?;
    if evidence.iter().any(|object| {
        !context
            .accepted_registries()
            .accepts_evidence_type(object.evidence_type())
    }) {
        return Err(VerificationFailure::Indeterminate(
            Requirement::UnsupportedEvidenceType,
        ));
    }
    let method_reservation = method.maximum_work_units();
    meter.reserve(method_reservation)?;
    meter.reserve(suite.work_units())?;
    let control = method
        .evaluate_control(
            PrincipalControlInput {
                principal,
                verification_method: descriptor.verification_method(),
                signature_suite: descriptor.suite(),
                purpose,
                signing_preimage,
                signature: signature.signature().as_slice(),
                asserted_signing_time,
                evidence: &evidence,
                evaluation_time: context.evaluation_time(),
            },
            DiagnosticMode::Discard,
        )
        .into_result()
        .map_err(control_failure)?;
    if control.work_units() > method_reservation {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    suite
        .verify(SignatureInput {
            verification_key: control.verification_key(),
            signing_preimage: control.signature_message().unwrap_or(signing_preimage),
            signature: signature.signature().as_slice(),
        })
        .map_err(signature_failure)?;
    Ok(control)
}

fn bound_evidence(
    bundle: &ProofBundle,
    statement: StatementRef,
) -> Result<Vec<&EvidenceObject>, VerificationFailure> {
    let binding = bundle
        .bindings()
        .iter()
        .find(|binding| binding.statement() == statement)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::MissingPrincipalEvidence,
        ))?;
    let mut objects = Vec::with_capacity(binding.evidence().len());
    for id in binding.evidence() {
        objects.push(
            bundle
                .evidence()
                .iter()
                .find(|object| object.id() == *id)
                .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?,
        );
    }
    Ok(objects)
}


pub(super) fn validate_action_binding<R: RegistryAccess + ?Sized>(
    controlled: &ControlVerifiedProof,
    canonical: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let bundle = controlled.resolved.decoded.bundle();
    if bundle
        .canonical_body()
        .is_some_and(|body| body != canonical.body())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::ActionBodyMismatch,
        ));
    }
    let expected_digest = body_digest(canonical.body());
    let first = bundle
        .actions()
        .first()
        .ok_or(VerificationFailure::Denied(
            DenialReason::AuthorizationPlanInvalid,
        ))?
        .envelope();
    for signed in bundle.actions() {
        let action = signed.envelope();
        if action.profile() != canonical.profile()
            || action.body_media_type() != canonical.media_type()
            || action.canonical_body_digest() != expected_digest
            || action.permission() != canonical.permission()
            || action.requested_budget() != canonical.requested_budget()
        {
            return Err(VerificationFailure::Denied(
                DenialReason::ActionBodyMismatch,
            ));
        }
        if !context
            .accepted_registries()
            .accepts_profile(action.profile())
        {
            return Err(VerificationFailure::Indeterminate(
                Requirement::UnsupportedProfile,
            ));
        }
        if action.audience() != context.expected_audience() {
            return Err(VerificationFailure::Denied(DenialReason::AudienceMismatch));
        }
        if action.challenge() != context.expected_challenge() {
            return Err(VerificationFailure::Denied(DenialReason::ChallengeMismatch));
        }
        if !action.validity().contains(context.evaluation_time()) {
            return Err(VerificationFailure::Denied(
                DenialReason::ActionOutsideValidity,
            ));
        }
        if action.channel_binding() != context.channel_policy() {
            return Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied));
        }
        if !same_shared_action(first, action) {
            return Err(VerificationFailure::Denied(
                DenialReason::PlanActionMismatch,
            ));
        }
        evaluate_extensions(action.extensions(), context, registries, meter)?;
        observation::validate_observation_attachments(signed)?;
    }
    validate_attachments(bundle, canonical, context)?;
    let profile_policy = registries
        .profile_policy(context.accepted_registries(), context.profile_policy())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedProfilePolicy,
        ))?;
    meter.reserve(profile_policy.maximum_work_units(canonical))?;
    match profile_policy
        .evaluate(canonical)
        .map_err(registry_operation_failure)?
    {
        ProfileDecision::Accept => Ok(()),
        ProfileDecision::Deny => Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied)),
    }
}

fn validate_attachments(
    bundle: &ProofBundle,
    canonical: &CanonicalAction,
    context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    let descriptors = bundle
        .actions()
        .first()
        .map(|action| action.envelope().attachments())
        .unwrap_or_default();
    if descriptors != bundle.attachments() {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalAttachment,
        ));
    }
    if descriptors
        .windows(2)
        .any(|window| window[0].digest() == window[1].digest())
        || canonical
            .detached_attachments()
            .windows(2)
            .any(|window| window[0].digest() == window[1].digest())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::DuplicateAttachment,
        ));
    }
    let total = canonical
        .detached_attachments()
        .iter()
        .try_fold(0usize, |total, attachment| {
            total.checked_add(attachment.bytes().len())
        })
        .ok_or(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ))?;
    if total
        > context
            .limits()
            .get(auths_model::LimitKind::AttachmentBytes)
    {
        return Err(VerificationFailure::Denied(
            DenialReason::ResourceLimitExceeded,
        ));
    }
    for descriptor in descriptors {
        let detached = canonical
            .detached_attachments()
            .iter()
            .find(|attachment| attachment.digest() == descriptor.digest());
        let Some(detached) = detached else {
            if matches!(descriptor.presence(), auths_model::Presence::Required) {
                return Err(VerificationFailure::Denied(DenialReason::AttachmentMissing));
            }
            continue;
        };
        let length = u64::try_from(detached.bytes().len())
            .map_err(|_| VerificationFailure::Denied(DenialReason::AttachmentLengthMismatch))?;
        if length != descriptor.byte_length() {
            return Err(VerificationFailure::Denied(
                DenialReason::AttachmentLengthMismatch,
            ));
        }
        if attachment_digest(detached.bytes()) != descriptor.digest() {
            return Err(VerificationFailure::Denied(
                DenialReason::AttachmentDigestMismatch,
            ));
        }
        if matches!(
            descriptor.confidentiality(),
            auths_model::Confidentiality::Encrypted
        ) && matches!(
            descriptor.opacity(),
            auths_model::Opacity::MustBeInspectable
        ) {
            return Err(VerificationFailure::Denied(
                DenialReason::OpaqueAttachmentNotAllowed,
            ));
        }
    }
    if canonical.detached_attachments().iter().any(|attachment| {
        !descriptors
            .iter()
            .any(|descriptor| descriptor.digest() == attachment.digest())
    }) {
        return Err(VerificationFailure::Denied(
            DenialReason::UnusedCriticalAttachment,
        ));
    }
    Ok(())
}

fn same_shared_action(
    left: &auths_model::ActionEnvelope,
    right: &auths_model::ActionEnvelope,
) -> bool {
    left.profile() == right.profile()
        && left.body_media_type() == right.body_media_type()
        && left.canonical_body_digest() == right.canonical_body_digest()
        && left.permission() == right.permission()
        && left.requested_budget() == right.requested_budget()
        && left.audience() == right.audience()
        && left.challenge() == right.challenge()
        && left.validity() == right.validity()
        && left.authorization_plan() == right.authorization_plan()
        && left.channel_binding() == right.channel_binding()
        && left.attachments() == right.attachments()
        && left.extensions() == right.extensions()
}


struct BranchInput<'a, R: RegistryAccess + ?Sized> {
    controlled: &'a ControlVerifiedProof,
    action: &'a SignedAction,
    action_id: ActionId,
    chain: &'a [&'a SignedGrant],
    root_control: (&'a PrincipalId, &'a ControlEvidence),
    canonical: &'a CanonicalAction,
    context: &'a TrustedContext,
    registries: &'a R,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn verify_branch<R: RegistryAccess + ?Sized>(
    controlled: &ControlVerifiedProof,
    proof_ref: ProofRef,
    canonical: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
    approvals: &mut approval::Approvals<'_>,
    approval_inputs: &approval::Inputs<'_, R>,
) -> Result<BranchAuthority, VerificationFailure> {
    let bundle = controlled.resolved.decoded.bundle();
    let action = bundle
        .actions()
        .iter()
        .find(|action| action.envelope().proof_ref() == proof_ref)
        .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
    let action_id = action_id(action.envelope()).map_err(codec_failure)?;
    let chain = branch_chain(&controlled.resolved, action)?;
    let root_principal = chain.first().map_or(action.envelope().actor(), |grant| {
        grant.statement().issuer()
    });
    let root_statement = match chain.first() {
        Some(grant) => StatementRef::Grant(grant_id(grant.statement()).map_err(codec_failure)?),
        None => StatementRef::Action(action_id),
    };
    let root_control = control_for(controlled, root_statement)?;

    let mut first_failure = None;
    for anchor in context
        .trust_anchors()
        .iter()
        .filter(|anchor| anchor.principal() == root_principal)
    {
        let branch = BranchInput {
            controlled,
            action,
            action_id,
            chain: &chain,
            root_control,
            canonical,
            context,
            registries,
        };
        match verify_branch_from_anchor(&branch, anchor, meter, approvals, approval_inputs) {
            Ok(authority) => return Ok(authority),
            Err(failure) => first_failure.get_or_insert(failure),
        };
    }
    Err(first_failure.unwrap_or(VerificationFailure::Denied(DenialReason::UntrustedRoot)))
}

fn verify_branch_from_anchor<R: RegistryAccess + ?Sized>(
    branch: &BranchInput<'_, R>,
    anchor: &TrustAnchor,
    meter: &mut WorkMeter,
    approvals: &mut approval::Approvals<'_>,
    approval_inputs: &approval::Inputs<'_, R>,
) -> Result<BranchAuthority, VerificationFailure> {
    let BranchInput {
        controlled,
        action,
        action_id,
        chain,
        root_control,
        canonical,
        context,
        registries,
    } = *branch;
    if !anchor
        .accepted_methods()
        .contains(action_or_first_method(action, chain))
        || anchor.assurance_policy() != context.assurance_policy().id()
    {
        return Err(VerificationFailure::Denied(DenialReason::UntrustedRoot));
    }
    let mut authority_not_after = anchor
        .validity()
        .expires_at()
        .min(action.envelope().validity().expires_at());
    authority_not_after = authority_not_after.min(check_principal_status(
        controlled,
        anchor.status_policy(),
        anchor.principal(),
        StatusListing::Required,
        anchor,
        context,
        registries,
        meter,
    )?);
    // Every grant subject is checked under the anchor's policy, not the
    // grant's own: by chain linkage the subjects are every issuer after the
    // root and the actor, and a grant's policy governs only that grant.
    for grant in chain {
        let id = grant_id(grant.statement()).map_err(codec_failure)?;
        authority_not_after = authority_not_after.min(grant.statement().validity().expires_at());
        authority_not_after = authority_not_after.min(check_grant_status(
            controlled,
            grant.statement().status_policy(),
            id,
            anchor,
            context,
            registries,
            meter,
        )?);
        authority_not_after = authority_not_after.min(check_principal_status(
            controlled,
            anchor.status_policy(),
            grant.statement().subject(),
            StatusListing::RevocationList,
            anchor,
            context,
            registries,
            meter,
        )?);
    }
    validate_resource_constraints(anchor, chain, action, context, registries, meter)?;
    validate_budget_constraints(anchor, chain, action, context, registries, meter)?;
    let mut reports = Vec::new();
    if chain.is_empty() {
        reports.push(participant_report(
            root_control.0,
            root_control.1,
            ParticipantRole::Root,
        )?);
    }
    delegate_chain(branch, anchor, &mut reports, meter)?;
    let action_control = control_for(controlled, StatementRef::Action(action_id))?;
    reports.push(participant_report(
        action_control.0,
        action_control.1,
        ParticipantRole::Actor,
    )?);
    let assurance_satisfactions = evaluate_branch_assurance(&reports, context, registries, meter)?;
    authority_not_after =
        authority_not_after.min(assurance_horizon(&assurance_satisfactions, context)?);
    let (observation_satisfactions, observation_not_after) = observation::Stage {
        chain,
        root: anchor.principal(),
        action,
        canonical,
        context,
        registries,
    }
    .evaluate(meter)?;
    authority_not_after = authority_not_after.min(observation_not_after);
    let approval_requirements = approval::chain_requirements(chain)?;
    approvals.evaluate_list(&approval_requirements, approval_inputs, meter)?;
    Ok(BranchAuthority {
        action_id,
        authority_not_after,
        assurance: reports,
        assurance_satisfactions,
        observation_satisfactions,
        approval_requirements: approval_requirements
            .into_iter()
            .map(|(identifier, _)| identifier)
            .collect(),
    })
}

/// Walks the grant chain root to terminal, applying every delegation edge,
/// and then checks the action against the terminal authority.
fn delegate_chain<R: RegistryAccess + ?Sized>(
    branch: &BranchInput<'_, R>,
    anchor: &TrustAnchor,
    reports: &mut Vec<ParticipantAssurance>,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let mut authority = EffectiveAuthority::from_anchor(anchor);
    let laws = branch
        .registries
        .extension_laws(branch.context.accepted_registries());
    for (index, grant) in branch.chain.iter().enumerate() {
        if let Some(parent) = index.checked_sub(1).map(|parent| branch.chain[parent]) {
            observation::require_parent_requirements(parent, grant)?;
            meter.reserve(laws.maximum_work_units(
                grant.statement().extensions(),
                parent.statement().extensions(),
            ))?;
        }
        let id = grant_id(grant.statement()).map_err(codec_failure)?;
        authority
            .delegate(id, grant.statement(), &laws)
            .map_err(VerificationFailure::Denied)?;
        let control = control_for(branch.controlled, StatementRef::Grant(id))?;
        reports.push(participant_report(
            control.0,
            control.1,
            grant_issuer_role(index),
        )?);
        evaluate_extensions(
            grant.statement().extensions(),
            branch.context,
            branch.registries,
            meter,
        )?;
    }
    authority
        .authorizes(
            branch.action.envelope(),
            branch.context.accepted_registries(),
        )
        .map_err(VerificationFailure::Denied)
}

fn validate_resource_constraints<R: RegistryAccess + ?Sized>(
    anchor: &TrustAnchor,
    chain: &[&SignedGrant],
    action: &SignedAction,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let matcher = registries
        .resource_matcher(context.accepted_registries(), context.resource_matcher())
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedResourceMatcher,
        ))?;
    let resources = chain
        .iter()
        .flat_map(|grant| grant.statement().permissions().as_slice())
        .map(auths_model::Permission::resource)
        .chain(core::iter::once(action.envelope().permission().resource()));
    for resource in resources {
        let mut allowed = false;
        for namespace in anchor.resource_namespaces() {
            meter.reserve(matcher.maximum_work_units(namespace, resource))?;
            allowed |= matcher
                .matches(namespace, resource)
                .map_err(registry_operation_failure)?;
        }
        if !allowed {
            return Err(VerificationFailure::Denied(
                DenialReason::ResourceNamespaceMismatch,
            ));
        }
    }
    Ok(())
}

fn validate_budget_constraints<R: RegistryAccess + ?Sized>(
    anchor: &TrustAnchor,
    chain: &[&SignedGrant],
    action: &SignedAction,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let mut parent = anchor.budget_ceiling();
    for grant in chain {
        let child = grant.statement().budget_ceiling();
        if let Some(parent_budget) = parent {
            let child_budget = child.ok_or(VerificationFailure::Denied(
                DenialReason::DelegationExpanded,
            ))?;
            let algebra = registries
                .budget_algebra(context.accepted_registries(), parent_budget.algebra())
                .ok_or(VerificationFailure::Indeterminate(
                    Requirement::UnsupportedBudgetAlgebra,
                ))?;
            meter.reserve(algebra.maximum_work_units())?;
            if !algebra
                .attenuates(child_budget, parent_budget)
                .map_err(registry_operation_failure)?
            {
                return Err(VerificationFailure::Denied(
                    DenialReason::DelegationExpanded,
                ));
            }
        }
        parent = child;
    }
    if let Some(ceiling) = parent {
        // A bounded terminal authority requires a bounded request *when the
        // action's profile is able to state one*. An action of a profile that
        // could have declared a budget and did not states no bound at all, so
        // there is nothing for the ceiling to bound and it is denied. An action
        // of a profile whose canonical body has no budget field provably spends
        // zero, and zero is within every ceiling.
        let expression = context
            .accepted_registries()
            .profile_budget_expression(action.envelope().profile());
        let Some(requested) = action.envelope().requested_budget() else {
            return match expression {
                ProfileBudgetExpression::Inexpressible => Ok(()),
                ProfileBudgetExpression::Expressible => Err(VerificationFailure::Denied(
                    DenialReason::BudgetCeilingExceeded,
                )),
            };
        };
        let algebra = registries
            .budget_algebra(context.accepted_registries(), ceiling.algebra())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedBudgetAlgebra,
            ))?;
        meter.reserve(algebra.maximum_work_units())?;
        if !algebra
            .covers(ceiling, requested)
            .map_err(registry_operation_failure)?
        {
            return Err(VerificationFailure::Denied(
                DenialReason::BudgetCeilingExceeded,
            ));
        }
    }
    Ok(())
}

/// Out-of-scope statements (`auths_model::status_issuer_in_scope`) take no
/// part: they are not control-checked, not extension-checked, and not
/// selected, so the result is the one the snapshot gives without them. Work
/// is still reserved for every snapshot statement.
#[allow(clippy::too_many_arguments)]
fn check_principal_status<R: RegistryAccess + ?Sized>(
    controlled: &ControlVerifiedProof,
    policy: &StatusPolicy,
    principal: &PrincipalId,
    listing: StatusListing,
    anchor: &TrustAnchor,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<Timestamp, VerificationFailure> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(Timestamp::new(u64::MAX));
    };
    let implementation = registries
        .status_method(context.accepted_registries(), method, true)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedStatusMethod,
        ))?;
    let snapshot = context.principal_status_snapshot();
    for status in snapshot.statements().iter().filter(|status| {
        status.statement().principal() == principal
            && status_issuer_in_scope(snapshot.trust(), status.statement().issuer(), anchor)
    }) {
        let identifier = principal_status_id(status.statement()).map_err(codec_failure)?;
        control_for(controlled, StatementRef::PrincipalStatus(identifier))?;
        check_status_extensions(status.statement().extensions(), context)?;
    }
    meter.reserve(
        implementation.maximum_work_units(context.principal_status_snapshot().statements().len()),
    )?;
    let decision = implementation
        .principal(
            policy,
            context.principal_status_snapshot(),
            principal,
            auths_model::StatusView::Anchor(anchor),
            context.evaluation_time(),
        )
        .map_err(registry_operation_failure)?;
    if matches!(
        (listing, decision.decision()),
        (StatusListing::RevocationList, StatusDecision::Missing)
    ) {
        return status_horizon(decision, context.evaluation_time());
    }
    status_decision(decision.decision(), true)?;
    status_horizon(decision, context.evaluation_time())
}

/// Out-of-scope statements take no part, as for principal status.
fn check_grant_status<R: RegistryAccess + ?Sized>(
    controlled: &ControlVerifiedProof,
    policy: &StatusPolicy,
    grant_id: GrantId,
    anchor: &TrustAnchor,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<Timestamp, VerificationFailure> {
    let StatusPolicy::SnapshotRequired { method, .. } = policy else {
        return Ok(Timestamp::new(u64::MAX));
    };
    let implementation = registries
        .status_method(context.accepted_registries(), method, false)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::UnsupportedStatusMethod,
        ))?;
    let snapshot = context.grant_status_snapshot();
    for status in snapshot.statements().iter().filter(|status| {
        status.statement().grant_id() == grant_id
            && status_issuer_in_scope(snapshot.trust(), status.statement().issuer(), anchor)
    }) {
        let identifier = grant_status_id(status.statement()).map_err(codec_failure)?;
        control_for(controlled, StatementRef::GrantStatus(identifier))?;
        check_status_extensions(status.statement().extensions(), context)?;
    }
    meter.reserve(
        implementation.maximum_work_units(context.grant_status_snapshot().statements().len()),
    )?;
    let decision = implementation
        .grant(
            policy,
            context.grant_status_snapshot(),
            grant_id,
            auths_model::StatusView::Anchor(anchor),
            context.evaluation_time(),
        )
        .map_err(registry_operation_failure)?;
    status_decision(decision.decision(), false)?;
    status_horizon(decision, context.evaluation_time())
}

fn branch_chain<'a>(
    resolved: &'a ResolvedProof,
    action: &SignedAction,
) -> Result<Vec<&'a SignedGrant>, VerificationFailure> {
    let bundle = resolved.decoded.bundle();
    let mut reversed = Vec::new();
    let mut cursor = action.envelope().terminal_grant();
    while let Some(id) = cursor {
        let position = resolved
            .grants
            .binary_search_by_key(&id, |record| record.id)
            .map_err(|_| VerificationFailure::Denied(DenialReason::MissingReference))?;
        let grant = &bundle.grants()[resolved.grants[position].index];
        reversed.push(grant);
        cursor = grant.statement().parent();
    }
    reversed.reverse();
    Ok(reversed)
}

fn action_or_first_method<'a>(
    action: &'a SignedAction,
    chain: &'a [&SignedGrant],
) -> &'a auths_model::PrincipalMethodId {
    chain.first().map_or_else(
        || action.signature().descriptor().principal_method(),
        |grant| grant.signature().descriptor().principal_method(),
    )
}

fn control_for(
    controlled: &ControlVerifiedProof,
    statement: StatementRef,
) -> Result<(&PrincipalId, &ControlEvidence), VerificationFailure> {
    let control = controlled
        .controls
        .iter()
        .find(|control| control.statement == statement)
        .ok_or(VerificationFailure::Indeterminate(
            Requirement::MissingPrincipalEvidence,
        ))?;
    control
        .result
        .as_ref()
        .map(|evidence| (&control.principal, evidence))
        .map_err(|failure| *failure)
}

fn participant_report(
    principal: &PrincipalId,
    evidence: &ControlEvidence,
    role: ParticipantRole,
) -> Result<ParticipantAssurance, VerificationFailure> {
    ParticipantAssurance::new(
        principal.clone(),
        role,
        evidence.claims().to_vec(),
        evidence.consumed_evidence().to_vec(),
        evidence.adapter().clone(),
        evidence.adapter_version(),
    )
    .map_err(|_| VerificationFailure::Denied(DenialReason::ResourceLimitExceeded))
}


pub(super) fn evaluate_branch_assurance<R: RegistryAccess + ?Sized>(
    reports: &[ParticipantAssurance],
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<Vec<AssuranceSatisfaction>, VerificationFailure> {
    validate_assurance_claims(reports, context, registries, meter)?;
    let implications = registries.assurance_implications(context.accepted_registries());
    for implication in &implications {
        meter.reserve(implication.maximum_work_units())?;
    }
    evaluate_with_implications(
        context.assurance_policy(),
        reports,
        context.evaluation_time(),
        |claim, target| {
            implications.iter().any(|implication| {
                implication.source() == claim.kind()
                    && implication.target() == target
                    && implication.implies(claim).unwrap_or(false)
            })
        },
    )
    .map_err(VerificationFailure::Indeterminate)
}

fn validate_assurance_claims<R: RegistryAccess + ?Sized>(
    reports: &[ParticipantAssurance],
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    for claim in reports.iter().flat_map(ParticipantAssurance::claims) {
        let rule = registries
            .assurance_claim(context.accepted_registries(), claim.kind())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedAssuranceClaim,
            ))?;
        meter.reserve(rule.maximum_work_units(claim))?;
        rule.validate(claim).map_err(registry_operation_failure)?;
    }
    Ok(())
}

pub(super) fn evaluate_extensions<R: RegistryAccess + ?Sized>(
    extensions: &auths_model::CriticalExtensions,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    for extension in extensions.as_slice() {
        if !context
            .accepted_registries()
            .accepts_critical_extension(extension.id())
        {
            return Err(VerificationFailure::Denied(
                DenialReason::CriticalExtensionUnknown,
            ));
        }
        let handler = registries
            .extension_handler(context.accepted_registries(), extension.id())
            .ok_or(VerificationFailure::Indeterminate(
                Requirement::UnsupportedCriticalExtension,
            ))?;
        meter.reserve(handler.maximum_work_units(extension))?;
        handler
            .evaluate(extension)
            .map_err(registry_operation_failure)?;
    }
    Ok(())
}
