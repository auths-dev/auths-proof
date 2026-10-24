//! Frozen pre-cutover authority aggregation; test-only.
use super::*;

/// Evaluates action binding, every authority branch, status, assurance, and
/// the authorization plan.
///
/// # Errors
///
/// Returns a stable denial or indeterminate requirement.
#[allow(clippy::too_many_lines)]
pub(super) fn verify_authority_measured<R: RegistryAccess + ?Sized>(
    controlled: ControlVerifiedProof,
    canonical_action: &CanonicalAction,
    context: &TrustedContext,
    registries: &R,
    meter: &mut WorkMeter,
    diagnostics: &mut AuthorityDiagnostics,
) -> Result<VerifiedAuthority, VerificationFailure> {
    validate_action_binding(&controlled, canonical_action, context, registries, meter)?;
    let context_digest = context_digest(context).map_err(codec_failure)?;
    let mut authorized_branches = Vec::new();
    let mut assurance = Vec::new();
    let mut assurance_satisfactions = Vec::new();
    let mut observation_satisfactions = Vec::new();
    let mut approval_requirements = Vec::new();
    let mut action_ids = Vec::new();
    let mut authority_not_after = Timestamp::new(u64::MAX);
    let bundle = controlled.resolved.decoded.bundle();
    let mut approvals = approval::Approvals::new(bundle)?;
    let approval_inputs = approval::Inputs {
        controlled: &controlled,
        canonical: canonical_action,
        context,
        registries,
    };

    let outcome = evaluate_plan_observed(
        bundle.plan(),
        context.limits(),
        &mut |reference| match verify_branch(
            &controlled,
            reference,
            canonical_action,
            context,
            registries,
            meter,
            &mut approvals,
            &approval_inputs,
        ) {
            Ok(branch) => {
                authority_not_after = authority_not_after.min(branch.authority_not_after);
                authorized_branches.push(reference);
                action_ids.push(branch.action_id);
                assurance.extend(branch.assurance);
                assurance_satisfactions.extend(branch.assurance_satisfactions);
                observation_satisfactions.extend(branch.observation_satisfactions);
                approval_requirements.extend(branch.approval_requirements);
                BranchOutcome::Authorized
            }
            Err(VerificationFailure::Denied(reason)) => BranchOutcome::Denied(reason),
            Err(VerificationFailure::Indeterminate(requirement)) => {
                BranchOutcome::Indeterminate(requirement)
            }
        },
        &mut |event| diagnostics.record_plan_event(event),
    )
    .map_err(VerificationFailure::Denied)?;

    match outcome {
        BranchOutcome::Authorized => {}
        BranchOutcome::Denied(reason) => return Err(VerificationFailure::Denied(reason)),
        BranchOutcome::Indeterminate(requirement) => {
            return Err(VerificationFailure::Indeterminate(requirement));
        }
        BranchOutcome::StructurallyInvalid(reason) => {
            return Err(VerificationFailure::Denied(reason));
        }
    }
    let composition = context.composition();
    let distinct_actors = OrderedSet::from_vec(assurance
        .iter()
        .filter(|report| report.role() == ParticipantRole::Actor)
        .map(ParticipantAssurance::principal)
        .collect());
    let distinct_roots = OrderedSet::from_vec(assurance
        .iter()
        .filter(|report| report.role() == ParticipantRole::Root)
        .map(ParticipantAssurance::principal)
        .collect());
    diagnostics.record_composition_counts(
        authorized_branches.len(),
        distinct_actors.len(),
        distinct_roots.len(),
    );
    if authorized_branches.len() < usize::from(composition.minimum_authorized_branches())
        || distinct_actors.len() < usize::from(composition.minimum_distinct_actors())
        || distinct_roots.len() < usize::from(composition.minimum_distinct_roots())
    {
        return Err(VerificationFailure::Denied(
            DenialReason::CompositionRequirementNotMet,
        ));
    }
    approval_requirements.extend(evaluate_context_approvals(
        &mut approvals,
        &approval_inputs,
        meter,
        diagnostics,
    )?);
    let approval_satisfactions = approvals.satisfactions(&approval_requirements);
    authority_not_after = authority_not_after.min(approvals.valid_through(&approval_requirements));
    assurance.sort_by(|left, right| {
        left.role()
            .cmp(&right.role())
            .then_with(|| left.principal().cmp(right.principal()))
    });
    assurance.dedup();
    action_ids.sort();
    action_ids.dedup();
    authorized_branches.sort();
    authorized_branches.dedup();
    assurance_satisfactions.sort();
    assurance_satisfactions.dedup();
    observation_satisfactions.sort();
    observation_satisfactions.dedup();
    let ControlVerifiedProof { resolved, .. } = controlled;
    Ok(VerifiedAuthority {
        canonical_action: canonical_action.clone(),
        proof_digest: resolved.decoded.proof_digest,
        context_digest,
        plan_id: resolved.plan_id,
        action_ids,
        authorized_branches,
        assurance,
        assurance_satisfactions,
        observation_satisfactions,
        approval_satisfactions,
        authority_not_after,
        work_units: meter.used,
    })
}

/// Evaluates the trusted context's approval requirements once the plan has
/// authorized and the composition floors hold, records each for the trace,
/// and returns their identifiers.
fn evaluate_context_approvals<R: RegistryAccess + ?Sized>(
    approvals: &mut approval::Approvals<'_>,
    inputs: &approval::Inputs<'_, R>,
    meter: &mut WorkMeter,
    diagnostics: &mut AuthorityDiagnostics,
) -> Result<Vec<auths_model::ApprovalRequirementId>, VerificationFailure> {
    let requirements = approval::context_requirements(inputs.context)?;
    let result = approvals.evaluate_list(&requirements, inputs, meter);
    let mut identifiers = Vec::with_capacity(requirements.len());
    let mut position = 0;
    while position < requirements.len() {
        let identifier = requirements[position].0;
        if let Some(evaluated) = approvals.get(identifier) { diagnostics.record_context_approval(evaluated); }
        identifiers.push(identifier);
        position += 1;
    }
    result?;
    Ok(identifiers)
}

