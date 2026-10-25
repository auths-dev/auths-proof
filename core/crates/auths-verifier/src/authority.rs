//! Actual plan-to-authority accumulation and composition enforcement.
//! Refused branches retain their outcome and contribute no authority fields.

use super::*;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct BranchCollection {
    pub(super) authorized_branches: Vec<ProofRef>,
    pub(super) assurance: Vec<ParticipantAssurance>,
    pub(super) assurance_satisfactions: Vec<AssuranceSatisfaction>,
    pub(super) observation_satisfactions: Vec<ObservationSatisfaction>,
    pub(super) approval_requirements: Vec<auths_model::ApprovalRequirementId>,
    pub(super) action_ids: Vec<ActionId>,
    pub(super) authority_not_after: Timestamp,
}
impl BranchCollection {
    fn new() -> Self {
        Self {
            authorized_branches: Vec::new(), assurance: Vec::new(),
            assurance_satisfactions: Vec::new(), observation_satisfactions: Vec::new(),
            approval_requirements: Vec::new(), action_ids: Vec::new(),
            authority_not_after: Timestamp::new(u64::MAX),
        }
    }
}

pub(super) fn record_branch(
    collection: &mut BranchCollection, reference: ProofRef,
    result: Result<BranchAuthority, VerificationFailure>,
) -> BranchOutcome {
    match result {
        Ok(mut branch) => {
            collection.authority_not_after = collection.authority_not_after.min(branch.authority_not_after);
            collection.authorized_branches.push(reference);
            collection.action_ids.push(branch.action_id);
            collection.assurance.append(&mut branch.assurance);
            collection.assurance_satisfactions.append(&mut branch.assurance_satisfactions);
            collection.observation_satisfactions.append(&mut branch.observation_satisfactions);
            collection.approval_requirements.append(&mut branch.approval_requirements);
            BranchOutcome::Authorized
        }
        Err(VerificationFailure::Denied(reason)) => BranchOutcome::Denied(reason),
        Err(VerificationFailure::Indeterminate(requirement)) => BranchOutcome::Indeterminate(requirement),
    }
}

fn distinct_principals(reports: &[ParticipantAssurance], role: ParticipantRole) -> OrderedSet<&PrincipalId> {
    let mut principals = OrderedSet::new();
    let mut position = 0;
    while position < reports.len() {
        if reports[position].role() == role { principals.insert(reports[position].principal()); }
        position += 1;
    }
    principals
}

pub(super) fn check_composition(
    authorized_branches: usize, distinct_actors: usize, distinct_roots: usize,
    minimum_branches: u16, minimum_actors: u16, minimum_roots: u16,
) -> Result<(), VerificationFailure> {
    if authorized_branches < usize::from(minimum_branches)
        || distinct_actors < usize::from(minimum_actors)
        || distinct_roots < usize::from(minimum_roots) {
        Err(VerificationFailure::Denied(DenialReason::CompositionRequirementNotMet))
    } else { Ok(()) }
}

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
    let mut collection = BranchCollection::new();
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
        &mut |reference| {
            let result = verify_branch(
                &controlled, reference, canonical_action, context, registries,
                meter, &mut approvals, &approval_inputs,
            );
            record_branch(&mut collection, reference, result)
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
    let BranchCollection {
        mut authorized_branches, mut assurance, mut assurance_satisfactions,
        mut observation_satisfactions, mut approval_requirements, mut action_ids,
        mut authority_not_after,
    } = collection;
    let composition = context.composition();
    let distinct_actors = distinct_principals(&assurance, ParticipantRole::Actor);
    let distinct_roots = distinct_principals(&assurance, ParticipantRole::Root);
    diagnostics.record_composition_counts(
        authorized_branches.len(),
        distinct_actors.len(),
        distinct_roots.len(),
    );
    check_composition(
        authorized_branches.len(), distinct_actors.len(), distinct_roots.len(),
        composition.minimum_authorized_branches(), composition.minimum_distinct_actors(),
        composition.minimum_distinct_roots(),
    )?;
    let mut context_approval_ids = evaluate_context_approvals(
        &mut approvals,
        &approval_inputs,
        meter,
        diagnostics,
    )?;
    approval_requirements.append(&mut context_approval_ids);
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

