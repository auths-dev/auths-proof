//! Authoritative per-branch evaluation with concrete registry types.
use super::*;
use crate::collections::try_fold_items;

/// Anchor-independent inputs for one actual branch attempt.
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
    controlled: &ControlVerifiedProof, proof_ref: ProofRef, canonical: &CanonicalAction,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
    approvals: &mut approval::Approvals<'_>, approval_inputs: &approval::Inputs<'_, R>,
) -> Result<BranchAuthority, VerificationFailure> {
    let bundle = controlled.resolved.decoded.bundle();
    let action = action_for(bundle.actions(), proof_ref)
        .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
    let action_id = action_id(action.envelope()).map_err(|error| codec_failure(error))?;
    let chain = branch_chain(&controlled.resolved, action)?;
    let (root_principal, root_statement) = match chain.first() {
        Some(grant) => (grant.statement().issuer(), StatementRef::Grant(
            grant_id(grant.statement()).map_err(|error| codec_failure(error))?)),
        None => (action.envelope().actor(), StatementRef::Action(action_id)),
    };
    let root_control = control_for(controlled, root_statement)?;
    let branch = BranchInput { controlled, action, action_id, chain: &chain, root_control,
        canonical, context, registries };
    let mut search = AnchorSearch::Looking(None);
    let mut position = 0;
    while position < context.trust_anchors().len() && matches!(&search, AnchorSearch::Looking(_)) {
        search = try_anchor(search, &branch, root_principal, &context.trust_anchors()[position],
            meter, approvals, approval_inputs);
        position += 1;
    }
    match search {
        AnchorSearch::Found(authority) => Ok(authority),
        AnchorSearch::Looking(first) => Err(first.unwrap_or(VerificationFailure::Denied(DenialReason::UntrustedRoot))),
    }
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
    // Every subject is checked under the anchor policy; a grant's status
    // policy governs that grant alone. Only this successful attempt's horizon
    // is returned, so failed anchors do not shorten another anchor's witness.
    authority_not_after = try_fold_items!(chain, authority_not_after, horizon, _position, grant =>
        check_chain_status(horizon, grant, branch, anchor, meter))?;
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
    let mut reports = delegate_chain(branch, anchor, reports, meter)?;
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
        approval_requirements: requirement_identifiers(&approval_requirements),
    })
}

/// Walks the grant chain root to terminal, applying every delegation edge,
/// and then checks the action against the terminal authority.
fn delegate_chain<R: RegistryAccess + ?Sized>(
    branch: &BranchInput<'_, R>, anchor: &TrustAnchor, reports: Vec<ParticipantAssurance>, meter: &mut WorkMeter,
) -> Result<Vec<ParticipantAssurance>, VerificationFailure> {
    let initial = DelegationState { authority: EffectiveAuthority::from_anchor(anchor), reports };
    let laws = branch.registries.extension_laws(branch.context.accepted_registries());
    let state = try_fold_items!(branch.chain, initial, state, index, grant =>
        delegate_grant(state, index, grant, branch, &laws, meter))?;
    state.authority.authorizes(branch.action.envelope(), branch.context.accepted_registries())
        .map_err(|reason| VerificationFailure::Denied(reason))?;
    Ok(state.reports)
}

fn validate_resource_constraints<R: RegistryAccess + ?Sized>(
    anchor: &TrustAnchor, chain: &[&SignedGrant], action: &SignedAction,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let matcher = registries.resource_matcher(context.accepted_registries(), context.resource_matcher())
        .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedResourceMatcher))?;
    let _ = try_fold_items!(chain, (), _checked, _position, grant =>
        check_grant_resources(grant, anchor.resource_namespaces(), matcher, meter))?;
    check_resource(action.envelope().permission().resource(), anchor.resource_namespaces(), matcher, meter)
}

fn validate_budget_constraints<R: RegistryAccess + ?Sized>(
    anchor: &TrustAnchor, chain: &[&SignedGrant], action: &SignedAction,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let terminal = try_fold_items!(chain, anchor.budget_ceiling(), parent, _position, grant =>
        advance_budget(parent, *grant, context, registries, meter))?;
    check_terminal_budget(terminal, action, context, registries, meter)
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
    let _ = try_fold_items!(snapshot.statements(), (), _checked, _position, status =>
        check_principal_attestation(status, controlled, principal, anchor, context))?;
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
        .map_err(|error| registry_operation_failure(error))?;
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
    let _ = try_fold_items!(snapshot.statements(), (), _checked, _position, status =>
        check_grant_attestation(status, controlled, grant_id, anchor, context))?;
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
        .map_err(|error| registry_operation_failure(error))?;
    status_decision(decision.decision(), false)?;
    status_horizon(decision, context.evaluation_time())
}

pub(super) fn branch_chain<'a>(resolved: &'a ResolvedProof, action: &SignedAction)
-> Result<Vec<&'a SignedGrant>, VerificationFailure> {
    let initial = ChainRead { cursor: action.envelope().terminal_grant(), visited: OrderedSet::new(), reversed: Vec::new() };
    let mut outcome = Ok(initial);
    while matches!(&outcome, Ok(state) if state.cursor.is_some()) {
        outcome = match outcome { Ok(state) => read_chain_step(state, resolved), Err(error) => Err(error) };
    }
    let mut state = outcome?;
    state.reversed.reverse();
    Ok(state.reversed)
}

fn action_or_first_method<'a>(action: &'a SignedAction, chain: &'a [&SignedGrant])
-> &'a auths_model::PrincipalMethodId {
    match chain.first() {
        Some(grant) => grant.signature().descriptor().principal_method(),
        None => action.signature().descriptor().principal_method(),
    }
}

pub(super) fn control_for(controlled: &ControlVerifiedProof, statement: StatementRef)
-> Result<(&PrincipalId, &ControlEvidence), VerificationFailure> {
    let mut position = 0;
    while position < controlled.controls.len() {
        let control = &controlled.controls[position];
        if control.statement == statement {
            return match &control.result {
                Ok(evidence) => Ok((&control.principal, evidence)),
                Err(failure) => Err(*failure),
            };
        }
        position += 1;
    }
    Err(VerificationFailure::Indeterminate(Requirement::MissingPrincipalEvidence))
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

enum AnchorSearch {
    Looking(Option<VerificationFailure>),
    Found(BranchAuthority),
}
fn action_for(actions: &[SignedAction], reference: ProofRef) -> Option<&SignedAction> {
    let mut position = 0;
    while position < actions.len() {
        if actions[position].envelope().proof_ref() == reference { return Some(&actions[position]); }
        position += 1;
    }
    None
}
fn try_anchor<R: RegistryAccess + ?Sized>(
    search: AnchorSearch, branch: &BranchInput<'_, R>, root: &PrincipalId, anchor: &TrustAnchor,
    meter: &mut WorkMeter, approvals: &mut approval::Approvals<'_>, inputs: &approval::Inputs<'_, R>,
) -> AnchorSearch {
    match search {
        AnchorSearch::Found(authority) => AnchorSearch::Found(authority),
        AnchorSearch::Looking(first) => {
            if anchor.principal() != root { return AnchorSearch::Looking(first); }
            match verify_branch_from_anchor(branch, anchor, meter, approvals, inputs) {
                Ok(authority) => AnchorSearch::Found(authority),
                Err(failure) => AnchorSearch::Looking(match first { Some(previous) => Some(previous), None => Some(failure) }),
            }
        }
    }
}
fn requirement_identifiers(requirements: &[(auths_model::ApprovalRequirementId, auths_model::ApprovalRequirement)])
-> Vec<auths_model::ApprovalRequirementId> {
    let mut output = Vec::with_capacity(requirements.len());
    let mut position = 0;
    while position < requirements.len() { output.push(requirements[position].0); position += 1; }
    output
}
fn check_chain_status<R: RegistryAccess + ?Sized>(
    mut horizon: Timestamp, grant: &SignedGrant, branch: &BranchInput<'_, R>, anchor: &TrustAnchor, meter: &mut WorkMeter,
) -> Result<Timestamp, VerificationFailure> {
    let id = grant_id(grant.statement()).map_err(|error| codec_failure(error))?;
    horizon = horizon.min(grant.statement().validity().expires_at());
    horizon = horizon.min(check_grant_status(branch.controlled, grant.statement().status_policy(), id,
        anchor, branch.context, branch.registries, meter)?);
    horizon = horizon.min(check_principal_status(branch.controlled, anchor.status_policy(), grant.statement().subject(),
        StatusListing::RevocationList, anchor, branch.context, branch.registries, meter)?);
    Ok(horizon)
}

struct DelegationState {
    authority: EffectiveAuthority,
    reports: Vec<ParticipantAssurance>,
}
fn delegate_grant<R: RegistryAccess + ?Sized>(
    mut state: DelegationState, index: usize, grant: &SignedGrant, branch: &BranchInput<'_, R>,
    laws: &auths_registries::AcceptedExtensionLaws<'_, R>, meter: &mut WorkMeter,
) -> Result<DelegationState, VerificationFailure> {
    if index > 0 {
        let parent = branch.chain.get(index - 1)
            .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
        observation::require_parent_requirements(parent, grant)?;
        meter.reserve(laws.maximum_work_units(grant.statement().extensions(), parent.statement().extensions()))?;
    }
    let id = grant_id(grant.statement()).map_err(|error| codec_failure(error))?;
    state.authority.delegate(id, grant.statement(), laws).map_err(|reason| VerificationFailure::Denied(reason))?;
    let control = control_for(branch.controlled, StatementRef::Grant(id))?;
    state.reports.push(participant_report(control.0, control.1, grant_issuer_role(index))?);
    evaluate_extensions(grant.statement().extensions(), branch.context, branch.registries, meter)?;
    Ok(state)
}

fn check_namespace<M: auths_ports::ResourceMatcher + ?Sized>(
    allowed: bool, namespace: &auths_model::ResourceId, resource: &auths_model::ResourceId,
    matcher: &M, meter: &mut WorkMeter,
) -> Result<bool, VerificationFailure> {
    meter.reserve(matcher.maximum_work_units(namespace, resource))?;
    let matched = matcher.matches(namespace, resource).map_err(|error| registry_operation_failure(error))?;
    // All namespace checks run, even after a match: a later error/reservation
    // still decides in the original verifier and must not be short-circuited.
    Ok(allowed | matched)
}
fn check_resource<M: auths_ports::ResourceMatcher + ?Sized>(
    resource: &auths_model::ResourceId, namespaces: &[auths_model::ResourceId], matcher: &M, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    let allowed = try_fold_items!(namespaces, false, allowed, _position, namespace =>
        check_namespace(allowed, namespace, resource, matcher, meter))?;
    if allowed { Ok(()) } else { Err(VerificationFailure::Denied(DenialReason::ResourceNamespaceMismatch)) }
}
fn check_grant_resources<M: auths_ports::ResourceMatcher + ?Sized>(
    grant: &SignedGrant, namespaces: &[auths_model::ResourceId], matcher: &M, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    try_fold_items!(grant.statement().permissions().as_slice(), (), _checked, _position, permission =>
        check_resource(permission.resource(), namespaces, matcher, meter))
}
fn advance_budget<'a, R: RegistryAccess + ?Sized>(
    parent: Option<&'a auths_model::BudgetCeiling>, grant: &'a SignedGrant,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<Option<&'a auths_model::BudgetCeiling>, VerificationFailure> {
    let child = grant.statement().budget_ceiling();
    if let Some(parent_budget) = parent {
        let child_budget = child.ok_or(VerificationFailure::Denied(DenialReason::DelegationExpanded))?;
        let algebra = registries.budget_algebra(context.accepted_registries(), parent_budget.algebra())
            .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedBudgetAlgebra))?;
        meter.reserve(algebra.maximum_work_units())?;
        if !algebra.attenuates(child_budget, parent_budget).map_err(|error| registry_operation_failure(error))? {
            return Err(VerificationFailure::Denied(DenialReason::DelegationExpanded));
        }
    }
    Ok(child)
}
fn check_terminal_budget<R: RegistryAccess + ?Sized>(
    ceiling: Option<&auths_model::BudgetCeiling>, action: &SignedAction,
    context: &TrustedContext, registries: &R, meter: &mut WorkMeter,
) -> Result<(), VerificationFailure> {
    if let Some(ceiling) = ceiling {
        let expression = context.accepted_registries().profile_budget_expression(action.envelope().profile());
        let Some(requested) = action.envelope().requested_budget() else {
            return match expression {
                ProfileBudgetExpression::Inexpressible => Ok(()),
                ProfileBudgetExpression::Expressible => Err(VerificationFailure::Denied(DenialReason::BudgetCeilingExceeded)),
            };
        };
        let algebra = registries.budget_algebra(context.accepted_registries(), ceiling.algebra())
            .ok_or(VerificationFailure::Indeterminate(Requirement::UnsupportedBudgetAlgebra))?;
        meter.reserve(algebra.maximum_work_units())?;
        if !algebra.covers(ceiling, requested).map_err(|error| registry_operation_failure(error))? {
            return Err(VerificationFailure::Denied(DenialReason::BudgetCeilingExceeded));
        }
    }
    Ok(())
}

fn check_principal_attestation(
    status: &SignedPrincipalStatus, controlled: &ControlVerifiedProof, principal: &PrincipalId,
    anchor: &TrustAnchor, context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    if status.statement().principal() != principal
        || !status_issuer_in_scope(context.principal_status_snapshot().trust(), status.statement().issuer(), anchor)
    { return Ok(()); }
    let id = principal_status_id(status.statement()).map_err(|error| codec_failure(error))?;
    control_for(controlled, StatementRef::PrincipalStatus(id))?;
    check_status_extensions(status.statement().extensions(), context)
}
fn check_grant_attestation(
    status: &SignedGrantStatus, controlled: &ControlVerifiedProof, grant: GrantId,
    anchor: &TrustAnchor, context: &TrustedContext,
) -> Result<(), VerificationFailure> {
    if status.statement().grant_id() != grant
        || !status_issuer_in_scope(context.grant_status_snapshot().trust(), status.statement().issuer(), anchor)
    { return Ok(()); }
    let id = grant_status_id(status.statement()).map_err(|error| codec_failure(error))?;
    control_for(controlled, StatementRef::GrantStatus(id))?;
    check_status_extensions(status.statement().extensions(), context)
}

struct ChainRead<'a> {
    cursor: Option<GrantId>,
    visited: OrderedSet<GrantId>,
    reversed: Vec<&'a SignedGrant>,
}
fn read_chain_step<'a>(mut state: ChainRead<'a>, resolved: &'a ResolvedProof)
-> Result<ChainRead<'a>, VerificationFailure> {
    if let Some(id) = state.cursor {
        if !state.visited.insert(id) { return Err(VerificationFailure::Denied(DenialReason::ReferenceCycle)); }
        let position = crate::resolution::grant_position(&resolved.grants, id)
            .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
        let grant = resolved.decoded.bundle().grants().get(resolved.grants[position].index)
            .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))?;
        state.reversed.push(grant);
        state.cursor = grant.statement().parent();
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::Cell;
    use auths_model::{AdapterConfigurationId, ResourceId, ResourceMatcherId};
    use auths_ports::ResourceMatcher;

    struct LaterFailure { id: ResourceMatcherId, calls: Cell<usize> }
    impl ResourceMatcher for LaterFailure {
        fn id(&self) -> &ResourceMatcherId { &self.id }
        fn configuration_id(&self) -> AdapterConfigurationId { AdapterConfigurationId::new([0x53; 32]) }
        fn maximum_work_units(&self, _: &ResourceId, _: &ResourceId) -> u64 { 1 }
        fn matches(&self, namespace: &ResourceId, _: &ResourceId) -> Result<bool, RegistryOperationError> {
            self.calls.set(self.calls.get() + 1);
            if namespace.as_str() == "scope://allowed" { Ok(true) } else { Err(RegistryOperationError::InvalidInput) }
        }
    }
    #[test]
    fn an_early_namespace_match_does_not_skip_later_refusal_or_reservation() {
        let matcher = LaterFailure { id: ResourceMatcherId::parse("test-matcher").unwrap(), calls: Cell::new(0) };
        let namespaces = vec![ResourceId::parse("scope://allowed").unwrap(), ResourceId::parse("scope://invalid").unwrap()];
        let resource = ResourceId::parse("scope://allowed/item").unwrap();
        let mut meter = WorkMeter::new(2);
        assert_eq!(check_resource(&resource, &namespaces, &matcher, &mut meter),
            Err(VerificationFailure::Denied(DenialReason::LocalPolicyDenied)));
        assert_eq!(matcher.calls.get(), 2);
        assert_eq!(meter.used, 2);
        matcher.calls.set(0);
        let mut meter = WorkMeter::new(1);
        assert_eq!(check_resource(&resource, &namespaces, &matcher, &mut meter),
            Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)));
        assert_eq!(matcher.calls.get(), 1);
        assert_eq!(meter.used, 1);
    }

    #[test]
    fn private_chain_reads_refuse_forged_cycles_and_invalid_indices() {
        let fixture = auths_testkit::corpus().into_iter().find(|case| case.name() == "approval-grant-child-keeps").unwrap();
        let context = decode_verifier_context(fixture.context_bytes()).unwrap();
        let decoded = decode_proof(fixture.proof_bytes(), &context).unwrap();
        let resolved = resolve_proof(decoded, &context).unwrap();
        let action = resolved.decoded.bundle().actions()[0].clone();
        let (child_index, parent) = resolved.decoded.bundle().grants().iter().enumerate()
            .find_map(|(index, grant)| grant.statement().parent().map(|parent| (index, parent))).unwrap();
        let mut cyclic = resolved.clone();
        let parent_record = cyclic.grants.iter_mut().find(|record| record.id == parent).unwrap();
        parent_record.index = child_index;
        assert_eq!(branch_chain(&cyclic, &action), Err(VerificationFailure::Denied(DenialReason::ReferenceCycle)));
        let mut invalid = resolved;
        let terminal = action.envelope().terminal_grant().unwrap();
        invalid.grants.iter_mut().find(|record| record.id == terminal).unwrap().index = usize::MAX;
        assert_eq!(branch_chain(&invalid, &action), Err(VerificationFailure::Denied(DenialReason::MissingReference)));
    }
}
