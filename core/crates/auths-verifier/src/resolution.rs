//! Bounded reference resolution for the authoritative staged verifier.
//! Every fallible traversal carries its first error explicitly. The index
//! retains original object positions and never substitutes a digest for the
//! value whose identifier was computed.

use super::*;
use crate::collections::try_fold_items;
use auths_model::{ControlBinding, EvidenceId};

pub(crate) fn resolve_proof(
    decoded: DecodedProof,
    context: &TrustedContext,
) -> Result<ResolvedProof, VerificationFailure> {
    let bundle = decoded.bundle();
    let computed_plan_id = plan_id(bundle.plan()).map_err(|error| codec_failure(error))?;
    require_expected_plan(context, computed_plan_id)?;
    let mut grants = try_fold_items!(bundle.grants(), Vec::new(), records, index, grant =>
        index_grant(records, index, grant))?;
    grants.sort();
    if grant_records_duplicate(&grants) { return Err(duplicate_object()); }
    let (mut actions, _) = try_fold_items!(bundle.actions(), (Vec::new(), OrderedSet::new()), indexed, index, action =>
        index_action(indexed, index, action, computed_plan_id))?;
    actions.sort();
    if action_records_duplicate(&actions) { return Err(duplicate_object()); }
    let shape = bundle.plan().validate(context.limits())
        .map_err(|_| VerificationFailure::Denied(DenialReason::AuthorizationPlanInvalid))?;
    if shape.leaves().len() != bundle.actions().len()
        || missing_plan_reference(shape.leaves(), bundle.actions())
    { return Err(missing_reference()); }
    let evidence = evidence_identifiers(bundle.evidence());
    if evidence.len() != bundle.evidence().len() { return Err(duplicate_object()); }
    let principal_status = principal_status_records(context)?;
    let grant_status = grant_status_records(context)?;
    let index = ObjectIndex { grants: &grants, actions: &actions,
        principal_status: &principal_status, grant_status: &grant_status, evidence: &evidence };
    let _ = try_fold_items!(bundle.bindings(), OrderedSet::new(), statements, _position, binding =>
        check_binding(statements, binding, &index))?;
    let used_grants = try_fold_items!(bundle.actions(), OrderedSet::new(), used, _position, action =>
        resolve_chain(bundle, &grants, action, used))?;
    if used_grants.len() != grants.len() {
        return Err(VerificationFailure::Denied(DenialReason::UnusedCriticalEvidence));
    }
    reject_duplicate_attachments(bundle)?;
    validate_carried_status(bundle, context)?;
    Ok(ResolvedProof { decoded, plan_id: computed_plan_id, grants, actions })
}

fn duplicate_object() -> VerificationFailure { VerificationFailure::Denied(DenialReason::DuplicateObject) }
fn missing_reference() -> VerificationFailure { VerificationFailure::Denied(DenialReason::MissingReference) }

fn require_expected_plan(context: &TrustedContext, actual: PlanId) -> Result<(), VerificationFailure> {
    match context.composition().expected_plan() {
        Some(expected) if expected != actual => Err(VerificationFailure::Denied(DenialReason::CompositionRequirementNotMet)),
        _ => Ok(()),
    }
}

fn index_grant(mut records: Vec<GrantRecord>, index: usize, grant: &SignedGrant)
-> Result<Vec<GrantRecord>, VerificationFailure> {
    records.push(GrantRecord { id: grant_id(grant.statement()).map_err(|error| codec_failure(error))?, index });
    Ok(records)
}

fn index_action(
    (mut records, mut references): (Vec<ActionRecord>, OrderedSet<ProofRef>),
    index: usize, action: &SignedAction, expected_plan: PlanId,
) -> Result<(Vec<ActionRecord>, OrderedSet<ProofRef>), VerificationFailure> {
    if action.envelope().authorization_plan() != expected_plan {
        return Err(VerificationFailure::Denied(DenialReason::PlanActionMismatch));
    }
    if !references.insert(action.envelope().proof_ref()) { return Err(duplicate_object()); }
    records.push(ActionRecord { id: action_id(action.envelope()).map_err(|error| codec_failure(error))?, index });
    Ok((records, references))
}

fn grant_records_duplicate(records: &[GrantRecord]) -> bool {
    let mut position = 1;
    let mut duplicate = false;
    while position < records.len() && !duplicate {
        duplicate = records[position - 1].id == records[position].id;
        position += 1;
    }
    duplicate
}
fn action_records_duplicate(records: &[ActionRecord]) -> bool {
    let mut position = 1;
    let mut duplicate = false;
    while position < records.len() && !duplicate {
        duplicate = records[position - 1].id == records[position].id;
        position += 1;
    }
    duplicate
}
fn sorted_ids_duplicate<T: Eq>(values: &[T]) -> bool {
    let mut position = 1;
    let mut duplicate = false;
    while position < values.len() && !duplicate {
        duplicate = values[position - 1] == values[position];
        position += 1;
    }
    duplicate
}

fn has_action_reference(actions: &[SignedAction], reference: ProofRef) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < actions.len() && !found {
        found = actions[position].envelope().proof_ref() == reference;
        position += 1;
    }
    found
}
fn missing_plan_reference(leaves: &[ProofRef], actions: &[SignedAction]) -> bool {
    let mut position = 0;
    let mut missing = false;
    while position < leaves.len() && !missing {
        missing = !has_action_reference(actions, leaves[position]);
        position += 1;
    }
    missing
}
fn evidence_identifiers(evidence: &[EvidenceObject]) -> OrderedSet<EvidenceId> {
    let mut output = OrderedSet::new();
    let mut position = 0;
    while position < evidence.len() {
        output.insert(evidence[position].id());
        position += 1;
    }
    output
}
fn missing_evidence(identifiers: &[EvidenceId], known: &OrderedSet<EvidenceId>) -> bool {
    let mut position = 0;
    let mut missing = false;
    while position < identifiers.len() && !missing {
        missing = !known.contains(&identifiers[position]);
        position += 1;
    }
    missing
}

struct ObjectIndex<'a> {
    grants: &'a [GrantRecord],
    actions: &'a [ActionRecord],
    principal_status: &'a [PrincipalStatusId],
    grant_status: &'a [GrantStatusId],
    evidence: &'a OrderedSet<EvidenceId>,
}
fn check_binding(mut statements: OrderedSet<StatementRef>, binding: &ControlBinding, index: &ObjectIndex<'_>)
-> Result<OrderedSet<StatementRef>, VerificationFailure> {
    if !statements.insert(binding.statement()) { return Err(duplicate_object()); }
    if !statement_exists(binding.statement(), index) || missing_evidence(binding.evidence(), index.evidence) {
        return Err(missing_reference());
    }
    Ok(statements)
}
fn statement_exists(statement: StatementRef, index: &ObjectIndex<'_>) -> bool {
    match statement {
        StatementRef::Grant(id) => grant_position(index.grants, id).is_some(),
        StatementRef::Action(id) => action_position(index.actions, id).is_some(),
        StatementRef::PrincipalStatus(id) => index.principal_status.binary_search(&id).is_ok(),
        StatementRef::GrantStatus(id) => index.grant_status.binary_search(&id).is_ok(),
    }
}

pub(super) fn grant_position(records: &[GrantRecord], id: GrantId) -> Option<usize> {
    let mut lower = 0;
    let mut upper = records.len();
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if records[middle].id < id { lower = middle + 1; } else { upper = middle; }
    }
    if lower < records.len() && records[lower].id == id { Some(lower) } else { None }
}
fn action_position(records: &[ActionRecord], id: ActionId) -> Option<usize> {
    let mut lower = 0;
    let mut upper = records.len();
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        if records[middle].id < id { lower = middle + 1; } else { upper = middle; }
    }
    if lower < records.len() && records[lower].id == id { Some(lower) } else { None }
}

fn principal_status_records(context: &TrustedContext) -> Result<Vec<PrincipalStatusId>, VerificationFailure> {
    let mut values = try_fold_items!(context.principal_status_snapshot().statements(), Vec::new(), accumulated, _position, status =>
        index_principal_status(accumulated, status))?;
    values.sort();
    if sorted_ids_duplicate(&values) { return Err(duplicate_object()); }
    Ok(values)
}
fn index_principal_status(mut values: Vec<PrincipalStatusId>, status: &SignedPrincipalStatus)
-> Result<Vec<PrincipalStatusId>, VerificationFailure> {
    values.push(principal_status_id(status.statement()).map_err(|error| codec_failure(error))?);
    Ok(values)
}
fn grant_status_records(context: &TrustedContext) -> Result<Vec<GrantStatusId>, VerificationFailure> {
    let mut values = try_fold_items!(context.grant_status_snapshot().statements(), Vec::new(), accumulated, _position, status =>
        index_grant_status(accumulated, status))?;
    values.sort();
    if sorted_ids_duplicate(&values) { return Err(duplicate_object()); }
    Ok(values)
}
fn index_grant_status(mut values: Vec<GrantStatusId>, status: &SignedGrantStatus)
-> Result<Vec<GrantStatusId>, VerificationFailure> {
    values.push(grant_status_id(status.statement()).map_err(|error| codec_failure(error))?);
    Ok(values)
}

struct ChainState {
    cursor: Option<GrantId>,
    branch: OrderedSet<GrantId>,
    used: OrderedSet<GrantId>,
}
fn chain_step(mut state: ChainState, bundle: &ProofBundle, grants: &[GrantRecord])
-> Result<ChainState, VerificationFailure> {
    if let Some(id) = state.cursor {
        if !state.branch.insert(id) {
            return Err(VerificationFailure::Denied(DenialReason::ReferenceCycle));
        }
        let position = grant_position(grants, id).ok_or(missing_reference())?;
        let grant = &bundle.grants()[grants[position].index];
        state.cursor = grant.statement().parent();
        state.used.insert(id);
    }
    Ok(state)
}
fn resolve_chain(bundle: &ProofBundle, grants: &[GrantRecord], action: &SignedAction, used: OrderedSet<GrantId>)
-> Result<OrderedSet<GrantId>, VerificationFailure> {
    let mut outcome = Ok(ChainState { cursor: action.envelope().terminal_grant(), branch: OrderedSet::new(), used });
    while matches!(&outcome, Ok(state) if state.cursor.is_some()) {
        outcome = match outcome {
            Ok(state) => chain_step(state, bundle, grants),
            Err(error) => Err(error),
        };
    }
    outcome.map(|state| state.used)
}

fn reject_duplicate_attachments(bundle: &ProofBundle) -> Result<(), VerificationFailure> {
    let mut position = 1;
    let mut duplicate = false;
    while position < bundle.attachments().len() && !duplicate {
        duplicate = bundle.attachments()[position - 1].digest() == bundle.attachments()[position].digest();
        position += 1;
    }
    if duplicate { Err(VerificationFailure::Denied(DenialReason::DuplicateAttachment)) } else { Ok(()) }
}

// Every rollback check precedes every holding check. The issuer and method
// belong to the sequence namespace; another issuer's larger sequence is not
// evidence that the carried statement has rolled back.
fn principal_rolled_back(carried: &SignedPrincipalStatus, snapshot: &[SignedPrincipalStatus]) -> bool {
    let statement = carried.statement();
    let mut position = 0;
    let mut rolled_back = false;
    while position < snapshot.len() && !rolled_back {
        let current = snapshot[position].statement();
        rolled_back = current.principal() == statement.principal() && current.method() == statement.method()
            && current.issuer() == statement.issuer() && current.sequence() > statement.sequence();
        position += 1;
    }
    rolled_back
}
fn grant_rolled_back(carried: &SignedGrantStatus, snapshot: &[SignedGrantStatus]) -> bool {
    let statement = carried.statement();
    let mut position = 0;
    let mut rolled_back = false;
    while position < snapshot.len() && !rolled_back {
        let current = snapshot[position].statement();
        rolled_back = current.grant_id() == statement.grant_id() && current.method() == statement.method()
            && current.issuer() == statement.issuer() && current.sequence() > statement.sequence();
        position += 1;
    }
    rolled_back
}
fn any_principal_rollback(carried: &[SignedPrincipalStatus], snapshot: &[SignedPrincipalStatus]) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < carried.len() && !found { found = principal_rolled_back(&carried[position], snapshot); position += 1; }
    found
}
fn any_grant_rollback(carried: &[SignedGrantStatus], snapshot: &[SignedGrantStatus]) -> bool {
    let mut position = 0;
    let mut found = false;
    while position < carried.len() && !found { found = grant_rolled_back(&carried[position], snapshot); position += 1; }
    found
}
fn principal_not_held(carried: &[SignedPrincipalStatus], snapshot: &[SignedPrincipalStatus]) -> bool {
    let mut position = 0;
    let mut missing = false;
    while position < carried.len() && !missing { missing = !snapshot.contains(&carried[position]); position += 1; }
    missing
}
fn grant_not_held(carried: &[SignedGrantStatus], snapshot: &[SignedGrantStatus]) -> bool {
    let mut position = 0;
    let mut missing = false;
    while position < carried.len() && !missing { missing = !snapshot.contains(&carried[position]); position += 1; }
    missing
}
fn validate_carried_status(bundle: &ProofBundle, context: &TrustedContext) -> Result<(), VerificationFailure> {
    let principal = context.principal_status_snapshot().statements();
    let grant = context.grant_status_snapshot().statements();
    if any_principal_rollback(bundle.principal_status(), principal) || any_grant_rollback(bundle.grant_status(), grant) {
        return Err(VerificationFailure::Denied(DenialReason::StatusSequenceRollback));
    }
    if principal_not_held(bundle.principal_status(), principal) || grant_not_held(bundle.grant_status(), grant) {
        Err(VerificationFailure::Denied(DenialReason::DigestMismatch))
    } else { Ok(()) }
}
