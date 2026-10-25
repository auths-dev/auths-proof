//! Previous production evaluator, retained only as a refactor oracle.
use super::*;

pub(super) fn evaluate_node(
    plan: &AuthorizationPlan,
    branch: &mut impl FnMut(ProofRef) -> BranchOutcome,
    observer: &mut impl FnMut(EvaluationEvent),
) -> BranchOutcome {
    match plan.as_ref() {
        AuthorizationPlanRef::Proof(reference) => {
            let outcome = branch(reference);
            observer(EvaluationEvent::Proof { reference, outcome });
            outcome
        }
        AuthorizationPlanRef::AllOf(members) => {
            let child_count = members.len();
            let mut authorized = 0usize;
            let mut denied = Vec::new();
            let mut indeterminate = Vec::new();
            for member in members {
                match evaluate_node(member, branch, observer) {
                    BranchOutcome::Authorized => authorized += 1,
                    BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
                        denied.push(reason);
                    }
                    BranchOutcome::Indeterminate(requirement) => indeterminate.push(requirement),
                }
            }
            let outcome = canonical_denial(&denied).map_or_else(
                || {
                    canonical_requirement(&indeterminate)
                        .map_or(BranchOutcome::Authorized, BranchOutcome::Indeterminate)
                },
                BranchOutcome::Denied,
            );
            observe_aggregate(
                observer,
                child_count,
                u16::try_from(child_count).unwrap_or(u16::MAX),
                authorized,
                indeterminate.len(),
                outcome,
            )
        }
        AuthorizationPlanRef::AnyOf(members) => {
            let child_count = members.len();
            let mut authorized = 0usize;
            let mut denied = Vec::new();
            let mut indeterminate = Vec::new();
            for member in members {
                match evaluate_node(member, branch, observer) {
                    BranchOutcome::Authorized => authorized += 1,
                    BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
                        denied.push(reason);
                    }
                    BranchOutcome::Indeterminate(requirement) => indeterminate.push(requirement),
                }
            }
            let outcome = if authorized > 0 {
                BranchOutcome::Authorized
            } else if let Some(requirement) = canonical_requirement(&indeterminate) {
                BranchOutcome::Indeterminate(requirement)
            } else {
                BranchOutcome::Denied(
                    canonical_denial(&denied).unwrap_or(DenialReason::AuthorizationPlanInvalid),
                )
            };
            observe_aggregate(
                observer,
                child_count,
                1,
                authorized,
                indeterminate.len(),
                outcome,
            )
        }
        AuthorizationPlanRef::KOfN { k, members } => {
            let child_count = members.len();
            let mut authorized = 0usize;
            let mut indeterminate = 0usize;
            let mut denied = Vec::new();
            let mut requirements = Vec::new();
            for member in members {
                match evaluate_node(member, branch, observer) {
                    BranchOutcome::Authorized => authorized += 1,
                    BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
                        denied.push(reason);
                    }
                    BranchOutcome::Indeterminate(requirement) => {
                        indeterminate += 1;
                        requirements.push(requirement);
                    }
                }
            }
            let outcome = match evaluate_threshold_counts(k, authorized, indeterminate) {
                ThresholdTruth::Authorized => BranchOutcome::Authorized,
                ThresholdTruth::Indeterminate => BranchOutcome::Indeterminate(
                    canonical_requirement(&requirements)
                        .unwrap_or(Requirement::ExternalFactUnavailable),
                ),
                ThresholdTruth::Denied => BranchOutcome::Denied(
                    canonical_denial(&denied).unwrap_or(DenialReason::AuthorizationPlanInvalid),
                ),
            };
            observe_aggregate(observer, child_count, k, authorized, indeterminate, outcome)
        }
    }
}

fn observe_aggregate(
    observer: &mut impl FnMut(EvaluationEvent),
    child_count: usize,
    required: u16,
    authorized: usize,
    indeterminate: usize,
    outcome: BranchOutcome,
) -> BranchOutcome {
    observer(EvaluationEvent::Aggregate {
        child_count,
        required,
        authorized,
        indeterminate,
        outcome,
    });
    outcome
}

fn canonical_denial(reasons: &[DenialReason]) -> Option<DenialReason> {
    reasons.iter().copied().min_by_key(|reason| reason.code())
}

fn canonical_requirement(requirements: &[Requirement]) -> Option<Requirement> {
    requirements
        .iter()
        .copied()
        .min_by_key(|requirement| requirement.code())
}
