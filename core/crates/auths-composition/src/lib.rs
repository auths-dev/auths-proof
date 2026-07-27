//! Deterministic bounded authorization-plan evaluation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
pub use auths_algebra_kernel::Truth as ThresholdTruth;
use auths_model::{
    AuthorizationPlan, AuthorizationPlanRef, DenialReason, ProofRef, Requirement, VerifierLimits,
};

/// Result of evaluating one plan branch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BranchOutcome {
    /// The branch established authority.
    Authorized,
    /// Available facts established a permanent failure.
    Denied(DenialReason),
    /// A trustworthy required fact was unavailable.
    Indeterminate(Requirement),
    /// The referenced leaf cannot be interpreted as a branch result.
    StructurallyInvalid(DenialReason),
}

/// One plan node evaluated by the shipping composition engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvaluationEvent {
    /// One proof leaf and its exact branch result.
    Proof {
        reference: ProofRef,
        outcome: BranchOutcome,
    },
    /// One compound node emitted after all immediate children.
    Aggregate {
        child_count: usize,
        required: u16,
        authorized: usize,
        indeterminate: usize,
        outcome: BranchOutcome,
    },
}

impl EvaluationEvent {
    /// Returns the exact outcome of this evaluated node.
    #[must_use]
    pub const fn outcome(self) -> BranchOutcome {
        match self {
            Self::Proof { outcome, .. } | Self::Aggregate { outcome, .. } => outcome,
        }
    }
}

/// Classifies threshold counts without consulting diagnostics.
///
/// The implementation is generated from the shared Rust–Lean algebra contract.
#[must_use]
pub fn evaluate_threshold_counts(
    k: u16,
    authorized: usize,
    indeterminate: usize,
) -> ThresholdTruth {
    auths_algebra_kernel::threshold_counts(k, authorized, indeterminate)
}

/// Evaluates a validated plan in its canonical child order.
///
/// # Errors
///
/// Returns [`DenialReason::AuthorizationPlanInvalid`] when `plan` exceeds the
/// supplied deployment limits.
pub fn evaluate(
    plan: &AuthorizationPlan,
    limits: &VerifierLimits,
    branch: &mut impl FnMut(ProofRef) -> BranchOutcome,
) -> Result<BranchOutcome, DenialReason> {
    evaluate_observed(plan, limits, branch, &mut |_| {})
}

/// Evaluates a validated plan while emitting its exact post-order evaluation
/// DAG events.
///
/// The observer receives every leaf and aggregate exactly once from the same
/// execution that produces the returned result. Aggregate events are emitted
/// after their immediate children, so a bounded consumer can reconstruct the
/// plan tree without reevaluating authorization semantics.
///
/// # Errors
///
/// Returns [`DenialReason::AuthorizationPlanInvalid`] when `plan` exceeds the
/// supplied deployment limits.
pub fn evaluate_observed(
    plan: &AuthorizationPlan,
    limits: &VerifierLimits,
    branch: &mut impl FnMut(ProofRef) -> BranchOutcome,
    observer: &mut impl FnMut(EvaluationEvent),
) -> Result<BranchOutcome, DenialReason> {
    plan.validate(limits)
        .map_err(|_| DenialReason::AuthorizationPlanInvalid)?;
    Ok(evaluate_node(plan, branch, observer))
}

fn evaluate_node(
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn outcome(tag: u8) -> BranchOutcome {
        match tag % 3 {
            0 => BranchOutcome::Authorized,
            1 => BranchOutcome::Denied(DenialReason::PermissionNotGranted),
            _ => BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable),
        }
    }

    proptest! {
        #[test]
        fn threshold_matches_exact_counting(
            tags in proptest::collection::vec(0u8..3, 1..16),
            selector in any::<u16>(),
        ) {
            let k = usize::from(selector) % tags.len() + 1;
            let members = tags
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    AuthorizationPlan::proof(ProofRef::new([
                        u8::try_from(index + 1).expect("bounded test index");
                        32
                    ]))
                })
                .collect();
            let plan = AuthorizationPlan::k_of_n(
                u16::try_from(k).expect("bounded threshold"),
                members,
            )
            .expect("valid threshold");
            let actual = evaluate(
                &plan,
                &VerifierLimits::default(),
                &mut |reference| outcome(tags[usize::from(reference.as_bytes()[0]) - 1]),
            )
            .expect("bounded plan");
            let authorized = tags.iter().filter(|tag| **tag % 3 == 0).count();
            let indeterminate = tags.iter().filter(|tag| **tag % 3 == 2).count();
            let expected = if authorized >= k {
                BranchOutcome::Authorized
            } else if authorized + indeterminate >= k {
                BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable)
            } else {
                BranchOutcome::Denied(DenialReason::PermissionNotGranted)
            };
            prop_assert_eq!(actual, expected);
        }
    }

    #[test]
    fn all_of_and_any_of_preserve_three_way_logic() {
        let first = AuthorizationPlan::proof(ProofRef::new([1; 32]));
        let second = AuthorizationPlan::proof(ProofRef::new([2; 32]));
        let all = AuthorizationPlan::all_of(vec![first.clone(), second.clone()]).unwrap();
        let any = AuthorizationPlan::any_of(vec![first, second]).unwrap();
        let mut branch = |reference: ProofRef| {
            if reference.as_bytes()[0] == 1 {
                BranchOutcome::Indeterminate(Requirement::StaleStatus)
            } else {
                BranchOutcome::Authorized
            }
        };
        assert_eq!(
            evaluate(&all, &VerifierLimits::default(), &mut branch).unwrap(),
            BranchOutcome::Indeterminate(Requirement::StaleStatus)
        );
        assert_eq!(
            evaluate(&any, &VerifierLimits::default(), &mut branch).unwrap(),
            BranchOutcome::Authorized
        );
    }

    #[test]
    fn nested_plans_evaluate_every_leaf_with_canonical_precedence() {
        let first = AuthorizationPlan::proof(ProofRef::new([1; 32]));
        let second = AuthorizationPlan::proof(ProofRef::new([2; 32]));
        let third = AuthorizationPlan::proof(ProofRef::new([3; 32]));
        let left = AuthorizationPlan::any_of(vec![
            AuthorizationPlan::all_of(vec![second.clone(), first.clone()]).unwrap(),
            third.clone(),
        ])
        .unwrap();
        let right = AuthorizationPlan::any_of(vec![
            third,
            AuthorizationPlan::all_of(vec![first, second]).unwrap(),
        ])
        .unwrap();
        assert_eq!(left, right, "plan construction canonicalizes member order");

        let mut visited = Vec::new();
        let actual = evaluate(&left, &VerifierLimits::default(), &mut |reference| {
            visited.push(reference);
            match reference.as_bytes()[0] {
                1 => BranchOutcome::Denied(DenialReason::PermissionNotGranted),
                2 => BranchOutcome::Denied(DenialReason::InvalidSignature),
                _ => BranchOutcome::Indeterminate(Requirement::StaleStatus),
            }
        })
        .unwrap();

        assert_eq!(
            actual,
            BranchOutcome::Indeterminate(Requirement::StaleStatus)
        );
        assert_eq!(visited.len(), 3, "optional branches remain work-observable");
    }

    #[test]
    fn observer_reports_the_exact_post_order_threshold_execution() {
        let plan = AuthorizationPlan::k_of_n(
            2,
            [1_u8, 2, 3]
                .into_iter()
                .map(|tag| AuthorizationPlan::proof(ProofRef::new([tag; 32])))
                .collect(),
        )
        .unwrap();
        let mut events = Vec::new();
        let result = evaluate_observed(
            &plan,
            &VerifierLimits::default(),
            &mut |reference| match reference.as_bytes()[0] {
                1 | 2 => BranchOutcome::Authorized,
                _ => BranchOutcome::Denied(DenialReason::InvalidSignature),
            },
            &mut |event| events.push(event),
        )
        .unwrap();
        assert_eq!(result, BranchOutcome::Authorized);
        assert_eq!(events.len(), 4);
        assert!(
            events[..3]
                .iter()
                .all(|event| matches!(event, EvaluationEvent::Proof { .. }))
        );
        assert_eq!(
            events[3],
            EvaluationEvent::Aggregate {
                child_count: 3,
                required: 2,
                authorized: 2,
                indeterminate: 0,
                outcome: BranchOutcome::Authorized,
            }
        );
    }
}
