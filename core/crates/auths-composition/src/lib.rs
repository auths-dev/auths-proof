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
    plan.validate(limits)
        .map_err(|_| DenialReason::AuthorizationPlanInvalid)?;
    Ok(evaluate_node(plan, branch))
}

fn evaluate_node(
    plan: &AuthorizationPlan,
    branch: &mut impl FnMut(ProofRef) -> BranchOutcome,
) -> BranchOutcome {
    match plan.as_ref() {
        AuthorizationPlanRef::Proof(reference) => branch(reference),
        AuthorizationPlanRef::AllOf(members) => {
            let mut denied = Vec::new();
            let mut indeterminate = Vec::new();
            for member in members {
                match evaluate_node(member, branch) {
                    BranchOutcome::Authorized => {}
                    BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
                        denied.push(reason);
                    }
                    BranchOutcome::Indeterminate(requirement) => indeterminate.push(requirement),
                }
            }
            canonical_denial(&denied).map_or_else(
                || {
                    canonical_requirement(&indeterminate)
                        .map_or(BranchOutcome::Authorized, BranchOutcome::Indeterminate)
                },
                BranchOutcome::Denied,
            )
        }
        AuthorizationPlanRef::AnyOf(members) => {
            let mut authorized = false;
            let mut denied = Vec::new();
            let mut indeterminate = Vec::new();
            for member in members {
                match evaluate_node(member, branch) {
                    BranchOutcome::Authorized => authorized = true,
                    BranchOutcome::Denied(reason) | BranchOutcome::StructurallyInvalid(reason) => {
                        denied.push(reason);
                    }
                    BranchOutcome::Indeterminate(requirement) => indeterminate.push(requirement),
                }
            }
            if authorized {
                BranchOutcome::Authorized
            } else if let Some(requirement) = canonical_requirement(&indeterminate) {
                BranchOutcome::Indeterminate(requirement)
            } else {
                BranchOutcome::Denied(
                    canonical_denial(&denied).unwrap_or(DenialReason::AuthorizationPlanInvalid),
                )
            }
        }
        AuthorizationPlanRef::KOfN { k, members } => {
            let mut authorized = 0usize;
            let mut indeterminate = 0usize;
            let mut denied = Vec::new();
            let mut requirements = Vec::new();
            for member in members {
                match evaluate_node(member, branch) {
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
            match evaluate_threshold_counts(k, authorized, indeterminate) {
                ThresholdTruth::Authorized => BranchOutcome::Authorized,
                ThresholdTruth::Indeterminate => BranchOutcome::Indeterminate(
                    canonical_requirement(&requirements)
                        .unwrap_or(Requirement::ExternalFactUnavailable),
                ),
                ThresholdTruth::Denied => BranchOutcome::Denied(
                    canonical_denial(&denied).unwrap_or(DenialReason::AuthorizationPlanInvalid),
                ),
            }
        }
    }
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
}
