//! Deterministic bounded authorization-plan evaluation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

#[cfg(test)]
use alloc::vec::Vec;

#[cfg(test)]
mod oracle;
mod summary;
pub use auths_algebra_kernel::Truth as ThresholdTruth;
use auths_model::{
    AuthorizationPlan, AuthorizationPlanRef, DenialReason, ProofRef, Requirement, VerifierLimits,
};
use summary::Summary;

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

fn evaluate_members(
    members: &[AuthorizationPlan],
    branch: &mut impl FnMut(ProofRef) -> BranchOutcome,
    observer: &mut impl FnMut(EvaluationEvent),
) -> Summary {
    let mut state = Summary::default();
    let mut index = 0;
    while index < members.len() {
        summary::push(&mut state, evaluate_node(&members[index], branch, observer));
        index += 1;
    }
    state
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
            let state = evaluate_members(members, branch, observer);
            observe_aggregate(
                observer,
                members.len(),
                u16::try_from(members.len()).unwrap_or(u16::MAX),
                state.authorized,
                state.indeterminate,
                summary::all(state),
            )
        }
        AuthorizationPlanRef::AnyOf(members) => {
            let state = evaluate_members(members, branch, observer);
            observe_aggregate(
                observer,
                members.len(),
                1,
                state.authorized,
                state.indeterminate,
                summary::threshold(state, 1),
            )
        }
        AuthorizationPlanRef::KOfN { k, members } => {
            let state = evaluate_members(members, branch, observer);
            observe_aggregate(
                observer,
                members.len(),
                k,
                state.authorized,
                state.indeterminate,
                summary::threshold(state, k),
            )
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

    #[test]
    fn formal_summary_witnesses_match_shipping_operations() {
        use BranchOutcome::{
            Authorized as A, Denied as D, Indeterminate as I, StructurallyInvalid as S,
        };
        let cases = [
            (true, 2, vec![A, A], A),
            (
                true,
                2,
                vec![
                    I(Requirement::StaleStatus),
                    D(DenialReason::InvalidSignature),
                ],
                D(DenialReason::InvalidSignature),
            ),
            (
                true,
                3,
                vec![
                    D(DenialReason::InvalidSignature),
                    S(DenialReason::ActionBodyMismatch),
                    D(DenialReason::MissingReference),
                ],
                D(DenialReason::ActionBodyMismatch),
            ),
            (false, 1, vec![S(DenialReason::MissingReference), A], A),
            (
                false,
                1,
                vec![
                    D(DenialReason::InvalidSignature),
                    I(Requirement::StaleStatus),
                ],
                I(Requirement::StaleStatus),
            ),
            (
                false,
                1,
                vec![
                    I(Requirement::StaleStatus),
                    I(Requirement::ApprovalUnavailable),
                ],
                I(Requirement::ApprovalUnavailable),
            ),
            (
                false,
                1,
                vec![
                    A,
                    I(Requirement::StaleStatus),
                    D(DenialReason::InvalidSignature),
                ],
                A,
            ),
            (
                false,
                2,
                vec![
                    A,
                    I(Requirement::StaleStatus),
                    D(DenialReason::InvalidSignature),
                ],
                I(Requirement::StaleStatus),
            ),
            (
                false,
                3,
                vec![
                    A,
                    I(Requirement::StaleStatus),
                    D(DenialReason::InvalidSignature),
                ],
                D(DenialReason::InvalidSignature),
            ),
        ];
        for (all, required, children, expected) in cases {
            let mut state = Summary::default();
            for child in children {
                summary::push(&mut state, child);
            }
            let actual = if all {
                summary::all(state)
            } else {
                summary::threshold(state, required)
            };
            assert_eq!(actual, expected);
        }
    }

    fn nested_plan(seed: u64, leaves: &[u8]) -> AuthorizationPlan {
        if leaves.len() == 1 {
            return AuthorizationPlan::proof(ProofRef::new([leaves[0]; 32]));
        }
        let middle = leaves.len() / 2;
        let children = vec![
            nested_plan(seed.rotate_left(7).wrapping_add(1), &leaves[..middle]),
            nested_plan(seed.rotate_right(5).wrapping_add(3), &leaves[middle..]),
        ];
        match seed % 3 {
            0 => AuthorizationPlan::all_of(children),
            1 => AuthorizationPlan::any_of(children),
            _ => AuthorizationPlan::k_of_n(if seed & 8 == 0 { 1 } else { 2 }, children),
        }
        .expect("bounded distinct test leaves")
    }

    fn diagnostic(tag: usize) -> BranchOutcome {
        match tag % 8 {
            0 | 1 => BranchOutcome::Authorized,
            2 => BranchOutcome::Denied(DenialReason::InvalidSignature),
            3 => BranchOutcome::Denied(DenialReason::ActionBodyMismatch),
            4 => BranchOutcome::Indeterminate(Requirement::StaleStatus),
            5 => BranchOutcome::Indeterminate(Requirement::ApprovalUnavailable),
            6 => BranchOutcome::StructurallyInvalid(DenialReason::MissingReference),
            _ => BranchOutcome::StructurallyInvalid(DenialReason::ActionConstraintMismatch),
        }
    }

    fn run_with_stateful_callbacks(
        plan: &AuthorizationPlan,
        tags: &[u8],
        previous: bool,
    ) -> (BranchOutcome, Vec<ProofRef>, Vec<EvaluationEvent>, usize) {
        let state = core::cell::Cell::new(0usize);
        let mut visited = Vec::new();
        let mut events = Vec::new();
        let mut branch = |reference: ProofRef| {
            state.set(state.get() + 11);
            visited.push(reference);
            diagnostic(usize::from(tags[usize::from(reference.as_bytes()[0]) - 1]) + state.get())
        };
        let mut observer = |event| {
            state.set(state.get() + 17);
            events.push(event);
        };
        let outcome = if previous {
            oracle::evaluate_node(plan, &mut branch, &mut observer)
        } else {
            evaluate_observed(plan, &VerifierLimits::hard(), &mut branch, &mut observer)
                .expect("valid bounded plan")
        };
        (outcome, visited, events, state.get())
    }

    proptest! {
        #[test]
        fn streaming_summary_preserves_nested_results_and_callback_events(
            tags in proptest::collection::vec(any::<u8>(), 1..33),
            seed in any::<u64>(),
        ) {
            let leaves: Vec<u8> = (1..=tags.len())
                .map(|index| u8::try_from(index).expect("bounded test index"))
                .collect();
            let plan = nested_plan(seed, &leaves);
            prop_assert_eq!(
                run_with_stateful_callbacks(&plan, &tags, false),
                run_with_stateful_callbacks(&plan, &tags, true),
            );
        }

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

    /// At K = 0 and at K above the member count the count function takes the
    /// threshold formula's values, as the Lean two-input helper does; plan
    /// validation rejects both before any evaluation.
    #[test]
    fn threshold_counts_outside_the_plan_domain_follow_the_formula() {
        let two_input_counts = [(0, 0), (0, 1), (0, 2), (1, 0), (1, 1), (2, 0)];
        for (authorized, indeterminate) in two_input_counts {
            assert_eq!(
                evaluate_threshold_counts(0, authorized, indeterminate),
                ThresholdTruth::Authorized
            );
            for k in [3, 4, u16::MAX] {
                assert_eq!(
                    evaluate_threshold_counts(k, authorized, indeterminate),
                    ThresholdTruth::Denied
                );
            }
        }
        let member = |byte| AuthorizationPlan::proof(ProofRef::new([byte; 32]));
        assert!(AuthorizationPlan::k_of_n(0, vec![member(1), member(2)]).is_err());
        assert!(AuthorizationPlan::k_of_n(3, vec![member(1), member(2)]).is_err());
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
