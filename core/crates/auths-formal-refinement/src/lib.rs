//! Executable refinement checks for the Auths-Proof Lean model.

#![forbid(unsafe_code)]
#![allow(unexpected_cfgs)]

use auths_composition::{BranchOutcome, evaluate};
use auths_model::{AuthorizationPlan, DenialReason, ProofRef, Requirement, VerifierLimits};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Three-valued truth projection shared with the Lean model.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormalTruth {
    Denied,
    Indeterminate,
    Authorized,
}

/// Closed composition constructor used by generated semantic vectors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FormalOperator {
    AllOf,
    AnyOf,
    KOfN,
}

/// One formal composition refinement case.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct FormalCompositionCase {
    /// Stable case identifier.
    pub id: String,
    /// Composition operator.
    pub operator: FormalOperator,
    /// Threshold for `k-of-n`; ignored by other operators.
    pub k: Option<u16>,
    /// Canonically ordered leaf outcomes.
    pub leaves: Vec<FormalTruth>,
    /// Expected formal truth value.
    pub expected: FormalTruth,
}

/// Evaluates the small mathematical reference definition.
#[must_use]
pub fn reference_evaluate(case: &FormalCompositionCase) -> FormalTruth {
    let authorized = case
        .leaves
        .iter()
        .filter(|outcome| **outcome == FormalTruth::Authorized)
        .count();
    let indeterminate = case
        .leaves
        .iter()
        .filter(|outcome| **outcome == FormalTruth::Indeterminate)
        .count();
    match case.operator {
        FormalOperator::AllOf => {
            if case.leaves.contains(&FormalTruth::Denied) {
                FormalTruth::Denied
            } else if indeterminate > 0 {
                FormalTruth::Indeterminate
            } else {
                FormalTruth::Authorized
            }
        }
        FormalOperator::AnyOf => {
            if authorized > 0 {
                FormalTruth::Authorized
            } else if indeterminate > 0 {
                FormalTruth::Indeterminate
            } else {
                FormalTruth::Denied
            }
        }
        FormalOperator::KOfN => {
            let required = usize::from(case.k.unwrap_or(1));
            if authorized >= required {
                FormalTruth::Authorized
            } else if authorized + indeterminate >= required {
                FormalTruth::Indeterminate
            } else {
                FormalTruth::Denied
            }
        }
    }
}

/// Evaluates the same case through the public shipping plan API.
///
/// # Panics
///
/// Panics only when a checked-in formal vector violates its own schema.
#[must_use]
pub fn shipping_evaluate(case: &FormalCompositionCase) -> (FormalTruth, Vec<ProofRef>) {
    let leaves: Vec<_> = case
        .leaves
        .iter()
        .enumerate()
        .map(|(index, _)| {
            let marker = u8::try_from(index + 1).expect("target V1 vector has at most 16 leaves");
            AuthorizationPlan::proof(ProofRef::new([marker; 32]))
        })
        .collect();
    let plan = match case.operator {
        FormalOperator::AllOf => AuthorizationPlan::all_of(leaves),
        FormalOperator::AnyOf => AuthorizationPlan::any_of(leaves),
        FormalOperator::KOfN => AuthorizationPlan::k_of_n(case.k.unwrap_or(1), leaves),
    }
    .expect("formal vector contains a valid plan");
    let outcomes: BTreeMap<_, _> = case
        .leaves
        .iter()
        .enumerate()
        .map(|(index, outcome)| {
            let marker = u8::try_from(index + 1).expect("bounded vector");
            (ProofRef::new([marker; 32]), *outcome)
        })
        .collect();
    let mut visited = Vec::new();
    let actual = evaluate(&plan, &VerifierLimits::default(), &mut |reference| {
        visited.push(reference);
        match outcomes[&reference] {
            FormalTruth::Authorized => BranchOutcome::Authorized,
            FormalTruth::Denied => BranchOutcome::Denied(DenialReason::PermissionNotGranted),
            FormalTruth::Indeterminate => {
                BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable)
            }
        }
    })
    .expect("formal vector plan is bounded");
    let truth = match actual {
        BranchOutcome::Authorized => FormalTruth::Authorized,
        BranchOutcome::Denied(_) | BranchOutcome::StructurallyInvalid(_) => FormalTruth::Denied,
        BranchOutcome::Indeterminate(_) => FormalTruth::Indeterminate,
    };
    (truth, visited)
}

/// Exhaustively enumerates every three-valued vector through four leaves.
#[must_use]
pub fn exhaustive_cases() -> Vec<FormalCompositionCase> {
    let mut cases = Vec::new();
    for len in 1usize..=4 {
        let combinations = 3usize.pow(u32::try_from(len).expect("bounded length"));
        for encoded in 0..combinations {
            let mut value = encoded;
            let mut leaves = Vec::with_capacity(len as usize);
            for _ in 0..len {
                leaves.push(match value % 3 {
                    0 => FormalTruth::Denied,
                    1 => FormalTruth::Indeterminate,
                    _ => FormalTruth::Authorized,
                });
                value /= 3;
            }
            for operator in [FormalOperator::AllOf, FormalOperator::AnyOf] {
                let mut case = FormalCompositionCase {
                    id: format!("{operator:?}/{len}/{encoded}"),
                    operator,
                    k: None,
                    leaves: leaves.clone(),
                    expected: FormalTruth::Denied,
                };
                case.expected = reference_evaluate(&case);
                cases.push(case);
            }
            for k in 1..=len {
                let mut case = FormalCompositionCase {
                    id: format!("KOfN/{k}/{len}/{encoded}"),
                    operator: FormalOperator::KOfN,
                    k: Some(u16::try_from(k).expect("bounded threshold")),
                    leaves: leaves.clone(),
                    expected: FormalTruth::Denied,
                };
                case.expected = reference_evaluate(&case);
                cases.push(case);
            }
        }
    }
    cases
}

#[cfg(kani)]
mod kani_harnesses {
    use auths_composition::{ThresholdTruth, evaluate_threshold_counts};

    #[kani::proof]
    fn shipping_threshold_count_partition_is_total() {
        let authorized: u16 = kani::any();
        let indeterminate: u16 = kani::any();
        let required: u16 = kani::any();
        kani::assume(authorized <= 16);
        kani::assume(indeterminate <= 16 - authorized);
        kani::assume(required > 0 && required <= 16);
        let result = evaluate_threshold_counts(
            required,
            usize::from(authorized),
            usize::from(indeterminate),
        );
        assert!(
            (result == ThresholdTruth::Authorized && authorized >= required)
                || (result == ThresholdTruth::Indeterminate
                    && authorized < required
                    && authorized + indeterminate >= required)
                || (result == ThresholdTruth::Denied && authorized + indeterminate < required)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustive_composition_refines_shipping_evaluator() {
        for case in exhaustive_cases() {
            let (actual, visited) = shipping_evaluate(&case);
            assert_eq!(actual, case.expected, "{}", case.id);
            assert_eq!(visited.len(), case.leaves.len(), "{}", case.id);
        }
    }

    #[test]
    fn checked_in_vectors_refine_shipping_evaluator() {
        let source = include_str!("../../../formal-vectors/v1/composition.json");
        let cases: Vec<FormalCompositionCase> =
            serde_json::from_str(source).expect("valid generated vector JSON");
        for case in cases {
            assert_eq!(reference_evaluate(&case), case.expected, "{}", case.id);
            assert_eq!(shipping_evaluate(&case).0, case.expected, "{}", case.id);
        }
    }
}
