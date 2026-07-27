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
    use super::*;

    #[kani::proof]
    #[kani::unwind(17)]
    fn threshold_two_of_three_refines_reference() {
        let tags: [u8; 3] = kani::any();
        kani::assume(tags[0] < 3 && tags[1] < 3 && tags[2] < 3);

        let references = [
            ProofRef::new([1; 32]),
            ProofRef::new([2; 32]),
            ProofRef::new([3; 32]),
        ];
        let plan = AuthorizationPlan::k_of_n(
            2,
            references
                .iter()
                .copied()
                .map(AuthorizationPlan::proof)
                .collect(),
        )
        .unwrap();
        let actual = evaluate(&plan, &VerifierLimits::default(), &mut |reference| {
            let index = usize::from(reference.as_bytes()[0] - 1);
            match tags[index] {
                0 => BranchOutcome::Denied(DenialReason::PermissionNotGranted),
                1 => BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable),
                _ => BranchOutcome::Authorized,
            }
        })
        .unwrap();

        let mut authorized = 0usize;
        let mut indeterminate = 0usize;
        for tag in tags {
            if tag == 2 {
                authorized += 1;
            } else if tag == 1 {
                indeterminate += 1;
            }
        }
        let expected = if authorized >= 2 {
            FormalTruth::Authorized
        } else if authorized + indeterminate >= 2 {
            FormalTruth::Indeterminate
        } else {
            FormalTruth::Denied
        };
        let actual = match actual {
            BranchOutcome::Authorized => FormalTruth::Authorized,
            BranchOutcome::Denied(_) | BranchOutcome::StructurallyInvalid(_) => FormalTruth::Denied,
            BranchOutcome::Indeterminate(_) => FormalTruth::Indeterminate,
        };
        assert_eq!(actual, expected);
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
