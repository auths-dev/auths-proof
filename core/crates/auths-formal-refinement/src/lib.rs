//! Executable refinement checks for the generated Auths-Proof Lean model.

#![forbid(unsafe_code)]

#[cfg(test)]
mod refinement {
    use auths_algebra_kernel::{AttenuationChecks, Truth, attenuation_accepts, threshold_counts};
    use auths_composition::{BranchOutcome, evaluate};
    use auths_model::{AuthorizationPlan, DenialReason, ProofRef, Requirement, VerifierLimits};
    use serde::Deserialize;
    use std::collections::BTreeMap;

    #[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
    #[serde(rename_all = "kebab-case")]
    enum VectorTruth {
        Denied,
        Indeterminate,
        Authorized,
    }

    impl From<VectorTruth> for Truth {
        fn from(value: VectorTruth) -> Self {
            match value {
                VectorTruth::Denied => Self::Denied,
                VectorTruth::Indeterminate => Self::Indeterminate,
                VectorTruth::Authorized => Self::Authorized,
            }
        }
    }

    #[derive(Debug, Deserialize)]
    struct ThresholdVector {
        required: u16,
        authorized: usize,
        indeterminate: usize,
        expected: VectorTruth,
    }

    #[derive(Debug, Deserialize)]
    struct ThresholdVectorFile {
        schema: String,
        exhaustive_bound: u16,
        cases: Vec<ThresholdVector>,
    }

    #[derive(Debug, Deserialize)]
    struct AttenuationVector {
        checks: [bool; 10],
        accepted: bool,
    }

    #[derive(Debug, Deserialize)]
    struct AttenuationVectorFile {
        schema: String,
        dimensions: usize,
        cases: Vec<AttenuationVector>,
    }

    fn checks(values: [bool; 10]) -> AttenuationChecks {
        AttenuationChecks {
            root_preserved: values[0],
            depth_decreases: values[1],
            profile_attenuates: values[2],
            permissions_attenuate: values[3],
            validity_attenuates: values[4],
            audiences_attenuate: values[5],
            action_constraint_attenuates: values[6],
            budget_attenuates: values[7],
            status_attenuates: values[8],
            assurance_attenuates: values[9],
        }
    }

    fn shipping_plan_truth(vector: &ThresholdVector) -> (Truth, usize) {
        let total = usize::from(auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND);
        let leaves: Vec<_> = (0..total)
            .map(|index| {
                let marker = u8::try_from(index + 1).unwrap_or(u8::MAX);
                AuthorizationPlan::proof(ProofRef::new([marker; 32]))
            })
            .collect();
        let plan = AuthorizationPlan::k_of_n(vector.required, leaves)
            .expect("Lean emits thresholds within the target V1 plan bound");
        let outcomes: BTreeMap<_, _> = (0..total)
            .map(|index| {
                let marker = u8::try_from(index + 1).unwrap_or(u8::MAX);
                let outcome = if index < vector.authorized {
                    BranchOutcome::Authorized
                } else if index < vector.authorized + vector.indeterminate {
                    BranchOutcome::Indeterminate(Requirement::ExternalFactUnavailable)
                } else {
                    BranchOutcome::Denied(DenialReason::PermissionNotGranted)
                };
                (ProofRef::new([marker; 32]), outcome)
            })
            .collect();
        let mut visited = 0;
        let outcome = evaluate(&plan, &VerifierLimits::default(), &mut |reference| {
            visited += 1;
            outcomes[&reference]
        })
        .expect("Lean emits a target V1 bounded plan");
        let truth = match outcome {
            BranchOutcome::Authorized => Truth::Authorized,
            BranchOutcome::Indeterminate(_) => Truth::Indeterminate,
            BranchOutcome::Denied(_) | BranchOutcome::StructurallyInvalid(_) => Truth::Denied,
        };
        (truth, visited)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn lean_threshold_vectors_exhaust_target_v1_and_refine_shipping_rust() {
            let vectors: ThresholdVectorFile = serde_json::from_str(include_str!(
                "../../../formal-vectors/v1/threshold-counts.json"
            ))
            .expect("valid Lean-generated threshold vectors");
            assert_eq!(vectors.schema, "auths-proof-threshold-vectors/v1");
            assert_eq!(
                usize::from(vectors.exhaustive_bound),
                auths_model::DEFAULT_MAX_PLAN_LEAVES
            );
            assert_eq!(
                vectors.exhaustive_bound,
                auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND
            );
            assert_eq!(vectors.cases.len(), 2_448);
            for vector in vectors.cases {
                let expected = Truth::from(vector.expected);
                assert_eq!(
                    threshold_counts(vector.required, vector.authorized, vector.indeterminate),
                    expected
                );
                let (shipping, visited) = shipping_plan_truth(&vector);
                assert_eq!(shipping, expected);
                assert_eq!(
                    visited,
                    usize::from(auths_algebra_kernel::EXHAUSTIVE_THRESHOLD_BOUND)
                );
            }
        }

        #[test]
        fn lean_attenuation_vectors_exhaust_the_generated_projection() {
            let vectors: AttenuationVectorFile = serde_json::from_str(include_str!(
                "../../../formal-vectors/v1/attenuation-checks.json"
            ))
            .expect("valid Lean-generated attenuation vectors");
            assert_eq!(vectors.schema, "auths-proof-attenuation-vectors/v1");
            assert_eq!(vectors.dimensions, 10);
            assert_eq!(vectors.cases.len(), 1_024);
            for vector in vectors.cases {
                assert_eq!(attenuation_accepts(&checks(vector.checks)), vector.accepted);
            }
        }
    }
}
