//! Deterministic causal-slice projection.

use crate::trace::{FactEvaluation, FactResult, VerificationTrace};
use alloc::vec::Vec;

/// Relationship between one fact and the final result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Contribution {
    Decisive,
    NecessarySupport,
    SufficientAlternative,
    ContributingBlocker,
    ContextConstraint,
    Informational,
}

/// One fact selected for the causal explanation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalFact {
    /// Original trace fact.
    pub fact: FactEvaluation,
    /// Deterministic contribution classification.
    pub contribution: Contribution,
}

/// Produces the smallest linear causal slice recorded by the staged evaluator.
#[must_use]
pub fn causal_slice(trace: &VerificationTrace) -> Vec<CausalFact> {
    trace
        .events()
        .iter()
        .cloned()
        .map(|fact| {
            let contribution = if fact.sequence() == trace.final_node() {
                Contribution::Decisive
            } else {
                match fact.result() {
                    FactResult::Satisfied => Contribution::NecessarySupport,
                    FactResult::Contradicted | FactResult::Unavailable => {
                        Contribution::ContributingBlocker
                    }
                    FactResult::NotEvaluated => Contribution::Informational,
                }
            };
            CausalFact { fact, contribution }
        })
        .collect()
}
