//! Deterministic causal-slice projection.

use crate::trace::{FactEvaluation, FactKind, FactResult, FactValue, VerificationTrace};
use alloc::{vec, vec::Vec};

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

/// Produces the deterministic backward slice rooted at the final decision.
///
/// Only graph ancestors of the final node are retained. Plan children are
/// classified from the exact threshold node that consumed them, allowing
/// successful alternatives to remain distinct from necessary conjunction
/// support.
#[must_use]
pub fn causal_slice(trace: &VerificationTrace) -> Vec<CausalFact> {
    let event_count = trace.events().len();
    let Some(_) = usize::try_from(trace.final_node())
        .ok()
        .filter(|index| *index < event_count)
    else {
        return Vec::new();
    };

    let mut included = vec![false; event_count];
    let mut pending = vec![trace.final_node()];
    while let Some(sequence) = pending.pop() {
        let Some(index) = usize::try_from(sequence)
            .ok()
            .filter(|index| *index < event_count)
        else {
            continue;
        };
        if included[index] {
            continue;
        }
        included[index] = true;
        pending.extend_from_slice(trace.events()[index].parents());
    }

    let mut dependents = vec![Vec::new(); event_count];
    for fact in trace.events().iter().filter(|fact| {
        usize::try_from(fact.sequence())
            .ok()
            .and_then(|index| included.get(index))
            .copied()
            .unwrap_or(false)
    }) {
        for parent in fact.parents() {
            if let Ok(parent_index) = usize::try_from(*parent)
                && parent_index < event_count
            {
                dependents[parent_index].push(fact.sequence());
            }
        }
    }

    trace
        .events()
        .iter()
        .filter(|fact| {
            usize::try_from(fact.sequence())
                .ok()
                .and_then(|index| included.get(index))
                .copied()
                .unwrap_or(false)
        })
        .cloned()
        .map(|fact| {
            let dependent_nodes = usize::try_from(fact.sequence())
                .ok()
                .and_then(|index| dependents.get(index))
                .map_or(&[] as &[u32], Vec::as_slice);
            let contribution = classify(
                &fact,
                fact.sequence() == trace.final_node(),
                dependent_nodes,
                trace,
            );
            CausalFact { fact, contribution }
        })
        .collect()
}

fn classify(
    fact: &FactEvaluation,
    final_node: bool,
    dependents: &[u32],
    trace: &VerificationTrace,
) -> Contribution {
    if final_node {
        return Contribution::Decisive;
    }
    if matches!(
        fact.kind(),
        FactKind::MinimumAuthorizedBranches
            | FactKind::MinimumDistinctActors
            | FactKind::MinimumDistinctRoots
    ) {
        return Contribution::ContextConstraint;
    }
    if let Some(parent) = dependents.iter().find_map(|sequence| {
        trace
            .events()
            .get(usize::try_from(*sequence).ok()?)
            .filter(|candidate| {
                candidate.kind() == FactKind::PlanNode
                    && matches!(candidate.value(), FactValue::Count { .. })
            })
    }) {
        return plan_child_contribution(fact, parent);
    }
    match fact.result() {
        FactResult::Satisfied => Contribution::NecessarySupport,
        FactResult::Contradicted | FactResult::Unavailable => Contribution::ContributingBlocker,
        FactResult::NotEvaluated => Contribution::Informational,
    }
}

fn plan_child_contribution(child: &FactEvaluation, parent: &FactEvaluation) -> Contribution {
    let FactValue::Count { required, .. } = parent.value() else {
        return Contribution::Informational;
    };
    let every_child_required =
        usize::try_from(required).is_ok_and(|required| required >= parent.parents().len());
    match child.result() {
        FactResult::Satisfied
            if every_child_required
                && matches!(
                    parent.result(),
                    FactResult::Satisfied | FactResult::Unavailable
                ) =>
        {
            Contribution::NecessarySupport
        }
        FactResult::Satisfied
            if matches!(
                parent.result(),
                FactResult::Satisfied | FactResult::Unavailable
            ) =>
        {
            Contribution::SufficientAlternative
        }
        FactResult::Contradicted | FactResult::Unavailable
            if matches!(
                parent.result(),
                FactResult::Contradicted | FactResult::Unavailable
            ) =>
        {
            Contribution::ContributingBlocker
        }
        _ => Contribution::Informational,
    }
}
