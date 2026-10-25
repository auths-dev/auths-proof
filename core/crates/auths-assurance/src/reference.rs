// Frozen pre-cutover assurance evaluator. Test-only oracle.
//! Role-indexed assurance policy evaluation.



use alloc::vec::Vec;
use auths_model::{
    AssuranceClaim, AssurancePolicy, AssuranceQuantifier, AssuranceSatisfaction,
    ParticipantAssurance, ParticipantRole, Requirement, Timestamp,
};

/// Checks every policy requirement against claims for the exact participant
/// role.
///
/// # Errors
///
/// Returns [`Requirement::AssuranceRequirementNotMet`] when no exact,
/// sufficiently fresh claim satisfies a requirement.
pub fn evaluate(
    policy: &AssurancePolicy,
    reports: &[ParticipantAssurance],
    evaluation_time: Timestamp,
) -> Result<Vec<AssuranceSatisfaction>, Requirement> {
    evaluate_with_implications(policy, reports, evaluation_time, |_, _| false)
}

/// Evaluates typed assurance constraints with an exact closed implication
/// registry supplied by the verifier.
///
/// # Errors
///
/// Returns [`Requirement::AssuranceRequirementNotMet`] when no exact or
/// explicitly implied claim satisfies one policy requirement.
pub fn evaluate_with_implications(
    policy: &AssurancePolicy,
    reports: &[ParticipantAssurance],
    evaluation_time: Timestamp,
    mut implies: impl FnMut(&AssuranceClaim, &auths_model::AssuranceClaimId) -> bool,
) -> Result<Vec<AssuranceSatisfaction>, Requirement> {
    let mut satisfactions = Vec::new();
    for (index, requirement) in policy.requirements().iter().enumerate() {
        let selected: Vec<_> = reports
            .iter()
            .filter(|report| report.role() == requirement.role())
            .collect();
        if selected.is_empty() {
            return Err(Requirement::AssuranceRequirementNotMet);
        }
        let requirement_index =
            u16::try_from(index).map_err(|_| Requirement::AssuranceRequirementNotMet)?;
        let required = match requirement.quantifier() {
            AssuranceQuantifier::Any => 1,
            AssuranceQuantifier::Every => selected.len(),
        };
        let mut matched = 0usize;
        for report in selected {
            let mut candidates: Vec<_> = report
                .claims()
                .iter()
                .filter(|claim| {
                    (claim.kind() == requirement.claim_kind()
                        || implies(claim, requirement.claim_kind()))
                        && requirement
                            .parameters()
                            .iter()
                            .all(|parameter| claim.parameters().binary_search(parameter).is_ok())
                        && requirement
                            .source()
                            .is_none_or(|source| claim.source() == source)
                        && requirement
                            .adapter()
                            .is_none_or(|adapter| report.adapter() == adapter)
                        && requirement
                            .adapter_version()
                            .is_none_or(|version| report.adapter_version() == version)
                        && requirement.maximum_age().is_none_or(|maximum_age| {
                            claim.observed_at().is_some_and(|observed_at| {
                                observed_at <= evaluation_time
                                    && evaluation_time.get().saturating_sub(observed_at.get())
                                        <= maximum_age.get()
                            })
                        })
                })
                .collect();
            candidates.sort();
            if let Some(claim) = candidates.first() {
                matched = matched.saturating_add(1);
                satisfactions.push(AssuranceSatisfaction::new(
                    requirement_index,
                    report.principal().clone(),
                    (*claim).clone(),
                    report.evidence().to_vec(),
                ));
                if requirement.quantifier() == AssuranceQuantifier::Any {
                    break;
                }
            } else if requirement.quantifier() == AssuranceQuantifier::Every {
                return Err(Requirement::AssuranceRequirementNotMet);
            }
        }
        if matched < required {
            return Err(Requirement::AssuranceRequirementNotMet);
        }
    }
    satisfactions.sort();
    satisfactions.dedup();
    Ok(satisfactions)
}

/// Returns the role used for the issuer of a grant at `chain_index`.
#[must_use]
pub const fn grant_issuer_role(chain_index: usize) -> ParticipantRole {
    if chain_index == 0 {
        ParticipantRole::Root
    } else {
        ParticipantRole::Intermediate
    }
}

