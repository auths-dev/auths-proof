//! Role-indexed assurance policy evaluation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

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
    let mut outcome = Ok(Vec::new());
    let mut position = 0;
    while position < policy.requirements().len() && outcome.is_ok() {
        outcome = match outcome {
            Ok(satisfactions) => evaluate_requirement(satisfactions, position,
                &policy.requirements()[position], reports, evaluation_time, &mut implies),
            Err(failure) => Err(failure),
        };
        position += 1;
    }
    let mut satisfactions = outcome?;
    satisfactions.sort();
    satisfactions.dedup();
    Ok(satisfactions)
}


struct RequirementProgress {
    satisfactions: Vec<AssuranceSatisfaction>,
    matched: usize,
}
fn selected_count(reports: &[ParticipantAssurance], role: ParticipantRole) -> usize {
    let mut count = 0;
    let mut position = 0;
    while position < reports.len() {
        if reports[position].role() == role { count += 1; }
        position += 1;
    }
    count
}
fn parameters_present(
    required: &[(auths_model::ClaimParameterId, auths_model::ClaimParameterId)],
    actual: &[(auths_model::ClaimParameterId, auths_model::ClaimParameterId)],
) -> bool {
    let mut position = 0;
    let mut present = true;
    while position < required.len() && present {
        present = actual.binary_search(&required[position]).is_ok();
        position += 1;
    }
    present
}
fn claim_matches<I: FnMut(&AssuranceClaim, &auths_model::AssuranceClaimId) -> bool>(
    claim: &AssuranceClaim, report: &ParticipantAssurance, requirement: &auths_model::AssuranceRequirement,
    evaluation_time: Timestamp, implies: &mut I,
) -> bool {
    if claim.kind() != requirement.claim_kind() && !implies(claim, requirement.claim_kind()) { return false; }
    if !parameters_present(requirement.parameters(), claim.parameters()) { return false; }
    if let Some(source) = requirement.source() && claim.source() != source { return false; }
    if let Some(adapter) = requirement.adapter() && report.adapter() != adapter { return false; }
    if let Some(version) = requirement.adapter_version() && report.adapter_version() != version { return false; }
    match requirement.maximum_age() {
        None => true,
        Some(maximum_age) => match claim.observed_at() {
            None => false,
            Some(observed_at) => observed_at <= evaluation_time
                && evaluation_time.get().saturating_sub(observed_at.get()) <= maximum_age.get(),
        },
    }
}
fn select_claim<'a, I: FnMut(&AssuranceClaim, &auths_model::AssuranceClaimId) -> bool>(
    report: &'a ParticipantAssurance, requirement: &auths_model::AssuranceRequirement,
    evaluation_time: Timestamp, implies: &mut I,
) -> Option<&'a AssuranceClaim> {
    let mut selected: Option<&AssuranceClaim> = None;
    let mut position = 0;
    // Evaluate every claim in its original order, including implication calls,
    // then retain the same minimum that the old filtered stable sort selected.
    while position < report.claims().len() {
        let claim = &report.claims()[position];
        if claim_matches(claim, report, requirement, evaluation_time, implies) {
            selected = match selected {
                None => Some(claim),
                Some(previous) => if claim < previous { Some(claim) } else { Some(previous) },
            };
        }
        position += 1;
    }
    selected
}
fn evaluate_report<I: FnMut(&AssuranceClaim, &auths_model::AssuranceClaimId) -> bool>(
    mut progress: RequirementProgress, report: &ParticipantAssurance,
    requirement: &auths_model::AssuranceRequirement, requirement_index: u16,
    evaluation_time: Timestamp, implies: &mut I,
) -> Result<RequirementProgress, Requirement> {
    if report.role() != requirement.role() { return Ok(progress); }
    match select_claim(report, requirement, evaluation_time, implies) {
        Some(claim) => {
            progress.matched = progress.matched.saturating_add(1);
            progress.satisfactions.push(AssuranceSatisfaction::new(requirement_index,
                report.principal().clone(), claim.clone(), report.evidence().to_vec()));
            Ok(progress)
        }
        None => match requirement.quantifier() {
            AssuranceQuantifier::Every => Err(Requirement::AssuranceRequirementNotMet),
            AssuranceQuantifier::Any => Ok(progress),
        },
    }
}
fn evaluate_requirement<I: FnMut(&AssuranceClaim, &auths_model::AssuranceClaimId) -> bool>(
    satisfactions: Vec<AssuranceSatisfaction>, index: usize, requirement: &auths_model::AssuranceRequirement,
    reports: &[ParticipantAssurance], evaluation_time: Timestamp, implies: &mut I,
) -> Result<Vec<AssuranceSatisfaction>, Requirement> {
    let selected = selected_count(reports, requirement.role());
    if selected == 0 { return Err(Requirement::AssuranceRequirementNotMet); }
    let requirement_index = u16::try_from(index).map_err(|_| Requirement::AssuranceRequirementNotMet)?;
    let required = match requirement.quantifier() { AssuranceQuantifier::Any => 1, AssuranceQuantifier::Every => selected };
    let mut outcome = Ok(RequirementProgress { satisfactions, matched: 0 });
    let mut position = 0;
    while position < reports.len() && matches!(&outcome, Ok(progress)
        if requirement.quantifier() != AssuranceQuantifier::Any || progress.matched == 0) {
        outcome = match outcome {
            Ok(progress) => evaluate_report(progress, &reports[position], requirement, requirement_index, evaluation_time, implies),
            Err(failure) => Err(failure),
        };
        position += 1;
    }
    let progress = outcome?;
    if progress.matched < required { Err(Requirement::AssuranceRequirementNotMet) }
    else { Ok(progress.satisfactions) }
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

#[cfg(test)]
#[path = "reference.rs"]
mod reference;
#[cfg(test)]
#[path = "parity_tests.rs"]
mod parity_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        AdapterId, AssuranceClaimId, AssurancePolicyId, AssuranceQuantifier, AssuranceRequirement,
        ClaimParameterId, EvidenceId, EvidenceSourceId, FreshnessLimit, PrincipalId,
    };

    #[test]
    fn first_grant_is_root_role() {
        assert_eq!(grant_issuer_role(0), ParticipantRole::Root);
        assert_eq!(grant_issuer_role(1), ParticipantRole::Intermediate);
    }

    fn constrained_fixture(
        role: ParticipantRole,
        parameter_value: &str,
        source: &str,
        adapter: &str,
        adapter_version: u16,
        observed_at: u64,
    ) -> (AssurancePolicy, ParticipantAssurance) {
        let kind = AssuranceClaimId::parse("hardware-attested").unwrap();
        let parameter_name = ClaimParameterId::parse("protection").unwrap();
        let expected_value = ClaimParameterId::parse("hardware").unwrap();
        let policy = AssurancePolicy::new(
            AssurancePolicyId::parse("constrained-test").unwrap(),
            vec![
                AssuranceRequirement::constrained(
                    ParticipantRole::Actor,
                    AssuranceQuantifier::Every,
                    kind.clone(),
                    vec![(parameter_name.clone(), expected_value)],
                    Some(EvidenceSourceId::parse("attestation").unwrap()),
                    Some(AdapterId::parse("hsm-attested-v1").unwrap()),
                    Some(1),
                    Some(FreshnessLimit::new(10).unwrap()),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let claim = AssuranceClaim::new(
            kind,
            vec![(
                parameter_name,
                ClaimParameterId::parse(parameter_value).unwrap(),
            )],
            Some(Timestamp::new(observed_at)),
            EvidenceSourceId::parse(source).unwrap(),
        )
        .unwrap();
        let report = ParticipantAssurance::new(
            PrincipalId::parse("raw:test").unwrap(),
            role,
            vec![claim],
            vec![EvidenceId::new([1; 32])],
            AdapterId::parse(adapter).unwrap(),
            adapter_version,
        )
        .unwrap();
        (policy, report)
    }

    #[test]
    fn all_typed_constraints_are_enforced() {
        let evaluation_time = Timestamp::new(50);
        let (policy, valid) = constrained_fixture(
            ParticipantRole::Actor,
            "hardware",
            "attestation",
            "hsm-attested-v1",
            1,
            40,
        );
        assert!(evaluate(&policy, &[valid], evaluation_time).is_ok());
        for report in [
            constrained_fixture(
                ParticipantRole::Root,
                "hardware",
                "attestation",
                "hsm-attested-v1",
                1,
                40,
            )
            .1,
            constrained_fixture(
                ParticipantRole::Actor,
                "software",
                "attestation",
                "hsm-attested-v1",
                1,
                40,
            )
            .1,
            constrained_fixture(
                ParticipantRole::Actor,
                "hardware",
                "document",
                "hsm-attested-v1",
                1,
                40,
            )
            .1,
            constrained_fixture(
                ParticipantRole::Actor,
                "hardware",
                "attestation",
                "other-adapter-v1",
                1,
                40,
            )
            .1,
            constrained_fixture(
                ParticipantRole::Actor,
                "hardware",
                "attestation",
                "hsm-attested-v1",
                2,
                40,
            )
            .1,
            constrained_fixture(
                ParticipantRole::Actor,
                "hardware",
                "attestation",
                "hsm-attested-v1",
                1,
                39,
            )
            .1,
        ] {
            assert_eq!(
                evaluate(&policy, &[report], evaluation_time),
                Err(Requirement::AssuranceRequirementNotMet)
            );
        }
    }

    #[test]
    fn implication_requires_explicit_rule() {
        let (policy, report) = constrained_fixture(
            ParticipantRole::Actor,
            "hardware",
            "attestation",
            "hsm-attested-v1",
            1,
            40,
        );
        let alternate = AssurancePolicy::new(
            policy.id().clone(),
            vec![AssuranceRequirement::new(
                ParticipantRole::Actor,
                AssuranceQuantifier::Every,
                AssuranceClaimId::parse("workload-attested").unwrap(),
                None,
            )],
        )
        .unwrap();
        assert!(
            evaluate(
                &alternate,
                core::slice::from_ref(&report),
                Timestamp::new(50)
            )
            .is_err()
        );
        assert!(
            evaluate_with_implications(
                &alternate,
                &[report],
                Timestamp::new(50),
                |claim, expected| claim.kind().as_str() == "hardware-attested"
                    && expected.as_str() == "workload-attested"
            )
            .is_ok()
        );
    }

    #[test]
    fn every_rejects_one_weak_intermediate_while_any_accepts_one_strong_intermediate() {
        let (_, strong) = constrained_fixture(
            ParticipantRole::Intermediate,
            "hardware",
            "attestation",
            "hsm-attested-v1",
            1,
            40,
        );
        let (_, weak) = constrained_fixture(
            ParticipantRole::Intermediate,
            "software",
            "attestation",
            "hsm-attested-v1",
            1,
            40,
        );
        let claim = AssuranceClaimId::parse("hardware-attested").unwrap();
        let requirement = |quantifier| {
            AssuranceRequirement::constrained(
                ParticipantRole::Intermediate,
                quantifier,
                claim.clone(),
                vec![(
                    ClaimParameterId::parse("protection").unwrap(),
                    ClaimParameterId::parse("hardware").unwrap(),
                )],
                Some(EvidenceSourceId::parse("attestation").unwrap()),
                Some(AdapterId::parse("hsm-attested-v1").unwrap()),
                Some(1),
                Some(FreshnessLimit::new(10).unwrap()),
            )
            .unwrap()
        };
        let every = AssurancePolicy::new(
            AssurancePolicyId::parse("every-intermediate").unwrap(),
            vec![requirement(AssuranceQuantifier::Every)],
        )
        .unwrap();
        let any = AssurancePolicy::new(
            AssurancePolicyId::parse("any-intermediate").unwrap(),
            vec![requirement(AssuranceQuantifier::Any)],
        )
        .unwrap();

        assert_eq!(
            evaluate(&every, &[strong.clone(), weak.clone()], Timestamp::new(50)),
            Err(Requirement::AssuranceRequirementNotMet)
        );
        let satisfactions =
            evaluate(&any, &[weak, strong], Timestamp::new(50)).expect("one strong intermediate");
        assert_eq!(satisfactions.len(), 1);
    }
}
