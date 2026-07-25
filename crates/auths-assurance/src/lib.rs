//! Role-indexed assurance policy evaluation.

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;
use auths_model::{
    AssuranceClaim, AssurancePolicy, AssuranceSatisfaction, ParticipantAssurance, ParticipantRole,
    Requirement, Timestamp,
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
        let mut candidates: Vec<_> = reports
            .iter()
            .filter(|report| report.role() == requirement.role())
            .flat_map(|report| report.claims().iter().map(move |claim| (report, claim)))
            .filter(|(report, claim)| {
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
                                && evaluation_time.get() - observed_at.get() <= maximum_age.get()
                        })
                    })
            })
            .collect();
        candidates.sort_by(|(left_report, left_claim), (right_report, right_claim)| {
            left_report
                .principal()
                .cmp(right_report.principal())
                .then_with(|| left_claim.cmp(right_claim))
                .then_with(|| left_report.evidence().cmp(right_report.evidence()))
        });
        let Some((report, claim)) = candidates.first() else {
            return Err(Requirement::AssuranceRequirementNotMet);
        };
        let requirement_index =
            u16::try_from(index).map_err(|_| Requirement::AssuranceRequirementNotMet)?;
        satisfactions.push(AssuranceSatisfaction::new(
            requirement_index,
            report.principal().clone(),
            (*claim).clone(),
            report.evidence().to_vec(),
        ));
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use auths_model::{
        AdapterId, AssuranceClaimId, AssurancePolicyId, AssuranceRequirement, ClaimParameterId,
        EvidenceId, EvidenceSourceId, FreshnessLimit, PrincipalId,
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
            vec![AssuranceRequirement::constrained(
                ParticipantRole::Actor,
                kind.clone(),
                vec![(parameter_name.clone(), expected_value)],
                Some(EvidenceSourceId::parse("attestation").unwrap()),
                Some(AdapterId::parse("hsm-attested-v1").unwrap()),
                Some(1),
                Some(FreshnessLimit::new(10).unwrap()),
            )
            .unwrap()],
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
                AssuranceClaimId::parse("workload-attested").unwrap(),
                None,
            )],
        )
        .unwrap();
        assert!(evaluate(
            &alternate,
            core::slice::from_ref(&report),
            Timestamp::new(50)
        )
        .is_err());
        assert!(evaluate_with_implications(
            &alternate,
            &[report],
            Timestamp::new(50),
            |claim, expected| claim.kind().as_str() == "hardware-attested"
                && expected.as_str() == "workload-attested"
        )
        .is_ok());
    }
}
