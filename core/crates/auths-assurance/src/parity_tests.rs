use super::*;
use alloc::vec;
use auths_model::{
    AdapterId, AssuranceClaimId, AssurancePolicyId, AssuranceRequirement, ClaimParameterId,
    EvidenceId, EvidenceSourceId, FreshnessLimit, PrincipalId,
};

fn claim(kind: &str, parameter: &str, observed: Option<u64>, source: &str) -> AssuranceClaim {
    AssuranceClaim::new(AssuranceClaimId::parse(kind).unwrap(),
        vec![(ClaimParameterId::parse("protection").unwrap(), ClaimParameterId::parse(parameter).unwrap())],
        observed.map(Timestamp::new), EvidenceSourceId::parse(source).unwrap()).unwrap()
}
fn report(name: &str, role: ParticipantRole, adapter: &str, version: u16, claims: Vec<AssuranceClaim>) -> ParticipantAssurance {
    ParticipantAssurance::new(PrincipalId::parse(name).unwrap(), role, claims,
        vec![EvidenceId::new([0x55; 32])], AdapterId::parse(adapter).unwrap(), version).unwrap()
}
fn requirement(role: ParticipantRole, quantifier: AssuranceQuantifier, mask: u8) -> AssuranceRequirement {
    AssuranceRequirement::constrained(role, quantifier, AssuranceClaimId::parse("claim-z").unwrap(),
        if mask & 1 == 0 { Vec::new() } else { vec![(ClaimParameterId::parse("protection").unwrap(), ClaimParameterId::parse("hardware").unwrap())] },
        if mask & 2 == 0 { None } else { Some(EvidenceSourceId::parse("attestation").unwrap()) },
        if mask & 4 == 0 { None } else { Some(AdapterId::parse("adapter-a").unwrap()) },
        if mask & 8 == 0 { None } else { Some(1) },
        if mask & 16 == 0 { None } else { Some(FreshnessLimit::new(10).unwrap()) }).unwrap()
}

#[test]
fn complete_constraint_role_quantifier_and_callback_trace_parity() {
    let reports = vec![
        report("test:root", ParticipantRole::Root, "adapter-a", 1, vec![
            claim("claim-a", "hardware", Some(40), "attestation"),
            claim("claim-z", "hardware", Some(50), "attestation"),
            claim("claim-b", "software", None, "document"),
        ]),
        report("test:alice", ParticipantRole::Actor, "adapter-a", 1, vec![
            claim("claim-z", "hardware", Some(40), "attestation"),
            claim("claim-a", "software", Some(39), "document"),
            claim("claim-b", "hardware", Some(51), "attestation"),
        ]),
        report("test:bob", ParticipantRole::Actor, "adapter-b", 2, vec![
            claim("claim-z", "hardware", None, "attestation"),
            claim("claim-a", "hardware", Some(u64::MAX), "attestation"),
        ]),
    ];
    for role in [ParticipantRole::Root, ParticipantRole::Intermediate, ParticipantRole::Actor] {
        for quantifier in [AssuranceQuantifier::Any, AssuranceQuantifier::Every] {
            for mask in 0..32 {
                let policy = AssurancePolicy::new(AssurancePolicyId::parse("parity-policy").unwrap(),
                    vec![requirement(role, quantifier, mask), requirement(ParticipantRole::Root, AssuranceQuantifier::Any, 0)]).unwrap();
                for time in [0, 40, 50, u64::MAX] {
                    for length in 0..=reports.len() {
                        for reverse in [false, true] {
                            let mut selected = reports[..length].to_vec();
                            if reverse { selected.reverse(); }
                            assert_eq!(evaluate(&policy, &selected, Timestamp::new(time)),
                                reference::evaluate(&policy, &selected, Timestamp::new(time)));
                            let mut actual_trace = Vec::new();
                            let mut expected_trace = Vec::new();
                            let actual = evaluate_with_implications(&policy, &selected, Timestamp::new(time), |claim, target| {
                                actual_trace.push((claim.clone(), target.clone()));
                                actual_trace.len() % 2 == 1
                            });
                            let expected = reference::evaluate_with_implications(&policy, &selected, Timestamp::new(time), |claim, target| {
                                expected_trace.push((claim.clone(), target.clone()));
                                expected_trace.len() % 2 == 1
                            });
                            assert_eq!(actual_trace, expected_trace, "mask={mask}, time={time}, reverse={reverse}");
                            assert_eq!(actual, expected, "mask={mask}, time={time}, reverse={reverse}");
                        }
                    }
                }
            }
        }
    }
    for position in [0, 1, 2, usize::MAX] {
        assert_eq!(grant_issuer_role(position), reference::grant_issuer_role(position));
    }
}

#[test]
fn minimum_witness_and_any_every_boundaries_are_useful() {
    let reports = vec![report("test:alice", ParticipantRole::Actor, "adapter-a", 1, vec![
        claim("claim-b", "hardware", Some(50), "attestation"),
        claim("claim-a", "hardware", Some(40), "attestation"),
    ]), report("test:bob", ParticipantRole::Actor, "adapter-a", 1, vec![])];
    let any = AssurancePolicy::new(AssurancePolicyId::parse("any-policy").unwrap(),
        vec![requirement(ParticipantRole::Actor, AssuranceQuantifier::Any, 0)]).unwrap();
    let result = evaluate_with_implications(&any, &reports, Timestamp::new(50), |_, _| true).unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].claim().kind().as_str(), "claim-a");
    let every = AssurancePolicy::new(AssurancePolicyId::parse("every-policy").unwrap(),
        vec![requirement(ParticipantRole::Actor, AssuranceQuantifier::Every, 0)]).unwrap();
    assert_eq!(evaluate_with_implications(&every, &reports, Timestamp::new(50), |_, _| true),
        Err(Requirement::AssuranceRequirementNotMet));
    assert_eq!(evaluate_with_implications(&any, &[], Timestamp::new(50), |_, _| true),
        Err(Requirement::AssuranceRequirementNotMet));
}
