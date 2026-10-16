//! Boundary witnesses for the actual temporal functions in the qualified slice.

use super::{VerificationFailure, assurance_horizon, status_decision, status_horizon};
use auths_model::{
    AssuranceClaim, AssurancePolicy, AssuranceRequirement, AssuranceSatisfaction, EvidenceId,
    EvidenceSourceId, FreshnessLimit, Requirement, Timestamp, TrustedContext,
};
use auths_ports::{StatusDecision, StatusEvaluation};

fn context(maximum_age: Option<u64>) -> TrustedContext {
    let fixture = auths_testkit::raw_key_chain();
    let source = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
    let existing = source.assurance_policy().requirements().first().unwrap();
    let requirement = AssuranceRequirement::new(
        existing.role(),
        existing.quantifier(),
        existing.claim_kind().clone(),
        maximum_age.map(|age| FreshnessLimit::new(age).unwrap()),
    );
    let policy =
        AssurancePolicy::new(source.assurance_policy().id().clone(), vec![requirement]).unwrap();
    TrustedContext::new(
        source.configuration(),
        source.composition(),
        source.trust_anchors().to_vec(),
        source.accepted_registries().clone(),
        source.expected_audience().clone(),
        source.expected_challenge(),
        source.evaluation_time(),
        policy,
        source.principal_status_snapshot().clone(),
        source.grant_status_snapshot().clone(),
        source.resource_matcher().clone(),
        source.profile_policy().clone(),
        source.channel_policy().clone(),
        source.limits().clone(),
    )
    .unwrap()
}

fn witness(
    context: &TrustedContext,
    index: u16,
    observed_at: Option<u64>,
) -> AssuranceSatisfaction {
    let claim = AssuranceClaim::new(
        context.assurance_policy().requirements()[0]
            .claim_kind()
            .clone(),
        Vec::new(),
        observed_at.map(Timestamp::new),
        EvidenceSourceId::parse("temporal-boundary-test").unwrap(),
    )
    .unwrap();
    AssuranceSatisfaction::new(
        index,
        context.trust_anchors()[0].principal().clone(),
        claim,
        vec![EvidenceId::new([1; 32])],
    )
}

#[test]
fn temporal_status_needs_active_and_an_inclusive_current_horizon() {
    for decision in [
        StatusDecision::Active,
        StatusDecision::Revoked,
        StatusDecision::Missing,
        StatusDecision::Stale,
        StatusDecision::Rollback,
        StatusDecision::UntrustedIssuer,
        StatusDecision::WrongMethod,
    ] {
        for principal in [false, true] {
            for now in [99, 100, 101] {
                let evaluation = StatusEvaluation::new(decision, Timestamp::new(100));
                let admitted = status_decision(decision, principal).is_ok()
                    && status_horizon(evaluation, Timestamp::new(now)).is_ok();
                assert_eq!(admitted, decision == StatusDecision::Active && now <= 100);
            }
        }
    }
    assert_eq!(
        status_horizon(
            StatusEvaluation::new(StatusDecision::Active, Timestamp::new(100)),
            Timestamp::new(101),
        ),
        Err(VerificationFailure::Indeterminate(Requirement::StaleStatus))
    );
}

#[test]
fn temporal_selected_assurance_expiry_is_the_minimum() {
    let context = context(Some(20));
    let selected = [
        witness(&context, 0, Some(40)),
        witness(&context, 0, Some(45)),
    ];
    assert_eq!(
        assurance_horizon(&selected, &context),
        Ok(Timestamp::new(60))
    );
    assert_eq!(
        assurance_horizon(&selected[1..], &context),
        Ok(Timestamp::new(65))
    );
}

#[test]
fn temporal_missing_selected_metadata_fails_closed() {
    let context = context(Some(20));
    let refused = Err(VerificationFailure::Indeterminate(
        Requirement::AssuranceRequirementNotMet,
    ));
    assert_eq!(
        assurance_horizon(&[witness(&context, 1, Some(100))], &context),
        refused
    );
    assert_eq!(
        assurance_horizon(&[witness(&context, 0, None)], &context),
        refused
    );
}

#[test]
fn temporal_unbounded_rule_does_not_require_an_observation_time() {
    let context = context(None);
    assert_eq!(
        assurance_horizon(&[witness(&context, 0, None)], &context),
        Ok(Timestamp::new(u64::MAX))
    );
    assert_eq!(
        assurance_horizon(&[], &context),
        Ok(Timestamp::new(u64::MAX))
    );
}

#[test]
fn temporal_expiry_overflow_saturates_without_reopening_an_earlier_bound() {
    let context = context(Some(20));
    let overflow = witness(&context, 0, Some(u64::MAX));
    assert_eq!(
        assurance_horizon(core::slice::from_ref(&overflow), &context),
        Ok(Timestamp::new(u64::MAX))
    );
    let selected = [overflow, witness(&context, 0, Some(40))];
    assert_eq!(
        assurance_horizon(&selected, &context),
        Ok(Timestamp::new(60))
    );
}
