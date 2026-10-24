//! Full candidate/tally regression against the frozen pre-cutover stage.
//! This tests result codes, selected digests, horizons, cache and actual work
//! accounting. It does not stand in for source refinement or backend evidence.

use super::*;
use auths_codec::{decode_verifier_context, encode_signed_approval};
use auths_did_key::DidKeyMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_registries::ImmutableRegistries;
use auths_signature::{Ed25519Suite, P256Sha256Suite};

#[derive(Debug, Eq, PartialEq)]
struct View {
    // Keeping the complete satisfaction, including requirement and digests,
    // detects a representative or action-binding change hidden by a verdict.
    verdict: Result<Option<ApprovalSatisfaction>, ()>,
    counts: ApprovalCounts,
    threshold: u16,
    horizon: Timestamp,
}

fn actual_view(value: Evaluated) -> View {
    let verdict = match value.verdict {
        Verdict::Authorized(satisfaction) => Ok(Some(satisfaction)),
        Verdict::Denied => Err(()),
        Verdict::Indeterminate => Ok(None),
    };
    View { verdict, counts: value.counts, threshold: value.threshold, horizon: value.valid_through }
}

fn reference_view(value: reference::Evaluated) -> View {
    let verdict = match value.verdict {
        reference::Verdict::Authorized(satisfaction) => Ok(Some(satisfaction)),
        reference::Verdict::Denied => Err(()),
        reference::Verdict::Indeterminate => Ok(None),
    };
    View { verdict, counts: value.counts, threshold: value.threshold, horizon: value.valid_through }
}

#[test]
fn complete_approval_stage_preserves_order_results_horizons_and_meter() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let mut exercised = 0;
    for fixture in auths_testkit::corpus().into_iter().filter(|case| case.name().starts_with("approval-")) {
        let context = decode_verifier_context(fixture.context_bytes()).unwrap()
            .with_configuration(registries.configuration_id()).unwrap();
        // Cases with invalid wire/reference material cannot reach this stage.
        // The whole-entry corpus test separately retains their stable result.
        let Ok(decoded) = crate::decode_proof(fixture.proof_bytes(), &context) else { continue; };
        let Ok(resolved) = crate::resolve_proof(decoded, &context) else { continue; };
        let Ok(controlled) = crate::verify_principal_control(resolved, &context, &registries) else { continue; };
        let bundle = controlled.resolved.decoded.bundle();
        let inputs = Inputs { controlled: &controlled, canonical: fixture.canonical_action(), context: &context, registries: &registries };
        let reference_inputs = reference::Inputs { controlled: &controlled, canonical: fixture.canonical_action(), context: &context, registries: &registries };
        let mut requirements = context_requirements(&context).unwrap();
        assert_eq!(requirements, reference::context_requirements(&context).unwrap());
        for action in bundle.actions() {
            if let Ok(chain) = crate::branch_chain(&controlled.resolved, action) {
                let actual = chain_requirements(&chain);
                let expected = reference::chain_requirements(&chain);
                assert_eq!(actual, expected, "{} chain", fixture.name());
                requirements.extend(actual.unwrap());
            }
        }
        if requirements.is_empty() { continue; }
        let candidate_view = |values: &[(ApprovalDigest, &SignedApproval)]| {
            values.iter().map(|(digest, approval)| (*digest, auths_codec::CanonicalSignedApproval::new(auths_model::SignedApproval::clone(approval)).and_then(|canonical| encode_signed_approval(&canonical)).unwrap())).collect::<Vec<_>>()
        };
        let actual = Approvals::new(bundle).unwrap();
        let expected = reference::Approvals::new(bundle).unwrap();
        assert_eq!(candidate_view(&actual.candidates), candidate_view(&expected.candidates), "{} candidates", fixture.name());
        assert_eq!(actual.authority, expected.authority, "{} authority", fixture.name());
        for allowance in [0, 1, 99, 100, 101, 199, 200, 201, 10_000, context.limits().max_work_units()] {
            let mut actual = Approvals::new(bundle).unwrap();
            let mut expected = reference::Approvals::new(bundle).unwrap();
            let mut actual_meter = WorkMeter::new(allowance);
            let mut expected_meter = WorkMeter::new(allowance);
            for (identifier, requirement) in &requirements {
                // Repeat immediately, exercising the real cache on a decided
                // requirement and the failure path when no cache was inserted.
                for _ in 0..2 {
                    let result = actual.evaluate(*identifier, requirement, &inputs, &mut actual_meter).map(actual_view);
                    let oracle = expected.evaluate(*identifier, requirement, &reference_inputs, &mut expected_meter).map(reference_view);
                    assert_eq!(result, oracle, "{} allowance={allowance}", fixture.name());
                    assert_eq!(actual_meter, expected_meter, "{} meter", fixture.name());
                }
                assert_eq!(actual.get(*identifier).cloned().map(actual_view),
                    expected.get(*identifier).cloned().map(reference_view), "{} cache", fixture.name());
            }
            let identifiers: Vec<_> = requirements.iter().map(|(identifier, _)| *identifier).collect();
            assert_eq!(actual.satisfactions(&identifiers), expected.satisfactions(&identifiers));
            assert_eq!(actual.valid_through(&identifiers), expected.valid_through(&identifiers));
        }
        for reverse in [false, true] {
            let mut ordered = requirements.clone();
            if reverse { ordered.reverse(); }
            for allowance in [0, 100, 200, context.limits().max_work_units()] {
                let mut actual = Approvals::new(bundle).unwrap();
                let mut expected = reference::Approvals::new(bundle).unwrap();
                let mut actual_meter = WorkMeter::new(allowance);
                let mut expected_meter = WorkMeter::new(allowance);
                assert_eq!(actual.evaluate_list(&ordered, &inputs, &mut actual_meter),
                    expected.evaluate_list(&ordered, &reference_inputs, &mut expected_meter),
                    "{} list reverse={reverse}", fixture.name());
                assert_eq!(actual_meter, expected_meter);
                let identifiers: Vec<_> = ordered.iter().map(|(identifier, _)| *identifier).collect();
                assert_eq!(actual.satisfactions(&identifiers), expected.satisfactions(&identifiers));
                assert_eq!(actual.valid_through(&identifiers), expected.valid_through(&identifiers));
            }
        }
        exercised += 1;
    }
    assert!(exercised >= 20, "the frozen stage oracle must exercise the real approval corpus");
}
