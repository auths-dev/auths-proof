//! Reference/control stage parity against the frozen pre-cutover bodies.
//! Full stage values retain the decoded bytes, source indices, control results
//! and work counters, so equality checks more than the final decision code.

use super::*;
use auths_did_key::DidKeyMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_signature::{Ed25519Suite, P256Sha256Suite};

fn evidence_for(bundle: &ProofBundle, statement: StatementRef)
-> Result<Vec<&EvidenceObject>, VerificationFailure> {
    let binding = bundle.bindings().iter().find(|binding| binding.statement() == statement)
        .ok_or(VerificationFailure::Indeterminate(Requirement::MissingPrincipalEvidence))?;
    binding.evidence().iter().map(|id| bundle.evidence().iter().find(|evidence| evidence.id() == *id)
        .ok_or(VerificationFailure::Denied(DenialReason::MissingReference))).collect()
}

#[test]
fn every_reachable_corpus_stage_preserves_complete_values_and_first_error() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let empty_methods: [&dyn PrincipalMethod; 0] = [];
    let empty_suites: [&dyn SignatureSuite; 0] = [];
    let full = ImmutableRegistries::new(&methods, &suites).unwrap();
    let absent = ImmutableRegistries::new(&empty_methods, &empty_suites).unwrap();
    let mut reached = Vec::new();
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        for registries in [&full, &absent] {
            let context = context.with_configuration(registries.configuration_id()).unwrap();
            let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
            let actual = resolve_proof(decoded.clone(), &context);
            let expected = reference_stages::resolve_proof(decoded, &context);
            assert_eq!(actual, expected, "{} reference stage", fixture.name());
            if let (Ok(actual), Ok(expected)) = (actual, expected) {
                let actual = verify_principal_control(actual, &context, registries);
                let expected = reference_stages::verify_principal_control(expected, &context, registries);
                assert_eq!(actual, expected, "{} control stage", fixture.name());
                reached.push(fixture.name());
            }
        }
    }
    for name in ["closed-raw-key-ed25519", "closed-raw-key-p256", "closed-did-key-ed25519", "closed-did-key-p256"] {
        assert!(reached.contains(&name), "positive {name} must reach both stage implementations");
    }
}

#[test]
fn actual_signature_step_preserves_failures_and_reservation_state() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let mut exercised = 0;
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
        let bundle = decoded.bundle();
        for action in bundle.actions() {
            let identifier = action_id(action.envelope()).unwrap();
            let preimage = action_signing_preimage(action.envelope(), action.signature().descriptor()).unwrap();
            for allowance in [0, 1, 99, 100, 101, 199, 200, 201, 10_000] {
                let mut actual_meter = WorkMeter::new(allowance);
                let mut expected_meter = WorkMeter::new(allowance);
                let actual = evaluate_signature(action.envelope().actor(), action.signature(), &preimage,
                    ControlPurpose::CapabilityInvocation, action.envelope().validity().not_before(),
                    || evidence_for(bundle, StatementRef::Action(identifier)), &context, &registries, &mut actual_meter);
                let expected = reference_stages::evaluate_signature(action.envelope().actor(), action.signature(), &preimage,
                    ControlPurpose::CapabilityInvocation, action.envelope().validity().not_before(),
                    || evidence_for(bundle, StatementRef::Action(identifier)), &context, &registries, &mut expected_meter);
                assert_eq!(actual, expected, "{} allowance={allowance}", fixture.name());
                assert_eq!(actual_meter, expected_meter, "{} reservations", fixture.name());
            }
            exercised += 1;
        }
    }
    assert!(exercised >= 4, "the actual signature step needs useful positive coverage");
}

#[test]
fn mismatched_configuration_is_refused_before_control_work() {
    let fixture = auths_testkit::closed_signature_vectors().remove(0);
    let context = decode_verifier_context(fixture.context_bytes()).unwrap();
    let decoded = decode_proof(fixture.proof_bytes(), &context).unwrap();
    let resolved = resolve_proof(decoded, &context).unwrap();
    let raw = RawKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 1] = [&raw];
    let suites: [&dyn SignatureSuite; 1] = [&ed];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    assert_ne!(context.configuration(), registries.configuration_id());
    let expected = Err(VerificationFailure::Denied(DenialReason::VerifierConfigurationMismatch));
    assert_eq!(verify_principal_control(resolved.clone(), &context, &registries), expected);
    assert_eq!(reference_stages::verify_principal_control(resolved, &context, &registries), expected);
}

#[test]
fn action_binding_and_attachments_preserve_every_corpus_result_and_meter() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let mut exercised = 0;
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        let context = context.with_configuration(registries.configuration_id()).unwrap();
        let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
        let Ok(resolved) = resolve_proof(decoded, &context) else { continue; };
        let Ok(controlled) = verify_principal_control(resolved, &context, &registries) else { continue; };
        for allowance in [0, 1, 99, 100, 101, 10_000, context.limits().max_work_units()] {
            let mut actual_meter = WorkMeter::from_used(allowance, controlled.work_units());
            let mut expected_meter = actual_meter;
            let actual = validate_action_binding(&controlled, fixture.canonical_action(), &context, &registries, &mut actual_meter);
            let expected = reference_stages::validate_action_binding(&controlled, fixture.canonical_action(), &context, &registries, &mut expected_meter);
            assert_eq!(actual, expected, "{} binding allowance={allowance}", fixture.name());
            assert_eq!(actual_meter, expected_meter, "{} binding reservations", fixture.name());
        }
        exercised += 1;
    }
    assert!(exercised >= 4, "the binding comparison must include the useful closed configurations");
}

#[test]
fn complete_branch_results_cached_approvals_and_meter_match_the_frozen_stage() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let mut exercised = 0;
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        let context = context.with_configuration(registries.configuration_id()).unwrap();
        let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
        let Ok(resolved) = resolve_proof(decoded, &context) else { continue; };
        let Ok(controlled) = verify_principal_control(resolved, &context, &registries) else { continue; };
        let bundle = controlled.resolved.decoded.bundle();
        let inputs = approval::Inputs { controlled: &controlled, canonical: fixture.canonical_action(), context: &context, registries: &registries };
        let mut identifiers: Vec<_> = approval::context_requirements(&context).unwrap().into_iter().map(|(id, _)| id).collect();
        for action in bundle.actions() {
            let chain = branch_chain(&controlled.resolved, action).unwrap();
            if let Ok(requirements) = approval::chain_requirements(&chain) {
                identifiers.extend(requirements.into_iter().map(|(id, _)| id));
            }
        }
        for allowance in [0, 100, 10_000, context.limits().max_work_units()] {
            let mut actual_approvals = approval::Approvals::new(bundle).unwrap();
            let mut expected_approvals = approval::Approvals::new(bundle).unwrap();
            let mut actual_meter = WorkMeter::from_used(allowance, controlled.work_units());
            let mut expected_meter = actual_meter;
            for action in bundle.actions() {
                let reference = action.envelope().proof_ref();
                for _ in 0..2 {
                    let actual = verify_branch(&controlled, reference, fixture.canonical_action(), &context, &registries,
                        &mut actual_meter, &mut actual_approvals, &inputs);
                    let expected = reference_stages::verify_branch(&controlled, reference, fixture.canonical_action(), &context, &registries,
                        &mut expected_meter, &mut expected_approvals, &inputs);
                    assert_eq!(actual, expected, "{} branch allowance={allowance}", fixture.name());
                    assert_eq!(actual_meter, expected_meter, "{} branch meter", fixture.name());
                    assert_eq!(actual_approvals.satisfactions(&identifiers), expected_approvals.satisfactions(&identifiers));
                    assert_eq!(actual_approvals.valid_through(&identifiers), expected_approvals.valid_through(&identifiers));
                }
                exercised += 1;
            }
        }
    }
    assert!(exercised >= 4);
}
