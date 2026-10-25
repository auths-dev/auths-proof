//! Full dispatch results and charged work against the pre-cutover source.
//! The independent assurance evaluator has its own frozen-body comparison.

use super::*;
use auths_did_key::DidKeyMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_signature::{Ed25519Suite, P256Sha256Suite};

#[test]
fn actual_extension_and_assurance_dispatch_preserve_results_and_work() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let full = ImmutableRegistries::new(&methods, &suites).unwrap();
    let absent = ImmutableRegistries::new(&[], &[]).unwrap();
    let mut reached = 0;
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        for registries in [&full, &absent] {
            let context = context.with_configuration(registries.configuration_id()).unwrap();
            let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
            let bundle = decoded.bundle();
            for allowance in [0, 1, 99, 100, 101, 10_000, context.limits().max_work_units()] {
                for extensions in bundle.grants().iter().map(|grant| grant.statement().extensions())
                    .chain(bundle.actions().iter().map(|action| action.envelope().extensions())) {
                    let mut actual_meter = WorkMeter::new(allowance);
                    let mut expected_meter = actual_meter;
                    assert_eq!(policy::evaluate_extensions(extensions, &context, registries, &mut actual_meter),
                        reference_stages::evaluate_extensions(extensions, &context, registries, &mut expected_meter),
                        "{} extensions allowance={allowance}", fixture.name());
                    assert_eq!(actual_meter, expected_meter);
                }
            }
            let Ok(resolved) = resolve_proof(decoded, &context) else { continue; };
            let Ok(controlled) = verify_principal_control(resolved, &context, registries) else { continue; };
            let mut reports = Vec::new();
            for control in &controlled.controls {
                if let Ok(evidence) = &control.result {
                    for role in [ParticipantRole::Root, ParticipantRole::Intermediate, ParticipantRole::Actor] {
                        reports.push(ParticipantAssurance::new(control.principal.clone(), role,
                            evidence.claims().to_vec(), evidence.consumed_evidence().to_vec(),
                            evidence.adapter().clone(), evidence.adapter_version()).unwrap());
                    }
                }
            }
            for length in 0..=reports.len() {
                for allowance in [0, 1, 99, 100, 101, 10_000, context.limits().max_work_units()] {
                    let mut actual_meter = WorkMeter::new(allowance);
                    let mut expected_meter = actual_meter;
                    assert_eq!(policy::evaluate_branch_assurance(&reports[..length], &context, registries, &mut actual_meter),
                        reference_stages::evaluate_branch_assurance(&reports[..length], &context, registries, &mut expected_meter),
                        "{} assurance prefix={length} allowance={allowance}", fixture.name());
                    assert_eq!(actual_meter, expected_meter);
                }
            }
            reached += 1;
        }
    }
    assert!(reached >= 4, "include the four useful closed principal/signature combinations");
}
