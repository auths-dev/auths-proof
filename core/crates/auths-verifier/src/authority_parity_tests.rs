//! Complete authority values, refusal order, charged work and diagnostics
//! against the frozen pre-cutover aggregation. Earlier stages have independent
//! regression comparisons; both paths here consume identical controlled input.

use super::*;
use auths_did_key::DidKeyMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_signature::{Ed25519Suite, P256Sha256Suite};

#[test]
fn full_authority_and_diagnostics_match_the_original_aggregation() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let full = ImmutableRegistries::new(&methods, &suites).unwrap();
    let absent = ImmutableRegistries::new(&[], &[]).unwrap();
    let mut authorized = Vec::new();
    for fixture in auths_testkit::corpus() {
        let Ok(context) = decode_verifier_context(fixture.context_bytes()) else { continue; };
        for registries in [&full, &absent] {
            let context = context.with_configuration(registries.configuration_id()).unwrap();
            let Ok(decoded) = decode_proof(fixture.proof_bytes(), &context) else { continue; };
            let Ok(resolved) = resolve_proof(decoded, &context) else { continue; };
            let Ok(controlled) = verify_principal_control(resolved, &context, registries) else { continue; };
            for collect in [false, true] {
                for allowance in [0, 99, 100, 101, context.limits().max_work_units()] {
                    let mut actual_meter = WorkMeter::from_used(allowance, controlled.work_units());
                    let mut expected_meter = actual_meter;
                    let mut actual_diagnostics = if collect { AuthorityDiagnostics::collect() } else { AuthorityDiagnostics::discard() };
                    let mut expected_diagnostics = if collect { AuthorityDiagnostics::collect() } else { AuthorityDiagnostics::discard() };
                    let actual = authority::verify_authority_measured(controlled.clone(), fixture.canonical_action(),
                        &context, registries, &mut actual_meter, &mut actual_diagnostics);
                    let expected = authority_reference::verify_authority_measured(controlled.clone(), fixture.canonical_action(),
                        &context, registries, &mut expected_meter, &mut expected_diagnostics);
                    assert_eq!(actual, expected, "{} collect={collect} allowance={allowance}", fixture.name());
                    assert_eq!(actual_meter, expected_meter, "{} full authority work", fixture.name());
                    assert_eq!(actual_diagnostics.plan_events, expected_diagnostics.plan_events);
                    assert_eq!(actual_diagnostics.context_approvals, expected_diagnostics.context_approvals);
                    assert_eq!((actual_diagnostics.authorized_branches, actual_diagnostics.distinct_actors, actual_diagnostics.distinct_roots),
                        (expected_diagnostics.authorized_branches, expected_diagnostics.distinct_actors, expected_diagnostics.distinct_roots));
                    if actual.is_ok() { authorized.push(fixture.name()); }
                }
            }
        }
    }
    for name in ["closed-raw-key-ed25519", "closed-raw-key-p256", "closed-did-key-ed25519", "closed-did-key-p256"] {
        assert!(authorized.contains(&name), "useful authority path {name} must authorize");
    }
}
