//! Frozen observation-stage comparison. The explicit adapter-resource case
//! records the deliberate correction to the old ignore behavior.

use super::*;
use auths_did_key::DidKeyMethod;
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_raw_key::RawKeyMethod;
use auths_registries::ImmutableRegistries;
use auths_signature::{Ed25519Suite, P256Sha256Suite};
use core::cell::Cell;

#[test]
fn reachable_observation_stages_preserve_results_and_meter() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let mut exercised = 0;
    for fixture in auths_testkit::corpus() {
        let Ok(context) = auths_codec::decode_verifier_context(fixture.context_bytes()) else { continue; };
        let context = context.with_configuration(registries.configuration_id()).unwrap();
        let Ok(decoded) = crate::decode_proof(fixture.proof_bytes(), &context) else { continue; };
        let Ok(resolved) = crate::resolve_proof(decoded, &context) else { continue; };
        let Ok(controlled) = crate::verify_principal_control(resolved, &context, &registries) else { continue; };
        for action in controlled.resolved.decoded.bundle().actions() {
            let chain = crate::branch_chain(&controlled.resolved, action).unwrap();
            assert_eq!(chain_requirements(&chain), reference::chain_requirements(&chain), "{} requirements", fixture.name());
            for pair in chain.windows(2) {
                assert_eq!(require_parent_requirements(pair[0], pair[1]),
                    reference::require_parent_requirements(pair[0], pair[1]), "{} retention", fixture.name());
            }
            let root = chain.first().map_or(action.envelope().actor(), |grant| grant.statement().issuer());
            let actual = Stage { chain: &chain, root, action, canonical: fixture.canonical_action(), context: &context, registries: &registries };
            let expected = reference::Stage { chain: &chain, root, action, canonical: fixture.canonical_action(), context: &context, registries: &registries };
            for allowance in [0, 1, 99, 100, 101, 10_000, context.limits().max_work_units()] {
                let mut actual_meter = WorkMeter::from_used(allowance, controlled.work_units());
                let mut expected_meter = actual_meter;
                assert_eq!(actual.evaluate(&mut actual_meter), expected.evaluate(&mut expected_meter),
                    "{} observation allowance={allowance}", fixture.name());
                assert_eq!(actual_meter, expected_meter, "{} observation meter", fixture.name());
            }
            exercised += 1;
        }
    }
    assert!(exercised >= 4);
}

struct ExhaustedMethod { id: auths_model::PrincipalMethodId, calls: Cell<usize> }
impl PrincipalMethod for ExhaustedMethod {
    fn id(&self) -> &auths_model::PrincipalMethodId { &self.id }
    fn configuration_id(&self) -> auths_model::AdapterConfigurationId { auths_model::AdapterConfigurationId::new([0x54; 32]) }
    fn maximum_work_units(&self) -> u64 { 1 }
    fn verify_control(&self, _: PrincipalControlInput<'_>) -> Result<ControlEvidence, PrincipalControlError> {
        self.calls.set(self.calls.get() + 1);
        Err(PrincipalControlError::ResourceLimitExceeded)
    }
}

#[test]
fn adapter_resource_exhaustion_is_a_stage_refusal() {
    let fixture = auths_testkit::corpus().into_iter().find(|case| case.name() == "observation-satisfied").unwrap();
    let context = auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
    let bundle = auths_codec::decode_bundle(fixture.proof_bytes(), context.limits()).unwrap();
    let observation = fixture.canonical_action().detached_attachments().iter()
        .find_map(|attachment| decode_signed_observation(attachment.bytes(), context.limits()).ok()).unwrap();
    let method = ExhaustedMethod { id: observation.signature().descriptor().principal_method().clone(), calls: Cell::new(0) };
    let suite = Ed25519Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 1] = [&method];
    let suites: [&dyn SignatureSuite; 1] = [&suite];
    let registries = ImmutableRegistries::new(&methods, &suites).unwrap();
    let context = context.with_configuration(registries.configuration_id()).unwrap();
    let action = &bundle.actions()[0];
    let actual = Stage { chain: &[], root: action.envelope().actor(), action,
        canonical: fixture.canonical_action(), context: &context, registries: &registries };
    let expected = reference::Stage { chain: &[], root: action.envelope().actor(), action,
        canonical: fixture.canonical_action(), context: &context, registries: &registries };
    let mut actual_meter = WorkMeter::new(1_000);
    let mut expected_meter = actual_meter;
    assert_eq!(actual.authentic(&observation, &mut actual_meter),
        Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)));
    assert_eq!(expected.authentic(&observation, &mut expected_meter), Ok(false), "the frozen body exhibits the old swallowed failure");
    assert_eq!(actual_meter, expected_meter);
    assert_eq!(method.calls.get(), 2);
}

#[test]
fn control_classification_preserves_payload_and_ordinary_invalid_evidence_is_ignored() {
    assert_eq!(control_result::<u64>(Ok(7)), Ok(Some(7)));
    assert_eq!(control_result::<u64>(Err(PrincipalControlError::InvalidEvidence)), Ok(None));
    assert_eq!(control_result::<u64>(Err(PrincipalControlError::ExternalFactUnavailable)), Ok(None));
    assert_eq!(control_result::<u64>(Err(PrincipalControlError::ResourceLimitExceeded)),
        Err(VerificationFailure::Denied(DenialReason::ResourceLimitExceeded)));
}
