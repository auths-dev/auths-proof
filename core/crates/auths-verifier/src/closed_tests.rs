use super::*;
use alloc::vec::Vec;
use auths_codec::{decode_verifier_context, encode_verifier_context};
use auths_model::{
    DenialReason, Requirement, VerificationCode, VerificationDecision,
};
use auths_registries::ImmutableRegistries;

fn context_for(fixture: &auths_testkit::CorpusFixture, registries: &ClosedRegistries) -> Vec<u8> {
    let context = decode_verifier_context(fixture.context_bytes()).expect("fixture context");
    let context = context.with_configuration(registries.configuration_id()).expect("configuration");
    auths_codec::CanonicalTrustedContext::new(auths_model::TrustedContext::clone(&context)).and_then(|canonical| encode_verifier_context(&canonical)).expect("context encoding")
}

#[test]
fn closed_constructor_rejects_duplicate_handlers() {
    assert!(matches!(ClosedRegistries::new(
        [Some(PrincipalKind::RawKeyV1), Some(PrincipalKind::RawKeyV1)], [None, None],
    ), Err(RegistryError::DuplicateImplementation)));
    assert!(matches!(ClosedRegistries::new(
        [None, None], [Some(SuiteKind::Ed25519V1), Some(SuiteKind::Ed25519V1)],
    ), Err(RegistryError::DuplicateImplementation)));
}

#[test]
fn configuration_is_independent_of_slot_order_and_matches_open_registry() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let open = ImmutableRegistries::new(&methods, &suites).unwrap();
    let closed = ClosedRegistries::standard().unwrap();
    let reversed = ClosedRegistries::new(
        [Some(PrincipalKind::DidKeyV1), Some(PrincipalKind::RawKeyV1)],
        [Some(SuiteKind::P256Sha256V1), Some(SuiteKind::Ed25519V1)],
    ).unwrap();
    assert_eq!(closed.manifest_id(), open.manifest_id());
    assert_eq!(closed.configuration_id(), open.configuration_id());
    assert_eq!(closed.configuration_id(), reversed.configuration_id());
    let first = ClosedRegistries::new([Some(PrincipalKind::RawKeyV1), None],
        [Some(SuiteKind::Ed25519V1), None]).unwrap();
    let last = ClosedRegistries::new([None, Some(PrincipalKind::RawKeyV1)],
        [None, Some(SuiteKind::Ed25519V1)]).unwrap();
    assert_eq!(first.configuration_id(), last.configuration_id());
    assert_ne!(closed.configuration_id(), first.configuration_id());
}

#[test]
fn full_corpus_has_identical_portable_results_and_sealed_capabilities() {
    let raw = RawKeyMethod::new().unwrap();
    let did = DidKeyMethod::new().unwrap();
    let ed = Ed25519Suite::new().unwrap();
    let p256 = P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 2] = [&raw, &did];
    let suites: [&dyn SignatureSuite; 2] = [&ed, &p256];
    let open = ImmutableRegistries::new(&methods, &suites).unwrap();
    let closed = ClosedRegistries::standard().unwrap();
    for fixture in auths_testkit::corpus() {
        // Re-provision only the executable roster. A malformed context remains
        // the identical malformed bytes on both paths. No proof/action/signature
        // is rewritten and both paths receive precisely the same three inputs.
        let context = match decode_verifier_context(fixture.context_bytes()) {
            Ok(_) => context_for(&fixture, &closed),
            Err(_) => fixture.context_bytes().to_vec(),
        };
        let action = fixture.action_bytes();
        let actual = verify_v1_sealed(fixture.proof_bytes(), &action, &context, &closed);
        let expected = crate::verify_v1_sealed(fixture.proof_bytes(), &action, &context, &open);
        assert_eq!(actual, expected, "{}", fixture.name());
        if let Ok(result) = &actual {
            let portable = result.portable();
            assert_eq!(auths_codec::decode_verification_result(result.cbor()).unwrap().into_value(), *portable,
                "{} canonical portable result", fixture.name());
            assert_eq!(result.action().is_some(), portable.decision() == VerificationDecision::Authorized,
                "{} capability availability", fixture.name());
            if let Some(capability) = result.action() {
                assert_eq!(capability.canonical_action(), fixture.canonical_action());
                assert_eq!(capability.proof_digest(), portable.proof_digest());
                assert_eq!(capability.context_digest(), portable.context_digest());
                assert_eq!(Some(capability.plan_id()), portable.plan_id());
                assert_eq!(capability.authorized_branches(), portable.authorized_branches());
                assert_eq!(capability.assurance(), portable.assurance());
                assert_eq!(capability.assurance_satisfactions(), portable.assurance_satisfactions());
                assert_eq!(capability.observation_satisfactions(), portable.observation_satisfactions());
                assert_eq!(capability.approval_satisfactions(), portable.approval_satisfactions());
                assert_eq!(capability.work_units(), portable.resources().work_units());
                assert_eq!(portable.local_configuration(), closed.configuration_id());
                assert_eq!(portable.required_configuration(), Some(closed.configuration_id()));
            }
        }
        assert_eq!(verify_v1(fixture.proof_bytes(), &action, &context, &closed),
            crate::verify_v1(fixture.proof_bytes(), &action, &context, &open), "{}", fixture.name());
    }
}

#[test]
fn every_closed_principal_suite_combination_authorizes() {
    let closed = ClosedRegistries::standard().unwrap();
    let fixtures = auths_testkit::closed_signature_vectors();
    assert_eq!(fixtures.len(), 4);
    for fixture in fixtures {
        let context = context_for(&fixture, &closed);
        let action = fixture.action_bytes();
        let result = verify_v1_sealed(fixture.proof_bytes(), &action, &context, &closed).unwrap();
        assert_eq!(result.portable().decision(), VerificationDecision::Authorized, "{}", fixture.name());
        assert_eq!(result.action().unwrap().canonical_action(), fixture.canonical_action());
        assert_eq!(result.cbor(), verify_v1(fixture.proof_bytes(), &action, &context, &closed).unwrap());
    }
}

#[test]
fn missing_handlers_and_configuration_mismatch_do_not_release_authority() {
    let fixture = auths_testkit::closed_signature_vectors().remove(0);
    let action = fixture.action_bytes();
    let cases = [
        (ClosedRegistries::new([None, None], [Some(SuiteKind::Ed25519V1), None]).unwrap(),
            VerificationCode::Indeterminate(Requirement::UnsupportedPrincipalMethod)),
        (ClosedRegistries::new([Some(PrincipalKind::RawKeyV1), None], [None, None]).unwrap(),
            VerificationCode::Indeterminate(Requirement::UnsupportedSignatureSuite)),
    ];
    for (registries, code) in cases {
        let context = context_for(&fixture, &registries);
        let result = verify_v1_sealed(fixture.proof_bytes(), &action, &context, &registries).unwrap();
        assert_eq!(result.portable().code(), code);
        assert!(result.action().is_none());
    }
    let raw_only = ClosedRegistries::new([Some(PrincipalKind::RawKeyV1), None],
        [Some(SuiteKind::Ed25519V1), None]).unwrap();
    let context = context_for(&fixture, &raw_only);
    let standard = ClosedRegistries::standard().unwrap();
    let result = verify_v1_sealed(fixture.proof_bytes(), &action, &context, &standard).unwrap();
    assert_eq!(result.portable().code(), VerificationCode::Denied(DenialReason::VerifierConfigurationMismatch));
    assert!(result.action().is_none());
}

#[test]
fn approval_corpus_preserves_distinct_threshold_and_ignore_rules() {
    let closed = ClosedRegistries::standard().unwrap();
    let mut checked = 0;
    let mut authorized = 0;
    for fixture in auths_testkit::corpus().into_iter().filter(|fixture| fixture.name().starts_with("approval-")) {
        let context = context_for(&fixture, &closed);
        let result = verify_v1_sealed(fixture.proof_bytes(), &fixture.action_bytes(), &context, &closed).unwrap();
        let expected = match fixture.expected() {
            auths_testkit::Expected::Authorized => VerificationCode::Authorized,
            auths_testkit::Expected::Denied(reason) => VerificationCode::Denied(reason),
            auths_testkit::Expected::Indeterminate(requirement) => VerificationCode::Indeterminate(requirement),
        };
        assert_eq!(result.portable().code(), expected, "{}", fixture.name());
        assert_eq!(result.action().is_some(), expected == VerificationCode::Authorized, "{}", fixture.name());
        checked += 1;
        authorized += usize::from(expected == VerificationCode::Authorized);
    }
    assert!(checked >= 20);
    assert!(authorized >= 3);
}
