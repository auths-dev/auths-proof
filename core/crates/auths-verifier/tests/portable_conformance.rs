//! Portable-ABI conformance of the native verifier.
//!
//! The corpus test in the crate exercises the in-process API. These tests run
//! the byte-oriented portable entry points on the same inputs the Go and
//! TypeScript verifiers read, and on every adversarial-conformance case whose
//! recipe produces full verifier inputs, so a regression that only those
//! suites would notice fails `cargo test` as well.

use auths_model::{VerificationDecision, VerificationStage};
use auths_ports::{PrincipalMethod, SignatureSuite};
use auths_registries::ImmutableRegistries;
use auths_testkit::{
    Expected,
    conformance::{BoundaryExecution, ConformanceManifest, execute_case},
};

fn with_corpus_registries(run: impl FnOnce(&ImmutableRegistries<'_>)) {
    let raw_key = auths_raw_key::RawKeyMethod::new().unwrap();
    let did_key = auths_did_key::DidKeyMethod::new().unwrap();
    let did_keri = auths_did_keri::DidKeriMethod::new().unwrap();
    let did_web =
        auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records()).unwrap();
    let webauthn =
        auths_webauthn::WebAuthnMethod::new(auths_testkit::webauthn_corpus_credentials()).unwrap();
    let hsm =
        auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records()).unwrap();
    let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
    let spiffe = auths_testkit::spiffe_corpus_method(spiffe_trust, spiffe_status).unwrap();
    let ed25519 = auths_signature::Ed25519Suite::new().unwrap();
    let p256 = auths_signature::P256Sha256Suite::new().unwrap();
    let methods: [&dyn PrincipalMethod; 7] = [
        &raw_key, &did_key, &did_keri, &did_web, &webauthn, &hsm, &spiffe,
    ];
    let suites: [&dyn SignatureSuite; 2] = [&ed25519, &p256];
    run(&ImmutableRegistries::new(&methods, &suites).unwrap());
}

#[test]
fn every_corpus_vector_returns_its_decision_through_the_portable_abi() {
    with_corpus_registries(|registries| {
        for fixture in auths_testkit::corpus() {
            let action = auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
            let bytes = auths_verifier::verify_v1(
                fixture.proof_bytes(),
                &action,
                fixture.context_bytes(),
                registries,
            )
            .unwrap();
            let result = auths_codec::decode_verification_result(&bytes).unwrap();
            let (decision, code) = match fixture.expected() {
                Expected::Authorized => (VerificationDecision::Authorized, "authorized"),
                Expected::Denied(reason) => (VerificationDecision::Denied, reason.code()),
                Expected::Indeterminate(requirement) => {
                    (VerificationDecision::Indeterminate, requirement.code())
                }
            };
            assert_eq!(result.decision(), decision, "{}", fixture.name());
            assert_eq!(result.code().code(), code, "{}", fixture.name());
            if decision == VerificationDecision::Authorized {
                assert_eq!(
                    result.stage(),
                    VerificationStage::Complete,
                    "{}",
                    fixture.name()
                );
            }
        }
    });
}

#[test]
fn every_adversarial_conformance_case_returns_its_exact_code() {
    let manifest =
        ConformanceManifest::parse(include_bytes!("../../../conformance/v1/manifest.json"))
            .unwrap();
    with_corpus_registries(|registries| {
        let mut full_verifier_cases = 0usize;
        for case in &manifest.cases {
            let actual = match execute_case(&case.case).unwrap() {
                BoundaryExecution::Completed(code) => code.to_owned(),
                BoundaryExecution::FullVerifier(fixture) => {
                    full_verifier_cases += 1;
                    let context =
                        auths_codec::decode_verifier_context(fixture.context_bytes()).unwrap();
                    auths_verifier::verify_portable(
                        fixture.proof_bytes(),
                        fixture.canonical_action(),
                        &context,
                        registries,
                    )
                    .code()
                    .code()
                    .to_owned()
                }
            };
            assert_eq!(actual, case.expected_code, "{}", case.case);
        }
        assert!(
            full_verifier_cases > 0,
            "the manifest has no full-verifier case"
        );
    });
}
