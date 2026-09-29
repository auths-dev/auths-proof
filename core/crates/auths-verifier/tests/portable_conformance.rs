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
            let action = fixture.action_bytes();
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
            // Raw canonical-action bytes are rejected before the proof is read.
            if fixture.has_raw_action() {
                assert_eq!(
                    result.stage(),
                    VerificationStage::Decode,
                    "{}",
                    fixture.name()
                );
                assert_eq!(result.plan_id(), None, "{}", fixture.name());
            }
        }
    });
}

/// A CBOR text item.
fn cbor_text(value: &str) -> Vec<u8> {
    let length = value.len();
    let mut output = match u8::try_from(length) {
        Ok(short) if short < 24 => vec![0x60 | short],
        Ok(byte) => vec![0x78, byte],
        Err(_) => {
            let wide = u16::try_from(length).unwrap().to_be_bytes();
            vec![0x79, wide[0], wide[1]]
        }
    };
    output.extend_from_slice(value.as_bytes());
    output
}

/// Replaces the first occurrence of `from` in `source`.
fn replace_first(source: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let position = source
        .windows(from.len())
        .position(|window| window == from)
        .expect("splice site");
    let mut output = source[..position].to_vec();
    output.extend_from_slice(to);
    output.extend_from_slice(&source[position + from.len()..]);
    output
}

/// The three status scopes a context must refuse, spliced into the encoded
/// context of `status-scope-baseline`, whose rules all have floor 1 and scope
/// `own`. The model constructors run before the decoder's canonical
/// re-encoding check, so the order of an added rule does not matter.
fn invalid_scope_contexts() -> Vec<(&'static str, Vec<u8>)> {
    let fixture = auths_testkit::status_scope_baseline();
    let context = fixture.context_bytes();
    let decoded = auths_codec::decode_verifier_context(context).unwrap();
    let issuer = decoded.principal_status_snapshot().trust()[0]
        .issuer()
        .as_str();
    // Floor 1, then key 3 and the `own` scope `{0: 0}`.
    let own_tail = [0x02, 0x01, 0x03, 0xa1, 0x00, 0x00];

    let mut absent_anchor = vec![0x02, 0x01, 0x03, 0xa2, 0x00, 0x01, 0x01, 0x81];
    absent_anchor.extend_from_slice(&cbor_text("no-such-anchor"));

    let mut named = cbor_text(issuer);
    named.extend_from_slice(&own_tail);
    let mut service = cbor_text("raw:status-service");
    service.extend_from_slice(&own_tail);

    // The principal snapshot's rules: key 5, then an array of two rules.
    let mut second_rule = vec![0x05, 0x83, 0xa4, 0x00];
    second_rule.extend_from_slice(&cbor_text("other-principal-status-v1"));
    second_rule.push(0x01);
    second_rule.extend_from_slice(&cbor_text(issuer));
    second_rule.extend_from_slice(&[0x02, 0x01, 0x03, 0xa1, 0x00, 0x02, 0xa4, 0x00]);

    vec![
        (
            "a rule lists an anchor the context does not hold",
            replace_first(context, &own_tail, &absent_anchor),
        ),
        (
            "an own rule names an issuer that is no anchor's principal",
            replace_first(context, &named, &service),
        ),
        (
            "one issuer has two scopes in one snapshot",
            replace_first(context, &[0x05, 0x82, 0xa4, 0x00], &second_rule),
        ),
    ]
}

#[test]
fn invalid_status_scopes_are_malformed_at_decode() {
    let fixture = auths_testkit::status_scope_baseline();
    let action = fixture.action_bytes();
    with_corpus_registries(|registries| {
        for (name, context) in invalid_scope_contexts() {
            assert!(
                matches!(
                    auths_codec::decode_verifier_context(&context),
                    Err(auths_codec::CodecError::Model(
                        auths_model::ModelError::InvalidVerifierContext
                    ))
                ),
                "{name}"
            );
            let result = auths_codec::decode_verification_result(
                &auths_verifier::verify_v1(fixture.proof_bytes(), &action, &context, registries)
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(result.decision(), VerificationDecision::Denied, "{name}");
            assert_eq!(result.code().code(), "malformed-proof", "{name}");
            assert_eq!(result.stage(), VerificationStage::Decode, "{name}");
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
