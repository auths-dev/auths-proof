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

fn replace_once(source: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let positions: Vec<_> = source
        .windows(from.len())
        .enumerate()
        .filter(|(_, window)| *window == from)
        .map(|(position, _)| position)
        .collect();
    assert_eq!(positions.len(), 1, "mutation site must be unique");
    let mut output = source[..positions[0]].to_vec();
    output.extend_from_slice(to);
    output.extend_from_slice(&source[positions[0] + from.len()..]);
    output
}

/// Byte-level mutations of the raw-key-chain canonical action and the code
/// the decoder must return. The Go verifier's tests apply the same mutations.
fn canonical_action_mutations(action: &[u8]) -> Vec<(&'static str, Vec<u8>, &'static str)> {
    let attachments = |first: u8, second: u8| {
        let mut output = vec![0x05, 0x82];
        for fill in [first, second] {
            output.extend_from_slice(&[0xa2, 0x00, 0x58, 0x20]);
            output.extend_from_slice(&[fill; 32]);
            output.extend_from_slice(&[0x01, 0x41, 0x01]);
        }
        output
    };
    let body_at = action
        .windows(3)
        .position(|window| window == [0x02, 0x58, 0x18])
        .unwrap();
    let permission_at = action
        .windows(2)
        .position(|window| window == [0x03, 0xa2])
        .unwrap();
    let mut empty_body = action[..body_at].to_vec();
    empty_body.extend_from_slice(&[0x02, 0x40]);
    empty_body.extend_from_slice(&action[permission_at..]);
    let mut trailing = action.to_vec();
    trailing.push(0x00);
    let mut map_size = vec![0xa5];
    map_size.extend_from_slice(&action[1..]);
    let mut non_shortest_key = vec![0xa6, 0x18, 0x00];
    non_shortest_key.extend_from_slice(&action[2..]);
    vec![
        (
            "truncated",
            action[..action.len() - 1].to_vec(),
            "malformed-proof",
        ),
        ("trailing byte", trailing, "malformed-proof"),
        ("map size", map_size, "malformed-proof"),
        (
            "key out of order",
            replace_once(action, &[0x05, 0x80], &[0x06, 0x80]),
            "non-canonical-proof",
        ),
        ("non-shortest key", non_shortest_key, "non-canonical-proof"),
        (
            "zero profile version",
            replace_once(action, b"auths.mcp\x01\x01", b"auths.mcp\x01\x00"),
            "malformed-proof",
        ),
        (
            "whitespace in media type",
            replace_once(action, b"auths.mcp-call", b"auths mcp-call"),
            "malformed-proof",
        ),
        (
            "body as text",
            replace_once(action, &[0x02, 0x58, 0x18], &[0x02, 0x78, 0x18]),
            "malformed-proof",
        ),
        ("empty body", empty_body, "resource-limit-exceeded"),
        (
            "indefinite attachments",
            replace_once(action, &[0x05, 0x80], &[0x05, 0x9f, 0xff]),
            "malformed-proof",
        ),
        (
            "attachments out of order",
            replace_once(action, &[0x05, 0x80], &attachments(0xff, 0x00)),
            "non-canonical-proof",
        ),
        (
            "duplicate attachments",
            replace_once(action, &[0x05, 0x80], &attachments(0xaa, 0xaa)),
            "malformed-proof",
        ),
    ]
}

#[test]
fn canonical_action_decode_failures_return_stable_codes_before_the_proof() {
    let fixture = auths_testkit::raw_key_chain();
    let action = auths_codec::encode_canonical_action(fixture.canonical_action()).unwrap();
    with_corpus_registries(|registries| {
        for (name, bytes, code) in canonical_action_mutations(&action) {
            let result = auths_codec::decode_verification_result(
                &auths_verifier::verify_v1(
                    fixture.proof_bytes(),
                    &bytes,
                    fixture.context_bytes(),
                    registries,
                )
                .unwrap(),
            )
            .unwrap();
            assert_eq!(result.decision(), VerificationDecision::Denied, "{name}");
            assert_eq!(result.code().code(), code, "{name}");
            assert_eq!(result.stage(), VerificationStage::Decode, "{name}");
            assert_eq!(result.plan_id(), None, "{name}");
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
