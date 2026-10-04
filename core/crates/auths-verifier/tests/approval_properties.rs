//! The approval verdict is invariant under the order and repetition of the
//! approvals a presenter attaches and under adding approvals that cannot
//! count.

use auths_codec::{body_digest, decode_bundle, decode_verifier_context, encode_bundle};
use auths_model::{ApprovalSatisfaction, SignedApproval, VerificationDecision, VerifierLimits};
use auths_registries::ImmutableRegistries;
use auths_verifier::verify_portable;
use proptest::prelude::*;
use std::collections::BTreeSet;

struct Registries {
    raw_key: auths_raw_key::RawKeyMethod,
    did_key: auths_did_key::DidKeyMethod,
    did_keri: auths_did_keri::DidKeriMethod,
    did_web: auths_did_web::DidWebMethod,
    webauthn: auths_webauthn::WebAuthnMethod,
    hsm: auths_hsm_attested::HsmAttestedMethod,
    spiffe: auths_spiffe_x509::SpiffeX509Method,
    ed25519: auths_signature::Ed25519Suite,
    p256: auths_signature::P256Sha256Suite,
}

impl Registries {
    fn new() -> Self {
        let (spiffe_trust, spiffe_status) = auths_testkit::spiffe_corpus_context();
        Self {
            raw_key: auths_raw_key::RawKeyMethod::new().expect("raw-key"),
            did_key: auths_did_key::DidKeyMethod::new().expect("did:key"),
            did_keri: auths_did_keri::DidKeriMethod::new().expect("did:keri"),
            did_web:
                auths_did_web::DidWebMethod::new(auths_testkit::did_web_corpus_trust_records())
                    .expect("did:web"),
            webauthn: auths_webauthn::WebAuthnMethod::new(
                auths_testkit::webauthn_corpus_credentials(),
            )
            .expect("WebAuthn"),
            hsm: auths_hsm_attested::HsmAttestedMethod::new(auths_testkit::hsm_corpus_records())
                .expect("HSM"),
            spiffe: auths_testkit::spiffe_corpus_method(spiffe_trust, spiffe_status)
                .expect("SPIFFE"),
            ed25519: auths_signature::Ed25519Suite::new().expect("Ed25519"),
            p256: auths_signature::P256Sha256Suite::new().expect("P-256"),
        }
    }
}

struct Outcome {
    decision: VerificationDecision,
    work_units: u64,
    satisfactions: Vec<ApprovalSatisfaction>,
}

fn verify_with(approvals: Vec<SignedApproval>) -> Outcome {
    let fixture = auths_testkit::corpus()
        .into_iter()
        .find(|fixture| fixture.name() == "approval-with-stray-action")
        .expect("corpus fixture");
    let holder = Registries::new();
    let methods: [&dyn auths_ports::PrincipalMethod; 7] = [
        &holder.raw_key,
        &holder.did_key,
        &holder.did_keri,
        &holder.did_web,
        &holder.webauthn,
        &holder.hsm,
        &holder.spiffe,
    ];
    let suites: [&dyn auths_ports::SignatureSuite; 2] = [&holder.ed25519, &holder.p256];
    let registries = ImmutableRegistries::new(&methods, &suites).expect("registries");
    let context = decode_verifier_context(fixture.context_bytes()).expect("context");
    let bundle = decode_bundle(fixture.proof_bytes(), &VerifierLimits::default())
        .expect("proof")
        .with_approvals(approvals)
        .expect("bounded approvals");
    let result = verify_portable(
        &encode_bundle(&bundle).expect("proof bytes"),
        fixture.canonical_action(),
        &context,
        &registries,
    );
    Outcome {
        decision: result.decision(),
        work_units: result.resources().work_units(),
        satisfactions: result.approval_satisfactions().to_vec(),
    }
}

fn fixture_approvals() -> (Vec<SignedApproval>, Vec<u8>) {
    let fixture = auths_testkit::corpus()
        .into_iter()
        .find(|fixture| fixture.name() == "approval-with-stray-action")
        .expect("corpus fixture");
    let bundle =
        decode_bundle(fixture.proof_bytes(), &VerifierLimits::default()).expect("fixture proof");
    (
        bundle.approvals().to_vec(),
        fixture.canonical_action().body().to_vec(),
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn order_repetition_and_strays_never_change_the_verdict(
        sequence in proptest::collection::vec(0usize..3, 0..8)
    ) {
        let (approvals, body) = fixture_approvals();
        let expected_digest = body_digest(&body);
        let presented: Vec<_> = sequence.iter().map(|index| approvals[*index].clone()).collect();
        let counting: BTreeSet<_> = presented
            .iter()
            .filter(|approval| approval.statement().body_digest() == expected_digest)
            .map(|approval| approval.statement().approver().clone())
            .collect();
        let outcome = verify_with(presented.clone());
        let expected = if counting.len() >= 2 {
            VerificationDecision::Authorized
        } else {
            VerificationDecision::Denied
        };
        prop_assert_eq!(outcome.decision, expected);

        let mut canonical: Vec<_> = presented;
        canonical.sort_by_key(|approval| auths_codec::approval_digest(approval).expect("digest"));
        canonical.dedup();
        let reference = verify_with(canonical);
        prop_assert_eq!(outcome.decision, reference.decision);
        prop_assert_eq!(outcome.work_units, reference.work_units);
        prop_assert_eq!(outcome.satisfactions, reference.satisfactions);
    }
}
