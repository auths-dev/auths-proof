//! Frozen public commissioning bytes, consumed without issuance code.

use super::*;

fn fixture() -> serde_json::Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../bindings/fixtures/qualification/commissioning-v2.json");
    serde_json::from_slice(&std::fs::read(path).expect("fixture")).expect("fixture JSON")
}

#[test]
fn frozen_commissioning_bytes_authenticate_only_their_exact_binding() {
    let fixture = fixture();
    let text = |member: &str| fixture[member].as_str().expect("artifact").as_bytes();
    let root = QualificationTrustRoot::from_canonical_json(text("trust_root")).expect("root");
    let verified = VerifiedCommissioningPermit::verify(
        &root,
        &CommissioningInputs {
            signer_certificate: text("signer_certificate"),
            revocation_list: text("revocation_list"),
            permit: text("permit"),
        },
    )
    .expect("signed permit");
    let permit = verified.permit();
    assert_eq!(permit.digest().to_hex(), fixture["permit_digest"]);
    let binding = &permit.body().statement.binding;
    assert_eq!(
        binding.budget_key().expect("key").to_hex(),
        fixture["budget_scope_sha256"]
    );
    assert_eq!(
        binding.budget_binding().expect("binding").to_hex(),
        fixture["budget_binding_sha256"]
    );
    let mut request = CommissioningRequest {
        source_commit: &binding.source_commit,
        tuple: &binding.tuple,
        protected_run: &binding.protected_run,
        principal_sha256: binding.principal_sha256,
        trusted_context_sha256: binding.trusted_contexts_sha256[0],
        resources_sha256: binding.resources_sha256,
        canonical_action_sha256: binding.allowed_actions[0],
    };
    let now = permit.body().statement.not_before;
    for context in &binding.trusted_contexts_sha256 {
        request.trusted_context_sha256 = *context;
        assert_eq!(
            verified.evaluate(&request, now, true, &VerifierState::default()),
            Ok(())
        );
    }
    request.trusted_context_sha256 = Sha256Digest::from_bytes([0xfe; 32]);
    assert_eq!(
        verified.evaluate(&request, now, true, &VerifierState::default()),
        Err(CommissioningRefusal::BindingMismatch)
    );
    request.trusted_context_sha256 = binding.trusted_contexts_sha256[0];
    request.principal_sha256 = Sha256Digest::from_bytes([0xff; 32]);
    assert_eq!(
        verified.evaluate(&request, now, true, &VerifierState::default()),
        Err(CommissioningRefusal::BindingMismatch)
    );
}

#[test]
fn every_single_bit_signature_mutation_is_refused() {
    let fixture = fixture();
    let text = |member: &str| fixture[member].as_str().expect("artifact").as_bytes();
    let root = QualificationTrustRoot::from_canonical_json(text("trust_root")).expect("root");
    let permit =
        QualificationCommissioningPermit::from_canonical_json(text("permit")).expect("permit");
    let original = permit.body().signature_b64.to_bytes();
    for bit in 0..512 {
        let mut body = permit.body().clone();
        let mut changed = original;
        changed[bit / 8] ^= 1 << (bit % 8);
        body.signature_b64 = SignatureB64::from_bytes(&changed);
        let changed = QualificationCommissioningPermit::from_body(&body).expect("shape");
        assert_eq!(
            VerifiedCommissioningPermit::verify(
                &root,
                &CommissioningInputs {
                    signer_certificate: text("signer_certificate"),
                    revocation_list: text("revocation_list"),
                    permit: changed.canonical_bytes(),
                }
            )
            .map(|_| ()),
            Err(CommissioningRefusal::Unavailable),
            "bit {bit}"
        );
    }
}

#[test]
fn unsigned_shape_never_accepts_extra_duplicate_or_unknown_members() {
    let fixture = fixture();
    let permit = QualificationCommissioningPermit::from_canonical_json(
        fixture["permit"].as_str().expect("artifact").as_bytes(),
    )
    .expect("permit");
    for pointer in [
        "",
        "/statement",
        "/statement/binding",
        "/statement/binding/tuple",
        "/statement/binding/tuple/target",
        "/statement/binding/offline_evidence",
    ] {
        let mut document = serde_json::to_value(permit.body()).expect("body");
        document.pointer_mut(pointer).expect("member")["extra"] = serde_json::json!(true);
        assert_eq!(
            QualificationCommissioningPermit::from_canonical_json(
                &canonical::canonical_bytes(&document).expect("canonical")
            )
            .map(|_| ()),
            Err(QualificationFormatError::Malformed),
            "{pointer}"
        );
    }
    let text = std::str::from_utf8(permit.canonical_bytes()).expect("UTF-8");
    let duplicate = text.replacen("\"issued_at\":", "\"issued_at\":0,\"issued_at\":", 1);
    assert_eq!(
        QualificationCommissioningPermit::from_canonical_json(duplicate.as_bytes()).map(|_| ()),
        Err(QualificationFormatError::Malformed)
    );
    let mut body = permit.body().clone();
    body.statement.schema = "auths.qualification-commissioning-permit/1".to_owned();
    assert_eq!(
        QualificationCommissioningPermit::from_body(&body).map(|_| ()),
        Err(QualificationFormatError::UnknownSchema)
    );
    for contexts in [
        vec![],
        vec![Sha256Digest::from_bytes([0x61; 32]); 2],
        vec![
            Sha256Digest::from_bytes([0x65; 32]),
            Sha256Digest::from_bytes([0x61; 32]),
        ],
        (0..=MAX_COMMISSIONING_CONTEXTS)
            .map(|index| Sha256Digest::from_bytes([u8::try_from(index).expect("bound"); 32]))
            .collect(),
    ] {
        let mut body = permit.body().clone();
        body.statement.binding.trusted_contexts_sha256 = contexts;
        assert!(QualificationCommissioningPermit::from_body(&body).is_err());
    }
}
