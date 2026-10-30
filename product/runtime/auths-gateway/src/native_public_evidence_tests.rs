//! Native public mutation projection; protected evidence stays in the journal.
use super::*;
use sha2::{Digest as _, Sha256};

const CONTENT: &[u8] = b"private-mutation-evidence-canary";

fn private_values_absent(bytes: &[u8], values: &[&[u8]]) {
    use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};
    for value in values {
        for encoded in [
            value.to_vec(),
            hex::encode(value).into_bytes(),
            Base64::encode_string(value).into_bytes(),
            Base64UrlUnpadded::encode_string(value).into_bytes(),
        ] {
            assert!(
                !bytes.windows(encoded.len()).any(|window| window == encoded),
                "private evidence reached a public projection"
            );
        }
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "one native read/replay history proves the protected/public evidence boundary"
)]
fn history(backend: Backend) -> (Value, Vec<u8>, String) {
    let case = Case::start(backend, Outcome::LostEcho);
    let runtime = runtime();
    let (engine, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "privacy-reader",
        case.store.reopen(),
        controls(true),
    ));
    engine
        .activate_effect_configuration(
            engine
                .effect_configuration_revision()
                .expect("operator revision"),
        )
        .expect("withdraw writer");
    let mut response: Value =
        serde_json::from_slice(&case.provider.requests.lock().expect("request")[0].body)
            .expect("actual write body");
    response["private_note"] = json!(std::str::from_utf8(CONTENT).expect("fixture"));
    let echo = response["fields"]["auths_echo"]
        .as_str()
        .expect("native echo")
        .to_owned();
    let body = serde_json::to_vec(&response).expect("body");
    *case.provider.read_response.lock().expect("response") = Some(ReadResponse {
        status: 200,
        declared_length: body.len(),
        body: body.clone(),
    });
    let call = runtime
        .block_on(engine.recovery_authorization_call(SOURCE, RECOVERY))
        .expect("read call");
    let signed = author::signed(&call, true);
    let effect = runtime
        .block_on(engine.compile_recovery_effect(SOURCE, &signed.proof, &signed.action))
        .expect("native read");
    let approval = author::approval(&effect, NOW + 1);
    let recovered = runtime
        .block_on(Box::pin(engine.recover(
            SOURCE,
            &signed.proof,
            &signed.action,
            approval,
        )))
        .expect("record exact evidence");
    let evidence = recovered
        .source
        .provider_evidence()
        .expect("protected evidence");
    assert!(
        evidence.evidence() == body,
        "protected evidence bytes differ"
    );
    let digest: [u8; 32] = Sha256::digest(&body).into();
    assert!(
        evidence.evidence_digest() == &digest,
        "protected evidence digest differs"
    );
    let original: Value = serde_json::from_slice(&case.original).expect("source");
    let action = hex::decode(
        original["action_commitment"]
            .as_str()
            .expect("action digest"),
    )
    .expect("digest");
    let (proof, action_bytes, approval) = input(&case.setup.installation.root, SOURCE);
    let first = runtime.block_on(engine.submit(&proof, &action_bytes, approval.clone()));
    let public = serde_json::to_vec(&first).expect("public mutation result");
    private_values_absent(
        &public,
        &[CONTENT, &body, &digest, &action, echo.as_bytes()],
    );
    private_values_absent(
        format!("{:?}", recovered.source).as_bytes(),
        &[CONTENT, &digest, &action, echo.as_bytes()],
    );
    private_values_absent(
        format!("{evidence:?}").as_bytes(),
        &[CONTENT, &digest, echo.as_bytes()],
    );
    let mut value: Value = serde_json::from_slice(&public).expect("public JSON");
    assert_eq!(value["outcome"], "observed-by-provider");
    assert_eq!(
        value["evidence"]["schema"],
        "auths.gateway-public-evidence/1"
    );
    let commitment = value["evidence"]["evidence_commitment"]
        .as_str()
        .expect("commitment")
        .to_owned();
    assert_eq!(commitment.len(), 64);
    assert_ne!(commitment, hex::encode(digest));
    assert!(value["evidence"].get("echo").is_none());
    assert!(value["evidence"].get("evidence_digest").is_none());
    let witness = engine.execution_witness();
    let (reopened, _) = runtime.block_on(load_controlled_engine(
        &case.setup.installation,
        "privacy-reopened",
        case.store.reopen(),
        controls(true),
    ));
    assert_eq!(
        runtime.block_on(reopened.submit(&proof, &action_bytes, approval)),
        first
    );
    assert_eq!(reopened.execution_witness().credential_lease_calls, 0);
    assert_eq!(engine.execution_witness(), witness);
    assert_eq!(case.provider.requests.lock().expect("requests").len(), 2);
    assert_fixed_source(&case.original, &record(&case.store, SOURCE));
    for invalid in ["auths.gateway-public-evidence/0", "unsupported"] {
        let mut bad = value.clone();
        bad["evidence"]["schema"] = json!(invalid);
        assert!(serde_json::from_value::<GatewaySubmitResult>(bad).is_err());
    }
    let mut legacy = value.clone();
    legacy["evidence"]["echo"] = json!(&echo);
    assert!(serde_json::from_value::<GatewaySubmitResult>(legacy).is_err());
    value["evidence"]["evidence_commitment"] = json!("native-scoped-hiding-value-checked");
    (value, body, commitment)
}
fn wire_cases() -> Value {
    let valid = json!({"outcome":"observed-by-provider","status":200,
        "evidence":{"schema":crate::PUBLIC_EVIDENCE_SCHEMA,"channel":"read-back","evidence_commitment":"ab".repeat(32),"observed_at":NOW}});
    let mut cases = vec![("valid", valid.clone(), true)];
    for (name, field, value) in [
        (
            "obsolete-schema",
            "schema",
            json!("auths.gateway-public-evidence/0"),
        ),
        ("short-commitment", "evidence_commitment", json!("00")),
        (
            "uppercase-commitment",
            "evidence_commitment",
            json!("AB".repeat(32)),
        ),
        (
            "newline-commitment",
            "evidence_commitment",
            json!(format!("{}\n", "ab".repeat(32))),
        ),
        ("numeric-commitment", "evidence_commitment", json!(42)),
        ("private-echo", "echo", json!("auths-e1-private-canary")),
        ("raw-digest", "evidence_digest", json!("cd".repeat(32))),
        ("unsafe-time", "observed_at", json!(1_u64 << 53)),
        ("boolean-time", "observed_at", json!(true)),
        ("negative-time", "observed_at", json!(-1)),
    ] {
        let mut value_case = valid.clone();
        value_case["evidence"][field] = value;
        cases.push((name, value_case, false));
    }
    let mut output = Vec::new();
    for (name, value, accepted) in cases {
        let bytes = serde_json::to_string(&value).expect("wire");
        assert_eq!(
            serde_json::from_str::<GatewaySubmitResult>(&bytes).is_ok(),
            accepted,
            "{name}"
        );
        output.push(json!({"case":name,"response":bytes,"accepted":accepted}));
    }
    let base = serde_json::to_string(&valid).expect("wire");
    let duplicate = base.replacen(
        "\"schema\":",
        &format!(
            "\"schema\":\"{}\",\"schema\":",
            crate::PUBLIC_EVIDENCE_SCHEMA
        ),
        1,
    );
    assert!(serde_json::from_str::<GatewaySubmitResult>(&duplicate).is_err());
    output.push(json!({"case":"duplicate-schema","response":duplicate,"accepted":false}));
    for (name, bytes) in [
        (
            "fractional-time",
            base.replace(&format!("\"observed_at\":{NOW}"), "\"observed_at\":1.0"),
        ),
        (
            "exponent-time",
            base.replace(&format!("\"observed_at\":{NOW}"), "\"observed_at\":1e0"),
        ),
        ("bom", format!("\u{feff}{base}")),
    ] {
        assert!(serde_json::from_str::<GatewaySubmitResult>(&bytes).is_err());
        output.push(json!({"case":name,"response":bytes,"accepted":false}));
    }
    json!(output)
}

fn matrix(backend: Backend) {
    let (first, first_body, first_commitment) = history(backend);
    let (second, second_body, second_commitment) = history(backend);
    assert!(
        first_body == second_body,
        "same private bytes must exercise distinct private journal scopes"
    );
    assert_ne!(first_commitment, second_commitment);
    assert_eq!(first, second);
    let artifact = serde_json::to_vec_pretty(&json!({"schema":"auths.native-public-mutation-evidence/1","adapter":backend.label(),
        "scope":"native writer/read proofs and exact approvals, actual HTTP, protected complete evidence and public original-writer replay after withdrawal",
        "excluded":["signed outcome/pre-entry observation projection hardening", "live provider and hostile OS qualification"],
        "public_result":first,"wire_cases":wire_cases(),"same_private_bytes_have_distinct_record_scoped_commitments":true,"reopen_and_replay_preserve_commitment_without_io":true,
        "private_complete_evidence_and_original_binding_preserved":true,"public_and_debug_exclude_raw_body_digest_echo_and_action_digest":true})).expect("artifact");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../../bindings/fixtures/gateway/native-public-mutation-evidence-{}.json",
        backend.label()
    ));
    if std::env::var_os("AUTHS_UPDATE_FIXTURES").is_some() {
        std::fs::write(&path, &artifact).expect("fixture");
    }
    assert_eq!(std::fs::read(path).expect("fixture"), artifact);
}
#[test]
fn native_file_public_mutation_evidence_fixture_is_current() {
    matrix(Backend::File);
}
#[test]
#[ignore = "requires the TLS PostgreSQL fixture"]
fn postgres_native_public_mutation_evidence_fixture_is_current() {
    assert!(postgres_configured());
    matrix(Backend::Postgres);
}
