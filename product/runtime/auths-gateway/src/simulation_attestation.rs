//! Detached signatures for measured simulation reports, never qualifications.

use auths_recipe_qualification_issuance::SigningSeed;
use base64ct::{Base64Unpadded, Encoding as _};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const SCHEMA: &str = "auths.provider-simulation-attestation/1";
const DOMAIN: &[u8] = b"auths.provider-simulation-attestation/1\0";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Statement {
    schema: String,
    simulation: bool,
    stable_launch_ready: bool,
    signer_kind: String,
    family: String,
    report_sha256: String,
    public_key_b64: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attestation {
    statement: Statement,
    signature_b64: String,
}

fn preimage(statement: &Statement) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json_canonicalizer::to_vec(statement).expect("simulation statement"));
    bytes
}

pub(crate) fn sign(report: &[u8], family: &str) -> Vec<u8> {
    let seed = SigningSeed::generate().expect("ephemeral report signer");
    let key = SigningKey::from_bytes(seed.expose());
    let statement = Statement {
        schema: SCHEMA.to_owned(),
        simulation: true,
        stable_launch_ready: false,
        signer_kind: "disposable-self-signed-simulation-key".to_owned(),
        family: family.to_owned(),
        report_sha256: hex::encode(Sha256::digest(report)),
        public_key_b64: Base64Unpadded::encode_string(&key.verifying_key().to_bytes()),
    };
    let signature_b64 = Base64Unpadded::encode_string(&key.sign(&preimage(&statement)).to_bytes());
    let bytes = serde_json::to_vec_pretty(&Attestation {
        statement,
        signature_b64,
    })
    .expect("simulation attestation");
    assert!(verify(report, &bytes), "verify before publishing");
    bytes
}

pub(crate) fn verify(report: &[u8], attestation: &[u8]) -> bool {
    if report.len() > 1_048_576 || attestation.len() > 4096 {
        return false;
    }
    let Ok(envelope) = serde_json::from_slice::<Attestation>(attestation) else {
        return false;
    };
    let statement = &envelope.statement;
    let Ok(body) = serde_json::from_slice::<serde_json::Value>(report) else {
        return false;
    };
    if statement.schema != SCHEMA
        || !statement.simulation
        || statement.stable_launch_ready
        || statement.signer_kind != "disposable-self-signed-simulation-key"
        || statement.report_sha256 != hex::encode(Sha256::digest(report))
        || body["schema"] != "auths.recipe-qualification-simulation/1"
        || body["simulation"] != true
        || body["stable_launch_ready"] != false
        || body["family"] != statement.family
    {
        return false;
    }
    let Ok(public) = Base64Unpadded::decode_vec(&statement.public_key_b64) else {
        return false;
    };
    let Ok(public) = <[u8; 32]>::try_from(public.as_slice()) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&public) else {
        return false;
    };
    let Ok(signature) = Base64Unpadded::decode_vec(&envelope.signature_b64) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(&signature) else {
        return false;
    };
    key.verify_strict(&preimage(statement), &signature).is_ok()
}

#[test]
fn altered_reports_and_scope_are_refused() {
    let report = br#"{"schema":"auths.recipe-qualification-simulation/1","simulation":true,"stable_launch_ready":false,"family":"stripe-refund-v1","cases":[]}"#;
    let attestation = sign(report, "stripe-refund-v1");
    assert!(verify(report, &attestation));
    let mut altered = report.to_vec();
    altered.push(b' ');
    assert!(!verify(&altered, &attestation));
    let mut envelope: serde_json::Value = serde_json::from_slice(&attestation).expect("envelope");
    envelope["statement"]["simulation"] = false.into();
    assert!(!verify(
        report,
        &serde_json::to_vec(&envelope).expect("altered scope")
    ));
    envelope["statement"]["simulation"] = true.into();
    envelope["signature_b64"] = "A".repeat(86).into();
    assert!(!verify(
        report,
        &serde_json::to_vec(&envelope).expect("altered signature")
    ));
}
