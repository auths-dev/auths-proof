//! Public P-256 vectors exercise the native primitive and the shipping port adapter.

use auths_ports::{SignatureError, SignatureInput, SignatureSuite};
use auths_signature::P256Sha256Suite;
use auths_signature_core::{P256Error, validate_p256_key, verify_p256_sha256};

fn bytes(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "fixture hex width");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("fixture ASCII");
            u8::from_str_radix(text, 16).expect("fixture hex")
        })
        .collect()
}

#[test]
fn published_p256_corpus_and_strict_auths_derivations() {
    let suite = P256Sha256Suite::new().expect("mandatory suite ID");
    let mut cases = 0;
    let mut accepted = 0;
    let mut keys = std::collections::BTreeSet::new();
    for line in include_str!("../../../fixtures/crypto/p256-sha256-v1.tsv").lines() {
        if line.starts_with('#') || line.starts_with("id\t") {
            continue;
        }
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 6, "fixture fields");
        let [name, key_hex, message_hex, signature_hex, result, key_valid] = fields.as_slice()
        else {
            unreachable!("checked fixture width")
        };
        let key = bytes(key_hex);
        let message = bytes(message_hex);
        let signature = bytes(signature_hex);
        let (native, port) = match *result {
            "ok" => (Ok(()), Ok(())),
            "invalid-key" => (Err(P256Error::InvalidKey), Err(SignatureError::InvalidKey)),
            "invalid-signature-encoding" => (
                Err(P256Error::InvalidSignatureEncoding),
                Err(SignatureError::InvalidSignatureEncoding),
            ),
            "verification-failed" => (
                Err(P256Error::VerificationFailed),
                Err(SignatureError::InvalidSignature),
            ),
            _ => panic!("unknown fixture result: {result}"),
        };
        assert!(
            matches!(*key_valid, "true" | "false"),
            "fixture key verdict"
        );
        assert_eq!(
            validate_p256_key(&key).is_ok(),
            *key_valid == "true",
            "native key: {name}"
        );
        assert_eq!(
            suite.validate_key(&key).is_ok(),
            *key_valid == "true",
            "port key: {name}"
        );
        assert_eq!(
            verify_p256_sha256(&key, &message, &signature),
            native,
            "native: {name}"
        );
        assert_eq!(
            suite.verify(SignatureInput {
                verification_key: &key,
                signing_preimage: &message,
                signature: &signature
            }),
            port,
            "port: {name}"
        );
        cases += 1;
        if *result == "ok" {
            accepted += 1;
            keys.insert(key);
        }
    }
    assert_eq!(cases, 653, "no source or derived cases may disappear");
    assert_eq!(
        accepted, 173,
        "every upstream valid tuple has one admitted low-S form"
    );
    assert!(
        keys.len() == 98,
        "positive coverage must span distinct public keys"
    );
}
