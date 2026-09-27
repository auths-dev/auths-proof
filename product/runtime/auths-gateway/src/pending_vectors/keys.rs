//! Key identity for separation of duties: `raw-key-v1` and `did:key`
//! principals of the same Ed25519 or P-256 key, the SHA-256 of the key's
//! canonical `raw-key-v1` descriptor they share, and principals of other
//! methods, which have no key identity.
//!
//! Keys come from fixed seed bytes. The `did:key` spelling is built here and
//! checked against the custody adapter's `did:key` derivation for P-256 and
//! against the `did:key` evidence decoder for both key types.

use super::{load, require_current};
use crate::harness;
use auths_raw_key::{RawKeyDescriptor, RawKeyDescriptorV2, RawKeyType};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

pub(super) const FILE: &str = "key-identity.json";
const SCHEMA: &str = "auths.gateway-key-identity/1";
pub(super) const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];
const P256_MULTICODEC: [u8; 2] = [0x80, 0x24];
/// Framing of `did:key` evidence bytes, used only to run the decoder.
const DID_KEY_EVIDENCE_DOMAIN: &[u8] = b"AUTHS-DID-KEY\x00\x01";

fn base58btc(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits: Vec<u8> = Vec::new();
    for byte in bytes {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = u8::try_from(carry % 58).expect("remainder below 58");
            carry /= 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).expect("remainder below 58"));
            carry /= 58;
        }
    }
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    std::iter::repeat_n('1', zeros)
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| char::from(ALPHABET[usize::from(*digit)])),
        )
        .collect()
}

pub(super) fn did_key(multicodec: [u8; 2], public_key: &[u8]) -> String {
    let mut bytes = multicodec.to_vec();
    bytes.extend_from_slice(public_key);
    format!("did:key:z{}", base58btc(&bytes))
}

/// Decodes `principal` through the `did:key` evidence decoder and returns
/// the public key it names.
fn decoded_did_key(principal: &str) -> Vec<u8> {
    let multikey = principal
        .strip_prefix("did:key:")
        .expect("did:key principal");
    let mut evidence = DID_KEY_EVIDENCE_DOMAIN.to_vec();
    evidence.extend_from_slice(&u16::try_from(multikey.len()).expect("short").to_be_bytes());
    evidence.extend_from_slice(multikey.as_bytes());
    auths_did_key::DidKeyEvidence::decode(&evidence)
        .expect("canonical did:key")
        .multikey()
        .public_key()
        .to_vec()
}

struct Key {
    id: &'static str,
    kind: RawKeyType,
    seed: u8,
    public: Vec<u8>,
}

fn keys() -> Vec<Key> {
    let ed25519 = |id, seed| Key {
        id,
        kind: RawKeyType::Ed25519,
        seed,
        public: ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
            .to_vec(),
    };
    let p256 = |id, seed| {
        use p256::elliptic_curve::sec1::ToEncodedPoint as _;
        let secret = p256::SecretKey::from_slice(&[seed; 32]).expect("fixed scalar");
        Key {
            id,
            kind: RawKeyType::P256,
            seed,
            public: secret
                .public_key()
                .to_encoded_point(true)
                .as_bytes()
                .to_vec(),
        }
    };
    vec![
        ed25519("ed25519-a", 0x11),
        ed25519("ed25519-b", 0x44),
        p256("p256-a", 0x21),
        p256("p256-b", 0x52),
    ]
}

fn key_entry(key: &Key) -> Value {
    let raw = RawKeyDescriptor::new(key.kind, key.public.clone()).expect("raw key");
    let (label, multicodec) = match key.kind {
        RawKeyType::Ed25519 => ("ed25519", ED25519_MULTICODEC),
        RawKeyType::P256 => ("p256", P256_MULTICODEC),
    };
    let did = did_key(multicodec, &key.public);
    assert_eq!(decoded_did_key(&did), key.public, "{}", key.id);
    if key.kind == RawKeyType::P256 {
        let custody = auths_custody::CustodyIdentity::p256(
            auths_custody::CustodyPrincipalForm::DidKeyV1,
            &key.public,
        )
        .expect("custody identity");
        assert_eq!(custody.principal().as_str(), did, "{}", key.id);
    }
    json!({
        "id": key.id,
        "key_type": label,
        "seed_byte": key.seed,
        "public_key_hex": hex::encode(&key.public),
        "descriptor_hex": hex::encode(raw.encode()),
        "key_identity_hex": hex::encode(Sha256::digest(raw.encode())),
        "principals": [
            {"method": "raw-key-v1", "principal": raw.principal().expect("principal").as_str()},
            {"method": "did-key-v1", "multibase": multibase(&did)}
        ]
    })
}

/// The Multikey of a `did:key` principal. Fixtures carry the Multikey rather
/// than the whole identifier, which secret scanners read as a credential
/// assignment; the principal is `did:key:` followed by it.
pub(super) fn multibase(principal: &str) -> &str {
    principal
        .strip_prefix("did:key:")
        .expect("did:key principal")
}

fn document() -> Value {
    let keys = keys();
    let entries: Vec<Value> = keys.iter().map(key_entry).collect();
    let v2 = RawKeyDescriptorV2::new(
        auths_model::SignatureSuiteId::parse(auths_signature::ED25519_V1).expect("suite"),
        keys[0].public.clone(),
    )
    .expect("raw-key-v2")
    .identifier();
    let others = json!([
        {"method": "raw-key-v2", "principal": v2, "key_identity": null},
        {"method": "did-keri-v1", "principal": format!("did:keri:E{}", "A".repeat(43)), "key_identity": null},
        {"method": "did-web", "principal": "did:web:gateway.example", "key_identity": null}
    ]);
    let of = |id: &str, method: &str| json!({"id": id, "method": method});
    let pair = |left: Value, right: Value, overlap: &str| json!({"left": left, "right": right, "overlap": overlap});
    let overlaps = json!([
        pair(
            of("ed25519-a", "raw-key-v1"),
            of("ed25519-a", "did-key-v1"),
            "key-identity"
        ),
        pair(
            of("p256-a", "raw-key-v1"),
            of("p256-a", "did-key-v1"),
            "key-identity"
        ),
        pair(
            of("ed25519-a", "raw-key-v1"),
            of("ed25519-a", "raw-key-v1"),
            "identifier"
        ),
        pair(
            of("ed25519-a", "did-key-v1"),
            of("ed25519-b", "did-key-v1"),
            "none"
        ),
        pair(
            of("ed25519-a", "raw-key-v1"),
            of("ed25519-b", "raw-key-v1"),
            "none"
        ),
        pair(
            of("ed25519-a", "raw-key-v1"),
            json!({"principal": others[0]["principal"]}),
            "none"
        ),
        pair(
            of("p256-a", "did-key-v1"),
            of("p256-b", "raw-key-v1"),
            "none"
        ),
    ]);
    json!({
        "schema": SCHEMA,
        "identity_rule": "SHA-256 of the canonical raw-key-v1 descriptor of the one key the identifier names",
        "did_key_principal": "did:key:<multibase>",
        "keys": entries,
        "no_key_identity": others,
        "overlaps": overlaps,
    })
}

#[test]
fn key_identity_vectors_are_current() {
    require_current(FILE, &document());
}

/// Today's separation check compares identifiers only: an operator that is a
/// trusted root's own key under `did:key` passes, where key identity refuses
/// it as the root.
#[test]
fn current_separation_misses_one_key_under_two_methods() {
    let vectors = load(FILE);
    let key = &vectors["keys"][0];
    let seed = u8::try_from(key["seed_byte"].as_u64().expect("seed")).expect("byte");
    let root = harness::Signer::new(seed);
    assert_eq!(key["principals"][0]["method"], "raw-key-v1");
    assert_eq!(root.principal.as_str(), key["principals"][0]["principal"]);
    assert_eq!(key["principals"][1]["method"], "did-key-v1");
    let multibase = key["principals"][1]["multibase"]
        .as_str()
        .expect("multibase");
    let operator =
        auths_model::PrincipalId::parse(&format!("did:key:{multibase}")).expect("principal");
    let observer = crate::GatewayObserver::from_test_seed(0x33);
    let trust = harness::context(&root, observer.principal(), None, super::NOW).expect("trust");
    assert_eq!(vectors["overlaps"][0]["overlap"], "key-identity");
    assert_eq!(
        crate::check_principal_separation(&trust, &operator, None),
        Ok(())
    );
}
