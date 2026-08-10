use auths_identity::{
    IDENTITY_APPLICATION_PROTOCOL_V1, IDENTITY_MODEL_VERSION, IDENTITY_PROTOCOL_V1,
    IDENTITY_SIGNING_DOMAIN_VERSION, IDENTITY_WIRE_VERSION, IdentityError, IdentityPacket,
    SignedIdentityMessage,
};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_raw_key_core::{ED25519_V1, RAW_KEY_V2, RawKeyDescriptorV2};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::Value;

struct FrozenEd25519;

impl auths_identity::SignatureVerifier for FrozenEd25519 {
    fn suite_id(&self) -> &'static str {
        ED25519_V1
    }

    fn verify(
        &self,
        public_key: &[u8],
        signing_preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        auths_signature_core::verify_ed25519(public_key, signing_preimage, signature).map_err(
            |error| match error {
                auths_signature_core::Ed25519Error::InvalidKey => IdentityError::InvalidPublicKey,
                auths_signature_core::Ed25519Error::InvalidSignatureEncoding => {
                    IdentityError::InvalidSignature
                }
                auths_signature_core::Ed25519Error::VerificationFailed => {
                    IdentityError::VerificationFailed
                }
            },
        )
    }
}

fn bytes(value: &Value, field: &str) -> Vec<u8> {
    hex::decode(value[field].as_str().unwrap()).unwrap()
}

#[test]
fn checked_in_identity_vectors_match_all_semantic_owners() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../fixtures/identity/v1/vectors.json")).unwrap();
    let versions = &vectors["versions"];
    assert_eq!(versions["identityProtocol"], IDENTITY_PROTOCOL_V1);
    assert_eq!(versions["identityModel"], IDENTITY_MODEL_VERSION);
    assert_eq!(versions["wire"], IDENTITY_WIRE_VERSION);
    assert_eq!(versions["signingDomain"], IDENTITY_SIGNING_DOMAIN_VERSION);
    assert_eq!(versions["rawKeyMethod"], RAW_KEY_V2);
    assert_eq!(versions["signatureSuite"], ED25519_V1);
    assert_eq!(versions["irohDemoAlpn"], IDENTITY_APPLICATION_PROTOCOL_V1);

    let valid = &vectors["valid"];
    let signing_key = SigningKey::from_bytes(&bytes(valid, "seedHex").try_into().unwrap());
    let public_key = signing_key.verifying_key().to_bytes();
    assert_eq!(bytes(valid, "publicKeyHex"), public_key);
    let descriptor = RawKeyDescriptorV2::new(ED25519_V1, public_key.to_vec()).unwrap();
    assert_eq!(bytes(valid, "rawKeyDescriptorHex"), descriptor.encode());
    assert_eq!(valid["identityId"], descriptor.identifier());

    let public_packet = bytes(valid, "publicIdentityPacketHex");
    let identity = match IdentityPacket::decode(&public_packet).unwrap() {
        IdentityPacket::PublicIdentity(identity) => identity,
        IdentityPacket::SignedMessage(_) => panic!("public vector decoded as signed message"),
    };
    let validated = identity.validate(&RawKeyIdentityMethod).unwrap();
    assert_eq!(validated.identity_id(), descriptor.identifier());
    let message = bytes(valid, "messageHex");
    let preimage = SignedIdentityMessage::signing_preimage(&identity, &message).unwrap();
    assert_eq!(bytes(valid, "signingPreimageHex"), preimage);
    let signature = signing_key.sign(&preimage).to_bytes();
    assert_eq!(bytes(valid, "signatureHex"), signature);

    let signed_packet = bytes(valid, "signedMessagePacketHex");
    let signed = match IdentityPacket::decode(&signed_packet).unwrap() {
        IdentityPacket::PublicIdentity(_) => panic!("signed vector decoded as public identity"),
        IdentityPacket::SignedMessage(signed) => signed,
    };
    let authenticated = signed
        .verify(&RawKeyIdentityMethod, &FrozenEd25519)
        .unwrap();
    assert_eq!(authenticated.message(), message);
}

#[test]
fn checked_in_rejection_corpus_fails_with_declared_categories() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../fixtures/identity/v1/vectors.json")).unwrap();
    for case in vectors["rejected"].as_array().unwrap() {
        let operation = case["operation"].as_str().unwrap();
        let error = match operation {
            "decode" => IdentityPacket::decode(&bytes(case, "inputHex")).unwrap_err(),
            "raw-key-validate" => match IdentityPacket::decode(&bytes(case, "inputHex")).unwrap() {
                IdentityPacket::PublicIdentity(identity) => {
                    identity.validate(&RawKeyIdentityMethod).unwrap_err()
                }
                IdentityPacket::SignedMessage(_) => panic!("forged identity changed shape"),
            },
            "decode-repeated-zero" => {
                let length = usize::try_from(case["inputLength"].as_u64().unwrap()).unwrap();
                IdentityPacket::decode(&vec![0; length]).unwrap_err()
            }
            _ => panic!("unknown rejection operation"),
        };
        assert_eq!(error.to_string(), case["error"].as_str().unwrap());
    }
    assert_eq!(
        IdentityPacket::decode(&vec![0; auths_identity::MAX_IDENTITY_PACKET_BYTES + 1]),
        Err(IdentityError::Codec)
    );
}
