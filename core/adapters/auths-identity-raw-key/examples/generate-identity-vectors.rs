use auths_identity::{
    IDENTITY_APPLICATION_PROTOCOL_V1, IDENTITY_MODEL_VERSION, IDENTITY_PROTOCOL_V1,
    IDENTITY_SIGNING_DOMAIN_VERSION, IDENTITY_WIRE_MAGIC_V2, IDENTITY_WIRE_VERSION, IdentityPacket,
    PublicIdentity, SignedIdentityMessage,
};
use auths_identity_raw_key::RawKeyIdentityMethod;
use auths_raw_key_core::{ED25519_V1, RAW_KEY_V2, RawKeyDescriptorV2};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;
use std::{env, fs, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .ok_or("usage: generate-identity-vectors <output.json>")?;
    let signing_key = SigningKey::from_bytes(&[7; 32]);
    let public_key = signing_key.verifying_key().to_bytes();
    let validated = RawKeyIdentityMethod::identity(ED25519_V1, public_key.to_vec())?;
    let identity = validated.into_public_identity();
    let descriptor = RawKeyDescriptorV2::new(ED25519_V1, public_key.to_vec())?;
    let public_packet = IdentityPacket::PublicIdentity(identity.clone()).encode()?;
    let message = b"auths identity vector v1";
    let signing_preimage = SignedIdentityMessage::signing_preimage(&identity, message)?;
    let signature = signing_key.sign(&signing_preimage).to_bytes();
    let signed_packet = IdentityPacket::SignedMessage(SignedIdentityMessage::new(
        identity.clone(),
        message.to_vec(),
        signature.to_vec(),
    )?)
    .encode()?;

    let mut bad_magic = public_packet.clone();
    bad_magic[0] ^= 1;
    let mut unknown_tag = public_packet.clone();
    unknown_tag[IDENTITY_WIRE_MAGIC_V2.len()] = 0xff;
    let mut trailing = public_packet.clone();
    trailing.push(0);
    let forged = PublicIdentity::new(
        identity.method_id(),
        identity.identity_id(),
        identity.suite_id(),
        vec![9; public_key.len()],
    )?;
    let forged_relationship = IdentityPacket::PublicIdentity(forged).encode()?;

    let document = json!({
        "schema": "auths.identity-vectors/1",
        "generator": "auths-identity-raw-key/generate-identity-vectors",
        "versions": {
            "identityProtocol": IDENTITY_PROTOCOL_V1,
            "identityModel": IDENTITY_MODEL_VERSION,
            "wire": IDENTITY_WIRE_VERSION,
            "signingDomain": IDENTITY_SIGNING_DOMAIN_VERSION,
            "rawKeyMethod": RAW_KEY_V2,
            "signatureSuite": ED25519_V1,
            "irohDemoAlpn": IDENTITY_APPLICATION_PROTOCOL_V1
        },
        "valid": {
            "seedHex": hex::encode([7_u8; 32]),
            "publicKeyHex": hex::encode(public_key),
            "rawKeyDescriptorHex": hex::encode(descriptor.encode()),
            "identityId": identity.identity_id(),
            "publicIdentityPacketHex": hex::encode(public_packet),
            "messageHex": hex::encode(message),
            "signingPreimageHex": hex::encode(signing_preimage),
            "signatureHex": hex::encode(signature),
            "signedMessagePacketHex": hex::encode(signed_packet)
        },
        "rejected": [
            {
                "name": "bad-magic",
                "operation": "decode",
                "inputHex": hex::encode(bad_magic),
                "error": "invalid canonical identity message"
            },
            {
                "name": "unknown-packet-tag",
                "operation": "decode",
                "inputHex": hex::encode(unknown_tag),
                "error": "unsupported identity protocol"
            },
            {
                "name": "trailing-byte",
                "operation": "decode",
                "inputHex": hex::encode(trailing),
                "error": "invalid canonical identity message"
            },
            {
                "name": "forged-raw-key-relationship",
                "operation": "raw-key-validate",
                "inputHex": hex::encode(forged_relationship),
                "error": "invalid public identity"
            },
            {
                "name": "packet-over-limit",
                "operation": "decode-repeated-zero",
                "inputLength": auths_identity::MAX_IDENTITY_PACKET_BYTES + 1,
                "error": "invalid canonical identity message"
            }
        ]
    });
    let mut encoded = serde_json::to_vec_pretty(&document)?;
    encoded.push(b'\n');
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, encoded)?;
    Ok(())
}
