use std::error::Error;

use auths_identity::{
    IdentityError, IdentityMethod, IdentityPacket, PublicIdentity, SignatureVerifier,
    SignedIdentityMessage,
};

struct ExampleMethod;

impl IdentityMethod for ExampleMethod {
    fn method_id(&self) -> &'static str {
        "example-key-v1"
    }

    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
        (identity.identity_id() == "example:alice")
            .then_some(())
            .ok_or(IdentityError::InvalidIdentity)
    }
}

struct ExampleSuite;

impl SignatureVerifier for ExampleSuite {
    fn suite_id(&self) -> &'static str {
        "example-signature-v1"
    }

    fn verify(
        &self,
        public_key: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), IdentityError> {
        (public_key == b"public key bytes" && signature == preimage)
            .then_some(())
            .ok_or(IdentityError::VerificationFailed)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let identity = PublicIdentity::new(
        "example-key-v1",
        "example:alice",
        "example-signature-v1",
        b"public key bytes".to_vec(),
    )?;
    let message = b"identity works without a transport";
    let preimage = SignedIdentityMessage::signing_preimage(&identity, message)?;
    let packet = IdentityPacket::SignedMessage(SignedIdentityMessage::new(
        identity,
        message.to_vec(),
        preimage,
    )?);
    let decoded = IdentityPacket::decode(&packet.encode()?)?;
    if let IdentityPacket::SignedMessage(signed) = decoded {
        signed.verify(&ExampleMethod, &ExampleSuite)?;
        println!("verified {}", signed.identity().identity_id());
    }
    Ok(())
}
