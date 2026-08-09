use std::error::Error;

use auths_identity::{IdentityPacket, PublicIdentity, SignedIdentityMessage};
use ed25519_dalek::{Signer as _, SigningKey};

fn main() -> Result<(), Box<dyn Error>> {
    let key = SigningKey::from_bytes(&[7; 32]);
    let identity = PublicIdentity::from_ed25519(key.verifying_key().to_bytes())?;
    let message = b"identity works without a transport";
    let preimage = SignedIdentityMessage::signing_preimage(&identity, message)?;
    let packet = IdentityPacket::SignedMessage(SignedIdentityMessage::new(
        identity,
        message.to_vec(),
        key.sign(&preimage).to_bytes(),
    )?);
    let decoded = IdentityPacket::decode(&packet.encode()?)?;
    if let IdentityPacket::SignedMessage(signed) = decoded {
        signed.verify()?;
        println!("verified {}", signed.identity().principal());
    }
    Ok(())
}
