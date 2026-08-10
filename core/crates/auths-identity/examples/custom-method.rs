use auths_identity::{IdentityError, IdentityMethod, PublicIdentity};

struct ExampleP256Method;

impl IdentityMethod for ExampleP256Method {
    fn method_id(&self) -> &'static str {
        "example:p256:v1"
    }

    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
        if identity.public_key().len() == 33 {
            Ok(())
        } else {
            Err(IdentityError::InvalidPublicKey)
        }
    }
}

fn main() -> Result<(), IdentityError> {
    let decoded = PublicIdentity::new(
        "example:p256:v1",
        "customer-key-7",
        "p256-sha256:v1",
        vec![2; 33],
    )?;
    let validated = decoded.validate(&ExampleP256Method)?;
    assert_eq!(validated.identity_id(), "customer-key-7");
    Ok(())
}
