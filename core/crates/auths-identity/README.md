# auths-identity

`auths-identity` is the neutral, `no_std`-compatible identity port for Auths. It
defines bounded identity data, distinct decoded/validated/authenticated states,
canonical identity-message bytes, and extension traits for identity methods and
signature suites.

Security claim: a `ValidatedIdentity` was checked by the exact
`IdentityMethod` selected by the caller, and an `AuthenticatedIdentityMessage`
binds the exact message bytes to that validated identity through the selected
`SignatureVerifier`.

It does **not** claim that an identity is authorized, approved, trusted by an
application, or related to a transport peer. The crate has no capability,
approval, policy, authority, network, or product-runtime dependency.

```rust
use auths_identity::{IdentityError, IdentityMethod, PublicIdentity};

struct MyMethod;

impl IdentityMethod for MyMethod {
    fn method_id(&self) -> &'static str { "example:p256:v1" }

    fn validate(&self, identity: &PublicIdentity) -> Result<(), IdentityError> {
        if identity.public_key().len() == 33 { Ok(()) }
        else { Err(IdentityError::InvalidPublicKey) }
    }
}

let decoded = PublicIdentity::new(
    "example:p256:v1",
    "customer-key-7",
    "p256-sha256:v1",
    vec![2; 33],
)?;
let validated = decoded.validate(&MyMethod)?;
assert_eq!(validated.identity_id(), "customer-key-7");
# Ok::<(), IdentityError>(())
```

Compatibility family: `auths-identity/v1` (model 1, wire 2, signing domain 2).
The package version is `1.0.0-rc.1`, its MSRV is Rust 1.91, and it supports
`no_std` with `alloc`. See the repository's modular-component compatibility
table and third-party adapter conformance guide for the complete contract.
