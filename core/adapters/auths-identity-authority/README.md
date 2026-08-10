# auths-identity-authority

`auths-identity-authority` is an optional, explicit bridge from a method-
validated identity into the Auths authority model. Identity-only applications
do not need it.

Security claim: the bridge rechecks the raw-key V2 relationship and preserves
its canonical principal, suite, verification material, and evidence in types
accepted by the authority layer.

It does **not** authorize an action, mint a capability, approve a request, or
turn transport authentication into authority. Promotion is caller-selected and
produces authority-shaped input only.

```rust
use auths_identity_authority::{PrincipalFromIdentity, RawKeyV2AuthorityBridge};
use auths_identity_raw_key::RawKeyIdentityMethod;

let identity = RawKeyIdentityMethod::identity("example-pq:v1", vec![7; 4096])?;
let authority = RawKeyV2AuthorityBridge.promote(&identity)?;
assert_eq!(authority.principal().as_str(), identity.identity_id());
# Ok::<(), Box<dyn std::error::Error>>(())
```

The package follows `auths-identity/v1`, is versioned `1.0.0-rc.1`, has an MSRV
of Rust 1.91, and supports `no_std` when default features are disabled.
