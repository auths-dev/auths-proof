# auths-identity-raw-key

`auths-identity-raw-key` is the reference self-certifying raw-key identity
method. It accepts any bounded suite label and public-key byte shape, so it can
be composed with Ed25519, P-256, post-quantum, or caller-owned suites.

Security claim: the identity identifier is the canonical raw-key V2 digest of
the declared suite and exact public-key bytes.

It does **not** verify signatures, choose a cryptographic algorithm, establish
application trust, create authority, or grant a capability. It is a reference
adapter, not a required identity shape.

```rust
use auths_identity_raw_key::RawKeyIdentityMethod;

let identity = RawKeyIdentityMethod::identity("p256-sha256:v1", vec![2; 33])?;
assert_eq!(identity.suite_id(), "p256-sha256:v1");
# Ok::<(), auths_identity::IdentityError>(())
```

The package follows `auths-identity/v1`, is versioned `1.0.0-rc.1`, has an MSRV
of Rust 1.91, and supports `no_std` with `alloc`.
