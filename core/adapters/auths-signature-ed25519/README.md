# auths-signature-ed25519

`auths-signature-ed25519` is the optional Ed25519 implementation of the neutral
`auths-identity` signature-verifier port.

Security claim: it verifies the exact supplied preimage and signature under the
declared Ed25519 V1 suite through the shared Auths signature semantics.

It does **not** define identity shape, decide whether a key is trusted, create
authority, or approve an action. Applications may replace it with P-256,
post-quantum, hardware-backed, or other suite adapters.

```rust
use auths_identity::SignatureVerifier;
use auths_signature_ed25519::{Ed25519Verifier, ED25519_V1};

assert_eq!(Ed25519Verifier.suite_id(), ED25519_V1);
```

The package follows `auths-identity/v1`, is versioned `1.0.0-rc.1`, has an MSRV
of Rust 1.91, and is `no_std` compatible.
