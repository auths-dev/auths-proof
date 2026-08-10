# Identity-over-Iroh demo architecture

```text
browser -> native Axum demo -> auths-identity          -> canonical neutral bytes
                           -> raw-key + Ed25519 adapters
                           -> auths-iroh              -> real local Iroh connection
```

`auths-identity` owns a closed two-message packet family, bounded opaque key and
signature bytes, domain separation, and public extension traits. It owns no
identity method or cryptographic algorithm. `auths-iroh` owns caller-selected
ALPN negotiation, frames, timeouts, and peer observations; its payload is opaque.

The Iroh endpoint identifier and exchanged application identity are reported as
separate facts. The transport never turns either into an Auths authorization
verdict. The browser receives only public keys, principals, message/signature
evidence, endpoint identifiers, and explicit statements about which higher
layers did not participate.

## Measured library footprint

Cargo metadata for `auths-identity` reports zero workspace dependencies and no
cryptographic or network dependencies. The optional raw-key and Ed25519
adapters each depend only on `auths-identity` plus their implementation library.
`auths-iroh` has `iroh` and `tokio` dependencies and zero workspace dependencies.

The architecture policy independently encodes both closures and checks them
transitively. Adding any workspace dependency to the neutral identity port or
Iroh transport, or coupling an identity adapter to authority semantics, fails CI.
