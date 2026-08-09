# Identity-over-Iroh demo architecture

```text
browser -> native Axum demo -> auths-identity -> canonical identity bytes
                           -> auths-iroh     -> real local Iroh connection
```

The demo composes two independent components. `auths-identity` owns a closed
two-message packet family, canonical raw-key descriptors, and domain-separated
signature bytes. `auths-iroh` owns caller-selected ALPN negotiation, bounded
length-prefixed frames, timeouts, and peer observations; its payload is opaque.

The Iroh endpoint identifier and exchanged Ed25519 identity are reported as
separate facts. The transport never turns either into an Auths authorization
verdict. The browser receives only public keys, principals, message/signature
evidence, endpoint identifiers, and explicit statements about which higher
layers did not participate.

## Measured library footprint

Cargo metadata for `auths-identity` reports four direct and transitive workspace
dependencies: `auths-model`, `auths-ports`, `auths-raw-key`, and
`auths-signature`. It has no network dependency. `auths-iroh` has two runtime
dependencies, `iroh` and `tokio`, and zero workspace dependencies.

The architecture policy independently encodes both closures and checks them
transitively. Adding a network dependency to identity, or any Auths semantic
dependency to Iroh, fails CI until the boundary is deliberately reviewed.
