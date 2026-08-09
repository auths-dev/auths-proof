# Identity-over-Iroh demo architecture

```text
browser -> native Axum demo -> real local Iroh connection
                              -> auths-identity-iroh
                                 -> auths-raw-key
                                 -> auths-signature
```

The exchange adapter is a complete vertical protocol for public identity and
signed identity messages. It uses a dedicated ALPN, bounded length-prefixed
frames, a closed two-message packet family, canonical raw-key descriptors, and
domain-separated signature bytes.

The Iroh endpoint identifier and exchanged Ed25519 identity are reported as
separate facts. The transport never turns either into an Auths authorization
verdict. The browser receives only public keys, principals, message/signature
evidence, endpoint identifiers, and explicit statements about which higher
layers did not participate.

## Measured library footprint

Cargo metadata for `auths-identity-iroh` reports six direct runtime
dependencies: four Auths workspace packages (`auths-model`, `auths-ports`,
`auths-raw-key`, and `auths-signature`) plus `iroh` and `tokio`. Its complete
transitive workspace closure is still those same four packages. It reaches
zero product, binding, or demo packages.

The architecture policy encodes that four-package closure as an allowlist and
checks it transitively on every architecture run. This measurement therefore
doubles as a regression budget: adding any other workspace package fails CI
until the boundary is deliberately reviewed and changed.
