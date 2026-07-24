# Compatibility

## Versioning

V1 wire objects carry protocol version `1`. Decoders reject every other
version and unknown fields. There is no “best effort” parsing.

The normative compatibility set is:

- `spec/v1/auths-proof.cddl`;
- `spec/v1/domain-separation.md`;
- `spec/v1/registry.md`;
- `fixtures/v1/manifest.json`;
- exact bytes under `fixtures/v1/`.

`cargo xtask wire` regenerates fixtures in memory and fails if checked-in bytes
or manifest differ. Intentional changes require review and
`cargo xtask wire --update`.

## Rust targets

Milestone 3 supports:

- the pinned stable Rust toolchain;
- the workspace MSRV declared in `Cargo.toml`;
- native CLI/tests on supported Rust hosts;
- `auths-proof-verifier`, `auths-proof-multikey`, and all pure principal
  adapters on `wasm32-unknown-unknown` with default features disabled.

The verifier API and pure adapters use no ambient platform facilities. The
native `auths-proof-did-web-http` resolver is intentionally excluded from the
WASM compatibility set.

## Algorithm compatibility

V1 supports only:

- Ed25519, 32-byte public key and 64-byte signature;
- P-256 ECDSA/SHA-256, 33-byte compressed SEC1 key and 64-byte low-S
  signature.

PEM, JWK, DER ECDSA signatures, RSA, secp256k1, SHA-1, and algorithm
auto-detection are not accepted by the V1 adapter profiles.

## Stability status

The crates are version `0.1.0` and pre-audit. The fixture set prevents
accidental change; it does not yet promise long-term wire stability. A V1
stability declaration requires external review and at least one independent
implementation or fixture verifier.
