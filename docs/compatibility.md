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

Target V1 supports:

- the pinned stable Rust toolchain;
- the workspace MSRV declared in `Cargo.toml`;
- native libraries/tests on supported Rust hosts;
- `auths-verifier`, `auths-multikey`, and all pure principal
  adapters on `wasm32-unknown-unknown` with default features disabled.

The verifier API and pure adapters use no ambient platform facilities. The
native `auths-resolver-did-web` integration lives in `auths-proof-apps` and is
therefore outside both the proof workspace and its WASM compatibility set.

## Algorithm compatibility

V1 supports only:

- Ed25519, 32-byte public key and 64-byte signature;
- P-256 ECDSA/SHA-256, 33-byte compressed SEC1 key and 64-byte low-S
  signature.

PEM, JWK, DER ECDSA signatures, RSA, secp256k1, SHA-1, and algorithm
auto-detection are not accepted by the V1 adapter profiles.

## Stability status

The Rust and TypeScript packages are version `1.0.0-rc.1`; the equivalent
Python distribution version is `1.0.0rc1`. They remain prelaunch, pre-audit
release-candidate inputs. The semantic-freeze inventory records the exact V1
meaning and checked-in corpus proposed for the candidate. An incompatible
prelaunch correction requires a new semantic identity and RC ordinal; it does
not create a legacy decode or migration promise. External review remains a
launch requirement and is not implied by corpus, CI, preparation, provenance,
or reproducibility success.
