# Contributing

## Before changing code

Read:

- `AUTHS_PROOF_GREENFIELD_FOUNDATION.md`;
- `docs/architecture.md`;
- `docs/threat-model.md`;
- `spec/v1/protocol.md`.

The main dependency rule is:

> Auths owns authority. Adapters prove principal control.

Do not add networking, filesystem, system clock, randomness, private keys,
databases, async runtimes, or concrete adapters to the verifier graph.

## Required checks

```sh
cargo xtask ci
```

This runs formatting, checks, tests, Clippy, architecture validation, golden
vectors, and the WASM build.

For focused work:

```sh
cargo xtask product
cargo xtask arch
cargo xtask wire
cargo xtask conformance
cargo xtask wasm
cargo xtask fuzz-smoke
```

## Wire changes

Never update fixtures just to make CI green.

An intentional wire change requires:

1. an ADR explaining compatibility impact;
2. CDDL, protocol, registry, and domain-separation updates;
3. reviewed positive and negative vectors;
4. `cargo xtask wire --update`;
5. cross-target tests;
6. a protocol-version decision.

## New adapters

A principal adapter must:

- have an exact registered adapter ID and evidence media type;
- reject unsupported principal prefixes;
- bind principal, verification method, purpose, key, and algorithm;
- enforce canonical key/signature encoding;
- report only assurance it established;
- never fall back to another adapter;
- pass the shared conformance suite;
- document resolution, freshness, history, rotation, and revocation semantics.

Resolvers remain separate from pure verification adapters.

## Tests

Security regression tests should assert the exact `Decision` and
`VerdictReason`. Include tampering, truncation, substitution, replay-context,
resource-limit, and non-canonical cases where applicable.
