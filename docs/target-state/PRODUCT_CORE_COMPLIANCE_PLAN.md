# Product-to-Core Compliance Plan

## Objective

Keep every product, binding, and demo surface exactly aligned with the
authoritative Auths kernel after the monorepo consolidation.

Compliance is a continuously enforced property, not a one-time migration. A
surface is compliant only when it preserves authorization meaning, fails
closed on malformed or unavailable inputs, declares every core and wire
contract it consumes, and has executable evidence for every claimed role.

## Post-Merge Baseline

The repository now has five shipping layers:

- `core/`: offline protocol kernel, model, codec, verifier, adapters, canonical
  corpus, and fuzzing.
- `exchange/`: transport-neutral exchange protocol and transport adapters.
- `product/`: profiles, SDK, runtime, configuration, state, custody, evidence,
  receipts, cache, and operations.
- `bindings/`: WASM, TypeScript, Python, and independent implementations.
- `demos/`: reference flows, testkits, matrix analysis, and benchmarks.

`xtask` remains the non-shipping control plane. `auths-proof-site` and
`auths-proof-docs` remain separate consumers of immutable platform artifacts.

The migration-era compatibility failures are already corrected:

- Product code uses the current `VerifierContext`, assurance, registry, limit,
  and work-meter APIs.
- Registry construction commits every adapter configuration.
- Portable results expose the configuration required by the trusted context
  and the configuration executed locally.
- Rust, WASM, TypeScript, and Python consume portable ABI version 2.
- The canonical core corpus is byte-stable and has independent Rust, Go, and
  TypeScript semantic verification.
- Runtime execution is reachable only through sealed verified actions.
- Replay, budget, receipt, cache, and transport-policy invariants have
  deterministic tests.
- Release checks build and install the published Rust, npm, Python, and WASM
  artifacts.

The remaining work is therefore enforcement against future drift.

## Authoritative Compliance Manifest

`compliance.toml` is the checked-in source of truth for product-facing
compliance claims.

It covers every Cargo package classified by `architecture.toml` as `product`,
`bindings`, or `demos`, plus every publishable npm package and every Go module
under those layers.

Every package declares:

- Package kind, layer, and repository path.
- Direct core APIs consumed.
- Supported protocol versions and wire objects.
- Canonical fixture suites exercised.
- Principal, signature, profile, and transport families.
- Configuration commitment inputs.
- Security-sensitive state owned.
- One or more behavioral roles.
- At least one executable test anchor for every role.

The allowed roles cover:

- Core API and wire consumers/producers.
- Profile contracts and canonicalizers.
- Proof authors, custody, and evidence integrations.
- Runtime enforcement and replay/budget state.
- Receipt/audit producers and consumers.
- Configuration compilation and operational diagnostics.
- Verification caches.
- Language bindings and independent semantic implementations.
- Demo and conformance fixtures.

Adding, removing, moving, or reclassifying a package without updating its
compliance declaration fails CI. A Cargo package's declared core APIs must
exactly match its direct core dependencies from `cargo metadata`.

## Configuration Terminology

The trusted context carries the `required_configuration`: the exact verifier
configuration the caller requires.

The process reports the `executed_configuration`: the immutable registry and
adapter configuration actually installed for verification.

The portable ABI retains the stable `local_configuration` field name; its
meaning is the executed configuration. Authorized results require equality.
`verifier-configuration-mismatch` requires both values to be present and
unequal. Startup configuration and readiness APIs use the clearer required and
executed terminology.

## Compliance Command

The authoritative command is:

```text
cargo xtask compliance
```

It performs these gates:

1. Validate the complete package and external-language inventory.
2. Validate every declared surface and executable test anchor.
3. Enforce architecture, ownership, dependency direction, and exact direct
   core API declarations.
4. Run all product package tests.
5. Verify schema synchronization and all canonical core fixtures.
6. Compare Rust, Go, and TypeScript semantic results.
7. Run exchange and product end-to-end conformance.
8. Verify product profile fixtures and the compatibility matrix.
9. Build and test WASM, TypeScript, Python, and Go surfaces.
10. Install npm and Python artifacts in clean consumers.
11. Package every publishable Rust crate.
12. Emit deterministic compliance evidence.

The command writes:

- `target/compliance/inventory.json`
- `target/compliance/report.json`
- `target/compliance/summary.txt`

The inventory binds the compliance manifest, architecture snapshot, and
canonical corpus by SHA-256. The report contains only deterministic pass/fail
claims and the shared semantic digest; it contains no timestamps, absolute
paths, proof contents, or principals.

## Continuous Gates

### Core API and Architecture

- `architecture.toml` remains authoritative for package placement and allowed
  dependency direction.
- Core cannot depend on exchange, product, bindings, demos, networking,
  persistence, custody, or ambient configuration.
- Product contracts depend on the lowest valid layer.
- Direct core dependency drift must update both the architecture snapshot and
  the compliance declaration after review.
- Compatibility shims for obsolete constructors or ABI versions are not
  accepted.

### Portable ABI

Rust, WASM, TypeScript, and Python:

- Support exactly portable ABI version 2.
- Enforce bounded canonical CBOR and exact ordered map semantics.
- Reject missing, duplicate, reordered, unsupported, or trailing fields.
- Expose decision, stable code, stage, resource counters, result bytes,
  required configuration, and executed/local configuration.
- Construct executable actions only from sealed authorized output.

Independent semantic implementations such as Go do not claim portable-result
byte identity unless they implement the portable encoder. They must still
match the canonical corpus decision, code, digests, plan, authorized branches,
and assurance semantics for their declared scope.

### Fixtures and Profiles

- `core/fixtures/v1` is the only canonical core corpus.
- Product and demos may consume but never regenerate core fixtures.
- Product scenarios live under `product/fixtures` or `demos/fixtures`.
- Profile canonicalization must be deterministic and reject ambiguous,
  unknown, duplicate, oversized, excessive-depth, Unicode-confusable, or
  non-canonical inputs.
- Approval displays bind the exact canonical action.
- Cross-language profile support cannot be claimed without vectors and test
  evidence.

### Runtime and State

- Denied and indeterminate results never reach executors.
- Executors receive only commands decoded from sealed verified actions.
- Replay claims occur atomically before execution.
- Concurrent duplicate requests execute at most once.
- Budget claims are atomic, bounded, and keyed by exact action identity.
- Replay, budget, receipt, or resolver unavailability fails closed.
- Transport authentication never upgrades an invalid Auths proof.
- Signed channel policy must agree with runtime transport policy.
- Cache keys bind proof, canonical action, complete context, registry manifest,
  and verifier configuration commitments.

### Identity, Custody, and Evidence

- Signing intent binds the exact core signing preimage and descriptor.
- External providers cannot substitute method, suite, key, purpose, or action.
- Sensitive equality uses constant-time comparison.
- Secret material is zeroized at ownership boundaries.
- Resolver output is bounded, host-policy constrained, and converted into
  explicit evidence.
- Every provider-controlled substitution field has negative test evidence
  before production support is claimed.

### Configuration and Operations

- Configuration compilation is deterministic.
- Startup binds configuration digest, complete context digest, registry
  manifest, profiles, limits, channel policy, required verifier
  configuration, and executed verifier configuration.
- Startup fails before serving when required and executed configurations
  differ.
- Readiness exposes both configuration commitments.
- Diagnostics remain low-cardinality, payload-free, and principal-free.

### Storage and Receipts

- Persistent formats are canonical, versioned, and bounded.
- Corrupt or partially written state fails closed.
- No-clobber, idempotency, reopen, and failure-spool behavior is tested.
- Decision and execution receipts bind the exact verification and execution
  commitments.
- Audit bundles reject missing, duplicate, mutated, or unrelated artifacts.
- Distributed adapters are not production-claimed until backend-specific
  cross-process atomicity tests exist.

### Packages and Releases

- Rust consumers are tested from `.crate` archives.
- npm consumers are tested from the packed `.tgz` with packaged WASM.
- Python consumers are tested from a wheel in a fresh virtual environment.
- Go has no local replacements.
- Generated distributions are reproducible and stale checked-in output is
  rejected.
- Release evidence includes the compliance inventory, report, and human
  summary as checksummed subjects.

## CI and Branch Protection

GitHub Actions exposes a dedicated `compliance` job that runs
`cargo xtask compliance` and uploads `target/compliance/` as a retained
artifact.

Repository branch protection must require the `compliance` job in addition to
the authoritative build, dependency policy, and secret scanning jobs.

## Completion Criteria

- Every scoped Cargo, npm, and Go package is inventoried.
- Every claimed behavioral role resolves to executable test evidence.
- Declared Cargo core APIs exactly match workspace metadata.
- Required and executed verifier configurations are compared at startup and
  exposed in readiness diagnostics.
- Portable bindings reject malformed shape, ABI version, and trailing data.
- Every claimed implementation passes its canonical fixture scope.
- Runtime, replay, budget, receipt, cache, and transport invariants pass.
- Built package smoke tests pass in clean consumers.
- `cargo xtask compliance` produces deterministic evidence.
- CI has a standalone, artifact-producing `compliance` job suitable for branch
  protection.
