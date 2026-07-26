# Product-to-Core Compliance Plan

## Objective

Bring every component moved from `auths-proof-apps` into exact alignment with
the current `auths-proof` kernel, schemas, fixtures, result semantics,
configuration commitments, and security boundaries.

Compliance means more than compiling. Every product and language surface must
preserve the same authorization meaning, fail closed on the same malformed
inputs, and expose the same stable result information.

## Current Baseline

Before migration, record the known incompatibilities as regression tests:

- Product SDK uses the previous `VerifierContext` constructor.
- Product testkit uses the previous assurance requirement and context shapes.
- Receipt test adapters do not implement the current configuration commitment.
- TypeScript decodes an obsolete portable-result shape.
- TypeScript and Python do not expose both required and local verifier
  configuration IDs.
- Product fixtures and generated packages are not proven to match the current
  core portable ABI.

The initial compliance branch is expected to be red until these findings are
converted into passing tests.

## Compliance Inventory

Generate `target/compliance/inventory.json` from workspace metadata and source
manifests. Classify every moved package as:

- Core API consumer.
- Core wire producer.
- Core wire consumer.
- Profile canonicalizer.
- Proof author or assembler.
- Principal/evidence integration.
- Runtime enforcement boundary.
- Stateful replay/budget component.
- Receipt producer/consumer.
- Language binding.
- Independent semantic implementation.
- Demo or conformance fixture.

Every package must declare:

- Core APIs and protocol versions consumed.
- Wire objects encoded or decoded.
- Canonical fixture suites exercised.
- Supported principal, signature, profile, and transport families.
- Configuration-ID inputs.
- Security-sensitive state owned.

CI fails when a package is unclassified or its declared surface lacks a test.

## Phase 1: Restore Rust API Compatibility

Update all product Rust packages to the current core API:

- Construct `VerifierContext` with an explicit verifier configuration ID and
  composition requirement.
- Require explicit assurance quantifiers.
- Implement `configuration_id` for all adapter and test implementations.
- Include adapter configuration IDs in immutable registry construction.
- Propagate required/local verifier configurations through SDK explanations,
  receipts, audit artifacts, and operational diagnostics where appropriate.
- Use the current resource limits and work-meter semantics.
- Remove compatibility shims rather than carrying obsolete constructors.

Add compile-fail or API tests proving old ambiguous construction paths are no
longer available.

## Phase 2: Portable ABI Alignment

Treat the core schema and golden corpus as authoritative.

For every Rust, WASM, TypeScript, Python, and Go result decoder:

- Support exactly the current portable ABI version.
- Decode `required_configuration` as optional only when the trusted context
  cannot be decoded.
- Decode `local_configuration` on every result.
- Verify canonical key order, exact map shape, bounded collections, stable
  result code, and self-binding result digest.
- Reject older/newer unsupported ABI versions explicitly.
- Reject missing, duplicate, reordered, or trailing fields.
- Assert authorized results carry equal required/local configuration IDs.
- Assert `verifier-configuration-mismatch` carries two present and unequal IDs.

Where practical, generate field numbers and ABI constants from one checked-in
schema projection. Handwritten decoders remain independently tested and must
not copy behavior from one another.

## Phase 3: Canonical Fixture Compliance

Core owns `core/fixtures/v1`; product code cannot regenerate or edit it.

Build a language-neutral compliance runner that executes every core fixture
through:

- Native Rust verifier.
- WASM verifier.
- TypeScript package.
- Python wheel.
- Independent Go verifier where its supported scope applies.

For each implementation compare:

- Decision class.
- Stable code.
- Verification stage.
- Plan ID.
- Required/local configuration IDs.
- Resource counters.
- Canonical result bytes when the implementation promises byte identity.

Product-specific scenarios live under `product/fixtures` or `demos/fixtures`
and record the exact core corpus/schema fingerprint against which they were
generated.

## Phase 4: Profile Semantic Compliance

For MCP, HTTP, Git, deployment, supply-chain, and edge profiles:

- Canonicalizing identical semantic input twice produces identical bytes.
- Reference and independent implementations agree.
- Approval display digest binds the exact canonical action.
- Hostile mutations cannot retain the original permission or action digest.
- Derived permission, audience, budget, and resource identifiers are exact.
- Unknown fields, duplicate fields, ambiguous JSON, excessive depth, excessive
  size, and non-canonical values fail closed.
- A verified action is decoded only from the sealed verifier output, never from
  the original untrusted request.

Add cross-language profile vectors for every supported profile before claiming
that profile in a language SDK.

## Phase 5: Runtime and Enforcement Compliance

Verify the product runtime preserves core decisions without widening:

- Denied and indeterminate results never reach an executor.
- Executors receive only commands decoded from sealed verified actions.
- Challenge claim occurs atomically before execution.
- Concurrent duplicate requests execute exactly once.
- Budget claims are atomic, bounded, and keyed by the correct action identity.
- Unavailable replay or budget state fails closed.
- Receipt-policy behavior is explicit for fail-closed and local-spool modes.
- Transport authentication never upgrades an invalid Auths proof.
- Signed channel-binding policy agrees with runtime transport policy.
- Configuration mismatch exposes required and local IDs without executing.
- Cache keys include proof, canonical action, complete context, registry
  manifest, and verifier configuration commitments.

Use deterministic concurrency tests plus Loom/model tests for claim state
machines.

## Phase 6: Identity, Custody, and Evidence Compliance

For custody and evidence assemblers:

- Signing intent includes the exact core signing preimage and descriptor.
- Private material is never copied into ordinary long-lived buffers.
- Sensitive values are zeroized on drop.
- Security-sensitive equality uses constant-time comparison.
- External signer implementations cannot substitute method, suite, key,
  purpose, or action bytes.
- Evidence assemblers bind the exact expected media type and evidence ID.
- Trust-root and status ordering are canonical.
- Duplicate trust or status records fail closed.
- Resolver output is bounded, host-policy constrained, and converted into
  explicit evidence rather than hidden verifier I/O.

Add at least one negative test for every field an external provider could
substitute.

## Phase 7: Configuration and Operations Compliance

Unify declarative product configuration with the core context:

- Configuration compilation produces a deterministic digest.
- The compiled product configuration binds to the complete core context,
  registry manifest, local verifier configuration, profiles, limits, and
  channel policy.
- Startup fails before serving when any binding differs.
- Readiness reports required and local configuration IDs.
- Fleet diagnostics can identify configuration drift without exposing proof
  contents or principals.
- Operational events remain low-cardinality and payload-free.
- Metrics exporters preserve privacy classifications.

Add a startup conformance test that loads every supported production
configuration and verifies the resulting context and registry IDs.

## Phase 8: Storage and Receipt Compliance

For replay, budget, receipt, and audit stores:

- Persisted formats are canonical, versioned, and bounded.
- Corrupt or partially written state fails closed.
- No-clobber and idempotency behavior is tested.
- Concurrent claims are atomic across threads and, for distributed adapters,
  across processes.
- Receipt IDs and attestations are recomputed before acceptance.
- Decision receipts include the exact portable result commitments.
- Execution receipts bind the authorized decision and actual execution
  outcome.
- Audit bundles reject missing, duplicated, or unrelated artifacts.
- Migration and recovery tests cover every persistent schema version.

Add production distributed adapters only after their atomicity behavior has a
backend-specific integration test.

## Phase 9: Language Package Compliance

Rust, npm, Python, and Go packages must provide equivalent minimum semantics:

- Three-way authorized/denied/indeterminate result.
- Stable code and stage.
- Required/local configuration IDs.
- Resource metrics.
- Sealed verified-action boundary.
- Canonical result bytes.
- Explicit supported ABI and profile versions.

Test only built artifacts:

- Rust `.crate` in a clean consumer.
- npm `.tgz` with packaged WASM.
- Python wheel in a fresh virtual environment.
- Go module without local replacements.

Generated distributions must either be release artifacts or checked for exact
source reproducibility; stale checked-in `dist` output is forbidden.

## Phase 10: Differential and Adversarial Testing

Add:

- Differential result testing across native, WASM, TypeScript, Python, and Go.
- Property tests for every handwritten decoder.
- Fuzzing for FFI, WASM, JSON profile, receipt, and exchange boundaries.
- Mutation tests for configuration, proof, action, receipt, and channel
  bindings.
- Resource-boundary tests at exact limit, one below, and one above.
- Replay and budget race tests.
- Fault injection for storage, clocks, receipt sinks, resolvers, and executors.

No implementation may treat a panic, exception, or unavailable dependency as
authorization.

## Compliance CI Command

Add:

```text
cargo xtask compliance
```

It runs:

1. Inventory completeness.
2. Rust API and architecture checks.
3. ABI/schema synchronization.
4. Canonical core corpus across all languages.
5. Product profile vectors.
6. Runtime and state-machine tests.
7. Receipt/audit verification.
8. Built-package smoke tests.
9. Differential semantic report.

The command writes a deterministic machine-readable report and a concise human
summary. CI uploads both.

## Completion Criteria

- The full monorepo builds from one commit.
- No obsolete core constructor or ABI assumption remains.
- Every binding exposes required/local configuration semantics.
- Every canonical core fixture passes in every claimed implementation.
- Every product profile has canonical and hostile cross-language vectors.
- Runtime replay, budget, execution, and receipt invariants pass concurrency
  and fault-injection tests.
- All packages install and run from release artifacts.
- `cargo xtask compliance` is a required branch-protection check.

