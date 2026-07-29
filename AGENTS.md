# Auths Proof Repository Contract

This file is the canonical instruction set for agents working anywhere in this
repository. Read it before changing code, manifests, fixtures, generated
artifacts, CI, or repository structure.

After reading this file, every agent must also read
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md` before
planning or changing repository code. It defines the required vertical-first
process for adding profiles and domains, the evidence gates for extracting
shared mechanisms, and the boundaries that prevent premature semantic
coupling. Existing abstractions are not permission to bypass that review.

`AGENTS.md`, `architecture.toml`, `compliance.toml`, workspace metadata, and
`xtask` remain authoritative if the target-state document ever conflicts with
executable repository policy.

## The decision is already made

`auths-proof` is intentionally one monorepo. It consolidates the maintained
code that previously lived in `auths-proof`, `auths-proof-exchange`, and
`auths-proof-apps`.

Do not split those components back into repositories, recreate implementations
in the retired repositories, or treat the old repositories as sources of
truth. They are retirement records only.

The monorepo exists so a protocol change can update, in one atomic review:

- the offline security kernel;
- exchange formats and transports;
- product profiles and enforcement;
- language bindings;
- fixtures, conformance tests, demos, and release evidence.

The previous multi-repository layout made compatibility a cross-repository
coordination problem. It allowed version skew, duplicated fixtures, delayed
binding updates, and ambiguous ownership of integration failures. The monorepo
turns those risks into local dependency rules and one authoritative CI result.

This is not permission to create a dependency free-for-all. The repository is
a **layered monolith of packages**, not a single application. Boundaries are
machine-enforced by `architecture.toml`, `compliance.toml`, workspace metadata,
and `xtask`. Keeping the code together is what lets those boundaries be tested
rigorously.

`auths-proof-site` and `auths-proof-docs` remain separate repositories. They
must consume published packages, release artifacts, or explicitly pinned
platform metadata. Never connect them to this repository with mutable sibling
path dependencies.

## Sources of architectural truth

Treat these files as executable policy:

1. `architecture.toml` owns layer classification, allowed dependency
   directions, package placement, ownership, MSRV, and dependency constraints.
2. `compliance.toml` owns the inventory of product, binding, and demo
   consumers, including protocol objects, configurations, security state, and
   the tests that prove each claim.
3. The root `Cargo.toml` owns workspace membership, shared dependency versions,
   Rust edition, resolver, and workspace lints.
4. `xtask/src/main.rs` owns the authoritative local checks and generated
   evidence.
5. Canonical fixtures under `core/fixtures/` own the portable wire corpus.

Do not work around these policies. If a valid architectural change requires a
policy update, change the policy explicitly, update its generated snapshots,
and prove the new boundary in tests. Never weaken a check merely to make a
dependency or package placement pass.

## Layer model

Shipping code belongs to one of five layers:

| Layer | Owns | May depend on |
| --- | --- | --- |
| `core/` | Offline protocol semantics, canonical model and codec, signatures, registries and ports, deterministic authoring and verification, principal adapters, canonical fixtures, fuzzing, formal refinement, core testkit | `core` |
| `exchange/` | Proof exchange model, codec, framing, ports, transports, and exchange conformance | `core`, `exchange` |
| `product/` | Profiles, SDKs, runtimes, enforcement, evidence acquisition, custody, configuration, replay/budget state, receipts, stores, caches, and operations | `core`, `exchange`, `product` |
| `bindings/` | Thin WASM, TypeScript, Python, Go, and other language/ABI surfaces over the portable contract | `core`, `exchange`, `product`, `bindings` |
| `demos/` | Examples, live services, integration testkits, compatibility matrices, and benchmarks | all shipping layers and `demos` |

`xtask/` is the non-shipping control plane. Production packages must never
depend on `xtask` or `demos`.

Allowed dependency flow:

```text
core <- exchange <- product <- bindings
  ^         ^           ^          ^
  +---------+-----------+----------+--- demos
```

An arrow points from a consumer toward a dependency. Dependencies may move
toward `core`; they must not point back toward a higher layer.

### Why the direction matters

- `core` must remain portable, deterministic, auditable, and usable offline.
- `exchange` can move proofs but cannot change what makes a proof valid.
- `product` can add stateful policy and execution behavior but cannot redefine
  core verification.
- `bindings` expose existing semantics; they are not alternate
  implementations.
- `demos` prove integration behavior; production code must not depend on demo
  conveniences.

If a lower layer appears to need a higher-layer type, the abstraction is in the
wrong place. Introduce a narrow port or move the minimal domain type to the
lowest layer that can own it without importing policy or I/O.

## Where new components belong

Choose the **lowest valid layer**, not the layer that is easiest to import from.

Put a component in `core/` only when it:

- can operate from explicit inputs without network, filesystem, process,
  environment, clock, or mutable service state;
- defines portable protocol semantics or a narrow port required by those
  semantics;
- is deterministic and bounded for adversarial inputs;
- can satisfy the core dependency and `no_std` policies where classified.

Resolvers that perform network I/O, hosted policy calls, live key discovery,
custody providers, databases, replay ledgers, and execution engines do not
belong in core. Core may define a narrow input/result contract for them.

Put a component in `exchange/` when its primary responsibility is transporting,
framing, addressing, or exchanging proof material. A transport can authenticate
a channel, but channel authentication must never upgrade an invalid proof into
an authorized action.

Put a component in `product/` when it turns portable verification into an
application capability: a profile, SDK workflow, stateful runtime, enforcement
boundary, evidence assembler, custody integration, configuration compiler,
receipt system, store, cache, or operational surface.

Put a component in `bindings/` only when it exposes existing portable behavior
to another language or ABI. Keep the wrapper thin. It must use the canonical
corpus and stable result codes and must not reimplement verification semantics.

Put a component in `demos/` when it teaches, exercises, benchmarks, or validates
the system without becoming a production dependency. Reusable production logic
discovered while building a demo must move to the appropriate lower layer.

Before creating a crate, search for the existing domain type, port, profile, or
testkit. Prefer extending a coherent package over introducing a near-duplicate.
Crate boundaries are encouraged when they preserve capability or dependency
boundaries; a new repository is not.

Do not add a new top-level shipping directory casually. A sixth layer is an
architecture decision, not file organization. It requires an explicit policy
change, dependency rationale, ownership, CI coverage, and migration plan.

## Required work when adding a package

A new package is incomplete until all applicable items below are handled:

1. Place it under the correct layer and name it consistently.
2. Add it to the root workspace and centralize internal and external
   dependencies in `[workspace.dependencies]`.
3. Classify it in `architecture.toml`.
4. Confirm every dependency edge is allowed. Do not add a policy exception to
   hide a reverse edge.
5. For a product, binding, or demo consumer, add a complete
   `compliance.toml` entry: core APIs, protocol versions, wire objects, fixture
   suites, principal/signature families, profiles, transports, configuration
   inputs, security state, and claim-to-test evidence.
6. Add focused unit tests and boundary tests. Add conformance, regression,
   property, fuzz, cross-language, or integration coverage when the component
   touches the corresponding risk.
7. Update architecture snapshots with `cargo xtask arch --update` when the
   package graph intentionally changes.
8. Run the narrow layer check while iterating, then run the authoritative suite
   before handoff.

Deleting or moving a package requires the inverse work: remove stale workspace,
architecture, compliance, ownership, fixture, and generated-snapshot entries.

## Security invariants that cross every layer

Preserve these invariants even when a local API would be simpler without them:

- Verification fails closed. Unknown, malformed, non-canonical, oversized,
  unsupported, or ambiguous input is rejected with a stable result.
- The action that is executed is derived from verified canonical action bytes,
  never from an unverified request that merely resembles them.
- Authority may be preserved or narrowed through delegation; it must never be
  amplified.
- Parsing and verification of attacker-controlled input are bounded in bytes,
  collection sizes, chain depth, work, and recursion.
- Malformed external input returns a typed error or denial; it must not panic.
- Required verifier configuration and executed verifier configuration are both
  reported and tested. A mismatch is an explicit failure, not diagnostic noise.
- Transport identity, successful decoding, evidence presence, or a valid
  signature alone is not authorization.
- Replay protection, budgets, challenges, storage, and exactly-once execution
  are stateful product concerns. Do not smuggle mutable state into the offline
  kernel.
- Verification may be repeated. Irreversible execution must be claimed and
  recorded at the enforcement boundary.
- Bindings and independent implementations must agree with native behavior on
  canonical fixtures and stable result codes.
- Cryptographic behavior uses vetted libraries and constant-time operations
  where applicable. Do not invent primitives.

Treat all public inputs as adversarial. Keep secrets out of fixtures, logs,
errors, generated evidence, and repository history.

## Wire formats, fixtures, and compatibility

`core/fixtures/v1` is the single source of truth for the core portable corpus.
Higher layers may add scenario fixtures but must not fork core vectors or
silently generate different bytes.

- Never hand-edit canonical `.cbor` fixtures.
- Use `cargo xtask wire` to verify them.
- Use `cargo xtask wire --update` only for an intentional, reviewed protocol
  change.
- A wire change must update the model/codec, relevant specification, manifest,
  native tests, bindings, independent implementations, and compatibility
  evidence together.
- Do not change stable codes or serialized shapes as a refactor side effect.
- Prefer additive versioned evolution. Make incompatible changes explicit.

Regression tests should retain the smallest input that reproduces a failure,
including exact byte-length boundary seeds when the bug depends on a hard
limit.

## Dependencies and portability

- Add external dependencies only when an existing workspace dependency or a
  small local implementation cannot satisfy the requirement safely.
- Declare shared versions at the workspace root.
- Prefer `default-features = false` and opt into only required features.
- Keep core free of networking, async runtimes, databases, hosted SDKs, and
  platform key stores. `architecture.toml` contains the enforced forbidden
  dependency list.
- Do not add build scripts or native dependencies without updating the explicit
  approvals and providing a security/portability rationale.
- Preserve the configured MSRV, Rust 2024 edition, resolver 3, and workspace
  lint policy. The manifest and architecture policy are authoritative if
  versions advance.
- Preserve `no_std` for packages classified as such. Do not make `std` the
  accidental default through a transitive feature.

Commit lockfile and generated dependency-graph changes when they are the
intentional result of a dependency update. Do not regenerate them gratuitously.

## Implementation standards

- `unsafe` code is forbidden by workspace policy.
- Keep domain workflows separate from I/O and orchestration. Ports belong at
  the boundary; business and verification logic should be independently
  testable.
- Parse untrusted input directly into typed domain structures. Avoid passing
  unchecked strings, loosely typed JSON, or combinations of flags that permit
  invalid states downstream.
- Use domain-specific typed errors in libraries. Operational binaries may add
  process, path, or environment context at the outer boundary, but must preserve
  the typed source error.
- Production code must not use `unwrap()` or `expect()` for fallible external
  input. For a genuinely infallible invariant, prefer a structure that proves
  it; otherwise use the narrowest local lint allowance with an `INVARIANT:`
  explanation. Never add a crate-wide blanket allowance.
- Exported core and SDK APIs require useful Rustdoc describing the contract,
  inputs, outputs, errors, limits, and security-relevant behavior.
- Secret material, signing seeds, nonces, and session tokens must be scoped
  narrowly and zeroized on drop where they enter process memory.
- Use constant-time comparison for security-sensitive tokens and byte values.
- Use property-based tests for parsers, arithmetic, state-machine boundaries,
  and FFI/WASM decoding where a few examples cannot cover the invariant space.
- Comments should record non-obvious invariants and design decisions, not
  narrate implementation steps.

## Testing and handoff

Use the smallest useful check during development:

```text
cargo xtask core
cargo xtask exchange
cargo xtask product
cargo xtask bindings
cargo xtask demos
cargo xtask arch
cargo xtask compliance
cargo xtask wire
```

Format changed Rust with `cargo fmt --all`. Before handoff, run:

```text
cargo xtask ci
```

That command is authoritative: it covers formatting, architecture and
repository hygiene, workspace build/test/clippy, core boundaries, MSRV, ABI,
exchange and product conformance, fixtures, compatibility matrix, bindings,
package smoke tests, release evidence, fuzz smoke tests, WASM, and compliance
evidence.

CI separately enforces dependency policy and secret scanning. Release work must
also pass `cargo xtask release-check`.

Do not claim completion because a narrow crate test passed when the change
affects wire compatibility, another language, a layer boundary, or generated
evidence. Report exactly which checks ran and any checks that could not run.

## Change discipline for agents

- Preserve unrelated user changes. Never clean, reset, reformat, or stage files
  outside the requested scope.
- Do not use an architecture exception as a shortcut.
- Do not duplicate canonical types, fixtures, error codes, or verification
  logic in a higher layer.
- Do not make demos or bindings the source of protocol truth.
- Do not reintroduce cross-repository mutable dependencies.
- Do not silently weaken limits, fail-open behavior, test claims, ownership, or
  CI coverage.
- If a request appears to contradict these constraints, explain the conflict
  with the exact policy and propose the compliant design. Do not assume the
  architecture was accidental.

The correct default is: keep the change inside this monorepo, put it in the
lowest valid layer, depend only downward, record its compliance surface, and
make the full repository prove that the change is compatible.
