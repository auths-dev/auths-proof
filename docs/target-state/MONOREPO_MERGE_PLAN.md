# Auths Monorepo Merge Plan

## Objective

Merge `auths-proof`, `auths-proof-exchange`, and `auths-proof-apps` into the
existing `auths-proof` repository without weakening the offline-kernel
boundary. The destination repository may be renamed separately; that
administrative decision does not block the source merge. The merge does not
preserve source repository Git history. File movement is intentionally simple;
the substantive work is establishing machine-enforced architectural,
compatibility, security, and release guarantees.

`auths-proof-site` and `auths-proof-docs` remain separate repositories.

## Target Layout

```text
auths/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── architecture.toml
├── architecture/
│   ├── dependency-graph.json
│   └── dependency-graph.dot
├── docs/
├── core/
│   ├── crates/
│   ├── adapters/
│   ├── testkit/
│   ├── spec/
│   ├── fixtures/
│   └── fuzz/
├── exchange/
│   ├── crates/
│   ├── adapters/
│   ├── testkit/
│   └── spec/
├── product/
│   ├── sdk/
│   ├── profiles/
│   ├── runtime/
│   ├── integrations/
│   ├── receipts/
│   ├── stores/
│   ├── config/
│   ├── cache/
│   ├── operations/
│   ├── fixtures/
│   ├── docs/
│   └── spec/
├── bindings/
│   ├── wasm/
│   ├── typescript/
│   ├── python/
│   └── independent/
│       ├── go/
│       └── typescript/
├── demos/
│   ├── matrix/
│   ├── benchmarks/
│   ├── offline-verification/
│   ├── mcp/
│   └── live/
├── xtask/
└── .github/workflows/
```

All Rust packages belong to one top-level Cargo workspace and use one lockfile.
The workspace has one current toolchain for normal development. Packages retain
the `edition` and `rust-version` of their source repository rather than blindly
inheriting a root value; core's MSRV is not raised by exchange or product
dependencies.

Test-support packages are placed in the lowest layer they exercise:

- `auths-testkit` is core because core packages use it as a development
  dependency.
- `auths-proof-exchange-testkit` is exchange.
- `auths-apps-testkit` is demo support because it composes product, exchange,
  and core behavior.

This prevents a package from creating a reverse dependency merely because its
name contains `testkit`.

Root automation is classified as `tooling`, a non-shipping control plane rather
than a sixth product layer. Tooling may inspect or invoke every layer; shipped
packages may never depend on tooling.

## Required Dependency Direction

```text
core <- exchange <- product <- bindings
  ^         ^           ^          ^
  +---------+-----------+----------+--- demos

all shipped layers --------------------> tooling (forbidden)
tooling --------------------------------> all layers (allowed)
```

Allowed edges:

| Source layer | Allowed internal dependencies |
| --- | --- |
| `core` | `core` |
| `exchange` | `core`, `exchange` |
| `product` | `core`, `exchange`, `product` |
| `bindings` | `core`, `exchange`, `product`, `bindings` |
| `demos` | every layer |
| `tooling` | every layer, `tooling` |

No reverse edge is permitted through normal, optional, development,
build-time, target-specific, or feature-gated dependencies. The policy applies
to declared edges even when a feature is disabled in the current build.

## Source-to-Target Mapping

The migration uses the following explicit mapping:

| Source | Destination |
| --- | --- |
| `auths-proof/crates/*` except `auths-testkit` | `core/crates/*` |
| `auths-proof/adapters/*` | `core/adapters/*` |
| `auths-proof/crates/auths-testkit` | `core/testkit/auths-testkit` |
| `auths-proof/spec`, `auths-proof/fixtures`, `auths-proof/fuzz` | same category under `core/` |
| `auths-proof/bindings/auths-proof-wasm` | `bindings/wasm/auths-proof-wasm` |
| `auths-proof/examples/offline-verification` | `demos/offline-verification` |
| Exchange crates except its testkit | `exchange/crates/*` |
| Exchange adapters | `exchange/adapters/*` |
| Exchange testkit | `exchange/testkit/auths-proof-exchange-testkit` |
| Apps SDK, profiles, runtime, integrations, receipts, stores, config, cache, operations | same category under `product/` |
| Apps Python and TypeScript packages | `bindings/python`, `bindings/typescript` |
| Apps independent Go and TypeScript verifiers | `bindings/independent` |
| Apps lab matrix, benchmark, MCP, and test-support packages | corresponding `demos/` directories |
| Apps fixtures | `product/fixtures` |

Only source-controlled inputs move. Build outputs, virtual environments,
`node_modules`, Python caches, locally built extensions, and generated package
directories are recreated by their owning build and must not enter the
destination repository.

## Machine-Readable Architecture Policy

Add a committed `architecture.toml` containing:

- Every workspace package and its layer, including the non-shipping `tooling`
  classification.
- Allowed layer-to-layer edges.
- Core crates permitted to use `std`.
- External dependency allowlists for restricted core crates.
- Approved build scripts and native dependencies.
- Package owners and security reviewers using identifiers that can be matched
  to `CODEOWNERS`.
- Explicit temporary exceptions with owner, reason, issue, and expiry date.

`cargo xtask arch` must parse Cargo's complete declared dependency metadata and
fail when:

- A workspace member is unclassified or classified more than once.
- A package path does not live beneath its declared layer.
- Any dependency edge violates the layer table.
- An optional feature or target-specific dependency creates a forbidden edge.
- A development or build dependency bypasses the architecture.
- A core package introduces a networking, storage, runtime, or UI dependency.
- A core package enables an unapproved default feature.
- A restricted core crate acquires `std`, a build script, native code, or
  filesystem/environment access outside its allowlist.
- Two packages create a normal/build dependency cycle. Development cycles are
  also rejected unless Cargo itself requires a narrowly documented exception.
- An exception is expired, lacks an owner, or has no tracking issue.

The command emits deterministic JSON and DOT graphs. `cargo xtask arch
--update` is the only supported way to update the committed snapshots;
`cargo xtask arch` compares freshly generated data with those snapshots and
prints the exact added and removed edges. The snapshot contains every direct
internal and external declared dependency, its dependency kind, target
condition, optionality, and requested feature/default-feature state. This makes
the snapshot an external-dependency allowlist as well as an internal-boundary
check.

## Kernel Purity Checks

Add `cargo xtask core-boundary` with the following gates:

- Core source cannot import exchange, product, binding, or demo packages.
- Core manifests cannot depend on known networking/runtime packages such as
  HTTP clients, servers, transports, async network runtimes, databases, or
  cloud SDKs unless a narrowly scoped approved exception exists.
- Core verification tests run with networking disabled.
- Core packages must compile with their supported `no_std`/`alloc`
  configurations where declared.
- Core has a dedicated MSRV build independent of the workspace default
  toolchain.
- Every public core crate can be packaged without files from higher layers.
- Packaged core crates are extracted into a temporary external consumer
  workspace and compiled there, proving that no unpublished path dependency is
  required.
- Core fixture generation is owned only by `core`; downstream code is
  read-only against the canonical corpus.
- Core manifests cannot use relative paths that escape `core/`.
- Source scans reject networking, process, filesystem, and environment APIs in
  restricted core packages. The scan is defense in depth; successful
  restricted-feature compilation and dependency checks remain authoritative.

These checks enforce purity by capability and dependency, not by folder name
alone.

## ABI and Fixture Enforcement

Core remains the sole owner of normative wire schemas and golden vectors.

Add `cargo xtask abi` that:

- Validates canonical CBOR vectors byte-for-byte.
- Computes a deterministic schema fingerprint.
- Confirms the portable ABI version in schema, Rust codec, WASM, TypeScript,
  Python, and Go.
- Runs every downstream decoder against the same valid, denied,
  indeterminate, malformed, and over-limit vectors.
- Confirms each implementation rejects trailing bytes, non-minimal integers,
  duplicate keys, unsupported ABI versions, and incorrect result digests.
- Confirms authorized results have equal required/local configuration IDs.
- Confirms configuration-mismatch results preserve both unequal IDs.
- Detects changed schema/codec files without corresponding regenerated
  fixtures and ABI review metadata.

The canonical corpus is referenced through a repository-root path supplied by
automation. Consumers must not maintain copied normative fixtures. Product and
demo fixtures are explicitly non-normative and may cover application scenarios
only.

Protocol-changing pull requests must carry an `abi-change` label and approval
from both core and binding owners. The label never bypasses tests.

## Unified `xtask`

Retain one top-level `xtask` as the authoritative automation surface:

```text
cargo xtask fmt
cargo xtask arch
cargo xtask core-boundary
cargo xtask abi
cargo xtask core
cargo xtask exchange
cargo xtask product
cargo xtask bindings
cargo xtask demos
cargo xtask package
cargo xtask release-check
cargo xtask ci
```

`cargo xtask ci` runs the complete required PR suite. Subcommands exist for
local iteration but cannot redefine weaker checks. The three source-repository
`xtask` implementations are merged into this command surface; duplicate
`xtask` package names and nested automation entry points are removed.

## Pull-Request CI

Every pull request must run:

1. Formatting for Rust, TypeScript, Python, Go, TOML, YAML, and generated
   schema files.
2. `cargo xtask arch` and `cargo xtask core-boundary`.
3. Core MSRV checks, stable all-feature checks, and declared no-default-feature
   builds.
4. Full Rust workspace tests and Clippy with warnings denied.
5. WASM builds and browser/Node smoke tests.
6. TypeScript build, type-check, package tests, and corpus tests.
7. Python wheel build plus tests against the built wheel in a clean
   environment.
8. Go formatting, vet, tests, race tests for concurrent components, and corpus
   checks.
9. ABI/schema synchronization and canonical fixture byte stability.
10. Architecture, result-code, profile, and registry synchronization.
11. Dependency license, advisory, duplicate-version, and source-policy checks.
12. Package/install smoke tests from `.crate`, `.tgz`, and wheel artifacts
    rather than source-tree imports.
13. Fuzz-target inventory and bounded smoke execution.
14. Secret scanning and generated-artifact drift checks.
15. Repository hygiene checks that reject nested lockfiles, nested workspaces,
    tracked build outputs, sibling-repository path references, and duplicate
    canonical fixtures.

Security and architecture jobs always run. Expensive jobs may use
dependency-graph-aware affected-package selection only when the selector itself
is tested and a change to `core`, schemas, fixtures, workspace configuration,
or CI fans out to every downstream package.

Workflow dependencies are pinned to immutable revisions. CI installs tools at
locked versions, records those versions, uses least-privilege permissions, and
does not require credentials for sibling repositories after cutover.

## Nightly and Scheduled CI

Run nightly:

- Extended fuzzing for every core and boundary parser.
- Property tests for wire decoders, arithmetic, replay, budget, and FFI.
- Miri for selected pure and unsafe-adjacent boundaries.
- Sanitizer builds for native parsers and FFI.
- Loom or equivalent concurrency-model tests for replay and budget claims.
- Iroh and in-memory transport semantic-equivalence tests.
- Cross-language differential corpus verification.
- Dependency freshness and vulnerability reports.
- Benchmark comparison against committed latency, memory, proof-size, and WASM
  budgets.
- Failure-injection tests for unavailable stores, corrupt receipts, partial
  writes, executor failure, and concurrent duplicate requests.

## Branch Protection and Review Rules

- Require merge queue and all mandatory checks.
- Prohibit direct pushes to protected branches.
- Require core-owner review for `core/**`, ABI, fixture, registry, cryptography,
  and architecture-policy changes.
- Require product-owner review for execution, replay, budgets, custody, and
  receipt persistence.
- Require binding-owner review when public ABI fixtures change.
- Require security review for new external dependencies, build scripts, unsafe
  code, cryptographic changes, or exception additions.
- Reject generated files whose generator and verification command are absent.
- Use `CODEOWNERS` entries that agree with every owner named in
  `architecture.toml`; `cargo xtask arch` rejects drift between them.

## Release Gates

`cargo xtask release-check` must:

- Require a clean worktree.
- Validate coordinated package versions and internal dependency requirements.
- Build every package from its publishable archive.
- Run the cross-language ABI suite against release artifacts.
- Verify reproducible WASM and generated binding outputs.
- Produce checksummed crate archives, npm packages, wheels, Go module evidence,
  SBOM, provenance, and fixture/schema fingerprints.
- Confirm no package contains absolute paths, local path dependencies, secrets,
  development fixtures, or unrelated layer files.
- Confirm release notes identify intentional ABI changes.

Packages remain independently publishable. A monorepo release does not imply
one product version.

## Migration Sequence

Use ordinary filesystem moves and preserve content, not Git history.

1. Create the top-level layout, architecture policy, and empty consolidated
   workspace.
2. Commit the approved plans before source movement so the migration is
   reviewable against a fixed contract.
3. Move existing core packages under `core/`; repair paths without semantic
   changes.
4. Commit: `chore(monorepo): establish core layer`.
5. Move exchange crates and adapters under `exchange/`; repair paths only.
6. Commit: `chore(monorepo): add exchange layer`.
7. Move apps SDK, profiles, runtime, integrations, receipts, stores, config,
   cache, and operations under `product/`.
8. Commit: `chore(monorepo): add product layer`.
9. Move WASM, TypeScript, Python, Go, and independent-verifier surfaces under
   `bindings/`.
10. Commit: `chore(monorepo): consolidate language bindings`.
11. Move example, matrix, benchmark, MCP, and app test-support packages under
   `demos/`.
12. Commit: `chore(monorepo): consolidate demos and labs`.
13. Consolidate workspace dependencies, toolchains, lints, `xtask`, and CI.
14. Commit: `build(monorepo): enforce architecture and unified CI`.
15. Execute the compliance plan and commit fixes by subsystem.
16. Remove obsolete nested workspace files, duplicate lockfiles, copied
    generated outputs, and cross-repository path assumptions.
17. Commit: `chore(monorepo): remove superseded repository scaffolding`.
18. Run the full clean-room validation matrix, record the commands and tool
    versions, and cut over branch protection before archiving the source
    repositories.

Each movement commit must compile the layers moved so far or explicitly use a
short-lived integration branch that is never merged until the final required
checks pass. Commits must explain the mapping and boundary preserved, not just
state that files moved.

## Completion Criteria

- One workspace and lockfile cover all Rust packages.
- Every package is classified and every dependency edge is machine-checked.
- Core passes its own MSRV, package, offline, and no-default-feature gates.
- Full Rust, TypeScript, Python, Go, WASM, exchange, product, and demo suites
  pass from one commit.
- Canonical core fixtures have one owner and every consumer verifies them.
- No separate repository path dependency remains.
- No source-controlled file remains in the exchange or apps source trees
  except repository-retirement metadata deliberately added after cutover.
- Architecture snapshots are reproducible and match `architecture.toml`.
- `CODEOWNERS`, architecture owners, required checks, and release gates agree.
- Release artifacts install and run outside the source tree.
- `auths-proof-site` and `auths-proof-docs` consume published artifacts or
  pinned release assets, never mutable source paths.
