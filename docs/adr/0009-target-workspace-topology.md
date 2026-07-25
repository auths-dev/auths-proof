# ADR 0009: Build the Target System in the `auths-proof` Repository

**Status:** Proposed

**Date:** 25 July 2026

## Context

The target architecture names nine release units:

- `auths-spec`;
- `auths-proof`;
- `auths-evidence`;
- `auths-exchange`;
- `auths-profiles`;
- `auths-runtime`;
- `auths-authoring`;
- `auths-receipts`;
- `auths-lab`.

The current experiments are spread across `auths-proof`,
`auths-proof-exchange`, and `auths-proof-mcp`. Auths has zero users and none of
these repository boundaries is a supported public contract.

Separate Git repositories do not provide security isolation. Dependency
direction, sealed constructors, features, architecture tests, and review
ownership provide it. During prelaunch development, multiple repositories
make atomic protocol and conformance changes harder without protecting a user
or release cadence.

## Decision

The complete target system is built in one canonical Git repository:
`auths-proof`.

The target release units are package groups and security boundaries inside the
repository. They are not separate repositories.

The intended top-level layout is:

```text
auths-proof/
├── spec/                    language-neutral V1 specification and registries
├── crates/                  pure model, codec, ports, and authority kernel
├── adapters/                portable principal/signature/status adapters
├── resolvers/               native evidence acquisition leaves
├── exchange/                exchange messages, ports, and transports
├── profiles/                MCP, HTTP, Git, deploy, supply-chain, edge
├── runtime/                 replay, budgets, config, cache, execution gates
├── authoring/               planners, approval displays, signer integrations
├── receipts/                receipt formats, stores, and audit export
├── lab/                     corpus, fuzzing, matrices, benchmarks
├── implementations/
│   ├── go/                  independent Go verifier
│   └── typescript/          independent browser/Node verifier
├── apps/                    CLI and reference applications
└── xtask/                   architecture, conformance, and release checks
```

Rust packages share one Cargo workspace where practical. Go and TypeScript
implementations remain ordinary language-native modules in the same
repository.

## Release-unit ownership

| Release unit | Repository location | Responsibility |
|---|---|---|
| `auths-spec` | `spec/`, registry data, language-neutral fixtures | Normative meaning; no product-code dependency |
| `auths-proof` | `crates/` | Model, codec, registries, pure ports, authority, composition, action binding, verifier, WASM |
| `auths-evidence` | `adapters/`, `resolvers/` | Bounded fact verification and external evidence assembly |
| `auths-exchange` | `exchange/` | Messages, framing, transports, and peer observations |
| `auths-profiles` | `profiles/` | Canonical action meaning, approval display, permission mapping, verified decoding |
| `auths-runtime` | `runtime/` | Orchestration, replay, budgets, configuration, caches, and execution gates |
| `auths-authoring` | `authoring/` | Safe planning, signing requests, custody integrations |
| `auths-receipts` | `receipts/` | Decision/execution receipt formats, stores, and audit bundles |
| `auths-lab` | `lab/`, `implementations/` | Cross-language conformance, fuzzing, benchmarks, and evaluation |

Release units may become independently published packages. Publication does
not require a separate Git repository.

## Dependency shape

```text
                         +------------------+
                         |    auths-spec    |
                         | schemas/vectors  |
                         +---------+--------+
                                   |
                                   v
+------------------+      +------------------+      +------------------+
| auths-evidence   | ---> |   auths-proof    | <--- | auths-profiles   |
| facts/resolvers  |      | pure authority   |      | action meaning   |
+------------------+      +---------+--------+      +---------+--------+
                                   ^                         |
                                   |                         |
                         +---------+--------+                |
                         | auths-exchange   |                |
                         | bytes + peers    |                |
                         +---------+--------+                |
                                   \                        /
                                    \                      /
                                     v                    v
                                  +--------------------------+
                                  |      auths-runtime       |
                                  | replay/gates/receipts    |
                                  +------------+-------------+
                                               |
                                               v
                                  +--------------------------+
                                  |        application       |
                                  +--------------------------+

auths-lab may depend on public packages. Production packages never depend on
auths-lab.
```

The arrows show public composition, not permission to import private
constructors.

## Core crate boundaries

The target logical layers are:

```text
model <- codec <- registries/signature/principal/status/assurance
  ^                         |
  |                         v
  +------ authority <- composition
              |
              v
            action
              |
              v
           verifier ----> wasm
```

A logical layer becomes a separate crate when the crate enforces:

- a smaller `no_std + alloc` graph;
- a private constructor boundary;
- an adapter/port dependency direction;
- a feature graph that excludes effects;
- a useful independent audit or publication surface.

Crate splitting is not performed merely to match a diagram.

## Use of the current companion prototypes

The current `auths-proof-exchange` and `auths-proof-mcp` directories are source
material:

- useful exchange model, codec, port, memory, and Iroh code may be moved under
  `exchange/`;
- useful MCP canonicalization moves under `profiles/`;
- useful replay and authorization-gate code moves under `runtime/`;
- useful demos and benchmarks move under `apps/` and `lab/`;
- prototype package names, paths, and public APIs may be discarded.

The target does not keep sibling path dependencies or publish compatibility
releases for these prototypes.

## Dependency enforcement

`xtask` checks an allow-list derived from workspace metadata.

Required invariants:

- the pure proof graph has no network, filesystem, process, environment,
  ambient clock, randomness, async runtime, database, private-key, or
  execution dependencies;
- evidence adapters cannot import verdict constructors;
- native resolvers cannot be called by the verifier;
- transports cannot interpret grants or construct authority results;
- profiles cannot select trust anchors or construct verified authority;
- runtime can compose public proof, exchange, profile, and receipt APIs but
  cannot construct their sealed outputs;
- receipt storage cannot execute application commands;
- production packages do not depend on lab code;
- native and WASM features cannot substitute different authority semantics;
- dependency cycles fail CI.

## Consequences

### Positive

- Protocol, implementation, fixtures, and independent verifiers change
  atomically before launch.
- There are no cross-repository version or path-dependency coordination
  problems.
- The full target remains visibly anchored in `auths-proof`.
- Security boundaries remain machine-enforced at the package graph.
- Prototype package and repository structure can be discarded cleanly.

### Negative

- The repository contains multiple languages and runtime classes.
- CI must select targeted jobs rather than building every component for every
  change.
- Package ownership and review rules must be documented because Git ownership
  alone does not separate them.

## Rejected alternatives

### Preserve the three current repositories

Rejected because no user or published compatibility contract benefits from
their separation, while the target requires atomic changes across proof,
exchange, profile, runtime, receipt, and conformance contracts.

### Create one repository per release unit

Rejected because nine repositories would add coordination and release
overhead without increasing semantic isolation.

### Put everything in one crate

Rejected because effects and private constructors must be separated by the
compiler and dependency graph even inside one Git repository.

### Defer the target topology

Rejected because direct prelaunch restructuring is cheaper than letting
prototype paths become de facto public contracts.

## Future repository extraction

Repository extraction is outside the prelaunch target. After launch, a package
may be extracted if real ownership, release cadence, build isolation, or
distribution needs justify it. Such an extraction must preserve the public
conformance contract and dependency direction.

## Required follow-up

- Reshape `auths-proof` to the target top-level layout before broad feature
  expansion.
- Move only useful prototype code; do not preserve package names for their own
  sake.
- Add dependency allow-lists before introducing runtime and transport
  dependencies.
- Remove sibling path dependencies from the target workspace.

