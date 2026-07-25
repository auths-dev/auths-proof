# ADR 0009: Use Three Repositories with Enforced Crate Boundaries

**Status:** Accepted

**Date:** 25 July 2026

## Context

Auths is prelaunch with zero users. Existing repository names and package APIs
do not need compatibility support.

The target architecture names proof, evidence, exchange, profiles, runtime,
authoring, receipts, and lab as separate release units. Those are semantic,
dependency, and review boundaries; they do not each require a Git repository.

Two extremes are undesirable:

- putting transports and applications in `auths-proof` would expand the
  offline kernel's trusted computing base;
- creating a repository for every target release unit would make atomic
  protocol, corpus, and conformance changes unnecessarily difficult.

## Decision

Use three repositories:

| Repository | Responsibility |
|---|---|
| `auths-proof` | Pure V1 protocol, schemas, registries, deterministic codec, authority kernel, signature and evidence ports, portable adapters, status and assurance, WASM, keyless authoring, canonical CBOR corpus, fuzzing |
| `auths-proof-exchange` | Exchange protocol, framing, memory/Iroh/HTTPS/TCP/Unix/file transports, typed peer observations, transport conformance |
| `auths-proof-apps` | Live evidence acquisition and custody integrations, application profiles, runtime, replay and budgets, receipts, configuration, caches, reference applications, Auths Lab, and independent Go/TypeScript verifiers |

The current prelaunch `auths-proof-mcp` repository becomes
`auths-proof-apps`. MCP remains its first profile and reference application.
There is no compatibility or migration requirement.

All three implementation branches are named `dev-implementation-delta`.

## Architecture

```text
                     +--------------------------+
                     | auths-proof              |
                     | pure authority kernel    |
                     | canonical CBOR corpus    |
                     +------------+-------------+
                                  ^
                                  |
                +-----------------+-----------------+
                |                                   |
     +----------+-----------+            +----------+-----------+
     | auths-proof-exchange |            | auths-proof-apps     |
     | bytes + peer facts   |            | profiles + runtime   |
     +----------+-----------+            | receipts + lab       |
                |                        +----------+-----------+
                |                                   ^
                +-----------------------------------+
                         public package contracts
```

Dependency direction:

```text
auths-proof-exchange  ---> auths-proof public wire/model packages only
auths-proof-apps      ---> auths-proof + auths-proof-exchange
auths-proof           -X-> every downstream repository
```

`auths-proof-exchange` may remain proof-format-neutral where its semantic
exchange port only carries bounded bytes. Any dependency on proof types must
be narrow, explicit, and architecture-tested.

## Release-unit mapping

| Target release unit | Home |
|---|---|
| `auths-spec` | `auths-proof/spec` and `auths-proof/fixtures` |
| `auths-proof` | `auths-proof` core crates |
| portable `auths-evidence` | `auths-proof/adapters` and pure ports |
| native evidence acquisition | resolver, assembler, and signer-integration crates in `auths-proof-apps` |
| `auths-exchange` | `auths-proof-exchange` |
| `auths-profiles` | profile crates in `auths-proof-apps` |
| `auths-runtime` | runtime crates in `auths-proof-apps` |
| `auths-authoring` | pure builders in `auths-proof`; custody/UI integrations in `auths-proof-apps` |
| `auths-receipts` | receipt format and store crates in `auths-proof-apps` |
| `auths-lab` | non-production packages and language implementations in `auths-proof-apps` |

Package boundaries inside a repository remain independently versioned and
machine-enforced where useful.

## `auths-proof` boundary

The proof repository owns only deterministic authority semantics and bounded
fact verification.

```text
model <- codec -----+----> authoring
  |                 |
  +-> ports <-------+----> verifier
       ^                        ^
       |                        |
portable adapters          portable result composition
```

The verifier graph contains no:

- network, transport, or async runtime;
- filesystem, process, environment, or ambient clock;
- randomness or private-key custody;
- replay, budget, receipt, or application storage;
- profile canonicalizer or executor;
- application or presentation dependency.

Network-capable resolvers, evidence assemblers, and custody clients belong in
`auths-proof-apps`. They provide explicit inputs to public proof APIs and are
never callable by the kernel.

## `auths-proof-exchange` boundary

Exchange owns:

- bounded challenge, submission, response, and session messages;
- framing and protocol version negotiation;
- peer and channel observations;
- memory, Iroh, HTTPS, TCP, Unix, and file transports;
- shared transport-invariance tests.

Exchange does not:

- interpret grants;
- select trust anchors;
- verify or construct authority;
- canonicalize application actions;
- execute commands;
- own replay or budget state.

An authenticated peer remains a fact, never authority.

## `auths-proof-apps` boundary

The downstream application repository contains separate crate groups:

```text
integrations/
  evidence-acquisition  resolvers  custody

profiles/
  mcp  http  git  deploy  supply-chain  edge

runtime/
  orchestration  replay  budgets  config  cache  execution-gates

receipts/
  model  codec  stores  audit-export

apps/
  cli/demo/reference services

lab/
  corpus-runner  fuzz promotion  matrices  benchmarks

implementations/
  go  typescript
```

Internal architecture rules prevent:

- resolvers and assemblers from constructing verified authority;
- profiles from selecting trust anchors or constructing verdicts;
- runtime from constructing sealed proof/profile outputs;
- receipt stores from executing commands;
- production crates from depending on lab code;
- reference applications from bypassing verified command decoding.

## Canonical corpus contract

`auths-proof` is the source of truth for V1 `.cbor` fixtures and their
manifest.

Downstream repositories consume a pinned corpus release and add
surface-specific fixtures without rewriting core proof bytes.

The corpus manifest records:

- fixture hash and class;
- expected stage, verdict, and reason;
- action, plan, context, and receipt digests;
- assurance report;
- byte, count, depth, signature, and work-unit metrics.

No downstream `xtask` may update the core corpus.

## `xtask` responsibilities

### `auths-proof`

- spec/CDDL consistency;
- canonical wire stability;
- architecture allow-lists;
- unit, property, and conformance tests;
- native/WASM parity;
- fuzz smoke and promoted regressions;
- release checks for the protocol kernel.

### `auths-proof-exchange`

- exchange wire stability;
- framing fuzzing;
- transport-invariance corpus;
- peer-observation and channel-policy facts;
- release checks for every transport adapter.

### `auths-proof-apps`

- profile canonicalizer differential tests;
- runtime replay/budget state-machine tests;
- receipt stability;
- end-to-end verified execution;
- Rust/Go/TypeScript differential conformance;
- factorial Auths Lab and reproducible benchmarks.

An ecosystem release runs all three release checks against exact revisions.

## Consequences

### Positive

- The proof kernel remains small, offline, and independently auditable.
- Only three repositories require coordinated prelaunch changes.
- Profiles, runtime, receipts, and lab share fixtures and can change
  atomically.
- Security boundaries are enforced by crate graphs rather than repository
  count.
- Existing exchange and MCP work remain directly reusable.

### Negative

- `auths-proof-apps` contains several kinds of downstream package.
- Its architecture tests and ownership rules must prevent accidental
  dependency collapse.
- Ecosystem releases still coordinate three exact revisions.

## Rejected alternatives

### Put everything in `auths-proof`

Rejected because transports and application behavior would expand the
kernel's trusted computing base.

### Create separate profile, runtime, receipt, and lab repositories

Rejected because Git separation would add coordination without enforcing
semantic isolation better than crate graphs.

### Keep `auths-proof-mcp` permanently MCP-only

Rejected because it would require another repository for the shared profile,
runtime, receipt, and lab contracts. There are no users requiring its current
name or scope.

## Required follow-up

- Keep `auths-proof` and `auths-proof-exchange` on
  `dev-implementation-delta`.
- Rename/rescope `auths-proof-mcp` to `auths-proof-apps` on the same branch.
- Update every repository's `AGENTS.md` and `xtask` allow-list to match its
  boundary.
- Publish and pin the canonical proof corpus between repositories.
