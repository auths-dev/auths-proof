# Auths Developer Integration Plan

> Historical planning document. The supported integration is the
> `auths-proof` façade and compiling `examples/offline-verification` consumer.

**Status:** Implementation in progress

**Date:** 25 July 2026

**Protocol target:** Auths Proof Protocol V1

**Reference verticals:** internal deployment and MCP

## Purpose

This document defines the tooling and product architecture required to make
Auths straightforward for senior engineers to introduce into existing
systems.

It is not an identity-system plan. Auths remains principal-agnostic. No
principal method, credential technology, directory, identity provider, or
key-management implementation receives special authority semantics.

The target-state protocol and implementation remain governed by:

- [`DELTA.md`](DELTA.md);
- [`DELIVERY.md`](DELIVERY.md);
- [`ADR 0008`](../adr/0008-reset-prelaunch-v1.md);
- [`ADR 0009`](../adr/0009-target-workspace-topology.md).

## Product objective

The goal is:

> A senior engineer can add exact, delegated authorization to one existing
> service in under an hour, without replacing the service's identity system,
> deploying a new authorization control-plane service, or learning Auths
> implementation internals.

This objective produces controllable technical requirements:

- one package installation in the engineer's native ecosystem;
- one primary verification operation;
- no network access during verification;
- no client registration, redirect, or token-exchange ceremony for the basic
  path;
- existing principal-control mechanisms remain usable at system edges;
- safe construction APIs and explicit trust configuration;
- actionable denial and indeterminate explanations;
- identical protocol semantics in every supported language;
- production-grade metrics, receipts, and integration tests;
- no Rust, C, or other native compiler required on a consumer's machine for
  supported prebuilt packages.

## Hard boundaries

### Principal agnosticism

Auths defines authority over validated principal identifiers and bounded
evidence. It does not define which identity implementation an organization
must use.

Principal adapters may establish:

- control of a principal;
- accepted verification material;
- lifecycle or status facts;
- assurance claims with provenance.

They may not:

- create authority;
- select trust anchors;
- broaden a grant;
- construct `VerifiedAction`;
- change application-profile meaning.

Reference examples use the generic terms `human principal`,
`workload principal`, `service principal`, and `agent principal`. A concrete
adapter is an interchangeable integration choice, not part of the authority
model.

### Incremental introduction

One service may adopt Auths without requiring every caller, service,
identity system, or transport in the organization to change simultaneously.

Existing authentication and principal-control systems may remain outside
Auths and produce explicit evidence or signing results. Auths carries and
verifies authority after that boundary.

### Embedded verification

The enforcement path is an in-process verifier. It has:

- no network calls;
- no daemon dependency;
- no ambient identity lookup;
- no hidden policy fetch;
- no private-key custody;
- deterministic output for identical input bytes and context.

### Language-neutral semantics

The normative product is the protocol contract and corpus, not the Rust API.
Rust is the reference implementation.

Every implementation or binding must preserve:

- canonical bytes and identifiers;
- verification stages;
- `Authorized`, `Denied`, and `Indeterminate`;
- stable reason and requirement codes;
- sealed verified outputs;
- work and resource limits;
- fail-closed registry selection.

## Developer experience

The intended integration flow is:

```text
+----------------------------------------------------------+
| Add Auths to an existing service                         |
|----------------------------------------------------------|
| 1. Install the package for the service's language        |
| 2. Select or implement an application profile            |
| 3. Load explicitly trusted roots and policy              |
| 4. Call verify(proof, action, context)                   |
| 5. Decode a command only from the VerifiedAction         |
| 6. Execute that verified command                         |
| 7. Run the shared corpus in the service's CI             |
+----------------------------------------------------------+
```

The primary API should feel native in every language:

```go
result := auths.Verify(proof, action, context)

switch result.Kind {
case auths.Authorized:
    command := profile.DecodeVerified(result.Action)
    return executor.Execute(command)
case auths.Denied:
    return forbidden(result.Explanation)
case auths.Indeterminate:
    return unavailable(result.Requirement)
}
```

An engineer should not need to understand the Rust crate graph, CBOR
implementation, adapter dispatch, signature-suite dispatch, or sealed-stage
internals.

## Architecture

```text
                  LANGUAGE-NEUTRAL CONTRACT
        specification + CDDL + registries + corpus
              + stable errors + engine ABI
                             |
               +-------------+-------------+
               |                           |
               v                           v
       Rust reference kernel       Independent verifier
       authoritative behavior      validates the design
               |                           |
        +------+------+                    |
        |             |                    |
        v             v                    v
  TypeScript/WASM  Python/native        Pure Go
  npm package      Python wheels        Go module
        |             |                    |
        +-------------+--------------------+
                      |
           Idiomatic integration packages
                      |
        +-------------+----------------------+
        |             |                      |
        v             v                      v
    MCP middleware  deployment library   HTTP/gRPC integration
```

The architecture has five layers:

1. language-neutral protocol contract;
2. pure reference verifier;
3. portable engine boundary;
4. idiomatic language packages;
5. application-specific integration packages.

Only the fifth layer knows application behavior. Only explicit
principal-control adapters know identity implementation details.

## Language-neutral contract

The most important artifacts are:

- exact wire specification;
- CDDL schemas;
- registries and domain separation;
- canonical positive, denied, indeterminate, and malformed CBOR corpus;
- canonical context and action digests;
- stable verdict, reason, and requirement semantics;
- resource and work limits;
- conformance runner contract;
- portable engine ABI.

Every release identifies the exact revision and digest of each artifact.

## Portable engine boundary

The low-level portable surface remains deliberately small:

```text
verify-v1(
    proof_cbor,
    canonical_action_cbor,
    trusted_context_cbor
) -> verification_result_cbor
```

This interface:

- accepts only bounded byte sequences;
- performs no I/O or callbacks;
- owns no ambient configuration;
- returns canonical result bytes;
- never exposes Rust object layout;
- is fuzzed as an independent boundary;
- is exercised by every language's conformance tests.

Idiomatic language APIs wrap this boundary with native request, context,
result, explanation, and verified-action types.

The byte-oriented ABI is a portability mechanism, not the preferred
application API.

## Language distribution strategy

Different ecosystems use the delivery mechanism that best fits their build
and deployment expectations.

| Ecosystem | Primary delivery |
|---|---|
| Rust | Native reference crates and a small public facade |
| TypeScript | Rust verifier compiled to WASM with an idiomatic TypeScript wrapper |
| Python | Rust verifier exposed through a native extension and distributed as prebuilt wheels |
| Go | Independent pure-Go verifier and idiomatic Go module |
| Other languages | WASM Component or minimal C ABI where appropriate |

### Rust

Rust contains the normative reference behavior and sealed types. The public
facade exposes supported use cases without requiring consumers to compose
internal crates.

### TypeScript

The primary package includes precompiled WASM and generated TypeScript
declarations for browser and Node runtimes. Consumers do not install Rust.

An independent TypeScript verifier may remain a differential-conformance
artifact, but the WASM-backed package is the primary integration surface.

### Python

The primary package contains an idiomatic typed wrapper over a native Rust
extension. Release automation publishes supported wheels so ordinary
installation does not compile Rust or C code.

### Go

The production package is implemented in pure Go. It is both an idiomatic
integration and the first independent check that the language-neutral
specification is sufficient.

A C or WASM bridge may assist development and differential testing, but is not
the production Go dependency.

### Other languages

The WebAssembly Component Model and a minimal C ABI are secondary portability
surfaces. They do not replace native packages for the initial target
ecosystems.

## Product kits

A verifier alone is not a complete integration. Auths ships four coherent
kits.

## 1. Enforcement kit

The enforcement kit is for service owners.

It provides:

- proof verification;
- trusted-context construction;
- immutable registry construction;
- sealed `VerifiedAction`;
- verified profile-command decoding;
- stable explanations and error codes;
- work-unit and size metrics;
- decision-receipt inputs;
- corpus tests runnable in the host service's CI.

The verifier does not execute commands. The profile decoder derives a command
from the canonical bytes held by `VerifiedAction`, and the application
executes that command.

## 2. Authority issuance kit

The authority issuance kit is for callers and platform teams.

It provides:

- safe grant planning;
- authority-diff and widening detection;
- external signing requests;
- exact-action approval requests;
- delegation attenuation;
- proof assembly;
- proof and evidence minimization;
- optional integrations with existing principal-control and signing systems.

Private-key custody and identity implementation details remain outside the
protocol kernel.

## 3. Profile development kit

The profile development kit is for application teams.

It provides:

- typed action schemas;
- canonicalization contracts;
- capability and resource derivation;
- approval-display contracts;
- verified-command decoders;
- mutation and ambiguity tests;
- generated fixture scaffolding;
- fuzz-target scaffolding;
- cross-language conformance hooks.

A profile cannot select trust anchors or construct authority verdicts.

## 4. Integration kit

The integration kit supplies narrow application entry points:

- MCP server middleware;
- internal-deployment libraries;
- HTTP middleware;
- gRPC interceptors;
- CI integration.

All integrations run verification in process. Middleware must not verify one
request and allow the application to execute a different request.

## Reference vertical 1: internal deployment

The deployment vertical proves that an organization can introduce Auths at
one enforcement boundary without replacing its existing identity
infrastructure.

```text
Existing human principal control
              |
              v
Approve exact artifact + environment
              |
              v
Existing workload principal control
              |
              v
Short-lived deployment-agent grant
              |
              v
Deployment service verifies locally
              |
              v
Replay-safe execution + receipt
```

The action binds:

- artifact digest;
- source revision;
- configuration digest;
- target environment;
- deployment strategy;
- audience;
- expiry;
- actor;
- authorization-plan identifier.

The service executes only the deployment command decoded from
`VerifiedAction`.

## Reference vertical 2: MCP

The MCP vertical proves exact delegated authorization for agent tool use.

```text
Existing approving principal
              |
              v
Approve exact tool or bounded tool authority
              |
              v
Short-lived grant to agent principal
              |
              v
Agent submits canonical tool action + proof
              |
              v
MCP server verifies locally
              |
              v
Replay-safe tool execution + receipt
```

The action binds:

- MCP profile and version;
- service audience;
- tool capability;
- canonical tool arguments;
- challenge;
- expiry;
- actor;
- terminal grant;
- authorization-plan identifier.

The MCP server never executes the caller's original unverified arguments. It
executes the command decoded from `VerifiedAction`.

## Repository ownership

The three-repository topology remains unchanged.

### `auths-proof`

Owns:

- protocol specification and CDDL;
- canonical model and codec;
- pure verifier and evidence ports;
- canonical corpus and conformance contract;
- portable engine ABI;
- reference Rust API;
- WASM verifier core;
- fuzzing and architecture checks.

### `auths-proof-exchange`

Owns:

- challenge and submission exchange;
- framing;
- transport implementations;
- typed channel observations;
- transport-invariance tests.

### `auths-proof-apps`

Owns:

- idiomatic downstream packages and wrappers;
- Python and Go distribution projects;
- TypeScript wrapper and independent conformance implementation;
- application profiles;
- MCP and deployment integrations;
- runtime, replay, receipts, and configuration;
- profile development and integration kits;
- Auths Lab and cross-language differential testing.

Repository placement does not alter protocol ownership: every implementation
consumes the same `auths-proof` specification and canonical corpus.

## Build sequence

### Phase 1: contract

- Complete V1 language-neutral semantics.
- Freeze canonical engine inputs and outputs.
- Expand the corpus to cover all terminal verdicts and stable reasons.
- Make the corpus independently consumable.

### Phase 2: reference engine

- Complete the pure Rust verifier.
- Expose the minimal supported Rust facade.
- Implement the byte-oriented engine boundary.
- Prove native/WASM semantic parity.

### Phase 3: enforcement vertical

- Complete trusted-context construction.
- Complete verified-command decoding.
- Build the internal-deployment enforcement path.
- Build the MCP enforcement path.
- Add explanations, metrics, replay gates, and decision receipts.

### Phase 4: language packages

- Publish the TypeScript/WASM package.
- Publish prebuilt Python wheels.
- Complete the pure-Go verifier.
- Run the canonical corpus in each package's native test runner.

### Phase 5: authoring and profile tooling

- Complete authority issuance and safe planning.
- Complete the profile development kit.
- Add identity-agnostic signing and principal-control integration ports.
- Add proof minimization and authority-diff tooling.

### Phase 6: integration and operations

- Complete MCP and deployment middleware.
- Add HTTP, gRPC, and CI integrations.
- Add operational metrics and audit export.
- Run cross-language and hostile-input release gates.

## Acceptance gates

### Integration gate

For each supported ecosystem:

- installation uses its standard package manager;
- supported platforms require no local Rust or C compiler;
- one documented verification call covers the basic path;
- native types expose all stable outcomes;
- example services execute only verified commands;
- the host service can run the canonical corpus in its own CI.

### Semantic gate

- Rust, WASM, Python, Go, and TypeScript surfaces agree on canonical result
  bytes;
- the independent Go verifier agrees with the Rust reference;
- unknown critical identifiers fail closed;
- identical proof, action, and context inputs produce identical results;
- no binding introduces network or ambient state into verification.

### Security gate

- every parser and FFI/WASM boundary is fuzzed;
- malformed inputs cannot panic or cause unbounded allocation;
- verified outputs cannot be constructed by application code;
- adapters cannot construct authority;
- profile decoders cannot read unverified request bytes;
- stable denial and indeterminate explanations do not expose secrets.

### Product gate

A senior engineer unfamiliar with Auths can:

1. add Auths to a sample service in under one hour;
2. configure an explicit local trust context;
3. authorize and execute one internal-deployment action;
4. authorize and execute one MCP tool call;
5. diagnose a denied and an indeterminate result;
6. run the shared conformance corpus in the service's native CI.

## Completion condition

This plan is complete when both reference verticals pass through the same
language-neutral contract and corpus from:

- Rust;
- TypeScript/WASM;
- Python;
- independent Go;

and each integration can be installed, configured, verified, explained, and
tested without requiring knowledge of internal Rust crates or any particular
identity implementation.

## Implementation record

The first developer-ergonomics slice now provides:

- a supported `auths-proof` Rust facade and prebuildable three-input WASM
  boundary in `auths-proof`;
- a supported `auths-proof-exchange` facade with one client and one server
  sequence in `auths-proof-exchange`;
- a single Rust SDK for trusted contexts, verification, safe authority
  planning, and external custody;
- a transport-neutral enforcement kit whose executors accept only commands
  decoded from sealed verified actions;
- a replay- and budget-gated internal deployment integration, alongside the
  existing receipt-producing MCP runtime;
- a profile fixture/mutation kit;
- publishable TypeScript/WASM and stable-ABI Python package projects;
- a pure-Go package with the one-call API and all 99 shared semantic cases in
  native `go test`;
- release automation for TypeScript/WASM, Python wheels, and Go conformance;
- one integration guide spanning all supported language surfaces.

Release publication, hosted package installation checks, and the final
cross-language hostile-input release gate remain release-engineering work.
