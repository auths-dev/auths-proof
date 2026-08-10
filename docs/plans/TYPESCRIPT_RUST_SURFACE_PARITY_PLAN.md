# TypeScript and Rust surface parity plan

**Status:** Repository-local complete; external gates pending
**Baseline:** `main` at `c47af745`
**Branch:** `codex/typescript-rust-surface-parity`

## UX

The TypeScript package should expose Rust-owned security capabilities through small, typed entry points. A normal application should never construct protocol bytes, select a verifier implementation, or promote inspection data into an executable command.

```text
identity       trust          authority       profile        runtime
   |             |               |               |              |
   v             v               v               v              v
parse         parse/build      attach          parse action   claim state
validate      trusted input    delegate        authorize      emit receipt
authenticate                   compose plan    sealed command execute once
```

Each transition returns a new type. Parsing failures are typed errors. Boolean validation APIs and caller-authored protocol encodings are not part of the public surface.

## Architecture

```text
+----------------------- TypeScript package ------------------------+
| public types | parsers | async provider coordination | lifetimes |
+------------------------------|------------------------------------+
                               v
+------------------------- versioned WASM ABI ----------------------+
| opaque handles | bounded inputs | typed semantic projections      |
+------------------------------|------------------------------------+
                               v
+-------------------------- Rust owners ----------------------------+
| identity | author | codec | profiles | verifier | receipts/runtime|
+-------------------------------------------------------------------+
```

Rules:

- Rust owns parsing, canonicalization, identifiers, commitments, attenuation, profile meaning, and verification.
- TypeScript owns idiomatic types, provider calls, immutable projections, resource lifetime, and package boundaries.
- The normal API accepts typed values, not protocol CBOR.
- Effect-capable commands remain package-owned and non-serializable.
- Ports and conformance suites are preferred over an exhaustive adapter catalog.
- Public unions are exhaustive and compile-time misuse tests prove invalid transitions are rejected.
- Every fallible boundary parses into a narrower nominal or discriminated type; invalid transitions are unrepresentable rather than reported by validation booleans.

## APIs

The intended package layout is:

```text
@auths-dev/sdk                 integrated workflow
@auths-dev/sdk/identity        identity states and adapter ports
@auths-dev/sdk/trust           typed trusted-context inputs
@auths-dev/sdk/authority       verification and authorization plans
@auths-dev/sdk/lifecycle       principal and grant status authoring
@auths-dev/sdk/profiles        maintained profile facades
@auths-dev/sdk/runtime         replay, budget, receipt, and execution ports
@auths-dev/sdk/custody         signer port and adapter conformance
@auths-dev/sdk/advanced        raw verification and inspection
```

## Task list

### 1. Reconcile capability metadata and claims

- [x] Replace the single ambiguous capability tier with separate implementation, evidence, promotion, and publication states.
- [x] Derive documentation checks from the same capability record.
- [x] Preserve the independent-review and publication blockers.
- [x] Add a CI-facing consistency test that rejects contradictory README and metadata claims.

### 2. Expose typed trust-context and adapter composition

- [x] Add a `trust` entry point with parsed identifiers, roots, accepted registries, status snapshots, assurance requirements, profiles, and limits.
- [x] Compile typed inputs through Rust/WASM rather than serializing protocol objects in TypeScript.
- [x] Return an opaque trusted-context source accepted by `loadAuths`.
- [x] Add negative tests for malformed identifiers, empty roots, duplicate entries, unsupported registries, invalid limits, and mutable input aliasing.
- [x] Add compile-time tests that raw bytes cannot be supplied as typed trust configuration.

### 3. Generalize identity adapter surfaces

- [x] Define typed identity-method and signature-suite adapter ports.
- [x] Keep decoded, validated, and authenticated states distinct.
- [x] Adapt the existing raw-key and Ed25519 implementations to the ports.
- [x] Add a caller-owned test adapter proving method and suite substitution without authority dependencies.
- [x] Add conformance tests for method/suite mismatch, mutation, oversize input, and forged state transitions.

### 4. Expose maintained Rust profile families

- [x] Add separate HTTP, Git, deployment, supply-chain, and edge profile facades.
- [x] Parse and canonicalize every action through its Rust profile owner.
- [x] Give every profile distinct action, command, and gateway types.
- [x] Add authority projections, review displays, single-action authorization, and ordered plans.
- [x] Add cross-profile forgery and command-substitution tests.

### 5. Expose lifecycle and status authoring

- [x] Add typed principal-status and grant-status requests.
- [x] Prepare exact signing requests through Rust/WASM.
- [x] Complete signed status objects only after bound signer responses.
- [x] Add parsed status snapshots for trusted-context composition.
- [x] Test stale, reordered, duplicate, mismatched signer, overflow, and post-disposal paths.

### 6. Expose general authorization-plan authoring

- [x] Add opaque proof references and plan nodes.
- [x] Support proof, all-of, any-of, and threshold composition through Rust.
- [x] Parse plan shape and expose bounded leaf/depth summaries.
- [x] Prevent empty, duplicate, impossible-threshold, over-depth, and over-work plans.
- [x] Prove application code cannot construct or mutate an accepted plan handle.

### 7. Add optional runtime ports without moving effects into the SDK core

- [x] Add typed challenge, replay, budget, receipt, and closed-executor ports under `runtime`.
- [x] Require an authorized profile command before any state claim or execution.
- [x] Model claimed, duplicate, exhausted, unavailable, executed, failed, and outcome-unknown states exhaustively.
- [x] Add an in-memory conformance harness under `testkit`, not the production root.
- [x] Test zero state change and zero gateway calls for denied, indeterminate, forged, or mismatched commands.

### 8. Close custody adapter conformance without bundling providers

- [x] Publish the signer and custody contracts from a dedicated `custody` entry point.
- [x] Add a provider conformance harness covering transaction, principal, descriptor, request, expiry, duplicate, cancellation, and disposal binding.
- [x] Keep development custody under `testkit` and production providers out of the base package.
- [x] Document the adapter contract without claiming support for unimplemented vendors.

### 9. Close repository-local evidence and preserve external gates

- [x] Update installed public API snapshots and package export tests.
- [x] Run TypeScript compile-time, unit, integration, example, and packed-package suites.
- [x] Run focused Rust/WASM tests plus architecture, semantic-freeze, and compliance checks.
- [x] Update the external-consumer scorecard with exact local evidence.
- [x] Keep independent review, publication, and production-readiness states blocked until their external gates pass.

## Completion rule

Repository-local work is complete when all nine task groups have implementation and test evidence on one exact revision. External review and publication are not converted into checkboxes that repository code can satisfy; the branch is complete when it accurately reports those gates as pending and contains no contradictory capability claim.
