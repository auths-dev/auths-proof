# Auths Target-State Build Map

**Status:** Proposed implementation map

**Date:** 25 July 2026

**Repository:** `auths-proof`

**Target:** *Auths: A Complete Architecture for Portable,
Principal-Agnostic Authorization*, Target Architecture 1.0

## Product context

Auths is prelaunch with zero users.

There are no externally deployed Auths proofs, grants, receipts, trust-anchor
configurations, SDK contracts, or supported protocol integrations. The
current V1 implementation is useful prototype code, not a compatibility
boundary.

The target architecture therefore replaces the current V1 contract directly:

- the target remains **Auths Proof Protocol V1**;
- `spec/v1`, `fixtures/v1`, V1 Rust types, and V1 APIs may change
  incompatibly;
- obsolete prototype code and fixtures may be removed;
- no parallel protocol or prototype-support layer is required;
- Git history is sufficient to retain the old experiment.

The delivery order is defined in [`DELIVERY.md`](DELIVERY.md). The protocol
reset and repository structure are defined in
[ADR 0008](../adr/0008-reset-prelaunch-v1.md) and
[ADR 0009](../adr/0009-target-workspace-topology.md).

## Purpose

This document maps useful current implementation material to the target. The
current code does not constrain the target contract.

Every target capability is classified as:

- **Reuse** — preserve the current design or implementation where it fits;
- **Rewrite** — retain lessons or tests, but replace the contract or code;
- **Build** — implement a capability not present today.

## Reusable prototype inventory

The current `auths-proof` workspace demonstrates:

- validated protocol types;
- deterministic, bounded CBOR;
- exact permission and delegation attenuation;
- local trust anchors and three-way decisions;
- raw-key Ed25519 and P-256 verification;
- pure `did:key`, `did:keri`, and bundled `did:web` adapters;
- a separate native `did:web` resolver;
- keyless authoring;
- an offline CLI, WASM checks, fixtures, and architecture checks.

The local `auths-proof-exchange` and `auths-proof-mcp` prototypes demonstrate:

- semantic challenge and submission messages;
- in-memory and Iroh transports;
- typed peer observations;
- one canonical MCP `tools/call` profile;
- one-use challenge claiming;
- channel policy and authorization-before-execution.

These are implementation inputs. Their package names, wire bytes, public APIs,
workspace boundaries, and fixture stability do not constrain the target.

## Target architecture

```text
                           AUTHS-PROOF REPOSITORY

  +----------------+       +--------------------+       +----------------+
  | evidence       | ----> | pure authority     | <---- | profiles       |
  | bounded facts  |       | kernel             |       | action meaning |
  +----------------+       +----------+---------+       +--------+-------+
                                      ^                          |
                                      |                          |
                           +----------+---------+                |
                           | exchange           |                |
                           | bytes + peers      |                |
                           +----------+---------+                |
                                      \                         /
                                       \                       /
                                        v                     v
                                     +---------------------------+
                                     | runtime                   |
                                     | replay/gates/receipts     |
                                     +-------------+-------------+
                                                   |
                                                   v
                                     +---------------------------+
                                     | verified application      |
                                     | execution                 |
                                     +---------------------------+

  lab consumes all public boundaries. Production code never depends on lab.
```

The verification path is:

```text
ProofBytes
  -> DecodedProof
  -> ResolvedProof
  -> ControlVerifiedProof
  -> VerifiedAuthority
  -> VerifiedAction
  -> ExecutionLease
  -> ExecutableAction
```

The architectural rule remains:

> Auths owns authority. Adapters establish bounded facts.

## Signed-contract rewrite

The current and target contracts both use protocol major V1. The following
differences are implemented by replacing the current prelaunch V1 schema and
fixtures.

### Grant

| Concern | Current prototype | Target V1 | Action |
|---|---|---|---|
| Issuer and subject | Present | Present | Reuse |
| Permission set | Exact pairs | Exact pairs | Reuse |
| Validity | Issue time plus validity window | `not_before` and `expires_at` | Rewrite |
| Audience | Bound only by action | Attenuating set on every grant | Build |
| Action constraint | Not represented | `AnyBody`, exact digest, or bounded digest set | Build |
| Budget ceiling | Not represented | Optional monotonic ceiling | Build |
| Delegation depth | Present | Present | Reuse |
| Parent | Previous signed grant ID | Digest-addressed parent | Rewrite |
| Status policy | Expiry or unimplemented authority-state method | Explicit grant status policy | Rewrite |
| Assurance floor | Anchor and global policy only | Per-grant predicate identifier | Build |
| Critical extensions | Closed object | Bounded registered extensions | Build |
| Identifier | Digest includes signed representation | Digest of canonical statement bytes | Rewrite |

### Action

| Concern | Current prototype | Target V1 | Action |
|---|---|---|---|
| Actor | Present | Present | Reuse |
| Permission | Exact pair | Profile-namespaced capability and resource | Rewrite |
| Body binding | Digest of caller-supplied bytes | Digest of profile-canonical bytes and media type | Rewrite |
| Audience | Present | Present | Reuse |
| Challenge | Present | Present | Reuse |
| Time window | Present | Present | Reuse |
| Profile ID/version | Outside signed action | Signed into action envelope | Build |
| Terminal grant | Implied by vector order | Exact signed reference | Build |
| Authorization plan | Not represented | Exact signed plan identifier | Build |
| Channel requirement | Application-local | Signed requirement evaluated by outer gate | Build |

### Proof bundle

| Concern | Current prototype | Target V1 | Action |
|---|---|---|---|
| Actions | Exactly one | Bounded digest-addressed set | Rewrite |
| Grant topology | Ordered linear vector | Digest graph referenced by plan leaves | Rewrite |
| Authorization plan | Implicit one-chain proof | `Proof`, `AllOf`, `AnyOf`, and `KOfN` | Build |
| Evidence | Principal evidence plus bindings | General bounded evidence map | Rewrite |
| Principal status | Folded into method evidence | Separate status objects and snapshot | Build |
| Grant status | Port only | Signed status objects and snapshot | Build |
| Attachments | Not represented | Digest-addressed detached descriptors | Build |
| Reference validation | Linear checks | Cycle, ambiguity, mismatch, and unused-critical checks | Rewrite |

### Context and outputs

| Concern | Current prototype | Target V1 | Action |
|---|---|---|---|
| Time, audience, challenge, body | Explicit | Explicit | Reuse |
| Trust anchors | Principal, permission, validity, depth, assurance | Add profile, audience, resource, status, and assurance ceilings | Rewrite |
| Adapter selection | Explicit aggregate registry | Exact immutable registries by extension class | Rewrite |
| Status | Evidence passed with bundle | Immutable principal and grant snapshots | Rewrite |
| Profile policy | MCP service-local | Explicit verifier context input | Build |
| Channel policy | MCP service-local | Explicit outer-gate policy ID | Rewrite |
| Limits | Decode limits | Decode, graph, crypto, adapter, plan, and work limits | Rewrite |
| Context digest | Absent | Deterministic receipt/cache key | Build |
| Authorized value | Data-bearing verdict | Unforgeable `VerifiedAction` | Rewrite |
| Executable value | Application inspects verdict | Unforgeable `ExecutableAction<P>` | Build |

## Component build map

### Specification, model, and codec

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Language-neutral object model | Rewrite `spec/v1` and CDDL to the complete target | `spec/v1` | Signing bytes can be derived without Rust |
| Deterministic CBOR | Rewrite codec for all target objects and limits | `auths-codec` | Canonical round trips and malformed corpus |
| Domain separation | Rewrite all domains around protocol, object, profile, and version | `auths-codec` | Cross-object and cross-profile substitution tests |
| Validated newtypes | Expand identifier and bounded collection vocabulary | `auths-model` | Invalid and oversized construction fails |
| Registries | Build exact immutable registries and manifests | `auths-registries` | Unknown identifiers fail without fallback |
| Failure taxonomy | Rewrite as stable language-neutral codes | model/verifier/runtime | Corpus asserts stage, class, and code |

### Authority kernel

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Scoped roots | Rewrite with all authority ceilings | `auths-authority` | One widening-negative per dimension |
| Exact permissions | Reuse exact set inclusion | `auths-authority` | Property and mutation tests |
| Edge attenuation | Expand to time, audience, constraints, budgets, and depth | `auths-authority` | Mixed-dimension negative corpus |
| Action constraints | Build closed three-variant partial order | `auths-authority` | Algebra properties and boundary vectors |
| Authorization plans | Build bounded deterministic evaluator | `auths-composition` | Mixed-plan and mismatched-action vectors |
| Role-indexed assurance | Rewrite flat claims as role/provenance reports | `auths-assurance` | Evidence cannot satisfy the wrong role |
| Principal and grant status | Replace aggregate authority-state abstraction | `auths-status` | Revoked parent invalidates descendants |
| Sealed stages | Build private constructors and stage APIs | verifier/action/runtime | Compile-fail forgery tests |
| Pure native/WASM parity | Reuse and strengthen the boundary | verifier/WASM | Identical digests, verdicts, and reports |

### Cryptography and principal control

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Signature suites | Extract verification from principal adapters into exact suite registry | `auths-signature` | Algorithm substitution and high-S tests |
| Raw key | Adapt current Ed25519/P-256 code | raw-key adapter | Positive and malformed vectors |
| `did:key` | Adapt current parser/control code | did-key adapter | Official and confusion vectors |
| `did:keri` | Extend bounded KEL code with explicit checkpoint/status claims | did-keri adapter | Historical/current distinctions |
| Bundled `did:web` | Reuse resolver separation; rewrite assurance provenance | did-web adapter/resolver | Native/WASM and backdating tests |
| SPIFFE/X.509 | Build path, SAN, EKU, status, and bridge modes | evidence adapter | Trust-domain and bridge-confusion tests |
| WebAuthn | Build ceremony, origin, flags, credential, and attestation checks | evidence adapter | Ceremony and counter-policy vectors |
| HSM-backed principals | Build registered attestation profiles | evidence adapter | Downgrade and transaction-binding tests |

### Exchange, runtime, and receipts

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Exchange messages | Adapt useful prototype semantics to target V1 | `exchange/` | Byte-stable target corpus |
| Peer observations | Reuse typed fact boundary and add all transports | exchange adapters | Transport substitution preserves verdict |
| Memory and Iroh | Reuse implementations behind target ports | exchange adapters | Shared conformance |
| HTTPS, TCP, Unix, file | Build remaining adapters | exchange adapters | Shared conformance and channel-policy tests |
| Replay lease | Generalize the one-use ledger to action-bound atomic lease | `runtime/` | Concurrent duplicates execute once |
| Budget ledger | Build stateful atomic consumption | `runtime/` | Exhaustion and concurrency tests |
| Verified execution | Build `VerifiedAction -> Lease -> ExecutableAction<P>` | runtime/profiles | Executor cannot accept unverified bytes |
| Decision receipt | Build canonical decision record | `receipts/` | Tamper and offline verification vectors |
| Execution receipt | Build lease/result record | `receipts/` | Success/failure reconstruction |
| Audit bundle | Build minimized portable export | receipts/control | Redaction and offline reconstruction |

### Profiles and authoring

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Profile contract | Extract and formalize canonicalization/display/decoder interface | `profiles/` | Common contract tests |
| MCP | Adapt prototype to signed target envelope and verified decoder | MCP profile | Memory/Iroh end-to-end tests |
| HTTP | Build canonical HTTP profile | HTTP profile | URI/header/defaulting corpus |
| Git | Build commit/tag/ref/merge/release profile | Git profile | Ambiguity and TOCTOU analysis |
| Deployment | Build artifact/environment/config/strategy profile | deploy profile | Exact digest mismatch tests |
| Supply chain | Build build/attest/publish/promote profile | supply-chain profile | Provenance and subject tests |
| Edge control | Build device/firmware/sequence profile | edge profile | Offline and stale-sequence tests |
| Keyless authoring | Expand current builders and CLI | `authoring/` | External signer round trips |
| Approval display | Build exact human-readable profile displays | profiles/authoring | Display-to-digest fixtures |
| Custody integrations | Build WebAuthn, workload, KMS, HSM, and PKCS#11 leaves | authoring adapters | Transaction-binding tests |

### Configuration, performance, and conformance

| Target capability | Action | Target owner | Acceptance evidence |
|---|---|---|---|
| Declarative configuration | Build compiler to immutable context templates | runtime/control | Startup diagnostics and context digest |
| Dependency allow-list | Expand current architecture checks | `xtask` | Forbidden edges fail CI |
| Pure-stage caches | Build exact keys and validity bounds | runtime | Context/status invalidation tests |
| Stable-prefix cache | Build without skipping action checks | runtime/verifier | Mutated action remains denied |
| Bounded parallelism | Build deterministic scheduled verification | runtime | Sequential/parallel parity |
| Language-neutral corpus | Rewrite and expand fixtures | spec/lab | Rust, Go, and TypeScript share files |
| Go verifier | Build independent server verifier | `implementations/go` | Zero required divergence |
| TypeScript verifier | Build browser/Node verifier | `implementations/typescript` | Zero required divergence |
| Auths Lab | Build factorial matrices and raw result artifacts | `lab/` | Reproducible runs |
| Operator studies | Build and run target workflows | lab/control | Time, error, recovery, and over-granting metrics |

## Build-order correction

The target paper places exact-body constraints and multi-proof composition in
its final “composition and scale” phase. Their semantics affect the core grant,
action, proof, reference, identifier, and limit model.

For the implementation:

1. the complete `ActionConstraint` and `AuthorizationPlan` grammar is part of
   the initial target V1 specification;
2. all three plan operators are implemented before the verifier API is frozen;
3. the budget ceiling is part of the initial grant model, while budget
   consumption remains an outer runtime responsibility;
4. caching, parallelism, and independent implementations remain later because
   they do not define authority meaning.

## Prelaunch reset rules

- There is one target protocol: V1.
- Existing V1 schemas, bytes, fixtures, and APIs may be replaced.
- Old prototype proofs are not accepted by the target verifier.
- No compatibility or translation code is added.
- No deprecated aliases are retained solely for the prototype.
- Useful code is reused only when it fits the target boundary.
- Tests are rewritten around target requirements rather than preserving old
  implementation shape.
- Unknown protocol, suite, method, profile, evidence, status, and extension
  identifiers still fail closed; zero users does not weaken security rules.

## Target-section traceability

| Target sections | Delivery slice |
|---|---|
| 1–8: model, authority, and wire protocol | Slices 1–2 |
| 9–12: assurance, status, adapters, suites | Slice 3 |
| 13–18: profiles, exchange, runtime, authoring, receipts | Slices 4–5 |
| 19–23: topology, APIs, config, caching, extensions | Slices 0–6 |
| 24–26: conformance, security, evaluation | Slices 1–7 |
| 27–28: deployments and operations | Slices 4–7 |
| 29: build sequence | Superseded by `DELIVERY.md` |
| Appendices A–D | Enforced across Slices 1–7 |

## Completion

The target is complete only when:

- every row above is implemented or removed through an accepted replacement
  decision;
- Rust, Go, and TypeScript agree on all canonical digests, verdict classes,
  reason codes, and assurance reports;
- all six transports preserve the same Auths verdict for identical inputs;
- all six profiles execute only commands decoded from `VerifiedAction`;
- native and WASM verification preserve identical semantics;
- the architectural acceptance checklist is executable in CI where possible;
- independent protocol and implementation reviews are resolved against the
  launch candidate.
