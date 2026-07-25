# Auths Target-State Delivery Plan

**Status:** Proposed execution plan

**Date:** 25 July 2026

**Protocol target:** Auths Proof Protocol V1

**Repository:** `auths-proof`

## Product context

Auths is prelaunch with zero users. This plan builds the target directly.

The current implementation is prototype material. The plan does not preserve
its wire bytes, APIs, fixtures, package names, or repository boundaries. There
is one target protocol: V1.

The work is divided into dependency-ordered slices so each security boundary
can be reviewed and tested before more surface is added. The slices are build
gates.

This plan implements [`DELTA.md`](DELTA.md) and follows
[ADR 0008](../adr/0008-reset-prelaunch-v1.md) and
[ADR 0009](../adr/0009-target-workspace-topology.md).

## Delivery principles

1. **Specification precedes signed bytes.** No signed type is implemented
   before its language-neutral schema, domain, identifier rule, limit, and
   failure behavior are written.
2. **Build the target, not compatibility.** Prototype contracts may be broken
   or deleted whenever the target requires it.
3. **Complete one vertical before expanding the matrix.** One exact MCP action
   must pass the full target gate before more transports and profiles are
   added.
4. **Every boundary has negative evidence.** Happy-path tests are insufficient
   for parsers, adapters, attenuation, profiles, transports, or execution.
5. **Effects remain outside the kernel.** Networking, clocks, storage,
   randomness, private keys, and execution never enter the pure proof graph.
6. **Unknown means unsupported, never fallback.** Registry selection is exact
   at every extension point.
7. **Execution consumes verified data.** Applications never return to the
   original unverified request after producing `VerifiedAction`.
8. **Optimize only stable semantics.** Caching and parallelism may accelerate
   the decision relation but cannot define it.

## Build architecture

```text
SLICE 0          SLICE 1          SLICE 2          SLICE 3
repo reset  ---> V1 spec/corpus -> pure V1 kernel -> evidence/status
                      |                 |                 |
                      +-----------------+-----------------+
                                        |
                                        v
                                  SLICE 4
                       MCP + runtime + receipts
                          over memory and Iroh
                                        |
                                        v
                                  SLICE 5
                     transports + profiles + authoring
                                        |
                                        v
                                  SLICE 6
                        config + cache + operations
                                        |
                                        v
                                  SLICE 7
                   independent verifiers + review + launch
```

Work inside a slice may proceed concurrently only after the shared
language-neutral contracts and fixtures for that slice are fixed.

## Slice 0 — Reset the repository around the target

### Objective

Make `auths-proof` the single target repository and remove prototype structure
as a design constraint.

### Work

- Accept ADR 0008 and ADR 0009.
- Add the target-state paper, build map, and delivery plan to the canonical
  documentation.
- Establish the target top-level directories:

```text
spec        crates       adapters      resolvers
exchange    profiles     runtime       authoring
receipts    lab          implementations
apps        xtask
```

- Update workspace metadata and architecture checks for the target dependency
  graph.
- Move useful exchange, Iroh, MCP, replay, demo, and benchmark code into its
  target package group.
- Remove sibling path dependencies and prototype-only package names.
- Record current benchmark and test results only as engineering input, not as
  compatibility requirements.
- Delete obsolete specifications, fixtures, APIs, and code when their target
  replacements are ready.

### Exit gate

- All target package groups have an owner and allowed dependency direction.
- The pure proof graph is isolated from effectful packages.
- `auths-proof` is the only repository required to build and test the target.
- No target implementation path introduces a second protocol or
  prototype-support layer.
- Current prototype code has been classified as reuse, rewrite, or removal.

## Slice 1 — Define the complete target V1 contract

### Objective

Rewrite `spec/v1` and `fixtures/v1` as the only normative Auths protocol.

### Work

Define:

- object model and CDDL;
- deterministic encoding;
- domain separation and identifiers;
- protocol registries and compatibility manifests;
- verification algorithm;
- assurance predicates and implication rules;
- principal and grant status;
- application-profile contract;
- stable failure taxonomy;
- resource and work-unit limits.

The initial V1 grammar includes:

- scoped trust anchors;
- complete grants with audience, action constraint, budget, depth, status,
  assurance, and critical extensions;
- `AnyBody`, `ExactBodyDigest`, and `AllowedBodyDigests`;
- complete action envelopes;
- `Proof`, `AllOf`, `AnyOf`, and `KOfN`;
- digest-addressed grants, actions, evidence, status, and attachments;
- signed principal and grant status statements;
- decision and execution receipt inputs.

Replace the fixture corpus with:

- one hand-reviewed raw-key chain;
- one exact-body approval;
- one `AllOf` plan;
- one threshold plan;
- canonical byte and digest manifests;
- a negative fixture for every signed critical field;
- non-canonical CBOR fixtures;
- missing, duplicate, mismatched, cyclic, ambiguous, and unused-critical
  reference fixtures;
- maximum default bounded malformed objects.

Old fixture stability is not a goal. The rewritten target fixtures become the
only V1 corpus.

### API contract

The language-neutral pure verifier contract is:

```text
verify(
    proof_bytes,
    canonical_action,
    verifier_context,
    immutable_registries
) -> Authorized(VerifiedAction)
   | Denied(DenialReason)
   | Indeterminate(Requirement)
```

Replay, channel policy, budget consumption, receipts, and execution remain
outside this function.

### Exit gate

- A reviewer can calculate signing bytes, object identifiers, references, and
  expected verdicts without reading Rust.
- Every collection and byte string has a protocol maximum and lower default.
- Every registry has exact unknown-identifier behavior.
- The schema contains no Rust-specific enum layout or serialized
  implementation type.
- Every plan operator and action constraint has positive and negative vectors.
- The target V1 decision relation has no unresolved normative behavior.

## Slice 2 — Build the pure V1 authority kernel

### Objective

Produce a complete portable authorization result from raw-key evidence.

### Work

- Implement validated types and bounded collections.
- Implement the deterministic codec against the new V1 vectors.
- Implement immutable signature, principal, status, assurance, profile, and
  extension registries.
- Implement Ed25519 and P-256/SHA-256 behind the signature-suite port.
- Adapt raw-key principal control to the suite/control split.
- Resolve and validate the full digest graph before adapter or signature work.
- Implement scoped roots and attenuation across permissions, time, audience,
  action constraints, budget ceiling, and delegation depth.
- Implement the complete bounded authorization-plan evaluator.
- Implement role-indexed assurance for raw-key claims.
- Implement the sealed stages:

```text
ProofBytes
  -> DecodedProof
  -> ResolvedProof
  -> ControlVerifiedProof
  -> VerifiedAuthority
  -> VerifiedAction
```

- Return deterministic denial and indeterminate results with stable codes.
- Compute a deterministic context digest.
- Rewrite authoring builders and CLI commands around the target objects.
- Build the same pure implementation for native and
  `wasm32-unknown-unknown`.
- Remove superseded prototype model, codec, verifier, and fixture paths.

### Required tests

- exact permission, time, audience, constraint, budget, and depth attenuation;
- mixed Ed25519/P-256 chains;
- every plan operator, nesting limit, threshold boundary, and shared-action
  binding;
- algorithm, suite, adapter, profile, and object substitution;
- high-S P-256 rejection;
- one-bit mutations of every signed critical field;
- arbitrary-byte no-panic and maximum-invalid-input bounds;
- compile-fail tests for private verified-stage constructors;
- native/WASM digest and verdict parity.

### Exit gate

- A raw-key root authorizes a raw-key actor for an exact target V1 action.
- A mixed-algorithm threshold fixture produces the specified
  `VerifiedAction`.
- Widening any authority dimension is denied.
- Missing required evidence is indeterminate and cannot execute.
- The kernel dependency allow-list passes.
- All target V1 golden fixtures are byte-stable.
- No obsolete prototype decoder remains in the production graph.

## Slice 3 — Complete evidence, status, and assurance

### Objective

Support all principal families as bounded fact providers without changing
authority semantics.

### Slice 3A — Reuse the proven principal work

- Adapt `did:key`, `did:keri`, and bundled `did:web` to target control
  statements and the signature-suite registry.
- Preserve the pure/native resolver separation for `did:web`.
- Implement parameterized assurance claims carrying principal, role, adapter,
  version, evidence digest, and source.
- Separate principal status from grant status.
- Implement immutable signed status snapshots.
- Implement current, historical, statement-existence, and
  freshness-relative claims.
- Implement active, revoked, and superseded grant states with sequences.
- Demonstrate mixed-method chains in both directions.

#### Exit gate

- Raw key, `did:key`, `did:keri`, and bundled `did:web` pass the shared target
  adapter corpus.
- A revoked parent invalidates every descendant.
- Historical control without statement-existence evidence cannot satisfy a
  policy that requires it.
- Strong actor evidence cannot satisfy a root or intermediate requirement.
- Native and WASM results are identical for portable adapters.

### Slice 3B — Build the remaining principal families

- Implement SPIFFE/X.509 path, URI SAN, EKU, status, and explicit
  signing/bridge modes.
- Implement WebAuthn challenge, RP ID, origin, flags, credential state,
  counter, and attestation policy.
- Implement HSM/KMS attestation profiles with purpose, protection level,
  non-exportability, and transaction binding.
- Build evidence assemblers outside the kernel for certificates, WebAuthn
  registration data, and supported attestations.

#### Exit gate

- All seven principal families pass positive, negative, malformed, downgrade,
  cross-adapter, and work-limit vectors.
- Ed25519 and P-256 are mandatory suites with no fallback.
- Every assurance claim is traceable to accepted evidence.
- No resolver or custody integration appears in the verifier graph.

## Slice 4 — Build one complete verified execution vertical

### Objective

Execute one exact MCP tool call through the full target gate over memory and
Iroh.

### Exchange

- Implement target challenge, submission, response, peer-observation, and
  metrics messages.
- Bind submissions to exact Auths and MCP profile versions.
- Put in-memory and Iroh adapters behind the common exchange port.

### Profile

- Implement the common `ActionProfile` contract.
- Implement `auths.mcp/1` canonicalization, exact permission/resource mapping,
  approval display, and verified command decoder.
- Provide a second independent MCP canonicalizer.

### Runtime

- Compile clock, trust, registry, status, profile, channel, and limit inputs
  into explicit verifier context.
- Implement an atomic replay store.
- Bind `ExecutionLease` to challenge, action digest, audience, and expiry.
- Construct `ExecutableAction<Mcp>` only after:

```text
Auths authority
AND exact action binding
AND status freshness
AND channel policy
AND replay claim
AND local application policy
```

- Make the executor accept only the MCP command decoded from
  `VerifiedAction`.
- Emit canonical decision and execution receipts.
- Keep execution failure distinct from authority validity.

### Operator UX

```text
+----------------------------------------------------------+
| Auths V1 · MCP approval                                  |
|----------------------------------------------------------|
| Actor       did:key:...                                  |
| Tool        reports/read_report                          |
| Arguments   {"path":"/reports/q3.pdf"}                   |
| Audience    mcp://reports                                |
| Constraint  exact body digest                            |
| Plan        human approval AND agent authority           |
| Expires     2026-07-25T...                               |
|----------------------------------------------------------|
| [signing bytes digest]        [Approve] [Reject]          |
+----------------------------------------------------------+
```

The profile owns the display and proves that it represents the canonical bytes
sent to the signer.

### Exit gate

- The same proof, action, and context produce the same Auths verdict over
  memory and Iroh.
- An authenticated Iroh peer cannot upgrade a denied or indeterminate proof.
- Concurrent duplicate submissions produce at most one execution lease.
- The executor has no API accepting the original unverified request.
- Decision and execution receipts verify offline and fail on mutation.
- The complete vertical uses only target package paths and contracts.

## Slice 5 — Complete transports, profiles, and authoring

### Slice 5A — Transports

Implement:

1. HTTPS;
2. Unix sockets;
3. file exchange;
4. TCP.

Each transport defines framing, limits, sessions, peer observations,
confidentiality expectations, channel binding, replay relationship, streaming,
batching, and error mapping.

#### Exit gate

- Memory, Iroh, HTTPS, TCP, Unix, and file adapters pass the same semantic
  submissions.
- Transport substitution does not change the Auths verdict.
- Weaker peer observations fail only channel policies requiring stronger
  observations.
- Raw TCP is not presented as the recommended public deployment.

### Slice 5B — Profiles

Implement:

1. HTTP;
2. Git;
3. deployment;
4. software supply chain;
5. edge control.

Each profile ships:

- a versioned canonical action schema;
- exact permission and resource mapping;
- human-readable approval display;
- verified command decoder;
- two independent canonicalizers;
- collision, ambiguity, default, Unicode, and normalization vectors;
- verify-to-execute analysis;
- profile-specific limits and operational errors.

#### Exit gate

- All six profiles pass the common contract.
- Every executor accepts only a command decoded from `VerifiedAction`.
- Profiles cannot select trust anchors or construct authority verdicts.
- Semantically similar but byte-distinct actions have explicit behavior.

### Slice 5C — Authoring and custody

- Implement safe grant and plan builders.
- Add authority-diff and over-granting warnings.
- Add profile-owned approval displays.
- Integrate WebAuthn, workload, KMS, HSM, and PKCS#11 signers through external
  signing requests.
- Add receipt and audit export commands.
- Keep private keys and custody clients outside the proof kernel.

#### Exit gate

- An operator can author, inspect, sign, assemble, verify, revoke, and audit a
  mixed-method proof without editing CBOR.
- Approval displays reproduce the canonical signing digest.
- Signer failure cannot produce a partially signed accepted object.

## Slice 6 — Configuration, state, performance, and operations

### Objective

Make the complete system deployable, observable, and bounded under load.

### Work

- Compile declarative configuration into immutable registries,
  `VerifierContextTemplate`, context digest, startup diagnostics, authority
  summary, and policy tests.
- Implement persistent replay and budget-ledger ports and references.
- Implement receipt stores and local-spool behavior.
- Implement pure-stage caches with kernel-computed validity bounds.
- Implement stable-prefix authority caching without skipping action checks.
- Implement bounded parallel verification with deterministic diagnostics.
- Add readiness checks for registries, anchors, profiles, stores, and
  cryptographic self-tests.
- Add metrics, traces, privacy-preserving logs, and stable reason dimensions.
- Add degraded-mode and incident-response commands.

### Operational API

```text
configuration
    -> validate
    -> resolve pinned manifests
    -> compile immutable registries/context
    -> run policy self-tests
    -> open replay/budget/receipt stores
    -> ready
```

Startup fails closed when required registries, anchors, profiles, self-tests,
replay storage, or policy fixtures are invalid.

### Exit gate

- Context, status, registry, and policy changes invalidate affected caches.
- Cached and uncached verification produce identical outputs.
- Sequential and parallel verification produce identical ordered diagnostics.
- Replay-store unavailability prevents execution.
- Stale status never silently becomes current.
- Receipt-store failure follows explicit fail-closed or local-spool policy.
- Maximum malformed inputs remain within measured CPU and memory budgets.
- Native and browser performance results include reproducible build and
  hardware metadata.

## Slice 7 — Independent conformance, review, and launch

### Objective

Demonstrate portable meaning beyond the Rust implementation and close every
launch gate.

### Work

- Publish the complete language-neutral corpus.
- Build an independent Go server verifier.
- Build an independent TypeScript browser/Node verifier.
- Compare canonical digests, verdicts, reasons, assurance reports, context
  digests, and action digests.
- Run the factorial Auths Lab across security-equivalent combinations.
- Run fuzzing, hostile maximum-input evaluation, and differential decoding.
- Exercise agent tools, software release, cross-organization actions,
  air-gapped deployment, and edge control.
- Run operator studies for first action, delegation, rotation, revocation,
  stale evidence, diagnosis, multi-party approval, and audit reconstruction.
- Commission independent protocol/cryptography and implementation reviews.
- Resolve findings against an immutable launch candidate.

### Exit gate

- Rust, Go, and TypeScript have zero required divergence.
- Every adapter and profile has positive and negative vectors.
- Every transport passes transport-invariance tests.
- Dependency allow-lists and native/WASM graph checks pass.
- Performance and bounded-invalid-input results are published as measurements.
- The architectural acceptance checklist passes or has an accepted exception.
- Security and implementation reviews are resolved.
- Launch documentation distinguishes guarantees, local policy, operational
  state, and residual risks.

## Public API stabilization order

| Order | Contract | Stable after |
|---:|---|---|
| 1 | V1 schemas, domains, identifiers, limits, registries | Slice 1 |
| 2 | Signature, principal, status, and assurance ports | Slice 3 |
| 3 | Authority, plan, action, verdict, and stage types | Slice 2 |
| 4 | Exchange messages and peer observations | Slice 4 |
| 5 | Profile and verified-command contract | Slice 4 |
| 6 | Replay, lease, execution, budget, and receipts | Slice 6 |
| 7 | Configuration, cache, and observability | Slice 6 |
| 8 | Cross-language conformance results | Slice 7 |

No downstream API freezes before its semantic dependencies.

## Continuous gates

### Wire gate

- canonical byte stability after the target V1 freeze;
- no unknown critical-field acceptance;
- exact registry selection;
- cross-object, algorithm, adapter, and profile confusion negatives.

### Authority gate

- no widening;
- no proof-carried trust-anchor promotion;
- no assurance laundering;
- no stale or revoked evidence accepted as current;
- no mismatched action/plan composition.

### Architecture gate

- pure-kernel dependency allow-list;
- native/WASM semantic parity;
- no transport-to-verdict dependency;
- no profile-to-anchor dependency;
- no resolver-to-verifier effect path.

### Execution gate

- replay and budget state are atomic;
- channel observations cannot create authority;
- executors consume only verified commands;
- decision and execution failures remain distinct.

### Usability gate

- approval displays bind exact signed bytes;
- CLI errors retain stable reason codes;
- operators can distinguish denial, indeterminate evidence, replay, channel,
  and execution failure;
- safe defaults do not silently over-grant.

## Change packaging

- A slice may contain multiple small commits and pull requests.
- Prototype types and fixtures may be deleted once their target replacement is
  reviewed.
- Target fixtures change only in a commit naming the corresponding
  specification change.
- Generated vectors are never updated merely to make tests pass.
- Crate splitting must enforce an architectural property.
- Every adapter, transport, and profile uses its shared conformance suite from
  its first implementation.
- Performance changes include parity tests against the sequential uncached
  reference.
- No compatibility code is added without superseding ADR 0008.

## Completion

The program is complete when every target row in
[`DELTA.md`](DELTA.md) is implemented or removed through an accepted
replacement decision, all Slice 7 gates pass, and the launch candidate
completes external review.
