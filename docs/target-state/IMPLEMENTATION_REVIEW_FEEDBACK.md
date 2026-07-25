# Auths-Proof Implementation Review and Build-Out Requirements

Status: implementation feedback for `dev-implementation-delta`  
Review date: 2026-07-25  
Audience: implementers and reviewers of the Auths proof kernel

## Purpose

This document records the follow-up work identified while reviewing the current
target-state implementation.

The intended capability surface is assumed to be correct. The recommendation is
to finish and harden these capabilities, not to reduce the design until the
current code happens to satisfy it. A field, registry, outcome, extension point,
or resource limit that is part of the protocol must have real verification
semantics, tests, and portable vectors before V1 is frozen.

Deleting a superseded prototype after its behavior has been implemented in the
target architecture is cleanup, not feature removal. There is no requirement
for migration code, compatibility shims, or a V1-to-V2 transition: Auths is
prelaunch and the target implementation should become the one canonical V1.

This review is a branch snapshot. The branch was still receiving edits during
the review, so exact compiler diagnostics may move. The architectural and
semantic findings below are the durable feedback.

## Overall assessment

The branch establishes a promising kernel shape:

- protocol types are becoming distinct from codecs and cryptographic suites;
- verification is moving toward explicit immutable registries and injected
  trust;
- composition, assurance, status, authoring, and verification have separate
  homes;
- deterministic CBOR, fixture generation, `xtask`, and fuzzing are treated as
  first-class concerns;
- the repository boundary is substantially clearer than in the prototype.

It is not ready for a V1 semantic freeze yet. Several security-relevant inputs
are encoded but do not affect the verdict, some composition behavior is stricter
than the plan it is meant to evaluate, status trust is underspecified, and the
portable verification artifacts are not yet sufficient for an independent
implementation.

The right response is to build those paths out completely.

## Non-negotiable architecture boundary

`auths-proof` remains the deterministic, offline authorization-proof kernel. It
may define pure data types, ports, registries, algorithms, codecs, limits, and
conformance fixtures. It must not absorb:

- transports, listeners, RPC clients, or network discovery;
- runtime replay state, live budget consumption, or session coordination;
- MCP process lifecycle or tool execution;
- application-specific command parsing or business policy;
- live evidence acquisition;
- key custody, signing agents, or secret storage.

That boundary does not require removing profile, identity-method, assurance,
status, budget, or extension capabilities. It requires expressing them as
deterministic kernel contracts.

The ownership model should be:

- `auths-proof` defines and enforces the pure contract.
- Optional adapters can implement principal, status, assurance, budget, or
  extension contracts without becoming privileged protocol semantics.
- `auths-proof-apps` supplies application-profile implementations and runtime
  integration.
- `auths-proof-exchange` supplies transport and exchange behavior.

The dependency direction must always point toward `auths-proof`; the kernel
must never depend on either downstream repository.

## Priority build-out requirements

### 1. Make composition evaluate branch results

#### Current gap

The current principal-control path verifies referenced grants, actions, and
statuses before the authorization plan is evaluated. A failure in an optional
branch can therefore reject the whole proof before `AnyOf` or `KOfN` has a
chance to apply its semantics.

This makes the implementation behave like an implicit `AllOf` at an earlier
stage. For example, a valid branch in `AnyOf(valid, invalid-signature)` cannot
authorize if the invalid signature is returned as a global error first.

#### Required implementation

Build a deterministic result graph for all plan leaves:

- Each statement or leaf produces a typed local result such as satisfied,
  denied, indeterminate, or structurally invalid.
- The composition evaluator consumes those results according to `AllOf`,
  `AnyOf`, and `KOfN`.
- Errors that make the proof container itself uninterpretable remain global.
- A branch-local cryptographic, status, assurance, or policy failure remains
  local unless the plan requires that branch.
- The evaluator uses an explicit precedence table for denied and indeterminate
  outcomes.
- Reasons and authorized branches have canonical ordering independent of input
  map order or traversal accidents.

No branch may be skipped for resource accounting merely because an earlier
branch is already sufficient, unless short-circuiting and its observable work
semantics are specified canonically.

#### Acceptance evidence

Add unit tests and committed corpus cases for:

- `AnyOf(valid, invalid signature)` resulting in authorization;
- `AnyOf(denied, indeterminate)` using the specified outcome precedence;
- mixed `KOfN` success, denial, and indeterminate cases;
- nested plans with deterministic reason ordering;
- the same semantic plan encoded with different object order producing the
  same result and result digest;
- global malformed-container failures remaining global.

### 2. Give every accepted registry field executable semantics

#### Current gap

Several values participate in the encoded model but do not yet participate
fully in authorization:

- trust-anchor resource namespaces;
- verifier-context profile policy;
- budget algebra identifiers;
- accepted critical extensions and their bytes;
- the registry-manifest identifier.

Membership checks alone are insufficient. If a value can alter the meaning of
a proof, the verifier must select an exact registered implementation and execute
it. If it cannot alter the meaning of a proof, it should not be presented as a
security control.

#### Required implementation

Build explicit, closed, pure registry contracts:

1. **Resource matching**

   Define a registered resource-matching algebra. A trust anchor's namespace
   constraints and a grant's resource constraints must be evaluated by the
   selected algebra. Do not silently assume string-prefix behavior. Matching
   must be canonical, bounded, and testable.

2. **Profile policy**

   Define an effect-free profile-policy port that receives already validated
   protocol facts and the canonical action. It returns a typed deterministic
   decision and bounded work usage. Concrete application semantics live
   downstream; the verifier still enforces that the context-selected policy
   exists, is accepted, and is actually invoked.

   A profile implementation must not choose trust anchors, construct authority,
   acquire evidence, or perform I/O.

3. **Budget algebra**

   Resolve every budget algebra identifier through an immutable registry.
   The registered implementation defines canonical attenuation, coverage,
   comparison, and work-cost behavior. Unknown or unaccepted algebras fail
   closed. Numeric `<=` is not a substitute for an identified algebra unless
   that is the explicitly registered algebra.

4. **Critical extensions**

   Resolve each critical extension through an exact handler contract. The
   handler validates and evaluates the extension bytes, reports bounded work,
   and cannot expand authority beyond the enclosing signed statements. An
   accepted identifier with no executable handler fails closed.

5. **Registry manifest binding**

   `ImmutableRegistries` must expose a canonical manifest identifier computed
   from or pinned to the complete accepted registry set. Verification requires
   an exact match with the trusted context. A manifest mismatch must have a
   stable result code and corpus case.

Every registry lookup must be exact. Avoid fallback implementations, loose
version matching, and “closest supported” behavior.

#### Acceptance evidence

For each registry type, provide:

- a successful exact-selection test;
- unknown, unaccepted, missing-handler, and wrong-version cases;
- a test proving the implementation was invoked rather than only accepted by
  identifier;
- deterministic work-limit behavior;
- a committed portable vector for at least one positive and one negative case.

### 3. Complete status trust and rollback semantics

#### Current gap

Status method identifiers and sequence-related result codes exist, but the
current path does not yet bind all of them into a coherent trust decision.
Principal status and grant status also need the same typed method-selection
rules. Re-verifying a signed status statement is not sufficient if its issuer
was never authorized to make status assertions.

#### Required implementation

Define one explicit status model for principals and grants:

- Every status statement carries an exact `StatusMethodId`.
- The verifier resolves that identifier through a registered pure status
  method.
- The trusted context defines the issuer trust relationship or pins a trusted
  signed checkpoint from which it can be derived.
- The status subject, purpose, issuer, method, sequence, and snapshot boundary
  are all typed and domain separated.
- The verifier has an explicit freshness rule and sequence floor or checkpoint.
- A sequence below the trusted floor produces `StatusSequenceRollback`.
- Missing, stale, revoked, wrong-method, wrong-issuer, and rollback outcomes are
  distinguishable and stable.
- Status processing is offline and deterministic. Fetching or refreshing status
  belongs outside this repository.

Specify how multiple otherwise valid status statements are selected. A newer
statement must not accidentally override a trusted revoked state unless the
protocol's issuer and sequence rules explicitly allow it.

#### Acceptance evidence

Add tests and vectors for:

- a correct statement from a trusted issuer;
- the correct bytes under the wrong method identifier;
- a valid signature from an untrusted status issuer;
- a lower sequence replay;
- freshness exactly at and one unit beyond the boundary;
- conflicting active and revoked statements;
- principal and grant status following the same selection rules.

### 4. Enforce work limits before expensive work begins

#### Current gap

A method can currently perform verification and report its work afterward.
That accounts for work but does not bound it: an adapter could do unbounded work
before the verifier rejects the reported total.

#### Required implementation

Introduce enforceable pre-execution accounting:

- Every pluggable operation declares a conservative maximum cost before it is
  invoked, or receives a non-clonable work-budget meter that it must charge
  before each bounded operation.
- The verifier reserves enough budget before signature verification, principal
  control, status evaluation, assurance processing, profile policy, budget
  algebra, and extension evaluation.
- Any reconciliation between reserved and actual cost uses checked arithmetic.
- Registry contracts state whether implementations may allocate and the maximum
  size derived from validated inputs.
- All count, byte, depth, recursion, and work limits are checked before the
  corresponding allocation or expensive operation.
- The outcome at the exact boundary is specified.

This is a kernel resource-safety mechanism. It is distinct from runtime
authorization-budget consumption, which remains downstream.

#### Acceptance evidence

Test:

- one unit below, exactly at, and one unit over every important limit;
- accumulated cost across nested and optional branches;
- adapters attempting to exceed their reservation;
- arithmetic overflow;
- adversarial input that cannot induce unbounded allocation;
- deterministic totals across native and portable verifier builds.

### 5. Build assurance into a real constraint system

#### Current gap

The assurance model is richer than the current evaluator. Role, claim kind, and
age checks alone do not enforce claim parameters, source, adapter identity and
version, accepted-claim registries, or explicit implication rules.

#### Required implementation

Build typed assurance constraints:

- exact claim-kind registration;
- typed, canonically encoded parameter predicates;
- source and evidence-subject constraints;
- exact adapter identifier and version constraints where required;
- context-defined freshness using one trusted time snapshot;
- a closed implication registry rather than string or heuristic implication;
- acceptance checks on every emitted claim, including claims synthesized by an
  adapter;
- canonical reporting of which evidence and claims satisfied each requirement;
- deterministic treatment of duplicate or stronger claims.

Implication must never be inferred from naming conventions. A claim can satisfy
another claim only through an exact registered rule whose semantics are part of
the immutable registry manifest.

#### Acceptance evidence

Include cases for:

- correct claim under the wrong role;
- correct kind with the wrong parameter, source, adapter, or adapter version;
- an adapter emitting an unregistered claim;
- freshness at both sides of the boundary;
- accepted and rejected implication paths;
- equivalent evidence order producing the same assurance report;
- parity with an independent verifier.

### 6. Finish the portable verification contract and corpus

#### Current gap

The current action fixture is not yet a complete portable `CanonicalAction`;
writing only the action body prevents an independent verifier from reconstructing
all profile, media, permission, and budget semantics. The expected result is
also not yet a complete machine-readable interoperability artifact.

#### Required implementation

Define canonical encode/decode support for the full verifier input and output:

```text
verify_v1(
    proof_cbor,
    canonical_action_cbor,
    trusted_context_cbor
) -> verification_result_cbor
```

The contract must be portable across native Rust, WASM, and independent
implementations. It must not expose Rust-specific enum layout, trait objects,
allocation behavior, or error strings.

The result schema should include at least:

- authorized, denied, or indeterminate;
- stable stage and reason codes;
- proof, action, context, plan, and result digests where applicable;
- authorized plan branches;
- the assurance report;
- resource and work totals.

The corpus manifest should record:

- every input and expected-output file;
- expected decode or verification stage;
- expected verdict and stable codes;
- all relevant digests;
- assurance and authorized-branch summaries;
- byte, object, depth, and work totals;
- the registry-manifest identifier.

`xtask` must reject both missing files and unlisted stale files. Corpus updates
must be explicit and reviewable.

The committed corpus should contain positive, denied, indeterminate, malformed,
limit-boundary, and metamorphic classes. “Invalid” should not collapse denial,
indeterminacy, and malformed encoding into one bucket.

#### Acceptance evidence

- Round-trip tests for proof, action, context, and result.
- Independent reconstruction of every fixture using only committed bytes and
  the specification.
- Native/WASM and independent-verifier parity.
- A clean-tree check after corpus generation.
- Exact file-inventory verification.

### 7. Complete attachment integrity and use semantics

#### Current gap

Attachment descriptors can be represented, but descriptor uniqueness alone
does not prove that detached bytes exist, match the descriptor, or are
authorized for a particular use.

#### Required implementation

Build attachment verification as an explicit offline input:

- Signed statements reference attachment identifiers where the attachment has
  semantic meaning.
- The verifier accepts a bounded map of detached attachment bytes, or an
  explicitly specified availability representation for intentionally opaque
  content.
- It verifies identifier, digest, byte length, media type, disposition, and
  signed reference rules.
- Missing required attachments, digest mismatch, length mismatch, duplicate
  descriptors, and unused critical attachments have distinct stable outcomes.
- Encrypted or opaque attachments can remain opaque only when the signed
  semantics explicitly permit that; their ciphertext integrity is still
  checked.
- Attachment bytes and descriptor processing participate in resource limits.
- The specification states which attachment metadata contributes to each
  signature and digest.

This remains offline verification. Transporting detached attachments belongs to
`auths-proof-exchange`.

#### Acceptance evidence

Add positive and negative vectors for missing bytes, wrong digest, wrong length,
duplicate identifier, unused critical attachment, opaque encrypted content,
and exact maximum sizes.

### 8. Turn `xtask`, fuzzing, and `.cbor` files into release gates

#### Current gap

The current fuzz-smoke path primarily exercises normal tests and does not yet
prove that every libFuzzer target builds and runs against bounded corpus input.
Some fuzz metadata still points at superseded prototype packages. The topology
checker also needs to fail closed for new workspace packages instead of silently
ignoring unknown ones.

#### Required implementation

`cargo xtask ci` should be the required, deterministic pull-request gate. It
should cover:

- formatting and warnings-as-errors;
- the full workspace test matrix;
- feature and target combinations promised by the crate contracts;
- architecture and forbidden-dependency checks;
- specification, registry, error-code, and codec synchronization;
- canonical fixture verification without rewriting;
- building every fuzz target;
- a short, deterministic, bounded corpus smoke for each target.

`cargo xtask release-check` should add:

- exact corpus inventory and digest verification;
- native/WASM portable-contract parity;
- package and public-API checks;
- all-target fuzz compilation;
- confirmation that generated artifacts leave the tree clean.

Long sanitizer and mutation campaigns can run on a schedule rather than every
pull request, but they must use the same committed seeds and publish
reproducers.

Fuzz targets should cover:

- proof codec;
- canonical action codec;
- trusted-context codec;
- verification-result codec;
- full verification with bounded synthetic registries;
- composition and model state transitions;
- principal-method parsers and signature-suite boundaries;
- status, assurance, budget, profile-policy, and extension handlers;
- portable ABI/WASM entry points.

Every fuzz target must assert bounded execution, no panic, no undefined
behavior, and deterministic output for identical validated inputs.

The architecture checker should reject an unknown workspace crate until it is
assigned an allowed layer or an explicit tooling-only exemption. It should
inspect dependency edges and feature-enabled edges, not only package names.

### 9. Finish the target topology, then clean up the prototype

#### Current gap

The repository currently contains both the target crates and excluded or
superseded prototype paths. Excluded code is not protected by workspace CI and
can mislead contributors about the supported API.

#### Required implementation

Keep every intended capability, but establish one implementation of it:

1. Finish the capability in the target crate and portable corpus.
2. Port any still-useful tests or fixtures from the prototype.
3. Prove parity or intentionally document the corrected V1 semantics.
4. Remove the superseded duplicate path.

Git history is the archive; the repository should not retain a second,
unmaintained implementation as documentation.

If a CLI is retained or rebuilt, it must be a thin adapter over the same public
authoring and verification APIs. It must not contain authorization, assurance,
status, identity, or profile business logic. Application execution and runtime
integration remain downstream.

No migration framework or compatibility facade is needed.

### 10. Preserve identity-method agnosticism while building adapters

#### Current gap

Some planning material still describes named identity methods as if they were
core architecture milestones. Concrete adapters are valuable, but a named
identity system must not define Auths authority semantics or become the assumed
root of trust.

#### Required implementation

- Define conformance in terms of the generic `PrincipalMethod` contract.
- Keep method identifiers exact, registered, and versioned.
- Give no concrete method privileged behavior in the core verifier.
- Use a minimal deterministic test method for core semantic vectors where
  method-specific behavior is irrelevant.
- Keep method-specific vectors scoped to adapter conformance.
- Build useful concrete adapters as optional implementations of the contract.
- Never make network resolution part of proof verification.

This approach builds out the adapter ecosystem without coupling Auths to KERI,
DID, OIDC, a corporate directory, or any other identity implementation.

### 11. Make every normative outcome reachable and tested

#### Current gap

The specification and error-code registry contain outcomes that are not yet
produced by a defined verifier path. An unreachable security error is usually a
sign that the underlying rule is absent or underspecified.

#### Required implementation

For every normative stage and reason code:

- identify the exact algorithm branch that produces it;
- define whether it is malformed, denied, or indeterminate;
- provide a minimal committed vector;
- confirm the portable result contains the stable code;
- remove ambiguity between overlapping codes through an explicit precedence
  table.

If an outcome is intentionally reserved for a future protocol version, mark it
as reserved rather than pretending it is implemented. That is registry
accuracy, not capability removal.

## Recommended implementation order

The following order minimizes rework while preserving the full target scope.

### Gate 0: stabilize the branch

- Stop concurrent edits while a release-gate run is being evaluated.
- Restore a compiling workspace.
- Make `cargo xtask ci` authoritative for the target workspace.
- Separate generated fixture updates from semantic implementation changes where
  practical.

### Gate 1: freeze contracts, not implementations

- Define the portable input/output schemas.
- Define the composition outcome algebra and precedence.
- Define the registry manifest.
- Define pure contracts for resource, profile, budget, extension, status, and
  assurance evaluation.
- Define pre-execution work accounting.

### Gate 2: implement the verifier semantics

- Build branch-local verification results.
- Wire every security-relevant context and registry field into the verdict.
- Complete status trust, rollback, assurance, and attachment rules.
- Make every normative code reachable.

### Gate 3: build the conformance surface

- Expand positive, denied, indeterminate, malformed, boundary, and metamorphic
  `.cbor` vectors.
- Generate complete expected result bytes and manifest metadata.
- Add independent-verifier and native/WASM parity checks.

### Gate 4: harden

- Expand fuzz targets across every decoder and pluggable boundary.
- Enforce topology and dependency rules fail-closed.
- Run scheduled sanitizer and longer fuzz campaigns.
- Add release reproducibility and clean-tree checks.

### Gate 5: converge the repository

- Port useful prototype tests.
- Delete superseded duplicate implementations only after target parity.
- Reconcile architecture, protocol, registry, and delivery documents with the
  implemented contracts.

## Definition of done

The target-state implementation is ready to freeze only when all of the
following are true:

- [ ] `AllOf`, `AnyOf`, and `KOfN` operate on branch-local outcomes.
- [ ] Every security-relevant encoded field changes verification through
      specified semantics.
- [ ] Every accepted registry identifier resolves to an exact executable
      implementation.
- [ ] The trusted context is bound to the exact immutable registry manifest.
- [ ] Status issuer trust, method selection, freshness, and rollback are
      specified and implemented.
- [ ] Assurance parameters, source, adapter/version constraints, and implication
      are enforced.
- [ ] Work is reserved or charged before expensive operations and allocations.
- [ ] Attachments have signed use and detached-byte integrity semantics.
- [ ] Full proof, action, context, and result values have canonical portable
      encodings.
- [ ] Every normative verdict and reason code has a committed vector.
- [ ] Corpus inventory is exact and regeneration leaves the tree clean.
- [ ] All fuzz targets build and receive bounded smoke execution in CI.
- [ ] Native, WASM, and independent implementations agree on committed vectors.
- [ ] Unknown workspace crates and forbidden dependency edges fail architecture
      checks.
- [ ] The CLI, if present, contains no domain logic.
- [ ] Identity-method adapters remain optional and core semantics remain
      method-agnostic.
- [ ] Superseded prototype code no longer competes with the target
      implementation.
- [ ] `cargo xtask ci` and `cargo xtask release-check` both pass from a clean
      checkout.

## Related target-state documents

- [Developer Integration Plan](DEVELOPER_INTEGRATION_PLAN.md)
- [Target-State Delta](DELTA.md)
- [Delivery Plan](DELIVERY.md)
- [Greenfield Foundation](AUTHS_PROOF_GREENFIELD_FOUNDATION.md)
- [Target Workspace Topology](../adr/0009-target-workspace-topology.md)

This document should be treated as implementation feedback for those plans. If
the implementation reveals a genuine contradiction, resolve it explicitly in
the protocol and architecture documents; do not silently bypass a field, return
code, registry, or extension point in code.
