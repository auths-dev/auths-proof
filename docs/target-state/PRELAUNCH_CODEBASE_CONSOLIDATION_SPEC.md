# Auths Prelaunch Codebase Consolidation Specification

## Status

Implementation specification for a direct prelaunch cutover.

This document is written for an agent with no prior context. It defines the
required investigation, architectural decisions, source deletions, replacement
implementations, tests, and completion gates for consolidating the current
Rust, TypeScript, Python, and demo surfaces.

Auths is prelaunch. There are no external users or production state to preserve.
Do not add deprecation aliases, compatibility exports, legacy decoders,
dual-read or dual-write paths, migration commands, old state readers, or runtime
switches. Replace each superseded path with one authoritative implementation and
delete the old path in the same change.

## Objective

Produce one coherent product architecture with:

1. one public product API in TypeScript and one matching public product API in
   Python;
2. one Rust-owned production client contract projected into both bindings;
3. profile-specific product verticals, while retaining broader deterministic
   Rust reference APIs in a clearly separated advanced tier;
4. one error model, one telemetry event model, and one support-bundle model;
5. demos that use installed public APIs or explicit HTTP service contracts,
   never private SDK modules;
6. one current vendored browser artifact under `public/vendor-v1/`;
7. explicit clocks and typed, bounded failure causes at stateful product
   boundaries;
8. production state transitions backed by real compare-and-swap semantics; and
9. smaller reviewable implementation modules without changing protocol bytes or
   core verification meaning.

This is not a protocol V1 redesign or an instruction to make Rust artificially
small. Preserve canonical CBOR, domain separation,
stable core decision codes, fixtures, verification outcomes, and the sealed
verified-action boundary unless a separately reviewed protocol change is
required.

## Rust reference surface versus product surface

Rust is the full reference implementation and may intentionally expose much
more than TypeScript or Python.

Use three API tiers:

| Tier | Audience | Scope |
| --- | --- | --- |
| Protocol/reference Rust | protocol implementers, security reviewers, advanced embedders | Complete deterministic model, codec, authoring, verifier stages, registries, ports, profile contracts, fixtures, and conformance tools |
| Rust product facade | ordinary Rust application developers | Curated safe path for common verification and closed-profile use |
| TypeScript/Python product APIs | application developers | Small high-level product workflow, offline verification, identity, closed profiles, narrow framework ports, and testkit |

“Public in Rust” does not mean “exported in every binding.” A Rust crate may be
public and documented for advanced use without being re-exported from
`auths-sdk`, WASM, npm, or the Python wheel. The required parity is semantic
parity for claimed operations, not identical symbol counts.

Keep broad Rust APIs when they are deterministic from explicit inputs, bounded,
fail closed, owned by the correct layer, useful to implementers or auditors,
and covered by fixtures and conformance evidence. Do not retain a generic Rust
abstraction when it owns cross-domain credentials, provider calls, mutable
state, retry policy, reconciliation, or receipt meaning through callbacks or
operation tags; those are profile-specific product concerns.

## Mandatory operating rules

Before changing source:

1. Read `/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/AGENTS.md`
   in full.
2. Read
   `/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`
   in full.
3. Inspect the nested `auths-proof` Git worktree and preserve unrelated changes.
4. Treat Rust product verticals as the owners of domain semantics. Bindings may
   project those semantics but must not independently define them.
5. Treat existing canonical fixtures as test oracles, not compatibility paths.
6. Do not change or delete canonical fixtures merely to make the refactor pass.
7. Do not create a universal callback-based profile runtime as the replacement
   for the current generic profile runtime.
8. Use a direct cutover. A pull request must not contain both old and new
   shipping implementations when it is declared complete.

## Phase 0: build the source-reference inventory first

The first deliverable is a checked-in implementation inventory. Do not start
deleting code until this inventory exists and every shipping and demo consumer
has been classified.

Create:

```text
docs/target-state/prelaunch-consolidation-source-inventory.md
```

The inventory must contain one row per affected symbol or source family with:

| Field | Required content |
| --- | --- |
| Current owner | Exact file and line containing the implementation |
| Consumers | Every Rust, TypeScript, Python, WASM, test, demo, and generated consumer |
| Classification | authoritative, duplicate, generic semantic abstraction, private bridge, generated artifact, demo-only, or dead |
| Target owner | Exact package/module that will own the replacement |
| Action | keep, move, rewrite, generate, or delete |
| Evidence | Tests or fixtures that preserve the intended behavior |
| Cutover gate | Objective condition that permits deletion of the old path |

Use source searches over `.rs`, `.ts`, `.d.ts`, and `.py` files first. Then
inspect manifests, architecture policy, compliance inventory, build tooling,
packaging scripts, and CI only to find non-source consumers and update required
repository wiring.

At minimum, inventory all of the following source references.

### Public and internal TypeScript API layers

- `bindings/typescript/src/index.ts:1-49` — current root exports, including the
  old local product result names and the newer production result names.
- `bindings/typescript/src/product.ts:1-29` — the local MCP facade depends on
  workflow types while also importing the production client.
- `bindings/typescript/src/product.ts:35-124` — generic product names backed by
  MCP-specific authority, receipts, actions, and recovery references.
- `bindings/typescript/src/product.ts:340-362` — overloaded `createAuths`
  dispatches between a local configuration and a remote production client by
  checking for an `endpoint` property.
- `bindings/typescript/src/production-client.ts:1-149` — parallel production
  client types and result vocabulary.
- `bindings/typescript/src/production-client.ts:176-306` — production client
  implementation.
- `bindings/typescript/src/workflow.ts:1-2` — re-exports an internal
  orchestrator.
- `bindings/typescript/src/workflow-client.ts:1-61` — bridge over the workflow
  implementation.
- `bindings/typescript/src/internal-sdk.ts:1-25` — second SDK-shaped export
  surface.
- `bindings/typescript/src/workflow/internal/orchestrator.ts:98` and the full
  module — old workflow client implementation.
- `bindings/typescript/src/integrations.ts:115-143` — local development and
  production compositions layered over the old product facade.
- `bindings/typescript/src/profile-kit.ts:1` and
  `bindings/typescript/src/mcp.ts:1` — broad re-export entry points.

### Public and internal Python API layers

- `bindings/python/python/auths/__init__.py:20-48` — root combines local product,
  production client, product errors, and workflow approval types.
- `bindings/python/python/auths/__init__.py:50-124` — public ownership map
  exposes both local and production vocabularies.
- `bindings/python/python/auths/_product.py:8-47` — local product facade depends
  on MCP and workflow internals.
- `bindings/python/python/auths/_product.py:58-158` — generic product names are
  MCP-specific.
- `bindings/python/python/auths/_production_client.py:30-154` — parallel
  production result vocabulary.
- `bindings/python/python/auths/_production_client.py:157-322` — production
  client implementation.
- `bindings/python/python/auths/_workflow.py:1-1799` — older workflow
  implementation still underneath the public package.
- `bindings/python/python/auths/integrations.py:328-393` — development and
  production compositions.

### Rust reference profile contracts and cross-language generic abstractions

- `product/profiles/auths-profile-domains/src/lib.rs:19-132` — deterministic
  Rust `DomainMeaning`, `DomainProfile<T>`, `DomainCommand<T>`,
  canonicalization, and verified-command decoding. Determine which symbols
  belong in the advanced Rust reference tier; do not assume they must be
  deleted merely because the bindings should be smaller.
- `product/profiles/auths-profile-domains/src/lib.rs:271-867` — generic HTTP,
  Git, deployment, supply-chain, and edge action family.
- `product/profiles/auths-profile-domains/src/lib.rs:954-1002` — generic
  reference canonicalizers.
- `product/sdk/auths-sdk/src/lib.rs:26-29` — Rust SDK re-exports generic domain
  profile types.
- `product/integrations/auths-deployment/src/lib.rs:7-83` — production
  integration consumes the generic deployment profile.
- `product/sdk/auths-profile-kit/src/lib.rs:1-120` — generic profile fixture and
  mutation tooling; classify which pieces are neutral test mechanisms and which
  encourage generic shipping semantics.
- `bindings/wasm/auths-proof-wasm/src/lib.rs:37` — imports generic Rust domain
  profiles.
- `bindings/wasm/auths-proof-wasm/src/lib.rs:2802-2928` — exposes generic HTTP,
  Git, deployment, supply-chain, and edge parsers to bindings.
- `bindings/typescript/src/profiles/application/index.ts:37-86` — generic
  profile factory/runtime registration.
- `bindings/typescript/src/profiles/application/index.ts:342-430` — generic
  `ApplicationProfile`.
- `bindings/typescript/src/profiles/application/index.ts:577-583` — public
  `defineProfile` factory.
- `bindings/typescript/src/profiles/domains/index.ts:1-133` — generic domain
  action, command, gateway, authority, receipt, and error families.
- `bindings/typescript/src/profiles/domains/index.ts:136-219` — runtime-generated
  generic profiles.
- `bindings/python/python/auths/_application_profile.py:70-180` — generic
  canonical action, definition, request, and application types.
- `bindings/python/python/auths/_application_profile.py:732-870` — generic
  `ApplicationProfile` and `define_profile`.
- `bindings/python/src/http.rs:15-660` — native Python HTTP binding over the
  generic Rust profile.
- `bindings/python/src/domains.rs:2-107` — native Python edge/domain parser
  binding.

### Qualified production client and duplicated profile registries

- `product/runtime/auths-production-client/src/lib.rs:6-9` — canonical product
  client version and byte limits.
- `product/runtime/auths-production-client/src/lib.rs:129-207` — Rust product
  verbs and qualified profile enumeration.
- `bindings/typescript/src/profiles.ts:4-22` — separately hardcoded TypeScript
  qualified profile list.
- `bindings/typescript/src/production-client.ts:364-379` — second hardcoded
  TypeScript profile list and route mapping.
- `bindings/python/python/auths/profiles/__init__.py:24-45` — separately
  hardcoded Python qualified profile list.
- `bindings/python/python/auths/_production_client.py:375-413` — second
  hardcoded Python profile list and route mapping.
- `bindings/wasm/auths-proof-wasm/src/lib.rs:31-70` — WASM projection of the
  Rust production client contract.

### Error, telemetry, and support-bundle duplication

- `bindings/typescript/src/product-errors.ts:1-18` — known error definitions
  widened to arbitrary strings.
- `bindings/typescript/src/product-errors.ts:111-159` — `auths.support/2`
  support bundle.
- `bindings/typescript/src/observability.ts:3-68` — `auths.telemetry/2` events.
- `bindings/typescript/src/observability.ts:70-110` — a second support bundle
  named `createSupportBundle`, reporting `auths.support/1`.
- `bindings/python/python/auths/_product_errors.py:13` — error codes collapse to
  `str`.
- `bindings/python/python/auths/_product_errors.py:166-199` —
  `auths.support/2` support bundle.
- `bindings/python/python/auths/_observability.py:29-79` — Python telemetry
  model.
- `bindings/python/python/auths/_observability.py:82-109` — incompatible
  `auths.python-support-bundle/1` support bundle.
- `product/runtime/auths-production-client/src/lib.rs:11-127` — Rust-owned
  operational event validation and projection.

### Time, failure translation, and state transitions

- `bindings/typescript/src/profiles/mcp/index.ts:589-623` — direct wall-clock
  acquisition and broad failure replacement during MCP authorization.
- `bindings/typescript/src/profiles/application/index.ts:397-405` and
  `bindings/typescript/src/profiles/application/index.ts:605` — broad exception
  replacement and direct wall-clock acquisition.
- `bindings/python/python/auths/_application_profile.py:158-172` and
  `bindings/python/python/auths/_application_profile.py:744-750` — implicit
  clock and broad exception replacement.
- `bindings/python/python/auths/profiles/_mcp.py:1043-1069` — direct time use in
  receipt preparation.
- `bindings/typescript/src/production-client.ts:269-301` — all transport
  exceptions collapse to one indeterminate result, while malformed response
  cases follow inconsistent throw/result paths.
- `bindings/python/python/auths/_production_client.py:272-303` — same broad
  production transport collapse.
- `bindings/typescript/src/internal/development-store-node.ts:66-167` —
  file-backed development execution and receipt state.
- `bindings/python/python/auths/integrations.py:163-290` — matching Python
  file-backed development state.

### Demo private dependencies and generated browser artifacts

- `demos/cross-company-incident-response/agent-service/auths_incident_agent/incident.py:6-15`
  — imports private approval, application-profile, bootstrap, receipt, and
  workflow modules.
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/execution.py:13-21`
  — imports private error, application-profile, receipt, and runtime modules.
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/sdk.py:9-11`
  — imports private lifecycle, native, and runtime modules.
- `demos/cross-company-incident-response/agent-service/auths_incident_agent/domain_profile.py:8-16`
  — constructs a generic private edge profile.
- `demos/cross-company-incident-response/control-room/src/app.ts:1-3` — current
  public SDK imports used by the browser app.
- Every `.d.ts` file below each of:
  `demos/cross-company-incident-response/control-room/public/vendor/`,
  `public/vendor-v2/`, and `public/vendor-v3/`.
- `bindings/typescript/wasm/auths_proof_wasm.d.ts:1` — current binding
  declaration to compare against the vendored artifact.

### Large and dead source

- `bindings/wasm/auths-proof-wasm/src/lib.rs` — approximately 5,484 lines.
- `core/crates/auths-model/src/lib.rs` — approximately 5,091 lines.
- `core/testkit/auths-testkit/src/lib.rs` — approximately 4,772 lines.
- `core/crates/auths-verifier/src/lib.rs` — approximately 3,466 lines.
- `core/crates/auths-codec/src/decode.rs` — approximately 2,160 lines.
- `bindings/python/python/auths/_workflow.py` — approximately 1,799 lines.
- `bindings/python/python/auths/profiles/_mcp.py` — approximately 1,671 lines.
- `bindings/typescript/src/profiles/application/index.ts` — approximately
  1,169 lines.
- `demos/stripe-subscription-create/src/receipts.rs:108-110` and
  `demos/stripe-subscription-modify/src/receipts.rs:108-110` — explicit dead
  canonicalization helpers.

The inventory must also record every consumer discovered beyond this seed list.
The list above is a starting point, not permission to ignore additional
references.

## Target architecture

### One product API per language

The supported public topology must be:

```text
TypeScript
  @auths-dev/sdk               production client and shared result types
  @auths-dev/sdk/profiles      closed qualified profile selectors/types
  @auths-dev/sdk/verify        offline verification and receipt inspection
  @auths-dev/sdk/identity      standalone identity functionality
  @auths-dev/sdk/integrations  explicitly labelled development compositions
  @auths-dev/sdk/framework     narrow proven ports only
  @auths-dev/sdk/testkit       conformance helpers only

Python
  auths               production client and shared result types
  auths.profiles      closed qualified profile selectors/types
  auths.verify        offline verification and receipt inspection
  auths.identity      standalone identity functionality
  auths.integrations  explicitly labelled development compositions
  auths.framework     narrow proven ports only
  auths.testkit       conformance helpers only
```

The root product API is the remote production client contract currently owned
by Rust `auths-production-client`. The local MCP composition remains available
only as `development.createAuths` / `development.create_auths` under the
integration entry point. It must not define a second root-level `Auths`,
`Authority`, `Receipt`, `ExecutionResult`, or `createAuths` vocabulary.

There must be no overloaded constructor that guesses which product is wanted
by testing whether an object contains an `endpoint` property.

### One source of production profile truth

`product/runtime/auths-production-client/src/lib.rs::QualifiedProfile` owns the
closed production profile set, stable identifiers, and execution routes.

TypeScript and Python must not maintain hand-written duplicate arrays or route
maps. Export the Rust registry through the existing WASM/native boundaries:

```rust
pub struct QualifiedProfileDescriptor {
    pub id: &'static str,
    pub execute_path: &'static str,
}

pub const fn qualified_profiles() -> &'static [QualifiedProfileDescriptor];
```

Add bounded ABI functions that return the descriptor set in deterministic
order. Generate language type declarations from that output at package-build
time and compare the generated files byte-for-byte in CI. Runtime routing must
use the Rust-owned descriptor, not a second language-owned switch.

### Profile-specific product verticals and a broader Rust reference tier

Every shipping effect must be owned by its concrete Rust product integration:

- OpenTofu semantics: `product/integrations/auths-opentofu/`;
- PostgreSQL semantics: `product/integrations/auths-postgresql/`;
- GitHub semantics: `product/integrations/auths-github/`;
- Kubernetes semantics: `product/integrations/auths-kubernetes/`;
- Radicle semantics: `product/integrations/auths-radicle/`;
- Stripe semantics: profile-specific modules under
  `product/integrations/auths-stripe/`;
- records API semantics: `product/integrations/auths-records-api/`.

Deterministic portions of `auths-profile-domains` may remain as an advanced Rust
reference API if they satisfy the reference-tier criteria above. They must not
become a generic product executor or acquire credentials, provider I/O, mutable
state, retry policy, reconciliation, or receipt meaning.

Do not expose generic domain/profile machinery through TypeScript, Python, or
the default Rust product facade merely for symmetry. Do not replace it with
another generic action enum, operation tag, callback registry, or
optional-field carrier.

The current edge incident profile has no qualified closed product vertical. For
this cutover, create one complete profile-specific package only if the demo is
intended to remain a product-shaped reference. Suggested package:

```text
product/integrations/auths-edge-incident/
```

It must own the exact edge action, policy, evaluator, evidence, verified
command, state transition, credential port, provider request, reconciliation,
receipts, stable codes, fixtures, mutation tests, and demo service boundary.
Do not merely move the generic `EdgeAction` into a differently named crate.

If that complete vertical is outside the intended product, remove the custom
edge authorization path from the incident-response demo and rebase the demo on
an already qualified vertical. Do not retain the generic application-profile
framework solely to keep this demo working.

### One operational contract

Rust owns these final prelaunch schemas:

```text
auths.telemetry/1
auths.error/1
auths.support/1
```

Because the project is prelaunch, reset the final telemetry and support schema
numbers to `1`; do not retain `/2` readers or aliases.

`auths.support/1` must contain:

- SDK and runtime identity;
- ABI/contract version;
- semantic subject;
- qualified profiles;
- capabilities;
- a bounded, sorted list of sanitized `auths.error/1` values; and
- an optional bounded, sorted timeline of `auths.telemetry/1` events.

Rust validates and deterministically projects the complete bundle. TypeScript
and Python provide idiomatic wrappers over that projection. Delete the separate
telemetry support-bundle builder, the product-error support-bundle builder, and
the Python-specific support-bundle schema after the single implementation is
in place.

### Explicit time boundary

Stateful product code receives time through an explicit clock port:

```text
Clock.nowSeconds() -> unsigned integer seconds
Clock.nowMilliseconds() -> monotonic or wall value only where named explicitly
```

Requirements:

- The offline core continues to receive evaluation time as explicit input.
- Production server composition owns the trusted wall clock.
- Development composition supplies a system clock by default and permits a
  deterministic test clock.
- Profile canonicalization must not read time.
- Authorization, signing expiry, approval expiry, receipt observation, and
  lifecycle transitions receive a captured timestamp explicitly.
- One operation captures time once per semantic stage; it must not perform
  scattered wall-clock reads that can cross boundaries inconsistently.

### Bounded error causes without secret leakage

Do not preserve raw provider messages, bodies, credentials, proofs, keys,
signatures, or arbitrary exception strings.

Replace broad `catch { ... }` and `except Exception: ...` translation with:

1. typed validation errors for caller input;
2. typed adapter/provider errors with bounded cause categories;
3. typed native contract/ABI errors;
4. explicit cancellation and timeout handling;
5. a final sanitized `unknown` category for unclassified external failures; and
6. programmer/invariant errors that fail loudly in development and tests rather
   than being mislabeled as an authorization denial.

Serialized errors carry only registered family, code, stage, retry, effect,
entered-boundary flags, bounded remediation, references allowed by the
registry, and bounded cause categories.

### Known and unknown stable codes

TypeScript must expose:

```ts
type KnownAuthsErrorCode = /* generated literal union */;
type UnknownAuthsErrorCode = string & { readonly __unknownAuthsCode: unique symbol };
type AuthsErrorCode = KnownAuthsErrorCode | UnknownAuthsErrorCode;
```

Unknown codes may only be constructed by a parser after a registry lookup
fails. Application-authored arbitrary strings must not type-check as an
`AuthsErrorCode`.

Python must expose a generated `KnownAuthsErrorCode` enum or `Literal` union and
an explicit `UnknownAuthsErrorCode` value type. Result objects use that union,
not plain `str`.

Denial and indeterminacy result types in both bindings must use the same code
type. Add exhaustive tests for every generated known code and forward-compatible
tests for one syntactically valid unknown code.

## Implementation plan

## Phase 1: freeze behavioral evidence, not APIs

Before deleting old code:

1. Record the exact existing decisions, canonical action bytes, verified
   commands, provider requests, state transitions, recovery classifications,
   and receipt bytes for every path that will survive.
2. Add differential tests between old and target implementations where a
   direct replacement is being made.
3. Keep those old implementations test-only only for the duration of the
   bounded cutover branch.
4. Delete the oracle when the target implementation and canonical fixtures are
   sufficient. Do not ship it behind a compatibility flag.

Required scenarios include allowed action, widening denial, body mutation,
configuration mismatch, exact replay, reservation conflict, provider failure
before entry, ambiguous failure after entry, restart, resume, reconciliation,
receipt verification, and malformed/oversized input.

## Phase 2: classify and separate the Rust reference profile model

1. Review `auths-profile-domains`, `auths-profile-api`, and
   `auths-profile-kit` symbol by symbol using the Phase 0 inventory.
2. Keep deterministic, bounded canonicalization, verified-command decoding,
   profile contracts, fixtures, and conformance helpers available to advanced
   Rust users when their contracts are coherent.
3. Remove generic Rust profile types from the default `auths-sdk` root facade.
   Prefer a separately imported reference crate or an explicit advanced module
   over root-level re-exports.
4. Keep retained reference crates independently importable and document their
   audience, limits, errors, security properties, and non-goals.
5. Rewrite or delete `product/integrations/auths-deployment/`; its product
   execution path must consume a concrete deployment profile owned by a real
   domain vertical rather than a generic executor over
   `DomainProfile<DeploymentAction>`.
6. Remove generic domain parsing and canonicalization exports from the consumer
   `auths-proof-wasm` package. If advanced cross-language reference access is
   genuinely required, create a separately named reference-only artifact; do
   not enlarge the consumer npm SDK.
7. Remove corresponding Python native generic profile bindings unless replaced
   by a profile-specific ABI owned by a concrete vertical.
8. Retain `auths-profile-api::ActionProfile` as a public Rust reference contract
   when it remains a narrow deterministic port without state, credentials,
   execution, or receipt meaning.
9. Retain `auths-profile-kit` for Rust profile authors when it remains neutral
   fixture and conformance tooling. It does not need a TypeScript or Python
   equivalent.
10. Add tests proving retained reference profile APIs cannot invoke providers,
    acquire credentials, read clocks, or mutate state.
11. Update architecture, compliance, workspace membership, generated snapshots,
    and ownership entries atomically with any move or deletion.

The cutover is complete when generic reference APIs are confined to the
advanced Rust tier and no TypeScript, Python, consumer WASM, default product
facade, or generic effect runtime depends on them. Rust uses of `DomainProfile`
or `DomainCommand` are permitted in explicitly classified reference crates,
conformance tooling, and tests.

## Phase 3: consolidate TypeScript

1. Make `bindings/typescript/src/product.ts` the sole root product
   implementation. Replace its contents with the production-client
   implementation or move the production implementation there.
2. Delete `bindings/typescript/src/production-client.ts` after the move.
3. Remove the local MCP `Authority`, `Receipt`, `Completed`, `Denied`,
   `Indeterminate`, `ExecutionReference`, and `Auths` definitions from the root
   product module.
4. Remove the overloaded `createAuths`. The root `createAuths` accepts only the
   production options contract and returns one `Auths` product client.
5. Keep local MCP development creation only under
   `bindings/typescript/src/integrations.ts::development`.
6. Rename local development-only types with an explicit `DevelopmentMcp...`
   prefix where they must remain accessible from `integrations` or `testkit`.
7. Delete public or package-addressable legacy entry modules:
   `internal-sdk.ts`, `workflow.ts`, `workflow-client.ts`, `profile-kit.ts`, and
   `mcp.ts`.
8. Move any still-required workflow implementation behind
   `src/internal/development/` and expose no public re-export. Then delete it
   completely if the MCP development vertical can use the Rust-owned closed
   profile boundary without the old orchestrator.
9. Delete `src/profiles/application/` and `src/profiles/domains/` after all
   consumers move to profile-specific surfaces.
10. Make `src/profiles.ts` generated from the Rust qualified-profile registry;
    do not hand-code IDs or route paths.
11. Update `src/index.ts` so it exports one product vocabulary, not parallel
    local and `Production...` types. Once the production client is the only
    product, drop the `Production` prefixes:

```ts
createAuths
Auths
Authority
Receipt
RecoveryReference
Completed
Denied
Indeterminate
Recoverable
Rejected
ExecutionResult
VerificationResult
```

12. Keep development imports explicit:

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";
```

No deprecated export aliases are permitted.

## Phase 4: consolidate Python

1. Make `bindings/python/python/auths/_product.py` the sole root product
   implementation by moving the production-client implementation into it.
2. Delete `_production_client.py` after the move.
3. Remove the local MCP aliases and local product result classes from
   `_product.py`.
4. Root `auths.create_auths` accepts only the production client arguments and
   returns one `Auths` type.
5. Keep MCP development creation only under
   `auths.integrations.development.create_auths`.
6. Remove parallel `Production...` public names. Once there is one production
   product, expose the unprefixed names matching TypeScript.
7. Delete `_application_profile.py` and all generic profile factories after
   consumers move to closed verticals.
8. Reduce `_workflow.py` to private development mechanisms only, move those
   mechanisms into an accurately named internal package, and delete the rest.
   If the closed MCP development profile no longer needs it, delete it entirely.
9. Ensure `auths.profiles` is generated from or validated against the Rust
   qualified-profile registry rather than maintaining independent profile IDs.
10. Update `auths.__all__`, lazy ownership maps, type stubs, wheel-content
    checks, and installed-wheel tests atomically.
11. Add a negative installed-wheel test proving that removed private modules
    cannot be imported by a consumer.

No module alias or `sys.modules` compatibility mapping is permitted.

## Phase 5: unify errors, telemetry, and support bundles

1. Extend `auths-production-client` with Rust-owned bounded structures for the
   final telemetry event and support bundle.
2. Add deterministic encode/project functions to the WASM and Python native
   boundaries.
3. Generate the known error-code types from the Rust-owned registry.
4. Change result `code` fields in TypeScript and Python from arbitrary strings
   to the known-or-unknown parsed code type.
5. Merge the useful fields of the two support bundle families into the final
   `auths.support/1` contract.
6. Delete TypeScript `createSupportBundle` from both old modules. Add one
   canonical function in the product error/operations module.
7. Delete Python `_observability.support_bundle` and
   `_product_errors.create_support_bundle`; add one canonical public builder.
8. Add cross-language golden tests proving Rust, TypeScript, and Python emit
   byte-equivalent canonical JSON for the same bounded input.
9. Add negative tests for sensitive attribute names, oversized collections,
   invalid numbers, unknown fields, malformed references, retry/effect
   mismatches, and illegal boundary flags.

## Phase 6: make time and failure handling explicit

1. Define a narrow clock port in the shared framework surface.
2. Thread an explicit captured timestamp into authoring, authorization,
   approval, receipt, lifecycle, and recovery functions.
3. Replace direct `Date.now()` and `time.time()` inside semantic functions.
4. Keep system-clock creation at the outer production/development composition
   boundary only.
5. Add boundary tests for exactly-at-expiry, one second before, one second
   after, clock regression, and a long-running operation crossing expiry.
6. Replace broad transport and profile catches with typed mapping functions.
7. Make malformed successful responses a typed contract failure. Do not return
   `core.malformed-input`, which incorrectly describes caller-controlled core
   input when the actual problem is a malformed remote response.
8. Preserve only bounded cause categories in serialized output.
9. Add tests proving secrets and provider response bodies do not appear in
   errors, telemetry, support bundles, or exception formatting.

## Phase 7: harden development and production state boundaries

The existing file stores remain development-only. Make that true in type names,
exports, diagnostics, and tests.

1. Rename `FileMcpResources` / `_FileMcpResources` to include
   `SingleProcessDevelopment`.
2. Do not expose the file store through `framework` or any production
   composition.
3. Add advisory process locking or reject concurrent opens so two processes
   cannot perform read-modify-replace transitions concurrently.
4. Capture the owner process/session in the development manifest and fail
   closed on concurrent ownership. Because state is disposable, do not migrate
   the old manifest.
5. Add crash tests around reservation, provider entry, receipt persistence, and
   completion cleanup.
6. Production state ports must require compare-and-swap or transactional
   transition methods with expected prior version/stage.
7. Add concurrent tests proving only one claimant can enter the provider for an
   execution, completed state cannot regress, and exact replay returns the
   recorded result without provider re-entry.

Do not present filesystem replacement as a production durability mechanism.

## Phase 8: repair demos

### Cross-company incident response

1. Remove all imports beginning with `auths._` from the agent service.
2. Consume the installed public Python package exactly as a customer would, or
   call the public `auths-node` HTTP contract through `auths.create_auths`.
3. If the edge incident profile is retained, route it through the new complete
   `auths-edge-incident` vertical and add it to the Rust-owned qualified profile
   registry only after its evidence gates pass.
4. Replace the demo's direct generic application profile construction with
   profile-specific request and result types.
5. Run the demo integration test against a built wheel, not the repository
   source tree.

### Browser vendor directory

Perform a destructive prelaunch consolidation:

```text
demos/cross-company-incident-response/control-room/public/vendor/     DELETE
demos/cross-company-incident-response/control-room/public/vendor-v2/  DELETE
demos/cross-company-incident-response/control-room/public/vendor-v3/  DELETE
demos/cross-company-incident-response/control-room/public/vendor-v1/  CREATE
```

`public/vendor-v1/` must contain exactly one current packed TypeScript SDK
browser artifact, including the matching WASM and declarations. It must be
generated from the same revision under test; do not manually copy selected
files from the three old directories.

Implementation requirements:

1. Add one deterministic vendor-generation command owned by the demo.
2. Generate into a temporary directory.
3. Verify package identity, ABI, semantic subject, and artifact digests.
4. Replace `public/vendor-v1/` atomically.
5. Reject unexpected files and source maps containing local absolute paths.
6. Add a check that regenerates the artifact and fails on any diff.
7. Update browser imports, server static paths, tests, and deployment packaging
   to refer only to `/vendor-v1/`.
8. Add a repository check that fails if `public/vendor`, `public/vendor-v2`, or
   `public/vendor-v3` reappears.

The `v1` name identifies the one browser artifact contract, not a compatibility
window. There are no v2/v3 fallback loaders.

### Stripe dead code and copied helpers

1. Delete the unused `_canonical` functions in both subscription receipt
   modules.
2. Search all Stripe demo `.rs` files for identical receipt, persistence, HTTP,
   and test-harness helpers.
3. Classify each duplicate as profile semantic, family semantic, neutral demo
   infrastructure, or accidental duplication.
4. Keep profile semantics in their vertical modules.
5. Extract only neutral demo/test infrastructure whose inputs, outputs, errors,
   limits, and crash behavior are identical.
6. Do not create a generic Stripe operation dispatcher.

## Phase 9: split oversized modules along semantic boundaries

This phase follows behavioral consolidation so file moves do not conceal API or
semantic changes.

Suggested Rust splits:

```text
core/crates/auths-model/src/
  lib.rs                 re-exports only
  identifiers.rs
  authority.rs
  plans.rs
  actions.rs
  evidence.rs
  status.rs
  registries.rs
  context.rs
  limits.rs
  decisions.rs
  portable_result.rs

core/crates/auths-verifier/src/
  lib.rs                 public facade
  decode.rs
  resolve.rs
  control.rs
  authority.rs
  plans.rs
  action_binding.rs
  work.rs
  outcome.rs

bindings/wasm/auths-proof-wasm/src/
  lib.rs                 wasm exports only
  production_client.rs
  verification.rs
  authoring.rs
  identity.rs
  receipts.rs
  errors.rs
  conversion.rs
```

Split `auths-codec/src/decode.rs` by wire object or decoding stage while keeping
one bounded decoder context and one canonical error mapping.

Split testkit fixtures by concern, with a small root registry that makes the
complete corpus discoverable.

TypeScript and Python should mirror public concepts, not Rust file layout. Aim
for modules with one clear responsibility. A shipping implementation file over
roughly 1,500 lines requires an explicit review justification; generated tables
and test corpora are exempt.

Requirements for every split:

- no changed public symbol ownership unless specified elsewhere in this plan;
- no changed canonical bytes;
- no changed stable codes;
- no new dependency direction;
- no duplicate type definitions; and
- focused tests remain adjacent to the owning semantic module.

## Required deletion list

Delete these paths when their consumers have moved:

```text
bindings/typescript/src/production-client.ts
bindings/typescript/src/internal-sdk.ts
bindings/typescript/src/workflow.ts
bindings/typescript/src/workflow-client.ts
bindings/typescript/src/profile-kit.ts
bindings/typescript/src/mcp.ts
bindings/typescript/src/profiles/application/
bindings/typescript/src/profiles/domains/
bindings/python/python/auths/_production_client.py
bindings/python/python/auths/_application_profile.py
demos/cross-company-incident-response/control-room/public/vendor/
demos/cross-company-incident-response/control-room/public/vendor-v2/
demos/cross-company-incident-response/control-room/public/vendor-v3/
```

`product/profiles/auths-profile-domains/` is not an unconditional deletion
target. Keep it, rename it, split it, or delete it according to the Phase 0
inventory and the Rust reference-tier rules. Its generic behavior must not be
re-exported through consumer bindings or used as a generic effect runtime.

`bindings/typescript/src/workflow/`,
`bindings/python/python/auths/_workflow.py`, generic WASM parser exports, and the
Python native generic profile modules are also deletion targets. They may remain
temporarily only while the new closed MCP development implementation is being
completed. They must not remain in the finished cutover merely because moving
their last consumer is inconvenient.

Delete generated declarations, wheel contents, API snapshots, tests, and
packaging entries belonging solely to removed surfaces. Regenerate them from
the final API. Do not hand-edit generated snapshots to resemble success.

## Test and evidence requirements

### Public API tests

- Compile TypeScript customer programs using only each documented entry point.
- Build a wheel and run Python customer programs in an isolated environment.
- Assert removed TypeScript subpaths do not resolve.
- Assert removed Python private modules are absent or inaccessible to installed
  consumers.
- Assert there is one unprefixed product vocabulary and no parallel
  `Production...` vocabulary.
- Assert development MCP examples import through `integrations` and `profiles`
  only.

### Cross-language tests

- Qualified profile IDs and routes match Rust exactly.
- Known error code sets match Rust exactly.
- Unknown error code parsing behaves consistently.
- Telemetry and support-bundle projections are byte-equivalent.
- Production request/response bytes are equivalent.
- Decisions, stages, codes, retry classes, effect states, and receipt
  projections match.

### Profile tests

For every retained concrete profile:

- canonicalization is deterministic and bounded;
- verified-command decoding accepts only verifier-minted actions;
- requested authority cannot widen parent authority;
- provider request is derived only from the verified command;
- required and executed configuration mismatch stops before credentials;
- credentials are acquired only after authorization and durable reservation;
- exact replay does not re-enter the provider;
- ambiguous provider outcomes remain recoverable/reconcilable;
- receipt claims match durable state and observed provider behavior; and
- mutations and boundary-plus-one inputs fail closed.

### State tests

- concurrent reservation has one winner;
- transitions use expected version/stage;
- completed state cannot regress;
- crash before provider entry is safely resumable or not applied;
- crash after provider entry becomes outcome-unknown until reconciliation;
- receipt persistence is idempotent for identical bytes and rejects conflicts;
- old disposable state is rejected rather than migrated.

### Repository hygiene tests

Add automated checks rejecting:

- imports from `auths._` in demos;
- public exports from TypeScript `internal` or `workflow/internal` modules;
- `defineProfile`, `define_profile`, `DomainProfile`, or generic domain parser
  symbols in shipping code;
- duplicate support-bundle schema strings;
- hand-written binding profile route maps;
- the removed vendor directories;
- more than one `public/vendor-v1/` artifact source;
- `#[allow(dead_code)]` in shipping or demo code without a narrow documented
  invariant; and
- direct wall-clock reads in canonicalization, verification, or transition
  functions.

## Sequencing and pull-request boundaries

Use bounded, reviewable changes, but never merge a state where a new public path
ships alongside an old compatibility path.

Recommended sequence:

1. Source inventory and behavioral evidence.
2. Rust-owned qualified-profile/error/telemetry/support registries and binding
   projections.
3. Production API consolidation in TypeScript and Python.
4. Generic domain/profile removal and concrete vertical migrations.
5. Explicit clock and typed failure mapping.
6. Development state ownership/concurrency hardening.
7. Demo public-API migration and `vendor-v1` regeneration.
8. Dead-code removal and neutral demo-helper consolidation.
9. Large-module splits.
10. Final architecture, compliance, packaging, release, and CI closure.

If a temporary branch requires both implementations for differential testing,
keep the old implementation inaccessible to packaging and delete it before the
cutover commit is declared complete.

## Completion checklist

The work is complete only when all of the following are true:

- [ ] The source inventory exists and every seed reference has a disposition.
- [ ] Root TypeScript and Python expose one product client vocabulary.
- [ ] Development MCP composition exists only under the development integration
      namespace.
- [ ] No public legacy workflow or internal SDK entry point remains.
- [ ] Generic domain factories are absent from TypeScript, Python, consumer
      WASM, and default product facades.
- [ ] Any retained broad Rust profile APIs are explicitly classified as
      reference/advanced, deterministic, bounded, effect-free, and documented.
- [ ] Every shipping effect is owned by a concrete profile vertical.
- [ ] Rust is the only source of qualified profile IDs and routes.
- [ ] Rust is the only source of known error, telemetry, and support-bundle
      contracts.
- [ ] TypeScript and Python distinguish known from unknown stable codes.
- [ ] There is one `auths.support/1` builder and one `auths.telemetry/1` model.
- [ ] Semantic stages receive explicit captured time.
- [ ] Broad catches no longer relabel programmer or contract failures as
      authorization outcomes.
- [ ] Development file state rejects concurrent ownership and is unmistakably
      non-production.
- [ ] Production state transitions require atomic compare-and-swap or database
      transactions.
- [ ] No demo imports `auths._...` modules.
- [ ] The incident-response demo uses an installed public artifact or public
      HTTP contract.
- [ ] Only `public/vendor-v1/` exists, generated from the current packed SDK.
- [ ] Removed vendor generations cannot reappear unnoticed.
- [ ] Explicit dead receipt helpers are gone.
- [ ] Large source modules have been split along semantic boundaries or carry a
      written review justification.
- [ ] Canonical fixtures and stable protocol results are unchanged unless an
      independently reviewed protocol change explicitly authorized them.
- [ ] Architecture and compliance inventories match the final source tree.
- [ ] Installed package tests, cross-language tests, demo tests, and the
      authoritative repository CI pass on the exact final revision.

## Explicit non-goals

- Supporting imports or state formats removed by this cutover.
- Preserving old demo URLs or vendor directory names.
- Maintaining both local embedded and remote production clients at the package
  root.
- Providing a universal user-defined effect/execution callback framework in
  product bindings. Deterministic Rust profile contracts and authoring tools are
  allowed in the advanced reference tier.
- Turning demos into sources of production semantics.
- Moving clocks, stores, networks, credentials, or provider execution into the
  offline core.
- Changing protocol V1 merely to simplify binding code.
- Claiming a security audit from conformance or refactoring work.

## Handoff requirements

The implementing agent must report:

1. the completed source inventory;
2. every deleted public or private surface;
3. the final public API topology for Rust, TypeScript, and Python;
4. each profile vertical and its owning package;
5. the canonical owner of profile IDs, routes, stable codes, telemetry, and
   support bundles;
6. proof that demos use installed public artifacts;
7. proof that `vendor-v1` was generated from the final SDK revision;
8. tests run and exact results;
9. any canonical byte, stable-code, or fixture changes, with explicit review
   justification; and
10. any remaining item from this specification, which blocks declaring the
    consolidation complete.
