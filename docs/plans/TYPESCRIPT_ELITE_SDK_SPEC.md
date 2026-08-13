# TypeScript Elite SDK Product Specification

**Status:** TypeScript implementation complete; promotion gates remain external
**Superseding product-surface target:** [SDK simplification program](simplify/README.md);
its clean-break names replace the implemented baseline when that program lands
**Stable evolution gate:** [Post-1.0 evolution and versioning](simplify/13_POST_1_0_EVOLUTION_AND_VERSIONING.md)
**Baseline:** `670c801` on 2026-08-11
**Lifecycle:** Prelaunch; no external users or production state require
backward compatibility
**Product ambition:** Make `@auths-dev/sdk` credible as the “Stripe for identity
and permissions on the internet” for browser, Node.js, and edge developers
**Semantic owner:** Rust
**Language-product owner:** TypeScript
**Related plans:** [TypeScript and Rust surface parity](TYPESCRIPT_RUST_SURFACE_PARITY_PLAN.md),
[SDK product surface and Python parity](SDK_PRODUCT_SURFACE_AND_PYTHON_PARITY.md),
[semantic responsibility boundaries](AUTHS_SEMANTIC_RESPONSIBILITY_BOUNDARIES.md),
and [identity/Iroh decoupling](IDENTITY_IROH_DECOUPLING_SPEC.md)

## 1. Product decision

The TypeScript SDK will become the reference application experience for
Auths. It must make internet-native identity, authentication, delegation,
authorization, and enforcement feel like one coherent product while preserving
their independence.

“Stripe-like” means:

- a developer reaches a real protected action quickly;
- the normal path is short, typed, difficult to misuse, and production-shaped;
- errors say what happened, where, whether retry is safe, and what to do next;
- test mode, fixtures, inspection, receipts, and observability are first-class;
- browser, Node.js, edge, package, and version behavior is predictable;
- integrations are replaceable ports with conformance suites;
- protocol and cryptographic meaning remain in Rust; and
- the SDK can be adopted one layer at a time without an Auths account or
  hosted service.

It does **not** mean Auths becomes a universal identity provider, key manager,
policy language, transport, hosted control plane, or remote-effect executor.

### 1.1 Prelaunch clean-break policy

This specification governs a prelaunch SDK. Changes target one authoritative
current surface. They must not add or preserve backward-compatibility shims,
deprecated aliases, legacy decoders, migration helpers, dual read/write paths,
old/new runtime switches, version-support windows, or fixtures whose purpose
is to keep superseded SDK/core combinations working. A breaking change removes
the old source, documentation, tests, and exports in the same cutover.

Exact ABI identifiers, semantic identities, package/WASM subject agreement,
current-version fixtures, and fail-closed mismatch tests remain mandatory.
Those prove that the current release is coherent; they are not promises to run
old and new implementations together.

## 2. Customer promise

An application team must be able to choose any stopping point:

```text
+----------------+     +----------------+     +----------------+
| Public data    | --> | Identity       | --> | Authentication |
| bounded bytes  |     | method + state |     | exact message  |
+----------------+     +----------------+     +----------------+
                                                    |
                                                    v
+----------------+     +----------------+     +----------------+
| Effect receipt | <-- | Enforcement    | <-- | Authority      |
| outcome facts  |     | replay/budget  |     | grant + action |
+----------------+     +----------------+     +----------------+
                              ^                     |
                              |                     v
                        +-----+----------+     +----------------+
                        | Closed gateway | <-- | Optional       |
                        | profile-owned  |     | approval       |
                        +----------------+     +----------------+
```

The dependency direction is one-way. Exchanging an identity or authenticating
application bytes must not initialize or expose grants, capabilities,
approvals, policy, lifecycle, or effect runtimes. Adding authority must not
force a change in identity representation. Adding a transport must not change
identity or authorization meaning.

The full-workflow promise is:

> Load trust, attach an agent, delegate narrower authority, authorize an exact
> action or plan locally, and pass only a verifier-minted command into the
> matching gateway—without writing protocol bytes or exporting private keys.

## 3. Elite-bar scorecard

The SDK is not elite because it exports every Rust type. It is elite when the
following customer outcomes are true.

| Dimension | Required outcome |
| --- | --- |
| Time to value | A new TypeScript developer completes identity-only exchange in 5 minutes and a locally protected action in 15 minutes from the maintained quickstarts. |
| Progressive adoption | Identity, authentication, verification, authority, workflow, and runtime are separately importable and tree-shakeable. |
| Semantic safety | TypeScript never defines canonical Auths bytes, identifiers, commitments, attenuation, verdict meaning, or command minting. |
| Type safety | Invalid state transitions are unrepresentable; every public outcome and failure family is exhaustively typed. |
| Production integration | Custody, approval, resolution, status, storage, telemetry, clock, and gateway boundaries have stable ports and executable conformance suites. |
| Operational completeness | Replay, budget, receipt, revocation, rotation, timeout, cancellation, retry, and outcome-unknown behavior are explicit. |
| Debuggability | Every decision has a correlation ID, safe explanation, commitments, bounded work metrics, and structured observability events. |
| Extensibility | A team can add an identity method, signature suite, profile, signer, resolver, or runtime store without forking the SDK or weakening semantics. |
| Portability | The exact packed package works in supported Node.js, browser, worker, bundler, macOS, Linux, and Windows targets. |
| Artifact coherence | The installed package, bundled WASM, exact ABIs, profiles, suites, declarations, and current-version fixtures agree or fail closed. |
| Security evidence | Hostile API tests, fuzzing, cross-language fixtures, dependency policy, provenance, and independent review cover the exact released artifact. |
| Documentation | Every supported layer has one copyable golden path, one failure guide, one production recipe, and one exact current-surface reference. |

Phase 0 must record cold-start, warm-verification, plan-verification, memory,
and compressed-package baselines. Later work may not regress any p95 baseline
by more than 10% or package size by more than 15% without a reviewed exception
and release-note entry. Product SLOs may become stricter after measurement;
they may not silently become weaker.

## 4. UX

### 4.1 Layer 1: identity without permissions

```ts
import { identity } from "@auths-dev/sdk/identity";

const decoded = await identity.decode(receivedPacket);
const validated = await decoded.validate(methodRegistry);
const authenticated = await validated.authenticate({
  message: requestBytes,
  signature,
  suites: signatureRegistry,
});

routeFor(authenticated.identity);
```

This path imports no capability, approval, profile, policy, lifecycle, or
gateway code. Decoded, validated, and authenticated states are different
types. Suite and method selection is explicit and downgrade-resistant.

### 4.2 Layer 2: local verification

```ts
import { loadVerifier } from "@auths-dev/sdk/verify";

const verifier = await loadVerifier();
const decision = verifier.verify(proof, action, trustedContext);

switch (decision.kind) {
  case "authorized":
  case "denied":
  case "indeterminate":
    record(decision);
}
```

Verification is a first-class adoption layer, not an expert-only escape hatch.
An authorized result from `@auths-dev/sdk/verify` remains inert evidence and
cannot be promoted into a gateway command. Safe decision projection also
belongs in `@auths-dev/sdk/verify`; caller-supplied or differential engines
belong in `@auths-dev/sdk/testkit` and can never mint effect-capable results.

### 4.3 Layer 3: full workflow

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const reports = mcp.developmentProvider({
  tools: { publish_report: publishReport },
});
await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({
  action: mcp.callTool({
    name: "publish_report",
    arguments: { month: "august" },
  }),
  provider: reports,
});
```

The SDK must expose immutable authority summaries before a signature or effect,
show the exact attenuation diff for delegation, and keep denial and
indeterminate as ordinary result variants rather than exceptions. The
introductory recipe makes bounded authority visible and omits optional request
correlation. Rust and MCP derive the committed execution and provider
idempotency identities. No public API accepts an arbitrary provider
idempotency key.

### 4.4 Layer 4: custom application profile

```ts
const billing = defineApplicationProfile({
  id: "com.example.billing/1",
  actions: {
    refund: action({ input: refundInput, authority: refundAuthority }),
  },
});

const plan = billing.plan([
  billing.refund({ paymentId, amount: 500n, currency: "usd" }),
]);
const decision = await agent.authorizePlan(plan);
```

Profile code owns application vocabulary, review display, authority projection,
and command decoding. Rust owns the envelope, commitments, proof, verification,
and sealed handoff. There is no global operation tag or generic executor.

### 4.5 Failures and recovery

Construction and provider failures throw stable typed SDK errors. Security
outcomes return three-valued decisions. Every thrown error must include:

- stable family and code;
- safe, redacted message;
- operation and stage;
- correlation ID;
- retry class: `never`, `safe`, `conditional`, or `unknown`;
- effect state: `not-applied`, `possible`, or `applied`;
- whether any signer, approval, state, credential, or provider step was entered;
- optional structured remediation; and
- a causal chain that never exposes credentials, signatures, private material,
  protocol bytes, or unbounded provider bodies.

## 5. Architecture

```text
+------------------------- TypeScript product --------------------------+
| idiomatic types | async coordination | lifetimes | errors | telemetry |
| identity | trust | authority | profiles | workflow | runtime | testkit |
+--------------------------------|--------------------------------------+
                                 v
+-------------------------- Versioned WASM ABI -------------------------+
| bounded values | opaque handles | exact transactions | projections   |
| capability negotiation | stable errors | batch entry points           |
+--------------------------------|--------------------------------------+
                                 v
+---------------------------- Rust waist -------------------------------+
| identity states | canonicalization | authoring | attenuation          |
| approval/plan commitments | verification | profile command decoding  |
| lifecycle/status | replay/budget/receipt state machines               |
+--------------------------------|--------------------------------------+
                                 v
+---------------- Profile verticals + mechanisms -----------------------+
| profiles: provider request/result/reconciliation/receipts/failures     |
| mechanisms: custody | identity | suites | stores | clocks | telemetry  |
+------------------------------------------------------------------------+
```

### 5.1 Ownership rules

- Rust owns every meaning that must agree across languages.
- TypeScript owns scheduling, resource lifetime, ergonomic projections,
  language-native errors, package layout, and proven cross-domain mechanism
  contracts. Effect-domain contracts remain profile-owned.
- The WASM boundary passes bounded typed values or opaque native handles; it
  is not a bag of JSON commands or caller-authored CBOR.
- Normal APIs parse into narrower states. Public `validate(): boolean` gates
  are prohibited for security transitions.
- Effect-capable commands are non-constructible, non-cloneable,
  non-serializable, profile-specific, one-use handles.
- Resolver, signer, approval, clock, state, transport, and provider I/O happens
  outside the deterministic evaluator, but each subsequent side effect
  requires a Rust-accepted bounded result from an opaque profile session.
- Each profile owns credential timing, provider requests/results,
  reconciliation, receipt claims, and domain failures. There is no universal
  provider or effect-state contract.
- Review display is reusable by approval, audit, and diagnostics, but review
  generation does not imply approval.
- Capability and approval are optional layers. Neither participates in
  identity-only or authentication-only workflows.

### 5.2 Rust work that may be required

The SDK program may extend Rust when a cross-language semantic owner is
missing. It must not add TypeScript-only interpretations.

| ID | Rust deliverable | Why the SDK needs it |
| --- | --- | --- |
| CORE-E01 | A binding-oriented workflow kernel with bounded inputs, opaque profile sessions/steps, and stable projections for attach, delegate, execute, resume, inspect, and dispose | Prevents TypeScript and Python orchestration from acquiring semantic or transition meaning |
| CORE-E02 | Credential-shape-agnostic identity states and versioned method/suite descriptors supporting embedded keys, resolver references, rotating sets, threshold, and hybrid credentials | Makes Ed25519, P-256, post-quantum, and future identity systems substitutable without changing the core model |
| CORE-E03 | Versioned trust-bundle, principal-status, grant-status, rotation, compromise, and freshness operations | Enables production lifecycle behavior without online calls inside verification |
| CORE-E04 | One review model plus exact approval-policy/session commitments, independent of whether approval is used | Keeps explainability independent from human or machine approval |
| CORE-E05 | Bounded single and batch verification entry points with cancellation checkpoints and identical per-item semantics | Supports service throughput without a second fast-path meaning |
| CORE-E06 | Stable cross-language error, explanation, inspection, and observability event schemas | Gives applications operationally useful output that cannot drift by language |
| CORE-E07 | Versioned profile manifests, authority projections, command decoders, semantic mutation fixtures, and conformance metadata | Lets SDKs expose more profiles without a global action abstraction |
| CORE-E08 | Commitment-derived execution identity plus profile-owned replay, budget, receipt, retry, and outcome-unknown sessions behind lower storage/I/O mechanisms | Closes the gap between verification and reliable enforcement without a generic effect provider |
| CORE-E09 | Scenario corpus covering positive, negative, mutation, lifecycle, provider-failure, cancellation, concurrency, and downgrade cases | Proves all languages tell the same story, not only encode the same bytes |
| CORE-E10 | Exact runtime contracts for Rust, WASM, TypeScript, and Python artifacts | Makes mismatched artifacts fail clearly instead of drifting silently |

Whichever SDK first requires a CORE-E item owns landing it in Rust with shared
fixtures. The other SDK consumes the same semantic identity; it does not land a
parallel implementation. Semantic changes must pass the repository's freeze,
qualification, and review process. Formal artifacts change only when the
meaning under review actually changes.

## 6. Public APIs and package topology

The elite milestone originally proved the more granular subpaths that existed
at implementation time. The subsequent prelaunch simplification program
supersedes that topology. Implementations must use the authoritative rename map
in [Simplification Spec 04](simplify/04_PRELAUNCH_API_PRUNING.md) and the packed
artifact contract in [Simplification Spec 10](simplify/10_FRICTIONLESS_PACKAGING.md).

The final public topology is one installed npm package with six required entry
points and one evidence-gated framework entry point:

```text
@auths-dev/sdk                    create/delegate/execute/resume product facade
@auths-dev/sdk/identity           standalone identity and authentication
@auths-dev/sdk/verify             proof/receipt verification and inert inspection
@auths-dev/sdk/profiles           qualified profile-owned verticals; MCP at cutover
@auths-dev/sdk/integrations       development composition and mechanism adapters
@auths-dev/sdk/framework          only contracts proven by two independent verticals; otherwise absent
@auths-dev/sdk/testkit            deterministic fixtures, mechanism suites, profile suites
```

`trust`, `authority`, `approvals`, `custody`, `runtime`, `lifecycle`,
`observability`, `profile-kit`, `inspection`, `diagnostics`, and `mcp` cease to
be package subpaths. Product inputs move to the root, inert inspection moves to
`verify`, maintained profiles move to `profiles`, maintained adapters move to
`integrations`, evidence-proven extension ports move to `framework`, and
differential engines move to `testkit`. No alias or deprecation export
preserves the old paths.

Every retained entry point has an explicit export allowlist, independent type
and runtime tests, a package-size budget, and documentation that states what it
does **not** initialize. The root does not re-export the other entry points.
Internal WASM selection, handle registries, command minting, raw resources, and
test credentials remain unreachable.

The base package owns only proven cross-domain mechanism contracts and
Auths-owned conformance cases, not every integration. Effect-provider,
credential timing, result, reconciliation, receipt, and domain failure
contracts remain profile-owned. MCP is the initial qualified public profile;
generic HTTP, Git, deployment, supply-chain, and edge families are removed or
moved to demo ownership. Concrete domains join `profiles` only after their own
Rust sessions, TypeScript/Python bindings, and profile conformance pass.
The exact root allowlist and framework publication gate are normative in
[Simplification Spec 04](simplify/04_PRELAUNCH_API_PRUNING.md). An empty or
aspirational framework is not published merely to preserve an entry-point
count.

## 7. Delivery program

Checkboxes record repository-local TypeScript delivery against this branch.
They do not manufacture independent review, publication authorization, or
Python parity. Those gates are called out explicitly in TS-E10 and the final
qualification table.

Items below that mention the former `inspection`, `diagnostics`, or other
granular subpaths are historical milestone evidence. Section 6 and the linked
simplification specifications govern the next clean-break public surface.
Their checked state does not authorize retaining generic gateway contracts,
broad profiles, public idempotency keys, or universal adapter certification.

### TS-E0 — Freeze the elite contract and measurements

- [x] Inventory every public export, package subpath, supported runtime, and
      product claim against the exact installed tarball.
- [x] Record golden-path time, cold start, warm verification, plan throughput,
      memory, bundle size, and installation baselines.
- [x] Publish the error taxonomy, support matrix, prelaunch clean-break policy,
      threat model, and exact non-goals.
- [x] Turn the scorecard in section 3 into CI-readable capability metadata.
- [x] Create one shared Rust/TypeScript/Python customer-journey matrix.

**Exit:** scope, performance, artifact coherence, and claims cannot drift without a
reviewed artifact change.

### TS-E1 — Make the first 15 minutes exceptional

- [x] Provide one identity-only quickstart and one complete protected-action
      quickstart, each executable from a packed package.
- [x] Reduce normal setup to typed configuration with no raw protocol values,
      copied constants, manual hashing, or internal imports.
- [x] Replace the `advanced` catch-all with the direct `verify`, `inspection`,
      and `diagnostics` subpaths, deleting the superseded export and every
      stale reference in the same cutover.
- [x] Add a safe development mode with unmistakably non-production signers,
      approvals, clocks, stores, and gateways under `testkit`.
- [x] Add a diagnostic report that checks runtime, WASM subject, adapters,
      trust configuration, profile versions, and the exact runtime contract.
- [x] Test every documented snippet in CI.

**Exit:** an unfamiliar developer can complete both quickstarts without reading
the protocol specification.

### TS-E2 — Finish the layered identity product

- [x] Bind CORE-E02 and expose decoded, validated, resolved, and authenticated
      states without importing authority.
- [x] Ship raw-key/Ed25519 and one structurally different reference path such
      as P-256 or resolver-backed identity to prove substitution.
- [x] Add method and suite registries with explicit versions, purposes, exact
      selection, and downgrade rejection.
- [x] Add rotation, historical verification, composite credential, threshold,
      and hybrid/post-quantum conformance fixtures without promising adapters
      the project does not maintain.
- [x] Preserve an explicit validated-identity-to-principal bridge; never grant
      authority automatically after authentication.

**Exit:** identity is a credible standalone product and authority can consume
it through one explicit, lossless transition.

### TS-E3 — Productize trust, lifecycle, and evidence

- [x] Bind CORE-E03 as typed trust bundles, status snapshots, rotation facts,
      compromise facts, assurance requirements, and freshness policies.
- [x] Add resolver and evidence-source ports with timeout, cancellation, size,
      provenance, cache, redirect, and SSRF constraints.
- [x] Make missing, stale, conflicting, and unavailable evidence resolve to
      stable denied or indeterminate outcomes.
- [x] Add exportable offline evidence bundles and deterministic conflict tests.
- [x] Provide lifecycle recipes for delegation withdrawal, key rotation,
      compromise, and clean prelaunch policy/profile replacement.

**Exit:** production teams can reason about who was trusted, at what time, from
which source, under which freshness and assurance rules.

### TS-E4 — Perfect authoring, approval, and delegation

- [x] Consolidate root authoring, attach, delegation, semantic diff, signing,
      and deterministic disposal over CORE-E01.
- [x] Make review independently available before approval and reusable by
      audit/diagnostic UIs.
- [x] Support no approval, grant-only, every-action, risk-gated, threshold,
      and exact plan-once policies through one committed model.
- [x] Prove a child cannot widen permission, resource, audience, validity,
      budget, status, assurance, profile, extension, or delegation depth.
- [x] Make provider timeout, rejection, cancellation, duplicate response,
      mismatched transaction, and unknown outcome explicit and effect-safe.

**Exit:** the flagship “delegation only gets narrower” promise is both easy to
use and adversarially demonstrated.

### TS-E5 — Complete profiles and plans

- [x] Promote the maintained MCP, HTTP, Git, deployment, supply-chain, and edge
      profiles to the same quality bar or explicitly exclude them from V1.
- [x] Require distinct action, authority, command, gateway, receipt, and error
      types for each maintained profile.
- [x] Complete application profile-kit schemas, authority narrowing, review,
      exact plans, mutation testing, gateway conformance, and exact-version
      rejection.
- [x] Support ordered plans plus Rust-owned all-of, any-of, and threshold proof
      plans without conflating authorization atomicity with provider atomicity.
- [x] Add cross-profile, cross-version, reordered, duplicated, omitted,
      appended, and substituted command attacks.

**Exit:** built-in and customer-owned domains feel consistent without sharing a
generic executor or losing domain meaning.

### TS-E6 — Close enforcement and operational state

- [x] Bind CORE-E08 through challenge, replay, budget, receipt, store, and
      closed-executor ports.
- [x] Define exhaustive pre-effect, reserved, executing, executed, failed,
      duplicate, exhausted, unavailable, and outcome-unknown states.
- [x] Require idempotency and reconciliation contracts at every effectful
      gateway; never claim remote exactly-once or atomic execution.
- [x] Provide an in-memory test implementation and at least one separately
      packaged durable reference store.
- [x] Prove denied, indeterminate, forged, mismatched, expired, replayed, and
      exhausted commands cause zero gateway calls and no state mutation.

**Exit:** authorization can be operated safely under retries, races, crashes,
and ambiguous provider outcomes.

### TS-E7 — Make integration an ecosystem, not a bottleneck

- [x] Version signer, approval, resolver, status, clock, store, telemetry,
      transport, and gateway contracts independently of implementations.
- [x] Publish executable adapter conformance suites and certification metadata.
- [x] Maintain only a small reference set proving browser, server, workload,
      and durable-state substitution.
- [x] Add copyable recipes for Web Crypto/WebAuthn, one remote KMS/HSM family,
      one resolver family, and one durable store without importing them into
      the base SDK.
- [x] Document how third parties publish and qualify adapters, including
      support ownership and security-claim boundaries.

**Exit:** Auths can grow through external adapters without allowing adapters to
reinterpret protocol or profile semantics.

### TS-E8 — Add world-class errors, inspection, and observability

- [x] Bind CORE-E06 and expose stable errors, explanations, commitments,
      authority diffs, work metrics, safe logs, and correlation fields.
- [x] Publish OpenTelemetry-compatible hooks with no required exporter and no
      secret or raw-proof attributes.
- [x] Add decision timelines that distinguish acquisition, construction,
      approval, signing, verification, reservation, execution, and receipt.
- [x] Add redaction tests against keys, credentials, signatures, provider
      bodies, proof bytes, and high-cardinality application data.
- [x] Build a deterministic support-bundle format that is safe to attach to an
      issue and cannot mint or replay authority.

**Exit:** a production operator can diagnose a decision without reproducing it
from sensitive inputs or learning Auths internals.

### TS-E9 — Scale without a semantic fast path

- [x] Bind CORE-E05 for bounded batch verification and plan evaluation.
- [x] Cache only immutable, commitment-addressed artifacts with explicit
      invalidation and memory bounds.
- [x] Support worker-friendly initialization, cancellation, backpressure, and
      repeated load/disposal.
- [x] Benchmark Node, the supported Chromium browser and worker, and exact
      packed direct-ESM consumers against Phase 0 budgets. Bundler-specific
      support remains outside the V1 support matrix.
- [x] Prove batch and cached results are identical to independent single-item
      evaluation across the scenario corpus.

**Exit:** service-scale usage is faster to operate, never semantically weaker.

### TS-E10 — Make releases boring

- [x] Enforce CORE-E10 exact ABI identities, semantic identities, profile
      versions, and package/WASM subject matching.
- [x] Test the packed package on the full supported runtime, OS, browser,
      worker, module, and bundler matrix.
- [x] Add current-package/current-core agreement fixtures and fail-closed
      mismatched-artifact tests; support no cross-version runtime window.
- [x] Generate exact API, package-content, SBOM, provenance, license, audit,
      and claim manifests from one revision.
- [x] Complete repository fuzzing, hostile package-boundary tests, dependency
      policy, and clean packed-consumer qualification.
- [ ] Complete independent external security and consumer review against the
      exact release candidate.
- [x] Remove superseded public surfaces and semantic versions directly, with
      automated stale-reference and exact-artifact checks in the same change.

**Exit:** the released artifact, documentation, evidence, and support claim all
describe the same bits.

## 8. Required test matrix

Every public workflow must cover:

- authorized, denied, and indeterminate outcomes;
- malformed, oversized, non-canonical, unsupported-version, and unknown-suite
  inputs;
- identity method/suite mismatch, downgrade, rotation, compromise, and stale
  resolution;
- authority widening in every attenuation dimension;
- command construction, copying, cloning, serialization, reflection,
  mutation, substitution, replay, expiry, and double consumption;
- signer, approval, resolver, store, clock, and gateway failures before,
  during, after, and at cancellation;
- plan reordering, duplication, omission, append, partial failure, retry, and
  outcome unknown;
- concurrent state claims and budget exhaustion;
- source, packed-package, browser, worker, and clean external-consumer paths;
- TypeScript compile-time misuse using exact public declarations; and
- Rust/TypeScript/Python differential scenarios from CORE-E09.

## 9. Explicit non-goals

This specification does not authorize:

- a mandatory Auths cloud, account, network call, registry, wallet, or daemon;
- coupling identity exchange to grants, capabilities, approvals, or profiles;
- owning every identity, signature, custody, transport, resolver, store, or
  framework adapter;
- JavaScript implementations of Auths canonicalization or verification;
- a generic policy language, generic action envelope, or generic executor;
- private-key export or persistence in the base SDK;
- silent algorithm, identity-method, profile, or policy fallback;
- backward-compatibility shims, deprecated aliases, legacy readers, migration
  helpers, dual paths, version-support windows, or old/new runtime fixtures;
- automatic execution merely because verification authorized an action;
- collapsing indeterminate into denied or authorized;
- hidden retries of approval, signing, or provider effects;
- claims of remote atomicity, exactly-once effects, instantaneous revocation,
  or current global status for offline decisions; or
- stable-V1, production, certification, or reviewed claims before their exact
  evidence gates pass.

## 10. Definition of done

The TypeScript SDK earns the elite label only when an external team can, using
the exact installed package and public documentation:

1. use identity and message authentication without authority dependencies;
2. substitute a method, suite, signer, approval provider, resolver, store, and
   gateway through conformance-tested ports;
3. attach an agent and delegate strictly narrower authority with an exact,
   human-readable diff;
4. authorize an action and plan locally with three-valued results;
5. execute only a matching, verifier-minted, one-use profile command;
6. withdraw a delegation, rotate identity evidence, refresh trust, reject
   replay, consume budget, and produce a receipt;
7. recover safely from timeout, cancellation, retry, concurrency, and
   outcome-unknown conditions;
8. diagnose the decision through stable, redacted operational evidence;
9. add a custom profile without inventing protocol bytes or command branding;
10. obtain identical semantic results from Rust, TypeScript, and Python;
11. run on the claimed platform matrix within frozen performance budgets; and
12. map every public product claim to exact-version CI and review evidence.

Until all twelve are true, the repository may describe progress toward the
elite product, but it must not use the completed claim.

### 10.1 Qualification state

| Gate | State | Evidence or owner |
| --- | --- | --- |
| TypeScript repository implementation | Complete | `bindings/typescript/sdk-capability.json` and its CI-readable evidence paths |
| Exact packed Node/browser/worker qualification | Complete locally and enforced in CI | `.github/workflows/typescript-sdk.yml` |
| Rust/TypeScript semantic parity | Complete | Shared 88-scenario production-registry corpus plus the 102-scenario repository ABI corpus |
| Python consumption of CORE-E09 | Follow-up | Python SDK plan; intentionally outside this TypeScript-only branch |
| Independent external review | Pending | Must review the exact release candidate; cannot be self-attested by implementation code |
| Stable-V1 publication/promotion | Blocked | Release owner authorization after Python parity and independent review |

The implementation may be described as the completed TypeScript elite surface.
The broader cross-SDK product must not claim all twelve definition-of-done
outcomes until the two pending external gates close.
