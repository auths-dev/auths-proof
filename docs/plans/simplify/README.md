# Auths SDK simplification program

**Status:** proposed executable program
**Lifecycle:** prelaunch clean break
**Scope:** Rust semantic waist, TypeScript SDK, Python SDK, packaging, examples,
and extension ecosystem
**Primary outcome:** make the safe path the shortest path without moving Auths
meaning out of Rust

## The current issue

Auths has a strong semantic architecture but still exposes too much of that
architecture as the product experience. A developer can encounter identity,
trust, grants, profiles, plans, approvals, custody, lifecycle state, runtime
stores, gateways, receipts, diagnostics, and native boundaries before
performing one protected effect.

Those concepts are not all product concepts. Most are protocol or framework
mechanics that should remain behind a small product waist. The simplification
program establishes that waist while retaining independently usable identity,
authentication, verification, and transport components.

```text
Application developer
        |
        |  identity / authority / action / optional approval
        v
+-------------------------------------------------------+
| Auths product waist                                   |
| create | delegate | execute | resume | verify         |
+-----------------------------+-------------------------+
                              |
                              | opaque profile session
                              v
+-------------------------------------------------------+
| Profile-owned vertical                               |
| provider gateway | credential timing | transitions    |
| reconciliation | receipts | domain failures           |
+-----------------------------+-------------------------+
                              |
                              | opaque handles / bounded results
                              v
+-------------------------------------------------------+
| Rust semantic waist                                   |
| canonicalization | attenuation | authorization        |
| commitments | lifecycle | profile state | receipts    |
+-------------------------------------------------------+

Cross-domain mechanisms sit beside the verticals: signer and custody mechanics,
atomic stores, clocks, telemetry, byte transports, identity/suite resolution,
and exact approval-transaction binding. They may be shared only when their
semantics are truly independent of the effect domain.
```

The governing boundary is
[`PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`](../../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
There is no universal effect-provider callback, provider result type,
reconciler, or provider certification contract. Each maintained profile owns
the semantics of its effect domain. TypeScript and Python perform asynchronous
I/O, but Rust accepts each bounded result and controls whether the next side
effect is available.

## Target experience

A new developer should be able to describe the product in one sentence:

> Auths lets software prove exactly what it may do, execute through a closed
> profile, and leave a signed receipt.

The development path deliberately supplies safe local defaults:

```typescript
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

const reports = mcp.developmentProvider({
  tools: { publish_report: publishReport },
});
await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({ action, provider: reports });
```

```python
from auths.integrations import development
from auths.profiles import mcp

reports = mcp.development_provider(
    tools={"publish_report": publish_report},
)
async with development.create_auths(
    authority=mcp.allow_tools(["publish_report"]),
) as auths:
    result = await auths.execute(action=action, provider=reports)
```

The factory owns the development actor, signer, local trust, runtime store,
no-approval policy, and receipt sink. The caller supplies visibly bounded
profile authority. Production composition is explicit and is a later
integration concern.

The beginner journey uses five core security nouns: `Identity`, `Authority`,
`Action`, `Approval`, and `Receipt`. They are introduced progressively rather
than forced into Recipe 3. That recipe separately budgets three security
concepts, two MCP/domain concepts, and one development setup decision. `Result`
is a normal return value, not a security concept.

Public callers may supply an application `requestId`. They may not choose the
provider idempotency identity. Rust and the selected profile derive the
internal/provider idempotency identity from the committed request and profile
state.

## Product outcomes

- identity-only quickstart in five minutes;
- one protected development effect in fifteen minutes;
- no Rust toolchain for installed TypeScript or Python consumers;
- no more than three primary operations in the stateful root workflow;
- Recipe 3 stays within its separately measured security, domain, setup, and
  required-input budgets;
- equivalent TypeScript and Python journeys, outcomes, and stable errors;
- framework imports absent from root workflows and introductory docs;
- independently usable identity, verification, and transport components;
- profile-owned failure and reconciliation behavior rather than a generic
  lowest-common-denominator provider model.

## Six atomic milestones and one launch gate

The numbered files are design areas, not a twelve-PR queue. Their work lands in
the following milestone order. A milestone may contain several internal
commits, but a public API must not enter a half-migrated state.

### Milestone A — Evidence foundation

- [x] Aggregate the current experience evidence described by
  [01 — Current complexity baseline](01_CURRENT_COMPLEXITY_BASELINE.md).
- [x] Land the invariant and parity gates in
  [02 — Security and parity guardrails](02_SECURITY_AND_PARITY_GUARDRAILS.md).
- [x] Establish the cross-domain error envelope, core codes, and
  profile-code registration schema from
  [08 — Errors, recovery, and diagnostics](08_ERRORS_RECOVERY_AND_DIAGNOSTICS.md).

Exit: current complexity is measurable, Rust ownership is mechanically guarded,
and profiles have one registry schema without Milestone A inventing MCP or
ordered-plan codes.

### Milestone B — Contract design

- [x] Validate the five-noun vocabulary mechanically and prototype it in the
  first four journeys from
  [03 — Customer vocabulary](03_CUSTOMER_VOCABULARY.md). The moderated cohort
  remains the final-name freeze gate.
- [x] Design the root facade and opaque profile session from
  [05 — Primary product waist](05_PRIMARY_PRODUCT_WAIST.md).
- [ ] Design the six-required-plus-evidence-gated-framework topology in
  [06 — Progressive package layout](06_PROGRESSIVE_PACKAGE_LAYOUT.md).
- [ ] Complete the Spec 12 contract inventory without prematurely publishing
  candidate mechanisms.
- [ ] Prototype the user journeys in
  [11 — Outcome-first recipes](11_OUTCOME_FIRST_RECIPES.md) before freezing API
  names.

Exit: executable TypeScript and Python prototypes prove the vocabulary and
shape, but no old public API has been deleted yet.

### Milestone C — One vertical proof

- [x] Implement one maintained profile end to end using
  [07 — Closed execution orchestration](07_CLOSED_EXECUTION_ORCHESTRATION.md).
- [ ] Implement the explicit development composition from Phase A of
  [09 — Reference stacks and defaults](09_REFERENCE_STACKS_AND_DEFAULTS.md).
- [x] Prove Rust-gated sequencing, commitment-derived idempotency, failure
  classification, resumption, reconciliation, and receipts in TypeScript and
  Python.
- [x] Register MCP's actual stages, error codes, effect classifications, and
  recovery actions through the schema established in Milestone A.

The initial public cutover profile is MCP because it is already the maintained
reference integration. Concrete GitHub, Radicle, Stripe, Kubernetes, OpenTofu,
PostgreSQL, and Records verticals remain domain packages until each is
separately bound and qualified.

Exit: one real effect vertical proves the architecture before the public
surface is pruned.

### Milestone D — Atomic public cutover

- [ ] Apply [04 — Prelaunch API pruning](04_PRELAUNCH_API_PRUNING.md),
  [05 — Primary product waist](05_PRIMARY_PRODUCT_WAIST.md),
  [06 — Progressive package layout](06_PROGRESSIVE_PACKAGE_LAYOUT.md), and
  [10 — Frictionless packaging](10_FRICTIONLESS_PACKAGING.md) as one public
  cutover.
- [ ] Publish the first four installed-artifact recipes from
  [11 — Outcome-first recipes](11_OUTCOME_FIRST_RECIPES.md).
- [ ] Pass the Recipe 3 unfamiliar-developer gate: at least four of five
  Auths-new developers finish unaided in fifteen minutes on a clean machine.
- [ ] Delete replaced paths, tests, and docs in the same pull request. Add no
  aliases, deprecations, shims, or migration machinery.
- [ ] Apply Spec 12's two-independent-vertical evidence gate and publish or
  omit `/framework` explicitly.

Exit: the unfamiliar-developer gate passes, TypeScript and Python expose the same six required surfaces plus
`framework` only if its extraction evidence passes; external consumers cannot
import removed or unproven paths.

### Milestone E — Ordered plans and recovery

- [ ] Extend the vertical model to ordered plans without exposing partial
  effect-capable commands.
- [ ] Finish the decision, recovery, and inert diagnostic projections from
  [08 — Errors, recovery, and diagnostics](08_ERRORS_RECOVERY_AND_DIAGNOSTICS.md).
- [ ] Register ordered-plan, interruption, resume, and reconciliation codes
  only after those transitions exist.
- [ ] Add the explicit file-backed recoverable development composition from
  Spec 09 and prove resume across a process restart.
- [ ] Publish the fifth recipe and cross-language receipt/recovery fixtures.

Exit: interruption, ambiguous remote outcomes, resumption, and ordered effects
remain fail-closed and have equivalent TypeScript/Python behavior.

### Milestone F — Ecosystem and production integrations

- [ ] Bind and qualify one concrete vertical that differs materially from MCP
  in provider request, credentials, outcomes, and reconciliation; use Records
  as the measured reference vertical.
- [ ] Pass or explicitly fail the Spec 07 authoring-cost gates: MCP application
  specialization within eight active hours and Records qualification within
  five active engineering days.
- [ ] Extract only proven cross-domain mechanism contracts using
  [12 — Adapter conformance kit](12_ADAPTER_CONFORMANCE_KIT.md).
- [ ] Add profile-owned conformance suites for each maintained effect domain.
- [ ] Build the production reference compositions in Phase B of
  [09 — Reference stacks and defaults](09_REFERENCE_STACKS_AND_DEFAULTS.md).

Exit: at least two independent verticals justify every extracted mechanism;
custom mechanism authors can test shared contracts, profile authors can test
their own domain semantics, and production references do not distort the
development quickstart or delay the public cutover.

### Launch gate — Stable evolution contract

- [ ] Complete [13 — Post-1.0 evolution and versioning](13_POST_1_0_EVOLUTION_AND_VERSIONING.md).
- [ ] Prove patch, minor, major, profile-successor, error-retirement, persisted
  evidence, and emergency-security release behavior across Rust, TypeScript,
  and Python.
- [ ] Block every `1.0.0` publication until the stability acceptance criteria
  pass.

Exit: the prelaunch clean-break rule has an explicit end, and every stable API,
semantic subject, profile, error, receipt/state schema, ABI, and conformance
manifest has a governed evolution path.

## Public package topology

There is one npm package and one Python wheel. Entry points are purpose labels,
not separately installed products. Six are required at Milestone D;
`framework` is published only after Spec 12's extraction gate passes.

| Purpose | TypeScript | Python |
| --- | --- | --- |
| Integrated workflow | `@auths-dev/sdk` | `auths` |
| Identity/authentication | `@auths-dev/sdk/identity` | `auths.identity` |
| Effect-free verification | `@auths-dev/sdk/verify` | `auths.verify` |
| Qualified effect verticals | `@auths-dev/sdk/profiles` | `auths.profiles` |
| Mechanism adapters and compositions | `@auths-dev/sdk/integrations` | `auths.integrations` |
| Evidence-gated custom vertical construction | `@auths-dev/sdk/framework` | `auths.framework` |
| Deterministic fixtures/conformance | `@auths-dev/sdk/testkit` | `auths.testkit` |

`profiles` initially exposes MCP. It does not preserve the current broad
`http`, `git`, `deployment`, `supplyChain`, or `edge` families as maintained
public profiles. Demo-specific edge behavior remains demo-owned. Concrete
domain packages join `profiles` only after profile-specific qualification.

`framework` must not depend upward on the root product facade. It is absent,
not empty, when no contract has two-independent-vertical evidence. Shared contract
types live in a lower internal contract module consumed by both. `framework`
may expose cross-domain mechanisms and tools for building a custom vertical,
but never a universal provider gateway, result canonicalizer, reconciler, or
effect state machine.

Python surfaces are real typed modules or packages with explicit `__all__`, a
shipped `py.typed`, static-type checks, and installed-wheel tests. Lazy loading
is an internal implementation choice, not a substitute for a defined public
module topology.

## Profile and domain disposition gate

Before Milestone D, [Spec 04](04_PRELAUNCH_API_PRUNING.md) must inventory every
current public profile and Rust domain package and record one disposition:

- retain as the qualified MCP cutover profile;
- retain as an internal/domain package pending independent qualification;
- move to a demo-owned integration; or
- delete because a broad generic family conflicts with the target boundary.

The number of entry points and profiles is not a KPI. Every retained surface
must have one owner, one purpose, and evidence that it improves a maintained
journey.

## Program rules

- This is prelaunch. Remove superseded code, exports, tests, documentation, and
  fixtures in the same atomic cutover. Do not add compatibility machinery
  before 1.0. After 1.0, Spec 13 governs compatibility and retirement.
- Rust owns every meaning that must agree across languages.
- TypeScript and Python may perform I/O idiomatically, but an opaque
  profile-owned Rust session decides whether the next side effect is available.
- A shared FFI carrier may transport typed next-step variants; it may not
  impose one universal domain state machine.
- Parse into narrower types. Do not add boolean validation gates for security
  state transitions.
- No public workflow accepts an arbitrary provider idempotency key.
- Identity, authentication, verification, and transport remain independently
  usable without capability or approval setup.
- Check a milestone only when its code, installed-artifact tests, parity
  fixtures, documentation, and evidence pass on the same revision.

## Zero-context implementation prompt

```text
Implement docs/plans/simplify/README.md milestone by milestone.

Before changing code, read the root AGENTS.md, this README, the specifications
listed under the current milestone, and
docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md. Inspect the
existing Rust, TypeScript, and Python implementations named by those specs.

Treat the repository as prelaunch. Delete replaced APIs instead of creating
aliases, deprecations, shims, dual paths, or migration support. Preserve Rust
as the semantic owner. TypeScript and Python may execute asynchronous I/O, but
must receive each next side-effect step from an opaque profile-owned Rust
session after Rust accepts the previous bounded result.

For each milestone:
1. work through every unchecked requirement and acceptance criterion;
2. record evidence against existing authoritative snapshots and fixtures;
3. implement Rust, TypeScript, Python, docs, fixtures, and CI as required;
4. run installed-package/wheel tests plus repository-required gates;
5. update evidence links and check only requirements proven on this revision;
6. commit in coherent internal slices; and
7. preserve an atomic public cutover at Milestone D.

Do not stop at interfaces, scaffolding, TODOs, or one-language support. Do not
invent a generic provider abstraction where the profile/domain plan assigns
semantics to a vertical. Do not reinterpret a failing security invariant as a
documentation problem.

Before publishing any 1.0 artifact, complete Spec 13 and run its mock release
matrix. Prelaunch deletion rules do not apply after the stable cut.
```

## Program completion

The program is complete when clean external TypeScript and Python consumers
can complete identity-only, verification-only, single-effect,
delegated-effect, ordered-plan, recovery, and receipt-verification journeys;
both SDKs pass the same semantic and recovery fixtures; MCP is qualified as the
cutover profile; later concrete domains expose their own qualification; and
custom mechanism authors can test cross-domain contracts without importing
internal modules, and the stable evolution launch gate passes.
