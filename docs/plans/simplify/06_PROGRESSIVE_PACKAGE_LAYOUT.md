# 06 — Progressive package layout

**Status:** implemented
**Milestones:** B — topology design; D — atomic public cutover
**Design dependencies:** [03](03_CUSTOMER_VOCABULARY.md), the facade design in [05](05_PRIMARY_PRODUCT_WAIST.md), and the disposition inventory in [04](04_PRELAUNCH_API_PRUNING.md)

## Current issue

The existing package layout exposes many peer modules. It communicates
implementation breadth but not where users should start, which components are
independently adoptable, or which APIs are intended only for vertical authors.
Some surfaces describe internal mechanisms such as lifecycle and custody
rather than customer purposes.

## Components of the problem

- root workflow types compete with identity and verification entry points;
- broad profiles sit beside profile-authoring tools without qualification;
- cross-domain mechanisms and effect-domain semantics are mixed;
- diagnostics, inspection, and verification overlap in perceived purpose;
- a narrow import may load broader effect workflow code;
- TypeScript and Python do not present the same public map;
- a framework package can accidentally depend upward on product code;
- `advanced` describes perceived difficulty rather than customer value.

## Product decision

Ship one npm package and one Python wheel with six required purpose-labelled
entry points and one evidence-gated framework entry point across four
conceptual layers:

```text
+---------------- Product ----------------+
| root workflow | identity | verify        |
+--------------------+---------------------+
                     |
+---------------- Vertical ---------------+
| qualified profiles                       |
+--------------------+---------------------+
                     |
+--------------- Mechanisms --------------+
| integrations / compositions              |
+--------------------+---------------------+
                     |
+--------------- Extension ---------------+
| framework | testkit                      |
+------------------------------------------+
```

The root does not re-export secondary entry points. Entry points are not
separate products and do not imply eager loading. Count is not a KPI.

## Exact public entry-point contract

| Layer | TypeScript | Python | Public ownership |
| --- | --- | --- | --- |
| Product | `@auths-dev/sdk` | `auths` | closed create/delegate/execute/resume facade, approval policy, results, receipt, base error |
| Product | `@auths-dev/sdk/identity` | `auths.identity` | decode, resolve, validate, and authenticate identity material without authority setup |
| Product | `@auths-dev/sdk/verify` | `auths.verify` | effect-free proof/receipt verification and inert inspection |
| Vertical | `@auths-dev/sdk/profiles` | `auths.profiles` | independently qualified profile-owned effect verticals; MCP at cutover |
| Mechanism | `@auths-dev/sdk/integrations` | `auths.integrations` | development composition and maintained cross-domain mechanism adapters/configuration |
| Extension | `@auths-dev/sdk/framework` when evidence-gated | `auths.framework` when evidence-gated | only contracts extracted from at least two independent completed verticals |
| Test | `@auths-dev/sdk/testkit` | `auths.testkit` | deterministic fixtures, mechanism conformance, product guards, and profile-owned suite entry points |

No other public TypeScript subpath or Python module is supported after the
Milestone D clean break. Private implementation modules are excluded from
export maps, `__all__`, API snapshots, generated reference, and consumer tests.

At Milestone D, `framework` is handled mechanically:

- if the Spec 12 inventory proves at least one contract against two independent
  completed verticals, publish `framework` with only those proven contracts;
- otherwise omit the subpath/module and keep vertical construction private
  until Milestone F; and
- never publish an empty or aspirational framework merely to reach seven entry
  points.

## Ownership boundaries

### Product

- root owns the normal stateful workflow;
- identity owns independent identity and authentication;
- verify owns deterministic effect-free verification and inspection.

### Qualified verticals

A profile owns its action/plan builders, provider request types, credential
timing, remote result parsing, transition model, reconciliation, receipts, and
domain failures. MCP is the initial cutover profile. Generic `http`, `git`,
`deployment`, `supplyChain`, and `edge` are not maintained base profiles.

GitHub, Radicle, Stripe, Kubernetes, OpenTofu, PostgreSQL, and Records remain
domain packages until each passes the qualification gate in Spec 04. A demo may
own a local profile without creating a base SDK promise.

### Mechanisms

Integrations may provide development composition and adapters for concerns
whose semantics are truly cross-domain: identity/suite resolution, custody,
approval transaction binding, atomic stores, clocks, telemetry, and byte
transport. An integration never defines authorization meaning or a universal
effect-provider result.

### Extension

Framework exposes only lower contracts needed to implement a cross-domain
mechanism or complete custom vertical. Profile-specific provider, result,
reconciliation, and lifecycle contracts live with the profile. Testkit owns
the corresponding split conformance described by Spec 12.

## Dependency rules

- `identity` imports no authority, approval, profile, lifecycle, gateway, or
  execution-receipt code.
- `verify` imports no command mint or provider coordination.
- profiles depend on lower private contracts and Rust/profile operations, not
  maintained integrations or the root facade.
- integrations implement lower mechanism contracts and may compose the root,
  but do not define Auths or profile semantics.
- framework never imports the root facade. Shared types live in a lower private
  contract module consumed by root, framework, profiles, and bindings.
- testkit is never imported by production entry points.
- root coordinates selected profiles and mechanisms but does not export their
  framework contracts or opaque native/session handles.

These rules are checked for both runtime and type-only dependencies.

## Python module contract

All published Python roots are real typed modules or packages:

- explicit `__all__` at every public root;
- complete annotations and a shipped `py.typed` marker;
- mypy and pyright checks against the installed wheel;
- no reliance on `__getattr__` to invent undocumented public members;
- lazy internal loading allowed only when import/API behavior is identical.

## Implementation steps

- [x] Derive one layer/ownership manifest from the reviewed Spec 04 inventory;
  do not create a second hand-maintained API source of truth.
- [x] Move symbols according to that inventory and delete superseded owners.
- [x] Add the lower private contract module and enforce downward dependency
  direction; private shared code does not imply a public framework contract.
- [x] Run the Spec 12 extraction evidence review before deciding whether
  framework is the seventh Milestone D entry point.
- [x] Merge inert inspection into verify and bounded product diagnostics into
  the root owner.
- [x] Expose only qualified profiles; separate custom vertical construction.
- [x] Keep effect-provider and reconciliation contracts profile-owned.
- [x] Add TypeScript dependency/bundle tests and Python import/static-type tests
  against installed artifacts.
- [x] Generate public navigation and capability metadata from authoritative
  export/module inventories.
- [x] Land topology, removals, docs, recipes, package/wheel tests, and snapshots
  atomically in Milestone D.

## Acceptance criteria

- The six required entry points, plus framework only when evidence-gated, are
  the only supported navigation roots.
- Identity and verify consumers initialize no workflow/profile code.
- A root consumer cannot import native commands, session steps, or framework
  mechanism types.
- MCP is the only initial public profile unless another concrete vertical has
  independently passed qualification.
- No framework-to-product dependency exists, and an unproven or empty
  framework is not published.
- TypeScript and Python docs and installed-artifact tests display the same
  purpose map.
- Architecture policy fails on upward dependencies and on generic
  provider/reconciler ownership outside a profile.

## Non-goals

- One physical file per conceptual layer.
- Tree-shaking promises unsupported by the target runtime.
- Combining identity and authority merely to reduce module count.
- Treating every concrete Rust domain crate as a public SDK profile before it
  has bindings and parity evidence.
