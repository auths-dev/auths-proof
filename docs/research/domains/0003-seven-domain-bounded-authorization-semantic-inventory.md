# Seven-domain bounded-authorization semantic inventory

## Status

Closed comparison report for Milestone 3 contract design.

Baseline revision: `d73b160`

Evidence inventory: `bounded-domains.toml`

Migration-oracle audit:
`docs/research/domains/0002-seven-domain-bounded-authorization-readiness-audit.md`

This report compares GitHub, Kubernetes, OpenTofu, PostgreSQL, Radicle, the
records API, and Stripe. It classifies common-looking behavior before any
shared bounded-policy production implementation is introduced.

## Method

The comparison used:

- each domain's exact action, policy, evidence, configuration, evaluator,
  decision, claim/reservation, verified command, gateway, receipt, and demo;
- the generator-owned fixtures under `product/fixtures/v1`;
- the scenario and source anchors in `bounded-domains.toml`;
- live-effect, concurrency, crash, replay, and reconciliation tests;
- architecture and compliance inventories.

Similarity of control flow was not treated as semantic equivalence. A
candidate is approved only to the smallest contract supported by the seven
verticals.

## Domain witnesses

| Domain | Exact effect | Distinguishing witness |
| --- | --- | --- |
| GitHub | Publish one exact branch and draft pull request | Related multi-effect publication with expected Git object identities |
| Kubernetes | Apply one exact conditional Deployment mutation | Resource-version precondition followed by asynchronous convergence |
| OpenTofu | Apply one immutable saved plan | Artifact identity, state lock, partial effects, and backend reconciliation |
| PostgreSQL | Execute one typed bounded update | Transaction, row/value bounds, rollback, and ambiguous commit |
| Radicle | Publish one exact patch | Local write plus decentralized, observer-dependent propagation |
| Records API | Create one record or disclose approved fields | Separate write/read profiles delivered over HTTPS or Iroh without reusable client credentials |
| Stripe | Issue one exact bounded refund | Evidence-relative money limits, aggregate capacity, provider idempotency, and liabilities |

Stripe's additional profiles are intra-domain counterexamples and supporting
evidence. They do not count as independent cross-domain votes.

## Semantic axes

### Policy and evaluator identity

All domains require immutable policy/configuration meaning and an evaluator
whose semantics cannot change under the same identifier. Their policy payloads
are not interchangeable:

- GitHub constrains repository publication and path/change behavior.
- Kubernetes constrains object identity, namespace, replicas, containers, and
  patch fields.
- OpenTofu constrains an immutable plan, provider locks, backend state, and
  change classes.
- PostgreSQL constrains a typed mutation, relation, columns, predicates,
  values, isolation, and row bounds.
- Radicle constrains repository/issue identity, patch shape, and publication.
- Records create constrains namespace, fields, and capacity; records read
  separately constrains subjects and disclosed fields.
- Stripe constrains account, charge, currency, amount, evidence denominator,
  aggregate window, and refund behavior.

The common semantic is a commitment tuple, not a common policy payload.

### Exact actions

Every action is canonical, bounded, profile-versioned, audience-bound, and
committed before execution. Action fields and construction remain
domain-owned. A universal action union or operation-tag dispatcher would erase
which bytes authorize the provider effect and is rejected.

The records domain is explicit evidence that one provider boundary may still
need multiple profiles: create and read have different effects, capacity,
privacy meaning, receipts, and disclosure obligations.

### Evidence

All evaluators consume explicit evidence commitments and observation times.
The authority, normalization, contradiction, and freshness meaning diverge:

| Domain | Evidence authority | Stale/uncertain meaning |
| --- | --- | --- |
| GitHub | Repository, issue, refs, pull requests, inspected Git candidate | Denied or indeterminate according to the missing/conflicting fact |
| Kubernetes | API object UID/resource version, dry-run and current spec | Conditional mutation cannot be safely derived |
| OpenTofu | Saved-plan projection, lockfile, backend/state and lock identity | Plan/state relation is no longer established |
| PostgreSQL | Catalog/schema, row preconditions, transaction ledger | Row/commit truth may require a fresh transaction or reconciliation |
| Radicle | Repository identity, issue COB, refs, peers and candidate | Distributed evidence can be indeterminate without invalidating local identity |
| Records API | Exact request/presentation and authoritative local ledger | Durable local effect is definitive; delivery loss becomes replay |
| Stripe | Charge/PaymentIntent state and aggregate usage | Missing or stale monetary facts must fail closed |

Only evidence identity, source identity, observation time, and digest carriers
are common. Evidence schemas and freshness rules remain domain-owned.

### Pure decisions

The seven evaluators are total over validated explicit inputs and partition
results into:

- eligible/authorized;
- denied with stable domain code and stage; or
- indeterminate where required facts cannot be established safely.

Some current domains call the positive class `authorized`; the shared
product-level term is **eligible** because mutable capacity has not necessarily
been reserved. Existing domain result names and codes remain unchanged during
migration.

Required and executed evaluator/configuration commitments must compare equal
before an eligible result can become durable execution authority. This is the
strongest identical cross-domain invariant.

### Arithmetic and bounds

Common leaf laws are:

- fixed-width values embed exactly into checked arithmetic;
- dimensions and units must match before comparison or addition;
- overflow and underflow fail closed;
- boundaries and rounding are explicit;
- collections, bytes, nesting, and work are hard bounded.

The arithmetic meaning is domain-owned:

- money uses minor units and currency;
- percentages use basis points with a named evidence denominator;
- replicas, rows, resources, effects, disclosures, and workflow steps are
  distinct units;
- rolling, fixed, and provider-defined windows are not interchangeable.

There is no universal numeric policy or expression language.

### Reservations, claims, and replay

All consequential effects require a durable unique claim or reservation before
credentials/provider I/O. The common pure-policy output is a bounded,
canonical commitment to requested reservation intents and obligations.

The state invariant differs:

| Domain | Reserved thing | Core invariant |
| --- | --- | --- |
| GitHub | Branch/PR workflow identity | One publication workflow wins; replay returns prior state |
| Kubernetes | Exact rollout identity | One exact conditional mutation claim |
| OpenTofu | Saved-plan/backend execution | Plan claim and lock exclusivity |
| PostgreSQL | Typed mutation and bounded ledger use | Transaction/row capacity plus execution identity |
| Radicle | Exact patch publication | One local publication lease |
| Records API | Create/read capacity and replay identity | Atomic local ledger transition |
| Stripe | Monetary aggregate capacity and exact refund | Additive conservation, including unknown outcomes |

Compare-and-swap, idempotent lookup, and canonical key mechanics are plausible
shared leaves. One universal mutable reservation state machine is not approved
by this report; Milestone 4 must define closed reservation algebras and prove
their separate invariants.

### Credential and verified-command boundary

Every domain denies before credential release and constructs a closed verified
command only from the exact action and completed authorization state. Command
payload, provider conditional material, and least-privilege credential scope
remain domain-owned.

The records API proves that a domain may have no reusable client API credential
at all. The shared invariant is therefore not “obtain a token”; it is “no
protected execution capability or provider call exists before the durable
authorization boundary.”

### Definite failure, outcome unknown, and reconciliation

These terms are not interchangeable:

- Stripe, PostgreSQL, OpenTofu, GitHub, and Kubernetes can lose certainty after
  possible delivery and require domain observation/reconciliation.
- Radicle has a definitive local write followed by separately receipted
  decentralized propagation.
- Records has a definitive atomic local ledger effect; response loss becomes
  replay rather than an unknown provider outcome.

The shared rule is conservative: capacity or exclusivity that may have caused
an effect is not released without proof of non-effect. Reconciliation facts,
retry permissions, and observation meaning remain domain-owned.

### Receipts

All domains separate authorization from effect and later observation. A shared
receipt envelope may bind:

- schema and profile;
- action, policy/evaluator, evidence, state, and configuration commitments;
- decision class, stable code, and stage;
- reservation/obligation commitment;
- implementation/build provenance;
- domain payload digest and prior-receipt link.

The canonical domain payload remains authoritative. GitHub publication,
Radicle propagation, Stripe monetary capacity, Kubernetes convergence,
OpenTofu apply observations, PostgreSQL transaction observations, and records
delivery/disclosure claims must not be normalized into one vague success
object.

### Transport, UI, and deployment

Transport carries proof and domain request bytes but does not upgrade
authorization. The records HTTPS/Iroh parity test is direct evidence.

Frontend layout, stage rendering, inline canonical JSON, dedicated receipt
pages, health routes, Docker-local deployment, and browser test plumbing are
demo duplication and may be shared outside production semantics. Domain
language and security explanations remain domain-owned.

## Candidate classification

Each candidate has exactly one semantic classification and one locality
classification.

| ID | Candidate | Semantic classification | Locality classification | Decision |
| --- | --- | --- | --- | --- |
| C01 | Policy/evaluator commitment tuple | Shared invariant with domain payload | Identical mechanism | Approve in product |
| C02 | Explicit evaluation commitments and time | Shared invariant with domain payload | Identical mechanism | Approve in product |
| C03 | Required/executed equality before eligibility/execution | Identical invariant and transition | Identical mechanism | Approve and formally prove |
| C04 | Eligible/denied/indeterminate partition | Shared invariant with domain payload | Identical mechanism | Approve as an envelope; retain domain codes |
| C05 | Checked integers, units, basis points, windows, hard limits | Composition of smaller primitives | Identical mechanism | Approve only closed leaves |
| C06 | Fixed-context policy tightening law | Shared invariant with domain payload | Domain semantic | Approve the law; each evaluator owns its relation |
| C07 | Reservation-intent and obligation commitments | Shared invariant with domain payload | Identical mechanism | Approve commitments only in Milestone 3 |
| C08 | Canonical digest and stable identifier carriers | Composition of smaller primitives | Accidental duplication | Consolidate where identities are identical |
| C09 | Stable decision class/code/stage carrier | Shared invariant with domain payload | Identical mechanism | Approve carrier; domain vocabulary remains |
| C10 | Receipt envelope and hash links | Shared invariant with domain payload | Identical mechanism | Approve mechanics; domain payload stays canonical |
| C11 | Compare-and-swap and idempotent lookup leaves | Composition of smaller primitives | Identical mechanism | Defer implementation to Milestone 4 |
| C12 | Universal reservation state machine | Intentionally domain-specific | Structurally similar only | Reject; use closed reservation algebras |
| C13 | Generic evidence schema/normalizer | Intentionally domain-specific | Domain semantic | Reject |
| C14 | Universal freshness policy | Intentionally domain-specific | Domain semantic | Reject; share only timestamp/duration leaves |
| C15 | Generic action or provider request | Intentionally domain-specific | Profile semantic | Reject |
| C16 | Generic verified command/gateway | Intentionally domain-specific | Domain semantic | Reject |
| C17 | Generic credential broker semantics | Intentionally domain-specific | Domain semantic | Reject; only ordering is common |
| C18 | Generic reconciliation algorithm | Intentionally domain-specific | Domain semantic | Reject |
| C19 | Generic exact-effect workflow service | Intentionally domain-specific | Structurally similar only | Reject; later compose stage primitives |
| C20 | Common demo/receipt presentation | Shared invariant with domain payload | Demo duplication | Approve outside production semantics |
| C21 | HTTPS/Iroh/provider transport abstraction | Composition of smaller primitives | Domain semantic | Existing exchange ports carry bytes; no policy coupling |

## Approved Milestone 3 contract surface

Specification 0025 may define only:

1. immutable policy/evaluator/canonicalization commitments;
2. explicit action, evidence, state-snapshot, time, and configuration
   commitments;
3. required/executed equality;
4. a three-way eligibility envelope carrying domain-owned stable codes and
   committed reservation/obligation outputs;
5. checked unit/arithmetic and hard-limit leaves;
6. the fixed-context tightening/refinement laws;
7. receipt commitment/envelope mechanics needed to bind the pure decision;
8. a closed evaluator registry and conformance inventory.

It may not define provider commands, credentials, mutable reservation
transitions, provider retries, or reconciliation.

## Abstraction case files

The review artifacts are:

- `abstraction-cases/0001-policy-and-evaluator-commitments.md`;
- `abstraction-cases/0002-evaluation-context-and-configuration-match.md`;
- `abstraction-cases/0003-eligibility-reservations-and-obligations.md`;
- `abstraction-cases/0004-checked-arithmetic-limits-and-tightening.md`;
- `abstraction-cases/0005-receipt-envelope.md`;
- `abstraction-cases/0006-evidence-provider-and-lifecycle-exclusions.md`.

Rejecting any approved case leaves every vertical operational. Rejecting an
excluded generic surface requires no migration.

## Performance baseline

The readiness corpora establish deterministic encoded-size baselines:

| Domain | Fixture files | Canonical bytes |
| --- | ---: | ---: |
| GitHub | 6 | 4,749 |
| Kubernetes | 5 | 3,797 |
| OpenTofu | 7 | 7,104 |
| PostgreSQL | 7 | 16,967 |
| Radicle | 6 | 4,389 |
| Records API | 10 | 3,605 |
| Stripe | 7 | 4,257 |

There is not yet one comparable seven-domain CPU, allocation, durable-write,
or stage-latency benchmark. Existing live timings include incomparable
provider/container startup and cannot justify a semantic representation.
Milestone 3 must add deterministic evaluator work/allocation counters;
Milestone 4 must add reservation/store counters; Milestone 6 must benchmark
before optimizing. This is a measurement gap, not permission to infer a common
hot path.

## Contract blockers carried forward

Milestone 4 must resolve, by specification before implementation:

- the closed reservation algebra inventory;
- cancellation of reserved-but-not-executing work;
- expiry and rolling-window retention;
- multi-intent atomicity;
- decision/intent transaction boundaries;
- provider idempotency contract representation;
- unknown-outcome and reconciliation transition laws;
- store linearizability and crash assumptions.

Milestone 5 must preserve each original evaluator as a test-only oracle until
exact differential conformance passes.

## Conclusion

Seven working verticals support a narrow shared semantic center, not a generic
policy engine. The common center commits to identities and explicit inputs,
enforces configuration equality and checked bounds, and binds typed
eligibility outputs. Domains continue to decide what actions, evidence,
capacity, commands, credentials, observations, and receipts mean.
