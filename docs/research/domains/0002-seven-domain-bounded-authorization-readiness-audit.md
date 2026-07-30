# Seven-domain bounded-authorization readiness audit

## Status

Baseline audit for the bounded-authorization extraction program.

Baseline revision: `7628cbe`

Pinned toolchain identities:

- Rust and Cargo `1.97.1`;
- Lean `v4.31.0`;
- mathlib revision `fabf563a7c95a166b8d7b6efca11c8b4dc9d911f`;
- Aeneas revision `3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0`;
- qualified production source-closure digest
  `1c80ab8c7e7a157d62a5f5717e59146305bf4f42c1cc91757b50bc39c39b5fc5`.

This audit answers whether GitHub, Radicle, Stripe, Kubernetes, OpenTofu,
PostgreSQL, and the records API are complete enough to serve as empirical
inputs to the shared bounded-authorization contract. It does not approve a shared semantic
implementation. Its purpose is to identify the evidence that exists, the
evidence that must be frozen, and the domain behavior that must remain outside
the abstraction.

## Baseline qualification

The selected baseline follows:

- formal-hardening PR #17;
- OpenTofu and PostgreSQL completion PR #18;
- records API PR #23;
- dependency-aware CI PR #28;
- expanded Stripe profile PR #20.

PR #20 passed the authoritative, formal-translation, compliance,
OpenTofu-live, PostgreSQL-live, records-live, dependency, and secret phases
before merge. The baseline therefore contains the qualified rich-authority
work and the live recovery verticals on one revision.

The baseline remains reproducible only if those checks continue to pass after
the inventory and oracle additions. Historical green CI is evidence for
selecting the baseline, not permission to skip CI on this work.

## Status corrections

The following specifications described implemented repository behavior but
still carried stale pre-implementation status:

| Specification | Corrected status | Evidence |
| --- | --- | --- |
| 0005 GitHub issue workflows | Implemented | Product package, GitHub App execution, crash reconciliation, receipts, and deployed demo |
| 0006 Radicle issue workflows | Implemented | Product package, real Radicle write boundary, propagation evidence, receipts, and deployed demo |
| 0007 Kubernetes workload rollouts | Implemented | Product package, Kind/local execution, conditional mutation, receipts, and browser demo |
| 0008 OpenTofu saved-plan apply | Implemented | Exact saved artifact, real local effect, lock/recovery tests, receipts, and browser demo |
| 0009 PostgreSQL bounded data changes | Implemented | Typed update, real TLS database effect, concurrency/recovery tests, receipts, and browser demo |
| 0010 Stripe exact refunds | Implemented | Exact test-mode refund, claim/idempotency, receipts, and deployed demo |
| 0012 Stripe bounded refunds | Implemented | Pure relative/aggregate evaluator, persistent reservation, unknown outcomes, reconciliation, and bounded-refund UX |
| 0024 Transport-neutral records API | Implemented | Separate create/read profiles, HTTPS and Iroh delivery, aggregate capacity, replay, receipts, and deployed/live browser behavior |

The status correction is intentionally limited to the primary evidence set.
The presence of code or a demo directory does not automatically qualify every
Stripe profile in specifications 0013 through 0023 as complete. Their
machine-readable inventory remains authoritative until each profile satisfies
its complete fixture, live-effect, recovery, receipt, and compliance gate.

## Domain evidence matrix

| Axis | GitHub | Radicle | Stripe bounded refund | Kubernetes | OpenTofu | PostgreSQL | Records API |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Exact action | Branch publication plus draft PR | One exact patch publication | One exact refund | One exact Deployment patch | One immutable saved plan | One typed bounded update | Exact create or field-bounded read |
| Policy | Workflow grant and repository automation policy | Issue-address grant | Immutable bounded-refund policy | Closed verifier rollout configuration | Saved-plan verifier configuration | Closed update intent and verifier configuration | Immutable namespace, capacity, and disclosure policy |
| Fresh evidence | Repository, issue, refs, PRs, inspected Git candidate | Repository identity, issue COB, peers, inspected candidate | Charge/PaymentIntent state and aggregate usage | Resource UID/version, dry-run, current spec | Plan projection, backend/state/lock identity | Catalog, row preconditions, execution ledger | Exact action, presentation freshness, and ledger snapshot |
| Pure decision | `containment::evaluate` | `containment::evaluate` | `evaluate_bounded_refund` | `decision::evaluate` | `decision::evaluate` | `decision::evaluate` | `evaluate_create` or `evaluate_read` |
| Claim/reservation | Separate branch and PR claims | Execution lease | Monetary aggregate reservations plus exact-action claim | Rollout claim | Saved-plan claim | Bounded-update claim and database ledger | Atomic create/read capacity and replay ledger |
| Credential boundary | GitHub App token after exact claim | Radicle signer/write boundary after claim | Stripe mutation credential after reservation and claim | Kubernetes token after claim | Provider/backend credential after claim and artifact resolution | Database credential after claim | No reusable client API credential; sealed command precedes ledger effect |
| Provider effect | Git push and draft PR creation | Radicle patch write and gossip | Stripe refund request | Conditional Kubernetes patch | Apply exact saved plan | Transactional typed update | Create a record or disclose allowed fields |
| Unknown outcome | Branch or PR publication may require reconciliation | Local publication may await propagation/operator evidence | Capacity remains held pending Stripe reconciliation | Mutation may require read-after-write reconciliation | Partial or interrupted apply requires state reconciliation | Commit acknowledgement may be ambiguous | Local durable ledger transition is definitive; delivery failure does not reclassify the committed effect |
| Observation | Ref and PR state | Multiple Radicle observers | Refund lookup and charge state | Deployment state/convergence | Fresh backend/provider state | Execution ledger and row state | Stored record projection, usage, and receipt log |
| Receipts | Decision, execution, reconciliation | Decision, execution, propagation | Decision, reservation, execution, observation | Decision and execution | Decision, apply, observation | Decision and transaction observation | Delivery, decision, effect, and observation bundle |

## Lifecycle evidence already present

### GitHub

- `product/integrations/auths-github/src/containment.rs` owns the pure
  three-valued workflow decision.
- `product/integrations/auths-github/src/workflow.rs` owns atomic claims.
- `product/integrations/auths-github/src/executor.rs` seals branch and pull
  request commands.
- `product/integrations/auths-github/src/service.rs` keeps validation,
  credentials, execution, crash recovery, and reconciliation linear.
- `demos/github-issue/src/tests.rs` proves configuration mismatch, negative
  variants, crash-after-branch, crash-after-PR, and replay behavior.

### Radicle

- `product/integrations/auths-radicle/src/containment.rs` owns the pure
  decision.
- `product/integrations/auths-radicle/src/workflow.rs` owns the execution
  lease.
- `product/integrations/auths-radicle/src/executor.rs` seals the exact patch
  publication.
- `product/integrations/auths-radicle/src/receipts.rs` separates decision,
  execution, and propagation.
- The demo proves the real Radicle identity and write path, but its frozen
  migration corpus must retain propagation-specific facts rather than reducing
  them to a generic provider success.

### Stripe

- `product/integrations/auths-stripe/src/bounded.rs` owns the pure bounded
  refund evaluator.
- `product/integrations/auths-stripe/src/reservation.rs` owns persistent
  monetary capacity, final-unit concurrency, unknown outcomes, and
  reconciliation.
- `product/integrations/auths-stripe/src/bounded_service.rs` proves decision,
  receipt, reservation, claim, credential, provider, and observation ordering.
- `demos/stripe-refund/src/app.rs` and its browser tests expose aggregate
  capacity, exact boundaries, replay, outcome unknown, reconciliation, and
  dedicated receipts.
- The additional Stripe profiles supply intra-domain counterexamples to a
  generic operation dispatcher. They must not be counted as independent
  cross-domain evidence.

### Kubernetes

- `product/integrations/auths-kubernetes/src/decision.rs` owns the pure
  conditional-rollout decision.
- `product/integrations/auths-kubernetes/src/claim.rs` owns atomic rollout
  claims.
- `product/integrations/auths-kubernetes/src/executor.rs` seals the verified
  patch and fresh evidence.
- `product/integrations/auths-kubernetes/src/ports.rs` explicitly separates
  apply/observe from ambiguous-outcome reconciliation.
- The demo supplies a real local Kind effect and receipt UI.

### OpenTofu

- `product/integrations/auths-opentofu/src/decision.rs` owns the pure
  saved-plan decision.
- `product/integrations/auths-opentofu/src/claim.rs` owns persistent claims.
- `product/integrations/auths-opentofu/src/executor.rs` seals the exact saved
  artifact.
- `product/integrations/auths-opentofu/src/service.rs` rechecks critical state,
  applies only the saved plan, and reconciles ambiguous effects.
- The live contract, browser, and recovery tests cover real provider state,
  concurrent claims, restart, and reconciliation.

### PostgreSQL

- `product/integrations/auths-postgresql/src/decision.rs` owns the pure typed
  update decision.
- `product/integrations/auths-postgresql/src/compiler.rs` converts only the
  closed intent into parameterized SQL.
- `product/integrations/auths-postgresql/src/claim.rs` preserves
  outcome-unknown state.
- `product/integrations/auths-postgresql/src/service.rs` keeps credentials,
  transaction execution, observation, and reconciliation ordered.
- The live database and recovery tests cover TLS, privileges, RLS, locks,
  rollback, restart, ambiguous commit, and replay.

### Records API

- `product/integrations/auths-records-api/src/decision.rs` owns separate pure
  create and read policy decisions.
- `product/integrations/auths-records-api/src/ledger.rs` owns atomic aggregate
  capacity, durable replay, protected records, and receipt state.
- `product/integrations/auths-records-api/src/profile.rs` seals create and read
  commands independently.
- `demos/rest-api-authorization` proves that HTTPS and Iroh carry the same
  authority without reusable API keys and exposes inline and dedicated
  receipts.
- The records corpus must preserve the difference between mutation capacity
  and bounded field disclosure rather than reducing both to a generic
  operation.

## Oracle gap at baseline

The baseline does not yet provide one uniform, manifest-owned migration corpus
for all seven domains:

| Domain | Baseline fixture state | Required closure |
| --- | --- | --- |
| GitHub | No dedicated product fixture suite | Freeze grant, evidence, actions, decisions, command projections, claims, reconciliation, and receipts |
| Radicle | No dedicated product fixture suite | Freeze grant, evidence, action, decision, command projection, publication/propagation, replay, and receipts |
| Stripe | Extensive package-local fixture suites | Select and register the bounded-refund corpus as the cross-domain migration oracle without flattening other profiles |
| Kubernetes | No dedicated product fixture suite | Freeze configuration, evidence, exact patch, decisions, command projection, claim, ambiguous/reconciled outcomes, and receipts |
| OpenTofu | Deterministic product fixture suite | Extend the manifest with boundary, stale evidence, replay, unknown outcome, reconciliation, and command projection |
| PostgreSQL | Deterministic product fixture suite | Extend the manifest with boundary rows, stale evidence, replay, ambiguous commit, reconciliation, and transition receipts |
| Records API | Deterministic create/read fixtures | Register both profiles, exact create/read decisions, capacity boundary, disclosure boundary, replay, transport equivalence, and receipt commitments |

The readiness/oracle work must close these gaps before a shared evaluator or
state machine is introduced.

## Frozen oracle baseline

The readiness branch introduces generator-owned, flat, manifest-hashed corpora
for all seven domains. `cargo xtask product-fixtures --update` is the only
authoritative writer. `cargo xtask product-fixtures` regenerates the typed
inputs and outputs in memory and rejects byte drift; `cargo xtask
bounded-domains` checks profile identity, scenario coverage, file inventory,
SHA-256, exact byte length, executable evidence anchors, and compliance
registration.

The initial committed corpus measurements are:

| Domain | Files excluding manifest | Canonical bytes |
| --- | ---: | ---: |
| GitHub | 6 | 4,749 |
| Kubernetes | 5 | 3,797 |
| OpenTofu | 7 | 7,104 |
| PostgreSQL | 7 | 16,967 |
| Radicle | 6 | 4,389 |
| Records API | 10 | 3,605 |
| Stripe bounded refund | 7 | 4,257 |

These sizes are not performance targets. They are a reproducible baseline for
detecting accidental schema expansion before the semantic inventory proposes
any shared representation. Each manifest also records the generator command,
domain-owned profiles, implemented lifecycle scenarios, per-file byte length,
and SHA-256.

Records deliberately declares outcome-unknown and reconciliation not
applicable: its authoritative effect is an atomic local ledger transition.
Losing an HTTPS or Iroh response does not erase that durable fact, and
redelivery is replay handling rather than provider reconciliation. Radicle
likewise keeps local publication separate from later decentralized propagation
instead of relabeling observer latency as an ambiguous local write.

## Initial extraction risk assessment

The following are plausible shared mechanisms, not yet approved abstractions:

- fixed digest and semantic identity carriers;
- required/executed identity equality;
- checked integer arithmetic and explicit units;
- immutable policy commitments;
- narrow compare-and-swap storage mechanics;
- replay identifiers;
- the invariant that unknown outcomes retain capacity;
- receipt envelope mechanics;
- dependency-aware demo and browser-test infrastructure.

The following must remain domain-owned unless later evidence proves a smaller
identical primitive:

- evidence authority and freshness meaning;
- reservation units and release rules;
- provider commands and credential scopes;
- idempotency and conditional-write interpretation;
- the meaning of possible delivery;
- observation, convergence, propagation, and reconciliation;
- domain stable codes and receipt claims.

## Readiness decision

The repository is ready to freeze migration oracles and write the seven-domain
semantic inventory.

It is not yet ready to add the shared bounded-policy evaluator or reservation
state machine. Those implementations remain gated on:

1. deterministic seven-domain oracle manifests;
2. exact candidate classification;
3. a reviewed closed-contract specification;
4. abstraction case files for every non-trivial shared surface.
