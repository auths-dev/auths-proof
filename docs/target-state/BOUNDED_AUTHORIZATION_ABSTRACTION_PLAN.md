# Bounded Authorization Abstraction Plan

## Status

Target-state implementation plan.

This plan defines how Auths will evolve from domain-specific exact-action
demonstrations into a rigorously shared model for bounded agent autonomy. It
deliberately requires the OpenTofu and PostgreSQL verticals to work end to end
before the security-sensitive policy, reservation, and execution lifecycle is
abstracted.

The sequence is:

1. preserve the current domain implementations as empirical references;
2. implement the OpenTofu saved-plan apply demo;
3. implement the PostgreSQL bounded-change demo;
4. compare all completed verticals and specify the common contract;
5. extract the smallest stable abstractions;
6. migrate existing verticals without changing their observable decisions;
7. optimize only against exact fixtures, differential tests, and measured
   bottlenecks.

The plan covers production packages, demos, fixtures, conformance, CI, UX, and
performance. A demo is not complete when only its backend works.

## Goal

Auths must allow a human or organization to delegate a broad but bounded
decision space to an agent:

```text
Standing delegation
  "This agent may choose actions inside this bounded space."
                |
                v
Agent-selected exact action
  "Refund 37.42 USD for charge ch_123."
                |
                v
Deterministic containment decision
  "This exact action is inside the standing delegation now."
                |
                v
Atomic reservation and one-time execution
                |
                v
Decision, execution, and observation receipts
```

The human does not need to enumerate future actions. The agent may exercise
discretion inside the delegation, but every consequential action must become
canonical and exact before credentials or execution.

The resulting abstraction must support, at minimum:

- exact per-action limits;
- limits relative to fresh external evidence;
- aggregate and shared budgets;
- fixed and rolling time windows;
- resource, account, namespace, repository, table, and merchant scopes;
- validity, revocation, and status requirements;
- tiered or threshold approval;
- atomic reservation under concurrency;
- replay and idempotency;
- partial effects and outcome uncertainty;
- reconciliation against observed provider state;
- required and executed configuration equality;
- versioned policy and evaluator semantics.

## Non-goals

This work will not:

- introduce an unrestricted general-purpose policy language;
- move stateful policy, live evidence, credentials, or execution into `core/`;
- make demos a source of protocol truth;
- force every domain into one universal provider interface;
- make domain receipts identical;
- replace domain-specific evidence, canonical actions, postconditions, or
  reconciliation;
- change canonical core CBOR merely to match an optimized in-memory layout;
- weaken receipt durability or fail-closed behavior for lower latency;
- add custom allocators, unsafe packed-pointer structures, or speculative SIMD
  without a measured hot path.

## Exactness model

Canonical bytes alone are not sufficient for bounded authorization. The
abstraction must preserve five forms of exactness:

| Layer | Required guarantee |
| --- | --- |
| Representation | The exact canonical policy, action, evidence, configuration, and receipt bytes are known. |
| Semantics | Every policy field has versioned, deterministic meaning, including boundary, rounding, missing-data, and overflow behavior. |
| State | Every replay claim, budget reservation, release, commitment, and reconciliation transition is atomic and durable. |
| Implementation | The required evaluator/configuration and the evaluator/configuration that actually ran are identified and equal. |
| Effect | The provider command is derived only from the verified action, and its actual postcondition is separately observed. |

Every shared abstraction and optimization must demonstrate that it preserves
all applicable layers.

## Repository boundaries

The monorepo remains a layered collection of packages:

```text
+---------------------------------------------------------------+
| demos/                                                        |
| Interactive scenarios, deployments, browser tests, benchmarks |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| product/                                                      |
| Domain policies, evidence, state, runtime, credentials,        |
| exact effects, receipts, stores, SDKs, and conformance         |
+------------------------------+--------------------------------+
                               |
                               v
+---------------------------------------------------------------+
| core/                                                         |
| Portable canonical model, authority, proofs, verification,     |
| registries, codecs, and immutable wire fixtures                |
+---------------------------------------------------------------+
```

Domain-specific bounded policy belongs under
`product/integrations/<domain>/`. Shared stateful reservation and effect
orchestration belongs in `product/stores/` and `product/runtime/`. Reusable
profile-authoring and policy-conformance tools belong in `product/sdk/` or
`product/testkit/`.

Only a portable, deterministic, domain-independent type or invariant may move
into `core/`. Network access, mutable budgets, credentials, provider clients,
wall-clock access, and reconciliation remain product concerns.

## Phase 0: freeze the evidence-gathering boundary

Before implementing the remaining demos:

1. Inventory the GitHub, Radicle, Stripe, and Kubernetes implementations by
   lifecycle stage.
2. Record code that is:
   - identical;
   - structurally similar but semantically different;
   - domain-specific;
   - accidental demo/deployment duplication.
3. Record the state transitions, denial codes, indeterminate states,
   credential boundary, receipts, and reconciliation behavior of each
   vertical.
4. Establish a duplication ledger for OpenTofu and PostgreSQL. New code must
   identify whether it was copied unchanged, adapted, or designed for a new
   domain requirement.
5. Do not create a shared policy evaluator, generic exact-effect service, or
   generic reservation state machine during Phases 1 and 2.

Small leaf corrections are allowed before abstraction when they do not choose
the future lifecycle design, such as using one canonical digest type, fixing a
security defect, or improving shared browser-test utilities. Such work must not
make a demo depend on another demo.

## Phase 1: OpenTofu saved-plan apply

Implement `0008-opentofu-saved-plan-apply.md` as a real end-to-end vertical.
It must use OpenTofu, create an observable local effect, and expose the same
complete frontend and receipt experience as the existing demos.

### Required boundedness

The standing delegation must be able to constrain:

- permitted workspace and backend;
- permitted providers and pinned provider versions;
- permitted resource kinds and resource addresses;
- destructive versus non-destructive changes;
- maximum create, update, replace, and destroy counts;
- maximum monetary or domain cost estimate when trustworthy evidence exists;
- saved-plan age;
- authorization lifetime;
- executor audience;
- state and lock identity;
- required policy, evaluator, and verifier configuration.

### Required exactness

The exact action must commit to:

- canonical saved-plan bytes or an immutable plan artifact digest;
- configuration and dependency lock digests;
- prior state identity and serial/version;
- provider selections;
- normalized change summary;
- external evidence used for bounded decisions;
- required policy and evaluator identifiers;
- required verifier configuration digest.

The executor must apply the exact authorized saved plan. It must never
reconstruct a new plan from the same source configuration after authorization.

### Required failure and reconciliation cases

The vertical must demonstrate:

- configuration changed after planning;
- saved plan changed by one byte;
- provider lock changed;
- state drift after authorization;
- state lock unavailable;
- destructive change exceeds the delegation;
- plan expired;
- apply fails before any effect;
- apply partially changes infrastructure;
- process interruption after the provider may have been called;
- restart and reconciliation from fresh state;
- replay returns the original result without another apply.

### Required UX

The frontend must show, without requiring scrolling between control and result:

- the standing delegation;
- the exact saved-plan summary;
- policy and evidence-relative limits;
- required and executed configuration;
- whether state was locked;
- whether credentials were requested;
- whether apply began;
- observed resources before and after;
- claim/replay/reconciliation status;
- inline raw receipt JSON;
- a dedicated human-readable receipt route;
- a separate machine-readable receipt endpoint.

The demo must run end to end locally. Cloud deployment may be configurable, but
a static `file://` page is not a functioning demo.

### Phase 1 exit gate

OpenTofu is complete only when:

- the real provider effect is observed;
- every listed denial stops before credential release and apply;
- replay and interruption behavior are tested;
- canonical policy/action/evidence fixtures exist;
- native decision behavior and frontend behavior are tested;
- its complete compliance claims pass.

## Phase 2: PostgreSQL bounded data changes

Implement `0009-postgresql-bounded-data-changes.md` as a real end-to-end
vertical against a local containerized PostgreSQL instance.

### Required boundedness

The standing delegation must be able to constrain:

- database, schema, table, and operation;
- structured statement form;
- exact bound parameters;
- permitted columns;
- predicate requirements;
- maximum affected rows;
- maximum aggregate value when applicable;
- transaction isolation;
- required preconditions;
- statement and transaction timeouts;
- validity, audience, policy, evaluator, and verifier configuration.

Raw arbitrary SQL must not become the reusable abstraction. The profile must
use a closed typed command or a narrowly supported, canonical SQL subset with
specified parsing and normalization semantics.

### Required exactness

The exact action must commit to:

- normalized command;
- exact parameter types and values;
- target database/schema/table;
- expected precondition evidence;
- maximum affected rows and other requested budgets;
- policy and evaluator identifiers;
- verifier configuration;
- transaction and executor audience.

The database adapter must execute only a verified command type that cannot be
constructed from the untrusted request alone.

### Required failure and reconciliation cases

The vertical must demonstrate:

- one parameter changed;
- predicate broadened;
- unauthorized table or column;
- stale precondition evidence;
- zero, boundary, and boundary-plus-one affected rows;
- concurrent transactions competing for the same budget;
- row state changed before execution;
- statement failure and rollback;
- receipt persistence failure before execution;
- connection loss before commit;
- connection loss during commit with an ambiguous outcome;
- restart and reconciliation from database state;
- replay without a second committed mutation.

### Required UX

The frontend must show:

- the standing delegation;
- a human-readable exact data change;
- exact parameters and target;
- expected versus actual row bounds;
- transaction and credential boundary;
- authorization, claim, execution, commit, and reconciliation stages;
- before/after evidence;
- aggregate budget before, reserved, and after;
- inline raw receipt JSON;
- a dedicated human-readable receipt route;
- a separate machine-readable receipt endpoint.

### Phase 2 exit gate

PostgreSQL is complete only when:

- the real transaction commits for an authorized action;
- denied cases never obtain credentials or enter the transaction;
- rollback and ambiguous-commit behavior are tested;
- concurrent reservations have exactly one permitted outcome;
- canonical policy/action/evidence fixtures exist;
- the local Docker demo and browser tests pass;
- its complete compliance claims pass.

## Phase 3: cross-domain abstraction report

After both demos pass, compare all seven verticals:

| Domain | Lifecycle characteristic |
| --- | --- |
| GitHub | Multi-effect workflow with expected Git object identities |
| Radicle | Decentralized propagation and multiple observers |
| Stripe | Exact financial mutation and provider idempotency |
| Kubernetes | Conditional mutation and asynchronous convergence |
| OpenTofu | Saved artifact, state lock, partial apply, and reconciliation |
| PostgreSQL | Transactional mutation, row bounds, rollback, and ambiguous commit |
| Records API | Separate create/read disclosure semantics across HTTPS and Iroh without reusable client credentials |

For every lifecycle concept, classify it as:

1. identical invariant and identical transition;
2. identical invariant with a domain-specific payload;
3. composition of a smaller shared primitive;
4. domain-specific and intentionally not abstracted.

The report must include:

- authorization inputs;
- pure containment decisions;
- evidence normalization and freshness;
- policy commitments;
- required/executed implementation commitments;
- reservation keys and lifecycle;
- credential release;
- verified command construction;
- provider idempotency and conditional execution;
- outcome-unknown behavior;
- reconciliation;
- decision, execution, observation, and propagation receipts;
- UI projection;
- deployment and test plumbing;
- measured CPU, allocation, memory, and end-to-end latency profiles.

No lifecycle abstraction may be approved merely because two types have similar
field names.

## Phase 4: specify the bounded-policy contract

Define a closed product-layer contract from the cross-domain evidence.

### Canonical policy identity

Every policy must have:

```text
policy_type
policy_version
canonicalization_version
policy_digest
evaluator_id
```

The grant must commit to the canonical policy digest and required evaluator.
The policy must be carried in the proof or resolved by immutable content
digest. Mutable policy names are forbidden at the authorization boundary.

### Pure evaluation

Evaluation must be a deterministic, total function over explicit inputs:

```text
evaluate(
    canonical_policy,
    exact_action,
    canonical_evidence,
    state_snapshot,
    explicit_time,
    required_configuration,
    executed_configuration,
) ->
    Authorized { reservations, obligations }
  | Denied { stable_code, stage }
  | Indeterminate { stable_code, stage }
```

Evaluation performs no I/O and reads no environment, hidden clock, network,
filesystem, credential, or global mutable state.

### Closed policy types

Policies must use:

- versioned closed schemas;
- integer units and explicit dimensions;
- minor currency units and explicit currency;
- basis points instead of floating-point percentages;
- closed enums;
- sorted duplicate-free bounded collections;
- checked arithmetic;
- explicit rounding and inclusivity;
- no decode-time defaults;
- rejection of unknown fields;
- hard byte, item, nesting, and work limits.

A general expression language is out of scope until several versioned domain
policies prove a common algebra and that algebra has independent conformance
evidence.

### Evidence-relative bounds

Every relative rule must identify its denominator and evidence source. For
example, a refund percentage must explicitly choose captured amount, original
amount, or remaining refundable amount. Missing, stale, future-dated,
contradictory, or untrusted evidence produces a stable denial or indeterminate
result according to the versioned semantics; it never becomes zero, empty, or
unlimited implicitly.

### Stateful reservations

Define the shared lifecycle only after the seven-domain comparison. At minimum,
it must represent:

```text
available -> reserved -> committed
                    \-> released
                    \-> outcome-unknown -> reconciled
```

Reservation keys must bind the grant, policy/algebra version, scope, unit,
currency where applicable, and time window. The contract must specify crash
recovery, concurrency, expiry, revocation, definite non-execution, ambiguous
execution, and reconciliation.

### Verified command boundary

Provider adapters must accept a verified command that binds:

- the authorized canonical action;
- decision receipt;
- exact reservation/claim;
- evidence digest;
- expiry and audience;
- provider idempotency or conditional-write material.

The type must not have a public constructor that accepts an untrusted action.
Credential brokers must require proof of the completed authorization and
reservation stages.

## Phase 5: extract stable components

Extract in increasing order of security sensitivity.

### 5.1 Leaf primitives

Consolidate:

- fixed-byte digest types with hex only at display boundaries;
- canonical product-policy encoding helpers;
- safe non-serializable, non-debuggable, zeroizing secret bytes;
- explicit units, currencies, basis points, and checked arithmetic helpers.

These primitives must not introduce domain policy into `core/`.

### 5.2 Policy conformance kit

Add product-layer tooling for:

- canonical policy fixtures;
- deterministic evaluation vectors;
- boundary and mutation generation;
- explanation-to-policy coverage;
- native/WASM parity where the evaluator is portable;
- reference-versus-optimized differential evaluation;
- hard-limit and complexity tests.

### 5.3 Demo server and receipt presentation

Consolidate non-production demo plumbing:

- health/readiness;
- bounded sessions;
- scenario discovery;
- session status;
- inline receipt data;
- dedicated human receipt route;
- machine-readable receipt endpoint;
- common API error shape;
- local/cloud API routing;
- browser conformance.

Use a shared display projection over domain receipts. Do not replace canonical
domain receipts with a demo-oriented universal receipt.

### 5.4 Reservation stores

Extract atomic in-memory and persistent reservation primitives with:

- compare-and-swap claim;
- reserve, commit, release, and outcome-unknown transitions;
- replay returning the original receipt;
- crash recovery;
- bounded storage;
- multi-process/shared-store ports;
- concurrency and model-based tests.

### 5.5 Exact-effect runtime

Only after the reservation model is stable, extract the common ordering:

```text
normalize evidence
-> evaluate exact containment
-> durably record decision
-> atomically reserve
-> construct verified command
-> request credential
-> execute conditionally/idempotently
-> observe
-> commit or mark outcome unknown
-> durably record receipts
```

The runtime owns ordering and shared state transitions. Domains continue to
own action semantics, evidence, policies, provider commands, postconditions,
and reconciliation.

Avoid a public service parameterized by an unreadable collection of generic
types. Prefer small ports and explicit stage types.

## Phase 6: migration order

Migrate one vertical at a time:

1. Stripe;
2. Kubernetes;
3. PostgreSQL;
4. OpenTofu;
5. GitHub;
6. Radicle;
7. records create/read.

For each migration:

- preserve the previous implementation as a test oracle until differential
  conformance passes;
- run the same canonical fixtures through old and new paths;
- require identical decisions, stable codes, policy calculations, reservation
  requests, and receipt bytes where the receipt version is unchanged;
- retain the smallest regression seed for every discovered mismatch;
- remove the old path only after the complete repository suite passes.

If GitHub or Radicle does not fit the single-effect runtime, it must compose
claims and stages rather than weakening the abstraction.

## Performance and latency plan

Performance changes are allowed only after correctness fixtures and phase-level
measurements exist.

### Exact benchmark corpus

Add canonical benchmark fixtures for:

- minimal single grant;
- typical standing Stripe delegation;
- typical Kubernetes rollout;
- OpenTofu saved plan;
- PostgreSQL bounded transaction;
- repeated principals and permissions;
- deep grant chains;
- `all-of`, `any-of`, and `k-of-n` plans;
- maximum valid policy, evidence, and proof;
- adversarial unique identifiers;
- authorized, denied, and indeterminate paths.

The corpus must use exact repository-owned bytes. Performance results must
identify the fixture digest and build revision.

### Phase measurements

Measure separately:

- CBOR decode and canonical validation;
- hashing;
- signature verification;
- authority traversal;
- policy evaluation;
- reservation;
- credential acquisition;
- provider evidence;
- provider execution;
- observation/reconciliation;
- receipt encoding and durability;
- allocation count, bytes allocated, and peak live memory;
- native and WASM behavior;
- cold and warm configuration.

Do not optimize local verification based solely on end-to-end provider latency,
or provider latency based solely on a microbenchmark.

### Low-risk optimizations

Prioritize:

- parse and validate executed configuration once at startup;
- carry canonical typed values and computed digests instead of repeating
  serialization and hashing;
- store digests as fixed bytes internally;
- reuse provider connection pools without exposing credentials to agents;
- fetch independent required evidence concurrently under hard deadlines;
- keep claim and budget state close to the executor;
- cache only immutable, content-addressed proof/grant work;
- use provider conditional-write and idempotency facilities.

### Compact internal representation

After profiling, a bounded request-local verification arena may:

- intern repeated principals, methods, profiles, permissions, and digests;
- store small indexes in graph nodes;
- keep common values inline;
- move rare extensions and large attachments to bounded side tables;
- lazily decode uncommon referenced data when protocol validation permits;
- use bounded pages when an index range is exhausted.

The external canonical CBOR remains unchanged. Interning must be request-local,
hard bounded, collision safe, and unable to affect canonical output.

An index width may be chosen only when a compile-time or CI assertion proves
that protocol hard limits fit. Pathological inputs must fail closed or move to
a specified bounded fallback.

### Differential optimization gate

Every optimized evaluator or representation must agree with the simple
reference path across:

- canonical fixtures;
- invalid and non-canonical fixtures;
- mutation corpus;
- fuzz-generated valid inputs;
- all numeric boundaries;
- maximum-sized inputs;
- native and WASM targets.

Agreement includes:

- decision class;
- stable code and stage;
- selected authority branches;
- evaluated bounds;
- reservation requests;
- required/executed commitments;
- canonical receipt bytes.

### Prohibited performance shortcuts

Do not:

- execute before durable decision/claim/reservation state;
- make receipt persistence best effort;
- cache final authorization verdicts;
- use stale evidence outside its explicit freshness contract;
- skip structural validation on a fast path;
- add unbounded global interning;
- expose secret material through pooled clients or logs;
- introduce unsafe code or custom allocation without a separately approved
  architecture and security review;
- change a stable wire format as an internal refactor.

## UX contract for bounded autonomy

Every bounded-autonomy demo must keep the delegation, proposed action, and
result visible together:

```text
+------------------------------+------------------------------+
| Standing delegation          | Live result                  |
| Agent: support-agent         | Decision: AUTHORIZED         |
| Per action: evidence bounded | Requested: 75 USD            |
| Aggregate: 500 USD           | Allowed now: 120 USD         |
| Remaining: 425 USD           | Credential requested: yes    |
| Validity: 24 hours           | Provider called: yes         |
|                              | Budget after: 350 USD         |
+------------------------------+------------------------------+
| Agent-selected exact action and experiment controls          |
+--------------------------------------------------------------+
| Inline receipt JSON and dedicated receipt-page link          |
+--------------------------------------------------------------+
```

The UI must derive its explanation from the same canonical policy object used
by the evaluator. Tests must prove that every security-relevant field is
represented in the explanation.

Required experiments include:

- permitted action inside the delegation;
- exact boundary;
- boundary plus one;
- altered evidence;
- stale evidence;
- exhausted aggregate budget;
- concurrent attempt;
- revoked or expired grant;
- required/executed mismatch;
- replay;
- outcome unknown and reconciliation.

## API shape

The final names will be chosen after Phase 3, but the shared seams should
resemble:

```rust
pub struct PolicyCommitment {
    pub policy_type: PolicyType,
    pub version: u16,
    pub canonicalization: CanonicalizationId,
    pub digest: Digest,
    pub evaluator: EvaluatorId,
}

pub enum BoundedDecision<R, O> {
    Authorized {
        reservations: Vec<R>,
        obligations: Vec<O>,
    },
    Denied {
        code: StableDecisionCode,
        stage: DecisionStage,
    },
    Indeterminate {
        code: StableDecisionCode,
        stage: DecisionStage,
    },
}

pub enum ReservationState {
    Reserved,
    Committed,
    Released,
    OutcomeUnknown,
    Reconciled,
}
```

These types are illustrative constraints, not authorization to add them before
the cross-domain report. Domain policy evaluators should remain concrete until
their common shape is proven.

## CI and conformance enforcement

Add an authoritative `xtask` policy-conformance command and include it in
`cargo xtask ci`.

Every bounded policy version must register:

- owning package and architectural layer;
- policy type, version, canonicalization, and evaluator identifiers;
- canonical valid and invalid policy fixtures;
- exact action and evidence fixtures;
- boundary decision vectors;
- mutation corpus;
- stable denial and indeterminate codes;
- explanation renderer tests;
- required/executed evaluator and configuration tests;
- reservation lifecycle and concurrency tests;
- replay and reconciliation tests;
- receipt commitments;
- hard byte, item, depth, time, and work limits;
- fuzz target;
- native/WASM or other binding parity where applicable;
- compliance claims mapping every guarantee to tests.

CI must also enforce:

- fixtures are generated by repository tooling rather than hand edited;
- decode/re-encode produces identical canonical bytes;
- tightening a policy cannot authorize a newly permitted action;
- delegation cannot widen authority;
- reference and optimized implementations agree;
- provider adapters cannot accept unverified action types;
- credential brokers require completed authorization and reservation;
- demos expose inline and dedicated receipt interfaces;
- local end-to-end browser tests exercise the real backend.

Performance regression checks must use stable exact fixtures. Noisy wall-clock
thresholds should not be the only gate; also track allocations, encoded sizes,
work counters, and deterministic structural limits. Scheduled benchmark jobs
may report p50, p95, and p99 trends without weakening correctness CI.

## Versioning and change control

A change to policy meaning requires:

1. a new evaluator or policy version;
2. new canonical fixtures and decision vectors;
3. compatibility and migration tests;
4. explicit required/executed behavior;
5. updated explanation rendering;
6. updated receipts when the commitment changes;
7. review of active standing grants and persisted reservations.

Never silently change the meaning of an existing field. Support explicit
dual-version execution during migration and remove an old evaluator only after
active grants, receipts, and reconciliation state no longer require it.

## Completion criteria

The bounded authorization abstraction is complete when:

- OpenTofu and PostgreSQL work end to end with real local effects and complete
  frontends;
- the seven-domain comparison proves every extracted lifecycle concept;
- canonical policy bytes and evaluator semantics are versioned;
- evidence-relative and aggregate bounds are demonstrated;
- reservations are atomic, persistent, crash recoverable, and reconcilable;
- credentials remain unavailable before authorization and reservation;
- provider adapters accept only verified commands;
- standing delegation UX is derived from the canonical policy;
- all demos expose inline and dedicated receipt views;
- reference and optimized paths agree on exact fixtures;
- performance work is measured and does not alter decisions or receipt bytes;
- architecture, compliance, wire, product, demos, bindings, and full CI pass.

The target is not a generic policy engine. It is a small set of proven,
versioned primitives that let domain integrations express broad agent
discretion inside exact, auditable, and enforceable boundaries.
