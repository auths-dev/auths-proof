# AP-SPEC-026: Reservation and execution state semantics

**Status:** Specified — implementation requires a separate Milestone 4 PR

**Depends on:** AP-SPEC-025, Closed bounded-authorization policy contract

**Evidence:** GitHub, Kubernetes, OpenTofu, PostgreSQL, Radicle, records API,
and Stripe reference implementations and frozen product fixtures

**Scope:** Product-layer durable decisions, atomic reservation, execution
intent, replay, revocation, expiry, credential ordering, provider attempts,
unknown outcomes, reconciliation, and lifecycle receipts

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on conforming implementations.

## 1. Decision

Auths will implement one narrow, versioned product-layer lifecycle contract
between pure policy eligibility and domain-owned provider execution.

The contract separates three kinds of truth:

1. the pure evaluator determined that one exact action is eligible;
2. a linearizable durable store reserved the required capacity or exclusivity;
3. a domain provider may or may not have performed the external effect.

None of these facts implies either of the others.

```text
core authorization + AP-SPEC-025 eligibility
                      |
                      v
              decision recorded
                      |
                      v
                  reserved
                      |
                      v
          execution intent recorded
                      |
                      v
                  executing
                 /    |     \
                v     v      v
         committed  released  outcome unknown
                                  |
                           fresh reconciliation
                              /         \
                             v           v
                  reconciled committed  reconciled released
```

Absence of a reservation record represents available capacity. `available` is
not a persisted lifecycle state.

This state machine provides at-most-one live logical execution authorization.
It does not claim that an external provider performs at most one effect unless
the registered domain provider contract supplies exact idempotency or
conditional-write semantics.

## 2. Goals

The implementation MUST:

- preserve AP-SPEC-025 action, policy, evaluator, evidence, and configuration
  commitments;
- durably record the decision before reservation;
- reserve every emitted intent atomically or reserve none;
- prevent capacity overcommit and duplicate exclusive claims;
- durably record an exact execution intent before credential acquisition;
- make replays return existing state and receipts without creating another
  execution authorization;
- retain capacity whenever an external effect may have occurred;
- distinguish definite non-effect, definite effect, and unknown outcome;
- require fresh, domain-owned evidence for reconciliation;
- keep credentials and provider behavior outside the shared state package;
- provide an executable reference transition relation and mechanically linked
  formal model;
- support conforming in-memory and durable store adapters; and
- preserve the existing domain implementations as migration oracles.

## 3. Non-goals

This specification does not define:

- a universal provider API or provider request union;
- domain actions, policies, evidence, postconditions, or receipt payloads;
- a distributed consensus protocol;
- the durability guarantees of PostgreSQL, SQLite, a filesystem, or a cloud
  database;
- provider atomicity, availability, or idempotency that the provider does not
  actually offer;
- automatic retry of an ambiguous external effect;
- credential formats, custody, or secret persistence;
- a universal numeric budget for every reservation;
- a generic workflow language;
- migration of any existing domain vertical; or
- changes to the core proof format or authority algebra.

## 4. Architectural ownership

The shared implementation belongs under `product/`. It MUST NOT move into
`core/`.

`core/` continues to establish proof validity, authority, attenuation,
composition, and exact action authorization.

`auths-bounded-policy` continues to own pure eligibility and immutable
reservation-intent commitments.

The Milestone 4 product package may own:

- lifecycle identities and commitment carriers;
- the pure reference transition relation;
- stage-sealed execution authorization;
- atomic reservation and lifecycle store ports;
- canonical shared lifecycle records and receipt envelopes;
- model, fault, concurrency, and adapter conformance tooling.

Each domain permanently owns:

- reservation key payloads and capacity meaning;
- cancellation, expiry, and revocation policy;
- exact verified commands;
- credential scopes and brokers;
- provider request construction and retry rules;
- provider idempotency or conditional-write contracts;
- effect, non-effect, and reconciliation evidence;
- domain receipt payloads and stable domain diagnostics.

The shared package MUST NOT import provider SDKs or dispatch arbitrary
callbacks.

## 5. Versioned identities

Milestone 4 reserves these immutable V1 identities:

| Meaning | Identity |
| --- | --- |
| Lifecycle contract | `auths.product.reservation-execution-contract/1` |
| Reservation key | `auths.product.reservation-key/1` |
| Lifecycle record | `auths.product.lifecycle-record/1` |
| Execution intent | `auths.product.execution-intent/1` |
| Execution authorization | `auths.product.execution-authorization/1` |
| Provider attempt record | `auths.product.provider-attempt/1` |
| Reconciliation observation | `auths.product.reconciliation-observation/1` |
| Lifecycle receipt envelope | `auths.product.lifecycle-receipt-envelope/1` |
| Store contract | `auths.product.lifecycle-store-contract/1` |
| Transition semantics | `auths.product.lifecycle-transition/1` |

Changing state meaning, transition legality, reservation identity, capacity
accounting, retry behavior, receipt ordering, or canonical bytes requires a
new semantic identity.

Implementation/build provenance remains separate from semantic identity and
MUST be recorded in receipts.

## 6. Commitment types

The implementation MUST use distinct types for:

- workflow identity;
- reservation identity;
- execution identity;
- reconciliation identity;
- exact action digest;
- policy digest;
- evaluator semantic identity;
- evidence digest;
- required configuration digest;
- executed configuration digest;
- decision receipt digest;
- reservation-intent-set digest;
- obligation-set digest;
- execution-intent digest;
- provider request digest;
- provider idempotency or condition digest;
- provider result digest;
- observation digest;
- lifecycle receipt digest.

Unrelated digest types MUST NOT compare accidentally.

Each digest carrier MUST identify its algorithm or be enclosed by a versioned
schema whose algorithm is immutable. V1 MAY begin with SHA-256, but APIs MUST
NOT assume that every future commitment, signature, or encryption scheme uses
one fixed algorithm.

## 7. Reservation identity

`ReservationKeyV1` binds:

```text
contract identity
domain/profile identity
workflow identity
exact action digest
policy type/version/digest
evaluator semantic identity
reservation intent schema and intent identity
domain scope digest
reservation kind and unit
window identity when present
executor audience
```

The reservation ID is the domain-separated digest of canonical reservation-key
bytes.

For a single eligible action, every reservation intent MUST be reserved in one
linearizable all-or-none operation. Sorting is by canonical reservation key.
Duplicate keys, duplicate intent IDs, and conflicting units fail closed before
state mutation.

Two requests with the same workflow identity but different bound commitments
are a conflict, not a replay.

## 8. Reservation algebras

V1 supports only closed registrations composed from:

### 8.1 Additive capacity

An additive reservation names an exact unit and non-zero integer amount.
Under one registered scope and window:

```text
committed
+ reserved
+ executing
+ outcome_unknown
<= ceiling
```

All arithmetic is checked. Overflow, underflow, unit mismatch, missing
capacity, or contradictory snapshots produce no mutation.

`reconciled_committed` contributes to committed use.
`reconciled_released` and `released` do not consume capacity.

### 8.2 Exclusive claim

An exclusive reservation allows at most one live reservation for the exact
scope. Reserved, executing, and outcome-unknown records are live.

Committed exclusivity remains held or is retired according to the registered
domain algebra. The shared layer MUST NOT guess whether a completed Git ref,
database row transition, rollout, or patch continues to exclude another
operation.

### 8.3 Composite reservation

A composite is a bounded ordered set of additive and exclusive intents.
Composition changes only atomicity: every intent succeeds or none does.
It does not create a new universal domain meaning.

Arbitrary user callbacks and runtime-loaded reservation algebras are
forbidden. Every algebra is registered by exact semantic identity with Rust,
Lean, fixture, and migration evidence.

## 9. Lifecycle record

`LifecycleRecordV1` contains commitments rather than domain payloads:

```text
schema and semantic identities
implementation identity
workflow, reservation, and execution identities
profile and executor audience
action, policy, evaluator, evidence, and state commitments
required and executed configuration commitments
decision receipt commitment
reservation and obligation set commitments
reservation records and capacity units
revocation and expiry snapshot commitments
current lifecycle state
monotonic record revision
created and updated verifier times
execution-intent commitment when present
provider attempt commitments when present
terminal result or reconciliation commitment when present
previous lifecycle receipt commitment
```

Unknown fields, missing required fields, duplicate entries, unsupported
versions, non-canonical order, invalid transitions, and digest mismatch MUST
fail closed.

Domain payloads MAY be stored alongside the record by a domain adapter, but
their canonical schemas and confidentiality remain domain-owned.

## 10. States

The closed V1 states are:

- `decision-recorded`;
- `reserved`;
- `execution-intent-recorded`;
- `executing`;
- `committed`;
- `released`;
- `outcome-unknown`;
- `reconciled-committed`;
- `reconciled-released`.

`committed`, `released`, `reconciled-committed`, and
`reconciled-released` are terminal.

`outcome-unknown` is non-terminal for reconciliation but terminal for normal
execution and retry.

State values are not ordered integers. Legality is defined by the explicit
transition relation.

## 11. Legal transitions

### 11.1 Decision recording

An AP-SPEC-025 result may create `decision-recorded` only when:

- core authorization is authorized;
- policy result is eligible;
- required and executed configuration match;
- the action, policy, evaluator, evidence, state, reservation-intent, and
  obligation commitments are complete;
- the decision receipt is canonical and durably stored in the same transaction
  or before the lifecycle record.

Denied or indeterminate results cannot enter the lifecycle.

### 11.2 Atomic reservation

`decision-recorded -> reserved` atomically:

- revalidates the record revision and eligibility commitments;
- checks revocation and expiry at explicit verifier time;
- checks every reservation invariant against current durable state;
- reserves every intent or none;
- records the reservation receipt;
- returns a sealed reservation lease only to the winning caller.

Capacity failure, conflict, stale state, or store unavailability cannot leave a
partial reservation.

### 11.3 Execution intent

`reserved -> execution-intent-recorded` requires:

- the exact sealed reservation lease;
- a domain-produced verified command commitment;
- a provider request commitment;
- an exact idempotency, conditional-write, or non-retry contract commitment;
- rechecked revocation, expiry, configuration, and audience;
- durable recording before any credential is requested.

The command payload remains domain-owned. The shared layer seals its
commitments and does not construct provider requests.

### 11.4 Executing

`execution-intent-recorded -> executing` durably appends a provider attempt
before the provider call begins. The attempt records:

- monotonic attempt ordinal;
- execution and request commitments;
- idempotency or conditional material commitment;
- explicit start time;
- provider contract identity;
- no claim of delivery or acceptance.

After `executing` is durable, a crash or missing response is potentially
effectful. Recovery MUST NOT release capacity merely because no response was
stored.

### 11.5 Definite effect

`executing -> committed` requires domain evidence that the registered provider
contract classifies as a definite effect for the exact request.

The result commitment and execution receipt are durable before success is
reported to the caller.

### 11.6 Definite non-effect

`reserved -> released` is legal only when the registered cancellation contract
allows cancellation and no execution attempt exists.

`execution-intent-recorded -> released` is legal only when no execution attempt
exists or durable domain evidence proves the request was not sent.

`executing -> released` requires a registered provider result that proves
definite non-effect. A timeout, disconnect, process exit, or missing response
is not such proof.

### 11.7 Unknown outcome

`executing -> outcome-unknown` occurs when request delivery, provider
acceptance, or effect is ambiguous.

Recovery MUST also conservatively interpret an `executing` record without a
durable terminal result as outcome unknown.

Capacity and exclusivity remain held without time-based automatic release.

### 11.8 Reconciliation

`outcome-unknown -> reconciled-committed` requires fresh, canonical,
domain-owned evidence proving the exact effect.

`outcome-unknown -> reconciled-released` requires fresh, canonical,
domain-owned evidence proving non-effect.

Unavailability, staleness, contradiction, an unrelated provider object, or an
inconclusive query leaves the record unchanged in `outcome-unknown`.

A domain MAY permit reconciliation from `reserved` or
`execution-intent-recorded` after crash recovery only by first proving whether
an execution attempt could have started. Ambiguity is promoted to
`outcome-unknown`, never silently released.

## 12. Illegal transitions

The following are always illegal:

- any non-terminal state back to `decision-recorded`;
- `released` to any effectful state;
- `committed` to released;
- either reconciled state to another state;
- outcome unknown directly to committed or released without a reconciliation
  observation;
- creating a second execution identity for replay;
- changing any bound commitment after decision recording;
- changing reservation amount, unit, scope, or window after reservation;
- changing provider request or idempotency material after execution intent;
- deleting or replacing an earlier attempt;
- acquiring credentials before execution intent is durable;
- provider I/O before the attempt record is durable.

Illegal transition requests return stable failure information and perform no
mutation.

## 13. Replay and conflict

Replay is determined by exact workflow identity plus every bound semantic
commitment.

For an exact replay:

- the existing lifecycle record is returned;
- the original decision and lifecycle receipt commitments are returned;
- the existing reservation and execution identities are reused;
- provider idempotency or conditional material is unchanged;
- no new credential is issued solely because of the replay;
- no new provider attempt occurs unless the registered provider contract
  explicitly permits a same-request retry from the current state.

For the same workflow identity with any different commitment:

- the result is `conflict`;
- existing state is unchanged;
- no capacity, credential, or provider boundary is entered.

HTTP retries, queue redelivery, process restart, and delivery over a different
transport do not change these rules.

## 14. Revocation and expiry

Revocation and expiry are explicit inputs, not hidden clocks or network reads
inside the pure transition kernel.

Revoked or expired authority:

- cannot record a new eligible decision;
- cannot create a reservation;
- cannot create a new execution intent;
- cannot authorize a new credential or provider attempt.

A registered domain cancellation contract decides whether an already reserved,
not-yet-executing action may release.

Revocation or expiry MUST NOT release executing or outcome-unknown capacity.
Those states require definite non-effect or reconciliation.

Committed effects and historical receipts are not erased by later revocation.

Rolling-window capacity may age out only when the registered algebra proves the
usage is outside the window and is not reserved, executing, or outcome
unknown.

## 15. Credential ordering

The credential broker accepts only a sealed `ExecutionAuthorizationV1`.

That value binds:

- core authorization result;
- AP-SPEC-025 eligibility result;
- exact action, policy, evaluator, evidence, and configuration commitments;
- decision receipt;
- complete reservation set and reservation receipt;
- verified command and execution-intent commitments;
- provider contract, audience, and expiry;
- current lifecycle record identity and revision.

The value has no public constructor from untrusted fields.

Credential acquisition is a trace event after durable
`execution-intent-recorded`. Credential bytes:

- MUST NOT be stored in lifecycle records or receipts;
- MUST NOT implement ordinary debug or serialization;
- MUST be scoped to the exact domain operation where the provider supports it;
- MUST expire no later than the execution authorization;
- MUST NOT be returned for denied, indeterminate, conflict, released,
  committed, or outcome-unknown state.

Possession of a Rust stage type alone is not proof of durability. Tests and
formal traces must include the store acknowledgement that precedes credential
acquisition.

## 16. Provider execution contracts

Every domain registers one closed, versioned provider contract for an
execution profile. It declares:

- request canonicalization and equality;
- idempotency-key or conditional-write scope;
- retention window;
- whether same-key/different-request is rejected;
- which responses prove effect;
- which responses prove non-effect;
- which failures are ambiguous;
- whether and when retry is legal;
- reconciliation query and evidence semantics.

The contract selects one retry class:

- `exact-idempotent`: the provider guarantees the same exact request and key
  cannot create another logical effect within the declared window;
- `conditional`: the provider atomically enforces an exact precondition;
- `observe-before-retry`: no retry until reconciliation proves non-effect;
- `non-retryable`: ambiguity requires operator/domain reconciliation and never
  an automatic retry.

The shared runtime MUST NOT upgrade a weaker provider into
`exact-idempotent`.

Multiple transport attempts remain multiple attempts in the event trace and
receipts, even when the provider deduplicates their logical effect.

## 17. Reconciliation evidence

A reconciliation observation binds:

```text
reconciliation schema and semantic identity
lifecycle and execution identities
provider account/resource scope
provider request and idempotency commitments
observation source and adapter identity
observation time and freshness policy
canonical observation digest
conclusion: effect | non-effect | inconclusive
```

Only `effect` and `non-effect` conclusions may resolve outcome unknown.
`inconclusive` is durable evidence but does not change capacity.

Observation of a semantically similar effect is insufficient. Evidence must
bind the exact action or provider request according to the registered domain
contract.

## 18. Receipts and ordering

Lifecycle receipt envelopes form a hash-linked sequence:

1. decision recorded;
2. reservation committed;
3. execution intent recorded;
4. provider attempt started;
5. committed, released, or outcome unknown;
6. reconciliation observation and terminal reconciliation when applicable.

Each envelope binds:

- lifecycle schema and semantic identity;
- lifecycle record identity and revision;
- previous envelope digest;
- transition source and destination;
- triggering command/event commitment;
- verifier time;
- required and executed configuration;
- implementation identity;
- domain receipt digest when one exists.

Shared envelopes do not replace canonical domain receipts. They MUST NOT claim
provider acceptance, execution, or reconciliation without the corresponding
domain evidence.

Receipt persistence and state transition MUST be atomic, or recovery MUST be
able to reproduce the same canonical receipt without changing the transition.

## 19. Store contract

A conforming store provides:

- linearizable lookup by workflow and reservation identity;
- compare-and-swap on monotonic record revision;
- atomic multi-intent reservation;
- atomic state transition plus lifecycle-receipt append;
- durable acknowledgement semantics;
- bounded records and indexes;
- exact replay and conflict results;
- crash-safe reopen;
- corruption and non-canonical-state rejection;
- deterministic snapshot and history export.

The logical record uses canonical, versioned bytes. Storage-engine framing,
indexes, transactions, and replication metadata are adapter-owned and excluded
from the semantic digest.

A store MUST state what “durable” means. File-backed adapters must address file
contents, atomic replacement, and parent-directory durability. Database
adapters must state isolation, transaction, constraint, and commit
acknowledgement assumptions.

Lean proofs are conditional on this store contract. An adapter is not described
as mechanically verified unless its actual engine behavior is mechanically
connected.

## 20. Concurrency and linearizability

Concurrent operations must have a valid sequential history respecting real-time
ordering.

Required histories include:

- two exact replays;
- same workflow with different action;
- two workflows competing for final additive capacity;
- two workflows competing for one exclusive key;
- composite reservation where one intent lacks capacity;
- reserve racing revocation or expiry;
- execution-intent creation racing cancellation;
- commit racing outcome-unknown;
- reconciliation racing replay;
- two reconcilers with contradictory observations;
- restart while another process holds final capacity.

Exactly one contender may receive a new live reservation or execution
authorization where capacity permits only one.

## 21. Crash model

Fault injection MUST cover a crash immediately before and after:

- decision receipt persistence;
- lifecycle record creation;
- atomic reservation;
- reservation receipt persistence;
- execution-intent persistence;
- credential request;
- provider-attempt persistence;
- provider call entry;
- provider call return;
- terminal-state persistence;
- terminal receipt persistence;
- reconciliation observation persistence;
- reconciled-state persistence.

After every restart:

- canonical state reopens or fails closed as corrupt/unavailable;
- reserved capacity is not duplicated or lost;
- an exact replay returns the same identity;
- a possibly delivered provider request is not released;
- receipt order and record revision remain consistent;
- no credential or provider call occurs from an uncommitted stage.

## 22. Stable shared failures

V1 reserves these shared mechanical causes:

- `lifecycle-malformed`;
- `lifecycle-unsupported-version`;
- `lifecycle-configuration-mismatch`;
- `lifecycle-not-eligible`;
- `lifecycle-revoked`;
- `lifecycle-expired`;
- `lifecycle-replay`;
- `lifecycle-conflict`;
- `lifecycle-capacity-exceeded`;
- `lifecycle-illegal-transition`;
- `lifecycle-store-unavailable`;
- `lifecycle-state-corrupt`;
- `lifecycle-credential-unavailable`;
- `lifecycle-provider-definite-non-effect`;
- `lifecycle-outcome-unknown`;
- `lifecycle-reconciliation-stale`;
- `lifecycle-reconciliation-conflict`;
- `lifecycle-limit-exceeded`.

Domains may project these into existing stable codes, but projection is
versioned and tested. Store unavailability, missing trustworthy evidence, and
inconclusive reconciliation do not become authorization denial facts.

## 23. Hard limits

V1 enforces:

| Value | Maximum |
| --- | ---: |
| Workflow identifier | 256 bytes |
| Domain/profile/provider-contract identifier | 128 bytes |
| Reservation or execution identity | 64 bytes |
| Reservation intents | 32 |
| Provider attempts per execution | 16 |
| Reconciliation observations | 32 |
| Lifecycle events retained in one canonical record | 128 |
| Canonical lifecycle record | 256 KiB |
| Canonical domain payload referenced by conformance tooling | 1 MiB |
| Nested composite reservation depth | 16 |

Empty identifiers, zero additive reservations, invalid UTF-8 where text is
required, unknown fields, duplicate entries, invalid ordering, and values over
these limits fail before mutation.

Implementations MUST expose deterministic work counters for validation,
reservation-intent inspection, transition checks, and history inspection.

## 24. Reference transition kernel

Milestone 4 implementation begins with a simple, total, deterministic
transition kernel.

Inputs contain:

- one validated lifecycle record or absence;
- one closed transition command;
- explicit verifier time;
- revocation/expiry snapshot;
- exact current capacity snapshot;
- exact reconciliation observation when required.

Outputs contain:

- next record and receipt commitments;
- unchanged replay record;
- stable conflict/failure; or
- indeterminate store/evidence requirement.

The kernel performs no I/O, allocation without declared bounds, hidden clock
read, credential access, or provider call.

The runtime and store adapter execute the kernel result transactionally. The
kernel does not claim persistence merely because it returned a next state.

## 25. Formal model and mechanical link

Lean MUST model:

- the closed states and transition relation;
- append-only event traces;
- additive, exclusive, and composite reservation invariants;
- replay and conflict identity;
- revocation and expiry gates;
- credential and provider-event ordering;
- unknown-outcome retention;
- reconciliation refinement;
- record revision and receipt-chain monotonicity.

Required theorems include:

- legal transitions preserve state well-formedness;
- additive active plus committed use never exceeds capacity;
- exclusive scopes have at most one live owner;
- failed composite reservation changes no intent;
- one workflow has at most one live execution identity;
- exact replay cannot create a second reservation or provider attempt;
- conflict changes no state;
- credentials occur only after durable decision, reservation, and execution
  intent events;
- provider calls occur only after durable attempt events;
- outcome unknown retains every affected reservation;
- release requires a trace proving non-effect;
- commit and release are mutually exclusive;
- reconciliation preserves conservation;
- terminal states cannot transition;
- record revisions and receipt links are monotonic.

Shipping pure Rust transition predicates MUST be translated through the pinned,
qualified Aeneas route and proved to refine the Lean model.

Kani MUST cover finite representation and transition obligations. Property
tests and model checking remain defense in depth; they do not substitute for
the refinement proof.

## 26. Reference stores

Milestone 4 includes:

1. an in-memory reference store for deterministic model testing;
2. one crash-persistent local store;
3. a transactional multi-process conformance adapter.

The persistent local store MUST use atomic replacement or an append protocol,
sync the durable payload, address directory durability, reject non-canonical or
oversized state, and survive fault injection.

The transactional adapter MUST demonstrate:

- schema constraints encode legal identity and uniqueness;
- serializable or proven-equivalent isolation for reservation;
- atomic multi-intent capacity accounting;
- process-level concurrency on final capacity;
- restart and transaction-abort behavior;
- exact replay and conflict after reconnect.

The product package defines ports and conformance suites, not a mandatory
production database.

## 27. Domain registration and migration

The machine registry extends each AP-SPEC-025 evaluator registration with:

- reservation algebra identity;
- reservation-key schema;
- cancellation/revocation/expiry semantics;
- execution-intent schema;
- verified-command symbol;
- credential-broker boundary;
- provider contract identity and retry class;
- reconciliation semantic identity;
- lifecycle and domain receipt schemas;
- reference store/evaluator paths;
- formal, model, Kani, fault, concurrency, and fixture evidence;
- migration status.

Milestone 4 creates the shared reference implementation but does not migrate a
domain production path.

Milestone 5 migrates in this order:

1. Stripe;
2. Kubernetes;
3. PostgreSQL;
4. OpenTofu;
5. GitHub;
6. Radicle;
7. records create and read as separate profiles.

Each migration keeps the previous implementation as an oracle until exact
differential evidence passes. A provider change in Radicle, Stripe, or another
domain affects its adapter and provider contract; it does not silently change
the shared transition semantics.

## 28. Conformance

The canonical conformance corpus includes:

- every legal transition;
- every illegal edge from every state;
- exact replay and mutated conflict;
- zero, one, exact maximum, and maximum-plus-one capacity;
- overflow and underflow;
- additive, exclusive, and composite reservations;
- revocation and expiry at each pre-effect stage;
- exact attempt limit and one over;
- definite effect, definite non-effect, and ambiguous delivery;
- unknown outcome across restart and elapsed time;
- fresh, stale, contradictory, and unrelated reconciliation;
- intent deletion, insertion, reordering, and digest mutation;
- required/executed configuration mutation;
- receipt deletion, reordering, and link mutation;
- corruption, truncation, duplicate state, and unsupported version;
- the complete crash and concurrency matrices.

Every discovered mismatch retains its smallest regression input.

CI MUST reject drift in:

- lifecycle identities and registry;
- canonical fixtures and manifests;
- transition tables and stable failures;
- Lean theorem inventory;
- generated Aeneas output and source closure;
- Kani/model/fuzz target inventory;
- store-conformance and fault matrices;
- allocation/work ceilings.

## 29. Acceptance criteria

The specification-only PR is complete when:

- all states, transitions, failures, limits, and trusted boundaries are
  explicit;
- provider effect and store durability claims are accurately conditional;
- all seven domains can register or compose the contract without moving their
  provider semantics into shared code;
- AP-SPEC-025 eligible is never described as execution authorization;
- the implementation PR can be reviewed against this contract without open
  semantic questions.

The Milestone 4 implementation is complete only when:

- the reference transition kernel and stage-sealed APIs implement this
  specification;
- Lean and the mechanically translated shipping Rust agree;
- in-memory, persistent local, and multi-process store conformance pass;
- model, Kani, mutation, fuzz, crash, and concurrency evidence pass;
- no credential or provider call is reachable before required durable stages;
- outcome-unknown capacity survives restart until fresh reconciliation;
- existing domain verticals remain unchanged and passing;
- architecture, compliance, formal, authoritative, and required live CI pass;
- the implementation PR is merged to `main`.

## 30. Residual assumptions and claim language

The formal result is conditional on:

- correctness of cryptographic primitives and canonical codecs;
- the registered domain reservation algebra and provider contract;
- store linearizability and durability at its documented boundary;
- provider evidence accurately establishing effect or non-effect;
- credential broker enforcement.

Until a store or provider is mechanically connected, describe it as conforming
under tested and reviewed assumptions, not formally verified.

The allowed claim after Milestone 4 is:

> The shipping pure lifecycle kernel refines the formal transition semantics,
> and conforming store and provider adapters preserve the stated reservation,
> replay, ordering, and unknown-outcome invariants under their explicit
> contracts.

Do not claim that Lean proves PostgreSQL durability, filesystem behavior,
Stripe, Kubernetes, GitHub, Radicle, OpenTofu, or any other external system.
