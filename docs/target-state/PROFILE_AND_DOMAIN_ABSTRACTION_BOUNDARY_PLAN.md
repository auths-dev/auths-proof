# Profile and Domain Abstraction Boundary Plan

## Status

Target-state architectural plan.

This document defines how Auths Proof adds profiles, profile families, and
provider domains without prematurely coupling their semantics. It generalizes
the vertical-package decisions already used by the GitHub, Radicle, Stripe,
Kubernetes, OpenTofu, and PostgreSQL work.

The governing rule is:

> Build complete vertical semantics first. Extract shared mechanisms only
> after independent implementations prove that their contracts are identical.

Auths-proof is prelaunch and has no users or production state. Until that
changes, architectural “migration” means a direct source cutover to one
authoritative implementation. Do not add legacy readers, dual writes,
compatibility shims, deprecation windows, state converters, runtime rollback
paths, or obsolete API support. Reject obsolete disposable state and start
local and CI environments from empty state.

This does not relax canonical exactness, semantic identities, fixtures, or
differential tests. Those protect the correctness of the current contract; they
do not create a promise to accept superseded prelaunch formats.

This is not an argument against reuse. It is a process for ensuring that reuse
preserves exact authorization, state, effect, and receipt meaning instead of
merely reducing similar-looking code.

## Why this boundary exists

Authorization integrations often appear structurally identical:

```text
request -> policy check -> credential -> provider call -> result
```

That similarity is deceptive. A Stripe authorization hold, Kubernetes rollout,
OpenTofu saved-plan apply, PostgreSQL update, and GitHub pull request differ in:

- what constitutes the exact action;
- which external evidence is authoritative;
- how freshness and conflicts are interpreted;
- which capacity or obligation is reserved;
- when execution becomes irreversible;
- what an ambiguous provider response means;
- which facts permit retry, release, or reconciliation;
- which credential is minimally sufficient;
- what the receipts can truthfully claim.

A generic framework introduced from the common diagram tends to encode these
differences as operation tags, optional fields, callbacks, or loosely typed
JSON. That moves security semantics out of types and into runtime convention.
It also makes later formal claims apply to an attractive shape rather than the
shipping behavior.

Small, visible duplication is cheaper than an incorrect security abstraction.
Duplication can be compared and extracted later. Premature coupling can make a
single mistake silently affect every domain.

## Vocabulary

This plan uses the following terms:

- **Domain**: one external system or tightly coherent provider boundary, such
  as GitHub, Stripe, Kubernetes, OpenTofu, PostgreSQL, or Radicle.
- **Profile family**: profiles that intentionally share a closed policy
  carrier or lifecycle context inside one domain.
- **Profile**: one versioned exact-action authorization contract.
- **Effect**: one provider mutation or decision derived only from a verified
  command.
- **Mechanism**: implementation behavior whose contract does not depend on
  domain meaning, such as checked arithmetic, compare-and-swap persistence, or
  canonical digest handling.
- **Semantic abstraction**: shared code that decides authorization, state
  transitions, obligations, provider behavior, or receipt meaning.
- **Vertical**: the complete path from canonical action and policy through
  execution, observation, receipts, frontend, and live tests.

## Architectural decision

### Vertical package first

New domain semantics begin in one cohesive product package:

```text
product/integrations/auths-<domain>/
```

The package owns the domain vocabulary, profile families, exact actions,
evidence, pure evaluators, workflow transitions, provider ports, credential
ports, reconciliation, and domain receipts.

The package may be internally modular. It must not be scattered across generic
profile, runtime, store, receipt, and integration packages merely because each
directory name describes one responsibility.

Existing shared packages may provide narrow mechanisms. They do not acquire
ownership of domain resources, policy meaning, lifecycle states, or provider
outcomes.

### Profile-specific effect boundary

Every profile owns:

- its canonical action and bounded decoder;
- its immutable policy and evaluator commitments;
- its typed evaluator entry point;
- its denied and indeterminate semantics;
- its verified command;
- its transition function over shared or dedicated storage;
- its provider gateway and closed outbound request;
- its least-privilege credential scope;
- its orchestration and reconciliation rules;
- its profile receipts and stable codes;
- its fixtures, mutation corpus, live contract, and demo.

Two profiles may share a policy carrier without sharing an evaluator function.
They may share a store implementation without sharing transition semantics.
They may share a receipt envelope without sharing the fields or claims carried
inside it.

### Effect semantics do not dispatch from a generic operation tag

An operation identifier may appear in a canonical policy, profile identity, or
receipt. It must not select among unrelated evaluator, verified-command, or
executor behavior inside a generic runtime.

The prohibited shape is:

```text
GenericAction {
  operation,
  optional_fields_for_every_operation,
  arbitrary_provider_parameters
}
        |
        v
match operation {
  ...
}
```

The required shape is:

```text
ProfileAAction -> ProfileAEvaluator -> VerifiedACommand -> GatewayA
ProfileBAction -> ProfileBEvaluator -> VerifiedBCommand -> GatewayB
```

Shared leaf functions may appear beneath both paths after their contracts are
shown to be identical.

## The abstraction locality ladder

Code moves inward only as evidence becomes stronger:

```text
+--------------------------------------------------------------+
| One profile                                                  |
| Default home for new semantics                               |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| One profile family inside one domain                         |
| Shared closed policy carriers and proven lifecycle mechanics |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| One domain package                                           |
| Provider-local canonical leaves, adapters, stores, testkit    |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| Shared product packages                                      |
| Cross-domain mechanisms with differential evidence            |
+-------------------------------+------------------------------+
                                |
                                v
+--------------------------------------------------------------+
| Core                                                         |
| Portable, deterministic, domain-independent protocol meaning  |
+--------------------------------------------------------------+
```

Moving code down this ladder is an architectural promotion. It is not a
cleanup refactor.

### Profile to family

Promotion requires at least two implemented profiles with:

- the same canonical field meaning;
- identical boundary, missing-value, overflow, and freshness behavior;
- compatible tightening rules;
- the same state invariant where state is shared;
- differential fixtures proving no decision or receipt drift.

Similar names or common provider objects are insufficient.

### Family to domain

Promotion requires repeated use across independent families and evidence that
the candidate is provider-local mechanism rather than one family's semantics.
The domain-level API must remain closed and typed.

### Domain to shared product

The default review threshold is three implemented consumers spanning at least
two domains. Three examples are not proof of equivalence; they are the minimum
evidence needed to expose accidental assumptions.

Promotion additionally requires:

- a written cross-domain comparison;
- exact input, output, error, limit, and state contracts;
- differential tests against every existing implementation;
- direct source cutover without decision, command, or receipt drift;
- benchmarks showing that the abstraction does not impose unbounded work;
- test-only vertical reference evaluators and fixtures retained as semantic
  oracles.

A smaller promotion requires an ADR explaining why the behavior is already a
domain-independent primitive rather than inferred commonality.

### Product to core

Core promotion is allowed only when the type or function:

- is portable and deterministic from explicit inputs;
- has no network, filesystem, process, environment, wall-clock, credential, or
  mutable-service dependency;
- is meaningful without naming a provider or product workflow;
- is bounded for adversarial inputs;
- fits core dependency and `no_std` policy where classified;
- has canonical and formal semantics appropriate to the core claim.

Replay databases, reservations, live evidence, credentials, provider clients,
reconciliation, and operator workflows remain product concerns.

## Reuse classification

Every extraction candidate must first be classified:

| Classification | Meaning | Default action |
| --- | --- | --- |
| Identical mechanism | Inputs, outputs, errors, limits, and invariants are the same | Candidate for extraction |
| Structurally similar | Control flow resembles another implementation but semantics differ | Keep separate |
| Domain semantic | Meaning depends on provider resources or lifecycle | Keep in domain package |
| Profile semantic | Meaning changes the exact authorized effect | Keep profile-owned |
| Demo duplication | Deployment, layout, or test harness repetition | Extract outside production semantics |
| Accidental duplication | Byte-for-byte helper copied without semantic reason | Consolidate after focused tests |

An extraction proposal must identify its classification explicitly. “This code
looks repetitive” is not a classification.

## What may be shared early

Small leaf mechanisms may be shared before a full domain is complete when they
do not choose future policy or lifecycle design:

- canonical digest and fixed identifier carriers;
- bounded collection validation;
- checked integer arithmetic with explicit units;
- constant-time token comparison and secret zeroization;
- deterministic idempotency-key construction from explicit commitments;
- narrow atomic claim or compare-and-swap primitives;
- crash-safe file or database mechanics with no domain transition logic;
- receipt envelope serialization that does not erase domain fields;
- HTTP health/build metadata;
- frontend design tokens, receipt rendering, and browser-test utilities.

Even these require focused tests and stable failure behavior. A generic type
with many optional fields is not a leaf primitive.

## What must not be shared early

Keep these concrete until the extraction gate is met:

- policy languages and policy evaluators;
- evidence acquisition and freshness meaning;
- reservation allocation and release rules;
- obligations and lifecycle transitions;
- retry and unknown-outcome decisions;
- provider request construction;
- credential scopes and credential timing;
- postcondition and convergence interpretation;
- domain denial codes;
- profile receipt claims;
- generic workflow services that accept an operation tag and callbacks.

Framework inversion does not make semantics generic. Passing domain behavior as
traits, closures, or plugins can couple profiles just as strongly as a large
`match` statement.

## Vertical implementation workflow

### Phase 0: boundary specification

Before production code:

1. Define one exact profile and effect.
2. State the product and trust claim.
3. List explicit non-goals.
4. Define trusted, untrusted, and credential boundaries.
5. Define the canonical action, policy, evidence, and configuration.
6. Define denied versus indeterminate behavior.
7. Define reservation, claim, provider, observation, and reconciliation
   states.
8. Define stable codes and receipt claims.
9. Define hard byte, collection, work, time, and concurrency limits.
10. Define a real local effect and understandable frontend demonstration.

If two effects require different evidence, credential scopes, provider
commands, obligations, or reconciliation, they are separate profiles.

### Phase 1: closed reference semantics

Implement the pure, concrete evaluator first:

```text
canonical policy
+ exact action
+ trusted evidence
+ required configuration
+ executed configuration
+ explicit state snapshot
+ explicit time
        |
        v
eligible | denied(code) | indeterminate(code)
+ reservations
+ obligations
```

This implementation becomes the oracle for later refactors and optimizations.
Do not begin by implementing a generic evaluator interface.

### Phase 2: durable exact-effect boundary

Implement the ordered stateful path:

```text
fresh evidence
  -> exact proof verification
  -> profile evaluation
  -> durable decision
  -> atomic reservation
  -> exact-action claim
  -> least-privilege credential
  -> fresh critical re-read
  -> closed provider command
  -> durable provider result
  -> observation
  -> commit, release, unknown, or reconcile
```

Required and executed configurations must be equal before persistence,
reservation, credential acquisition, or provider I/O. A provider's
idempotency mechanism supplements but never replaces Auths replay and
reservation state.

### Phase 3: complete vertical demonstration

The demo must include:

- a real native backend;
- a real local or sandboxed provider effect;
- Docker-local operation through an HTTP `localhost` URL;
- a complete frontend connected to the native backend;
- controls and current result visible together;
- exact-boundary, boundary-plus-one, stale/mutated evidence, configuration
  mismatch, replay, unknown-outcome, and reconciliation scenarios;
- inline canonical receipt JSON;
- a designed dedicated receipt page;
- browser end-to-end tests;
- public deployment when the domain can be demonstrated safely and
  economically.

A static page, fixture-only service, backend-only implementation, or `file://`
frontend is not a completed vertical.

### Phase 4: evidence closure

Close the profile with:

- canonical valid and invalid fixtures;
- mutation corpus;
- property and arithmetic tests;
- denial-before-credential tests;
- provider-request equality tests;
- concurrent final-capacity tests;
- crash-before/after-delivery and restart tests;
- replay and reconciliation tests;
- architecture and compliance registration;
- secret and sensitive-data scanning;
- redacted deployment evidence;
- authoritative CI on the exact revision.

The implementation remains profile-local after completion. Completion creates
evidence for abstraction; it does not automatically authorize abstraction.

### Phase 5: comparison before extraction

When duplication appears, write a comparison before changing code. For every
candidate surface, compare:

- canonical representation;
- semantic meaning;
- denial and indeterminate cases;
- hard limits and work;
- state transitions;
- concurrency behavior;
- crash behavior;
- credential timing;
- provider effect;
- observation and reconciliation;
- receipt commitments;
- UX explanation.

Classify each field as identical, analogous, or domain-specific. Extract only
the identical subset.

## Abstraction case file

Every non-trivial semantic extraction must include one review artifact that
records:

1. Candidate abstraction and intended owning layer.
2. All current consumers.
3. The exact contract shared by those consumers.
4. Assumptions deliberately excluded from the contract.
5. Comparison table with identical and divergent behavior.
6. Versioning and compatibility rules.
7. Formal and executable invariants.
8. Reference fixtures and differential tests.
9. Prelaunch cutover plan, including obsolete-state rejection and confirmation
   that no compatibility or runtime rollback machinery is being added.
10. Performance measurements.
11. Why composition of smaller primitives is insufficient.
12. The code that will remain domain- or profile-owned.

The reviewer must be able to reject the abstraction without blocking continued
vertical development.

## Machine-enforced inventories

Human plans explain intent; executable inventories prevent drift.

A domain with multiple profiles, shared budgets, cross-profile obligations, or
non-trivial reconciliation must register a machine-readable profile inventory
validated by `xtask` and compliance CI. The inventory must record:

- domain and owning package;
- profile and family identifiers and versions;
- evaluator and canonicalization identities;
- specification and implementation status;
- exact action type;
- typed evaluator entry point;
- verified command;
- lifecycle transition;
- state store or reservation family;
- provider gateway;
- credential scope;
- effect identity;
- receipt type and stable code family;
- fixture and mutation corpus;
- demo and live-test locations;
- explicit profile dependencies;
- allowed shared mechanisms;
- profile-owned surfaces;
- prohibited shared semantics.

CI should reject:

- duplicate semantic identities;
- undeclared profile dependencies;
- family membership drift;
- inventory/specification mismatch;
- a profile marked implemented without its fixtures, demo, compliance claims,
  and tests;
- a profile-specific gateway, command, credential scope, transition, or
  receipt reused under an unrelated profile;
- new reverse dependencies or demo-to-production dependencies.

`architecture.toml`, `compliance.toml`, workspace metadata, and `xtask` remain
the executable repository authority. A domain inventory supplements them; it
does not bypass them.

## Formal assurance

Formalization follows stable semantics and risk, not code deduplication.

### During vertical implementation

Use:

- property tests for parsers, tightening, arithmetic, and transition laws;
- Kani for bounded representation and state-machine obligations;
- mutation tests for security-relevant branches;
- exact fixtures and work counters for deterministic conformance.

The initial formal target is the concrete pure evaluator and transition
relation, not a hypothetical universal policy engine.

### Before semantic extraction

For stable shared candidates, model and prove the applicable laws:

- tightening cannot expand eligibility or reservations;
- authority and delegation remain downward closed;
- arithmetic cannot wrap, underflow, or hide rounding;
- capacity is conserved across reserve, commit, release, unknown, and
  reconcile;
- replay cannot create a second effect;
- required/executed mismatch stops before credentials and provider I/O;
- optimized representations refine the reference semantics.

Follow specification 0011 for the Rust-to-Lean link. An independently written
Lean model improves understanding but does not prove that shipping Rust
implements it. Shared semantic claims require translated or generated pure
Rust predicates, representation invariants, and refinement evidence.

Provider systems remain explicit nondeterministic boundaries. Formal models
reason about allowed commands, recorded outcomes, observations, and
reconciliation. They must not assume that a networked provider is atomic or
deterministic when it is not.

### Formal abstraction is also gated

Do not introduce a generic Lean policy algebra merely because several Rust
structs have limits and allowlists. First establish the concrete relations,
then extract the smallest common relation and prove each domain instance
refines it.

## Performance and optimization

Optimize only after measuring a completed vertical.

Safe early optimizations include bounded decoding, precomputed immutable
digests, indexed membership, allocation reduction, batched durable writes, and
avoiding repeated canonicalization. Every optimized path must remain
differentially checked against the reference implementation.

Do not weaken:

- durable reservation or receipt ordering;
- fresh critical evidence;
- configuration equality;
- denial-before-credential behavior;
- unknown-outcome retention;
- exact provider command derivation;
- receipt completeness.

Latency does not make two semantic contracts equivalent.

## UX contract

Presentation may share a common grammar without sharing domain semantics:

```text
+-----------------------------+-----------------------------+
| Bounded authority           | Exact proposed action       |
| scope, limits, validity     | target, change, commitments |
+-----------------------------+-----------------------------+
| decision | reserve | credential | provider | observation |
+-----------------------------------------------------------+
| domain-specific capacity, obligation, or lifecycle state  |
+-----------------------------------------------------------+
| inline canonical JSON                 [Designed receipt]  |
+-----------------------------------------------------------+
```

Shared frontend components may render canonical policy fields, stage
progression, raw receipts, and receipt links. Domain packages own the language
that explains what the action changes, what external evidence means, and what
obligations remain.

The UI must never collapse authorization, provider acceptance, and observed
success into one verdict.

## API contract

Demo and product APIs may share route conventions:

```text
GET  /healthz
GET  /readyz
POST /api/v1/sessions
GET  /api/v1/sessions/{id}
POST /api/v1/sessions/{id}/execute
POST /api/v1/sessions/{id}/reconcile
GET  /api/v1/receipts/{id}
GET  /receipts/{id}
```

This does not authorize a generic execution payload. Public calls select
closed, repository-owned experiments or submit a profile-specific canonical
request. They do not provide arbitrary provider endpoints, verbs, parameters,
commands, SQL, manifests, credentials, headers, URLs, metadata, or idempotency
keys.

Profile-specific preview, evidence, webhook, timeline, and test-control routes
remain explicit.

## Examples of correct separation

### GitHub and Radicle

Both manipulate Git repositories and issue workflows. They may share Git
object validation leaves after equivalence is proven. They do not share a
generic repository executor: identity, remote state, publication effects, and
reconciliation differ.

### Kubernetes and OpenTofu

Both change infrastructure. Kubernetes authorizes exact API object mutations
against resource versions. OpenTofu authorizes an opaque saved plan against
backend state and dependency locks. They may eventually share reservation and
receipt mechanisms, not a generic infrastructure action.

### Stripe collect and authorize

Both use PaymentIntents and may share a closed merchant policy carrier.
Collection settles a payment; authorization creates a time-bounded hold and
obligation. Their verified commands, gateways, transitions, credentials, and
receipts remain distinct.

### PostgreSQL and GitHub

Both may use an exact before-state and compare-and-swap mechanics. Row
predicates, transaction isolation, Git object identity, and publication
postconditions remain domain semantics.

## Agent and reviewer checklist

Before creating shared code, answer:

1. How many completed consumers exist?
2. Are they independent domains or variants of one implementation?
3. Which exact semantics are identical?
4. Which behavior merely looks structurally similar?
5. Does the API require an operation tag, optional union, callback, or loosely
   typed payload?
6. Would a new provider outcome require changing the shared state machine?
7. Can every consumer retain its exact denial codes and receipt claims?
8. Are reference fixtures and differential tests available?
9. Is the candidate in the lowest valid architectural layer?
10. What evidence proves the source cutover preserves current semantics?
11. What formal claims become stronger or weaker?
12. Can the source change be independently reverted before release without
    inventing a second runtime path?

If these questions do not have concrete answers, keep the code vertical.

## Change and exception protocol

A semantic abstraction requires:

1. the abstraction case file;
2. an explicit owning layer and package;
3. inventory and compliance updates;
4. architecture dependency review;
5. differential fixtures and source-cutover tests;
6. formal-assurance impact review;
7. performance evidence;
8. one atomic PR containing consumers and enforcement.

Exceptions require an ADR. An exception cannot weaken exactness, fail-closed
behavior, hard limits, credential ordering, replay, reservation durability,
unknown-outcome handling, or receipt truth.

Refactors that only share presentation, deployment, or test infrastructure do
not require the full semantic process, but they must remain dependencies of
demos rather than sources of production truth.

## Completion condition

This boundary is working when:

- new domains begin as cohesive vertical packages;
- every exact effect has a profile-owned typed path;
- domain inventories and compliance evidence agree;
- abstractions are supported by several completed verticals;
- source cutovers preserve exact decisions, commands, state, and receipts;
- formal claims refer to shipping predicates and stable semantics;
- shared code becomes smaller and more precise rather than more configurable;
- agents can add domains without either copying the entire platform or
  weakening everything into a universal gateway.

The desired architecture is not maximum duplication and not maximum reuse. It
is a layered set of narrow, proven abstractions surrounded by explicit
domain-specific semantics.
