# Bounded Authorization Milestone 3 Readiness and Execution Plan

## Status

Execution plan.

This document governs the transition from completed domain verticals and rich
authority refinement into the shared bounded-authorization program. It is
written for agents implementing the work and defines:

- the order of work;
- when a specification is required before implementation;
- branch and pull-request boundaries;
- the evidence that must exist before extracting shared semantics;
- the definition of done for every step.

This plan does not authorize an agent to begin with a generic policy engine,
provider interface, workflow runtime, or reservation state machine.

## Governing documents

Read all of the following before planning or changing code:

1. `AGENTS.md`
2. `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`
3. `docs/target-state/BOUNDED_AUTHORIZATION_ABSTRACTION_PLAN.md`
4. `docs/specs/0011-rich-authority-refinement-and-bounded-authorization.md`
5. `docs/target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md`

The executable repository policies remain authoritative:

- `architecture.toml`;
- `compliance.toml`;
- the root workspace manifest and lockfile;
- machine-readable domain/profile inventories;
- `xtask`;
- canonical fixture manifests.

If this plan conflicts with executable repository policy, stop and resolve the
conflict explicitly. Do not weaken a check to make an implementation fit.

## Current readiness conclusion

Auths Proof has enough independent domain evidence to begin the bounded
authorization abstraction program:

| Domain | Distinguishing lifecycle evidence |
| --- | --- |
| GitHub | Multiple related effects and expected Git object identities |
| Radicle | Decentralized publication and observer-dependent confirmation |
| Stripe | Monetary limits, aggregate capacity, idempotency, and liabilities |
| Kubernetes | Conditional mutation followed by asynchronous convergence |
| OpenTofu | Immutable saved artifacts, state locks, partial effects, and recovery |
| PostgreSQL | Transactions, rollback, row bounds, and ambiguous commit outcomes |
| Records API | Separate create/read disclosure profiles delivered over HTTPS and Iroh without reusable API credentials |

The primary evidence set therefore contains seven independently maintained
domain verticals:

- `demos/github-issue`;
- `demos/kubernetes-rollout`;
- `demos/opentofu-plan`;
- `demos/postgresql-data-change`;
- `demos/radicle-issue`;
- `demos/rest-api-authorization`;
- the Stripe demo family rooted at `demos/stripe-refund` and the other
  `demos/stripe-*` profiles.

Records is not a holdout. It is required evidence for transport neutrality,
read-versus-write disclosure semantics, and an authorization boundary that
does not depend on reusable API keys. A future eighth domain must serve as the
post-contract holdout; do not widen the initial contract in anticipation of it.

Additional Stripe profiles are intra-domain evidence. They test whether profile
families remain separated correctly; they do not count as independent
cross-domain votes for a shared abstraction.

Formal Milestones 0 through 2 are treated as implemented only when their
commits are present on the chosen baseline and the corresponding formal CI
passes. OpenTofu and PostgreSQL are treated as complete verticals only when
their live-effect and recovery jobs pass on that same baseline.

## Non-negotiable sequencing

```text
Clean, green baseline
  -> status and evidence audit
  -> freeze seven-domain migration oracles
  -> write the semantic inventory
  -> classify every candidate
  -> specify and freeze the closed contract
  -> Milestone 3: pure bounded-policy semantics
  -> Milestone 4: mutable reservation/execution semantics
  -> Milestone 5: one-domain-at-a-time migration
  -> Milestone 6: measured, equivalence-proven optimization
  -> post-Milestone 6 productization
```

An agent must not collapse adjacent steps into one speculative implementation.
In particular, the semantic inventory and closed contract must exist before
shared policy or lifecycle production code is introduced.

## Consolidation target and retained domain boundaries

“Consolidate the core” in this plan does not mean moving provider behavior,
domain vocabulary, or demo logic into `core/`. It means extracting the
smallest mechanisms whose contracts have been proved identical while retaining
thick, independently evolvable domain edges.

The target architecture is:

```text
+---------------------------------------------------------------+
| core/                                                         |
| Proof validity, attenuation, canonical commitments, portable  |
| deterministic types and formally justified invariants         |
+-------------------------------+-------------------------------+
                                |
                                v
+---------------------------------------------------------------+
| shared product mechanisms                                     |
| Closed policy commitments, checked arithmetic, reservation and |
| replay primitives, execution ordering, receipt envelopes       |
+-------------------------------+-------------------------------+
                                |
              +-----------------+-----------------+
              |                 |                 |
              v                 v                 v
     Stripe domain       Radicle domain     Kubernetes domain
     profiles            profiles            profiles
     evidence            evidence            evidence
     verified commands   verified commands   verified commands
     provider adapters   provider adapters   provider adapters
     reconciliation      reconciliation      reconciliation
              |                 |                 |
              v                 v                 v
     Stripe demo         Radicle demo        Kubernetes demo
```

The same rule applies to GitHub, OpenTofu, PostgreSQL, records, and future
domains.

### What shared code may own

Shared code may own only a contract shown to be provider-independent, such as:

- canonical commitment and version carriers;
- checked arithmetic with explicit units;
- immutable evaluator/configuration equality;
- narrow compare-and-swap and reservation mechanisms;
- replay identifiers and state mechanics;
- common execution-stage ordering after its invariants are proved identical;
- receipt envelope mechanics that preserve domain payloads;
- conformance, browser-test, and presentation infrastructure.

Shared product mechanisms do not automatically belong in `core/`. Mutable
state, credentials, provider execution, reconciliation, and product policy
remain outside `core/`. A pure product mechanism may move into `core/` only if
it independently satisfies the repository's portability, determinism,
boundedness, dependency, and formal-claim requirements.

### What must remain domain-owned

Each domain package permanently owns:

- exact action and evidence types;
- policy meaning and typed evaluator entry points;
- evidence authority, freshness, and conflict interpretation;
- verified commands and their construction;
- provider gateways and closed outbound requests;
- least-privilege credential scopes;
- provider-specific idempotency and conditional execution;
- domain lifecycle differences and obligations;
- observation, convergence, propagation, and reconciliation meaning;
- domain stable codes and canonical receipt payloads;
- provider contract tests and deployment configuration.

An upstream provider SDK or API type must terminate at its domain adapter. A
shared package must not import Stripe, GitHub, Radicle, Kubernetes, OpenTofu,
PostgreSQL, or other provider SDK types. If a change in one provider requires a
change in an unrelated domain or in the formal core, treat that as evidence of
an invalid abstraction and stop the migration.

### Permanent role of demos

The individual demos remain after consolidation. They become permanent
downstream compatibility laboratories that prove shared changes still work
against complete domain workflows.

Every maintained demo must continue exercising:

- the production path rather than a demo-local reimplementation;
- its real local, sandbox, or test-mode provider effect;
- denial before credential release;
- boundary and boundary-plus-one behavior;
- replay and final-capacity concurrency;
- provider failure and outcome-unknown behavior where meaningful;
- reconciliation;
- inline and dedicated receipt views;
- browser-to-native end-to-end operation.

Demos may share presentation and deployment mechanisms, but production
packages must never depend on demo code.

### Reference versus production implementations

During a Milestone 5 migration, retain both the original and migrated paths:

```text
frozen canonical input
       |
       +--> original domain reference --> expected result
       |
       +--> migrated production path  --> actual result
                                               |
                                      exact comparison
```

The original pure evaluator remains available as a test-only reference until
the relevant semantic version is retired. Preserve its frozen fixtures and
smallest regression seeds.

Do not keep two complete production execution pipelines indefinitely. Permanent
duplicate production paths create ambiguous authority, divergent security
fixes, and unclear operational state. Remove duplicate production orchestration
only after exact differential conformance, live domain tests, state
migration/rollback tests, and the complete repository suite pass.

The intended steady state is:

- one authoritative production path;
- one deliberately simple test-only reference evaluator where useful;
- frozen migration oracles;
- permanent domain profiles, provider adapters, reconciliation, receipts, and
  demos.

### Upstream provider change containment

Classify an upstream change before editing shared code:

| Upstream change | Required containment |
| --- | --- |
| Endpoint, SDK, transport, or response-shape change with identical meaning | Update the domain adapter and provider contract tests |
| Evidence representation changes without semantic change | Add or update a versioned domain evidence normalizer |
| Provider API version changes observable execution behavior | Change executed configuration and version the adapter; change profile semantics only if meaning changed |
| Policy field or exact action meaning changes | Introduce a new profile/evaluator version |
| New ambiguous outcome, retry rule, or reconciliation requirement | Extend the domain lifecycle first; do not widen the shared state machine without new cross-domain evidence |
| Provider idempotency guarantee changes | Update domain execution and reconciliation while retaining independent Auths replay protection |
| Fundamentally new provider capability | Add a separate profile with its own verified command, gateway, credential scope, and receipts |
| Existing standing grants become unsafe or ambiguous | Fail closed and explicitly revoke or migrate; never silently reinterpret them |

Provider changes must not silently change an existing evaluator's meaning.
Existing grants, reservations, and receipts remain bound to their committed
profile, evaluator, canonicalization, and required/executed configuration
identities.

## Branch and pull-request protocol

### General rule

Every repository-changing unit in this plan must use a branch and pull request.
Do not commit this program directly to `main`.

Before creating a branch:

1. confirm the intended preceding PR is merged;
2. fetch the remote;
3. update local `main` to the exact remote revision;
4. confirm the worktree is clean;
5. create a new branch or isolated worktree from that revision;
6. record the baseline commit in the PR description.

Never reuse a branch whose stated purpose has already been merged. Never put
unrelated cleanup, dependency upgrades, or demo redesign into a milestone PR.
Do not overwrite or absorb another agent's uncommitted work.

### Required PR boundaries

Use these boundaries unless a later approved specification narrows them
further:

1. **Readiness and oracle PR**
   - status audit;
   - machine-readable seven-domain inventory shell;
   - domain-specific migration fixtures;
   - fixture generation and validation;
   - baseline measurements;
   - no shared semantic implementation.
2. **Semantic report and closed-contract PR**
   - seven-domain comparison;
   - candidate classifications;
   - abstraction case files;
   - the closed bounded-policy specification;
   - proposed evaluator and compatibility identities;
   - no production implementation of the proposed contract.
3. **Milestone 3 PR or narrowly ordered PR series**
   - pure deterministic bounded-policy semantics;
   - formalization and production refinement;
   - conformance tooling.
4. **Milestone 4 PR or narrowly ordered PR series**
   - reservation and execution state semantics;
   - formalization and model-based testing;
   - storage mechanisms only after the transition contract is fixed.
5. **Milestone 5 migration PRs**
   - one domain per PR, in the prescribed migration order;
   - GitHub and Radicle may share a final coordinated PR only if the approved
     contract explicitly treats them as a composition and independent
     differential evidence is retained.
6. **Milestone 6 optimization PRs**
   - one measured bottleneck or tightly coupled representation change per PR;
   - never combine an unmeasured semantic refactor with an optimization.

Do not stack dependent PRs by default. Begin the next branch from updated
`main` after the preceding PR merges. A stacked PR requires an explicit reason
in both PR descriptions and must not obscure which gate is actually passing.

### Suggested branch names

Names are descriptive, not normative:

```text
bounded-readiness-oracles
bounded-semantic-inventory
bounded-m3-policy-semantics
bounded-m4-reservation-semantics
bounded-m5-stripe
bounded-m5-kubernetes
bounded-m5-postgresql
bounded-m5-opentofu
bounded-m5-github-radicle
bounded-m6-<measured-bottleneck>
```

Follow the repository's active branch-prefix policy when one is configured.

### Pull-request description requirements

Every PR must state:

- baseline commit;
- plan step and milestone;
- specifications governing the change;
- packages and persisted/wire identities affected;
- explicit non-goals;
- invariants added or preserved;
- fixtures added or changed;
- exact validation run;
- CI phases expected to run and why;
- formal-assurance impact;
- compatibility and rollback plan;
- known residual assumptions.

“Tests pass” is not sufficient. Link each security claim to the specific
fixture, theorem, property, model check, or live test that supports it.

## When a specification must be written first

### A new or amended specification is mandatory before implementation when a task changes:

- policy meaning, policy schema, or evaluator identity;
- canonical action, evidence, configuration, or receipt meaning;
- wire bytes, persisted state, fixture identity, or compatibility behavior;
- denial, indeterminate, reconciliation, or stable-code semantics;
- reservation keys, capacity units, lifecycle transitions, expiry, release,
  commitment, or outcome-unknown behavior;
- credential timing or the verified-command boundary;
- provider retry, idempotency, conditional-write, or reconciliation rules;
- a public API, binding, profile, profile family, or domain contract;
- a formal theorem, refinement boundary, trusted assumption, or claimed source
  closure;
- a new production crate, shared semantic abstraction, or architectural
  dependency direction;
- a migration that could change decisions, commands, receipt bytes, or
  persisted state;
- a performance representation that could change evaluation order, work
  limits, canonical output, or observable results.

For these tasks, write or amend the specification before production code. The
specification must define the inputs, outputs, hard limits, failure behavior,
versioning, acceptance tests, and compatibility rules. Commit the specification
first on the branch so the implementation diff can be reviewed against a fixed
contract.

Use a separate specification-only PR when:

- the decision introduces a new shared semantic abstraction;
- persisted or canonical meaning will be frozen;
- more than one domain must migrate to the contract;
- formal claims or trusted boundaries materially change;
- reasonable reviewers could approve the problem but disagree about the
  semantic design.

Implementation may share a PR with a small specification amendment only when
the existing approved design already determines the behavior and the amendment
clarifies acceptance criteria rather than inventing new semantics.

### A new specification is normally not required for:

- adding missing fixtures for already specified behavior;
- correcting stale implementation status;
- adding differential tests without changing expected results;
- wiring an existing test into CI;
- regenerating an authoritative snapshot from unchanged semantics;
- fixing a defect whose correct behavior is already unambiguous in an existing
  specification;
- presentation-only demo work that does not alter canonical receipts or
  product behavior.

Even in these cases, cite the existing specification in the commit and PR.
If implementation exposes ambiguity, stop and update the specification before
choosing behavior.

## Step 0: establish the authoritative baseline

### Work

1. Confirm Formal Milestones 0–2 are present on `main`.
2. Confirm the qualified production source closure matches the selected
   revision.
3. Confirm OpenTofu and PostgreSQL live-effect, concurrency, recovery, receipt,
   and browser tests pass.
4. Merge or explicitly exclude any open domain PR whose behavior is meant to
   become evidence, including the expanded Stripe profile work.
5. Record the exact baseline commit and toolchain identities.
6. Run the dependency-aware authoritative CI plan and verify that all required
   phases are terminal and successful.

### Done means

- one clean `main` commit contains the intended formal and domain evidence;
- no required evidence exists only in an unmerged worktree or PR;
- formal, authoritative, compliance, OpenTofu-live, and PostgreSQL-live checks
  are successful on that commit;
- required and executed tool/configuration identities are recorded;
- the baseline commit is referenced by the next PR.

An open PR, a locally passing worktree, or a successful happy-path demo does not
complete this step.

## Step 1: audit status and evidence

### Work

For GitHub, Radicle, Stripe, Kubernetes, OpenTofu, PostgreSQL, and the records
API:

1. compare specifications, package inventory, `compliance.toml`, implementation,
   fixtures, demos, and CI;
2. correct stale `Proposed`, `Specified`, or `Implemented` labels;
3. distinguish implemented code from a completed vertical;
4. inventory policy inputs, evidence, exact actions, decisions, reservations,
   credentials, verified commands, provider effects, observations,
   reconciliation, receipts, and UX;
5. identify claims supported only by unit tests or simulated providers;
6. register missing machine-readable inventory entries;
7. record all known evidence gaps without filling them through a shared
   abstraction.

### Done means

- human specifications and machine inventories agree;
- every `implemented` profile has the required package, fixtures, tests, demo,
  compliance claims, and live contract;
- every incomplete profile is explicitly marked and excluded from the
  abstraction evidence set;
- `xtask` rejects status/inventory drift;
- the audit contains no unresolved “probably implemented” conclusions.

## Step 2: freeze seven-domain migration oracles

### Required oracle scenarios

Each primary domain must freeze representative canonical inputs and outputs for:

- authorized action;
- exact boundary;
- boundary plus one;
- malformed or mutated canonical input;
- stale or contradictory evidence;
- required/executed configuration mismatch;
- concurrent attempt at final capacity;
- replay;
- provider failure before a possible effect;
- provider outcome unknown after possible delivery;
- reconciliation;
- final decision, reservation, verified command, execution transition,
  observation, and receipt commitments.

When a scenario is impossible or meaningless for a domain, document why. Do
not fabricate a fake analogue merely to make the matrix rectangular.

Fixtures must include:

- canonical policy, action, evidence, and configuration bytes;
- expected decision class, stable code, and stage;
- expected reservations and obligations;
- expected closed provider command or command digest;
- expected transition and receipt bytes where stable;
- manifest, generator identity, schema/evaluator versions, and digests;
- hard-limit and smallest regression seeds where applicable.

### Rules

- Generate canonical fixtures through repository tooling; do not hand-edit
  canonical bytes.
- Keep domain-specific fixtures domain-specific.
- Do not normalize divergent receipt fields into a universal demo receipt.
- Preserve old implementations as the fixture oracle until migration
  differential tests pass.

### Done means

- all seven domains have manifest-owned oracle corpora;
- regeneration from a clean checkout is deterministic;
- decode/re-encode is byte identical;
- manifests reject missing, duplicate, stale, or manually drifted files;
- native implementations reproduce the expected decisions, commands,
  transitions, and receipts;
- CI runs the oracle validation;
- every fixture is tied to a specification and compliance claim.

## Step 3: produce the seven-domain semantic inventory

### Required comparison axes

Compare:

- policy and evaluator identity;
- exact action representation;
- evidence authority, normalization, and freshness;
- pure containment decision;
- arithmetic, rounding, and limits;
- reservation unit, scope, key, and expiry;
- obligations;
- claim and replay semantics;
- credential-release point and credential scope;
- verified-command construction;
- provider conditional execution and idempotency;
- definite failure versus outcome unknown;
- observation and reconciliation;
- revocation;
- decision, transition, execution, observation, and propagation receipts;
- UI projection;
- deployment and test plumbing;
- CPU, allocation, durable-write, and stage-latency measurements.

### Required classification

Every candidate must be classified as exactly one of:

1. identical invariant and identical transition;
2. shared invariant with a domain-specific payload;
3. composition of smaller primitives;
4. intentionally domain-specific.

Also apply the locality classification from the abstraction-boundary plan:

- profile semantic;
- domain semantic;
- structurally similar only;
- identical mechanism;
- demo duplication;
- accidental duplication.

### Done means

- every candidate has an explicit classification and evidence citation;
- similarities and divergences are shown at field, error, transition, and
  receipt level rather than asserted from control-flow shape;
- proposed shared candidates meet the minimum multi-consumer/domain threshold
  or have an ADR-backed exception;
- each candidate identifies what remains profile- or domain-owned;
- the report includes unresolved disagreements as blockers rather than silently
  choosing a generic shape;
- no production abstraction code is added by this step.

## Step 4: specify and freeze the closed bounded-policy contract

### Work

Write a numbered specification before implementation. It must define:

- immutable policy type, version, canonicalization, digest, and evaluator
  identities;
- deterministic, total, I/O-free evaluation inputs and result;
- denied versus indeterminate behavior;
- closed schemas, hard limits, checked arithmetic, units, rounding, and
  inclusivity;
- evidence-relative bounds and freshness;
- reservations and obligations as pure evaluator outputs, without mutable
  storage behavior;
- required/executed evaluator and configuration equality;
- compatibility, dual-version operation, and deprecation;
- domain-owned extension points that do not permit arbitrary callbacks,
  operation tags, or optional-field unions;
- exact conformance, differential, mutation, property, fuzz, Kani, and Lean
  obligations;
- explicit treatment of the records API's distinct create and read profiles,
  disclosure bounds, HTTPS/Iroh delivery equivalence, and transport-neutral
  policy decision.

Create an abstraction case file for every non-trivial shared semantic surface.

### Done means

- the specification is approved and merged before production implementation;
- every contract field traces to identical evidence in the semantic inventory;
- deliberately excluded semantics are listed;
- both records profiles can express their shared needs by composition while
  disclosure meaning and delivery adapters remain domain-owned;
- a future eighth-domain holdout is reserved without speculating about its
  vocabulary;
- evaluator and compatibility identities are reserved without silently
  changing existing versions;
- reviewers can reject any candidate abstraction without invalidating the
  frozen verticals.

## Step 5: implement Milestone 3 — pure bounded-policy semantics

### Scope

Implement only the immutable, deterministic policy layer:

```text
canonical policy
+ exact action
+ canonical evidence
+ explicit state snapshot
+ explicit time
+ required configuration
+ executed configuration
        |
        v
authorized { reservations, obligations }
| denied { stable code, stage }
| indeterminate { stable code, stage }
```

No evaluator may perform network, filesystem, environment, hidden-clock,
credential, provider, or mutable-store I/O.

### Required evidence

- simple reference implementation;
- rich Lean semantics for the closed contract;
- mechanically connected production Rust refinement following specification
  0011;
- tightening laws;
- arithmetic, overflow, rounding, and freshness laws;
- required/executed mismatch laws;
- hard-limit and work-counter tests;
- property, mutation, fuzz, Kani, and conformance coverage;
- all seven domain-oracle evaluations without migrating execution.

### Done means

- the numbered Milestone 3 specification is implemented exactly;
- production Rust refines the rich semantics across the qualified source
  closure;
- all seven reference paths remain unchanged and passing;
- new pure results match the frozen domain oracles wherever the shared contract
  applies;
- no credential, provider, storage, or execution behavior is smuggled into the
  pure evaluator;
- architecture, compliance, formal, conformance, and authoritative CI pass;
- the PR is merged to `main`.

## Step 6: implement Milestone 4 — reservation and execution semantics

### Specification-first requirement

Write and merge the state-machine specification before implementation. It must
separate authorization from mutable lifecycle behavior and define:

The governing contract is
`docs/specs/0026-reservation-and-execution-state-semantics.md`.

```text
available -> reserved -> committed
                    \-> released
                    \-> outcome-unknown -> reconciled
```

Specify durable decision recording, reservation keys, capacity conservation,
claims, replay, revocation, expiry, credential ordering, provider intent,
possible delivery, crashes, unknown outcomes, reconciliation, and receipt
ordering.

### Required evidence

- executable reference transition relation;
- Lean invariants for capacity conservation, replay, and credential ordering;
- model-based and bounded-concurrency tests;
- Kani obligations over finite representations and transitions;
- crash injection before and after every durable or external boundary;
- in-memory and persistent-store conformance;
- multi-process final-capacity tests;
- no assumption that a provider is atomic or deterministic.

### Done means

- all legal transitions and stable failures are specified and versioned;
- capacity cannot be double-reserved, lost, or released while an effect may
  have occurred;
- replay cannot create a second effect;
- configuration mismatch stops before decision persistence, reservation,
  credentials, and provider I/O as specified;
- unknown outcomes remain durable until fresh reconciliation;
- credentials are unavailable before the required completed stages;
- reference and production transitions agree;
- all required formal, model, crash, concurrency, and CI evidence passes;
- the PR is merged to `main`.

## Step 7: implement Milestone 5 — extraction and migration

### Required order

1. Stripe;
2. Kubernetes;
3. PostgreSQL;
4. OpenTofu;
5. GitHub;
6. Radicle;
7. records API create/read as a transport-neutral composition.

Use one branch and PR per migration. A migration specification or amendment is
required before coding if persisted state, receipt meaning, evaluator identity,
or compatibility behavior changes.

### Migration rules

- retain the old implementation as an executable oracle;
- run old and new paths against the same frozen fixtures;
- require identical decision class, stable code, stage, arithmetic,
  reservations, obligations, verified commands, transitions, and receipt bytes
  when versions are unchanged;
- add the smallest regression fixture for every mismatch;
- test rollback to the old path before deleting it;
- do not widen the abstraction to force a domain to fit;
- if a domain does not fit, prefer composition or retain domain-local
  semantics.
- keep the domain package, provider adapter, reconciliation, canonical receipt
  payloads, provider contract tests, and end-to-end demo after migration;
- preserve the old pure evaluator as a test-only reference where it remains
  necessary to qualify the semantic version;
- remove duplicate production orchestration only after equivalence, live
  behavior, state migration, and rollback are proved.

### Done means for each domain

- differential conformance is exact for all unchanged versioned behavior;
- state migration and rollback are tested;
- live effect, denial-before-credential, concurrency, crash, replay,
  outcome-unknown, reconciliation, frontend, and receipt tests pass;
- compliance claims point to the migrated evidence;
- the old path is removed only after equivalence passes;
- the domain migration PR is merged independently.

### Done means for Milestone 5

- all seven migrations are merged in the prescribed order;
- no shared API contains unrelated operation dispatch, arbitrary provider
  payloads, or semantically meaningful optional-field unions;
- shared product packages import no provider SDK or domain execution types;
- each domain retains its own actions, evidence, verified commands, gateway,
  credential scope, reconciliation, and receipt claims;
- every domain demo remains a dependency-aware downstream compatibility suite
  over the authoritative production path;
- there is one production execution path per migrated semantic version, with
  reference evaluators and frozen oracles retained for qualification rather
  than a second operational path;
- a provider-only change can be confined to its domain unless a separately
  specified semantic change supplies new cross-domain evidence;
- an eighth domain can use the mechanisms without changing core or weakening
  the abstraction.

## Step 8: implement Milestone 6 — optimized implementations

### Entry gate

Do not begin optimization until:

- reference semantics are frozen;
- all seven migrations pass differential conformance;
- exact benchmark fixtures and baseline revision exist;
- profiling identifies a concrete bottleneck.

### Work

Optimize one measured bottleneck at a time. Candidate work may include bounded
decoding, precomputed immutable digests, indexed membership, allocation
reduction, batched durable writes, connection reuse, immutable
content-addressed caching, or bounded request-local interning.

### Done means for each optimization

- the PR identifies the exact fixture digest, baseline revision, measurement,
  and bottleneck;
- the optimized implementation agrees with the reference on valid, invalid,
  mutated, fuzzed, maximum-sized, native, and WASM inputs;
- decisions, codes, stages, reservations, commitments, and canonical receipt
  bytes are unchanged;
- hard work and memory bounds remain enforced;
- the measured improvement is reproducible and material;
- no durability, freshness, validation, credential, or receipt ordering is
  weakened;
- rollback is possible;
- the optimization PR is merged independently.

### Done means for Milestone 6

- measured bottlenecks have either been improved with equivalence evidence or
  explicitly accepted;
- the reference evaluator remains available for differential qualification;
- benchmark and assurance artifacts identify the exact release revision;
- the entire authoritative suite passes from a clean checkout.

## Step 9: hand off to productization

After Milestone 6, follow
`docs/target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md`.

### Done means

- one clean `main` revision contains the completed formal and bounded program;
- semantic identities, fixtures, persisted states, receipts, and compatibility
  guarantees are frozen for a release candidate;
- the exact assurance claim is written;
- independent formal, Rust/protocol, and stateful-execution review can begin;
- the platform can be consumed without depending on demo code.

## Agent stop conditions

Stop implementation and escalate in the PR when:

- the existing specification does not determine behavior;
- two domains disagree on supposedly shared semantics;
- a proposed shared type requires unrelated operation tags, callbacks, or
  optional fields;
- migration changes a decision, reservation, command, transition, or receipt
  unexpectedly;
- formal semantics cannot be mechanically connected to the shipping predicate;
- a provider's ambiguous outcome cannot be represented without premature
  release;
- required and executed identities cannot be compared before side effects;
- fixtures cannot be reproduced deterministically;
- another active worktree contains overlapping uncommitted work;
- completing the task would require weakening architecture, compliance,
  hard-limit, secret, or CI enforcement.
- a provider-specific type, lifecycle rule, retry rule, or outcome meaning
  would enter a shared package;
- an upstream change in one provider would require changing an unrelated
  domain or the formal core without a new, approved cross-domain abstraction
  case;
- migration would delete the only reference evaluator, fixture oracle,
  rollback path, or end-to-end domain compatibility test.

Do not “temporarily” bypass these conditions. Record the blocker, preserve the
smallest reproducer, and amend the specification or architecture explicitly.

## Universal definition of done

No step in this plan is done merely because code exists.

A step is done only when:

1. governing specifications exist and match the implementation;
2. the branch contains only the intended unit of work;
3. canonical and persisted identities are versioned;
4. fixtures and manifests are deterministic;
5. claims map to executable or formal evidence;
6. architecture and compliance inventories are current;
7. focused tests and all dependency-required CI phases pass;
8. generated artifacts show no unexplained drift;
9. compatibility, migration, rollback, and residual assumptions are documented;
10. the PR is reviewed and merged into `main`;
11. a clean checkout of the merged revision reproduces the required evidence.

Until all eleven conditions apply, report the step as in progress rather than
complete.
