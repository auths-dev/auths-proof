# Post-Milestone 6 Productization and Release Plan

## Status

Target-state implementation plan.

This plan begins only after the formal-hardening and bounded-authorization
program is complete:

- Milestones 0 through 2 close the rich Rust-to-Lean authority refinement
  boundary.
- OpenTofu and PostgreSQL satisfy the complete end-to-end criteria, including
  real effects, concurrency, crashes, reconciliation, receipts, and
  frontends.
- The six-domain semantic inventory classifies every candidate concept.
- Representative canonical fixtures from every vertical are frozen as
  migration oracles.
- Milestones 3 and 4 establish pure bounded-policy semantics and separate
  mutable reservation/execution semantics.
- Milestone 5 migrates Stripe, Kubernetes, PostgreSQL, OpenTofu, GitHub, and
  Radicle with decision and receipt equivalence.
- Milestone 6 optimizes only measured bottlenecks while proving equivalence to
  the reference evaluators.

At that point, Auths Proof should stop behaving primarily like a research
project accumulating demonstrations. It should become a releasable,
independently reviewable platform for bounded machine authority.

The required sequence is:

```text
Milestone 6 complete
  -> reproducible release candidate
  -> exact assurance claim
  -> independent review
  -> stable developer and runtime surfaces
  -> profile certification
  -> real flagship deployment
  -> unified six-domain workbench
  -> public v1 release
  -> controlled domain expansion
```

## Goal

Turn the proven kernel, state machine, domain integrations, fixtures, and
formal evidence into a platform that another team can deploy, audit, extend,
and operate without weakening the verified boundaries.

The platform claim is:

> Auths lets an agent exercise bounded discretion while withholding ambient
> credentials and binding every consequential effect to exact, versioned,
> replay-safe, recoverable, and auditable authorization.

Auths does not prove that an external provider is correct, available, atomic,
or deterministic. It proves which exact commands may cross the credential
boundary and records provider outcomes and observations without conflating
authorization, execution, and observed success.

## Non-goals

This program will not:

- replace the vertical domain packages with a generic workflow engine;
- introduce an unrestricted policy language;
- make a hosted Auths control plane mandatory for verification;
- centralize every provider credential in one service;
- add more domains before stabilizing and reviewing the proven platform;
- claim that Lean proves the behavior of networked providers;
- merge domain-specific receipts into one vague success object;
- optimize without benchmark evidence;
- standardize unstable evaluator or receipt semantics;
- treat a provider SDK interface as proof of semantic equivalence.

## Phase 7: close and freeze the research program

### Objective

Produce one clean release candidate from `main` containing the entire completed
formal and bounded-authorization program.

### Required work

The release candidate must contain:

- rich Lean authority semantics;
- qualified Aeneas production translation;
- production Rust refinement evidence;
- the closed bounded-policy contract;
- reservation and exact-effect semantics;
- six migrated domain integrations;
- reference-versus-extracted differential tests;
- reference-versus-optimized differential tests;
- canonical migration fixtures for every domain;
- rebuilt formal paper and assurance manifest;
- exact benchmark evidence;
- reproducible release metadata for the source revision.

Freeze the following identities:

- core protocol and portable ABI versions;
- policy and evaluator semantic IDs;
- canonicalization versions;
- exact-action profile versions;
- stable decision and indeterminate codes;
- receipt schemas and commitment meaning;
- fixture bytes and manifests;
- persisted reservation and reconciliation states.

This is a semantic freeze, not a permanent feature freeze. Later incompatible
meaning requires an explicit new version.

### Release artifact

Create a release candidate tag such as:

```text
auths-proof-v1.0.0-rc.1
```

The tag must be generated from a clean checkout after all checks and artifact
generation. Nothing may be regenerated or edited after the evidence revision
is recorded.

### Exit gate

A clean checkout of the tag reproduces:

- formal statements and qualification evidence;
- canonical fixtures and conformance results;
- native and binding compatibility;
- benchmark inputs and reports;
- SBOM and dependency policy;
- signed or attestable release artifacts;
- the release assurance manifest.

## Phase 8: publish the exact assurance claim

### Objective

State precisely what has been proved, mechanically connected, tested, audited,
and trusted.

### Required assurance layers

```text
Rich Lean authorization semantics
              |
              v
Qualified production Rust refinement
              |
              v
Bounded representation and state obligations
              |
              v
Trusted storage, credential and execution boundary
              |
              v
Nondeterministic external provider
              |
              v
Observed and receipted provider outcome
```

The assurance claim must identify:

- every theorem included in the public claim;
- the production Rust source closure for each refinement;
- representation invariants discharged by Kani;
- properties supported by mutation, property, fuzz, conformance, or
  integration tests;
- all trusted components and residual assumptions;
- provider behavior that remains outside the proof;
- the exact difference between authorization, provider acceptance, and
  observed postcondition;
- versioning and compatibility limits.

The paper, website, release notes, operator documentation, and customer-facing
claims must use this same boundary.

### Exit gate

Every public security claim maps to a theorem, translated source closure,
test, audit finding, or explicit residual assumption. No claim depends on
marketing interpretation.

## Phase 9: independent review

### Objective

Submit the release candidate to independent specialists before treating the
platform as production-ready.

### Review tracks

#### Formal methods

Review:

- rich Lean models and theorem statements;
- Aeneas qualification and generated artifacts;
- Rust-to-Lean representation and refinement boundaries;
- transitive axioms and residual trust;
- consistency between the paper and compiled evidence.

#### Rust and protocol security

Review:

- canonical encoding and bounded decoding;
- authority attenuation and verification;
- proof and configuration binding;
- verified-command construction;
- replay and credential ordering;
- secret handling and unsafe assumptions;
- stable-code and receipt integrity.

#### Stateful and distributed execution

Review:

- reservation atomicity and capacity conservation;
- concurrent final-unit behavior;
- execution intent and claims;
- crashes before and after possible provider delivery;
- outcome-unknown retention;
- reconciliation and revocation;
- database isolation, failover, backup, and restoration.

### Finding discipline

Every accepted finding must produce one or more of:

- a regression fixture;
- a property, mutation, fuzz, Kani, or Lean obligation;
- an architecture or compliance rule;
- an operational control;
- a documented residual assumption.

### Exit gate

No unresolved critical findings remain. High-severity accepted findings have a
verified resolution plan and release-blocking status.

## Phase 10: stabilize the platform thin waist

### Objective

Expose the proven behavior through a small developer-facing surface without
erasing domain semantics.

### Product surfaces

| Surface | Responsibility |
| --- | --- |
| Core kernel | Exact proofs, rich authority, canonical verification |
| Profile SDK | Closed policy, action, evidence and evaluator authoring |
| Enforcement runtime | Verify, decide, reserve, claim, credential, execute, observe |
| Receipt SDK | Decision, transition, execution and observation evidence |
| Conformance kit | Fixtures, mutation, differential and hard-limit tests |
| Domain packages | Provider semantics, gateways, credentials and reconciliation |
| Bindings | Thin WASM, TypeScript, Python and Go access |
| Demos | Teaching and real end-to-end integration evidence |

The thin waist is not a universal provider request. It is a collection of
versioned commitments, decisions, reservations, verified-command boundaries,
and receipts that preserve profile-owned effects.

### Profile-authoring workflow

Provide a repository tool such as:

```text
cargo xtask profile new <domain> <profile>
```

The generated vertical should include:

- one cohesive product integration package or module;
- closed typed action, policy, evidence, and configuration shells;
- pure evaluator and verified-command boundaries;
- provider and credential ports;
- reservation and reconciliation tests;
- fixture generation and mutation corpus;
- compliance inventory;
- demo backend and frontend skeleton;
- inline and dedicated receipt interfaces;
- CI and release-evidence expectations.

The scaffold must not generate a runtime operation dispatcher or a union
action containing unrelated provider effects.

### Developer success test

A capable team can build a seventh domain:

- without modifying core;
- without inventing a new replay or reservation model;
- without bypassing required/executed configuration equality;
- without exposing provider credentials to the agent;
- without copying the entire platform;
- without weakening the vertical-first boundary.

## Phase 11: productionize the enforcement runtime

### Objective

Turn the demonstrated state and exact-effect semantics into an operable,
deployable runtime.

### Required capabilities

- Immutable policy and evaluator distribution.
- Atomic replay and reservation stores.
- Durable decision, transition, execution, and observation receipts.
- Credential brokers backed by KMS, HSM, workload identity, GitHub Apps, or
  provider-scoped secrets.
- Reconciliation workers with durable scheduling and backoff.
- Revocation and evaluator-version handling.
- Structured diagnostics, metrics, traces, and audit export.
- Multi-instance concurrency and leader/fencing behavior.
- Backup, restoration, schema migration, and disaster recovery.
- Explicit degraded and fail-closed modes.
- Secret redaction and data-retention controls.

### Deployment forms

Support an embedded verifier:

```text
application -> Auths library -> local deterministic decision
```

Support a protected enforcement service:

```text
agent/application -> Auths executor -> external provider
                              |
                              +-> credential boundary
                              +-> reservation and receipt stores
```

Verification must not require a universal phone-home service. A hosted control
plane may distribute policies, manage evaluator versions, and aggregate
receipts, while consequential execution remains near the protected credential
and provider boundary.

### Exit gate

The runtime passes:

- multi-instance contention tests;
- process and host crash tests;
- database interruption and recovery;
- unknown-outcome reconciliation;
- credential-broker failure;
- revocation and version-transition tests;
- backup and restoration exercises;
- chaos tests against the flagship integration.

## Phase 12: create profile certification

### Objective

Make Auths-compatible profile claims executable and reviewable.

### Inventory

Every maintained profile registers:

- domain, package and architectural layer;
- profile, policy, evaluator and canonicalization versions;
- exact action and evidence types;
- stable denied and indeterminate codes;
- required and executed configuration;
- hard byte, collection, depth, time and work limits;
- reservation and reconciliation model;
- credential scope;
- fixture and mutation corpus;
- receipt schemas;
- demo and live-test locations;
- formal, Kani, property, conformance and integration claims.

### Conformance command

Provide:

```text
cargo xtask profile-conformance <profile>
```

Certification requires:

- valid, invalid, exact-boundary and boundary-plus-one cases;
- policy-tightening monotonicity;
- denial before credentials;
- atomic concurrent reservation;
- replay without a second provider effect;
- crash before and after possible request delivery;
- outcome-unknown retention;
- fresh reconciliation;
- exact provider-command equality;
- required/executed mismatch behavior;
- inline canonical JSON and dedicated receipt views;
- a real native backend and frontend.

### Exit gate

An integration cannot be described as Auths-conformant unless its inventory,
fixtures, implementation, live evidence, and compliance claims agree on the
same revision.

## Phase 13: operate a flagship production workflow

### Decision

Use GitHub issue workflow publication as the first production flagship.

GitHub is recommended because:

- the effect is understandable;
- the protected credential is clearly valuable;
- a draft pull request remains reviewable and reversible;
- the no-agent-credential claim is directly demonstrable;
- it exercises external evidence, claims, credentials, provider mutation,
  observation, replay, and receipts;
- operational risk is lower than financial or infrastructure mutation.

### Required workflow

1. A human grants bounded issue-resolution authority.
2. The agent works locally without GitHub credentials.
3. The agent proposes one exact branch and draft pull request.
4. Auths evaluates the exact action and reserves workflow capacity.
5. The executor acquires a short-lived GitHub App installation token.
6. GitHub accepts the exact branch and pull request mutations.
7. Auths observes the resulting GitHub state and records receipts.
8. Replay returns the prior outcome without a second mutation.
9. Direct publication from the credentialless agent environment fails.
10. Crash and ambiguous-response scenarios reconcile without duplication.

### Second flagship

After GitHub is stable, operate Kubernetes/OpenTofu as the infrastructure
flagship. Keep Stripe in test mode or under extremely restricted production
limits until financial credential, reservation, dispute, and reconciliation
controls have completed independent review.

### Exit gate

The flagship survives continuous operation, upgrades, configuration changes,
credential rotation, provider failures, crashes, and operator recovery without
breaking exactness or receipt truth.

## Phase 14: unify the six-domain workbench

### Objective

Present the completed domains through one consistent explanatory experience
without merging their semantics.

### User journey

```text
choose a domain
      |
      v
inspect bounded authority
      |
      v
let the agent select an exact action
      |
      v
authorize or deny
      |
      v
reserve and execute without agent credentials
      |
      v
observe provider state
      |
      v
inspect canonical receipts
```

Every domain view shows:

- the bounded policy or delegation;
- the exact agent-selected action;
- required and executed configuration;
- the current decision stage;
- reservation and replay state;
- whether a credential was requested;
- whether the provider was called;
- provider acceptance and later observation;
- outstanding obligations or unknown outcomes;
- inline canonical receipt JSON;
- a designed dedicated receipt page.

Controls and live results remain adjacent. The frontend uses the
`auths-proof-site` design language and runs against real native backends.

### Exit gate

Browser end-to-end tests cover success, denial, exact boundary, mutation,
configuration mismatch, replay, unknown outcome, reconciliation, raw receipts,
and designed receipt pages for every domain.

## Phase 15: publish the platform contract

### Public artifacts

Publish:

- the formal and security paper;
- the precise assurance claim;
- the protocol and threat-model specification;
- an operator deployment and recovery guide;
- a profile-authoring developer guide;
- compatibility and versioning policy;
- conformance fixtures and evidence;
- benchmark methodology and results.

Benchmark evidence includes:

- verification latency;
- pure evaluation latency;
- reservation latency under contention;
- receipt size;
- encoded object size;
- allocation and deterministic work counters;
- reconciliation latency;
- reference-versus-optimized equivalence.

### Release

After independent review and flagship operation, promote the compatible release
candidate to the first public v1 release. Profile and evaluator versions remain
independent from the repository release version.

### Exit gate

The public release can be reproduced, deployed, audited, and extended from its
published artifacts without relying on an undocumented local environment.

## Phase 16: controlled domain expansion

### Objective

Resume domain growth only after the platform and certification process are
operational.

Every new domain:

1. Begins as a cohesive vertical package.
2. Defines one exact effect.
3. Completes the native backend, frontend, receipts, replay and recovery.
4. Registers its semantic and effect boundary.
5. Reuses shared primitives through conformance rather than resemblance.
6. Changes shared abstractions only when it demonstrates a missing invariant.
7. Adds formal work when it introduces a stable reusable law.

Useful future domains include:

- cloud IAM and role assumption;
- secrets rotation;
- package and artifact publishing;
- CI/CD deployment;
- high-value SaaS administration;
- certificate and key lifecycle;
- controlled data export.

Prioritize domains that introduce new authority, evidence, reservation, or
reconciliation shapes rather than merely adding another provider logo.

## Governance and versioning

A change to existing policy, evaluator, action, receipt, or persisted-state
meaning requires:

1. a new semantic version or schema;
2. compatibility and migration fixtures;
3. required/executed configuration review;
4. updated explanation rendering;
5. active grant and reservation migration analysis;
6. formal-assurance impact analysis;
7. deprecation and rollback procedures.

Do not silently reinterpret an existing field. Dual-version execution is
explicit and temporary. An evaluator can be retired only when active grants,
receipts, reservations, and reconciliation state no longer depend on it.

New profiles and abstractions must follow
`PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`.

## Program completion

This post-Milestone 6 program is complete when:

- the formal and bounded semantics are released from a reproducible tag;
- the assurance claim is exact and independently reviewed;
- the developer thin waist is stable;
- the runtime operates durably under concurrency and failure;
- profile conformance is executable;
- one real GitHub workflow operates without agent credentials;
- the infrastructure flagship is operationally proven;
- the six-domain workbench demonstrates the complete lifecycle;
- the public v1 release is reproducible and auditable;
- new domains can be added without changing core or weakening boundaries.

At that point, Auths Proof is no longer primarily a collection of impressive
proofs and demonstrations. It is a credible execution substrate for bounded
machine authority.
