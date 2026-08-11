# 08 — Errors, recovery, and diagnostics

**Status:** implemented as the Rust-owned registry and generated SDK contract  
**Milestones:** A — cross-domain envelope/schema; C — MCP registrations; E — ordered-plan/recovery registrations  
**Design dependencies:** [01](01_CURRENT_COMPLEXITY_BASELINE.md) and [02](02_SECURITY_AND_PARITY_GUARDRAILS.md); each profile registers codes only after its transitions exist in [07](07_CLOSED_EXECUTION_ORCHESTRATION.md)

## Current issue

Auths exposes typed codes and some recovery metadata, but understanding a
failure can still require knowledge of the subsystem that produced it.
Authorization decisions, workflow exceptions, provider failures, gateway
errors, lifecycle conflicts, and diagnostic projections are distributed across
several modules and do not yet form one customer recovery language.

A simpler API is incomplete if a user cannot answer “did anything happen, may I
retry, and what do I do next?” without reading implementation code.

## Components of the problem

- denied and indeterminate decisions coexist with thrown operational errors;
- codes describe internal families more readily than customer recovery;
- provider exceptions can be unbounded, sensitive, or runtime-specific;
- correlation, operation, stage, retry, and effect fields are not uniformly
  present on every error path;
- TypeScript and Python exception mechanics differ;
- outcome-unknown requires durable recovery state rather than a message;
- diagnostics and inspection are separate concepts in current navigation;
- documentation is manually synchronized with code.

## Product decision

Use one Rust-owned registry system with separately versioned ownership layers.
Milestone A defines the envelope and registration rules, not hypothetical
profile behavior. Each profile registers its own codes only when its Rust
session exists. Every SDK projects registered entries idiomatically while
preserving stable identity and bounded fields.

Authorization results remain values:

- `authorized` internally on the closed path;
- `denied` returned to the caller;
- `indeterminate` returned to the caller.

Operational failures use one base error with:

- `family` and stable `code`;
- customer operation and stage;
- safe summary;
- correlation ID;
- retry class: `never`, `safe`, `conditional`, or `unknown`;
- effect state: `not-applied`, `possible`, or `applied`;
- whether approval, signer, state, credential, or provider was entered;
- bounded remediation action and reference ID;
- decision/receipt IDs where safe;
- bounded causal categories without raw provider bodies or secrets.

## Recovery model

```text
+----------------------+----------------------+--------------------------+
| Effect state         | Retry class          | Required response        |
+----------------------+----------------------+--------------------------+
| not-applied          | safe                 | retry with new execution |
| not-applied          | never                | change request/config    |
| not-applied          | conditional          | satisfy named condition  |
| possible             | unknown              | resume and reconcile     |
| applied              | never/conditional    | inspect receipt/result   |
+----------------------+----------------------+--------------------------+
```

No error message may tell a user to retry when `effect=possible`.
`applied` means the selected profile has evidence of an effect; it does not
claim every ordered-plan member completed.

## Public UX

Both SDKs provide:

- exhaustive result matching helpers;
- `isAuthsError` / `isinstance(AuthsError)`;
- safe structured serialization for telemetry and support bundles;
- a human-readable formatter generated from the registry;
- `recommendedAction` / `recommended_action` as a closed enum;
- direct links from stable codes to generated documentation;
- diagnostics reporting installed artifact, ABI, runtime, profile, suite, and
  adapter capabilities without exposing key or proof material.

Normal recovery stays on the root facade:

```text
execution = auths.resume(error.execution_reference)
result = execution.reconcile()
```

The reference is opaque and commitment-bound. No framework import, provider
idempotency key, replacement action, or arbitrary provider is accepted.

Diagnostic verification remains inert. No diagnostic result can become an
effect-capable result, even if a caller supplies the diagnostic engine.

## Registry ownership by milestone

### Milestone A — Cross-domain envelope and registration schema

Define only:

- the error envelope fields, bounds, redaction rules, retry/effect enums, and
  impossible field combinations;
- genuinely cross-domain core codes such as invalid configuration, unsupported
  ABI/semantic subject, malformed bounded input, unavailable native runtime,
  forged opaque reference, and internal invariant failure;
- namespace/version rules for profile-owned codes;
- the schema a profile uses to register stages, allowed effect/retry pairs,
  remediation, safe references, and fixtures; and
- generators/checkers that project registered entries into TypeScript, Python,
  documentation, and parity tests.

Milestone A must not name MCP provider failures, assign evidence to
`not-applied`/`possible`/`applied`, or register plan/reconciliation outcomes.
The taxonomy exists; profile evidence rules do not yet exist.

### Milestone C — MCP registrations

After the MCP Rust session and typed handler contract exist, register:

- MCP-specific stages and stable codes;
- the exact evidence that classifies each terminal path as `not-applied`,
  `possible`, or `applied`;
- timeout, cancellation, handler failure, malformed/oversized handler output,
  reservation, replay, receipt, and MCP reconciliation behavior; and
- Rust/TypeScript/Python fixtures for every allowed combination.

### Milestone E — Ordered-plan and recovery registrations

After ordered-plan/resume transitions exist, register:

- plan-member interruption and partial-progress projections;
- still-possible, reconciled-not-applied, and reconciled-applied outcomes;
- resume/reference failures; and
- ordered receipt/recovery relationships.

## Registry entry contract

Extend the existing result-code/semantic registries rather than introducing a
binding-owned list. Each registered entry defines:

- stable identifier;
- owning semantic operation;
- allowed stages;
- allowed retry/effect combinations;
- bounded remediation enum;
- whether a decision or receipt reference is permitted;
- TypeScript error/result projection;
- Python error/result projection;
- documentation title and plain-language explanation;
- fixture cases that must produce it.

## Implementation steps

- [x] Inventory every current decision code, workflow error, profile/provider
  error, lifecycle conflict, and package/runtime diagnostic failure by owner.
- [x] Merge duplicates by meaning and split codes that currently hide different
  effect/retry states.
- [x] In Milestone A, define only the Rust-owned envelope, core-code set, and
  profile registration schema; validate impossible field combinations.
- [x] Generate TypeScript unions/classes and Python enums/classes or verify
  hand-written projections against the registry.
- [x] Route provider exceptions through bounded sanitizers.
- [x] Add one safe support-bundle schema with deterministic redaction.
- [x] Generate an error reference and recovery table from the registry.
- [ ] Replace separate beginner-facing inspection/diagnostics navigation with
  verification details and operational diagnostics by purpose.
- [x] Add parity fixtures for every stable code and terminal outcome.
- [x] In Milestone C, register and generate the complete MCP code/evidence
  matrix from its implemented Rust session.
- [ ] In Milestone E, add a profile-session-bound recovery operation for
  unknown outcome. It accepts only an opaque commitment-bound execution
  reference, never an arbitrary provider, command, or idempotency key.
- [x] In Milestone E, register ordered-plan/resume/reconciliation entries from
  implemented transitions rather than forecasted names.
- [ ] Delete superseded error names and compatibility branches in the atomic
  Spec 04 cutover, after the new root facade consumes this contract.

## Delivered contract

- `auths-errors` owns the bounded envelope, recovery enums, impossible-state
  validation, stable core/MCP/ordered-plan registrations, and namespace rules.
- `cargo xtask error-registry` generates the registry, both language
  projections, executable fixtures, and the public recovery table and rejects
  any drift in authoritative CI.
- TypeScript and Python parse every Rust-owned fixture, expose the same stable
  code/effect/retry/action fields, collapse native exceptions to closed cause
  categories, and build the same bounded support schema.
- `possible` always means `unknown` retry, a provider boundary was entered,
  and an authenticated execution reference is present; the parsers reject all
  other combinations.
- The profile registration JSON schema prevents unversioned, unowned, or
  unbounded profile code families.

## Acceptance criteria

- Every terminal path answers effect state, retry class, and next action.
- Milestone A can pass with zero profile codes, and the registry checker rejects
  an unowned or unversioned profile code.
- MCP and ordered-plan codes cannot appear before their owning semantic
  operations exist and have fixtures.
- No provider exception text, credentials, signatures, proof bytes, canonical
  command bytes, or unbounded bodies cross the SDK boundary.
- Every registry code has at least one executable fixture in both SDKs.
- Unknown outcome can never format as retry-safe.
- Generated documentation and SDK error metadata cannot drift independently.
- A support bundle is deterministic, bounded, redacted, and contains enough
  artifact/correlation information to reproduce the semantic environment.
- Product recipes demonstrate denied, indeterminate, safe retry, and
  reconciliation behavior.

## Non-goals

- Treating authorization denial as an exception.
- Preserving native provider exception classes.
- Embedding business-specific remediation prose in the core registry.
