# Stripe Profile Family Implementation Plan

## Status

Target-state implementation plan for specifications 0013 through 0023.

The machine-readable boundary is the repository-root
`stripe-profiles.toml`. `cargo xtask stripe-profiles` validates that inventory
against the specifications and runs in the compliance CI phase. This document
explains why those checks exist and how implementations advance through them.

## Goal

Build a coherent family of bounded Stripe profiles without turning Stripe into
one generic payment interpreter.

Each profile authorizes one exact provider effect. Related profiles may share
closed policy carriers, canonical leaf types, arithmetic, storage mechanisms,
and receipt envelopes. They must retain separate semantic entry points,
verified commands, lifecycle transitions, provider gateways, credential
scopes, receipts, fixtures, and end-to-end demonstrations.

```text
standing bounded policy
          |
          v
profile-specific pure evaluator ----> durable profile decision
          |                                      |
          v                                      v
profile-specific verified command ---> atomic reservation/claim
                                                 |
                                                 v
                                      least-privilege credential
                                                 |
                                                 v
                                      one exact Stripe effect
                                                 |
                                                 v
                                    observation + reconciliation
```

The shared policy says which choices are inside a bounded space. It does not
erase the distinction between collecting, authorizing, capturing, canceling,
transferring, paying out, creating a mandate, or changing a subscription.

## Architectural boundary

### Share mechanisms, not effect semantics

The following are eligible for Stripe-local reuse when their contracts are
identical:

- canonical identifier, currency, amount, digest, timestamp, and bounded-list
  primitives;
- checked minor-unit arithmetic and explicit time-window calculations;
- immutable policy/evaluator commitments;
- replay-key, idempotency-key, and reservation identifiers;
- durable storage mechanics such as compare-and-swap, transaction boundaries,
  persistence, and crash-safe append;
- receipt envelope fields for policy, evaluator, configuration, credential,
  provider, and observation commitments;
- redaction, secret-handling, Stripe request-ID capture, and test helpers;
- frontend layout primitives and browser-test infrastructure.

Reuse is allowed only below the point where a different effect would require a
runtime operation tag, optional fields with operation-dependent meaning, or a
branch that changes authorization or lifecycle semantics.

### Keep these profile-owned

Every profile owns:

- its exact canonical action and private constructor;
- its typed evaluator entry point and denial/indeterminate mapping;
- its verified command;
- its transition function over the applicable shared or dedicated store;
- its provider gateway and closed provider request;
- its least-privilege credential scope;
- its service orchestration and reconciliation rules;
- its profile receipts and stable result codes;
- its fixtures, mutation corpus, live contract, and demo.

The following designs are forbidden:

- `PaymentOperation` or equivalent selecting evaluator or executor behavior at
  runtime;
- one action containing the union of fields for several Stripe operations;
- a generic executor accepting arbitrary endpoint, parameters, metadata,
  headers, idempotency keys, or Stripe object IDs;
- a shared receipt that hides whether the provider effect was a hold, charge,
  capture, cancellation, transfer, payout, mandate, or subscription change;
- treating a successful authorization decision as proof of provider success;
- releasing reservations from elapsed wall time without fresh provider
  observation;
- using credits, refunds, cancellations, or missing list results as
  unobserved capacity;
- allowing one demo or profile implementation to become another profile's
  source of semantic truth.

### Family map

```text
bounded-merchant-payment-policy/1
  +-- 0013 collect
  +-- 0014 authorize
  +-- 0015 capture ---- depends on an exact authorization
  +-- 0016 cancel ----- resolves an exact authorization obligation

bounded-purchase-policy/1
  +-- 0017 Issuing purchase authorization

bounded-connect-transfer-policy/1
  +-- 0018 Connect transfer

bounded-payout-policy/1
  +-- 0019 payout

bounded-payment-mandate-policy/1
  +-- 0020 mandate

bounded-subscription-policy/1
  +-- 0021 create ----- consumes an exact mandate receipt
  +-- 0022 modify ----- transitions an exact bounded subscription
  +-- 0023 cancel ----- releases only observed-ended liability
```

Sharing a policy semantic ID within a family does not authorize sharing an
evaluator function. The common policy carrier is validated once; a
profile-specific evaluator interprets only the fields applicable to its
effect and rejects populated irrelevant fields.

## Repository architecture

```text
+------------------------------------------------------------------+
| demos/stripe-*/                                                  |
| native API, real Stripe test effect, frontend, receipt page, E2E |
+-------------------------------+----------------------------------+
                                |
                                v
+------------------------------------------------------------------+
| product/integrations/auths-stripe/                               |
| shared canonical leaves, family policies, stores, exact profiles |
| provider gateways, credential scopes, receipts, reconciliation   |
+-------------------------------+----------------------------------+
                                |
                                v
+------------------------------------------------------------------+
| core/                                                            |
| exact proof, rich authority, canonical protocol and refinement    |
+------------------------------------------------------------------+
```

All Stripe policy, live evidence, budget state, credentials, provider calls,
and reconciliation remain in `product/` or `demos/`. No Stripe-specific type
moves into `core/`.

## Implementation sequence

### Phase 0: install the harness

Before counting any profile as implemented:

1. Land this plan and `stripe-profiles.toml`.
2. Run its validator from compliance CI.
3. Inventory every profile's semantic and effect boundary.
4. Require an explicit inventory change whenever a profile, family, evaluator,
   module, gateway, credential scope, fixture location, or demo changes.
5. Audit any already-written 0013/0014 code against the inventory. Existing
   code is evidence, not an exception.

### Phase 1: merchant lifecycle

Implement and close 0013 through 0016 in this order:

1. collect, establishing the family policy carrier and reusable leaf
   mechanisms;
2. authorize, proving the same policy carrier supports a distinct hold effect;
3. capture, proving a receipt-linked transition from hold exposure to settled
   amount;
4. cancel, proving obligations and capacity are released only from a terminal
   Stripe fact.

This phase is the primary anti-coupling test. Collect and authorize must not
share a tagged service or gateway. Capture and cancel must consume exact
authorization identity rather than reconstructing or loosely matching it.

### Phase 2: consent and recurring liability

Implement 0020 first, then 0021 through 0023:

1. mandate establishes an exact, consent-bound future-payment capability;
2. subscription create consumes that capability and reserves finite recurring
   liability;
3. modify performs an atomic before/after liability transition;
4. cancel retains or releases liability only as observed provider state
   permits.

The mandate receipt is a typed dependency, not a boolean saying that consent
exists. Subscription credits and cancellation expectations never become
spendable capacity until their provider facts are observed.

### Phase 3: movement of platform funds

Implement 0018 and 0019 separately.

Connect transfers move funds inside Stripe's account graph. Payouts move
balance toward an external bank destination. They require different evidence,
credential scopes, risk controls, postconditions, and receipts even if they
reuse money arithmetic and durable reservation mechanics.

### Phase 4: latency-critical Issuing authorization

Implement 0017 after the lifecycle and reservation contracts are stable.
Issuing has a provider response deadline and webhook-driven evidence boundary.
Performance changes must be measured and must preserve the reference
evaluator, durable reservation, fail-closed fallback, and receipt semantics.

### Phase 5: extraction review

Only after all profiles pass their completion gates:

1. compare implementations field by field and transition by transition;
2. classify duplication as identical mechanism, analogous structure, or
   domain semantics;
3. extract only identical mechanisms;
4. retain the pre-extraction evaluators as differential oracles;
5. prove fixture, decision, reservation, provider-request, and receipt
   equivalence across migration;
6. reject an extraction if it introduces an operation tag or weakens a typed
   boundary.

This Stripe-local review does not authorize the cross-domain bounded-policy
abstraction. That remains gated by the OpenTofu and PostgreSQL evidence and the
Bounded Authorization Abstraction Plan.

## Per-profile completion gate

A profile may change from `specified` to `implemented` in
`stripe-profiles.toml` only when one revision contains all of the following:

1. A closed, deny-unknown-fields exact action with bounded decoding.
2. Immutable policy and evaluator identities with canonical digests.
3. Required and executed configuration equality checked before persistence,
   reservation, credential access, or provider I/O.
4. A pure, deterministic evaluator returning eligible, denied, or
   indeterminate with stable codes.
5. Checked arithmetic, explicit rounding, window boundaries, freshness, and
   hard work/collection limits.
6. A profile-specific verified command that cannot be constructed from
   unverified inputs.
7. Atomic reservation/claim behavior under concurrency.
8. A profile-specific credential scope and closed provider request.
9. Deterministic idempotency plus durable replay protection.
10. Crash-safe unknown-outcome handling and fresh-state reconciliation.
11. Separate decision, transition/execution, and observation evidence.
12. Canonical fixtures for every state and denial, including boundary and
    boundary-plus-one cases.
13. Unit, property, mutation, concurrency, crash/restart, and provider-request
    equality tests.
14. A Docker-local native backend and frontend that perform a real Stripe test
    effect.
15. A tested public frontend and native API deployment.
16. Adjacent controls/results, inline canonical receipt JSON, and a designed
    dedicated receipt page in the `auths-proof-site` design language.
17. Redacted deployment evidence, compliance registration, secret/PII scans,
    and authoritative CI on the exact revision.

An implementation is not complete if it is fixture-only, backend-only,
frontend-only, reachable only through `file://`, or unable to demonstrate
replay and reconciliation.

## Formal assurance

Formal work follows semantic risk, not crate shape.

Before sharing family semantics, provide executable reference semantics and
prove or mechanically check:

- policy tightening cannot expand eligibility or increase a reservation;
- checked money arithmetic cannot wrap, underflow, silently round, or net
  forbidden credits against debits;
- reservations conserve capacity across reserve, commit, release, unknown,
  and reconcile transitions;
- hold-to-capture/cancel transitions do not double count or prematurely free
  capacity;
- subscription before/after transitions preserve liability conservation;
- replay cannot create a second provider effect;
- configuration inequality stops before credentials and provider I/O.

Use Rust property tests and Kani for representation and state-machine
obligations immediately. Add rich Lean semantics for stable family relations
and conservation laws before extracting them into shared policy/runtime
abstractions. Provider APIs remain modeled as explicit nondeterministic
outcomes whose observations refine state; Lean must not pretend Stripe itself
is deterministic.

The Rust-to-Lean link must follow specification 0011: independently rewriting
the same rule in Lean is useful modeling but does not close the production
projection gap. Shared semantic claims require generated or translated pure
Rust predicates plus refinement evidence.

## UX contract

Every profile demo uses the same interaction grammar while preserving its
effect-specific vocabulary:

```text
+-----------------------------+-----------------------------+
| Bounded policy              | Exact action                |
| allowed scope and limits    | provider target and amount  |
+-----------------------------+-----------------------------+
| decision | reserve | credential | provider | observation |
+-----------------------------------------------------------+
| domain-specific capacity, obligation, or liability state  |
+-----------------------------------------------------------+
| inline canonical JSON                 [Designed receipt]  |
+-----------------------------------------------------------+
```

The frontend must explain the exact effect, what authority bounded it, whether
capacity was reserved, whether a credential was acquired, what Stripe
reported, and what remains unknown or obligated. It must not collapse
authorization, execution, and observation into one green check.

## APIs

Demos share route shapes, not a generic Stripe execution request:

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

The execute body selects a repository-owned experiment. It never accepts raw
Stripe endpoint names, arbitrary provider parameters, credentials, headers,
metadata, URLs, idempotency keys, or unrestricted object identifiers.
Profile-specific preview, timeline, webhook, and test-clock routes are allowed
only where their specification requires them.

## Change protocol

Any change to specifications 0013–0023 must update
`stripe-profiles.toml` when it changes an inventoried identity or boundary.
Any implementation status promotion must be reviewed against the full
completion gate. CI validates inventory/spec agreement; reviewers validate
semantic truth and evidence.

If a proposed convenience conflicts with this plan, keep the profile boundary
and duplicate the small amount of orchestration until equivalence is
demonstrated. Premature duplication is visible and reversible. Premature
semantic coupling is much harder to detect and unwind.
