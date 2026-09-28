# ADR 0012: Permit a data-only, credential-isolated exact-request mechanism

**Status:** Accepted. Amended on 28 September 2026 under the owner's decision
of 27 September 2026 ([AP-SPEC-063](../specs/0063-generalized-gateway.md)
§12, option A); the decision and consequences below are the amended text

**Date:** 21 September 2026; amended 28 September 2026

**Decision:** The data-only, credential-isolated gateway is the single
production path for provider writes; verticals stay the source of reviewed
semantics and evidence, not the production executor

## Context

AP-SPEC-051 lets an application build a self-hosted exact-action adapter, but
the application retains its credential and can bypass its own SDK runner. The
[boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
prohibits turning that adapter into executable code inside an Auths
credential-owning gateway. AP-SPEC-053 proposes a different boundary: an
operator approves immutable data describing one closed request, and a separate
process alone holds the bound credential.

The [abstraction case](../research/domains/abstraction-cases/0007-declarative-credential-isolated-request.md)
compares an Airtable fixed-field update, a Todoist task creation, and GitHub
issue creation. Their bounded request-construction mechanics are candidates
for reuse. Their preconditions, response interpretation, observation, and
retry safety are not identical. Three plausible request shapes are evidence
for a narrow transport mechanism, not evidence for generic provider semantics.

By September 2026 the gateway carried the north-star Stripe refund journey,
and the hand-built local-agent effect profiles (`auths.stripe.refund/1`,
`auths.postgresql.bounded-update/1`, `auths.postgresql.update-preflight/1`,
`auths.opentofu.saved-plan-apply/1`, `auths.opentofu.plan-preflight/1`) were
all unqualified. The public record showed defects clustering in mechanisms
each vertical re-implemented and the gateway implements once: refund
recovery (#145), receipt clocks (#147), and provider-client proxy and
redirect settings (#160). AP-SPEC-063 §12 set out two options, and on 27
September 2026 the owner chose option A: one provider-write path.

## Decision

The gateway of [AP-SPEC-053](../specs/0053-declarative-credential-isolated-gateway.md),
as generalized by AP-SPEC-063, is the single production path for provider
writes. Every production write is a data-only recipe: versioned, bounded,
typed, and operator-approved, with its digest and stable logical operation ID
committed in verified action bytes. The application submits proof and
canonical action only. The operator, not the application submission, pins
the origin, request shape, connection, credential generation, and trust
configuration. The interpreter never executes third-party code, accepts a
runtime URL, header, or body, leases a secret to a callback, or branches on a
provider or operation tag. It compares bytes, integers, and HTTP statuses and
reads JSON values at declared pointers; every provider-specific value is
recipe data. [ADR 0013](0013-recipe-capabilities-and-sum-budget.md) lists
the closed capabilities a recipe may declare.

This is an exception for closed transport and recording mechanics, not an
exception to vertical-first provider semantics. A vertical package stays the
source of reviewed semantics and evidence for its domain: its pure
evaluators, fixtures, mutation corpus, Kani harnesses, formal models, and
demos are test-only references that a recipe capability is compared against
before it is admitted. A vertical is not a production executor: it holds no
production credential, serves no application channel, and issues no
production receipt. A domain whose provider is not reached over HTTPS, such
as PostgreSQL or OpenTofu, has no production path.

The recipe author owns the mapping from command to provider meaning. Auths
attests its verified action, approved recipe binding, one-use claim, spend
limit, and recorded gateway attempt stage, and, where a read-back succeeds,
the observed provider evidence (AP-SPEC-063 §1). Provider acceptance, effect,
idempotency, reconciliation, and safe retry stay operation-specific and
unqualified. A recipe earns a qualified claim only as ADR 0013 states. A
library in the credential-owning application is not this mechanism.

This ADR does not by itself approve a deployment or a "non-bypassable"
label. Each gateway capability keeps its own typed AST, hostile fixtures,
credential isolation, crash and claim behavior, egress tests, hosted CI, and
deployment evidence as release gates. If a provider write cannot be expressed
without arbitrary requests or provider-effect callbacks, it is not shipped,
or it waits for a new capability admitted under ADR 0013's form; the
interpreter is not enlarged to make a demonstration pass.

## Ownership and invariants

- `auths.mcp/v2` and the existing self-hosted profile contract continue to
  own exact canonical action and typed projection; no second generic action
  or verifier is introduced.
- The product-layer `auths-gateway` package owns the invariant “closed
  request derived only from verified fields and approved literals.”
  New public types require a named owner, private construction after
  validation, and a test showing why an existing type is insufficient.
- Existing connection types own credential identity, scope, generation, and
  opaque storage where their contracts fit. A separate operator/admin
  channel owns installation and binding; the application channel cannot
  mutate either.
- Attempt/lifecycle types must be compared before reuse. Local single-host
  demo storage is not relabeled as multi-host enforcement.

## Rejected alternatives

1. **Load developer adapters into the credential-owning runtime:** grants
   application code access to the protected process and makes the isolation
   claim false.
2. **Accept a runtime HTTP request after proof verification:** permits the
   caller to redirect a credential-bearing request beyond the approved exact
   action.
3. **Treat one shared request builder as provider qualification:** conflates
   transport mechanics with provider-specific effect and recovery semantics.
4. **Require a new Auths-maintained vertical as the production executor of
   every operation:** duplicates the claim, credential, recovery, and client
   mechanics per domain, where the public record shows defects clustering,
   and defeats the narrow self-service use case. Verticals stay the
   reference for reviewed semantics.
5. **Keep both paths (AP-SPEC-063 §12, option B):** not chosen by the owner
   on 27 September 2026.

## Consequences

- Two authoring paths remain. AP-SPEC-051 is the immediately usable,
  bypassable self-hosted path, in which the application holds its own
  credential. The gateway recipe is the credential-isolated path, and the
  only one through which Auths holds a credential or sends a provider write.
- The five local-agent effect profiles, their routes, the local agent's
  journal executor, their generated clients, and their connection
  administration were removed in one cutover with no switch (AP-SPEC-063
  epic 8). The PostgreSQL serializable row-version write and OpenTofu's
  stale-plan refusal leave production with them.
- [AP-SPEC-040](../specs/0040-generic-profile-sdk-and-contributor-system.md)
  is superseded for provider writes.
  [AP-SPEC-041](../specs/0041-stripe-connection.md)–[AP-SPEC-044](../specs/0044-live-provider-qualification-and-recovery-evidence.md)
  and [AP-SPEC-038 Epic 6](../specs/0038/epic_6.md) move to gateway recipes;
  each carries a status note naming what moved and what ended.
- The Stripe refund is the recipe of AP-SPEC-063 §3.1, and production keeps
  the vertical's five checks as provider-neutral recipe capabilities (ADR
  0013). AP-SPEC-063 §6.9 and §14 list where each is narrower than the
  vertical.
- The `auths-stripe`, `auths-postgresql`, and `auths-opentofu` packages
  remain as test-only references under the boundary plan's "Phase 1" and
  "Domain to shared product" rules.
- The boundary plan's vertical-package rule and its paragraph on this ADR are
  rewritten to match.
