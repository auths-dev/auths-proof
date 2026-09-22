# ADR 0012: Permit a data-only, credential-isolated exact-request mechanism

**Status:** Accepted as an architectural boundary; no gateway implementation or deployment claim is approved by this ADR

**Date:** 21 September 2026

**Decision:** Conditional data-only mechanism; provider semantics remain vertical or application-owned

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

## Decision

Allow AP-SPEC-053 to investigate one product-layer, data-only request
interpreter, separate from the application and the qualified vertical runtime.
It may consume only a versioned, bounded, typed, operator-approved recipe
whose digest and stable logical operation ID are committed in verified action
bytes. The application submits proof and canonical action only. The operator,
not the application submission, pins the origin, request shape, connection,
credential generation, and trust configuration. The interpreter must never
execute third-party code, accept a runtime URL/header/body, or lease a secret
to a callback.

This is an architectural exception for closed transport mechanics, **not** an
exception to vertical-first provider semantics. The recipe author owns the
mapping from command to provider meaning. Auths may attest only its verified
action, approved recipe binding, one-use claim, and recorded gateway attempt
stage. Provider acceptance, effect, idempotency, reconciliation, and safe
retry remain operation-specific and unqualified unless a separately reviewed
vertical earns stronger claims. A library in the credential-owning
application is not this mechanism.

This ADR does not authorize shipping a gateway or using a “non-bypassable”
label. AP-SPEC-053's typed AST, immutable binding, hostile fixtures,
credential isolation, crash/claim behavior, egress tests, hosted CI, and
deployment evidence remain separate release gates. If the compiler cannot
express all three candidates without arbitrary requests or provider-effect
callbacks, reject or narrow the mechanism; do not enlarge the interpreter to
make a demonstration pass.

## Ownership and invariants

- `auths.mcp/v2` and the existing self-hosted profile contract continue to
  own exact canonical action and typed projection; no second generic action
  or verifier is introduced.
- A future product-layer recipe package, if justified, owns the invariant
  “closed request derived only from verified fields and approved literals.”
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
4. **Require a new Auths-maintained vertical for every developer operation:**
   remains appropriate for qualified provider claims but defeats the narrow
   self-service, unqualified use case.

## Consequences

AP-SPEC-051 remains the immediately usable, bypassable self-hosted path. The
AP-SPEC-040 qualified vertical remains the path for reviewed provider-effect
claims. AP-SPEC-053 may proceed to a separately reviewed typed-recipe design
under this boundary, but no gateway code, credential handling, deployment, or
stronger product claim follows from this ADR alone.
