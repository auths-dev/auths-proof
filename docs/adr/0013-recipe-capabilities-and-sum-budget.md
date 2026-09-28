# ADR 0013: Admit ten closed recipe capabilities and a sum budget into the data-only gateway

**Status:** Proposed, for owner review with AP-SPEC-063 epic 1. It amends
ADR 0012. Accepting it approves the mechanisms below as candidates for
epics 2–7; it approves no implementation, deployment, or product claim.
Epic 8 removed the local-agent code some evidence entries cite; those
entries name the last revision that held it, `09596075`.

**Date:** 27 September 2026

**Decision:** Amend ADR 0012 with ten closed, digest-bound recipe capabilities
and one sum budget, each separately reviewable; gateway code still gains no
provider semantics

## Context

[ADR 0012](0012-declarative-credential-isolated-gateway-boundary.md) permits a
data-only interpreter for closed provider requests and keeps provider effect,
recovery, idempotency, and retry semantics with the recipe author or a
reviewed vertical. [AP-SPEC-063](../specs/0063-generalized-gateway.md) adds
ten recipe capabilities (§2) and a sum budget (§6.10). On 2026-09-27 the
owner chose §12 option A, making the gateway the single provider-write path,
and decided that production keeps the `auths-stripe` vertical's five checks
as provider-neutral gateway capabilities.

The [boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)
sets the default threshold for a shared product mechanism at three
implemented consumers across two domains. None of the ten capabilities meets
it. The version header, credential guard, idempotency declaration, response
locator, form echo, and pre-entry re-read rest on at most two consumers, and
the relative ceiling, account binding, denied reads, and account-scope header
rest on `auths-stripe` alone. The sum budget rests on `auths-stripe`'s
budgets. The plan allows a smaller promotion only with an ADR that explains
why the behavior is already a domain-independent primitive rather than
inferred commonality. This is that ADR. The written comparisons the plan
requires are in
[abstraction case 0007](../research/domains/abstraction-cases/0007-declarative-credential-isolated-request.md),
section "AP-SPEC-063 capability comparisons".

## Decision

Each capability below is admitted only in this form:

- it is a closed, optional field of the recipe AST, digest-bound under
  `auths.gateway-compiled-recipe/2`, or a policy member bound by the grant's
  commitment;
- every provider-specific value in it (a header value, a prefix, a path, a
  JSON pointer, a status, a ratio, a retention period) is data the author
  writes, the compiler bounds, the review output shows, and the operator
  approves by digest;
- the gateway only compares bytes, integers, and HTTP statuses, and reads a
  JSON value at a declared pointer; it interprets no provider field;
- no operation tag, optional union across operations, or callback enters a
  shared API; and
- every failure is a stable code, before the claim with nothing stored, or
  after the claim recorded as `not-entered`.

A reviewer may reject any one capability without blocking the others.
Rejecting one of the five Stripe checks (relative ceiling, account binding,
denied reads, account scope, sum budget) reopens its row of AP-SPEC-063 §12.

### 1. Provider version headers

- **Primitive.** A closed registry, `PROVIDER_HEADERS`, of header names with a
  value grammar and a response rule. A `version` header carries a fixed value
  on every request to the origin; a response rule is either "must echo the
  same value" or "not checked".
- **Why it is a primitive.** Sending a fixed header and comparing one response
  header for byte equality needs no knowledge of what the version means. The
  registry is the only place a provider header name appears in gateway code,
  and it names headers, not behavior; adding an entry needs an amendment with
  vertical evidence and hostile fixtures.
- **Evidence.** `auths-stripe` sent and required `Stripe-Version`
  (`bounded_provider_result` in `local_agent.rs`, removed in epic 8; see
  `09596075`); `auths-github` sends `X-GitHub-Api-Version` (`adapters.rs`).
- **Operation-owned.** Which version, and what it changes at the provider.

### 2. Credential-mode guard

- **Primitive.** A byte-prefix allowlist on the leased secret, and an optional
  probe: one GET whose JSON value at one pointer must equal one declared
  literal.
- **Why it is a primitive.** A prefix test and one JSON equality are
  independent of what "test mode" means; the author states the convention.
- **Evidence.** `valid_static_secret` and `verify_account_response`
  (`auths-stripe` onboarding) and the lease-time prefix check in
  `credentials.rs`, all removed in epic 8 (see `09596075`); AP-SPEC-012 §7.
- **Operation-owned.** What a prefix or the probed field means.

### 3. Idempotency declaration

- **Primitive.** Either #156's derived `Idempotency-Key` (a deterministic
  function of namespace and logical operation ID), or a declaration that the
  body already carries the verified operation ID; plus a declared retention
  that the gateway shows and uses only for the retention rule.
- **Why it is a primitive.** Deterministic key construction from explicit
  commitments is on the plan's list of mechanisms that may be shared early.
  The declaration adds no behavior beyond sending the key and refusing an
  action whose window exceeds the declared retention.
- **Evidence.** #156; `IdempotencyPreimage` in `auths-stripe`; the Todoist
  command `uuid` in `bindings/fixtures/gateway/todoist/recipe.json`.
- **Operation-owned.** Whether the provider honors it, and for how long.

### 4. Response locator

- **Primitive.** One bounded string or non-negative integer read at one
  pointer of the recorded, complete, 2xx write response, percent-encoded into
  one path segment of the observation.
- **Why it is a primitive.** It reuses the observation pointer rules and the
  path encoder; it cannot add a segment, query, or fragment, and stores only
  the value.
- **Evidence.** AP-SPEC-012 §14 (the refund read by its returned ID); the
  GitHub issue `number` in case 0007.
- **Operation-owned.** What a later read-back match means.

### 5. Form echo

- **Primitive.** AP-SPEC-059's echo token in one new form field, added by the
  compiler in sorted order.
- **Why it is a primitive.** It is the existing JSON placement in the form
  grammar; the token, stages, and evidence record are unchanged.
- **Evidence.** `echo_token` in `recipe.rs`; the vertical wrote form
  `metadata[...]` fields (`local_agent.rs`, removed in epic 8; see
  `09596075`).
- **Operation-owned.** Authorship, which the unkeyed token never shows.

### 6. Pre-entry re-read

- **Primitive.** One GET after the lease and before the write, evaluated by the
  shipping AP-SPEC-060 predicates against the grant's own requirements.
- **Why it is a primitive.** It adds no condition language; it re-runs
  existing observation requirements on a fresh read.
- **Evidence.** AP-SPEC-012 §13; the plan's Phase 2 order;
  `observed_tests.rs`.
- **Operation-owned.** Which conditions apply. The write stays unconditional.

### 7. Relative ceiling

- **Primitive.** One integer read at one pointer, optionally minus a second,
  with up to two equality binds to verified fields, and one exact comparison
  `argument × 10 000 ≤ basis × basis_points` in `u128`.
- **Why it is a primitive.** It is checked arithmetic with explicit units, on
  the plan's early-shareable list, applied to a declared pointer. The ratio
  lives in the recipe, so no grant issuer can widen it (AP-SPEC-063 §13,
  reading 23).
- **Evidence.** `RelativeRefundLimit` and its basis-point check in
  `auths-stripe` `bounded.rs`; AP-SPEC-012 §5.
- **Operation-owned.** Which record and pointer are the basis, and what the
  ratio means.

### 8. Account binding at every lease

- **Primitive.** One JSON string read at one pointer, hashed under the
  installation's account domain, and compared in constant time with the
  connection record's commitment.
- **Why it is a primitive.** Constant-time comparison of two commitments is on
  the plan's early-shareable list; the read uses the probe mechanics.
- **Evidence.** `verify_account_response` at onboarding and the
  `account_commitment` lookup in `lease_credential` (`auths-stripe`, removed
  in epic 8; see `09596075`).
- **Operation-owned.** What an account is.

### 9. Denied reads

- **Primitive.** Up to four fixed-path GET or HEAD requests carrying only the
  credential and version headers, each of which must be answered with a
  declared 4xx status other than 408 and 429.
- **Why it is a primitive.** It compares HTTP statuses and nothing else. It is
  the one capability with no vertical implementation: the vertical checks only
  the `rk_test_` prefix. It replaces AP-SPEC-012's restricted-key requirement
  with an observed check, and claims only that the declared requests were
  refused at that lease.
- **Evidence.** AP-SPEC-012 §13's restricted credential; `valid_static_secret`
  and `lease_credential`, which cannot read a key's permissions (removed in
  epic 8; see `09596075`).
- **Operation-owned.** Which permissions a key should lack.

### 10. Account-scope headers

- **Primitive.** A second registry class whose value comes only from a
  verified field that every bounded link lists, sent on the write and every
  action read and never on a credential read.
- **Why it is a primitive.** Membership of a verified string in a sorted list,
  and a header whose value matches a registry grammar, need no knowledge of
  what the account context means.
- **Evidence.** `ConnectScope` in `bounded.rs` and `MerchantConnectAccount`
  in `merchant/policy.rs`; AP-SPEC-012 §7.
- **Operation-owned.** What the account context means at the provider.

### Sum budget

- **Primitive.** Policy `/2` members 4–6 (sum limit, partition, scope), and one
  sum counter per link subject and partition value whose slots carry a fixed
  running total, reserved atomically with the claim and never released.
- **Why it is a primitive.** It is a narrow atomic reservation with checked
  addition, keyed like the count counters; the partition values are listed
  by the grant and the partition field must reach the provider or be bound to
  the provider record, so an agent cannot spread one budget over labels of
  its choosing.
- **Evidence.** `AggregateRefundBudget` in `bounded.rs`; AP-SPEC-012 §6;
  AP-SPEC-025 §24–§25.
- **Operation-owned.** Release on proven non-effect or reconciliation, and
  rolling windows, which stay with the vertical's reference evaluator.

## Invariants across the capabilities

- Credential reads (probe, account read, denied reads) carry no action value
  and no account-scope header; action reads and the write carry verified
  values only.
- A version mismatch makes a read unavailable; it never makes a refusal pass.
- Every capability fails closed: an unreadable, oversized, non-JSON, or
  ambiguous response is unavailable, never zero or empty.
- No capability changes when `unknown` resolves: only a `linked` read-back
  does, as AP-SPEC-063 §4.4 states.
- Registry entries are closed; operator approval cannot widen them.

## Qualification

No capability here makes a recipe qualified, and no recipe claim goes beyond
AP-SPEC-063 §1: authorized, entered, recorded, and, where a read-back
succeeds, observed. A recipe could earn a qualified provider claim only
through a later ADR that names its digest family, keeps the vertical's pure
evaluator and fixtures as a test-only oracle, shows differential agreement
with that oracle on the vertical's corpus, and cites hosted evidence from a
live provider contract. Until such an ADR, no document may call a recipe
qualified. Epic 8 removed the AP-SPEC-044 qualification machinery with the
local-agent profiles it qualified, so such an ADR also specifies the hosted
evidence pipeline for the recipe it names.

## Rejected alternatives

1. **Keep the five Stripe checks only in the vertical (AP-SPEC-063 §12,
   option B).** Not chosen by the owner on 2026-09-27.
2. **A general expression language for ceilings and budgets.** AP-SPEC-060
   conditions stay comparison-only; arithmetic beyond one subtraction and one
   ratio is a new mechanism needing its own ADR.
3. **Provider-specific branches in gateway code.** That is dispatch on an
   operation tag, which the plan prohibits.
4. **Admitting the ten capabilities as one unit.** Each must be reviewable
   and removable on its own.
5. **Permission introspection.** HTTP has no provider-neutral form; denied
   reads claim only observed refusals.
6. **The relative ratio in each grant, as AP-SPEC-012 places it.** A grant
   issuer could then widen it; the recipe places it under operator approval.

## Consequences

- Epics 2–7 of AP-SPEC-063 implement the capabilities. Epic 1 commits their
  vectors under `bindings/fixtures/gateway/` (`hostile-recipes-v2.json`,
  `attempt-scenarios-v3.json`, `bounds-aggregate.json`, `outcome-v2.json`,
  `key-identity.json`, and `codes.json`), each with a test showing that
  current code does not satisfy it.
- ADR 0012 stays in force. Epic 8 rewrote its decision and consequences
  under §12 option A; this ADR changes only the set of mechanisms the
  interpreter may contain.
- A rejected capability loses its compile rows, codes, and vectors in the
  same change that records the rejection.
- AP-SPEC-063 §17 governs what any document may claim before each epic is
  green.
