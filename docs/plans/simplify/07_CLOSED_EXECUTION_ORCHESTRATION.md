# 07 — Profile-owned closed execution

**Status:** implemented for the MCP single-effect vertical; ordered coordination is tracked by Milestone E  
**Milestones:** C — one vertical proof; E — ordered plans and recovery  
**Design dependencies:** [02](02_SECURITY_AND_PARITY_GUARDRAILS.md), the facade design in [05](05_PRIMARY_PRODUCT_WAIST.md), and [`PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`](../../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md)

## Current issue

Today the repository contains the pieces required for safe effects, but a
binding or application can still become responsible for the order among
authorization, durable reservation, credential acquisition, provider entry,
result handling, reconciliation, and receipt minting. That creates two risks:

1. TypeScript and Python can implement subtly different Auths meaning.
2. A universal coordinator can erase the semantics that belong to a concrete
   effect domain.

The system needs closed orchestration without a lowest-common-denominator
provider abstraction.

## Components of the problem

- effect-capable commands must never become ordinary binding values;
- Rust must gate security transitions even while TypeScript/Python perform I/O;
- provider request, result, credential, and reconciliation semantics differ by
  domain;
- reservation must precede credentials and remote effects;
- cancellation means different things before and after provider entry;
- a possible remote effect must block blind retry;
- ordered plans must not release later members prematurely;
- caller-selected idempotency values may not be bound to the authorization;
- a shared FFI representation can accidentally become a universal state model.

## Architecture decision

Each qualified profile owns an opaque Rust execution session. The session
produces at most one bounded next step. TypeScript or Python performs exactly
that I/O and returns a parsed bounded result to Rust. Rust accepts or rejects
the result and then either releases the next step or returns a terminal value.

```text
application
    |
    v
Auths.execute(profile action + profile provider)
    |
    v
Rust profile session
    |
    +-- terminal: denied / indeterminate / completed / failed
    |
    +-- next bounded step -----------------------------+
                                                       |
                                             TS/Python I/O driver
                                                       |
    +<------------- parsed bounded result -------------+
    |
    v
Rust profile session accepts result and advances
```

The binding never chooses the next transition. It switches exhaustively over
the step variants Rust released, invokes the matching typed port, bounds and
parses the response, and submits it back to the same session.

A shared private FFI carrier may transport common shapes such as `read state`,
`compare-and-swap`, `request approval`, `sign`, `acquire credential`, `call
provider`, or `persist receipt`. That carrier is plumbing only. A profile owns
which variants it uses, their order, their commitments, and the meaning of
their results. There is no public `EffectProvider`, `ProviderResult`, generic
reconciler, or fixed universal effect state machine.

## Opaque session contract

The Rust-owned session/reference must be:

- unforgeable outside native code;
- non-cloneable and single-consumer;
- non-serializable, non-picklable, and non-subclassable;
- bound to the exact profile, semantic version, authority, context, action or
  plan commitment, execution record, and application request ID;
- unable to expose canonical command bytes as reusable application data;
- invalidated or terminal after consuming a step result;
- resumable only through a separate authenticated execution reference stored
  with durable state.

Bindings own resource lifetime and asynchronous cancellation, not state
transition meaning.

## Commitment-derived idempotency

The public API may accept a bounded application `requestId`/`request_id` for
correlation. It never accepts a provider idempotency key.

Rust/profile code derives:

```text
execution identity = H(
  semantic subject,
  profile identity/version,
  authority commitment,
  trusted-context commitment,
  action or plan commitment,
  plan position,
  application request ID
)
```

The profile derives any provider-specific token from that execution identity
according to the provider's requirements. An identical committed request
joins or observes the same durable execution. A conflicting commitment cannot
reuse the execution identity. The raw derived value is not exposed as a
general application credential.

## Profile-owned responsibilities

Every maintained effect vertical owns and versions:

- typed action/plan construction and display;
- provider request construction from sealed profile data;
- credential scope and acquisition timing;
- remote result/error parsing and bounded canonicalization;
- not-applied, possible, and applied evidence rules;
- cancellation and timeout meaning at each domain step;
- reconciliation inputs, remote queries, and accepted evidence;
- receipt claims and domain-specific failure identities;
- ordered-plan member semantics where supported; and
- TypeScript/Python parity fixtures and profile conformance cases.

MCP is the first proof vertical. The implementation must not generalize its
transition sequence into a contract for GitHub, Stripe, Kubernetes, OpenTofu,
PostgreSQL, Records, or future domains.

## MCP development handler contract

Milestone C must specify and implement the exact application-written boundary
used by Recipe 3. It is MCP-specific, not a base `Provider` interface.

TypeScript target shape:

```ts
type McpToolHandler<Input, Output> = (
  input: Input,
  context: McpToolContext,
  signal: AbortSignal,
) => Promise<McpHandlerOutcome<Output>>;

const reports = mcp.developmentProvider({
  tools: { publish_report: publishReport },
});
```

Python target shape:

```python
McpToolHandler = Callable[
    [Input, McpToolContext],
    Awaitable[McpHandlerOutcome[Output]],
]

reports = mcp.development_provider(
    tools={"publish_report": publish_report},
)
```

The concrete generic/Protocol spelling is language-idiomatic, but both
bindings enforce the same contract:

- construction parses a bounded immutable tool-name-to-handler map before I/O;
- duplicate, unsupported, empty, malformed, or excessive tool declarations
  fail construction with registry-owned bounded errors;
- Rust releases only a profile-decoded typed input plus bounded context;
- context contains correlation/cancellation data and inert review metadata, not
  authority, credentials, command bytes, or a reusable session handle;
- the handler returns a closed `not-applied | applied | possible` outcome; raw
  return values may be accepted only as an explicit convenience mapping to
  `applied`;
- the binding parses and bounds the outcome against versioned MCP profile
  limits before submitting it to Rust;
- malformed, wrong-tool, oversized, or excessive-depth output is rejected and
  never truncated;
- a handler throw, rejected promise, unhandled Python exception, timeout, or
  cancellation after invocation begins maps to `possible` unless the handler
  returned profile-accepted conclusive `not-applied` evidence;
- the provider exception/body is sanitized into a bounded cause category;
- a timeout uses a profile-declared limit or an explicitly parsed bounded
  override committed before authorization; and
- a second handler invocation cannot occur until Rust accepts the first
  outcome and releases another step.

The MCP profile manifest records exact limits for tool count, tool-name bytes,
input bytes/depth, output bytes/depth, safe error bytes, and duration. The
TypeScript and Python constructors derive from those values rather than
maintaining independent constants. A 40 MB return fails at the binding/profile
boundary before it can enter Rust, logs, receipts, or support output.

## Profile-authoring cost gate

“Write a profile” and “create a new effect domain” are different products and
must be measured separately.

### Tier 1 — Application specialization

An application specialization reuses a qualified vertical's provider,
transition, reconciliation, and receipt semantics while defining narrower
application actions, authority, display, and fixtures. The worked example is
the MCP reports specialization used by Recipe 3.

Provisional budget: one developer unfamiliar with the internals completes it,
including negative authority cases and both language examples, in at most eight
active engineering hours using the candidate profile construction API. If
`framework` has passed its extraction gate, that API must be public; otherwise
the experiment runs against the proposed private construction API and does not
publish it merely to make the metric pass.

### Tier 2 — Qualified effect vertical

A qualified vertical owns the full responsibilities listed above. The worked
example is the Records domain, chosen because its resource mutation, remote
outcome, and reconciliation behavior differ materially from MCP.

Provisional budget: from the recorded pre-milestone Records baseline to green
Rust, TypeScript, Python, installed-artifact, recovery, receipt, and profile
conformance evidence in at most five active engineering days. The measurement
includes repository-local design, Rust semantics, bindings, types, tests,
fixtures, documentation, package snapshots, and semantic-freeze updates. It
may exclude waiting time for external infrastructure or independent review,
but not work required to make local qualification pass.

For both tiers record:

- baseline revision and pre-existing reusable code;
- active engineering time and elapsed calendar time;
- files and lines added/changed by Rust, TypeScript, Python, fixtures, and docs;
- new semantic identities, registry codes, manifest entries, and conformance
  cases;
- number of framework/private imports or core changes required;
- failed design attempts and manual steps; and
- the exact first-green and fully-qualified revisions.

If either provisional budget fails, Milestone F cannot claim low-cost profile
extension. The implementation must reduce ceremony or publish a reviewed
exception with the observed cost and resulting product limitation before 1.0.

## Single-effect safety rules

- Authorization completes before state, credential, or provider steps.
- Durable reservation completes before credential acquisition.
- Provider entry is marked durably before an ambiguous call can escape.
- Each next side effect requires a Rust-accepted result from the previous step.
- A denied or indeterminate decision releases no effect session.
- A malformed, oversized, wrong-profile, stale, duplicated, or substituted
  step result terminates without releasing another side effect.
- An observed applied effect can mint a receipt only after the profile accepts
  its evidence.
- A possible effect persists a recovery reference and blocks new execution.

## Cancellation and ambiguity

- Before provider entry, cancellation yields `effect=not-applied`; retry is
  allowed only if the profile/session returns a safe classification.
- After provider entry, cancellation yields `effect=possible` unless the
  profile accepts conclusive no-effect evidence.
- A possible effect never automatically retries, reacquires credentials, or
  re-enters the provider.
- Resume opens the stored profile session from an opaque execution reference.
  The caller cannot swap the profile, provider kind, action, or idempotency
  input.
- Reconciliation is a profile operation. It may conclude not-applied, applied,
  still-possible, or a profile-specific terminal failure.

## Ordered plans

Milestone E extends the same profile-session model:

- Rust commits the complete ordered plan before approval or signing;
- approval binds the exact plan commitment, not a mutable member list;
- only the current member's step may be released;
- a failed or possible member prevents later member release;
- completed members remain recorded and cannot be repeated;
- cancellation exposes bounded completed/current/not-started projections but
  no partial effect-capable command;
- each member's derived execution identity binds its plan commitment and index;
- receipts link to the plan and member position without claiming provider-level
  atomicity.

Cross-profile ordered plans require an explicit Rust-owned plan coordinator
whose members remain delegated to their profile-owned sessions. They do not
create a generic provider state machine.

## Implementation steps

- [x] Select MCP as the Milestone C proof vertical and inventory its real
  action, provider, failure, reconciliation, and receipt semantics.
- [x] Freeze the MCP handler input, context, closed outcome, bounds, timeout,
  exception, cancellation, and disposal contracts in its versioned manifest.
- [x] Define the private opaque Rust session/reference and bounded FFI step
  carrier.
- [x] Move transition selection, execution identity derivation, and receipt
  eligibility into Rust/profile code.
- [x] Implement exhaustive TypeScript and Python I/O drivers with equivalent
  parsing, bounds, cancellation, and disposal behavior.
- [ ] Remove public generic provider idempotency inputs.
- [ ] Add hostile tests for forged, cloned, serialized, stale, duplicate,
  wrong-profile, and substituted session/results.
- [ ] Add handler tests for duplicate tools, throws, rejection/exceptions,
  hangs, cancellation, wrong outcome types, 40 MB output, excessive nesting,
  redaction, and attempted second entry.
- [ ] Add deterministic crash-point tests before/after every side-effect step.
- [ ] Prove zero credential/provider entry after denial, indeterminate,
  reservation failure, or invalid prior result.
- [x] Implement profile-bound resume/reconciliation for MCP.
- [ ] In Milestone E, add ordered-plan coordination and cross-language receipt
  fixtures without exposing partial commands.
- [ ] In Milestone F, run and publish the Tier 1 MCP reports and Tier 2 Records
  authoring measurements against the declared budgets.
- [ ] Update semantic freeze and formal/assurance evidence for every new
  security transition identity.

## Acceptance criteria

- TypeScript/Python contain no independent table or branch structure that
  decides Auths/profile transition meaning.
- Every side effect after the first requires a Rust-accepted bounded result.
- Session and step handles cannot be constructed, copied, serialized, pickled,
  subclassed, or replayed from either binding.
- Concurrent identical execution produces one profile provider entry.
- A conflicting committed request fails before credentials/provider I/O.
- No public operation accepts a provider idempotency key.
- Cancellation before and after provider entry yields different stable effect
  classifications where required.
- A possible effect blocks execute until the same profile session reconciles.
- MCP passes the same Rust-generated transition and receipt cases in both SDKs.
- TypeScript and Python MCP handlers accept the same logical inputs/outcomes,
  enforce the same manifest bounds, and map throw/timeout/cancellation to the
  same Rust-registered codes and effect states.
- Adding a second profile does not require weakening or expanding a universal
  provider result/state contract.
- The two authoring experiments report complete costs; passing claims require
  the eight-hour specialization and five-day qualified-vertical budgets or an
  explicit reviewed exception that blocks a low-friction claim.

## Non-goals

- Distributed transactions across Auths and arbitrary providers.
- Automatically deciding whether an ambiguous remote effect happened.
- A generic untyped provider callback or cross-domain result union.
- Moving asynchronous network/database I/O into Rust solely to centralize it.
