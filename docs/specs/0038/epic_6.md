# Epic 6 — Qualify Three Exact-Effect Verticals

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** Epic 1; production runtime integration depends on Epics 2–3

**Blocks:** Epics 7–9

## Outcome

Qualify three materially different, fully open effect paths:

1. `auths.opentofu.saved-plan-apply/1` — infrastructure;
2. `auths.postgresql.bounded-update/1` — data; and
3. `auths.github.issue-address/1` — hosted service and ordered publication.

Each vertical must preserve its own action, evidence, evaluator, capacity,
credential, request, provider outcome, reconciliation, and receipt meaning
while using the shared durable mechanisms from Epics 2–3.

## Zero-context starting point

Read the profile/domain abstraction plan, then for each selected package read
all source and its governing specification:

- `product/integrations/auths-opentofu/` and
  `docs/specs/0009-opentofu-saved-plan-apply.md`;
- `product/integrations/auths-postgresql/` and
  `docs/specs/0010-postgresql-bounded-data-change.md`;
- `product/integrations/auths-github/` and
  `docs/specs/0005-github-issue-workflows.md`;
- `demos/opentofu-plan/`, `demos/postgresql-data-change/`, and
  `demos/github-issue/`;
- their entries in `compliance.toml`;
- `product/fixtures/v1/{opentofu,postgresql,github}/`; and
- Epic 3's coordinator and recovery contract.

Current facts:

- Each package already has closed canonical types, pure decision logic,
  profile-owned commands, gateways, lifecycle projections, receipts, and
  demonstrations.
- OpenTofu commits to one exact saved plan and its source/state/lock evidence.
- PostgreSQL compiles one bounded update with typed values, row preconditions,
  and before/after commitments.
- GitHub implements branch publication followed by one draft pull request,
  with separate actions, budgets, receipts, and recovery state.
- These verticals are deliberately not one generic “provider operation.”

## Product constraint

All three should feel like the same excellent product without pretending their
semantics are the same.

Root workflow:

```text
create -> delegate -> execute -> resume -> verify
```

Profile package:

```text
describe bounded authority -> create typed action -> connect closed provider
```

The first successful sandbox effect should take no more than 15 minutes from a
published package and one profile guide. The developer supplies meaningful
domain values; Auths supplies canonicalization, safe sequencing, idempotency,
receipt creation, and recovery plumbing.

Advanced controls—exact commitments, evidence sources, capacity algebra,
provider contracts, and reconciliation—remain accessible through progressive
disclosure and profile-specific documentation.

## Architecture

```text
                  shared open mechanisms
        +-----------------------------------------+
        | Rust verifier | lifecycle | store       |
        | custody | operations | receipts         |
        +-----------+-------------+---------------+
                    |             |
        +-----------+--+ +--------+------+ +----------------+
        | OpenTofu     | | PostgreSQL    | | GitHub         |
        | saved plan   | | bounded row   | | branch + PR    |
        | own gateway  | | own gateway   | | own gateways   |
        | own observer | | own observer  | | own recovery   |
        +--------------+ +---------------+ +----------------+
```

Shared code never accepts an arbitrary provider endpoint, operation, request,
credential, idempotency key, observation, or receipt payload.

## APIs and common vertical completion contract

Every vertical MUST own and test:

- strict input types with `deny_unknown_fields` and hard byte/count/work limits;
- canonical action and action digest;
- immutable policy, trusted evidence, required configuration, and executed
  configuration;
- total pure evaluator with closed eligible/denied/indeterminate codes;
- lifecycle projection into `DecisionInputV1`, reservations, execution intent,
  provider contract, and cancellation behavior;
- opaque verified command whose constructor is not available to callers;
- exact outbound request derived only from that verified command;
- typed credential scope and post-reservation acquisition;
- definite-effect, definite-non-effect, and possible-effect classification;
- read-only observation and reconciliation;
- domain decision, execution, observation, and reconciliation receipts;
- Rust-owned opaque/summary/full receipt inspection;
- profile-specific API, operator copy, examples, and runbook;
- deterministic fixtures, mutation corpus, crash/replay/concurrency tests; and
- a real provider sandbox/local effect with cleanup and redacted evidence.

## Vertical A — OpenTofu saved-plan apply

Keep semantics in `auths-opentofu`.

Production input commits to:

- source-bundle digest and pinned module identities;
- saved plan artifact digest and canonical projection;
- dependency-lock digest;
- backend/workspace and before-state evidence;
- permitted resource-change summary and configured limits;
- executor audience, expiry, evaluator/configuration identities; and
- exact provider condition/idempotency material.

Required implementation work:

- [ ] Replace development plan-artifact and receipt stores in the production
  composition with durable bounded stores.
- [ ] Bind the Epic 3 recovery-reference digest into the lifecycle projection.
- [ ] Use `ExecutionAuthorizationV1` to obtain short-lived execution
  credentials/workload identity only after durable intent.
- [ ] Use `ProviderCallAuthorizationV1` immediately before invoking the closed
  OpenTofu runtime.
- [ ] Persist plan artifact and lock/state evidence before accepting the
  workflow; reject missing or changed artifact bytes.
- [ ] Run `tofu show`/apply through a closed argument builder. No user-provided
  binary path, flags, environment, working directory, backend parameters, or
  shell is accepted at execution time.
- [ ] On process/network ambiguity, observe backend state and exact resource
  postconditions before deciding effect/non-effect.
- [ ] Keep unknown when observation cannot prove either conclusion.

API:

```text
POST /v1/profiles/opentofu/saved-plan-apply/execute
GET  /v1/workflows/{opaque-reference}
```

The request is one typed saved-plan submission. It does not contain arbitrary
OpenTofu CLI arguments.

Live evidence uses a disposable cloud sandbox or local provider with a small,
reversible resource. It records plan/apply identifiers and redacted resource
commitments, then destroys the resource and proves cleanup.

## Vertical B — PostgreSQL bounded update

Keep semantics in `auths-postgresql`. This package is the *protected data
effect*. It is distinct from the Auths lifecycle PostgreSQL store in Epic 2.

Production input commits to:

- database/relation policy identity, not a caller connection string;
- schema and column evidence;
- typed predicate and assignment values;
- exact expected before row/version state;
- maximum affected row count and configured isolation level;
- computed after-state commitment;
- executor audience, expiry, evaluator/configuration identities; and
- provider condition/idempotency material.

Required implementation work:

- [ ] Bind the vertical service to the Epic 3 lifecycle coordinator.
- [ ] Obtain a least-privilege database role only after durable intent.
- [ ] Compile SQL exclusively through `compile_statement`; the gateway accepts
  `CompiledBoundedUpdate`, never raw SQL.
- [ ] Run precondition check and mutation in one transaction at the configured
  isolation level.
- [ ] Enforce affected-row bound and exact returned state before commit.
- [ ] Record provider entry at the last durable point before beginning the
  mutation transaction.
- [ ] On connection loss during commit, retain outcome unknown and reconcile
  through read-only comparison of the committed before/after identities.
- [ ] Never infer non-effect merely because reconnect cannot find an expected
  row; schema and identity mismatch are indeterminate.

API:

```text
POST /v1/profiles/postgresql/bounded-update/execute
GET  /v1/workflows/{opaque-reference}
```

The request carries the profile's typed bounded-update intent. It cannot carry
SQL, connection settings, credentials, arbitrary isolation, or transaction
callbacks.

Live evidence uses a dedicated TLS test database and a table containing only
synthetic data. The suite proves exact update, boundary-plus-one denial,
concurrent precondition conflict, ambiguous commit recovery, and cleanup.

## Vertical C — GitHub issue-address workflow

Keep semantics in `auths-github`.

This is an ordered two-effect workflow:

1. publish one exact branch candidate; then
2. open one exact draft pull request referencing the branch receipt.

The second action is separately authorized and cannot be minted before the
first action's committed receipt is available. Do not flatten both provider
effects into one generic command or expose a partially effect-capable plan.

Production input commits to:

- repository owner/name and issue identity;
- inspected candidate/source identity and containment evidence;
- exact base revision, target branch, commit/tree changes, and candidate digest;
- branch and pull-request budgets;
- draft PR title/body commitments;
- executor audience, expiry, evaluator/configuration identities; and
- exact GitHub provider contracts and idempotency/conditional material.

Required implementation work:

- [ ] Bind both actions to Epic 3 without changing their separate command,
  capacity, request, receipt, and recovery types.
- [ ] Acquire credentials independently for branch and pull-request scopes.
- [ ] Derive Git data and GitHub API requests only from verified commands.
- [ ] Preserve the branch receipt commitment as a required input to PR action.
- [ ] Reconcile branch publication from the exact ref/object state.
- [ ] Reconcile pull-request creation from repository, head/base, draft state,
  and fixed Auths metadata; never select a merely similar PR.
- [ ] Report branch-completed/PR-unknown as a recoverable partial plan, never as
  full success or a command that permits another branch publication.

API:

```text
POST /v1/profiles/github/issue-address/execute
GET  /v1/workflows/{opaque-reference}
POST /v1/workflows/resume
```

Live evidence uses a dedicated sandbox repository, opens only draft PRs on a
fixed prefix, records redacted commitments, and deletes/ closes all generated
resources in cleanup.

## SDK profile UX

Epic 6 defines the profile-specific contract consumed by Epic 7. Target shapes:

```typescript
const action = opentofu.applySavedPlan({ plan, workspace });
const provider = opentofu.provider({ artifacts, gateway, credentials });
const result = await auths.execute({ action, provider });
```

```python
action = opentofu.apply_saved_plan(plan=plan, workspace=workspace)
provider = opentofu.provider(artifacts=artifacts, gateway=gateway, credentials=credentials)
result = await auths.execute(action=action, provider=provider)
```

Production convenience factories may compose proven ports, but provider
credentials are never arguments to `execute`, and the profile's closed gateway
does not expose arbitrary requests.

## Common adversarial matrix

For every vertical test:

- exact valid fixture and every field mutation;
- missing, extra, duplicate, non-canonical, oversized, and boundary-plus-one
  input;
- expired/revoked authority and stale evidence;
- required/executed configuration mismatch;
- budget/capacity exhaustion and concurrent final capacity;
- changed verified command or outbound request;
- credential request before durable authorization;
- gateway call before durable provider entry;
- timeout before send, failure before effect, possible effect, lost response,
  and receipt persistence failure;
- restart from each lifecycle checkpoint;
- replay from a second host;
- exact observation, mismatched observation, stale observation, and unavailable
  observation; and
- receipt mutation and disclosure authorization.

Provider-request equality tests compare the exact request produced at the
gateway to the frozen request fixture. They must not stop at digest equality.

## Evidence and qualification

For each vertical add:

- canonical valid/invalid fixtures and mutation manifest;
- conformance report linked from `compliance.toml`;
- live sandbox result with provider request count, outcome, observation,
  receipts, and cleanup;
- credential ordering trace with no credential data;
- crash/replay/reconciliation report;
- bounded performance envelope;
- operator runbook; and
- exact limitations and provider assumptions.

At least one selected vertical must run with an external design partner in a
non-production or explicitly gated pilot. Customer acceptance does not waive
technical gates.

## Validation commands

```text
cargo test -p auths-opentofu -p auths-postgresql -p auths-github
cargo test -p auths-opentofu-demo -p auths-postgresql-demo -p auths-github-demo
cargo xtask bounded-domains
cargo xtask compliance
cargo xtask semantic-freeze
cargo xtask live-demo
```

Run live provider jobs only with sandbox credentials, explicit cost/effect
limits, cleanup traps, and redacted artifacts.

## Exit gate

This epic is complete when all three verticals pass the common matrix and
their own live contracts; no generic provider/reconciliation semantics were
introduced; exact outbound requests and credential ordering are proven; every
possible effect is recoverable; and a developer can complete each published
sandbox quickstart in 15 minutes without understanding lifecycle internals.
