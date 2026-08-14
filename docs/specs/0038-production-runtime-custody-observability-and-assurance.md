# AP-SPEC-038: Open Production Substrate and Assurance Gate

**Status:** Specified as nine ordered implementation epics. Production claims
remain prohibited until the completion gate in this document is satisfied for
one immutable release candidate.

**Depends on:** [AP-SPEC-026 reservation and execution
semantics](0026-reservation-and-execution-state-semantics.md), [AP-SPEC-029
human approval and custody](0029-human-approval-and-custody.md), [AP-SPEC-032
reproducible release candidates](0032-reproducible-release-candidate-and-exact-assurance-claim.md),
[AP-SPEC-033 independent review](0033-independent-review-and-remediation-gate.md),
and the maintained Rust, TypeScript, and Python SDK contracts

**Commercial boundary:** [AP-SPEC-039 enterprise coordination and
operations](0039-enterprise-coordination-and-operations-plane.md)

## 1. Product decision

Auths will provide a complete open, self-hostable path for safely authorizing,
executing, recovering, observing, and auditing exact effects. This path must
work without an Auths-hosted service, private package, commercial account, or
online license check.

The production claim is release-scoped. It names the exact runtime topology,
store, custody adapters, provider profiles, SDK versions, limits, deployment,
and evidence. It is not a blanket claim about every package or future commit.

**Product-experience north star:** this must feel like Stripe-quality authority
infrastructure: intuitive before it is impressive, and extremely powerful when
the user deliberately asks for more. The default product surface remains five
verbs—`create`, `delegate`, `execute`, `resume`, and `verify`—acting on five
nouns—Identity, Authority, Action, Approval, and Receipt. A new developer must
reach a safe sandbox effect in fifteen minutes without learning the internal
protocol. Advanced custody, lifecycle, reconciliation, disclosure, and profile
composition remain available through progressive disclosure, not through a
wider default API.

```text
untrusted request
       |
       v
+------------------+      +------------------------+
| Rust verification|----->| durable lifecycle store|
| + exact profile  |      | reservation + receipts |
+---------+--------+      +------------+-----------+
          |                            |
          | sealed durable authority  | recoverable state
          v                            v
+------------------+      +------------------------+
| profile-owned    |<-----| profile-owned observer |
| closed gateway   |      | and reconciler         |
+---------+--------+      +------------------------+
          |
          v
 exact provider effect

TypeScript and Python call the same Rust-owned semantic operations.
Telemetry observes the path but cannot change it.
```

## 2. Open-source boundary

The open repository owns every component required for safe customer-operated
use:

- protocol, canonical formats, verifier, authoring, and formal artifacts;
- durable lifecycle, replay, capacity, receipt, and recovery semantics;
- a qualified PostgreSQL adapter and reference deployment;
- custody ports, transaction-bound signing requests, conformance fixtures, and
  maintained reference adapters;
- Rust, TypeScript, and Python workflow APIs;
- privacy-safe operational vocabulary, exporters, dashboards, alerts, and
  runbooks;
- exact-effect profiles, closed gateways, and adversarial fixtures;
- local receipt disclosure, inspection, and export; and
- public artifact identities, SBOMs, advisories, and assurance evidence.

Open packages must not import commercial modules. Enterprise services may
supply optional signed evidence through public ports, but their absence cannot
widen authority or prevent ordinary local verification and enforcement.

## 3. Epic order

Each epic is an executable specification for a zero-context implementation
agent. Complete them in order unless an epic explicitly permits parallel work.

| Order | Epic | Outcome |
| --- | --- | --- |
| 1 | [Freeze the production contract](0038/epic_1.md) | One machine-checked candidate manifest, topology, API, and evidence contract |
| 2 | [Qualify the PostgreSQL lifecycle store](0038/epic_2.md) | Multi-host durable state with TLS, pooling, failover, corruption, and backup evidence |
| 3 | [Build runtime orchestration and recovery](0038/epic_3.md) | Sealed execution ordering, opaque recovery handles, leases, and profile-owned reconciliation |
| 4 | [Harden external custody](0038/epic_4.md) | Closed KMS/PKCS#11 adapters with transaction binding, lifecycle, and conformance |
| 5 | [Build privacy-safe operations and operator UX](0038/epic_5.md) | Rust-owned telemetry, readiness, local APIs, dashboards, alerts, and runbooks |
| 6 | [Qualify three exact-effect verticals](0038/epic_6.md) | OpenTofu, PostgreSQL, and GitHub production paths with real sandbox evidence |
| 7 | [Deliver TypeScript and Python parity](0038/epic_7.md) | Identical thin SDK projections over the Rust lifecycle and profile operations |
| 8 | [Ship the open reference deployment](0038/epic_8.md) | Reproducible three-node deployment, recovery, supply-chain, and operator package |
| 9 | [Run sustained qualification and independent review](0038/epic_9.md) | One immutable candidate with fault, load, security, and 30-day evidence |

Epic 4 may begin after Epic 1 while Epic 2 is underway. Epic 6 vertical-local
fixture work may begin after Epic 1, but integration with the production
runtime waits for Epic 3. Epic 7 begins only after the Rust operational contract
from Epics 2–4 is stable. Epics 8 and 9 are integration gates and remain last.

## 4. Repository rules for every epic

Before editing, read `AGENTS.md` and
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md` completely.

Every epic must preserve these rules:

- Rust owns canonicalization, lifecycle transitions, custody-response
  validation, error classification, and receipt meaning.
- TypeScript and Python are thin, type-safe projections; they do not implement
  alternative state machines.
- Provider actions, evidence, credentials, requests, retry rules,
  reconciliation, and receipts remain in cohesive domain packages.
- Shared runtime code may own identical storage, leasing, readiness, and
  transport mechanisms; it may not dispatch semantic behavior from a generic
  operation tag or arbitrary payload.
- Credentials are acquired only from sealed durable authorization.
- Possible provider effects remain unknown until fresh domain evidence proves
  effect or non-effect. They are never blindly retried.
- Public inputs are parsed into closed bounded types before use.
- Prelaunch changes are direct cutovers. Do not add legacy readers, shims,
  aliases, dual writes, deprecations, or multiple runtime paths.
- Existing untracked or unrelated changes belong to the user and remain
  untouched.

If an epic introduces or removes a package, update the root workspace,
`architecture.toml`, `compliance.toml`, architecture snapshots, semantic-freeze
inventory, and release subjects atomically.

## 5. UX contract

The open operator experience is for one customer-operated deployment. It is
not an enterprise organization or fleet console.

```text
+------------------------------------------------------------------+
| Workflow 7X... · PostgreSQL bounded update                       |
+------------------------------------------------------------------+
| Authorized | Reserved | Provider possible | Reconciling          |
+------------------------------------------------------------------+
| Effect: UNKNOWN — do not retry                                   |
| Recovery age: 43s        Observer: healthy        [Reconcile]     |
+------------------------------------------------------------------+
| Public details: bounded summary                                  |
| Sensitive receipt: authorization required                        |
+------------------------------------------------------------------+
```

Authorization, durable reservation, provider entry, reported outcome,
observation, reconciliation, and receipt persistence must remain visibly
distinct. A health check, successful transport, approval, or provider HTTP
response must never be displayed as authorization.

## 6. APIs

The reference service exposes only infrastructure-neutral health and retrieval
routes plus profile-specific workflow routes. It does not accept a generic
provider payload.

```text
GET  /live
GET  /ready
GET  /version
GET  /metrics
POST /v1/authority/create
POST /v1/authority/delegate
POST /v1/profiles/opentofu/saved-plan-apply/execute
POST /v1/profiles/postgresql/bounded-update/execute
POST /v1/profiles/github/issue-address/execute
POST /v1/workflows/resume
GET  /v1/workflows/{opaque-reference}
GET  /v1/receipts/{id}/summary
POST /v1/receipts/{id}/disclose
```

Every execution route parses one profile-owned request type and invokes that
profile's concrete service. The composition node may resolve an opaque recovery
reference to one closed, compiled-in profile worker; the shared runtime never
interprets profile meaning. There is no `POST /workflows` body containing a
profile name plus arbitrary JSON. Full receipt views require Rust-owned
disclosure authorization.

## 7. Bounded production claim

Completion supports only this statement:

> Auths release candidate RC.N operated the named profiles on the documented
> open three-node/PostgreSQL deployment with the named custody and provider
> adapters. Under the recorded load, crash, failover, partition, replay,
> possible-effect, key, backup, restore, and recovery tests, it preserved exact
> authorization, durable reservation, credential ordering, receipt truth, and
> reconciliation. The immutable candidate and claims passed the recorded
> independent reviews with no unresolved critical or high findings.

It does not establish correctness of unregistered profiles or deployments,
provider atomicity beyond observed evidence, universal exactly-once effects,
regulatory compliance, freedom from defects, or inheritance by later commits.

## 8. Completion gate

No general production claim is permitted until:

- every epic checklist and exit test is complete for one immutable candidate;
- the runtime and store pass the full multi-host fault matrix;
- custody adapters pass transaction-binding and lifecycle conformance;
- operations, backup, restore, and emergency controls are exercised by a
  second operator;
- three real provider verticals and both language SDKs pass differential and
  installed-artifact evidence;
- the candidate runs for at least 30 days within frozen objectives;
- no critical or high independent-review finding remains unresolved;
- all claims match the exact evidence strength; and
- the release owner signs the bounded production gate report.

Anything less is a development build, release candidate, restricted preview,
sandbox integration, or design-partner pilot according to its actual evidence.
