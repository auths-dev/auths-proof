# AP-SPEC-038: Open Production Substrate and Assurance Gate

**Status:** Specified as nine ordered implementation epics. Production claims
remain prohibited until the completion gate in this document is satisfied for
one immutable release candidate. §9 engineering is implemented on branch
`038-production-trust` (see §9.5); the §9.3 gate items that need a second
operator, a root ceremony record, or the AP-SPEC-060 §16 observer quorum are
open, and no §9 production claim is made.

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

## 9. Amendment (2026-09-23): gateway, provider evidence, observers, and Git signing

The gateway, provider-bound evidence, gateway observations, and Git signing
(AP-SPEC-053, 059, 060, 058) were built after this specification. Each runs
on development-grade trust today:

- The gateway's attempt store is a single-host file store
  (`FileGatewayAttemptStore`).
- The gateway observer key and Git-signing root keys are software seed files.
- A single operator provisions the trust, runs the gateway, and runs the
  observer.

This amendment brings them into the production substrate. It is not a
second production specification, and no general production claim covers
them until the requirements below are satisfied in the completion gate.

### 9.1 Scope added to existing epics

| Epic | Added requirement |
| --- | --- |
| 2 — PostgreSQL lifecycle store | The gateway's logical-operation claims, provider-bound evidence records, and outcome stages run on the qualified multi-host store. The single-host file store stays the development default. The multi-host fault matrix includes the gateway's replay, fresh-challenge, crash-after-entry, and concurrent re-observation cases. |
| 4 — External custody | The gateway observer key and Git-signing root keys are held behind `auths-custody` (KMS or PKCS#11), with the same transaction binding and lifecycle conformance as other custody. Each signer reports its custody kind. A trusted context MAY require a custody kind for roots and observers, and a verifier with that requirement MUST refuse any other kind. |
| 5 — Operations | The operator runbook covers observer key rotation, observer-anchor updates in trust, and Git-signing revocation records. |
| 9 — Qualification | The candidate's evidence includes a hostile run of observation-conditioned grants and provider-bound evidence against the multi-host deployment. |

### 9.2 Trust that does not reduce to one operator

A production deployment separates these principals, and the verifier
refuses any overlap:

- **Root.** It issues grants. Production roots are provisioned in a
  reviewed ceremony, recorded with who held which key share, and MAY be
  M-of-N through the kernel's `KOfN` composition.
- **Operator.** It runs the gateway and holds provider credentials.
- **Observer.** It signs observations. The kernel already refuses an
  observer that appears in an authority chain.

**Observer quorum.** A grant MAY require a K-of-N quorum of observers from
distinct operator domains (AP-SPEC-060 §16), for example the gateway plus a
read-only observer run by a different party.

- Each observer anchor declares its operator domain.
- Observers are counted per domain, so one operator cannot meet a quorum
  alone.
- The production deployment names the observer operators and their domains
  in the candidate evidence.

### 9.3 Claim and gate additions

The bounded claim in §7 extends to the gateway, provider evidence, and
observation-conditioned grants only when the deployment:

- runs them on the qualified store;
- holds the observer and root keys in qualified custody;
- separates root, operator, and observer principals.

The completion gate in §8 adds three items:

- the separation and custody requirements are exercised by a second
  operator;
- a 2-of-3 observer quorum across three distinct operator domains is
  demonstrated, including one refuting observer that leaves the quorum
  reachable and two that deny it;
- the root ceremony record is part of the candidate evidence.

### 9.4 Not in scope

- **Certification.** FIPS 140-3 validated modules, accreditation regimes,
  and similar programs are commercial and customer-driven. Nothing in this
  amendment claims them.
- **Hardware custody for local developer agents** (for example the Secure
  Enclave). It is deferred until someone adopts Git signing.


### 9.5 Implementation status

Implemented (engineering only; no production claim):

| Requirement | Where | Evidence |
| --- | --- | --- |
| §9.1 Epic 2: claims, provider-bound evidence, and outcome stages on the qualified store | `GatewayAttemptStore` in `auths-gateway`; `PostgresLifecycleStore` rows in schema `auths.lifecycle.postgresql/4` | One conformance suite on both stores: claim exactly once, replay, fresh challenge, unknown and re-observe, `echo-mismatch`, concurrent re-observation, fail-closed reads, and concurrent claims from two gateway processes. The PostgreSQL variants run in the PostgreSQL lifecycle workflow against its TLS fixture. |
| §9.1 Epic 2 fault matrix: replay, fresh challenge, crash after entry, concurrent re-observation | same | The attempt-scenario corpus and the conformance suite, on both stores. The TLS/pooling/failover/backup parts of the Epic 2 matrix are Epic 2's own open work. |
| §9.1 Epic 4: observer and Git roots behind `auths-custody` | `GatewayObserver::from_custody`, `CustodyKeySigner`, `CustodyKey` | KMS- and PKCS#11-held keys, through the reference adapters over mock provider APIs, sign observations and grants that verify in the kernel. The shared custody conformance kit runs every `CustodyConformanceCase` and every lifecycle state on both paths. |
| §9.1 Epic 4: each signer reports its custody kind | `ObserverCustody`, `GitProofSigner::custody` | Unit tests. |
| §9.1 Epic 5: runbook | [gateway trust and Git-signing runbook](../operations/GATEWAY_TRUST_AND_GIT_SIGNING_RUNBOOK.md) | Observer key rotation, observer-anchor updates, Git revocation records. |
| §9.1 Epic 9: hostile run against the multi-host store | `observed_tests` and `engine` suites | Observation-conditioned grants and provider-bound evidence, pre-generated fixtures, on both stores. |
| §9.2 separation | `check_principal_separation` in `auths-gateway`; production install | Stable codes `gateway.trust.operator-is-root`, `operator-is-observer`, `observer-is-root`, `observer-not-anchored`. |
| §9.2 root M-of-N | kernel `KOfN` with a two-distinct-root composition requirement | 2-of-3 root test. |

Readings taken:

- The operator is not a kernel principal, so operator separation lives in
  the gateway, its only consumer, and runs at install and at every start.
  Root and observer overlap is also checked statically there; the kernel's
  per-proof refusal is unchanged.
- Gateway claims are row-level insert-once and compare-and-swap operations
  in the lifecycle database. They do not take the singleton contract-row
  lock, so the AP-SPEC-057 §3 concern about that lock under competing
  instances does not arise for gateway claims.
- The AWS KMS and PKCS#11 reference adapters derived their principal as
  SHA-256 of the SEC1 key, which is not a `raw-key-v1` identifier; the
  kernel could not have verified their signatures. They now derive it
  through `CustodyIdentity`.

Open, each with its reason:

| Item | Reason |
| --- | --- |
| §9.3: separation and custody exercised by a second operator | Needs a second human operator. |
| §9.3: 2-of-3 observer quorum across three operator domains, with one refuting observer | Depends on AP-SPEC-060 §16, which the program board holds as demand-gated; not implemented. |
| §9.3: root ceremony record in the candidate evidence | Needs a reviewed human key ceremony. |
| §9.1 Epic 4: a trusted context requiring a custody kind for roots and observers | Custody kind is self-reported today; a verifier requirement needs provider attestation evidence and a trusted-context wire field (a core wire change with its own spec, fixtures, and bindings). Not implemented. |
| Custody keys in the shipped binaries | The `auths-gateway` and `auths-git` binaries have no KMS or PKCS#11 client: the reference adapters define ports with no maintained production client, and adding one (with SoftHSM CI) is Epic 4's own work. The binaries refuse a software observer in production and keep the software root for development. |
| Git trust M-of-N roots | AP-SPEC-058 pins one root anchor per repository trust, and a Git signature carries one delegation branch. An M-of-N Git root needs a 058 amendment for multi-branch signature proofs; the M-of-N composition is implemented and tested for gateway trust. |
