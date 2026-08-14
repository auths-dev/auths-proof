# AP-SPEC-039: Enterprise Coordination and Operations Plane

**Status:** Specified boundary and delivery gate — implementation of a paid
product remains conditional on the evidence and selection record required by
[AP-SPEC-031](0031-commercial-discovery.md)

**Depends on:** [AP-SPEC-031 commercial
discovery](0031-commercial-discovery.md), [AP-SPEC-038 open production
substrate](0038-production-runtime-custody-observability-and-assurance.md),
[AP-SPEC-032 reproducible release
candidates](0032-reproducible-release-candidate-and-exact-assurance-claim.md),
[AP-SPEC-033 independent review](0033-independent-review-and-remediation-gate.md),
and versioned public Auths protocols and packages

**Scope:** Optional hosted or enterprise-self-managed coordination around the
open Auths substrate: organization governance, trust and configuration
distribution, approval workflows, fleet operations, receipt retention and
search, managed integrations, deployment automation, residency, support, and
commercial service operation

**Architectural owner:** A separately licensed enterprise implementation that
depends only on versioned public Auths interfaces. The open `auths-proof`
repository owns the protocol, verifier, runtime, SDKs, conformance, reference
verticals, local operations, and assurance evidence.

**Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are
requirements on any product represented as the Auths enterprise plane.

## 1. Decision

Auths may offer an enterprise coordination and operations plane, but it will
not commercialize the correctness of local authorization.

The open system remains complete enough to:

- author and delegate authority;
- verify and enforce exact actions;
- operate durable lifecycle and recovery state;
- use external custody;
- inspect receipts under bounded disclosure;
- monitor and recover a self-hosted deployment; and
- evaluate its release and conformance evidence.

The enterprise product sells optional organizational leverage:

- administering many teams, environments, deployments, and trust sources;
- distributing signed configuration and policy safely;
- coordinating exact transaction-bound approvals;
- operating and upgrading fleets;
- retaining, searching, exporting, and governing permitted evidence;
- integrating enterprise identity, custody, monitoring, and workflow systems;
- satisfying residency, private-connectivity, and support requirements; and
- reducing the human cost of operating the open substrate.

```text
+----------------------- enterprise coordination ------------------------+
| organization | trust/config | approvals | fleet | evidence | support   |
+-------------------------------+----------------------------------------+
                                |
                  signed, versioned public contracts
                                |
                                v
+--------------------- customer enforcement boundary --------------------+
| open SDK -> open verifier/runtime -> closed profile gateway -> effect  |
+------------------------------------------------------------------------+
```

The default commercial topology is a hosted coordination plane with
customer-operated enforcement. Consequential provider credentials and exact
execution remain customer-near. A self-managed enterprise control plane MAY be
offered when buyer evidence justifies it. A multi-tenant hosted executor is not
part of the initial product and requires a new specification and threat model.

## 2. Product-selection gate

This specification defines a safe enterprise boundary. It does not establish
that every listed module should be built or that a buyer will pay for it.

Before implementation begins, AP-SPEC-031 MUST produce:

- linked observations from design partners;
- a named economic buyer and urgent problem;
- current alternatives, spend, and switching constraints;
- the minimum selected product and explicit exclusions;
- a hosted, self-managed, or hybrid topology decision;
- a data-processing and credential-boundary record;
- willingness-to-pay evidence;
- an open-core architecture test; and
- either one signed product-selection record or a no-build decision.

Only modules selected by that record enter the initial release plan. Remaining
modules are hypotheses, not backlog commitments. The product MUST be resliced
to the smallest useful operational outcome rather than treating this
specification as a mandate to build an enterprise suite at once.

## 3. Open and enterprise ownership

### 3.1 Open repository ownership

The open `auths-proof` repository owns:

- portable protocol semantics and canonical formats;
- Rust verification and authoring meaning;
- TypeScript and Python workflow APIs;
- local runtime, durable state, replay, budget, lifecycle, and recovery;
- custody and evidence ports plus conformance suites;
- privacy-safe operational vocabulary and self-hosted exporters;
- exact-effect profiles, closed gateways, fixtures, and reference deployments;
- local receipt disclosure, inspection, and export;
- artifact identities, SBOMs, vulnerability notices, and assurance evidence;
  and
- every interface required to use the open system without this product.

Security fixes and conformance evidence for those surfaces MUST NOT be
restricted to enterprise customers.

### 3.2 Enterprise implementation ownership

A proprietary enterprise implementation MUST live outside the MIT/Apache-2.0
open monorepo, normally in a separate private repository. This repository MAY
contain public specifications, schemas, integration contracts, client stubs,
conformance fixtures, and a non-privileged local simulator needed to prevent
vendor lock-in or semantic drift.

The enterprise repository MAY own:

- hosted organization and project administration;
- enterprise SSO, SCIM, organization RBAC, and separation of duties;
- signed trust, profile, and configuration distribution;
- approval routing and escalation workflows;
- fleet inventory, rollout, drift, and lifecycle automation;
- encrypted receipt retention, indexed search, legal hold, and governed export;
- managed KMS, HSM, SIEM, ticketing, and workflow integrations;
- hosted dashboards, alert routing, tenant analytics, and SLA reporting;
- residency routing, private connectivity, customer-managed encryption, and
  self-managed deployment packaging;
- billing, subscription, entitlement, and support systems; and
- customer-specific control mappings, onboarding, and review facilitation.

Commercial modules may depend on public Auths packages. Open packages MUST NOT
import commercial modules.

### 3.3 Boundary matrix

| Capability | Open substrate | Enterprise value |
| --- | --- | --- |
| Verification and enforcement | Complete local implementation | Fleet visibility; no alternate semantics |
| Durable state and recovery | PostgreSQL contract, adapter, tools, runbooks | Managed deployment, upgrades, backup coordination |
| Custody | Port, signing intents, conformance, reference adapters | Managed enrollment, rotation, vendor integrations, support |
| Operations | Vocabulary, exporters, dashboards, alerts, runbooks | Cross-fleet aggregation, paging, SLA and support workflows |
| Receipts | Local persistence, disclosure, inspection, export | Long retention, search, legal hold, governed cross-org export |
| Trust and policy | Canonical objects, verification, local configuration | Signed distribution, staged rollout, inventory and drift |
| Identity | Agnostic principal/evidence ports and adapters | SSO/SCIM administration and organization membership mapping |
| Profiles | SDK, conformance, open references | Supported connector catalogue and deployment assistance |
| Release evidence | Public identities, SBOM, advisories, review scope | Customer-specific mappings and facilitated assessments |

## 4. Hard architectural invariants

The enterprise plane MUST NOT:

- become necessary for ordinary local verification or execution using already
  available trusted inputs;
- mint a verifier-owned command, opaque authorization handle, decision receipt,
  or execution receipt;
- reinterpret grants, approvals, plans, lifecycle states, profile meaning, or
  canonical bytes;
- turn organization membership, SSO success, transport authentication, a
  workflow status, or a license entitlement into authorization;
- accept arbitrary provider commands, URLs, SQL, shell, callbacks, or payloads;
- acquire or transmit provider credentials before an open runtime has produced
  durable exact execution intent;
- silently retry a possible external effect;
- convert denial, indeterminate, unavailable, or provider-unknown into success;
- suppress security fixes, revocation information, or release evidence from
  non-paying open users;
- make cancellation of a subscription invalidate cryptographically valid local
  objects or prevent export of customer-owned data; or
- introduce a second enterprise-only authorization implementation in
  TypeScript, Python, a service, or a policy engine.

When the enterprise plane supplies approval, trust, identity, configuration,
or lifecycle evidence, that evidence is an ordinary bounded input to the open
runtime. Rust-owned parsing and verification remain authoritative.

## 5. Availability and failure semantics

The enterprise plane is optional infrastructure, not a fail-open oracle.

Every integration MUST declare one of three modes:

1. **Cached coordination:** previously verified, unexpired signed state remains
   usable during an outage until its explicit freshness boundary.
2. **Required fresh evidence:** the profile produces its declared denied or
   indeterminate result while fresh evidence is unavailable.
3. **Management only:** local authorization and enforcement continue, while
   inventory, search, rollout, or administrative operations are delayed.

There is no implicit default. Required and executed configuration commitments
make the selected mode visible.

An enterprise outage MUST NOT:

- widen authority;
- extend expiry or budgets;
- bypass approvals;
- erase reservations or possible effects;
- encourage blind provider retries; or
- prevent local emergency denial, reconciliation, receipt retrieval, backup,
  and customer-data export.

## 6. Trust and data boundary

### 6.1 Default data minimization

The hosted plane SHOULD receive commitments and bounded projections rather
than raw authorization material. By default it stores:

- organization, environment, deployment, and public profile identifiers;
- build, semantic, configuration, policy, and evidence commitments;
- bounded workflow stage and stable result codes;
- opaque local recovery and receipt references;
- privacy-safe fleet health and aggregate operational signals;
- signed approval responses bound to exact transaction commitments; and
- encrypted customer-authorized receipt projections.

It MUST NOT receive raw proofs, capability chains, action bodies, receipt bytes,
provider payloads, credentials, private keys, arbitrary resource identifiers,
or sensitive evidence unless a selected feature strictly requires them and an
explicit data-classification record authorizes the field.

### 6.2 Customer-controlled disclosure

Receipt ingestion and display MUST use the Rust-owned disclosure semantics:

- unauthorized viewers receive the opaque view;
- authorized bounded roles receive the summary view;
- explicitly authorized investigators receive the full permitted view; and
- no enterprise service reconstructs fields absent from the authorized
  projection.

Search indexes contain only approved bounded fields. Legal hold does not widen
disclosure. Exports bind query, tenant, purpose, requester, time, result count,
and object commitments to an auditable export receipt.

### 6.3 Credentials and keys

The preferred hosted plane holds no consequential provider credential and no
customer signing key. Customer-operated runtimes use workload identity and
customer custody.

If a selected managed connector requires an enterprise service credential, it
MUST have a dedicated threat model, tenant isolation, least-privilege scope,
short lifetime, audited access, revocation, emergency disablement, and a closed
profile-specific request path. This exception does not authorize a generic
hosted executor.

## 7. Enterprise threat model

In addition to AP-SPEC-038, the selected product MUST address:

- cross-tenant reads, writes, inference, cache bleed, and search leakage;
- organization, project, environment, and deployment identifier confusion;
- SSO, SCIM, role, group, and administrator mapping drift;
- compromised organization administrators and malicious support operators;
- confused-deputy approval routing and approval-response substitution;
- stale, rolled-back, partially distributed, or forked configuration;
- a control-plane compromise attempting to widen local authority;
- replayed fleet commands or downgrade to a vulnerable release;
- receipt disclosure, export, retention, deletion, and legal-hold conflicts;
- webhook, SIEM, ticketing, KMS, HSM, and workflow connector compromise;
- tenant-controlled high cardinality, storage exhaustion, and noisy-neighbor
  denial of service;
- residency or private-connectivity routing mistakes;
- billing or entitlement failures affecting security behavior;
- backup or disaster-recovery restoration into the wrong tenant;
- supply-chain substitution across open and enterprise release subjects; and
- insiders using support or break-glass access without customer-visible
  evidence.

Tenant isolation is necessary but not sufficient. A compromised enterprise
plane must still be unable to mint effect-capable authorization objects or make
a customer runtime execute arbitrary provider requests.

## 8. Module A — Organization governance

The governance module MAY provide:

- organizations, projects, environments, deployments, and teams;
- SAML or OIDC SSO and SCIM lifecycle synchronization;
- bounded administrator roles and separation of duties;
- service accounts and workload membership mapping;
- domain verification and organization recovery;
- break-glass access with two-person control; and
- customer-visible administrative audit records.

Organization roles govern use of enterprise management surfaces. They do not
become Auths authority. Mapping a user or workload into an Auths principal or
evidence object requires a versioned adapter and the same open verifier path as
any other identity source.

Every administrative mutation MUST be tenant-bound, idempotent, auditable, and
protected against stale revisions. High-risk mutations require reauthentication
and, where selected, transaction-bound multi-party approval.

## 9. Module B — Trust and configuration distribution

The distribution module MAY manage:

- trusted identity and signature-suite bundles;
- registered profiles and supported semantic versions;
- approval-policy, evidence-source, custody, and operational configuration;
- environment-specific overlays compiled into closed configuration;
- staged rollout, pause, rollback to an immutable safe release, and emergency
  revocation;
- deployment acknowledgements and drift inventory; and
- expiry, freshness, and minimum-version requirements.

Every delivered object MUST be canonical, signed, versioned, tenant- and
environment-bound, size-bounded, and independently verifiable by the open
runtime. The service distributes objects; it does not redefine their meaning.

The runtime reports required and executed configuration commitments. A
mismatch fails before reservation, credentials, or provider I/O. A rollback
selects a previously signed current configuration; it does not introduce dual
semantic readers or compatibility execution paths.

## 10. Module C — Transaction-bound approval workflows

The approval module MAY provide organization routing, notifications,
escalation, quorum collection, timeout, cancellation, and evidence delivery.

Every request binds:

- tenant and environment;
- requester and declared approver audiences;
- exact plan, action, context, policy, evaluator, and configuration
  commitments;
- approval policy and threshold;
- expiry and cancellation state; and
- response schema and signing identity.

Responses are signed evidence for the open runtime. There is no reusable
`approved = true` flag. Changed bytes, policy, configuration, approver set,
threshold, expiry, or transaction identity require a new request.

The service MUST distinguish declined, cancelled, expired, insufficient,
unavailable, invalid, and indeterminate outcomes. Notification delivery is not
approval. UI state is not approval. Database state without the required signed
response is not approval.

## 11. Module D — Fleet and deployment operations

The fleet module MAY provide:

- deployment registration and public-key enrollment;
- build, semantic, profile, configuration, and conformance inventory;
- health, capacity, version, drift, and recovery-state summaries;
- signed rollout intent and acknowledgement;
- canary, staged rollout, pause, and emergency revocation;
- self-managed installation and upgrade automation; and
- compatibility planning across public versioned interfaces.

Fleet commands are management instructions, not effect authority. Agents on a
customer deployment accept only closed, signed, audience-bound, expiring
commands from a pinned management trust root. They never accept arbitrary
shell, package URL, container tag, environment mutation, provider request, or
configuration bytes.

Rollout tooling verifies immutable digests, signatures, SBOM/provenance, schema
identity, supported upgrade edge, backup state, and rollback target before
activation. Prelaunch source cutovers remain direct; production lifecycle
support begins only after the first release explicitly covered by a support
policy.

## 12. Module E — Receipt and evidence operations

The evidence module MAY provide:

- encrypted retention by organization, environment, profile, and time;
- bounded search over authorized projections;
- disclosure-controlled receipt views;
- retention schedules, deletion, legal hold, and residency controls;
- tamper-evident export and evidence packages;
- case annotations that cannot alter canonical receipts; and
- links between decision, execution, reconciliation, disclosure, and export
  receipts.

Canonical receipts remain immutable. An annotation, case state, alert, or
ticket cannot rewrite what Auths decided or what the provider outcome means.

Customer export MUST be available in documented, non-proprietary formats. A
subscription end MUST allow a bounded export period and verified deletion. The
product MUST document which indexes, backups, holds, and cryptographic erasure
states remain and for how long.

## 13. Module F — Managed integrations

Commercial integrations MAY include:

- KMS and HSM enrollment, policy validation, rotation, and monitoring;
- SIEM, OpenTelemetry, paging, and incident-management routing;
- SSO, SCIM, HRIS, directory, and workload-identity sources;
- ticketing and human approval systems;
- cloud deployment and private-connectivity automation; and
- supported provider-profile packaging.

Every integration is a narrow adapter over a public port. It MUST use bounded
types, parse untrusted input once, preserve stable outcome classes, minimize
credentials, and have contract and adversarial tests. Integration failures
cannot be flattened into a generic unavailable or success response when the
open semantics distinguish denial, indeterminate, possible effect, or recovery.

Provider integrations follow the vertical-first process. Similar APIs do not
justify a generic enterprise connector or universal executor.

## 14. Module G — Hosted operations and support

The hosted product MAY provide:

- multi-tenant service operation and regional cells;
- customer-specific data residency and deletion controls;
- private ingress and egress connectivity;
- bounded fleet telemetry, dashboards, alerting, and escalation;
- backup, restore, disaster-recovery, and game-day coordination;
- published service objectives and measured availability;
- support cases, incident communication, and postmortems; and
- customer-specific assurance and control mappings.

No external SLA is promised until measured operation, recovery exercises,
staffing, legal terms, and an on-call model exist. Support access is
time-bounded, least-privilege, approved where required, and visible to the
customer. Support tooling cannot mint Auths authority or bypass receipt
disclosure.

## 15. Enterprise APIs and user experience

Public enterprise APIs MUST be versioned separately from internal services and
use opaque tenant-bound identifiers. Candidate resources include:

```text
/v1/organizations
/v1/environments
/v1/deployments
/v1/trust-bundles
/v1/configurations
/v1/approval-requests
/v1/fleet-rollouts
/v1/receipt-index
/v1/exports
/v1/integrations
```

The API MUST NOT expose an endpoint equivalent to:

```text
POST /execute-arbitrary-provider-request
POST /mint-authorized-command
POST /sign-arbitrary-bytes
POST /mark-provider-success
```

The enterprise UI MUST preserve the distinction among:

- identity and organization membership;
- distributed policy/configuration and local executed configuration;
- approval evidence and authorization decision;
- durable reservation and provider entry;
- reported, observed, unknown, and reconciled provider outcomes;
- canonical receipts and mutable case annotations; and
- platform health and authority to perform an effect.

Progressive disclosure SHOULD present five simple operational verbs—connect,
configure, approve, observe, and audit—while allowing expert access to exact
commitments, evidence freshness, profile identities, lifecycle states, and
receipt disclosures. Simplicity cannot collapse distinct security states.

## 16. Tenancy, isolation, and deployment topology

The hosted plane MUST use explicit organization, environment, region, and data-
class boundaries in storage, caches, queues, search, telemetry, encryption,
backups, and support access.

Before any external pilot it MUST demonstrate:

- cross-tenant authorization and data-isolation tests;
- tenant-bound encryption context and key rotation;
- cache, queue, search-index, object-store, and backup isolation;
- regional routing and residency enforcement;
- per-tenant quotas and high-cardinality resistance;
- deterministic deletion and export state;
- disaster recovery without tenant reassignment or rollback;
- support and break-glass controls; and
- independent penetration testing of the selected topology.

The initial deployment SHOULD use cell-based isolation with a small bounded
tenant population per cell. Global services contain only the minimum routing
and organization metadata needed to locate a tenant cell. Cross-region data
movement is explicit and auditable.

The self-managed edition, if selected, consumes the same public contracts and
release subjects. It MUST NOT fork authorization semantics or become a second
product implementation.

## 17. Commercial entitlements and customer exit

Entitlements govern access to enterprise management services only. They MUST
NOT:

- change verifier decisions or accepted canonical objects;
- disable local enforcement, recovery, receipt retrieval, or export;
- withhold open security updates;
- make an expired subscription a security incident; or
- create an online check in the local decision path.

The product MUST document customer exit before taking production data:

- export formats and APIs;
- export authorization and integrity evidence;
- retention and legal-hold interactions;
- deletion deadlines and backup expiry;
- enterprise agent removal and trust-root rotation;
- continued open-runtime operation; and
- removal of enterprise-supplied required-fresh evidence or replacement with a
  customer-controlled source.

## 18. Delivery sequence

### Milestone 0 — Select one paid product

- [ ] Complete AP-SPEC-031 evidence and architecture tests.
- [ ] Name the buyer, problem, topology, modules, exclusions, and success
  metric.
- [ ] Record the open repository and enterprise repository boundary.
- [ ] Obtain legal review of license, trademark, data, security, and service
  obligations.

**Exit:** one evidence-backed product is selected, or implementation stops with
a no-build record.

### Milestone A — Freeze public boundaries

- [ ] Version every open/enterprise protocol, schema, and trust root.
- [ ] Publish conformance fixtures and an inert local enterprise simulator.
- [ ] Prove open operation with the enterprise plane absent and unavailable.
- [ ] Prove commercial code is absent from open package dependency graphs.

**Exit:** the enterprise product composes with Auths without owning Auths
meaning.

### Milestone B — Deliver one narrow design-partner outcome

- [ ] Implement only the modules selected at Milestone 0.
- [ ] Use customer-operated enforcement and customer custody.
- [ ] Run one real bounded workflow with reversible or tightly gated effects.
- [ ] Record adoption, operational burden, failure, and willingness-to-pay
  evidence.

**Exit:** a customer receives measurable operational value beyond the open
self-hosted path.

### Milestone C — Close governance and isolation

- [ ] Complete identity administration, bounded roles, tenant isolation, audit,
  deletion, export, support access, and break-glass controls required by the
  selected product.
- [ ] Pass cross-tenant, confused-deputy, rollback, and control-plane compromise
  exercises.
- [ ] Complete an independent penetration test and remediation retest.

**Exit:** one tenant or operator cannot obtain another tenant's data or widen a
customer runtime's authority.

### Milestone D — Qualify operations

- [ ] Run regional failure, backup/restore, queue, search, integration, and
  enterprise-plane outage game days.
- [ ] Verify local enforcement and recovery behavior during every outage.
- [ ] Measure selected service objectives for at least 30 days.
- [ ] Staff and exercise the declared support model.

**Exit:** the selected service can be operated without weakening Auths safety.

### Milestone E — Expand only from evidence

- [ ] Review module demand, adoption, support burden, margins, and evidence
  against the original selection record.
- [ ] Add at most one next module or integration set per evidence-backed
  expansion record.
- [ ] Re-run boundary, isolation, data, and operational gates.

**Exit:** enterprise scope grows from observed customer need rather than from
the architectural possibility described here.

## 19. Required evidence

Every enterprise release claim MUST bind:

- selected product and AP-SPEC-031 evidence identifiers;
- open and enterprise source/release subjects;
- public protocol, SDK, schema, and simulator versions;
- topology, cells, regions, residency, stores, queues, indexes, and encryption;
- tenant and administrator authorization model;
- enterprise evidence supplied to open runtimes and its freshness semantics;
- outage behavior with local decisions and effects;
- cross-tenant, rollback, substitution, export, deletion, and recovery tests;
- integration inventories and credential boundaries;
- operational objectives, incident exercises, support coverage, and residual
  limits;
- independent review findings, remediations, and retests; and
- exact customer-facing claims.

Public release material SHOULD disclose architecture, subprocessors, data
classes, retention, security contacts, current assurance scope, and material
limitations without exposing tenant information or security-sensitive
operational detail.

## 20. Completion gate

No enterprise production or general-availability claim is permitted until:

- AP-SPEC-031 selected the exact product and buyer;
- AP-SPEC-038 qualifies every open runtime/profile dependency used by it;
- the open path works without a commercial account or available enterprise
  plane;
- every selected enterprise module satisfies its threat and data boundaries;
- tenant isolation, customer exit, export, deletion, and support access are
  independently tested;
- outages preserve local fail-closed and provider-unknown behavior;
- no critical or high independent-review finding remains unresolved;
- measured operation supports the published objectives and support promise;
- commercial claims name their exact release, topology, modules, regions,
  exclusions, and evidence; and
- the release owner signs the enterprise gate report.

Before this gate, the product may be described only as an internal build,
design-partner pilot, restricted preview, or release candidate according to
its actual evidence.

## 21. Success condition

This boundary succeeds when an enterprise customer can choose either:

1. the complete open, self-hosted production substrate; or
2. the same substrate with optional organizational coordination and managed
   operations;

without changing what an Auths authorization means.

The enterprise product is valuable because it makes safe operation easier
across organizations and fleets. It is defensible because it compounds trusted
integrations, operational experience, workflow adoption, and assurance—not
because it holds the verifier hostage.
