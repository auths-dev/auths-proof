# Epic 5 — Build Privacy-Safe Operations and Operator UX

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** Epics 1–3; custody readiness from Epic 4 may land in parallel

**Blocks:** Epics 8–9

## Outcome

Create one Rust-owned operational vocabulary and a self-hosted operator
experience that makes failures understandable without exposing authorization
payloads. Ship bounded readiness, metrics, logs/traces, workflow status,
reconciliation controls, receipt disclosure, dashboards, alerts, and runbooks.

Telemetry remains observational. No exporter, dashboard, health check, or UI
state may alter authorization, lifecycle, recovery, or provider effects.

## Zero-context starting point

Read:

- `product/operations/auths-operations/src/lib.rs` and `explanation.rs`;
- `product/errors/auths-errors/src/lib.rs`;
- `product/receipts/auths-receipts/src/disclosure.rs`;
- `product/config/auths-config/src/lib.rs`;
- `bindings/typescript/src/observability.ts`;
- `bindings/python/python/auths/_observability.py`;
- `bindings/typescript/src/doctor.ts` and Python `_doctor.py`;
- lifecycle state/event types from Epic 3; and
- the incident-response demo receipt/disclosure UI for established house style.

Current facts:

- Rust `auths-operations` has strict readiness probes, stable stages/outcomes,
  bounded reason labels, and an in-memory aggregate.
- TypeScript and Python each define a different telemetry schema and validation
  logic. Production cannot preserve three competing meanings.
- Receipt inspection already supports Rust-owned opaque, summary, and full
  projections.
- Existing diagnostics intentionally omit raw proof, principal, resource,
  argument, and custody data.

## Product constraint

Operations must have the same Stripe-like quality as the developer API:

- a green/red readiness answer with a precise safe reason;
- one workflow timeline that uses plain language;
- one recommended next action for every non-terminal state;
- copyable opaque references instead of raw identifiers or protocol bytes;
- advanced commitments and stable codes one click deeper;
- dashboards and alerts that work from the reference deployment; and
- no requirement to understand lifecycle enum names to operate normally.

The default UI answers four questions:

1. Was it authorized?
2. Could the provider have received it?
3. Is the effect known?
4. What should the operator do next?

## Architecture

```text
Rust runtime / store / custody / profile
              |
              | OperationalEventV2 (closed, bounded)
              v
+---------------------------+
| auths-operations          |
| readiness + event parser  |
| status projection         |
+-------------+-------------+
              |
        +-----+------+----------------+
        v            v                v
  OTEL exporter   /metrics       operator API/UI
  failure inert   aggregate      disclosure-gated
```

TypeScript and Python receive native-produced projections. They may transport
or render them but cannot add fields, stages, result meaning, or retry advice.

## Rust operational contract

Replace the existing V1 event shape directly with a single semantic identity,
`auths.operations/2`. Do not keep parallel V1/V2 runtime paths.

```rust
pub struct OperationalEventV2 {
    build: BuildSemanticId,
    profile: Option<ProfileRef>,
    stage: OperationalStage,
    outcome: OperationalOutcome,
    reason: OperationalReasonCode,
    elapsed: LatencyBucket,
    subsystem: OperationalSubsystem,
    saturation: Option<SaturationBucket>,
}

pub enum OperationalStage {
    Acquisition,
    Verification,
    Policy,
    DecisionPersistence,
    Reservation,
    ExecutionIntent,
    Credential,
    ProviderEntry,
    ProviderResult,
    Observation,
    Reconciliation,
    Receipt,
    Recovery,
}

pub enum OperationalOutcome {
    Succeeded,
    Denied,
    Indeterminate,
    Conflict,
    Saturated,
    Unavailable,
    Failed,
    OutcomeUnknown,
}

pub struct WorkflowStatusProjection {
    reference: PublicWorkflowReference,
    profile: ProfileRef,
    stage: PublicWorkflowStage,
    authorization: AuthorizationProjection,
    effect: EffectState,
    recommended_action: RecommendedAction,
    age: AgeBucket,
    observer: DependencyHealth,
    receipt: Option<ReceiptDisclosureLocator>,
}
```

Use enums and bounded newtypes, not arbitrary strings or maps. Every output
field must have a finite cardinality documented in the fixture manifest.

Allowed event dimensions:

- build and semantic identity;
- registered profile and bounded stage;
- stable outcome and reason code;
- deployment class;
- latency bucket, never raw high-resolution request timing as a label;
- store, custody, provider, observer, receipt, and runtime subsystem; and
- aggregate queue/saturation bucket.

Prohibited dimensions:

- proof, grant, action, plan, policy, evidence, or receipt bytes;
- action arguments, principals, resources, tenant/customer IDs;
- workflow, recovery, receipt, provider request, or idempotency identifiers;
- credentials, keys, tokens, signatures, URLs, SQL, IP addresses;
- provider payloads and arbitrary error strings; and
- caller-supplied label names or values.

## Readiness and health

`/healthz` proves only that the process event loop is alive. It performs no
external I/O and returns no dependency details.

`/readyz` uses the existing `ReadinessProbe` model with required probes for:

- verifier registries and cryptographic self-test;
- required/executed configuration equality;
- lifecycle store connectivity and schema identity;
- recovery-reference and lease storage;
- receipt persistence/retrieval;
- configured custody descriptor and self-test;
- every enabled profile's immutable registration; and
- required exporter backpressure state where loss is configured fail-closed
  for audit, never for ordinary metrics.

Provider availability is not authorization and SHOULD NOT gate general
readiness unless the profile explicitly declares it required for accepting new
work. Provider outage is reported through the profile status and admission
policy.

## Exporter implementation

Create `product/operations/auths-operations-otel/` rather than adding network
and exporter dependencies to the vocabulary crate.

The exporter:

- accepts only `OperationalEventV2`;
- maps enums to a fixed OpenTelemetry name/attribute registry;
- uses bounded in-process buffering and explicit drop/backpressure counters;
- never blocks or changes a completed Auths decision/effect result;
- supports OTLP over TLS and a local Prometheus scrape projection;
- omits event bodies by default; and
- rejects configuration that adds custom dimensions.

The Prometheus surface exposes aggregate counters, histograms, gauges, and
build information. It never exposes per-workflow series.

## Operator APIs

Add a narrow product package only if it is reusable independently of the
reference deployment; otherwise implement handlers in the reference node from
Epic 8. The domain API is:

```text
GET  /healthz
GET  /readyz
GET  /metrics
GET  /v1/workflows/{opaque-reference}
POST /v1/workflows/resume
GET  /v1/receipts/{id}/summary
POST /v1/receipts/{id}/disclose
GET  /version
```

Rules:

- route IDs are bounded opaque references, not raw workflow/database keys;
- GET status performs no mutation or provider call;
- reconcile acquires a recovery lease and invokes the registered concrete
  profile recovery path; it cannot execute a fresh effect;
- receipt views call Rust-owned disclosure authorization;
- unauthorized receipt access returns the opaque projection, not field-level
  authorization errors that reveal existence;
- health, readiness, metrics, and build routes disclose no workflow data;
- request/response bodies have hard byte and collection limits; and
- authentication is a deployment boundary supplied by localhost, mTLS, or a
  reverse proxy. Authentication alone does not authorize full receipt
  disclosure.

Profile workflow creation routes remain concrete and are implemented in Epic
6/8. There is no generic `{ profile, operation, payload }` route.

## Operator UX

Build a responsive local operator UI under the open reference deployment. The
primary page is horizontally compact and keyboard accessible:

```text
+-----------------------------------------------------------------------+
| Auths node · ready · build 4f2...                    [Run diagnostics] |
+-----------------------------------------------------------------------+
| Needs attention (2) | Recovering (1) | Completed today (142)          |
+-----------------------------------------------------------------------+
| Workflow 7X... · PostgreSQL bounded update                            |
| Authorized ✓  Reserved ✓  Provider possible !  Effect unknown         |
| Do not retry · Observation pending                     [Reconcile]     |
+-----------------------------------------------------------------------+
```

Workflow detail progressively discloses:

1. plain-language status and next action;
2. lifecycle timeline and stable codes;
3. bounded commitments and configuration identities; and
4. authorization-gated receipt projection.

Never color denial as an operational failure or provider success as an Auths
authorization. Use text/icons in addition to color.

## Dashboards, objectives, alerts, and runbooks

Ship reference dashboards for:

- authorization/denial/indeterminate rate;
- store checkout, transaction, conflict, timeout, and saturation;
- provider entry and possible-effect count;
- unknown-outcome age and reconciliation queue depth/drain time;
- custody denial, throttle, invalid response, and outage;
- receipt persistence/retrieval;
- readiness/configuration mismatch; and
- emergency-denial state.

Freeze numeric qualification objectives in the Epic 1 candidate manifest for
availability, p95/p99 decision latency, maximum possible-effect age,
reconciliation backlog/drain time, receipt availability, store RPO/RTO, and
custody availability.

Security invariants have a test budget of zero: duplicate logical execution,
false terminal receipt, credential-before-intent, accepted configuration
mismatch, and sensitive telemetry exposure.

Every severity-one alert links to one checked-in runbook with detection,
customer impact, safety state, actions, forbidden actions, validation,
escalation, and closure evidence. At minimum cover store outage, unknown-effect
age, reconciliation failure, receipt failure, custody revocation/outage,
configuration drift, credential failure, trusted clock failure, telemetry
exfiltration, and emergency denial.

## Implementation steps

- [ ] Freeze the Rust V2 event/status types and generated field registry.
- [ ] Delete TypeScript/Python-owned event validation and state meaning; replace
  them with native projection in Epic 7.
- [ ] Instrument lifecycle coordinator, PostgreSQL store, custody, receipts,
  and the three selected verticals at stable stage boundaries.
- [ ] Add the OTEL/Prometheus adapter package and backpressure tests.
- [ ] Implement health/readiness/build/status/reconcile/receipt handlers.
- [ ] Build the local UI from status projections, not database records.
- [ ] Add dashboards, alert rules, and runbooks to the reference deployment.
- [ ] Add a generated privacy inventory and CI test that rejects undeclared
  telemetry fields/dimensions.
- [ ] Update architecture, compliance, SDK snapshots, semantic freeze, and
  release subjects.

## Adversarial tests

- inject every prohibited value into errors, profile data, provider responses,
  and identifiers and prove exporters/UI/support bundles omit it;
- attempt arbitrary/custom labels and oversized events;
- saturate exporter buffers and disconnect the collector;
- make every readiness probe fail independently;
- forge opaque references and request cross-workflow receipts;
- request full receipt views without disclosure authorization;
- race status/reconcile requests from multiple hosts;
- kill the process during reconciliation and reload status elsewhere;
- prove health success does not imply readiness or provider correctness; and
- prove exporter/UI failure does not alter lifecycle records or provider calls.

Browser tests cover ready, denied, indeterminate, reserved, executing,
outcome-unknown, reconciling, committed, released, and receipt-disclosure
states at desktop and mobile widths.

## Validation commands

```text
cargo test -p auths-operations
cargo test -p auths-operations-otel
cargo test -p auths-errors -p auths-receipts -p auths-runtime
cargo xtask arch
cargo xtask compliance
cargo xtask semantic-freeze
```

Run browser tests and a secret-seeded telemetry test in the reference
deployment. The test fails if any seeded sensitive value appears in metrics,
logs, traces, support bundles, HTML, or downloaded receipt projections.

## Exit gate

This epic is complete when a new operator can diagnose and safely act on every
workflow state without reading protocol bytes; Rust, exporters, APIs, and UI
share one bounded vocabulary; privacy tests find no sensitive value; every
alert has an exercised runbook; and telemetry or UI failure cannot alter an
Auths decision, effect, or recovery outcome.
