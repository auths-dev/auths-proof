# Content Epic 8 — Operations, Testing, Failure, and Recovery

> **Status revoked by rendered-site audit.** Requalify through Content Epics
> 10–19; existing checked tasks record prior implementation, not completion.

**Depends on:** [Content Epic 0](./epic_0.md), Content Epics 4–7, and Platform
Epic P9.

**Ownership:** This epic owns operational explanation and procedure ordering.
Commands, configuration, error inventories, outcomes, limits, and evidence are
generated or scenario-backed; CI and deployment mechanics belong to P11.

## Outcome

Operators can deploy the open Auths runtime, test realistic outcomes, observe
its boundaries, recover uncertain work safely, upgrade it, and respond to
incidents without relying on tribal knowledge.

## Current problem

Auths has production-shaped runtime, custody, state, observability, and recovery
surfaces, but the public documentation does not yet form a complete operator
journey. Failure knowledge is spread across code, specs, demos, and error
registries.

Stripe publishes scenario-based testing, action-oriented error handling, and
ordered configuration procedures with explicit operating modes and boundaries.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-2--tours-prerequisites-testing-and-outcome-recipes),
[configuration evidence](./STRIPE_CONTENT_RESEARCH.md#batch-4--product-landings-design-decisions-and-operational-boundaries)

## Operations information architecture

```text
/operations
├── evaluate locally
├── deploy the open runtime
├── configure durable state
├── configure custody
├── configure trust and profiles
├── configure provider gateways
├── observability and SLOs
├── backup and restore
├── recovery and reconciliation
├── upgrade and rollback
├── receipt retention and disclosure
└── incident response runbooks
```

## Testing catalog

`/developers/testing` exposes deterministic recipes for:

- successful authorization and execution;
- malformed or oversized input;
- invalid signature and unknown suite;
- untrusted identity evidence;
- action-byte mutation;
- attenuation widening;
- expiry and not-yet-valid authority;
- revocation;
- replay, use exhaustion, and budget exhaustion;
- approval substitution and insufficient threshold;
- denied, indeterminate, and internal failure;
- provider timeout before submission;
- provider-unknown after possible submission;
- recoverable resume and invalid fresh retry;
- receipt tampering and unauthorized disclosure; and
- state-store, custody, and trust-resolver unavailability.

Each recipe names the fixture, expected stable outcome/error, permitted retry or
resume action, and observable evidence.

## Failure hub

`/developers/errors` begins with the closed outcome model, then groups generated
stable errors by reader response:

| Class | Operator/developer response |
|---|---|
| denied | Change authority, trust, or request; do not retry unchanged |
| indeterminate | Investigate missing evidence or unavailable decision input |
| recoverable | Observe and resume the same execution reference |
| provider-unknown | Reconcile provider state before any retry |
| invalid input | Correct parsing/size/schema failure before resubmission |
| internal | Preserve correlation evidence and escalate |

Every generated error page includes meaning, safe response, unsafe response,
language examples, related fixtures, runbook, source-at-release, and version.

## Runbook contract

Every procedure contains:

1. ownership and severity;
2. preconditions and required access;
3. safety and secret-handling warnings;
4. exact commands from tested scripts;
5. expected observations after each step;
6. stop conditions;
7. rollback or resume path;
8. reconciliation and evidence retention; and
9. escalation information.

## Implementation steps

- [x] Author the operations landing and deployment-mode chooser.
- [x] Author procedures around tested P7/P9 commands for runtime, state,
  custody, trust, gateway, telemetry, backup/restore, upgrade, and rollback.
- [x] Curate the generated testing catalog from adversarial and differential
  fixtures.
- [x] Curate the generated failure hub from stable error and outcome registries.
- [x] Add decision trees for retry, resume, reconcile, and stop.
- [x] Add observable metrics, logs, traces, health checks, and SLO examples
  without leaking authority or receipt contents.
- [x] Build incident runbooks for state loss, signer outage, trust-root error,
  provider uncertainty, receipt disclosure, and compromised credentials.
- [x] Require every published command to resolve to an isolated local or
  field-lab scenario identity.
- [x] Explain sanitized sample evidence produced by the owning scenario.

## Acceptance criteria

- No runbook recommends blind retry after a provider-unknown outcome.
- Every command is sourced from an executable checked script.
- Secret values, raw sealed commands, and full receipts are absent from logs and
  examples unless an explicitly authorized disclosure lesson requires them.
- Operators can distinguish liveness, readiness, dependency degradation, and
  semantic authorization failure.
- Backup/restore and rollback exercises preserve replay, budget, recovery, and
  receipt invariants.
- All supported failure classes have a generated error page and a tested recipe.

## Validation

```text
npm run test:runbooks
npm run test:error-catalog
npm run test:failure-recipes
npm run test:observability-redaction
npm run test:links
npm run test:markdown
npm run build
```
