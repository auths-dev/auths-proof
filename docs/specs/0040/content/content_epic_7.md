# Content Epic 7 — Adoption and Migration

**Depends on:** [Content Epic 0](./epic_0.md), Content Epics 2–6, and Platform
Epic P9.

**Ownership:** This epic owns migration strategy and reader guidance. Product
support, integration capabilities, commands, and conformance results resolve
from generated facts or tested scenarios.

## Outcome

Teams can introduce Auths beside existing identity, credential, IAM, policy,
capability, and signed-request systems, prove value on one bounded effect, and
cut over without a flag day.

## Current problem

Auths documentation explains the target model but does not yet give an
implementation owner a safe migration process from existing authorization and
credential systems. Without an adoption path, a strong protocol can appear to
require replacing the identity provider, policy engine, cloud IAM, and runtime
simultaneously.

Stripe's migration content separates overview, planning, coordination,
sensitive-data procedures, field-level requirements, output mapping, and
post-migration updates.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-1--global-landings-catalogs-and-depth-transitions)

## Adoption principles

- Compose before replacing.
- Start with one exact high-value effect.
- Reuse existing identity and policy evidence where safe.
- Keep provider credentials behind the existing trusted gateway first.
- Compare decisions in shadow mode before enforcing.
- Preserve denied, indeterminate, recoverable, and provider-unknown outcomes.
- Make rollback a documented state transition, not an emergency improvisation.
- Never export or copy secret key material into documentation tooling.

## Required pages

| Route | Reader job |
|---|---|
| `/get-started/adopt` | Choose an adoption path |
| `/adopt/plan` | Inventory effects, actors, credentials, policies, and state |
| `/adopt/signed-requests` | Add exact authority to an existing signed request |
| `/adopt/oauth-oidc` | Retain login/session identity and add bounded effect authority |
| `/adopt/api-keys` | Move from ambient bearer access to closed gateway execution |
| `/adopt/cloud-iam` | Compose workload/IAM identity with exact Auths authority |
| `/adopt/policy-engines` | Use Cedar, OPA, or ReBAC decisions as explicit context |
| `/adopt/capabilities` | Import or bridge UCAN, Biscuit, or macaroon authority |
| `/adopt/approvals` | Bind existing approval workflows to exact plan bytes |
| `/adopt/shadow-mode` | Compare Auths with current enforcement without effects |
| `/adopt/cutover` | Enforce, observe, and rollback one protected effect |

## Migration phases

```text
inventory -> model -> verify in shadow -> compare -> enforce one effect
    -> observe -> expand deliberately
                    |
                    +--> rollback to previous gateway while preserving evidence
```

### Inventory

Record actor sources, effect entry points, existing scopes/roles, provider
credential location, approval systems, replay/idempotency behavior, audit data,
and unknown-outcome handling. Do not collect credential values.

### Model

Map one effect to canonical action bytes, authority limits, trust evidence,
state requirements, gateway ownership, expected outcomes, and receipt
disclosure.

### Shadow

Run effect-free Auths verification beside existing enforcement. Store bounded
decision comparison records; never call the provider from shadow mode.

### Enforce

Place the existing provider client behind the closed gateway and require an
opaque verified command. Start with one route or operation and an explicit
rollback switch.

### Expand

Add actors, effects, delegation, approvals, or transports one dimension at a
time. Every expansion requires new fixtures and operational evidence.

## Implementation steps

- [x] Author a privacy-safe adoption inventory form against P9's registered
  schema.
- [x] Author the adoption chooser and phased planning guide.
- [x] Build the nine source-system composition guides with ownership matrices.
- [x] Select shadow comparison fixtures from the interoperability repository and
  record missing fixtures as platform dependencies.
- [x] Explain generated bounded comparison and migration receipts without
  copying secrets or raw business payloads.
- [x] Link one qualified end-to-end cutover/rollback field lab; do not reproduce
  its commands or results in MDX.
- [x] Document key rotation and trust-root changes without requiring identity
  migration.
- [x] Add mapping-output review and reconciliation procedures.
- [x] Link every competitive claim to the evidence-based research repository.

## Acceptance criteria

- Every guide preserves the existing system's legitimate role and states where
  Auths overlaps, composes, or adds operational cost.
- No guide requires replacing an IdP, policy engine, transport, or cloud IAM to
  protect the first effect.
- Shadow mode cannot mint an executable authorization object or call a provider.
- Cutover includes preconditions, observable success, fail-closed cases,
  rollback, and reconciliation.
- Migration records contain commitments and classifications, not credentials or
  unnecessary business payloads.

## Validation

```text
npm run test:adoption-content
npm run test:integration-matrix
npm run test:shadow-fixtures
npm run test:privacy
npm run test:links
npm run test:markdown
npm run build
```
