# Prompt: provider integrations and evidence truth

Scope: `product/integrations/*` (especially `auths-stripe`, `auths-postgresql`, `auths-github`, `auths-opentofu`, `auths-records-api`), `auths-gateway` recipes, `bindings/fixtures/gateway/*`, `product/tools/auths-openapi-derive`, `demos/*`.

Goal: check that each provider path delivers the headline evidence claims, and find where it doesn't.

For each provider (Stripe, PostgreSQL, GitHub, OpenTofu, and each gateway recipe such as Airtable and Todoist), fill one row:

| Question | Answer with path:line |
|---|---|
| Where a spec or claim promises one, is an echo token derived from the exact action written into the provider's own record? Which field? (AP-SPEC-059 covers gateway recipes only; Stripe is out of its scope by design.) | |
| Can someone other than the gateway change that field afterwards? Does verification notice? | |
| Could an attacker with write access plant a valid-looking echo? | |
| How does an auditor verify it using only their own provider credentials? | |
| Is the check that the record is unchanged since the approver saw it enforced at write time (conditional write, row version, `FOR UPDATE`), or only before it? | |
| Which idempotency mechanism is used, and how long does it last? | |
| Is recovery/reconciliation complete (pagination, filters) and does it match on unforgeable data? | |
| Are timestamps taken from the provider/DB or from the caller? | |
| Is it live-qualified, a sandbox demo, or a fixture only? | |

Then:
- Measure coverage honestly. How many operations are implemented in code, per provider, out of the provider's total API? Which are hand-built and which are generated?
- Find every seam where two implementations of the same concept disagree (e.g. the gateway echo derivation vs a provider crate's own linking).
