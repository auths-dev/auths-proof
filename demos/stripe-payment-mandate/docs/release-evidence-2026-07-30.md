# Release evidence — exact payment mandate

Date: 2026-07-30
Profile: `auths.stripe.exact-payment-mandate/1`
Revision: the profile commit containing this document

## Stripe test-mode effect

The native service and the Docker-local service each created and confirmed a
real test-mode Stripe `SetupIntent` for a repository-created Customer and
attached test PaymentMethod. Stripe returned `succeeded`, `livemode: false`,
and a SetupAttempt. The card-based test fixture did not produce a separate
Mandate object. No PaymentIntent or charge was created.

Representative redacted identifiers:

- Account: `acct_1TuH…M2Te`
- Native SetupIntent: `seti_1TymfM…XiWFF`
- Docker SetupIntent: `seti_1Tymq8…XAO1k`
- Docker lost-response SetupIntent: `seti_1Tymui…BmILi`

The public receipt projection contained no `client_secret` field.

## Recovery evidence

The Docker-local lost-response scenario deliberately discarded the successful
create response, leaving the durable capability in `outcome-unknown` with
`provider: null`. Reconciliation made a fresh list/read request, found exactly
one SetupIntent by `metadata.auths_workflow_id`, and committed the same
capability with source `reconcile-workflow-search`. It did not issue a second
create request.

The normal replay path returned the committed capability with zero credential
requests and zero provider calls.

## Local artifact and browser evidence

- Local URL: `http://localhost:18085` while the evidence container was running
- Image: `sha256:ab7891b8be5fa3ba86ca2860de07864a4f3dbb00c09ab469d9e7115102cc44e3`
- Browser scenarios: missing consent, changed configuration, success, replay,
  response loss, reconciliation, inline canonical receipt, and designed
  receipt page
- Boundary observation: denials used zero credential requests and zero
  provider mutations; success used one of each

Both evidence containers were stopped after the run.

## Public deployment status

No public deployment was made. The available local credential is a standard
Stripe test secret, not a provider-restricted mandate credential, and
transmitting it to Fly.io or Vercel was not authorized. The inventory therefore
remains `specified`.
