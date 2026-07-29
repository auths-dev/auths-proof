# Stripe payment collection release evidence — 2026-07-30

This record contains only test-mode identifiers and public deployment
metadata. It contains no Stripe credential, `client_secret`, authorization
header, or reusable payment data.

## Revision and deployment

- Runtime source revision: `6391626`
- Branch: `dev-stripe-bounded-demo`
- Public origin: <https://auths-stripe-payment-collect-demo.fly.dev>
- Fly image: `deployment-01KYR26FR3S76VJA0M5JQGFE1N`
- Fly machine: `2863e32c163508`, version 3
- Persistent volume: `vol_r6898dy33g92j6p4`
- Region: `cdg`
- Deployment observation: `2026-07-29T23:11:50Z`
- Stripe API version: `2026-06-24.dahlia`
- Stripe account commitment:
  `6738148edaca97e9f4c9157b139641616074e13c102d613d6da7db9597c0184d`

The Fly remote builder built
`demos/stripe-payment-collect/Dockerfile`. The resulting container passed its
health check, mounted the encrypted persistent volume, and survived explicit
machine restarts.

## Exact collection and restart replay

The browser created a fresh Stripe test Customer and attached test
PaymentMethod, collected exactly USD 5.00, and displayed `COLLECTED`.
The machine was then restarted. Replaying the same workflow in the same
browser returned the original committed record with zero credential requests
and zero provider calls.

- Workflow: `collect-fc799542b0ec6f5e4273235c0a6b6cab`
- Receipt:
  `62228b019e61bed2963325a86196ebf0b3e628496c4686f750ed0e06cdaeac8b`
- PaymentIntent: `pi_3TygdHPbjgb2M2Te3hVb8le6`
- Charge: `ch_3TygdHPbjgb2M2Te3X0VjUSQ`
- Stripe request: `req_Mm2KpRLx9N2UNc`
- Provider response commitment:
  `d79d0010e1725957ccb5fd1dd243bd8e8a60ef0922c8a5afa82c744e6b9069c3`

Fresh Stripe retrieval after replay reported:

- PaymentIntent `succeeded`;
- amount and amount received `500` USD minor units;
- amount capturable `0`;
- capture method `automatic`;
- `livemode=false`;
- the same latest Charge;
- Charge `succeeded`, paid, and captured; and
- the Charge referenced the same PaymentIntent.

## Unknown outcome and reconciliation

A separate fresh browser session injected a lost response after real Stripe
delivery. The UI reported `OUTCOME-UNKNOWN`, retained capacity, and exposed a
reconciliation control. Reconciliation performed one retrieval and no second
create, then reported `RECONCILED` and `reconciled-committed`.

- Receipt:
  `cc8f4911ea055ea68bc338a4f63839374bcbeeb2a32e5b3f85448c18b338e06d`
- PaymentIntent: `pi_3TygPmPbjgb2M2Te3tbJ87UN`
- Charge: `ch_3TygPmPbjgb2M2Te36mufe4b`
- Stripe request: `req_ApGKtLt5fZqYvh`
- Provider observation commitment:
  `c6f69d1a86cf972fb9cf6163d1b16732084ee84c083c8325a1adfb7a0cbd77d5`
- Observation source: `retrieve`

Direct Stripe retrieval confirmed the PaymentIntent and Charge were
test-mode, succeeded, USD 5.00, paid, and automatically captured.

## Browser and boundary checks

The public same-origin frontend and native API were exercised in a real
browser:

- exact collection: one credential request and the expected Stripe calls;
- one-past boundary: rejected with zero credential/provider calls;
- changed action: rejected with zero credential/provider calls;
- changed configuration: rejected with zero credential/provider calls;
- replay: returned the durable record with zero credential/provider calls;
- replay after container restart: returned the durable record with zero
  credential/provider calls;
- lost response: retained `outcome-unknown` capacity;
- reconciliation: one retrieval, no second create;
- inline canonical receipt JSON rendered;
- designed receipt page rendered the canonical lifecycle;
- separate machine receipt API returned
  `auths.stripe.machine-readable-receipt/1`; and
- malformed and unknown receipt IDs returned HTTP 404.

## Secret and artifact checks

The final public machine receipt was scanned for:

- a serialized `client_secret` field;
- `sk_test_` or `sk_live_` credential material; and
- an `Authorization: Bearer` header.

All three checks were false. Repository frontend/source scans and the
compliance suite enforce the same exclusions.

## Remaining promotion gate

Profile 0013 remains `specified`. The public Docker image, live Stripe
contract, browser, restart, receipt, and secret-scan evidence are complete,
but the specification separately requires a Docker-local live Stripe run.
The local Docker daemon did not respond during this evidence run. Do not
change the registry status to `implemented` until that local gate and the
authoritative exact-revision CI gate pass.
