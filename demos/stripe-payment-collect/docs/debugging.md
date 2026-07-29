# Debugging

The service fails closed and never includes environment values in startup or
API errors.

## Readiness

```sh
curl -sS http://localhost:8080/healthz
curl -sS http://localhost:8080/readyz
```

Readiness exposes a Stripe account commitment and pinned API version, not a
credential.

## Common failures

`Stripe test-mode configuration is unavailable`

: Check that the ignored `.env` exists at
  `demos/stripe-payment-collect/.env`. Local development may use
  `AUTHS_STRIPE_TEST_SECRET_KEY`; production requires separate fixture and
  collection keys. Never paste either value into logs or issue reports.

`stripe-fixture-unavailable`

: Session setup could not create the test Customer and attached PaymentMethod.
  Confirm the fixture key can create customers and payment methods and that
  the pinned API version is enabled.

`internal-failure`

: The protected service rejected or could not durably record a stage. Inspect
  state file ownership and disk capacity. The API intentionally does not
  serialize provider responses or internal errors.

`outcome-unknown`

: This is a durable workflow state, not a safe failure. Use the displayed
  reconciliation control. Do not remove the state file or retry with a new
  workflow.

## Durable files

The configured state directory contains:

- `merchant-state.json`: canonical atomic reservation/claim/provider state;
- `merchant-state.lock`: cross-process lock;
- `receipts.jsonl`: canonical append-only receipts.

Back up all three while the service is stopped. Deleting state can invalidate
the durable replay guarantee and is not a debugging step.

## Safe diagnostics

Search artifacts and frontend files for prohibited material:

```sh
rg -n 'client_secret|Authorization: Bearer|sk_live_' \
  demos/stripe-payment-collect target
```

The literal `client_secret_exposed: false` compliance field is safe; no
`client_secret` value or field from Stripe may be serialized.
