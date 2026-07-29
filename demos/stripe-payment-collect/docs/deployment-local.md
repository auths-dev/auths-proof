# Local Docker deployment

The application serves the frontend and native API from one real HTTP origin.
It does not support `file://`.

1. Copy `.env.example` to the ignored `.env`.
2. Fill test-mode values without committing or printing them.
3. Build from the repository root:

```sh
docker compose \
  --env-file demos/stripe-payment-collect/.env \
  -f demos/stripe-payment-collect/compose.local.yaml \
  up --build
```

4. Open <http://localhost:8080>.
5. Run success, replay, denial, changed-action, changed-configuration, and
   ambiguous/reconcile experiments.
6. Verify the resulting PaymentIntent and Charge with the Stripe Dashboard or
   a credential-safe retrieval script.

The named volume preserves merchant state and receipts across container
restarts. A replay after restart must return the original durable record
without another create request.

For a native process, set an absolute writable
`AUTHS_STRIPE_STATE_DIR`, set
`AUTHS_STRIPE_ALLOWED_ORIGIN=http://localhost:8080`, and run:

```sh
cargo run -p auths-stripe-payment-collect-demo
```
