# Local deployment

Copy `.env.example` to `.env` and provide Stripe test credentials. For local
development, `AUTHS_STRIPE_TEST_SECRET_KEY` may provide both fixture and
mutation access. Production configuration requires separate fixture and
subscription-modify secrets.

Run:

```sh
docker compose -f demos/stripe-subscription-modify/compose.local.yaml up --build
```

Open `http://localhost:8080`. Durable modification transitions and receipts live in the
named Docker volume.
