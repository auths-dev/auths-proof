# Local deployment

Copy `.env.example` to `.env` and provide Stripe test-mode values. For local
development only, `AUTHS_STRIPE_TEST_SECRET_KEY` may supply both fixture and
mandate credentials; production mode requires the two explicitly named
secrets.

```sh
docker compose -f demos/stripe-payment-mandate/compose.local.yaml up --build
```

Open `http://localhost:8080`, accept the synthetic terms, and run the exact
mandate. The state and receipt journal persist in the named Docker volume.
