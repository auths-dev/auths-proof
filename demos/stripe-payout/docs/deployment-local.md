# Local deployment

```sh
AUTHS_STRIPE_ALLOWED_ORIGIN=http://localhost:8080 \
AUTHS_STRIPE_STATE_DIR=/tmp/auths-stripe-payout \
cargo run -p auths-stripe-payout-demo
```

Or run `docker compose -f demos/stripe-payout/compose.local.yaml up --build`.
Stripe and bank credentials are server-only and never belong in browser assets.
