# Local deployment

```sh
AUTHS_STRIPE_ALLOWED_ORIGIN=http://localhost:8080 \
AUTHS_STRIPE_STATE_DIR=/tmp/auths-stripe-connect-transfer \
cargo run -p auths-stripe-connect-transfer-demo
```

Open `http://localhost:8080`. Alternatively:

```sh
docker compose -f demos/stripe-connect-transfer/compose.local.yaml up --build
```

Do not put a Stripe secret in frontend files. A live adapter must read a
server-only restricted test credential.
