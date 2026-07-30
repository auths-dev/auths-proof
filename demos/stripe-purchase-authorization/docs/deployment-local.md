# Local deployment

Copy `.env.example` to `.env`, set a Stripe webhook signing secret if testing
the webhook route, then run:

```sh
cargo run -p auths-stripe-purchase-authorization-demo
```

Open `http://localhost:8080`. For container validation:

```sh
docker compose -f demos/stripe-purchase-authorization/compose.local.yaml up --build
```

Credentials remain backend-only. The repository scenario does not require a
Stripe key; sandbox helper execution requires an Issuing-enabled test account,
cardholder, and card.
