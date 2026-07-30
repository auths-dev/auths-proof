# Cloud deployment

The backend is packaged by `Dockerfile` and configured by `fly.toml`. The
static `web/` directory is Vercel-ready.

Required backend secrets are:

- `AUTHS_STRIPE_FIXTURE_SECRET_KEY`;
- `AUTHS_STRIPE_SUBSCRIPTION_CREATE_SECRET_KEY`; and
- `AUTHS_STRIPE_ACCOUNT_ID`.

Stripe restricted keys can limit endpoint families, but cannot constrain exact
metadata values, Price IDs, Customer IDs, quantities, or finite liability.
Those residual constraints are enforced and receipted by the closed gateway.
Do not claim provider-side restriction without testing the actual restricted
key. Public deployment remains unpromoted until both endpoints and that
credential evidence exist on the exact revision.
