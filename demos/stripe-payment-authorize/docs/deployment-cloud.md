# Cloud deployment

The repository includes a Fly-style backend definition and a Vercel-style
static frontend definition. A same-origin deployment may serve both directly
from the native binary.

## Backend

Provision a persistent volume at `/data`, deploy the Dockerfile, and configure:

- `AUTHS_STRIPE_RELEASE=production`;
- `AUTHS_STRIPE_ALLOWED_ORIGIN` as the exact public frontend origin;
- `AUTHS_PAYMENT_AUTHORIZE_PUBLIC_API_BASE` as the exact public API origin;
- `AUTHS_STRIPE_ACCOUNT_ID` and `AUTHS_STRIPE_API_VERSION`;
- separate `AUTHS_STRIPE_FIXTURE_SECRET_KEY` and
  `AUTHS_STRIPE_PAYMENT_AUTHORIZE_SECRET_KEY` secrets.

The mutation key should be restricted to the PaymentIntent/PaymentMethod reads
and PaymentIntent create operation needed by this profile. The fixture key is
used only during trusted session setup.

## Separate static frontend

Before deploying `web/`, provide a `config.js` containing only:

```js
window.AUTHS_PAYMENT_AUTHORIZE_API_BASE = "https://your-api.example";
```

Set the same origin in backend CORS. Update the deployment-specific rewrite
and CSP connect target in `web/vercel.json`. Neither file may contain a Stripe
identifier that is treated as secret, a client secret, or a Stripe key.

## Verification

On the exact deployed revision:

1. check `/healthz` and `/readyz`;
2. create a fresh session in a real browser;
3. authorize once and retrieve the manual-capture PaymentIntent and latest
   Charge afterward;
4. prove `requires_capture`, the exact capturable amount, zero received funds,
   and `capture_before`;
5. replay and prove no second PaymentIntent or authorization request exists;
6. inject the lost-response experiment and reconcile by retrieval;
7. open the designed receipt and its separate machine API;
8. retain redacted revision, deployment, region, timestamp, Stripe request ID,
   and provider observation commitments.

Do not describe a deployment as complete if those real test-mode and browser
checks were not performed.
