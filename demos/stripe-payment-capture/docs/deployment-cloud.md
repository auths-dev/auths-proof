# Cloud deployment

The repository includes a Fly-style backend definition and a Vercel-style
static frontend definition. A same-origin deployment may serve both directly
from the native binary.

## Backend

Provision a persistent volume at `/data`, deploy the Dockerfile, and configure:

- `AUTHS_STRIPE_RELEASE=production`;
- `AUTHS_STRIPE_ALLOWED_ORIGIN` as the exact public frontend origin;
- `AUTHS_PAYMENT_CAPTURE_PUBLIC_API_BASE` as the exact public API origin;
- `AUTHS_STRIPE_ACCOUNT_ID` and `AUTHS_STRIPE_API_VERSION`;
- separate `AUTHS_STRIPE_FIXTURE_SECRET_KEY` and
  `AUTHS_STRIPE_PAYMENT_CAPTURE_SECRET_KEY` secrets.

The capture key should be restricted to PaymentIntent reads and capture
mutation where Stripe supports those permissions. The fixture key creates the
repository-owned Customer, PaymentMethod, and manual authorization only during
trusted session setup. A broad test key is a documented residual assumption,
not provider-enforced least privilege.

## Separate static frontend

Before deploying `web/`, provide a `config.js` containing only:

```js
window.AUTHS_PAYMENT_CAPTURE_API_BASE = "https://your-api.example";
```

Set the same origin in backend CORS. Update the deployment-specific rewrite
and CSP connect target in `web/vercel.json`. Neither file may contain a Stripe
identifier that is treated as secret, a client secret, or a Stripe key.

## Verification

On the exact deployed revision:

1. check `/healthz` and `/readyz`;
2. create a fresh session in a real browser;
3. prove the initial exact PaymentIntent and Charge are linked to the durable
   authorization receipt and expose $10.00 capturable;
4. capture exactly $5.00 once, then retrieve `succeeded`, zero capturable,
   $5.00 received, and the Charge balance transaction;
5. prove the settlement commit and full $10.00 hold release were atomic;
6. replay and prove no second capture request exists;
7. inject the lost-response experiment and reconcile by retrieval;
8. open the designed receipt and its separate machine API;
9. retain redacted revision, deployment, region, timestamp, Stripe request ID,
   and provider observation commitments.

Do not describe a deployment as complete if those real test-mode and browser
checks were not performed.
