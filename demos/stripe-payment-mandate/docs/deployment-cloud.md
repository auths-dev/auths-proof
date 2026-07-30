# Cloud deployment

Fly runs the native API and serves the same web bundle. Vercel may host the
static `web/` directory when its generated `config.js` points to the Fly API.

Production requires separate Stripe test credentials:

- fixture credential for Customer and synthetic PaymentMethod preparation;
- mandate credential restricted to SetupIntent create, confirm, and retrieve.

The repository does not upload either secret automatically. Public deployment
remains blocked until the operator explicitly authorizes secret transmission
to Fly and configures the Vercel origin/API values. The inventory therefore
remains `specified` until both public endpoints are exercised end to end.
