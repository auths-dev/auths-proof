# Cloud deployment

The native service can be built from `fly.toml`; the static `web/` directory
can be deployed separately after setting `config.js` to the native HTTPS
origin. Configure CORS to the exact frontend origin.

Production additionally requires:

- `AUTHS_STRIPE_ISSUING_WEBHOOK_SECRET`;
- a restricted read-only reconciliation credential;
- a separate backend-only test-helper key only for a sandbox deployment;
- durable volume and receipt backups; and
- Stripe's direct-response webhook endpoint pinned to the configured API
  version.

Never expose these values through Vercel, browser configuration, receipts, or
logs.
