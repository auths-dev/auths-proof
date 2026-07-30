# Cloud deployment

The repository includes a Fly backend definition and a Vercel static frontend
definition. A same-origin deployment may serve both from the native binary.

Provision persistent storage at `/data` and configure:

- `AUTHS_STRIPE_RELEASE=production`;
- `AUTHS_STRIPE_ALLOWED_ORIGIN` as the exact frontend origin;
- `AUTHS_PAYMENT_CANCEL_PUBLIC_API_BASE` as the exact API origin;
- `AUTHS_STRIPE_ACCOUNT_ID` and `AUTHS_STRIPE_API_VERSION`;
- separate `AUTHS_STRIPE_FIXTURE_SECRET_KEY` and
  `AUTHS_STRIPE_PAYMENT_CANCEL_SECRET_KEY` secrets.

The cancellation key should be restricted to PaymentIntent reads and
cancellation where Stripe supports those permissions. The fixture key creates
the repository-owned Customer, PaymentMethod, and manual-capture authorization.

For a separate frontend, provide a non-secret `web/config.js`:

```js
window.AUTHS_PAYMENT_CANCEL_API_BASE = "https://your-api.example";
```

On the exact deployed revision, create a session, observe
`requires_capture`, execute cancellation, retrieve `canceled`, prove zero
capturable and zero received, prove the linked hold was released, replay
without another cancel call, reconcile a lost response by retrieval, and open
both the designed receipt and machine API.

Do not describe deployment as complete until real test-mode and browser checks
have passed.
