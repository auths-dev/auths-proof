# Debugging

- `payment-mandate-consent-required`: accept the displayed terms in the same
  browser session; the endpoint requires its HttpOnly consent cookie.
- `payment-mandate-consent-mismatch`: reload so the displayed terms and digest
  come from one session.
- `bounded-configuration-mismatch`: required and executing deployment
  commitments differ; no state or provider access should be present.
- `payment-mandate-outcome-unknown`: use reconcile. The capability slot is
  intentionally retained. If the create response was lost before its
  identifier could be persisted, reconciliation lists the Customer's
  SetupIntents and requires exactly one `metadata.auths_workflow_id` match.
  Zero matches remain unavailable and multiple matches fail closed.
- Stripe fixture unavailable: verify test-mode keys, account, API version, and
  network access without logging credential values.
