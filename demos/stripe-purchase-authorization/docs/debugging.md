# Debugging

- `purchase-decision-timeout`: elapsed time reached the configured 1000 ms
  deadline; decline is correct.
- `purchase-intent-mismatch`: the intent is absent, expired, or differs in
  merchant, scope, currency, amount, or digest.
- `purchase-aggregate-budget-exceeded`: durable held capacity plus the exact
  amount exceeds a budget.
- `outcome_unknown`: do not retry approval; reconcile the existing
  authorization.
- webhook `400`: the Stripe signature is absent, malformed, stale, or invalid.
- webhook `503`: no webhook secret is configured.
