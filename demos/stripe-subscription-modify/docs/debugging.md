# Debugging

- `subscription-configuration-mismatch` occurs before reservation, credential
  access, or Stripe I/O.
- `subscription-before-state-mismatch` means the current Subscription or Item
  set no longer equals the committed before state.
- `subscription-preview-mismatch` means the fresh preview, proration date,
  debit, credit, or recurring calculation changed.
- `subscription-pending-update-conflict` means another update is already
  unresolved.
- `pending_payment` is not an applied change. Both transition sides stay held.
- `subscription-update-outcome-unknown` requires reconciliation; never submit
  a second update blindly.
- Timeline and test-clock routes accept only repository-owned objects.
