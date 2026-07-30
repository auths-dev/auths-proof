# Debugging

- `configuration-mismatch` before any counter increase means the action and
  runtime identities differ.
- `critical-preview-changed` means the protected re-preview changed an
  economic line, Price, quantity, amount, mandate, test clock, or active count.
- `outcome-unknown` intentionally holds all liabilities. Call reconcile; do
  not create again.
- `incomplete` holds first-invoice and recurring exposure until a fresh
  Subscription/Invoice observation resolves it.
- A test clock can be advanced only for repository-created session objects.
