# Debugging

- `payout-approval-required`: exact commitments, scope, assurance, expiry, or
  distinct-principal count failed.
- `payout-minimum-balance-violated`: payout plus local holds would breach the
  retained minimum.
- `payout-outcome-unknown`: keep capacity and retrieve by Payout ID or fixed
  workflow metadata; never create again blindly.
- `payout-failed`: do not release merely from delivery status; wait for fresh
  available-balance return evidence.
- `payout-replay`: return the durable record with no second provider effect.

The receipt journal is sanitized. Never record destination coordinates,
credentials, or full provider payloads.
