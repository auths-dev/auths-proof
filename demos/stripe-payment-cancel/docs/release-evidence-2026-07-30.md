# Stripe payment cancellation release evidence — 2026-07-30

This record contains only non-secret Stripe test-mode identifiers and
commitments. No API key, client secret, card data, or reusable payment
credential is retained here.

## Revision and runtime

- validated base revision: `5baae8d`
- validated cancellation source: this evidence's enclosing revision
- local image digest:
  `sha256:c444d72f0baaec86f4fb17bfca4a9ccd01bc7aa2161d80e8811ee1a34fd78b0d`
- local origin: `http://localhost:8080`
- execution mode: `stripe-test-mode`
- Stripe API version: `2025-04-30.basil`
- account commitment:
  `6738148edaca97e9f4c9157b139641616074e13c102d613d6da7db9597c0184d`

## Exact terminal cancellation

- session: `f6ac7ee03ee8b8689843bb698344714e`
- workflow: `cancel-f6ac7ee03ee8b8689843bb698344714e`
- PaymentIntent: `pi_3TykoaPbjgb2M2Te3CNSyoHD`
- latest Charge: `ch_3TykoaPbjgb2M2Te3slrK2qE`
- Stripe request: `req_7bTjlul1fC4Tki`
- sanitized provider response commitment:
  `ba42892103560e2cce8eb34844d011cea5d074b5cca6f90a6174720cb1f8e46b`
- canonical receipt:
  `7431637804b2768b421db08038f480a7730e3ce0a69e487fd7a3c4a5c7294dea`

The native result, canonical receipt, designed receipt, and fresh Stripe
retrieval agreed on:

- the pre-effect PaymentIntent was a `1000 usd` manual-capture authorization;
- the exact cancellation reason was `requested_by_customer`;
- the terminal provider state became `canceled`;
- amount capturable and amount received both became `0`;
- the Charge was not captured;
- the prior `1000` authorization hold was released only after terminal
  observation;
- cancellation claim commit and authorization release occurred in one durable
  store transition; and
- the resulting state is `cancel-committed`.

No refund was created or represented by this profile.

## Replay and restart

The exact workflow replayed with:

- credential requests: `0`;
- provider calls: `0`;
- agent credential exposure: `false`; and
- client-secret exposure: `false`.

The container was rebuilt and restarted against the same persistent volume.
The original session identifier then resolved from durable state to the same
`cancel-committed` record and receipt with zero credential or provider calls.

## Ambiguous delivery and reconciliation

- session: `aed5d30accba03a1c4051ab0f09a44ba`
- workflow: `cancel-aed5d30accba03a1c4051ab0f09a44ba`
- PaymentIntent: `pi_3TykzlPbjgb2M2Te3kPT4E5r`
- latest Charge: `ch_3TykzlPbjgb2M2Te3Abw8TK2`
- reconciled Stripe request: `req_J87xSrZbmLssH3`
- sanitized provider response commitment:
  `3647b10352d1ab9639d8c7c8fac330116e5b9ef4eb4335ffcb85e329b5174660`
- reconciled receipt:
  `320507badb741494561cd3a98a972eaec5789c6974463e0fb622eeb07c9322c4`

The injected lost-response path reached `outcome-unknown` and retained both the
exclusive cancellation claim and prior authorization hold. Reconciliation
used one provider retrieval, issued no second cancellation, observed the
original terminal effect, released the full hold, and reached
`reconciled-cancel-committed`.

The reconciled receipt explicitly records `execution_attempted=true`,
`provider_accepted=true`, and `reconciled_observation=true`. Browser inspection
found and verified the correction of an earlier draft receipt that had lost
the historical execution-attempt fact.

## Browser and negative-path evidence

The real browser verified:

- exact cancellation renders `CANCELED`, `cancel-committed`, `$0.00`
  capturable, `$0.00` active hold, and `requested_by_customer`;
- the designed receipt renders the digest-addressed
  `merchant-cancel-transition` lifecycle and the canonical JSON remains
  available separately;
- replay makes zero credential and provider calls;
- denied reason and changed configuration stop before credentials and
  provider calls, with configuration mismatch writing no merchant state;
- lost response renders `OUTCOME-UNKNOWN`; and
- retrieval renders `RECONCILED` without another cancellation.

A missing digest-addressed receipt renders `UNAVAILABLE` and does not present
provider acceptance.

## Secret scan

The exact local test key was absent from repository source and built
cancellation binaries. Credential-shaped scans were also clean for the new
source and fixture corpus, container logs, and the persistent state/receipt
volume.

## Promotion blockers

Public Fly deployment evidence is still pending. Importing the user's Stripe
test secret into the profile-specific Fly app requires explicit user
confirmation at the secret-transmission boundary.

The available credential is an `sk_test_` key. The code accepts
profile-specific `rk_test_` credentials and maintains a distinct compile-time
cancellation credential scope, but provider-side least privilege has not been
proven with a restricted Stripe key. The profile must remain `specified` until
the public deployment and credential assumptions are either satisfied or
explicitly accepted as a release exception.
