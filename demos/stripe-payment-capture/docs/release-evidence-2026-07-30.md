# Stripe payment capture release evidence — 2026-07-30

This record contains only non-secret Stripe test-mode identifiers and
commitments. No API key, client secret, card data, or reusable payment
credential is retained here.

## Revision and runtime

- validated base revision: `24da40c`
- local image digest:
  `sha256:c78e59f509d1f8456f00fde0a0afec92fc8d6d1daabb6a721fc869b80d57e70d`
- local origin: `http://localhost:8080`
- execution mode: `stripe-test-mode`
- Stripe API version: `2025-04-30.basil`
- account commitment:
  `6738148edaca97e9f4c9157b139641616074e13c102d613d6da7db9597c0184d`

## Exact final capture

- session: `a60b1fa4e23e08b8eb6aa9f465a69694`
- workflow: `capture-a60b1fa4e23e08b8eb6aa9f465a69694`
- PaymentIntent: `pi_3TyjYBPbjgb2M2Te3fMveKuP`
- Charge: `ch_3TyjYBPbjgb2M2Te3cV3io18`
- balance transaction: `txn_3TyjYBPbjgb2M2Te3BGdf2Vv`
- Stripe request: `req_k7RrgDgdwRNkwl`
- sanitized provider response commitment:
  `efd111f46d34c5d5cb6de50556dfd1e3208c4151b4b35cea670e7274e49c385d`
- canonical receipt:
  `bdcc7713d920af6fab0908093ae22434fdca8a9f2807f12fe1d350f3f2754b79`

The native result, canonical receipt, designed receipt, and a fresh Stripe
retrieval agreed on:

- the exact `500 usd` settlement was captured;
- the provider's capturable amount became `0`;
- the settlement budget committed exactly `500`;
- the entire prior `1000` authorization hold was released;
- the settlement commit and authorization release occurred in one durable
  store transition; and
- the resulting state is `capture-committed`.

Stripe rejected an earlier adapter request because it explicitly supplied
`final_capture=true` to a PaymentIntent that did not support multicapture.
The verified Auths command still requires a final capture. The adapter now
omits that redundant optional wire field, for which Stripe's capture endpoint
defaults to final capture, and the live capture above proves the resulting
effect.

## Replay and restart

The exact workflow replayed with:

- credential requests: `0`;
- provider calls: `0`;
- agent credential exposure: `false`; and
- client-secret exposure: `false`.

After the container restarted against its persistent volume, the same session
identifier resolved from durable state to the original capture with the same
zero-I/O boundary counters.

## Ambiguous delivery and reconciliation

- session: `fe200050a12b5abf6d9e9332c8603c9c`
- workflow: `capture-fe200050a12b5abf6d9e9332c8603c9c`
- PaymentIntent: `pi_3TyjZ1Pbjgb2M2Te0nSHVF4P`
- Charge: `ch_3TyjZ1Pbjgb2M2Te0zKVPSpa`
- balance transaction: `txn_3TyjZ1Pbjgb2M2Te0RGMZHem`
- reconciled Stripe request: `req_auj5R6gLfYwALp`
- sanitized provider response commitment:
  `53e91ae14b92a7c298184c1e447e00f8f175bc233c27059856165c02cb4f178b`
- reconciled receipt:
  `a6ec13ece5d67035a4665751ac942937b097b57a54d48232b42a2b1cb981a116`

The injected lost-response path reached `outcome-unknown` and retained both
the new settlement reservation and prior authorization hold. Reconciliation
used one provider read, issued no second capture, observed the original exact
effect, atomically committed `500` settlement, released the full `1000` hold,
and reached `reconciled-capture-committed`.

## Browser and negative-path evidence

The real browser verified:

- exact final capture renders `CAPTURED`, `capture-committed`, `$0.00`
  capturable, `$0.00` active hold, and `$5.00` captured;
- the designed receipt renders the digest-addressed
  `merchant-capture-transition` lifecycle;
- replay makes zero credential and provider calls;
- lost response renders `OUTCOME-UNKNOWN`; and
- reconciliation renders `RECONCILED` without a second capture.

Automated API tests additionally prove one-minor-unit-over-policy denial,
changed action, and changed configuration all stop before credential and
provider boundaries.

## Promotion blockers

Public Fly deployment evidence is still pending. Importing the user's Stripe
test secret into the profile-specific Fly app requires explicit user
confirmation at the secret transmission boundary.

The available credential is an `sk_test_` key. The code accepts
profile-specific `rk_test_` credentials and maintains a distinct compile-time
capture credential scope, but provider-side least privilege has not been
proven with a restricted Stripe key. The profile must remain specified until
the public deployment and credential assumptions are either satisfied or
explicitly accepted as a release exception.
