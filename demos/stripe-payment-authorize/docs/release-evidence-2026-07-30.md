# Stripe payment authorization release evidence — 2026-07-30

This record contains only non-secret Stripe test-mode identifiers and
commitments. No API key, client secret, card data, or reusable payment
credential is retained here.

## Revision and runtime

- validated code revision: `2bd9c2b`
- local image digest:
  `sha256:dd08abcb73f8c5642aa27569b86632fde20c498e46d0135fed070fe4d4c0c238`
- local origin: `http://localhost:8080`
- execution mode: `stripe-test-mode`
- Stripe API version: `2025-04-30.basil`
- account commitment:
  `6738148edaca97e9f4c9157b139641616074e13c102d613d6da7db9597c0184d`

## Exact authorization

- session: `df07966386defdde0be2b65a3e04998a`
- workflow: `authorize-df07966386defdde0be2b65a3e04998a`
- PaymentIntent: `pi_3TyiALPbjgb2M2Te3SD3mhX0`
- latest Charge: `ch_3TyiALPbjgb2M2Te3HFEdbHv`
- Stripe request: `req_ysDL5eEn59lhWY`
- sanitized provider response commitment:
  `2308f1a067a396d00f36ba91ebcf84cdf59df4c1ec41fd6fdfc71794112a46f3`
- canonical receipt:
  `d9dcf4b62652d370f306f56e6a2de65308aee73c480ce521427ef231bcdaf330`

The native result, canonical receipt, designed receipt, and an independent
Stripe retrieval agreed on:

- `livemode=false`;
- `status=requires_capture`;
- `capture_method=manual`;
- amount and capturable amount are exactly `500 usd`;
- amount received is `0`;
- the Charge is not captured;
- `capture_before=1785977381`; and
- the durable merchant state is `authorized`, with `500` held and `0`
  committed as captured revenue.

The Stripe Charge reports `paid=true` while `captured=false`. The demo does not
present that provider-specific `paid` flag as captured or settled funds.

## Replay and restart

The exact workflow replayed with the original PaymentIntent and:

- credential requests: `0`;
- provider calls: `0`; and
- client-secret exposure: `false`.

The same result survived a container restart against the persistent volume.
After the provider observation was 131 seconds old—past the configured
120-second evidence freshness bound—the replay still resolved from matching
durable action and policy commitments with zero credential or provider calls.
This guards replay from incorrectly becoming a fresh authorization decision.

## Ambiguous delivery and reconciliation

- session: `2db3220f2400c823fd8e5d86917d12df`
- PaymentIntent: `pi_3TyiCCPbjgb2M2Te0xjw587F`
- outcome-unknown receipt:
  `fd08b2a35129f4356f80864c97bb6d3a2f2760a06c9a0e1ae36aafd355d16d03`
- reconciled receipt:
  `9660afb3ab2e735355b3102d55db50a73924ee90a377f697b70c1663a935aef2`

The injected lost-response path retained `500` as outcome-unknown. A separate
retrieval reconciled the same PaymentIntent to `reconciled-authorized`,
`requires_capture`, `500` capturable, `0` received, without another create.

## Browser and negative-path evidence

The real browser verified:

- exact authorization renders `AUTHORIZED`, `authorized`, `$5.00`
  capturable, `$5.00` active hold, and `$0.00` captured;
- the designed receipt renders the digest-addressed
  `merchant-authorization-transition` lifecycle;
- one-minor-unit-over-policy denial stops with zero credential requests and
  zero provider calls; and
- required/executed configuration mismatch writes no merchant state and makes
  zero credential or provider calls.

## Promotion blockers

The isolated Fly app and encrypted persistent volume exist, but public
deployment evidence is still pending. Importing the user's Stripe test secret
into the specific Fly app requires explicit user confirmation at the secret
transmission boundary.

The available credential is an `sk_test_` key. The code now accepts
profile-specific `rk_test_` credentials and maintains distinct compile-time
authorization and collection scopes, but provider-side least privilege has not
been proven with a restricted Stripe key. The profile must not be marked
implemented until the cloud and credential assumptions are either satisfied or
explicitly accepted as a release exception.
