# Architecture

## Profile boundary

```text
merchant/cancel/
  action.rs       StripeExactPaymentCancelV1 + closed reason vocabulary
  evidence.rs     Stripe target + optional durable authorization evidence
  profile.rs      StripePaymentCancelProfile and command
  evaluator.rs    cancellation-only pure decision
  execution.rs    verified command, credential scope, gateway, transitions
  service.rs      proof-to-observed-cancellation pipeline
  receipts.rs     closed MerchantCancelReceipt family
```

Adding another profile does not add variants to `MerchantCancelReceipt`.
Likewise, `PaymentCancelCredentialScope` cannot satisfy the collection,
authorization, or capture gateway boundary.

## Protected ordering

```text
exact proof
  -> required/executed configuration equality
  -> pure cancellation decision
  -> durable decision receipt
  -> exclusive non-monetary cancellation claim
  -> cancellation-scoped credential acquisition
  -> critical PaymentIntent + hold reread
  -> POST exact cancellation reason with deterministic idempotency
  -> durable provider response or outcome-unknown
  -> retrieve the exact PaymentIntent
  -> release a linked authorization only after terminal canceled observation
```

Denial occurs before a claim, credential request, or Stripe call.
Outcome-unknown retains both the cancellation claim and any linked hold.
Reconciliation retrieves once and never repeats cancellation.

## Capture race

Capture and cancellation reserve the same PaymentIntent target under one
durable store lock. Only one claim can win. If Stripe shows that capture won
after cancellation delivery, the cancellation record moves to
`cancel-capture-conflict`; cancellation is not retried and the authorization
hold is not released by cancellation.

## State transitions

| Current | Event | Next |
|---|---|---|
| reserved | claim | claimed |
| claimed | begin attempt | attempting |
| attempting | provider accepted | provider-accepted |
| provider-accepted | terminal canceled observed | cancel-committed |
| active nonterminal | outcome unknown | outcome-unknown |
| active nonterminal | capture conflict observed | cancel-capture-conflict |
| active/unknown | reconcile canceled | reconciled-cancel-committed |
| active/unknown | reconcile released | reconciled-released |

Every unlisted transition is rejected.

## Receipts

Decision, transition, and observation receipts have separate schemas and are
wrapped only by `MerchantCancelReceipt`. They commit to the exact target and
reason, pre/post provider facts, optional authorization link and release,
configuration equality, credential/provider boundaries, conflicts, and
reconciliation.
