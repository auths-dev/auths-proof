# Architecture

## Module boundary

The product remains one `auths-stripe` package with explicit internal
boundaries:

```text
merchant/
  policy.rs                 closed Stripe merchant-policy family
  budget.rs                 operation-aware budget values
  authorize/                separate authorization vertical consumed by capture
  commitments.rs            profile-bound metadata/config commitments
  state.rs                  closed transition kernel + atomic persistence
  capture/
    action.rs               StripeExactPaymentCaptureV1
    profile.rs              StripePaymentCaptureProfile/Command
    evaluator.rs            capture-only pure evaluator
    execution.rs            VerifiedPaymentCaptureCommand + gateway
    service.rs              capture-only protected pipeline
    receipts.rs             MerchantCapture* receipts
```

The demos share only `stripe-payment-common`: exact Auths proof-fixture
assembly and strict HTTP/secret transport. It contains no operation enum,
financial evaluator, verified command, provider outcome, or lifecycle service.

## Protected ordering

```text
exact proof
  -> required/executed configuration equality
  -> capture evaluator
  -> durable decision receipt
  -> atomic operation-aware reservation
  -> exact capture claim
  -> restricted credential acquisition
  -> capture-specific credential acquisition
  -> critical PaymentIntent/Charge/hold reread
  -> final capture of the exact existing PaymentIntent
  -> durable provider response or outcome-unknown
  -> retrieve PaymentIntent + Charge + balance transaction
  -> atomically commit settlement and release the linked authorization hold
```

No denial path before the credential boundary can call the broker or Stripe.
The private `VerifiedPaymentCaptureCommand` is the only input accepted by the
capture gateway.

The broker and gateway share the compile-time
`PaymentCaptureCredentialScope`; a collection, authorization, cancellation, or
refund credential type cannot satisfy this service. Capture receipts are
persisted as the closed `MerchantCaptureReceipt` family through
`ReceiptSink<MerchantCaptureReceipt>`. Adding another profile therefore
does not add variants that this demo must handle.

## State transition table

Callers provide semantic events, never destination states. The shared
Stripe-local ledger derives:

| Operation | Current | Event | Next |
|---|---|---|---|
| capture | reserved | claim | claimed |
| capture | claimed | begin attempt | attempting |
| capture | attempting | provider accepted | provider-accepted |
| capture | provider-accepted | capture committed | capture-committed |
| capture | claimed/attempting/provider-accepted | outcome unknown | outcome-unknown |
| capture | active nonterminal | reconcile committed | reconciled-capture-committed |
| capture | active nonterminal | definite/reconciled release | released/reconciled-released |

Every unlisted combination is rejected. In particular, a collect or authorize
event cannot advance a capture record, and a capture event cannot advance
those profiles.

## Aggregate identity

Every match includes:

```text
Stripe account
+ budget_id
+ operation
+ currency
+ exact resolved fixed/rolling window
```

Reserved settlement, committed settlement, outcome-unknown settlement, and
active authorization liability are distinct integer categories. A successful
partial final capture commits $5.00 of settlement while releasing the full
$10.00 authorization liability in one store transaction. All arithmetic is
checked.

## Receipts

Capture decision, transition, and observation receipts are distinct
schemas. Each commits to the exact profile, operation, action digest, decision,
policy/configuration digests, and legal state transition. The JSONL journal is
canonical, append-only, fsynced, and digest-addressed.
