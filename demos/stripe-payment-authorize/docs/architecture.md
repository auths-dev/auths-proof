# Architecture

## Module boundary

The product remains one `auths-stripe` package with explicit internal
boundaries:

```text
merchant/
  policy.rs                 closed Stripe merchant-policy family
  budget.rs                 operation-aware budget values
  evidence.rs               protected Customer/PaymentMethod/order evidence
  commitments.rs            profile-bound metadata/config commitments
  state.rs                  closed transition kernel + atomic persistence
  authorize/
    action.rs               StripeExactPaymentAuthorizeV1
    profile.rs              StripePaymentAuthorizeProfile/Command
    evaluator.rs            authorization-only pure evaluator
    execution.rs            VerifiedPaymentAuthorizeCommand + gateway
    service.rs              authorization-only protected pipeline
    receipts.rs             MerchantAuthorization* receipts
```

The demos share only `stripe-payment-common`: exact Auths proof-fixture
assembly and strict HTTP/secret transport. It contains no operation enum,
financial evaluator, verified command, provider outcome, or lifecycle service.

## Protected ordering

```text
exact proof
  -> required/executed configuration equality
  -> authorization evaluator
  -> durable decision receipt
  -> atomic operation-aware reservation
  -> exact authorization claim
  -> restricted credential acquisition
  -> critical Customer/PaymentMethod/order reread
  -> create+confirm manual-capture PaymentIntent
  -> durable provider acceptance or outcome-unknown
  -> retrieve PaymentIntent + Charge
  -> authorization observation and hold/reconciliation receipt
```

No denial path before the credential boundary can call the broker or Stripe.
The private `VerifiedPaymentAuthorizeCommand` is the only input accepted by the
authorization gateway.

The broker and gateway share the compile-time
`PaymentAuthorizeCredentialScope`; a collection, capture, cancellation, or
refund credential type cannot satisfy this service. Authorization receipts are
persisted as the closed `MerchantAuthorizationReceipt` family through
`ReceiptSink<MerchantAuthorizationReceipt>`. Adding another profile therefore
does not add variants that this demo must handle.

## State transition table

Callers provide semantic events, never destination states. The shared
Stripe-local ledger derives:

| Operation | Current | Event | Next |
|---|---|---|---|
| authorize | reserved | claim | claimed |
| authorize | claimed | begin attempt | attempting |
| authorize | attempting | provider accepted | provider-accepted |
| authorize | provider-accepted | authorization held | authorized |
| authorize | claimed/attempting/provider-accepted | outcome unknown | outcome-unknown |
| authorize | active nonterminal | reconcile authorization held | reconciled-authorized |
| authorize | active nonterminal | definite/reconciled release | released/reconciled-released |

Every unlisted combination is rejected. In particular, this profile can never
turn an authorization into a collection, capture, cancellation, or refund.

## Aggregate identity

Every match includes:

```text
Stripe account
+ budget_id
+ operation
+ currency
+ exact resolved fixed/rolling window
```

Reserved, collected, outcome-unknown, and active-authorization exposure are
separate integer categories. An accepted hold moves into active authorization
exposure while collected funds remain zero. All addition and subtraction is
checked.

## Receipts

Authorization decision, transition, and observation receipts are distinct
schemas. Each commits to the exact profile, operation, action digest, decision,
policy/configuration digests, and legal state transition. The JSONL journal is
canonical, append-only, fsynced, and digest-addressed.
