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
  collect/
    action.rs               StripeExactPaymentCollectV1
    profile.rs              StripePaymentCollectProfile/Command
    evaluator.rs            collection-only pure evaluator
    execution.rs            VerifiedPaymentCollectCommand + gateway
    service.rs              collection-only protected pipeline
    receipts.rs             MerchantCollection* receipts
  authorize/
    action.rs               separate authorization action
    profile.rs              separate authorization profile/command
```

The demos share only `stripe-payment-common`: exact Auths proof-fixture
assembly and strict HTTP/secret transport. It contains no operation enum,
financial evaluator, verified command, provider outcome, or lifecycle service.

## Protected ordering

```text
exact proof
  -> required/executed configuration equality
  -> collection evaluator
  -> durable decision receipt
  -> atomic operation-aware reservation
  -> exact collection claim
  -> restricted credential acquisition
  -> critical Customer/PaymentMethod/order reread
  -> create+confirm automatic-capture PaymentIntent
  -> durable provider acceptance or outcome-unknown
  -> retrieve PaymentIntent + Charge
  -> collection observation and commit/reconciliation receipt
```

No denial path before the credential boundary can call the broker or Stripe.
The private `VerifiedPaymentCollectCommand` is the only input accepted by the
collection gateway.

## State transition table

Callers provide semantic events, never destination states. The shared
Stripe-local ledger derives:

| Operation | Current | Event | Next |
|---|---|---|---|
| collect | reserved | claim | claimed |
| collect | claimed | begin attempt | attempting |
| collect | attempting | provider accepted | provider-accepted |
| collect | provider-accepted | collection committed | committed |
| collect | claimed/attempting/provider-accepted | outcome unknown | outcome-unknown |
| collect | active nonterminal | reconcile collection committed | reconciled-committed |
| collect | active nonterminal | definite/reconciled release | released/reconciled-released |
| authorize | provider-accepted | authorization activated | active-authorization |
| authorize | active nonterminal | reconcile authorization active | reconciled-active-authorization |

Every unlisted combination is rejected. In particular, collect can never
become active authorization and authorize can never become committed
collection.

## Aggregate identity

Every match includes:

```text
Stripe account
+ budget_id
+ operation
+ currency
+ exact resolved fixed/rolling window
```

Reserved, committed, outcome-unknown, and active-authorization exposure are
separate integer categories. All addition and subtraction is checked.

## Receipts

Collection decision, transition, and observation receipts are distinct
schemas. Each commits to the exact profile, operation, action digest, decision,
policy/configuration digests, and legal state transition. The JSONL journal is
canonical, append-only, fsynced, and digest-addressed.
