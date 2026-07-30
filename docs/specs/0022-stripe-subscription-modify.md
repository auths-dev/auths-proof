# 0022: Bounded Stripe subscription modification

Status: Proposed  
Exact action profile: `auths.stripe.exact-subscription-modify/1`  
Policy family: `auths.stripe.bounded-subscription-policy/1`  
Evaluator: `auths.stripe.bounded-subscription-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-subscription-modify`

## 1. Decision

Add a profile for one exact modification of an existing bounded Stripe
subscription. V1 permits only fixed-price and quantity changes that preserve
the exact Customer, currency, collection method, payment method/mandate,
billing anchor, and terminal `cancel_at`.

Every action commits to an exact before state and Stripe invoice preview. A
change that can require immediate payment uses
`payment_behavior=pending_if_incomplete` and
`proration_behavior=always_invoice`, so the subscription change applies only
if its invoice payment succeeds. Non-billing metadata, tax, discounts,
schedules, trial manipulation, pending invoice items, and usage changes are
prohibited.

## 2. Exact action

`StripeExactSubscriptionModifyV1` commits to:

```text
profile = "auths.stripe.exact-subscription-modify/1"
stripe_account_id
connect_account
subscription_id
customer_id
before_subscription_digest
before_items[] { subscription_item_id, price_id, product_id, quantity }
after_items[] { subscription_item_id, price_id, product_id, quantity }
currency
billing_cycle_anchor
cancel_at
proration_date
proration_behavior = always_invoice
payment_behavior = pending_if_incomplete
mandate_receipt_digest
invoice_preview_digest
proration_debit_minor
proration_credit_minor
before_recurring_minor
after_recurring_minor
remaining_cycle_count
incremental_term_liability_minor
test_clock_id
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

Debit and credit are separate non-negative values; they are never netted before
policy evaluation. The action cannot exploit a large credit to authorize an
otherwise forbidden new debit or recurring liability.

## 3. Evidence and bounded evaluation

Protected evidence binds the current Subscription and item IDs, Customer,
Price/Product catalog, current period and anchor, fixed terminal date,
PaymentMethod/mandate, latest invoices/payment state, pending update, exact
proration preview/lines, test clock, API version/test mode, source, and
observation time.

Eligibility requires:

- exact proof and required/executed configuration equality;
- `modify` allowed by the policy from specification 0021;
- exact current-state digest and no conflicting pending update;
- allowed after prices, products, quantities, interval, and Customer;
- unchanged protected anchor, cancel date, currency, collection, and mandate;
- fresh exact preview at the committed proration date;
- proration debit and new recurring/remaining-term liability within every
  ceiling;
- active-slot identity retained rather than double counted; and
- atomic capacity for positive liability deltas and immediate debit.

A downgrade may reduce future recurring liability only after the provider
change is observed. Credits are receipts/observations, not available spending
capacity until Stripe applies them.

Required/executed configuration follows specification 0021 and additionally
binds `auths.stripe.exact-subscription-modify/1`, pending-update/proration
semantics, liability-transition schema, API version, and hard item,
preview-line, evidence, reservation, cycle, and work limits. Inequality denies
before decision persistence, reservation, credential access, or Stripe I/O.

## 4. Reservation, execution, and reconciliation

```text
fresh subscription/catalog/preview -> exact proof
-> bounded before/after evaluator -> durable decision
-> reserve positive recurring delta + proration debit
-> exact claim -> acquire subscription-update credential
-> fresh critical re-read/preview equality
-> POST exact update with pending_if_incomplete
-> observe applied update or pending_update + invoice/payment
-> atomically commit, release, or hold liability transitions
```

If payment succeeds and the update is applied, commit the new liability and
release superseded future liability. If payment fails and Stripe records a
`pending_update`, retain new reservations until it is applied, explicitly
voided/expired, or reconciled. Do not report the after state while only a
pending update exists.

A definite pre-delivery failure releases the new delta and leaves old liability
unchanged. Timeout/disconnect holds both transition sides until retrieval and
webhook evidence settle the state. Recovery never submits a second update
blindly.

## 5. Receipts and stable codes

Receipts include exact before/after item sets, catalog and preview commitments,
separate debit/credit, recurring/term delta, reservation transitions,
configuration equality, credential/provider boundaries, Subscription,
pending-update, Invoice and PaymentIntent commitments, and reconciliation.

Codes include:

- `subscription-modify-authorized`;
- `subscription-before-state-mismatch`;
- `subscription-protected-field-changed`;
- `subscription-price-denied`;
- `subscription-quantity-exceeded`;
- `subscription-proration-limit-exceeded`;
- `subscription-recurring-limit-exceeded`;
- `subscription-preview-mismatch`;
- `subscription-pending-update-conflict`;
- `subscription-update-payment-incomplete`;
- `subscription-update-outcome-unknown`; and
- shared bounded policy, evidence, configuration, reservation, replay, and
  arithmetic codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Modification policy        | Exact before -> after      |
| Allowed products/quantity  | Price/quantity diff        |
| Proration / term ceilings  | Debit, credit, new recurring|
| Protected fields unchanged | Preview and proration date |
+----------------------------+----------------------------+
| Decision | reserve | pending/applied | invoice/payment   |
+---------------------------------------------------------+
| Old liability -> delta -> new bounded liability         |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The UI distinguishes “pending payment” from “subscription changed.” It renders
security-relevant values from canonical policy/action/preview data, keeps
controls/results adjacent, and uses the `auths-proof-site` design language.

## 7. Architecture and APIs

```text
Browser -> API -> Stripe preview/current-state evidence
        -> exact verifier -> subscription-delta evaluator
        -> liability store -> verified update -> credential broker
        -> Stripe pending update/invoice -> observer/reconciler
```

Use the common subscription session, preview, execute, reconcile, timeline, and
receipt routes from specification 0021. Experiment IDs select repository-owned
upgrade, downgrade, boundary, conflict, and pending-payment scenarios.

## 8. Verification and completion

Tests cover exact and boundary deltas, credits versus debits, Price/quantity/
Customer/anchor/cancel-date mutation, stale or changed preview, concurrent
updates, existing pending update, proration success/failure, pending update
application/expiry, denial before credential, disconnect before and during
update, restart, reconciliation, and replay.

The live demo creates a bounded test-clock Subscription, previews an upgrade,
applies it with `pending_if_incomplete`, observes the invoice/payment and final
item set, then separately demonstrates a failed pending update and expiry
without duplicate application. Browser E2E covers before/after, pending/applied
states, and receipts.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures/compliance mapping, secret/PII
scanning, and complete workspace/live/browser CI on the exact revision.

## 9. Acceptance and deferred work

Acceptance requires exact before/after state, independent debit/credit
accounting, no unauthorized protected-field changes, atomic liability
transition, accurate pending-update state, and deterministic reconciliation.

Deferred: immediate non-pending updates, trial/anchor/cancel-date changes,
usage-based items, schedules, discounts, tax, payment-method changes,
add-invoice-items, live mode, and generic subscription-delta abstraction.

Provider references:

- [Modify subscriptions](https://docs.stripe.com/billing/subscriptions/change)
- [Pending updates](https://docs.stripe.com/billing/subscriptions/pending-updates)
