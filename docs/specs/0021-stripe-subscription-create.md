# 0021: Bounded Stripe subscription creation

Status: Proposed  
Exact action profile: `auths.stripe.exact-subscription-create/1`  
Policy family: `auths.stripe.bounded-subscription-policy/1`  
Evaluator: `auths.stripe.bounded-subscription-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-subscription-create`

## 1. Decision

Add a profile for creating one exact, fixed-term Stripe subscription for one
existing Customer. A subscription creates continuing billing authority and can
finalize and attempt payment of a first invoice during creation. The profile
therefore reserves both recurring liability and any immediate first-invoice
amount.

V1 allows only fixed licensed prices, bounded quantities, automatic collection,
an explicit terminal `cancel_at`, one Customer, one mandate/payment method, and
Stripe test clocks. Usage-based pricing, indefinite subscriptions, schedules,
discounts, coupons, arbitrary invoice items, uncontrolled tax settings,
multiple currencies, and live mode are prohibited.

This specification owns the shared
`auths.stripe.bounded-subscription-policy/1` used by specifications 0021 through
0023. It is a Stripe-local closed evaluator, not a generic recurring-policy
language.

Implementation remains domain-local in `auths-stripe`. Calendar, invoice,
proration, mandate, and continuing-liability semantics remain outside `core/`
and outside any generic runtime until the formal extraction gates.

## 2. Closed subscription policy

`StripeBoundedSubscriptionPolicyV1` contains:

```text
policy_type = "auths.stripe.bounded-subscription-policy"
policy_version = 1
canonicalization = "rfc8785-sha256-v1"
evaluator_semantic_id = "auths.stripe.bounded-subscription-evaluator"
evaluator_semantic_version = 1
policy_id
valid_from
expires_at
allowed_operations[] = create | modify | cancel
allowed_test_account_ids[]
allowed_customer_ids[]
allowed_product_ids[]
allowed_price_ids[]
allowed_payment_method_ids[]
allowed_mandate_receipt_digests[]
allowed_currencies[]
allowed_intervals[]
allowed_collection_methods[] = charge_automatically
allowed_payment_behaviors[]
allowed_proration_behaviors[]
allowed_cancel_modes[]
maximum_quantity_by_price{}
maximum_recurring_minor_by_currency_and_interval{}
maximum_first_invoice_minor_by_currency{}
maximum_proration_debit_minor_by_currency{}
maximum_term_seconds
maximum_billing_cycles
maximum_active_subscriptions_per_customer
aggregate_recurring_budgets[] { budget_id, scope, currency, interval, limit_minor }
aggregate_immediate_budgets[] { budget_id, currency, limit_minor, window }
minimum_preview_validity_seconds
maximum_evidence_age_seconds
maximum_action_lifetime_seconds
allowed_api_versions[]
require_fixed_term = true
require_livemode = false
```

All Price semantics are resolved into protected evidence. Policy IDs do not
stand in for canonical policy digests. Amounts are integer minor units;
intervals and cycle calculations use checked arithmetic and explicit calendar
semantics from Stripe evidence.

## 3. Exact action

`StripeExactSubscriptionCreateV1` commits to:

```text
profile = "auths.stripe.exact-subscription-create/1"
stripe_account_id
connect_account
customer_id
items[] { price_id, product_id, quantity }
currency
collection_method = charge_automatically
default_payment_method_id
mandate_receipt_digest
payment_behavior = default_incomplete | error_if_incomplete
trial_end = optional exact timestamp
billing_cycle_anchor
cancel_at
proration_behavior
automatic_tax = disabled
discounts = absent
add_invoice_items = absent
fixed_metadata_commitment
invoice_preview_digest
projected_first_invoice_minor
projected_recurring_minor
projected_cycle_count
projected_term_liability_minor
test_clock_id
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

Items are sorted and duplicate-free. `cancel_at` is mandatory and within the
maximum term/cycle policy. The action cannot name a Price merely by display
name. Product, Price, interval, quantity, currency, and amount evidence are all
committed.

## 4. Evidence and calculations

Protected evidence binds account/Connect context, Customer, PaymentMethod and
mandate receipt, Product/Price identities and immutable billing properties,
licensed versus usage type, tax behavior, test clock, existing subscriptions,
invoice preview and line items, API version/test mode, source, and observation
times.

The evaluator calculates:

```text
recurring_minor = sum(price_unit_minor * quantity)
cycle_count = exact cycles from anchor through cancel_at
term_liability_minor = recurring_minor * cycle_count
immediate_debit_minor = positive amount due from exact invoice preview
```

Calendar intervals are derived using Stripe/test-clock semantics, not an
assumed number of seconds per month or year. Overflow, contradictory previews,
negative totals, credits, metered items, or unknown tax/discount behavior fail
closed.

Eligibility requires exact proof and configuration equality plus allowed
account, Customer, prices/products, payment method/mandate, interval, quantity,
term, collection/payment behavior, current active count, recurring and
immediate ceilings, fresh preview/evidence, and atomic capacity.

Required/executed configuration commits to policy/evaluator and implementation
identity, exact profile, account/Connect and test-clock context, API version,
recurring/immediate reservation and receipt schemas, executor audience, and
hard byte, item, preview-line, evidence, reservation, cycle, and work limits.
Inequality denies before decision persistence, reservation, credential access,
or Stripe I/O.

## 5. Reservations, execution, and reconciliation

Atomic reservation covers:

- one active-subscription slot;
- the exact recurring liability for the bounded term; and
- the positive immediate first-invoice amount.

```text
fresh catalog/customer/preview -> exact proof -> bounded evaluator
-> durable decision -> atomic recurring + immediate reservation
-> exact claim -> acquire subscription-only credential
-> fresh critical preview/re-read -> create exact Subscription
-> persist Subscription + first Invoice/PaymentIntent
-> observe active/trialing/incomplete/incomplete_expired
-> commit/release/hold reservations
```

`active` or `trialing` commits recurring capacity. First-invoice capacity
commits only when the associated payment is collected; pending/incomplete
states hold it until reconciliation. A known no-effect rejection releases all
new reservations. A timeout or disconnect retains them.

Recovery retrieves by Subscription ID or fixed Auths metadata and reconciles
Subscription, Invoice, PaymentIntent, mandate, and test-clock evidence. It does
not create another subscription. Renewal observations decrement the remaining
term obligation without widening the original liability.

## 6. Receipts and stable codes

Receipts include policy/evaluator identity, exact items/term, mandate link,
catalog and preview commitments, all cycle/liability calculations, aggregate
reservations, required/executed configuration, credential/provider boundaries,
Stripe request ID, Subscription/Invoice/PaymentIntent commitments, lifecycle,
and reconciliation.

Codes include:

- `subscription-create-authorized`;
- `subscription-price-denied`;
- `subscription-metered-price-denied`;
- `subscription-quantity-exceeded`;
- `subscription-term-required`;
- `subscription-term-exceeded`;
- `subscription-recurring-limit-exceeded`;
- `subscription-first-invoice-limit-exceeded`;
- `subscription-preview-mismatch`;
- `subscription-mandate-mismatch`;
- `subscription-payment-incomplete`;
- `subscription-outcome-unknown`; and
- shared bounded policy, configuration, evidence, reservation, replay, and
  arithmetic codes.

## 7. UX

```text
+----------------------------+----------------------------+
| Subscription policy        | Exact subscription         |
| Products/prices/quantities | Customer / price / quantity|
| Recurring + term ceilings  | Interval / anchor / end    |
| Active count / first invoice| Mandate / preview         |
+----------------------------+----------------------------+
| Decision | reservations | credential | Stripe lifecycle |
+----------------------------------------------------------+
| First invoice + bounded term liability + cycles remaining|
+----------------------------------------------------------+
| Inline canonical receipt JSON        [Designed receipt]  |
+----------------------------------------------------------+
```

The UI never reduces a subscription to “$10 payment”; it shows the continuing
term obligation, first invoice, renewal count, and cancellation date. Policy,
action, and result remain adjacent with canonical copy and
`auths-proof-site` styling.

## 8. Architecture and APIs

```text
Browser -> API -> catalog/preview normalizer -> exact verifier
        -> subscription evaluator -> recurring/immediate store
        -> verified command -> credential broker -> Stripe Billing
        -> Subscription/Invoice/PaymentIntent observer + test clock
```

Use common session/execute/reconcile/receipt routes plus:

```text
POST /api/v1/sessions/{id}/preview
POST /api/v1/sessions/{id}/advance-clock
GET  /api/v1/subscriptions/{id}/timeline
```

Price IDs, Customers, PaymentMethods, and clocks are repository-owned demo
fixtures. The public endpoint does not accept arbitrary Stripe objects.

## 9. Verification, deployment, and completion

Fixtures/tests cover term/cycle arithmetic, exact and boundary-plus-one
quantity/amount/term, metered price, price mutation, stale preview, changed
Customer/mandate/clock, duplicate active subscription, concurrent last slot,
first-invoice success/failure/action required, denial before credential,
timeout, restart, incomplete expiry, renewal, reconciliation, and replay.

The live demo creates a fresh Stripe test-clock Customer and fixed Price,
obtains an invoice preview, creates one bounded fixed-term Subscription,
observes its first invoice/payment, advances the clock through renewal and
terminal date, and proves replay cannot create a second subscription. Browser
E2E covers the full timeline and receipt surfaces.

Completion requires Docker-local and tested public deployments, redacted
release evidence, canonical fixtures/compliance mapping, secret/PII scanning,
and complete workspace/live/browser CI on the exact revision.

## 10. Acceptance and deferred work

Acceptance requires a finite auditable liability, exact Price/Customer/mandate,
atomic capacity, one provider Subscription, observable invoice lifecycle, no
credential on denial, and fail-closed recovery.

Deferred: indefinite and usage-based subscriptions, schedules, multiple
currencies, tax, discounts/coupons, manual invoicing, trials with dynamic end,
customer portal, live mode, and provider-neutral recurring abstractions.

Provider references:

- [Create a Subscription](https://docs.stripe.com/api/subscriptions/create)
- [Billing test clocks](https://docs.stripe.com/billing/testing/test-clocks)
