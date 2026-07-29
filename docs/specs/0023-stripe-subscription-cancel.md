# 0023: Bounded Stripe subscription cancellation

Status: Proposed  
Exact action profile: `auths.stripe.exact-subscription-cancel/1`  
Policy family: `auths.stripe.bounded-subscription-policy/1`  
Evaluator: `auths.stripe.bounded-subscription-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-subscription-cancel`

## 1. Decision

Add a profile for terminating one exact existing subscription either:

- at the current period end; or
- immediately under a stricter no-hidden-charge branch.

Cancellation stops or schedules the end of a continuing obligation. It does
not itself refund prior invoices, remove arbitrary pending invoice items, or
prove downstream service deprovisioning. Those effects require separate exact
actions and observations.

V1 immediate cancellation requires `invoice_now=false`, `prorate=false`, no
pending update, and protected evidence proving no unhandled pending invoice
items. Period-end cancellation preserves the current-period obligation until
the provider reports the terminal canceled state.

## 2. Exact action

`StripeExactSubscriptionCancelV1` commits to:

```text
profile = "auths.stripe.exact-subscription-cancel/1"
stripe_account_id
connect_account
subscription_id
customer_id
subscription_digest
item_set_digest
currency
current_period_end
cancel_at
mode = at_period_end | immediate
invoice_now = false
prorate = false
pending_update_digest = absent
pending_invoice_items_digest
latest_invoice_digest
remaining_term_liability_minor
current_period_liability_minor
cancellation_reason_commitment
test_clock_id
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

The action cannot change prices, quantities, payment method, metadata, tax,
discounts, collection, invoice settings, or cancellation time independently
of the selected mode.

## 3. Evidence and bounded evaluation

Protected evidence binds the current Subscription, Customer and items,
status/period/cancel fields, latest Invoice/PaymentIntent, pending update and
invoice items, test clock, durable recurring-liability reservation, API
version/test mode, source, and observation time.

Eligibility requires exact proof/configuration equality, `cancel` and selected
mode allowed by the policy from specification 0021, permitted target/customer,
fresh exact state, matching liability reservation, no conflicting update or
cancellation, and the branch rules:

```text
at_period_end:
  current subscription remains active through current_period_end
  release only liability strictly after current_period_end

immediate:
  no pending update
  no unhandled pending invoice items
  invoice_now = false
  prorate = false
  release future liability only after terminal provider observation
```

Existing paid or payable invoices remain separately accounted. Cancellation
cannot manufacture budget by assuming credits or refunds.

Required/executed configuration follows specification 0021 and additionally
binds `auths.stripe.exact-subscription-cancel/1`, supported cancellation
branches, liability-release schema, API version, and hard invoice-item,
evidence, reservation, cycle, and work limits. Inequality denies before
decision persistence, release intent, credential access, or Stripe I/O.

## 4. Execution and reconciliation

```text
fresh subscription/invoice evidence -> exact proof
-> cancellation evaluator -> durable decision + release intent
-> exact claim -> acquire cancellation-only credential
-> fresh critical re-read
-> update cancel_at_period_end OR DELETE exact Subscription
-> persist provider result -> observe scheduled/terminal state
-> atomically release only proven-ended recurring liability
```

Scheduled cancellation commits the action but retains current-period capacity.
Terminal cancellation releases future recurring liability after observation.
A known pre-delivery failure leaves all liability unchanged. A timeout or
disconnect holds the release intent in `outcome-unknown` until Subscription and
Invoice evidence establish the result.

If a renewal or modification races cancellation, exact before-state mismatch
or provider conflict prevents an incorrect release. Recovery does not
resubmit blindly and never treats a missing active-list result as proof of
cancellation; it retrieves the exact Subscription including canceled objects.

## 5. Receipts and stable codes

Receipts include policy/evaluator identity, exact target/mode, before state,
invoice/pending commitments, liability retained/released, configuration
equality, credential/provider boundaries, Stripe request ID, scheduled and
terminal observations, test-clock events, reconciliation, and downstream
deprovisioning obligation.

Codes include:

- `subscription-cancel-authorized`;
- `subscription-cancel-mode-denied`;
- `subscription-cancel-before-state-mismatch`;
- `subscription-cancel-pending-update`;
- `subscription-cancel-pending-invoice-items`;
- `subscription-cancel-already-scheduled`;
- `subscription-cancel-already-terminal`;
- `subscription-cancel-renewal-conflict`;
- `subscription-cancel-outcome-unknown`; and
- shared bounded policy, evidence, configuration, claim, replay, and
  reconciliation codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Cancellation policy        | Exact cancellation         |
| Allowed modes              | Subscription / customer    |
| Liability release rules    | Now or period end          |
| Invoice safety constraints | Current period / invoices  |
+----------------------------+----------------------------+
| Decision | claim | credential | scheduled / terminal    |
+---------------------------------------------------------+
| Liability retained now -> released when observed ended  |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The UI explains whether service/billing ends now or later and whether any
invoice remains payable. It does not say “refunded.” Canonical policy/action/
evidence drive the copy; controls and result remain adjacent with
`auths-proof-site` styling.

## 7. Architecture and APIs

```text
Browser -> API -> subscription/invoice evidence -> exact verifier
        -> cancellation evaluator -> liability release-intent store
        -> verified cancellation -> credential broker -> Stripe
        -> subscription/invoice observer + test clock
```

Use the common subscription session, execute, reconcile, timeline, and receipt
routes. Repository-owned experiments cover period-end, immediate, pending
invoice, concurrent renewal, replay, and unknown outcome. Arbitrary target IDs
and deletion options are not accepted.

## 8. Verification and completion

Tests cover both modes, disallowed mode, target/customer/item mutation, stale
state, pending update/items, exact liability release, concurrent renewal/
modification/cancel, already scheduled/terminal, denial before credential,
disconnect before/after provider delivery, restart, test-clock period end,
terminal observation, reconciliation, and replay.

The live demo creates a bounded Stripe test-clock Subscription, schedules
period-end cancellation and advances to terminal state, then uses a separate
fixture for immediate safe cancellation. It proves invoices and liability are
reported accurately and replay creates no second effect. Browser E2E covers
both modes and receipt surfaces.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures/compliance mapping, secret/PII
scanning, and complete workspace/live/browser CI on the exact revision.

## 9. Acceptance and deferred work

Acceptance requires an exact cancellation, no hidden invoice/refund behavior,
liability release only after the relevant provider fact, denial before
credential acquisition, deterministic race handling, and restart-safe
reconciliation.

Deferred: custom cancel dates, invoice-now/proration branches, pending-item
deletion, refunds/credits, pause/resume, schedule termination, downstream
service deprovisioning executors, live mode, and generic recurring-cancellation
abstraction.

Provider references:

- [Cancel subscriptions](https://docs.stripe.com/billing/subscriptions/cancel)
- [Cancel a Subscription API](https://docs.stripe.com/api/subscriptions/cancel)
