# 0016: Bounded Stripe payment cancellation

Status: Proposed  
Exact action profile: `auths.stripe.exact-payment-cancel/1`  
Policy family: `auths.stripe.bounded-merchant-payment-policy/1`  
Evaluator: `auths.stripe.bounded-merchant-payment-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payment-cancel`

## 1. Decision

Add a profile that cancels one exact eligible PaymentIntent for one permitted
reason. Cancellation is terminal for that PaymentIntent and can release an
existing manual-capture hold. It is not modeled as a refund and cannot target
a Checkout Session.

The bounded policy defined in specification 0013 controls which principals may
cancel which PaymentIntents, in which states, for which reasons, and whether an
associated Auths hold reservation may be released.

## 2. Exact action and evidence

`StripeExactPaymentCancelV1` commits to:

```text
profile = "auths.stripe.exact-payment-cancel/1"
stripe_account_id
connect_account
payment_intent_id
customer_id
order_scope
current_status
amount_minor
amount_capturable_minor
currency
cancellation_reason =
  duplicate | fraudulent | requested_by_customer | abandoned
authorization_action_digest = optional
authorization_reservation_id = optional
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

Protected evidence binds the complete target identity, account/Connect
context, current PaymentIntent status, Customer, order, amount, currency,
latest Charge, amount capturable, existing Auths reservation, cancellation
eligibility, API version, test mode, source, and observation time.

## 3. Bounded semantics

Eligibility requires exact proof and configuration equality, `cancel` in the
policy operation set, an allowed cancellation reason, permitted target scope,
fresh evidence, and a cancelable provider state. V1 permits:

```text
requires_payment_method
requires_capture
requires_confirmation
requires_action
```

`processing` is denied in V1 even where Stripe might sometimes permit it,
because provider- and payment-method-dependent cancellation windows are not yet
modeled. `succeeded` requires the refund profile, not cancellation.

For `requires_capture`, the evaluator emits a conditional hold-release
obligation bound to the existing authorization reservation. For other states,
the action uses an exclusivity claim but no monetary reservation. Capacity is
released only after fresh Stripe evidence proves `canceled` and the exact
remaining capturable amount has been released.

Required/executed configuration follows specification 0013 and additionally
binds `auths.stripe.exact-payment-cancel/1`, supported statuses/reasons,
conditional-release schema, API version, and hard evidence/work limits.
Inequality denies before decision persistence, claim/release intent,
credential access, or Stripe I/O.

## 4. Execution and recovery

```text
fresh target -> exact proof -> bounded cancellation decision
-> durable decision -> claim/conditional release intent
-> acquire restricted credential -> fresh target re-read
-> POST cancellation with exact reason and deterministic idempotency
-> persist result -> retrieve terminal PaymentIntent
-> release linked hold only after observation
```

A definite pre-delivery failure leaves the PaymentIntent and hold unchanged. A
timeout or disconnect retains the claim and hold in `outcome-unknown`.
Reconciliation retrieves the exact PaymentIntent and never assumes that a
cancel request failed merely because its response was lost.

If the target became captured before cancellation, recovery does not retry
cancellation or release capacity; it records a conflicting provider transition
and requires capture/refund reconciliation.

## 5. Receipts and stable codes

Receipts include policy/evaluator identity, exact reason and target, pre/post
provider commitments, linked authorization and hold, required/executed
configuration, credential/provider boundaries, Stripe request ID, release
decision, and conflicts.

Codes include:

- `payment-cancel-authorized`;
- `payment-cancel-state-ineligible`;
- `payment-cancel-reason-denied`;
- `payment-cancel-target-mismatch`;
- `payment-cancel-already-terminal`;
- `payment-cancel-capture-conflict`;
- `payment-cancel-outcome-unknown`; and
- shared policy, evidence, configuration, claim, replay, and reconciliation
  codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Cancellation policy        | Exact cancellation         |
| Allowed states / reasons   | PaymentIntent / order      |
| Target/customer scope      | Current status / reason    |
| Hold-release rules         | Capturable amount          |
+----------------------------+----------------------------+
| Decision | claim | credential | cancel | observed state |
+---------------------------------------------------------+
| Hold retained / released / outcome unknown              |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The page says what cancellation changes and what it does not. It never labels a
cancel as a refund. Policy/action/result remain adjacent, use canonical
explanations and `auths-proof-site` styling, and operate through the native
backend.

## 7. Architecture and APIs

```text
Browser -> API -> exact verifier -> cancellation evaluator
        -> durable claim/release intent -> credential broker
        -> Stripe cancel -> retrieval/webhook observation
        -> hold-store reconciliation
```

Use the common session and receipt routes from specification 0013. The execute
request accepts only a repository-owned cancellation experiment. Arbitrary
PaymentIntent IDs or cancellation reasons are not accepted by the public demo
endpoint.

## 8. Verification and completion

Fixtures and tests cover every allowed and forbidden status/reason, changed
target/customer/order/account, missing or mismatched hold, concurrent capture,
cancel, and replay, denial-before-credential, disconnect before and after
delivery, restart, canceled observation, capture conflict, and exact release
accounting.

The live test creates cancelable Stripe test PaymentIntents in the supported
states, cancels one exact target, observes `canceled`, proves a manual hold is
released, and shows replay cannot issue another cancellation. Browser E2E
covers success, denial, conflict, inline JSON, designed receipt, and invalid
receipt IDs.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures and compliance registration,
secret scanning, and complete workspace/live/browser CI on the exact revision.

## 9. Acceptance and deferred work

Acceptance requires one exact terminal cancellation, no mistaken refund
semantics, observed hold release, no credential on denial, and deterministic
reconciliation of response loss or capture races.

Deferred: Checkout Session expiration, `processing` cancellation,
payment-method-specific cancellation windows, refund orchestration,
subscription cancellation, live mode, and generic reversal abstractions.

Provider reference:

- [Cancel a PaymentIntent](https://docs.stripe.com/api/payment_intents/cancel)
