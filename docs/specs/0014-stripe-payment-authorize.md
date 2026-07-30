# 0014: Bounded Stripe payment authorization

Status: Proposed  
Exact action profile: `auths.stripe.exact-payment-authorize/1`  
Policy family: `auths.stripe.bounded-merchant-payment-policy/1`  
Evaluator: `auths.stripe.bounded-merchant-payment-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payment-authorize`

## 1. Decision

Add a profile that places one exact manual-capture authorization hold without
settling it. The executor creates and confirms a PaymentIntent with
`capture_method=manual` and accepts success only when fresh Stripe evidence
shows `requires_capture`.

An authorization consumes customer capacity and creates a time-bounded
obligation even though it is not captured revenue. It is therefore distinct
from immediate collection, capture, cancellation, and agent purchasing.

The profile uses the immutable bounded merchant-payment policy defined in
specification 0013. V1 is Stripe test mode, server-confirmed, and rejects flows
requiring further customer action.

## 2. Exact action and evidence

`StripeExactPaymentAuthorizeV1` commits to:

```text
profile = "auths.stripe.exact-payment-authorize/1"
stripe_account_id
connect_account
customer_id
payment_method_id
payment_method_type
order_scope
authorized_amount_minor
currency
capture_method = manual
confirmation_method = manual
off_session = false
error_on_requires_action = true
request_extended_authorization = false
request_incremental_authorization = false
statement_descriptor_commitment
fixed_metadata_commitment
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

Protected evidence binds account, Connect context, Customer, PaymentMethod
attachment/type, test mode, order uniqueness, API version, relevant merchant
capabilities, observation source/time, and existing PaymentIntents. Provider
observation after execution additionally binds PaymentIntent, latest Charge,
`amount_capturable`, `capture_before`, authorization status, and payment-method
details needed to interpret expiration.

Card data, client secrets, and reusable payment credentials never enter the
action, evidence, receipt, or browser.

## 3. Bounded semantics

Eligibility requires exact Auths coverage and required/executed configuration
equality plus the policy checks from specification 0013. The authorization
branch additionally checks:

- `authorize` is an allowed operation;
- requested amount is within per-authorization, customer, order, and aggregate
  hold ceilings;
- the order has no successful or ambiguous existing authorization;
- the payment method supports separate authorization and capture;
- the requested action lifetime fits the configured authorization policy; and
- no unsupported extended, delayed, incremental, or customer-action mode is
  requested.

The reservation is charged to an authorization-exposure budget, not collected
revenue. It remains held while the PaymentIntent is `requires_capture` or the
provider outcome is unknown. Later capture moves the applicable amount into a
settlement budget; cancellation or expiration releases the hold according to a
durable cross-profile transition.

Checked arithmetic and conservation apply across:

```text
available_hold
  = hold_limit - active_holds - outcome_unknown_holds
```

No clock-derived expiry releases capacity without fresh provider observation.

Required/executed configuration follows specification 0013 and additionally
binds `auths.stripe.exact-payment-authorize/1`, supported manual-capture payment
methods, hold-reservation schema, provider API version, and hard evidence/work
limits. Inequality denies before decision persistence, hold reservation,
credential access, or Stripe I/O.

## 4. Execution, obligations, and recovery

```text
fresh evidence -> exact proof -> bounded eligibility
-> durable decision -> reserve hold capacity -> exact claim
-> acquire restricted credential -> fresh critical re-read
-> create+confirm manual-capture PaymentIntent
-> persist provider result -> observe requires_capture/capture_before
```

The deterministic idempotency key binds the account, Connect context, policy,
action, workflow, and operation. `requires_capture` commits the authorization
reservation and creates typed obligations:

- capture or cancel before `capture_before`;
- do not capture more than `amount_capturable`;
- observe expiration, cancellation, or capture events; and
- keep the reservation until one terminal fact is durable.

A decline or definite pre-delivery failure releases capacity. `requires_action`
is a stable V1 denial. A timeout, disconnect, `processing`, missing Charge, or
contradictory amount is `outcome-unknown`; recovery retrieves the exact
PaymentIntent and does not create another.

## 5. Receipts and stable codes

Receipts show policy/evaluator identity, exact hold, evidence, all limits,
reservation lifecycle, credential/provider boundaries, Stripe request ID,
PaymentIntent and Charge commitments, `amount_capturable`, `capture_before`,
obligations, and later capture/cancel/expiry reconciliation.

Codes include:

- `payment-authorization-authorized`;
- `payment-authorization-limit-exceeded`;
- `payment-method-capture-unsupported`;
- `payment-authorization-window-too-short`;
- `payment-authorization-already-exists`;
- `payment-authorization-customer-action-required`;
- `payment-authorization-declined`;
- `payment-authorization-expired`;
- `payment-authorization-outcome-unknown`; and
- shared bounded configuration, evidence, reservation, replay, and arithmetic
  codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Authorization policy       | Exact hold                 |
| Per hold / customer        | Customer / order           |
| Aggregate active exposure  | Amount / payment method    |
| Minimum capture window     | Manual capture             |
+----------------------------+----------------------------+
| Decision | hold reserved | credential | Stripe request  |
+---------------------------------------------------------+
| Capturable amount | capture-before | current obligation |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The result never calls an authorization “paid.” It distinguishes requested,
held, capturable, captured, released, expired, and unknown amounts. Policy,
action, and result remain visible together in the `auths-proof-site` design
language.

## 7. Architecture and APIs

```text
Browser -> demo API -> exact Auths verifier -> bounded hold evaluator
        -> durable hold reservation/claim -> credential broker
        -> Stripe test PaymentIntent -> retrieval/webhook observer
```

The credential broker and provider gateway are both typed to
`PaymentAuthorizeCredentialScope`. The profile persists only its closed
`MerchantAuthorizationReceipt` family; authorization receipt additions do not
expand a shared cross-profile union or require collection consumers to change.

Use the session, execute, reconcile, machine receipt, and designed receipt
routes defined in specification 0013. Add:

```text
GET /api/v1/sessions/{id}/authorization
```

It returns the durable hold and observed provider status without credentials or
client secrets. The browser cannot capture or cancel under this profile.

## 8. Verification and completion

Canonical fixtures and tests cover exact boundary and boundary-plus-one,
unsupported payment method, stale evidence, duplicate order, configuration
mismatch, concurrent last-unit hold, decline, customer action, crash before and
after provider delivery, restart, observation, expiration, replay, and
cross-profile capture/cancel transitions.

The live Stripe test creates one exact manual-capture PaymentIntent, proves
`requires_capture`, `amount_capturable`, and `capture_before`, repeats the
workflow without another hold, then drives capture, cancellation, and
expiration fixtures separately. Browser E2E displays the live hold and receipt
routes.

Completion also requires Docker-local operation, a tested public frontend and
native API, redacted release evidence, canonical fixture/compliance
registration, secret scanning, and complete workspace/live/browser CI on the
same revision. Static HTML or a fixture-only backend is insufficient.

## 9. Acceptance and deferred work

Acceptance requires that the exact hold is created once; captured funds remain
zero; the durable exposure budget is conserved; every denial precedes
credentials; and ambiguous responses reconcile without another authorization.

Deferred: extended authorizations, incremental authorization, automatic
delayed capture, asynchronous payment methods, customer-interactive
authentication, multicapture, overcapture, and live mode.

Provider references:

- [Place a hold on a payment method](https://docs.stripe.com/payments/place-a-hold-on-a-payment-method)
- [PaymentIntent lifecycle](https://docs.stripe.com/payments/paymentintents/lifecycle)
