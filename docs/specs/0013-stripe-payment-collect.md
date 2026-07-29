# 0013: Bounded Stripe one-time payment collection

Status: Implemented
Exact action profile: `auths.stripe.exact-payment-collect/1`  
Policy family: `auths.stripe.bounded-merchant-payment-policy/1`  
Evaluator: `auths.stripe.bounded-merchant-payment-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payment-collect`

## 1. Decision

Add a closed Stripe-local profile for collecting one exact customer payment
with automatic capture. The protected executor creates and confirms one
PaymentIntent with `capture_method=automatic`; the agent never receives a
Stripe secret, PaymentIntent client secret, raw PaymentMethod data, or an
arbitrary Stripe request surface.

This is merchant-side collection. It is not agent procurement, a manual
authorization, capture of an existing hold, a subscription, a transfer, or a
payout. Those effects have separate profiles.

This specification owns the shared
`auths.stripe.bounded-merchant-payment-policy/1` schema used by specifications
0013 through 0016. The family has one closed semantic identity, but each exact
profile owns a separate typed evaluator entry point, verified command,
provider gateway, execution service, decision receipt, and lifecycle effect.
There is no generic executor or evaluator that accepts an operation tag and
branches at runtime. The policy family is not a generic payment language.

Implementation remains domain-local in `auths-stripe`. It may reuse proven
leaf primitives, but it must not introduce a generic bounded evaluator or
stateful runtime ahead of the extraction gates in specifications 0011 and the
Bounded Authorization Abstraction Plan. A later migration retains this
implementation as a decision, reservation, receipt, and effect-boundary oracle.

## 2. Product and trust statement

The initial policy provenance is `executor-local-trusted-configuration`.
Receipts prove which immutable policy and evaluator ran, not who approved that
policy. A later human-signed standing delegation must commit to the same policy
digest and evaluator identity before the UI may describe it as delegated human
authority.

The agent may select an exact customer, order, amount, currency, and permitted
payment-method reference inside the configured policy. It cannot select
credentials, API version, Connect headers, idempotency material, metadata
names, return URLs, webhook destinations, capture mode, or retry behavior.

## 3. Shared bounded merchant-payment policy

`StripeBoundedMerchantPaymentPolicyV1` is a closed
`deny_unknown_fields` structure with no decode-time defaults:

```text
policy_type = "auths.stripe.bounded-merchant-payment-policy"
policy_version = 1
canonicalization = "rfc8785-sha256-v1"
evaluator_semantic_id = "auths.stripe.bounded-merchant-payment-evaluator"
evaluator_semantic_version = 1
policy_id
valid_from
expires_at
allowed_operations[] =
  collect | authorize | capture | cancel
allowed_test_account_ids[]
allowed_connect_accounts[]
allowed_customer_ids[]
allowed_payment_method_ids[]
allowed_payment_method_types[]
allowed_currencies[]
allowed_order_scopes[]
allowed_cancellation_reasons[]
per_operation_absolute_minor_by_currency{}
per_customer_minor_by_currency{}
per_order_minor_by_currency{}
aggregate_budgets[] { budget_id, operation, currency, limit_minor, window }
maximum_authorization_age_seconds
minimum_capture_window_seconds
maximum_evidence_age_seconds
maximum_action_lifetime_seconds
allowed_api_versions[]
require_livemode = false
require_manual_confirmation = true
allow_customer_action = false
```

Collections are bounded, sorted, duplicate-free, and non-empty when required.
Money uses checked integer minor units. Windows, boundaries, missing values,
and rounding are explicit. V1 permits test mode only.

Operation-specific fields are conditional and fail closed. Every enabled
operation requires all and only its applicable constraints. In particular, a
collect-only policy requires collection money, customer, order, PaymentMethod,
window, and aggregate constraints; it requires
`maximum_authorization_age_seconds=0`,
`minimum_capture_window_seconds=0`, and an empty cancellation-reason set.
Missing applicable fields and populated irrelevant fields are both invalid.

Tightening means removing an operation or allowed identifier, reducing a
ceiling, shortening validity or freshness, or narrowing a window. For fixed
action, evidence, state, time, and configuration, tightening must not turn a
denial into eligibility or increase any reservation.

## 4. Exact action

`StripeExactPaymentCollectV1` commits to:

```text
profile = "auths.stripe.exact-payment-collect/1"
stripe_account_id
connect_account = platform | acct_...
customer_id
payment_method_id
payment_method_type
order_scope
amount_minor
currency
confirmation_method = manual
capture_method = automatic
off_session = false
error_on_requires_action = true
setup_future_usage = absent
application_fee = absent
transfer_data = absent
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

The provider request is constructed only from a
`VerifiedPaymentCollectCommand`. Its constructor is private to the completed
Auths, policy, reservation, and claim stages. The executor uses one
create-and-confirm request or an equivalent transactionally bound sequence; it
must not create an unconfirmed orphan and later fill fields from untrusted
input.

## 5. Evidence and containment

Protected evidence binds the Stripe account and Connect context, Customer,
PaymentMethod attachment and type, test-mode status, API version, prior
PaymentIntents for the order scope, consent/order commitment, observation time,
and evidence source. It contains identifiers and commitments rather than PAN,
bank details, client secrets, or reusable credentials.

Eligibility requires:

- exact required/executed configuration equality;
- a valid immutable policy and evaluator;
- an exact Auths proof opening to the canonical action;
- permitted account, customer, payment method, order, currency, and API
  version;
- amount within operation, customer, order, and aggregate ceilings;
- fresh, internally consistent evidence;
- no successful or ambiguous prior collection for the same order/action; and
- sufficient atomic aggregate capacity.

The pure evaluator returns `Eligible`, `Denied`, or `Indeterminate`. Eligibility
does not spend capacity. The durable store repeats aggregate checks atomically.

Required and executed configurations each commit to the policy/evaluator
identity, approved implementation build, exact action profile, Stripe account
and Connect context, API version, reservation/receipt schemas, executor
audience, and maximum bytes, collections, evidence objects, reservations, and
evaluator work. Any canonical inequality is
`bounded-configuration-mismatch` before decision persistence, reservation,
credential access, or Stripe I/O.

## 6. Execution and reconciliation

Ordering is:

```text
fresh evidence -> exact Auths verification -> bounded eligibility
-> durable decision receipt -> atomic aggregate reservation
-> exact-action claim -> acquire restricted Stripe credential
-> fresh critical re-read -> create+confirm with deterministic idempotency
-> persist provider result -> commit/hold/release reservation
-> retrieve PaymentIntent and latest Charge -> observation receipt
```

The deterministic idempotency key binds policy, action, workflow, account, and
Connect context. Reuse with different parameters is a conflict. Stripe's
provider idempotency retention is not the durable Auths replay store.

`succeeded` commits capacity. A known pre-delivery rejection releases it.
`requires_action` is denied in V1 because customer action is disabled. A
timeout, disconnect, `processing`, or uncertain response retains capacity in
`outcome-unknown` until retrieval and webhook evidence establish succeeded or
definite non-execution. Recovery never creates a second PaymentIntent.

## 7. Receipts and stable codes

Receipts include policy/evaluator identity, exact action, evidence age and
source, every bound calculation, aggregate before/reserved/after values,
required/executed configurations, claim and reservation transitions,
credential/provider booleans, Stripe request ID, PaymentIntent/Charge
commitments, reconciliation, and explicit residual assumptions.

Profile-specific codes include:

- `payment-collect-authorized`;
- `payment-collect-limit-exceeded`;
- `payment-customer-denied`;
- `payment-method-denied`;
- `payment-order-conflict`;
- `payment-customer-action-required`;
- `payment-processing`;
- `payment-provider-declined`;
- `payment-execution-outcome-unknown`;
- `payment-reconciliation-required`; and
- the Stripe-local merchant-policy evidence, configuration, reservation,
  replay, and arithmetic codes defined for this policy family. Merchant public
  schemas do not import refund action, evaluator, service, or receipt types
  from specification 0012.

## 8. UX

The workbench keeps policy, exact charge, and live result together:

```text
+----------------------------+----------------------------+
| Merchant collection policy | Exact customer payment     |
| Per payment / customer     | Customer / order           |
| Aggregate collected        | Amount / currency          |
| Allowed payment methods    | Payment method commitment  |
+----------------------------+----------------------------+
| Decision | reservation | credential | Stripe | observed |
+---------------------------------------------------------+
| Budget before / reserved / committed / unknown          |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

Copy states that the agent has no Stripe key and that the demo is test mode.
Policy explanations come from the canonical policy projection. The frontend
uses the `auths-proof-site` design language and works against the real native
backend, not a static `file://` page.

## 9. Architecture and APIs

```text
+---------+   +----------------+   +-----------------------+
| Browser |-->| Demo API       |-->| Auths exact verifier  |
+---------+   | no Stripe key  |   +-----------+-----------+
              +----------------+               |
                                               v
                                +---------------------------+
                                | bounded evaluator + store |
                                +-------------+-------------+
                                              |
                                              v
                                +---------------------------+
                                | verified command + broker |
                                +-------------+-------------+
                                              |
                                              v
                                +---------------------------+
                                | Stripe sandbox + observer |
                                +---------------------------+
```

Required routes:

```text
GET  /healthz
GET  /readyz
POST /api/v1/sessions
GET  /api/v1/sessions/{id}
POST /api/v1/sessions/{id}/execute
POST /api/v1/sessions/{id}/reconcile
GET  /api/v1/receipts/{id}
GET  /receipts/{id}
```

The execute body accepts a repository-owned experiment identifier, never raw
policy, arbitrary Stripe parameters, credentials, URLs, headers, metadata, or
idempotency keys.

## 10. Verification, deployment, and completion

Canonical fixtures cover policy, action, evidence, evaluator configuration,
aggregate state, eligibility, reservation, execution, observation, replay, and
every denial. Required tests include all arithmetic boundaries, concurrent
last-unit reservation, duplicate order scopes, changed payment method,
configuration mismatch, denial-before-credential, provider decline,
`requires_action`, `processing`, crash before/after request delivery, restart,
reconciliation, and exact provider equality.

The live test creates a fresh Stripe test Customer and PaymentMethod, performs
one exact collection, verifies the PaymentIntent and Charge, retries the same
workflow without a second charge, and reconciles an injected ambiguous
response. Browser E2E covers the control/result hero, denial, success, replay,
inline JSON, designed receipt page, and invalid receipt IDs.

Completion requires:

- Docker-local frontend and native backend with a real Stripe sandbox effect;
- public frontend and native API URLs tested end to end;
- redacted release evidence with source revision, deployment IDs, API version,
  provider request/observation commitments, region, and timestamp;
- canonical fixture and compliance registration;
- secret scanning proving no credential or client secret enters receipts,
  logs, artifacts, or frontend bundles; and
- formatting, architecture, MSRV, clippy, dependency, compliance, live
  contract, browser, and authoritative CI gates on the exact revision.

## 11. Acceptance and deferred work

The profile is accepted only when one exact bounded payment is collected once,
every denial stops before credential acquisition, ambiguous outcomes retain
capacity and reconcile without duplicate collection, and receipts distinguish
authorization from provider success and observation.

Deferred: customer-interactive SCA, asynchronous payment methods, automatic
payment-method selection, saved payment methods, Connect fees/transfers,
incremental authorization, multicapture, live mode, and generic payment
abstraction.

Provider references:

- [PaymentIntents](https://docs.stripe.com/api/payment_intents)
- [Confirm a PaymentIntent](https://docs.stripe.com/api/payment_intents/confirm)
- [Idempotent requests](https://docs.stripe.com/api/idempotent_requests)
