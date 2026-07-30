# 0020: Bounded Stripe payment mandates

Status: Proposed  
Exact action profile: `auths.stripe.exact-payment-mandate/1`  
Policy type: `auths.stripe.bounded-payment-mandate-policy/1`  
Evaluator: `auths.stripe.bounded-payment-mandate-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payment-mandate`

## 1. Decision

Add a profile for establishing one exact future-payment capability through a
Stripe SetupIntent. No money is charged by this action, but a successful setup
can enable later on-session or off-session charges. It is therefore a
capability-creation profile with explicit customer-consent evidence, not a
zero-dollar payment.

V1 uses Stripe test mode, one existing Customer, one protected test
PaymentMethod, explicit trusted-user consent, one usage mode, and a closed
future-use scope. A successful mandate does not authorize any later charge by
itself; every later collection or subscription still requires its own exact
profile, bounded policy, and link to this receipt.

Implementation remains Stripe-domain-local. Consent, capability-slot, and
future-action linkage are evidence for later abstraction; they must not be
collapsed into core authority or a generic payment runtime.

## 2. Consent and authority

The agent may request that a mandate be established, but cannot provide or
forge customer acceptance. A trusted human-facing consent surface or another
approved consent authority produces canonical `PaymentConsentEvidenceV1`
binding:

```text
customer
payment method commitment
merchant/account
usage = on_session | off_session
future amount type = fixed | maximum
future amount minor
currency
frequency/interval
reference
displayed terms digest
accepted_at
expires_at
consent principal and assurance
```

Consent evidence is distinct from the Auths standing agent policy. Both are
required. Test fixtures are labeled synthetic consent and never presented as
real cardholder consent.

## 3. Closed policy and exact action

`StripeBoundedPaymentMandatePolicyV1` contains:

```text
policy/evaluator identity
valid_from
expires_at
allowed_test_account_ids[]
allowed_customer_ids[]
allowed_payment_method_ids[]
allowed_payment_method_types[]
allowed_usage_modes[]
allowed_currencies[]
allowed_intervals[]
per_future_charge_minor_by_currency{}
maximum_active_mandates_per_customer
maximum_consent_age_seconds
maximum_evidence_age_seconds
maximum_action_lifetime_seconds
required_consent_assurance
allowed_api_versions[]
require_livemode = false
```

`StripeExactPaymentMandateV1` commits to:

```text
profile = "auths.stripe.exact-payment-mandate/1"
stripe_account_id
connect_account
customer_id
payment_method_id
payment_method_type
usage
mandate_amount_type
mandate_amount_minor
currency
interval
reference
consent_evidence_digest
displayed_terms_digest
on_behalf_of = optional exact account
return_url_commitment = optional trusted UI
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

The action contains identifiers/commitments only. Payment details, client
secret, and credentials are excluded.

## 4. Evidence and evaluation

Protected Stripe evidence binds account/Connect context, Customer,
PaymentMethod ownership and type, existing SetupIntents/mandates, active
mandate count, API version, test mode, and observation time. Trusted consent
evidence is evaluated independently.

Eligibility requires exact proof/configuration equality, allowed account,
customer, payment method, usage, amount, currency, interval, and Connect
context; valid unexpired consent with sufficient assurance; matching displayed
terms; active-mandate capacity; fresh Stripe evidence; and no duplicate or
ambiguous SetupIntent.

The durable reservation is a capability slot and exact mandate scope, not a
monetary spend. A future payment evaluator must prove:

```text
future exact action is inside mandate receipt scope
AND future exact action is inside its own current bounded policy
```

Neither side substitutes for the other.

Required/executed configuration commits to policy/evaluator and implementation
identity, exact profile, account/Connect and trusted-consent context, API
version, capability-store and receipt schemas, executor audience, and hard
byte, collection, consent, evidence, capability, and work limits. Inequality
denies before decision persistence, consent consumption, capability
reservation, credential/client flow, or Stripe I/O.

## 5. Execution and reconciliation

```text
trusted consent + fresh Stripe evidence -> exact Auths proof
-> mandate policy evaluation -> durable decision + capability reservation
-> exact claim -> broker SetupIntent credential/client flow
-> create+confirm exact SetupIntent
-> observe succeeded/requires_action/processing/failure
-> commit/release/hold capability slot
```

If customer action is required, only the trusted consent UI may receive the
minimum client-side material needed to complete Stripe's flow. The agent and
demo logs never receive the SetupIntent client secret. Server-side test
confirmation is permitted only for repository-owned synthetic methods.

A known failure releases the slot. Timeout, disconnect, `processing`, or
uncertain customer action holds it until SetupIntent retrieval and event
evidence establish success or failure. Recovery uses deterministic idempotency
and never creates a second SetupIntent blindly.

## 6. Receipts and stable codes

Receipts include policy/evaluator identity, redacted mandate scope, consent
principal/assurance and terms commitment, Stripe evidence, capability
reservation, configuration equality, credential/client-boundary booleans,
SetupIntent/SetupAttempt/Mandate commitments, status, and reconciliation.

Codes include:

- `payment-mandate-authorized`;
- `payment-mandate-consent-required`;
- `payment-mandate-consent-mismatch`;
- `payment-mandate-scope-exceeded`;
- `payment-mandate-capacity-exceeded`;
- `payment-mandate-customer-action-required`;
- `payment-mandate-provider-failed`;
- `payment-mandate-outcome-unknown`; and
- shared bounded policy, evidence, configuration, claim, and replay codes.

## 7. UX

```text
+----------------------------+----------------------------+
| Mandate policy             | Exact future-use authority |
| Customer / method types    | Customer / method commit.  |
| Usage / max / interval     | Terms and consent          |
| Active mandate limit       | on-session or off-session  |
+----------------------------+----------------------------+
| Auths decision | consent | capability slot | Stripe     |
+---------------------------------------------------------+
| No charge occurred; future charges need new Auths       |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The user explicitly approves synthetic test terms in the demo. Copy states
that no payment occurred and the agent cannot reuse the payment method outside
later bounded profiles. The UI follows `auths-proof-site`, keeps controls and
result adjacent, and uses the native backend.

## 8. Architecture and APIs

```text
Agent request ----+
                  v
Trusted consent UI -> consent evidence -> exact verifier/evaluator
                                      -> capability store/claim
                                      -> SetupIntent broker -> Stripe
                                                           -> observer
```

Use common session/execute/reconcile/receipt routes plus:

```text
POST /api/v1/sessions/{id}/consent
GET  /api/v1/sessions/{id}/setup-status
```

The consent endpoint requires an authenticated trusted-human session and exact
displayed-terms digest. It is not callable with agent authority alone.

## 9. Verification and completion

Tests cover missing/forged/stale consent, terms mutation, customer/payment-
method substitution, usage/amount/currency/interval boundaries, active
capability concurrency, duplicate setup, required/executed mismatch,
denial-before-credential, customer action, known failure, ambiguous response,
restart, reconciliation, and proof that later payments require both mandate
and payment authorization.

The live test creates and confirms one Stripe test SetupIntent, observes the
SetupIntent, SetupAttempt, PaymentMethod attachment, and Mandate where
applicable, then proves replay cannot create another capability. Browser E2E
covers consent, success, denial, no-charge explanation, and receipt surfaces.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures, compliance mapping, client-
secret scanning, and complete workspace/live/browser CI on the exact revision.

## 10. Acceptance and deferred work

Acceptance requires real, separately authenticated consent; exact future-use
scope; no immediate payment; one durable capability; no agent exposure to
payment credentials/client secrets; and reconciliation without duplicate
SetupIntents.

Deferred: bank microdeposit verification, revocation/detachment profile,
multi-use versus single-use provider differences, live SCA, dynamic payment
methods, cross-merchant mandates, live mode, and generic capability-delegation
abstraction.

Provider references:

- [SetupIntents](https://docs.stripe.com/api/setup_intents)
- [Confirm a SetupIntent](https://docs.stripe.com/api/setup_intents/confirm)
