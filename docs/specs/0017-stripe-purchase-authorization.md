# 0017: Bounded Stripe Issuing purchase authorization

Status: Proposed  
Exact action profile: `auths.stripe.exact-purchase-authorization/1`  
Policy type: `auths.stripe.bounded-purchase-policy/1`  
Evaluator: `auths.stripe.bounded-purchase-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-purchase-authorization`

## 1. Decision

Add a Stripe Issuing profile that decides whether one exact incoming card
authorization is inside an agent's procurement policy. This is the first
profile that demonstrates:

> The agent may buy an external product or API access, from an allowed merchant
> and category, within a per-purchase and aggregate budget.

The exact provider event is initiated by the merchant/card network, not by the
agent calling Stripe. Auths consumes a verified
`issuing_authorization.request`, matches it to a durable agent procurement
intent where one exists, reserves capacity, and returns an approve or decline
decision within Stripe's real-time authorization deadline.

The profile does not collect merchant revenue, expose card details to the
agent, promise fulfillment, or treat a Stripe secret key as a buyer wallet.
V1 uses Stripe Issuing sandbox/test helpers and configures the provider timeout
fallback to decline.

Implementation remains Stripe-domain-local until the formal bounded-policy and
reservation extraction gates in specification 0011. The latency-sensitive
decision path may not create a weaker parallel evaluator merely to meet the
deadline.

## 2. Authority and consent model

Three principals remain distinct:

- the human or organization that configured the purchase policy;
- the agent that created a bounded procurement intent; and
- the external merchant/card network that produced the exact authorization.

The agent may propose merchant/product intent and later perform fulfillment
steps, but it cannot manufacture signed Stripe webhook evidence or approve its
own purchase. The exact action is built from protected webhook evidence.

Policy provenance is initially `executor-local-trusted-configuration`.
Procurement intent provenance and any human approval are separately committed.
The UI must not claim Auths proves that goods were delivered or that a merchant
description is truthful.

## 3. Closed purchase policy

`StripeBoundedPurchasePolicyV1` contains:

```text
policy_type = "auths.stripe.bounded-purchase-policy"
policy_version = 1
canonicalization = "rfc8785-sha256-v1"
evaluator_semantic_id = "auths.stripe.bounded-purchase-evaluator"
evaluator_semantic_version = 1
policy_id
valid_from
expires_at
allowed_test_account_ids[]
allowed_cardholder_ids[]
allowed_card_ids[]
allowed_currencies[]
allowed_merchant_ids[]
allowed_merchant_name_commitments[]
allowed_merchant_categories[]
blocked_merchant_categories[]
allowed_merchant_countries[]
blocked_merchant_countries[]
allowed_procurement_scopes[]
allowed_authorization_methods[]
allow_recurring = false
allow_cash_withdrawal = false
allow_wallet = false
allow_partial_approval = false
per_purchase_minor_by_currency{}
per_merchant_minor_by_currency{}
per_category_minor_by_currency{}
aggregate_budgets[] { budget_id, scope, currency, limit_minor, window }
maximum_intent_age_seconds
maximum_event_age_seconds
decision_deadline_milliseconds
capture_tolerance_policy
allowed_api_versions[]
required_timeout_fallback = decline
```

Allow and block sets have explicit precedence; V1 uses deny precedence.
Merchant names are explanatory evidence and cannot override merchant ID,
category, country, or procurement scope. Floating point, unbounded metadata,
regexes, and arbitrary expressions are prohibited.

## 4. Procurement intent and exact action

The optional `AgentProcurementIntentV1` commits to product/service scope,
expected merchant, maximum amount/currency, one-time versus recurring intent,
fulfillment reference, validity, nonce, and agent identity. It reserves no
money by itself unless a separately configured pre-reservation mode is used.

`StripeExactPurchaseAuthorizationV1` commits to:

```text
profile = "auths.stripe.exact-purchase-authorization/1"
stripe_account_id
event_id
issuing_authorization_id
cardholder_id
card_id
amount_minor
currency
merchant_amount_minor
merchant_currency
merchant_id
merchant_name_commitment
merchant_category
merchant_country
authorization_method
wallet
recurring
cashback_minor
is_amount_controllable
requested_approved_amount_minor
procurement_intent_digest = optional
stripe_api_version
webhook_payload_digest
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
received_at
```

V1 either approves the full amount or declines. Cashback, cash withdrawal,
partial approval, and recurring authorizations are denied.

## 5. Evidence, latency, and bounded evaluation

Protected evidence includes verified Stripe webhook signature/timestamp,
account and event identity, Issuing authorization fields, current card and
cardholder state, applicable Stripe spending controls, procurement intent,
aggregate store snapshot, API version, and explicit verifier time.

The hot path performs no discretionary external network calls. Card/cardholder
configuration and immutable policies are loaded before the event or from a
bounded local authoritative cache with explicit version and freshness.
Webhook signature verification, canonicalization, Auths proof verification,
policy evaluation, durable reservation, receipt intent, and response encoding
must fit the configured deadline. Timeout fails closed.

Eligibility requires every exact scope, method, merchant, category, country,
currency, amount, freshness, intent, configuration, and aggregate condition.
The durable store repeats capacity checks atomically before approval.

Required/executed configuration commits to policy/evaluator and implementation
identity, exact action profile, account, signed-webhook/API version, timeout
fallback, decision deadline, store/receipt schemas, executor audience, and
hard byte, collection, event, reservation, and work limits. Inequality declines
before decision persistence, reservation, or an approval response.

## 6. Lifecycle and reconciliation

```text
signed Stripe webhook -> normalize exact authorization
-> match procurement intent -> exact Auths verification
-> bounded evaluation -> durable decision + atomic reservation
-> direct approve/decline webhook response
-> observe authorization.created/updated
-> capture, void, expiry, refund, and transaction reconciliation
```

Approved capacity remains reserved while the authorization hold exists.
Capture commits actual captured amount; void or expiry releases it. Tips,
incremental authorizations, partial capture, FX changes, and late adjustments
are handled by the explicit V1 capture tolerance policy; unsupported changes
become `purchase-observation-outside-policy`, never silent budget expansion.

If the response may not have reached Stripe, capacity stays
`outcome-unknown` until a signed `issuing_authorization.created` event or
provider retrieval establishes the result. The executor must not issue a
second approval call; new integrations use the direct webhook response.

## 7. Receipts and stable codes

Receipts preserve webhook/event/action commitments, policy and procurement
intent, exact calculations, store transition, timing budget, response
commitment, later authorization/transaction evidence, and residual provider
assumptions. Card PAN, CVC, full merchant payloads containing sensitive data,
and credentials are absent.

Codes include:

- `purchase-authorized`;
- `purchase-declined`;
- `purchase-intent-mismatch`;
- `purchase-merchant-denied`;
- `purchase-category-denied`;
- `purchase-country-denied`;
- `purchase-currency-denied`;
- `purchase-amount-exceeded`;
- `purchase-aggregate-budget-exceeded`;
- `purchase-recurring-denied`;
- `purchase-cash-denied`;
- `purchase-decision-timeout`;
- `purchase-outcome-unknown`; and
- `purchase-observation-outside-policy`.

## 8. UX

```text
+----------------------------+----------------------------+
| Agent purchase policy      | Incoming purchase          |
| Merchant/category/country  | Merchant / category        |
| Per purchase / aggregate   | Requested amount           |
| One-time only              | Procurement intent match   |
+----------------------------+----------------------------+
| AUTHORIZED or DECLINED | decision latency | fallback    |
+---------------------------------------------------------+
| Reserved -> captured / voided / expired / unknown       |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The browser can create a bounded procurement intent and trigger a Stripe
Issuing test-helper authorization. It then displays the real signed-event
decision and subsequent provider state. Controls and result remain adjacent,
use the `auths-proof-site` design language, and never expose card secrets.

## 9. Architecture and APIs

```text
Agent -> procurement intent store
                     |
Stripe signed webhook v
        -> verifier/evaluator -> atomic budget store -> direct response
                    |                                  |
                    v                                  v
              receipt chain                 Stripe authorization state
                    ^                                  |
                    +---------- observer --------------+

Browser -> demo API -> Stripe test helper (test mode only)
```

Required routes include the common session/receipt routes plus:

```text
POST /api/v1/procurement-intents
POST /webhooks/stripe/issuing
GET  /api/v1/authorizations/{id}
```

The production webhook route authenticates Stripe and never trusts the browser
demo route. The test-helper credential is backend-only and unavailable outside
test mode.

## 10. Verification, deployment, and completion

Tests cover exact and boundary amounts, concurrent last-unit authorizations,
merchant/category/country precedence, unmatched and expired intents, malformed
or replayed signatures/events, webhook API-version mismatch, response deadline,
timeout fallback, duplicate delivery, approve/decline, void, expiry, capture
differences, unknown response, restart, and reconciliation.

The end-to-end demo uses Stripe Issuing test helpers, receives the signed
webhook, returns the real decision, and observes the resulting Authorization
and Transaction. Browser tests exercise success, denial, replay, unknown
outcome, inline receipt, designed receipt, and invalid receipt IDs.

Completion requires Docker-local operation and a publicly reachable webhook,
frontend, and native service tested against Stripe sandbox; redacted release
evidence; canonical fixtures; compliance mapping; timing histograms without
sensitive labels; secret scanning; and complete CI on the exact revision.

## 11. Acceptance and deferred work

Acceptance requires that an agent can operate inside a genuine merchant and
aggregate spending policy without Stripe/card credentials, while every exact
network authorization is independently verified, durably reserved, decided
within deadline, and reconciled to capture or release.

Deferred: partial approvals, cashback, ATM/cash, recurring purchases, dynamic
currency conversion, incremental authorizations, tips beyond a proven
tolerance policy, card provisioning, merchant/product attestation, fulfillment
proof, live Issuing, and provider-neutral procurement abstraction.

Provider references:

- [Issuing authorizations](https://docs.stripe.com/issuing/purchases/authorizations)
- [Real-time authorizations](https://docs.stripe.com/issuing/controls/real-time-authorizations)
- [Issuing spending controls](https://docs.stripe.com/issuing/controls/spending-controls)
