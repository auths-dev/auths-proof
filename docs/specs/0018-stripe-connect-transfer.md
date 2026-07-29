# 0018: Bounded Stripe Connect transfers

Status: Proposed  
Exact action profile: `auths.stripe.exact-connect-transfer/1`  
Policy type: `auths.stripe.bounded-connect-transfer-policy/1`  
Evaluator: `auths.stripe.bounded-connect-transfer-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-connect-transfer`

## 1. Decision

Add a profile for one exact transfer from a platform Stripe balance to one
permitted connected account. A transfer is marketplace/platform funds
movement. It is not a customer charge, external purchase, payout to a bank, or
refund.

V1 permits a single destination and requires a successful source Charge through
`source_transaction`. Unfunded transfers, arbitrary transfer groups, multi-
destination splits, application-fee mutation, and transfer reversal are
deferred.

Implementation remains domain-local in `auths-stripe`; similarities with
refund, payout, OpenTofu, or PostgreSQL reservation flows are extraction
evidence, not permission to introduce a generic funds-movement runtime.

## 2. Closed policy and exact action

`StripeBoundedConnectTransferPolicyV1` contains immutable identity/version
fields plus:

```text
allowed_test_platform_account_ids[]
allowed_destination_connected_account_ids[]
allowed_source_charge_ids[]
allowed_transfer_groups[]
allowed_currencies[]
allowed_business_scopes[]
per_transfer_minor_by_currency{}
per_destination_minor_by_currency{}
per_source_charge_basis_points
aggregate_budgets[] { budget_id, scope, currency, limit_minor, window }
maximum_source_evidence_age_seconds
maximum_action_lifetime_seconds
allowed_api_versions[]
require_source_transaction = true
require_livemode = false
```

`StripeExactConnectTransferV1` commits to:

```text
profile = "auths.stripe.exact-connect-transfer/1"
platform_account_id
destination_connected_account_id
source_charge_id
source_payment_intent_id
transfer_group
business_scope
amount_minor
currency
description_commitment
fixed_metadata_commitment
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

Destination, source, currency, amount, group, account context, and metadata are
exact. The agent cannot supply Stripe headers, arbitrary descriptions,
idempotency keys, or provider URLs.

## 3. Evidence and evaluation

Protected evidence binds the platform and connected accounts, their test-mode
status and capabilities, source Charge and PaymentIntent, successful/available
funds state, amount/currency, prior transfers and reversals, platform available
balance, transfer-group relationship, API version, source, and observation
time.

Eligibility requires exact Auths coverage and configuration equality, allowed
platform/destination/source/group/scope, fresh successful source funds, matching
currency, sufficient source remainder and platform balance, all per-action and
aggregate ceilings, and no prior committed or ambiguous duplicate.

The relative ceiling is:

```text
source_ceiling =
  floor(source_charge_amount_minor * basis_points / 10_000)
available_source =
  source_ceiling - committed_transfers - reserved - outcome_unknown
```

Arithmetic is checked. Stripe's balance rejection is defense in depth, not the
Auths budget store.

Required/executed configuration commits to policy/evaluator and implementation
identity, exact profile, platform/Connect context, API version,
multi-budget/store and receipt schemas, executor audience, and hard byte,
collection, evidence, reservation, and work limits. Inequality denies before
decision persistence, reservation, credential access, or Stripe I/O.

## 4. Reservation, execution, and reconciliation

```text
fresh source/account evidence -> exact proof -> bounded evaluation
-> durable decision -> atomically reserve source + destination + aggregate
-> exact claim -> acquire restricted Connect transfer credential
-> fresh critical re-read -> POST exact Transfer with source_transaction
-> persist provider result -> retrieve Transfer and balance transaction
-> commit or retain/release reservations
```

All applicable budgets reserve atomically. A known validation or insufficient-
funds rejection before provider effect releases them. A timeout or disconnect
holds them in `outcome-unknown`. Recovery retrieves by known Transfer ID or
fixed Auths metadata and exact idempotency commitment; it never creates a
second transfer.

An asynchronous source payment that later fails does not silently release or
reverse the transfer. V1 requires successful source evidence and records any
later failure as an obligation requiring the separate reversal profile planned
for later work.

## 5. Receipts and stable codes

Receipts include policy/evaluator identity, source and destination
commitments, source-relative and aggregate calculations, reservation keys,
configuration equality, credential/provider boundaries, Stripe request ID,
Transfer and balance-transaction commitments, and reconciliation.

Codes include:

- `connect-transfer-authorized`;
- `connect-destination-denied`;
- `connect-source-charge-denied`;
- `connect-source-not-available`;
- `connect-transfer-group-mismatch`;
- `connect-transfer-limit-exceeded`;
- `connect-source-capacity-exceeded`;
- `connect-platform-balance-insufficient`;
- `connect-transfer-outcome-unknown`; and
- shared policy, evidence, configuration, reservation, replay, and arithmetic
  codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Marketplace transfer policy| Exact transfer             |
| Destinations / source rule | Source charge / destination|
| Per transfer / aggregate   | Amount / currency / group  |
| Source percentage ceiling  | Available source evidence  |
+----------------------------+----------------------------+
| Decision | reservations | credential | Stripe | observed |
+----------------------------------------------------------+
| Platform/source/destination capacity before and after    |
+----------------------------------------------------------+
| Inline canonical receipt JSON        [Designed receipt]  |
+----------------------------------------------------------+
```

The page calls the effect a connected-account transfer, never a payout. It uses
canonical policy explanations, adjacent controls/results, the
`auths-proof-site` visual language, and the native backend.

## 7. Architecture and APIs

```text
Browser -> API -> exact verifier -> Connect transfer evaluator
        -> multi-budget store -> verified command -> credential broker
        -> Stripe Connect sandbox -> Transfer/balance observer
```

Use the common session, execute, reconcile, and receipt routes from
specification 0013. The demo API offers repository-owned source/destination
fixtures and cannot accept arbitrary account or Charge IDs.

## 8. Verification and completion

Fixtures and tests cover destination/source/group/currency mutation, exact and
boundary-plus-one amounts, aggregate and per-source concurrency, insufficient
balance, stale/asynchronous source evidence, duplicate action, required/
executed mismatch, denial-before-credential, known failure, ambiguous response,
restart, reconciliation, and replay.

The live test creates or uses repository-owned Stripe test platform,
connected-account, Charge, and balance fixtures; creates one exact Transfer;
retrieves the Transfer and balance transaction; and proves replay/recovery
cannot duplicate it. Browser E2E covers both receipt interfaces and invalid
receipt IDs.

Completion requires Docker-local and tested public deployments, redacted
release evidence, canonical fixtures, compliance mapping, secret scanning, and
complete workspace/live/browser CI on the same revision.

## 9. Acceptance and deferred work

Acceptance requires one exact bounded transfer, atomic conservation across all
budget scopes, denial before credentials, observed provider equality, and
fail-closed ambiguous reconciliation.

Deferred: transfer reversals, multiple destinations, transfers without a source
transaction, asynchronous source-risk orchestration, application fees,
cross-border rules, funds segregation preview features, live mode, and generic
funds-movement abstraction.

Provider references:

- [Create a Transfer](https://docs.stripe.com/api/transfers/create)
- [Separate charges and transfers](https://docs.stripe.com/connect/separate-charges-and-transfers)
