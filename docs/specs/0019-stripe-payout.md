# 0019: Bounded Stripe payouts

Status: Proposed  
Exact action profile: `auths.stripe.exact-payout/1`  
Policy type: `auths.stripe.bounded-payout-policy/1`  
Evaluator: `auths.stripe.bounded-payout-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payout`

## 1. Decision

Add a profile for one exact manual payout from a Stripe account balance to one
preconfigured external bank-account or debit-card destination. Payout is the
boundary where Stripe balance leaves Stripe. It therefore has stronger
destination, approval, and observation requirements than a Connect transfer.

V1 permits test mode, manual standard payouts, one destination, one currency,
and repository-owned synthetic accounts. Instant payout, automatic payout
configuration, cancellation, reversal, multi-currency conversion, and live
bank movement are deferred.

Implementation remains Stripe-domain-local. Destination, approval, bank-status,
and balance semantics must not be flattened into the Connect transfer policy or
a generic money-movement interface before the extraction gates.

## 2. Closed policy and action

`StripeBoundedPayoutPolicyV1` contains:

```text
policy identity and evaluator identity
valid_from
expires_at
allowed_test_account_ids[]
allowed_external_destination_ids[]
allowed_destination_type_commitments[]
allowed_currencies[]
allowed_source_types[]
allowed_business_scopes[]
allowed_methods[] = standard
per_payout_minor_by_currency{}
per_destination_minor_by_currency{}
aggregate_budgets[] { budget_id, scope, currency, limit_minor, window }
approval_thresholds[] {
  currency, amount_minor, required_assurance, required_approver_scope
}
minimum_available_balance_after_minor_by_currency{}
maximum_balance_evidence_age_seconds
maximum_destination_evidence_age_seconds
maximum_action_lifetime_seconds
allowed_api_versions[]
require_manual_payout = true
require_livemode = false
```

`StripeExactPayoutV1` commits to:

```text
profile = "auths.stripe.exact-payout/1"
stripe_account_id
destination_external_account_id
destination_type_commitment
business_scope
amount_minor
currency
method = standard
source_type
description_commitment
statement_descriptor_commitment
required_approval_commitments[]
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

The action never contains routing/account numbers, card numbers, credentials,
or an arbitrary destination. Destination IDs are resolved only inside the
protected executor.

## 3. Evidence and bounded evaluation

Protected evidence binds Stripe account/test mode, available and pending
balances by source type/currency, destination identity/status/fingerprint
commitments, payout schedule/manual capability, existing pending payouts,
approval assertions, API version, source, and observation time.

Eligibility requires exact proof/configuration equality, allowed account,
destination, type, scope, currency, method, and source; fresh balance and
destination evidence; amount within per-action/destination/aggregate ceilings;
required assurance/approvals; retained minimum balance; and no duplicate or
ambiguous payout.

All approval commitments are exact, scoped, unexpired, and distinct where a
threshold requires multiple principals. An agent cannot self-assert approval.

Required/executed configuration commits to policy/evaluator and implementation
identity, exact profile, account/source context, API version, approval,
reservation and receipt schemas, executor audience, and hard byte, collection,
evidence, approval, reservation, and work limits. Inequality denies before
decision persistence, approval consumption, reservation, credential access, or
Stripe I/O.

## 4. Reservation, execution, and reconciliation

```text
fresh balance/destination -> exact proof -> bounded evaluator
-> durable decision -> atomic outgoing-balance reservation
-> approval obligations -> exact claim
-> acquire payout-only credential -> fresh critical re-read
-> POST exact manual payout with deterministic idempotency
-> persist Payout -> observe pending/paid/failed/canceled/reversed
```

Creation commits budget when Stripe accepts the Payout because funds leave the
available balance even while delivery is pending. Known pre-delivery rejection
releases the reservation. Ambiguous delivery retains it. A later failed or
canceled payout transitions through explicit reconciliation; capacity is not
released until Stripe balance evidence confirms funds returned.

`paid` is provider observation, not proof the human owner recognizes the bank
credit. That external banking assumption is explicit in receipts.

## 5. Receipts and stable codes

Receipts include policy/evaluator identity, redacted destination commitment,
balance/source calculations, approvals, reservation, credential/provider
boundaries, Stripe request ID, Payout and balance-transaction commitments,
status history, reconciliation, and residual banking assumptions.

Codes include:

- `payout-authorized`;
- `payout-destination-denied`;
- `payout-destination-unavailable`;
- `payout-method-denied`;
- `payout-limit-exceeded`;
- `payout-minimum-balance-violated`;
- `payout-approval-required`;
- `payout-balance-insufficient`;
- `payout-pending`;
- `payout-failed`;
- `payout-outcome-unknown`; and
- shared bounded configuration, evidence, reservation, replay, and arithmetic
  codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Payout policy              | Exact payout               |
| Approved destinations      | Destination commitment     |
| Per payout / aggregate     | Amount / currency / source |
| Min retained / approvals   | Approval status            |
+----------------------------+----------------------------+
| Decision | reserve | credential | Stripe Payout status  |
+---------------------------------------------------------+
| Available before -> reserved -> available after         |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The UI emphasizes that test mode creates a real Stripe Payout object but does
not move real bank funds. Policy/action/result remain adjacent with canonical
copy and `auths-proof-site` styling.

## 7. Architecture and APIs

```text
Browser -> API -> exact verifier -> payout evaluator
        -> budget + approval store -> verified payout command
        -> payout-only credential broker -> Stripe sandbox
        -> Payout/balance observer
```

Use the common session/reconcile/receipt routes. Add a protected test-only
destination fixture endpoint during local setup; the public API never creates
or accepts arbitrary bank destinations.

## 8. Verification and completion

Tests cover destination substitution, stale/disabled destination, source/currency
change, exact/boundary-plus-one/minimum-balance calculations, approval
thresholds, concurrent payouts, pending capacity, duplicate/replay, denial
before credentials, provider rejection, timeout, restart, failed/canceled
return, and reconciliation.

The live Stripe test creates one manual test payout to a repository-owned test
destination, retrieves its Payout and balance transaction, and verifies no
duplicate on replay or ambiguous recovery. Browser E2E covers approval,
denial, pending state, inline JSON, designed receipt, and invalid IDs.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures, compliance mapping, secret/
destination-data scanning, and complete workspace/live/browser CI on the exact
revision.

## 9. Acceptance and deferred work

Acceptance requires exact destination binding, approvals where configured,
atomic outgoing capacity, one Payout object, observed balance impact, and
fail-closed recovery.

Deferred: instant and automatic payouts, payout cancellation/reversal, live
bank movement, multi-currency/FX, Treasury Financial Accounts, destination
onboarding, and provider-neutral treasury abstractions.

Provider references:

- [Create a Payout](https://docs.stripe.com/api/payouts/create)
- [Payout lifecycle endpoints](https://docs.stripe.com/api/payouts)
