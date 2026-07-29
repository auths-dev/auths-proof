# 0015: Bounded Stripe payment capture

Status: Proposed  
Exact action profile: `auths.stripe.exact-payment-capture/1`  
Policy family: `auths.stripe.bounded-merchant-payment-policy/1`  
Evaluator: `auths.stripe.bounded-merchant-payment-evaluator/1`  
Product package: `product/integrations/auths-stripe`  
Demo: `demos/stripe-payment-capture`

## 1. Decision

Add a profile that captures one exact amount from an existing, exact,
manual-capture PaymentIntent. V1 requires `final_capture=true` and permits one
capture only. It does not create or confirm a new PaymentIntent, increase an
authorization, perform multicapture or overcapture, or choose another payment
method.

Capture is the settlement boundary. It is distinct from authorization because
it converts a temporary hold into collected funds and may release an
uncaptured remainder.

## 2. Exact action

`StripeExactPaymentCaptureV1` commits to:

```text
profile = "auths.stripe.exact-payment-capture/1"
stripe_account_id
connect_account
payment_intent_id
latest_charge_id
customer_id
order_scope
authorized_amount_minor
amount_capturable_before_minor
amount_to_capture_minor
currency
final_capture = true
application_fee_amount = absent
transfer_data = absent
statement_descriptor_commitment
fixed_metadata_commitment
authorization_action_digest
authorization_reservation_id
stripe_api_version
required_policy_digest
required_evaluator
required_configuration_digest
executor_audience
expires_at
nonce
```

The exact action links to the authorization receipt and reservation. A capture
cannot be independently redirected to a different Customer, account, Connect
context, currency, order, or Charge.

## 3. Evidence and policy evaluation

Fresh protected evidence includes the PaymentIntent and latest Charge
commitments, `requires_capture`, `amount_capturable`, amount already captured,
authorization expiration, Customer, currency, Connect context, API version,
test mode, disputes/refunds relevant to consistency, and the durable Auths hold
reservation.

Eligibility requires:

- exact proof and required/executed configuration equality;
- `capture` allowed by the policy from specification 0013;
- exact equality with the linked authorization identity;
- `requires_capture` and sufficient remaining capture window;
- `0 < amount_to_capture <= amount_capturable`;
- capture within per-operation, customer, order, and aggregate settlement
  ceilings;
- one active matching hold reservation;
- no committed, pending, or ambiguous prior capture; and
- no application fee, transfer, overcapture, or multicapture behavior.

The pure evaluator emits both a settlement reservation and a hold-release
obligation:

```text
reserve settlement = amount_to_capture
on committed final capture:
  commit settlement = amount_to_capture
  release active hold = amount_capturable_before
```

The store performs this cross-budget transition atomically. A process crash
cannot expose both released hold capacity and unaccounted settled funds.

Required/executed configuration follows specification 0013 and additionally
binds `auths.stripe.exact-payment-capture/1`, final-capture-only semantics,
cross-budget transition schema, API version, and hard evidence/work limits.
Inequality denies before decision persistence, settlement reservation,
credential access, or Stripe I/O.

## 4. Execution and reconciliation

```text
fresh PaymentIntent -> exact proof -> bounded capture decision
-> durable decision -> atomic settlement reservation
-> capture claim -> acquire restricted credential
-> re-read requires_capture/amount_capturable/capture_before
-> POST exact capture with deterministic idempotency
-> persist result -> retrieve PaymentIntent + Charge + balance transaction
-> atomically commit settlement and release hold
```

A known pre-delivery failure releases only the new settlement reservation; it
does not release the existing hold. A timeout or disconnect leaves both the
settlement reservation and hold charged until fresh Stripe observation proves
capture or non-execution. Recovery never sends a second capture blindly.

Partial final capture must prove the remaining authorization was released.
Provider status without matching amounts, Charge, currency, account, Connect
context, or idempotency metadata remains indeterminate.

## 5. Receipts and stable codes

Receipts include the linked authorization, pre-capture provider state, capture
limits and calculations, settlement/hold transition, credential/provider
boundaries, Stripe request ID, post-capture PaymentIntent/Charge/balance
commitments, and reconciliation.

Codes include:

- `payment-capture-authorized`;
- `payment-intent-not-capturable`;
- `payment-capture-amount-exceeded`;
- `payment-capture-window-expired`;
- `payment-authorization-link-mismatch`;
- `payment-capture-already-executed`;
- `payment-capture-provider-mismatch`;
- `payment-capture-outcome-unknown`; and
- shared policy, evidence, configuration, reservation, replay, and arithmetic
  codes.

## 6. UX

```text
+----------------------------+----------------------------+
| Capture policy             | Exact capture              |
| Settlement ceiling         | PaymentIntent / order      |
| Aggregate settled budget   | Held / capture / remainder |
| Minimum time remaining     | final_capture = true       |
+----------------------------+----------------------------+
| Decision | reserve | credential | capture | observation |
+---------------------------------------------------------+
| Hold before -> captured -> released remainder           |
+---------------------------------------------------------+
| Inline canonical receipt JSON       [Designed receipt]  |
+---------------------------------------------------------+
```

The frontend clearly distinguishes the prior authorization from the new
capture. It uses canonical policy explanations, the `auths-proof-site` design
language, and the real native backend.

## 7. Architecture and APIs

```text
authorization receipt + Stripe evidence
                 |
                 v
Browser -> API -> exact verifier -> capture evaluator
                 -> atomic cross-budget store -> verified capture
                 -> credential broker -> Stripe -> fresh observation
```

Use the common routes from specification 0013. Session creation must import or
create a repository-owned authorization fixture and expose its linked receipt.
The execute body accepts only a capture experiment identifier.

## 8. Verification and completion

Tests cover zero, exact boundary, boundary-plus-one, partial final capture,
changed PaymentIntent/Charge/Customer/currency, stale or expired hold,
insufficient capture window, already captured, concurrent capture, cross-budget
atomicity, denial-before-credential, provider decline, disconnect before and
during capture, restart, reconciliation, and replay.

The live test authorizes a Stripe test payment, captures the exact amount,
proves the Charge and balance transaction, verifies the remainder behavior,
and confirms that replay and ambiguous-response recovery produce no second
capture. Browser E2E covers policy/action/result adjacency and both receipt
interfaces.

Completion requires Docker-local and tested public end-to-end deployments,
redacted release evidence, canonical fixtures, compliance mapping, secret
scanning, and complete workspace/live/browser CI on the exact revision.

## 9. Acceptance and deferred work

Acceptance requires atomic movement from held exposure to settled collection,
one provider capture, exact provider observation, and fail-closed ambiguous
reconciliation.

Deferred: multicapture, overcapture, incremental authorization, Connect
application fees and transfers, asynchronous capture states, tips, live mode,
and provider-neutral settlement abstraction.

Provider reference:

- [Capture a PaymentIntent](https://docs.stripe.com/api/payment_intents/capture)
