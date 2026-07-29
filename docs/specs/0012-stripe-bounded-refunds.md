# 0012: Domain-local bounded Stripe refunds

Status: Implementing
Target: Stripe-local bounded-autonomy demonstration
Exact action profile: `auths.stripe.exact-refund/1`
Policy type: `auths.stripe.bounded-refund-policy/1`
Evaluator semantics: `auths.stripe.bounded-refund-evaluator/1`
Product package: `product/integrations/auths-stripe`
Demo: `demos/stripe-refund`

## 1. Decision

Add an immutable, versioned Stripe refund policy and deterministic evaluator
that allow an agent to select one exact Stripe refund inside configured
bounds. Preserve `auths.stripe.exact-refund/1` as the exact provider action and
the only shape from which the Stripe request is constructed.

This implementation remains local to `auths-stripe`. It does not add a generic
bounded-policy evaluator, reservation runtime, or Stripe domain logic under
`core/`. Similarities with the other five domains are recorded in section 23
for later extraction only.

The initial authority provenance is executor-local trusted configuration. The
policy is accurately described as an **immutable configured policy**. It is
not described as a human-signed standing delegation because Auths V1 does not
mechanically carry a human-authorized commitment to this policy digest and
evaluator semantic identifier.

## 2. Product distinction

This specification includes:

> Refund up to 100% of an existing purchase, subject to per-refund and
> aggregate constraints.

It does not include:

> Buy access to an external API with a $500 budget.

The latter creates a Stripe payment or purchase and has different merchant,
price, fulfillment, dispute, and recurring-payment semantics. It requires a
separate exact action profile and separate specification. It must not be
modeled as a refund.

## 3. Trust and authorization statement

The protected executor is configured with exact canonical policy bytes,
required evaluator/configuration commitments, Stripe test credentials, and a
durable state path. The untrusted agent can choose only the fields of an exact
refund action. The executor:

1. obtains fresh Stripe evidence;
2. verifies that the exact action opens to the Auths-authorized canonical
   `auths.stripe.exact-refund/1` bytes;
3. evaluates the exact action against the immutable configured policy;
4. durably records the decision and atomically reserves aggregate capacity;
5. durably claims the exact action;
6. acquires the restricted Stripe mutation credential;
7. submits only the verified exact action with deterministic idempotency; and
8. commits, releases, holds unknown capacity, or reconciles from Stripe state.

The policy digest in receipts proves which configured policy was enforced. It
does not prove who configured or approved that policy.

## 4. Closed policy schema

`StripeBoundedRefundPolicyV1` is a closed, `deny_unknown_fields` value with no
decode-time defaults:

```text
policy_type = "auths.stripe.bounded-refund-policy"
policy_version = 1
canonicalization = "rfc8785-sha256-v1"
evaluator_semantic_id = "auths.stripe.bounded-refund-evaluator"
evaluator_semantic_version = 1
policy_id
valid_from
expires_at
allowed_test_account_ids[]
allowed_currencies[]
allowed_reasons[]
allowed_charge_ids[]
allowed_payment_intent_ids[]
allowed_api_versions[]
connect_scope
maximum_evidence_age_seconds
per_refund_absolute_minor_by_currency{}
relative_limit {
  basis_points
  denominator
  rounding
}
aggregate_budgets[] {
  budget_id
  currency
  limit_minor
  window
}
```

Canonical policy identity is the tuple:

```text
(policy_type,
 policy_version,
 canonicalization,
 canonical policy digest,
 evaluator semantic ID,
 evaluator semantic version)
```

`policy_id` is a display and operational identifier only. It is never a
substitute for the canonical policy digest.

Collections are bounded, sorted, duplicate-free, and non-empty where required.
All monetary values are positive integer minor units within Stripe's signed
integer range. All time values are explicit Unix seconds.

## 5. Per-refund bounds

Every eligible refund satisfies both limits:

```text
amount <= absolute ceiling for action currency
amount <= round(denominator_minor * basis_points / 10_000)
```

The denominator is an explicit closed enum:

- `original-charge-amount`;
- `captured-amount`; or
- `remaining-refundable-amount`.

The initial evidence carries original, captured, already-refunded, and
remaining-refundable minor units separately. Missing or contradictory values
are invalid evidence and never become zero or unlimited.

Basis points are integers in `1..=10_000`. The initial rounding mode is
`floor-minor-unit`. Evaluation uses checked multiplication and division:

```text
numerator = denominator.checked_mul(basis_points)
relative_ceiling = numerator / 10_000
```

Overflow is `arithmetic-overflow`, not saturation or wrapping. The boundary is
inclusive. A computed zero ceiling cannot authorize a positive refund.

## 6. Aggregate budgets and windows

Each policy declares one or more currency-specific budgets. Every eligible
action produces one reservation intent for each applicable budget.

Fixed windows use explicit inclusive start and exclusive end:

```text
fixed { starts_at, ends_at }
```

Rolling windows use an explicit duration:

```text
rolling { duration_seconds }
```

For rolling V1, evaluation uses the continuous whole-second look-back interval
ending at explicit verifier time: `[now - duration_seconds + 1, now + 1)`.
Committed effects whose reservation time is in that interval contribute to
spent usage. Pending reservations and outcome-unknown records remain charged
even after the interval advances; they return capacity only through an explicit
release or reconciliation transition.

For every key:

```text
available = limit - committed - reserved - outcome_unknown
```

All subtraction and addition are checked. Capacity in `outcome-unknown` remains
held. Reconciled-committed contributes to spent; reconciled-released does not.

## 7. Stripe constraints

Eligibility requires exact equality or membership for:

- Stripe test account;
- lower-case currency;
- refund reason;
- Charge ID;
- PaymentIntent ID and its relationship to the Charge;
- `livemode = false`;
- pinned Stripe API version;
- Connect context;
- evidence source and age;
- policy validity; and
- executor audience and configuration commitments.

`ConnectScopeV1` distinguishes a platform/direct account from an explicitly
allowed connected account. Application-fee refunds and transfer reversal
remain false in the exact action. An absent Connect account is not equivalent
to an arbitrary connected account. A bounded exact action commits to
`auths_connect_account = platform | acct_…`; provider reads, reconciliation,
and mutation use that same Stripe account header context.

## 8. Required and executed configuration

`StripeBoundedEvaluatorConfigurationV1` commits to:

- policy digest;
- policy type/version and canonicalization;
- evaluator semantic ID/version;
- evaluator implementation/build ID;
- exact-action profile;
- reservation schema;
- receipt schema;
- executor audience; and
- maximum evaluator work and collection limits.

The request carries `required_configuration`; the service carries
`executed_configuration`. Canonical inequality is
`bounded-configuration-mismatch` before decision persistence, reservation,
credential access, or Stripe mutation. Receipts include both full
configurations, their digests, and the equality result.

## 9. Pure evaluator

The Stripe-local evaluator is total and performs no I/O:

```text
evaluate_bounded_refund(
  canonical_policy,
  exact_refund_action,
  canonical_stripe_evidence,
  aggregate_state_snapshot,
  explicit_now,
  required_configuration,
  executed_configuration
) ->
  Eligible {
    effective_absolute_ceiling_minor,
    effective_relative_ceiling_minor,
    effective_per_refund_ceiling_minor,
    denominator_minor,
    reservation_intents
  }
| Denied { stable_code, stage }
| Indeterminate { stable_code, stage }
```

The snapshot is advisory for explanation. Eligibility does not spend capacity.
The durable reserve operation repeats all capacity checks atomically.

## 10. Durable reservation lifecycle

The Stripe-local store represents:

```text
available -> reserved -> committed
                      \-> released
                      \-> outcome-unknown
                              \-> reconciled-committed
                              \-> reconciled-released
                      \-> reconciled-committed  (restart reconciliation)
                      \-> reconciled-released   (restart reconciliation)
```

The durable state record binds:

- reservation ID;
- exact action and workflow digests;
- policy and evaluator identity;
- evidence and configuration digests;
- Stripe account and currency;
- all budget/window keys and amounts;
- deterministic Stripe idempotency key commitment;
- current state and timestamps; and
- provider refund/result commitments when known.

Reservation and replay are atomic under one store lock/transaction. A replay of
the same action returns the existing reservation and result. The same workflow
or reservation key with different committed inputs is a conflict.

## 11. Concurrency, crash recovery, and persistence

The in-memory store provides process-local conformance. The persistent store
uses canonical bounded state, an exclusive process lock, write-to-temporary,
`sync_all`, atomic replacement, and parent-directory synchronization. Startup
rejects malformed, oversized, non-canonical, or invariant-breaking state.

Concurrent reservations cannot oversubscribe a budget. A crash after durable
reservation but before credential acquisition leaves a recoverable reserved
record. Because a crash may also happen during provider I/O before the next
state write, restart treats `reserved` as potentially ambiguous. Recovery
queries Stripe with the exact action and idempotency metadata before
transitioning to reconciled-committed or reconciled-released.

`outcome-unknown` likewise retains capacity until reconciliation.

## 12. Deterministic idempotency

The existing exact action derives its Stripe idempotency key from exact action
commitments. The bounded reservation additionally derives:

```text
reservation_id =
  sha256("auths.stripe.bounded-reservation/1" ||
         policy_digest ||
         action_digest ||
         aggregate_window_keys ||
         workflow_id)
```

Retries for one logical effect use the same exact action bytes, reservation ID,
Stripe parameters, and Stripe idempotency key. A parameter mismatch is a hard
conflict and security signal.

## 13. Effect ordering

```text
fresh Stripe evidence
  -> exact action + Auths proof verification
  -> pure bounded eligibility
  -> durable bounded decision receipt
  -> atomic aggregate reservation
  -> durable exact-action claim / execution intent
  -> acquire restricted Stripe refund credential
  -> re-read critical Stripe evidence
  -> POST exact refund with deterministic idempotency key
  -> persist provider receipt
  -> commit reservation
  -> observe or reconcile
```

No denied, indeterminate, unrecorded, unreserved, replay-conflicting, expired,
or configuration-mismatched request can acquire a mutation credential.

## 14. Ambiguous Stripe responses and reconciliation

If request delivery may have reached Stripe, or restart finds a reservation
whose provider-call boundary cannot be proven:

1. retain `reserved` after a crash or transition a caught ambiguity to
   `outcome-unknown`;
2. retain every aggregate amount;
3. persist the attempt and Stripe idempotency commitment;
4. query Stripe by known refund ID or fixed Auths metadata;
5. compare account, Charge, PaymentIntent, amount, currency, and exact
   idempotency/request commitments;
6. transition to `reconciled-committed`, `reconciled-released`, or remain
   `outcome-unknown`; and
7. never release capacity merely because a timeout or process restart
   occurred.

Known pre-delivery provider rejection transitions to `released`. Provider
acceptance transitions to `committed`.

## 15. Receipts

The receipt chain contains:

- immutable configured-policy identity and full public policy;
- policy provenance = `executor-local-trusted-configuration`;
- evaluator semantic and implementation identities;
- exact agent-selected refund and digest;
- fresh evidence, source commitment, age, and denominator;
- absolute, percentage, relative, effective, and aggregate calculations;
- aggregate available, reserved, spent, and outcome-unknown amounts before and
  after;
- required and executed configurations plus equality;
- Auths decision;
- durable reservation and exact-action claim transitions;
- credential-requested and provider-call booleans;
- each Stripe HTTP attempt and request ID;
- normalized Stripe refund result;
- reconciliation and later observation; and
- the explicit residual assumption that Stripe and the durable storage engine
  are externally observed/tested, not formally proved.

Secrets and raw credentials never appear.

## 16. Stable codes

The bounded layer adds:

- `bounded-authorized`;
- `bounded-policy-invalid`;
- `bounded-policy-digest-mismatch`;
- `bounded-evaluator-mismatch`;
- `bounded-configuration-mismatch`;
- `bounded-policy-not-yet-valid`;
- `bounded-policy-expired`;
- `bounded-account-denied`;
- `bounded-api-version-denied`;
- `bounded-test-mode-required`;
- `bounded-connect-context-denied`;
- `bounded-charge-denied`;
- `bounded-payment-intent-denied`;
- `bounded-currency-denied`;
- `bounded-reason-denied`;
- `bounded-evidence-stale`;
- `bounded-evidence-mismatch`;
- `bounded-absolute-limit-exceeded`;
- `bounded-relative-limit-exceeded`;
- `bounded-aggregate-budget-exceeded`;
- `bounded-arithmetic-overflow`;
- `bounded-reservation-unavailable`;
- `bounded-reservation-conflict`;
- `bounded-replay`;
- `bounded-execution-outcome-unknown`; and
- `bounded-reconciliation-required`.

Existing exact-refund codes remain accurate for the exact provider action.

## 17. UX

The workbench keeps policy, exact action, and live result side by side:

```text
+-----------------------------+-----------------------------+
| Immutable configured policy | Agent-selected exact refund |
| Digest / evaluator          | Charge + PaymentIntent      |
| Absolute: $20.00             | Amount: $10.00              |
| Relative: 100% original     | Reason / API / test mode    |
| Fixed budget: $50.00         | Evidence observed 3s ago    |
| Provenance: local config    | [Execute exact refund]      |
+-----------------------------+-----------------------------+
| Aggregate budget: available | reserved | spent | unknown |
+-----------------------------+-----------------------------+
| Required config = executed  | Credential | Stripe calls  |
+-----------------------------+-----------------------------+
| Decision / reservation / provider / reconciliation       |
+-----------------------------------------------------------+
| Inline canonical receipt JSON        [Designed receipt]   |
+-----------------------------------------------------------+
```

Experiments cover success, exact boundary, boundary plus one, denominator
change, stale evidence, exhausted aggregate budget, concurrent execution,
expired policy, configuration mismatch, replay, outcome unknown, and
reconciliation. Security-relevant copy is derived from the canonical policy
projection, not duplicated constants.

The UI says “immutable configured policy,” never “human-signed standing
delegation.” It also states that the agent has no Stripe key and that all
effects are Stripe test mode.

## 18. API

The existing demo routes remain and return a bounded schema:

```text
GET  /healthz
GET  /readyz
GET  /api/v1/scenario
POST /api/v1/sessions
GET  /api/v1/sessions/{session_id}
POST /api/v1/sessions/{session_id}/execute
POST /api/v1/sessions/{session_id}/reconcile
GET  /api/v1/receipts/{session_id}
GET  /receipts/{session_id}
```

The execute API accepts only a repository-owned experiment identifier. It does
not accept policy JSON, credentials, arbitrary Stripe URLs or headers, raw
form bodies, arbitrary metadata, or a provider idempotency key.

## 19. Canonical fixtures

Repository-owned fixtures cover canonical policy, evaluator configuration,
exact action, fresh evidence, aggregate snapshot, eligibility result,
reservation record, and receipt. Tests require:

- decode/validate/re-encode identity;
- exact SHA-256 manifest identity;
- unknown-field rejection;
- sorted/unique collection enforcement;
- arithmetic and boundary vectors;
- mutation of policy/action/evidence/configuration commitments; and
- stable decision code and stage.

## 20. Tests

Required product tests include:

- all three denominators;
- 1, 9,999, and 10,000 basis points;
- floor rounding and a one-minor-unit boundary;
- checked multiplication overflow;
- absolute-only failure and relative-only failure;
- fixed and rolling window identity;
- available/reserved/spent/unknown conservation;
- concurrent last-unit reservation;
- replay and conflict;
- restart from reserved, committed, released, and outcome-unknown;
- deterministic idempotency and reservation identity;
- configuration and evaluator mismatch;
- account, currency, reason, Charge, PaymentIntent, test-mode, API-version,
  Connect, freshness, and expiry denial;
- denial before credential acquisition;
- known rejection release;
- ambiguous response hold;
- reconciliation commit/release; and
- exact Stripe result equality.

Browser E2E starts at the rendered workbench and exercises session creation,
policy/exact-action display, one material denial, exact execution, replay,
budget transitions, inline receipts, and the designed receipt route through
the same public API paths.

Live contract tests use Stripe test mode and are separately gated by explicit
credentials. They create a fresh payment, issue an exact bounded refund,
verify the Refund object, retry with the same idempotency key, and reconcile an
ambiguous response without a second effect.

## 21. Compliance claims

Compliance records:

- exact provider action remains `auths.stripe.exact-refund/1`;
- bounded policy type/evaluator identities and canonical fixture suite;
- configured-policy provenance;
- pure containment and arithmetic tests;
- durable aggregate reservation/concurrency/restart tests;
- credential-before-reservation negative test;
- replay, unknown outcome, and reconciliation evidence;
- real Stripe test-mode effect evidence; and
- browser receipt/workbench evidence.

No claim says the policy is human-signed or that formal proof establishes
Stripe truth, filesystem durability, or network delivery.

## 22. Acceptance criteria

1. An agent selects one exact refund inside an immutable configured policy.
2. `auths.stripe.exact-refund/1` remains the exact Stripe provider action.
3. Absolute and basis-point limits with explicit denominators are enforced
   using checked integer arithmetic and explicit floor rounding.
4. Fixed and rolling aggregate budgets reserve atomically and durably.
5. The full reservation lifecycle, replay, concurrency, restart, unknown
   outcome, and reconciliation are observable and tested.
6. Account, currency, reason, Charge, PaymentIntent, test mode, API version,
   Connect, freshness, validity, and configuration constraints fail closed.
7. Policy/configuration/evaluator identities are canonical and visible.
8. No Stripe mutation credential is acquired before durable reservation.
9. The exact Stripe test-mode effect and provider response are recorded.
10. Canonical fixtures, compliance claims, browser E2E, inline JSON, and the
    designed receipt page pass.
11. No generic bounded evaluator/runtime or new Stripe logic appears in
    `core/`.
12. Purchase/payment budget semantics remain deferred to a separate spec.

## 23. Six-domain extraction notes

Record, but do not extract, these similarities:

| Candidate invariant | Stripe-local realization | Extraction caution |
| --- | --- | --- |
| immutable policy identity | canonical refund policy digest + evaluator ID | policy fields and tightening remain domain-specific |
| exact action after discretion | exact refund profile bytes | exact command payload differs per provider |
| fresh evidence | Charge/PaymentIntent normalization | evidence truth and freshness source are domain-specific |
| required/executed equality | bounded evaluator configuration | configuration schemas are not interchangeable |
| durable pre-credential reservation | refund budget store | reservation algebra and keys differ |
| deterministic retry | Stripe idempotency key | provider retention/equality contracts differ |
| outcome unknown | held refund capacity | reconciliation evidence differs |
| receipt stages | decision/reservation/execution/observation | domain receipts must not be flattened |
| adjacent UX projection | policy/action/budget/effect panels | canonical receipt remains domain-owned |

Stripe-specific concepts that must not leak into a shared abstraction include
minor currency units, basis points over payment evidence, Charge and
PaymentIntent relationships, Connect context, Stripe API versions, refund
reasons, Stripe idempotency, and Refund object reconciliation.
