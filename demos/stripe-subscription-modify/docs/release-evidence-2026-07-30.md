# 0022 release evidence · 2026-07-30

Status remains `specified`: the profile is implemented and exercised locally
against Stripe test mode, but no public Fly/Vercel deployment or genuinely
restricted subscription-modify key was authorized for this revision.

Real test-mode observations (redacted):

- source Subscription `sub_1TypegPbjgb2M2Te2uJdQhu5`;
- the exact retained Subscription Item changed from quantity 1 to quantity 2;
- recurring amount changed from 500 to 1,000 USD minor units;
- preview preserved separate 1,000 debit and 500 credit commitments;
- remaining-cycle count was 2 and incremental term liability was 1,000;
- update used `pending_if_incomplete`, `always_invoice`, and the committed
  proration date;
- Stripe returned no pending update and the exact after-item set;
- update Invoice `in_1TypelPbjgb2M2TejmVjQ6Ki` was paid for 500 net minor
  units;
- one credential request and two provider calls covered the critical re-read
  and single update;
- configuration denial used zero credentials and zero provider calls;
- durable replay used zero credentials and zero provider calls;
- lost-response reconciliation retrieved the Subscription without repeating
  the update;
- installed Chrome exercised denial, applied success, replay, inline canonical
  JSON, and the dedicated receipt page.

The local run used the developer-provided standard `sk_test_…` key. That is not
provider-side least-privilege evidence. No secret or client secret appears in
tracked artifacts, receipts, frontend data, or this evidence.
