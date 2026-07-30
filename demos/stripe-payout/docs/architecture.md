# Architecture

`treasury::payout` owns its policy, action, evaluator, verified command,
payout-only credential scope, gateway, receipt family, lifecycle, and durable
store. Configuration inequality denies before approval consumption,
reservation, credential access, or Stripe I/O.

Eligibility atomically reserves outgoing balance, destination and aggregate
capacity, plus each exact approval commitment. A fresh balance/destination read
runs before create. Pending, paid, unknown, and failed-without-return states
hold capacity. Failed/canceled/reversed delivery releases it only after Stripe
evidence confirms funds returned to available balance.
