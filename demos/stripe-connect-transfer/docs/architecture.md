# Architecture

The `connect::transfer` module owns its action, pure evaluator, verified
command, gateway, credential scope, receipt family, transition function, and
durable reservation store.

Evaluation checks immutable configuration before any credential access. An
eligible request atomically reserves source-relative, destination, platform
balance, and aggregate budget capacity. Only then may the
`stripe-connect-transfer-create` credential and closed provider gateway be
used. A fresh critical read is evaluated immediately before create. Known
failure releases reservations; unknown outcome and observations outside the
signed policy retain capacity until exact reconciliation.

The demo browser contains no Stripe credential. Its deterministic scenarios
expose boundary counters and canonical receipt-shaped output; production
adapters belong behind the server-side gateway.
