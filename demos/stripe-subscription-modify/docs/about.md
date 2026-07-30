# Bounded subscription-modify demo

This native demo authorizes one exact before/after change to a repository-owned
Stripe test Subscription. V1 retains the Customer, Subscription Item identity,
currency, collection method, PaymentMethod/mandate, billing anchor, test clock,
and terminal `cancel_at`; only a fixed licensed Price and quantity may change.

The evaluator checks the positive proration debit and incremental remaining-term
liability independently. A Stripe credit is recorded as an observation and
never offsets either authorization ceiling.

The page keeps policy, before/after action, preview, result, and canonical
receipt together. It never returns Stripe credentials or client secrets.
