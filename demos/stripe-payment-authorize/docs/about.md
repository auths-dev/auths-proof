# About the bounded Stripe authorization demo

This application demonstrates
`auths.stripe.exact-payment-authorize/1`: one exact, manual-capture Stripe
test-mode authorization hold selected by an agent inside an immutable
configured merchant-payment policy.

It deliberately does not capture funds, call an authorization paid, refund,
purchase agent tooling, create a subscription, transfer, or pay out. Those
financial effects have different directionality, provider preconditions,
exposure, state transitions, reconciliation, and receipt meaning.

The policy provenance shown by the application is
`executor-local-trusted-configuration`. Until Auths mechanically carries a
human-authorized policy commitment, the application does not call this policy
human-signed standing authority.

The browser never receives:

- a Stripe secret or PaymentIntent client secret;
- arbitrary provider URLs or headers;
- an idempotency key;
- raw PaymentMethod or card data; or
- a generic operation selector.

The current implementation is an oracle for later six-domain extraction.
Similarities worth revisiting after all domain gates pass are canonical
configuration equality, exact-action claims, atomic capacity accounting,
append-only receipts, deterministic replay identity, credential gating, and
observation-driven reconciliation. The action, evaluator, verified command,
gateway, service, decision receipt, and lifecycle remain Stripe
authorization-specific.
