# About the bounded Stripe cancellation demo

This application demonstrates `auths.stripe.exact-payment-cancel/1`: one exact
terminal cancellation of an eligible Stripe test-mode PaymentIntent for one
authorized reason. Session setup first establishes a repository-owned $10.00
manual-capture authorization. The protected profile cancels that PaymentIntent
and releases the full $10.00 hold only after a fresh Stripe observation proves
`canceled` with zero capturable and zero received.

Cancellation is not a refund. The profile cannot cancel a succeeded payment,
create a refund, capture funds, choose another Customer or PaymentIntent,
expire a Checkout Session, subscribe, transfer, or pay out.

The policy provenance shown by the application is
`executor-local-trusted-configuration`. Until Auths mechanically carries a
human-signed policy commitment, the application does not call this policy
human-signed standing authority.

The browser never receives a Stripe key or client secret, arbitrary provider
input, or an idempotency key. Public endpoints select only repository-owned
experiments.

`PaymentCancelCredential` is distinct from collection, authorization, capture,
and refund credentials at the Rust boundary. A restricted Stripe test key
should be used where Stripe supports the required PaymentIntent reads and
cancel mutation; a broader test key remains an explicit trusted assumption.

The action, evaluator, verified command, gateway, service, receipt family, and
transition relation are cancellation-owned. Canonical mechanics and the
durable merchant store are shared, but the store exposes cancellation-specific
methods and invokes the cancellation-owned transition function.
