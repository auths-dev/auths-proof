# About the bounded Stripe capture demo

This application demonstrates
`auths.stripe.exact-payment-capture/1`: one exact, final Stripe test-mode
capture selected by an agent inside an immutable configured settlement policy.
Session setup first establishes a repository-owned $10.00 manual-capture
authorization. The protected profile may settle exactly $5.00 and atomically
release the full $10.00 authorization liability.

It cannot create or confirm a PaymentIntent, choose a Customer or card,
perform multicapture, add a fee or transfer, cancel an authorization, refund,
subscribe, transfer, or pay out. Those effects have separate authority,
provider preconditions, exposure, transitions, credentials, and receipts.

The policy provenance shown by the application is
`executor-local-trusted-configuration`. Until Auths mechanically carries a
human-captured policy commitment, the application does not call this policy
human-signed standing authority.

The browser never receives:

- a Stripe secret or PaymentIntent client secret;
- arbitrary provider URLs or headers;
- an idempotency key;
- raw PaymentMethod or card data; or
- a generic operation selector.

The typed `PaymentCaptureCredential` narrows the Rust boundary but does not
turn a broad Stripe secret key into provider-side least privilege. A restricted
test key should be used where Stripe supports the needed reads and capture
mutation; any broader fixture key remains a trusted setup-only assumption.

The action, evaluator, verified command, gateway, service, receipt family, and
transition relation remain capture-specific. Only canonical mechanics,
aggregate storage, and strict HTTP transport are shared.
