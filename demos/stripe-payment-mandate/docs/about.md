# Bounded Stripe payment mandate demo

This native Rust demo establishes one future-payment capability with a Stripe
test-mode `SetupIntent`. It requires both an exact Auths proof and separate
trusted-human consent to the displayed synthetic terms.

No money is charged. A successful receipt constrains later use but never
authorizes a later collection or subscription on its own; that later action
must satisfy its own exact profile and current bounded policy.

The browser and machine APIs never receive a Stripe credential or
`SetupIntent.client_secret`.
