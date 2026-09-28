# Auths recipes

These recipes cover the effect-free verification surface:

1. [Authenticate an identity](01_AUTHENTICATE_IDENTITY.md) without authority or approval setup.
2. [Verify existing authority](02_VERIFY_AUTHORITY.md) without gaining execution capability.

The displayed TypeScript and Python programs are generated from the
external-consumer sources in `bindings/recipes`. The installed-artifact runner
executes them against the packed root packages.

Effectful applications either send provider writes through a gateway recipe,
which holds the credential, or keep the credential in an application-owned
adapter. Start with the
[Stripe refund example](../../../examples/stripe-refund-approval/README.md) or
the [application-owned adapter quickstart](../SELF_HOSTED_PROFILE_QUICKSTART.md).
The removed caller-handler, remote-token, and staged-delegation recipes are not
compatibility examples.
