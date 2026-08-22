# Auths recipes

These recipes cover the effect-free verification surface:

1. [Authenticate an identity](01_AUTHENTICATE_IDENTITY.md) without authority or approval setup.
2. [Verify existing authority](02_VERIFY_AUTHORITY.md) without gaining execution capability.

The displayed TypeScript and Python programs are generated from the
external-consumer sources in `bindings/recipes`. The installed-artifact runner
executes them against the packed root packages.

Effectful applications use the local agent and a generated profile client.
Start with the [production SDK quickstart](../PRODUCTION_SDK_QUICKSTART.md).
The removed caller-handler, remote-token, and staged-delegation recipes are not
compatibility examples for the AP-SPEC-040 relaunch.
