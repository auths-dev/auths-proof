# Auths recipes

Choose the smallest outcome that matches what you need:

1. [Authenticate an identity](01_AUTHENTICATE_IDENTITY.md) without authority or approval setup.
2. [Verify existing authority](02_VERIFY_AUTHORITY.md) without gaining execution capability.
3. [Execute one exact action](03_EXECUTE_ONE_ACTION.md) and verify its signed receipt.
4. [Delegate to an agent](04_DELEGATE_TO_AN_AGENT.md) with narrower, expiring authority.
5. [Run a cross-organization ordered plan](05_CROSS_ORGANIZATION_ORDERED_PLAN.md), restart after an ambiguous effect, and reconcile without duplicate provider entry.

The displayed TypeScript and Python programs are generated from the external-consumer sources in `bindings/recipes`. The installed-artifact runner executes every program, records wall-clock duration, checks each adversarial outcome, and verifies the recovered receipt from Recipe 5 in the other language.

Recipe 3's independent human-usability gate is recorded in `bindings/recipes/experience-evidence.json`. Automated success does not count as unfamiliar-developer evidence.
