# Prompt: usability and the unfamiliar developer

Scope: `bindings/python`, `bindings/typescript`, `product/sdk`, `docs/product/*` quickstarts, `examples/`, `demos/`, gateway recipes, error registry (`product/errors`), CLIs (the packaged `auths` command and the `auths-node` binary).

Goal: act as a competent developer who has never seen this project. Try to get a real agent to issue one bounded Stripe refund, then add a new provider. Record every point where you would get stuck.

Do, and log time and friction for each step:
1. **Install.** From a clean clone, follow only the docs. Where are the docs wrong, stale or missing? Which commands fail?
2. **First success.** Follow `examples/stripe-refund-approval/README.md` with the Python SDK's `auths.gateway` client. How many concepts must you learn first (grant, principal method, trust context, recipe, connection, approval quorum)? Can you name each one's purpose after reading only the docs?
3. **First refusal.** Trigger a denial, such as an over-budget or expired grant. Is the error message actionable? Does it say *which* check failed and what to change? Compare the stable error codes with what the user actually sees.
4. **Adding a provider.**
   - Write a gateway recipe for a simple JSON REST API, using the example's `recipe.json` and `docs/specs/0053-declarative-credential-isolated-gateway.md`.
   - Count the files, lines and fields you must write.
   - Which mistakes does `auths-node gateway recipe check` catch, and which surface only at runtime?
   - Compare that with the application-owned adapter path (`docs/product/SELF_HOSTED_PROFILE_QUICKSTART.md`). When should a developer use which?
5. **API shape.**
   - Are the Python and TS SDKs idiomatic (async, typing, exceptions)?
   - Does the gateway client expose anything unsafe?
   - Are names consistent across the Rust, Python and TS APIs?
6. **Mental model.** Write the three-sentence explanation a developer needs before starting. Is it in the docs?

Output: a friction log (step → what happened → fix), then the top 5 changes that would most shorten time to first success.
