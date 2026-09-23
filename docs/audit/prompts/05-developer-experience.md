# Prompt: usability and the unfamiliar developer

Scope: `bindings/python`, `bindings/typescript`, `product/sdk`, `docs/product/*` quickstarts, `examples/`, `demos/`, `xtask` profile commands, error registry (`product/errors`), CLI (`auths` binary).

Goal: act as a competent developer who has never seen this project. Try to get a real agent to issue one bounded Stripe refund, then add a new provider. Record every point where you would get stuck.

Do, and log time and friction for each step:
1. **Install.** From a clean clone, follow only the docs. Where are the docs wrong, stale or missing? Which commands fail?
2. **First success.** Use the Python SDK's `connect()` and a typed call. How many concepts must you learn first (grant, principal method, trust context, connection, agent serve, workload mapping)? Can you name each one's purpose after reading only the docs?
3. **First refusal.** Trigger a denial, such as an over-budget or expired grant. Is the error message actionable? Does it say *which* check failed and what to change? Compare the stable error codes with what the user actually sees.
4. **Adding a provider.**
   - Follow `PROFILE_AUTHORING.md` for a simple JSON REST API.
   - Count the files, lines and TODOs you must write.
   - Which mistakes do the types catch, and which only qualification catches?
   - Compare that with the no-code gateway recipe path. When should a developer use which?
5. **API shape.**
   - Are the Python and TS SDKs idiomatic (async, typing, exceptions)?
   - Do the generated clients expose anything unsafe?
   - Are names consistent across the Rust, Python and TS APIs?
6. **Mental model.** Write the three-sentence explanation a developer needs before starting. Is it in the docs?

Output: a friction log (step → what happened → fix), then the top 5 changes that would most shorten time to first success.
