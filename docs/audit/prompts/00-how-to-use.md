# How to use these review prompts

Prompts `01`–`07` are standalone prompts, one reviewer agent each, with no prior context. Run them in parallel and paste the shared preamble below at the top of each. `90-verify.md` and `91-plan-work.md` run after them. `../README.md` describes a whole pass.

## Shared preamble (paste first)

> You are reviewing `auths-proof` (https://github.com/auths-dev/auths-proof) at commit `<sha>` as a senior staff engineer. Read the **code**; the README is known to be stale. Do not modify files.
>
> The project is proof-carrying authorization for AI agent actions:
> - a pure offline Rust verification kernel (`core/crates/*`);
> - a runtime, gateway and journal (`product/runtime/*`, `product/stores/*`);
> - provider integrations (`product/integrations/*`);
> - generated profiles (`xtask`, `product/sdk/auths-profile-kit`);
> - Python/TypeScript SDKs (`bindings/*`);
> - Go and TS independent verifiers;
> - Lean/Aeneas/Kani formal work (`formal/`).
>
> Before reporting, read `docs/audit/settled.md`. It lists findings already decided. Don't raise one again unless its "re-raise if" condition holds, and say which condition.
>
> Rules:
> - Cite `path:line @ <short sha>` for every claim.
> - Mark each finding **confirmed** (you read the code path end to end) or **suspected**.
> - For each finding, give a concrete failure scenario (inputs/state → wrong outcome), not just a code smell.
> - Separate real bugs from documented design limits. Those are recorded in `docs/audit/settled.md`, `docs/PROGRAM_BOARD.md` §4–§5, `docs/product/SELF_HOSTED_CLAIM_LEDGER.md`, the non-goals of each spec in `docs/specs/`, `SECURITY.md`, and `core/spec/v1/`. A documented limit is at most a claim-accuracy finding.
> - Give each finding a severity:
>   - **P0:** a hostile input or an unprivileged caller gets an action authorized that the spec denies, or a secret leaks.
>   - **P1:** a security guarantee or public claim fails under realistic conditions (misuse, a crash, concurrency), or code fails open.
>   - **P2:** code fails closed but needs manual recovery; a hardening gap; a spec or claim says more than the code does.
>   - **P3:** hygiene, docs, unreachable paths, or a breach of the repository's style rules.
> - Report at most 800 words: the 3 strongest things, then findings ranked by severity. Don't pad; "nothing found" is a valid answer.

## Method behind these prompts
1. **Start from the claims, not the code.** Write down what the project says it guarantees, then look for the exact line that enforces each claim.
2. **Classify every enforcement point** as *type* (impossible to misuse), *runtime check* (can be skipped by some path), or *convention* (docs, naming, TODOs). Most bugs are in the second and third kinds.
3. **Follow one guarantee across every boundary.** Guarantees are usually sound inside one crate and break at the seams between crates (e.g. the gateway echo vs the Stripe crate).
4. **Ask what the pure part cannot know.** Anything stateful (budgets, revocation, time, "already happened") has to live somewhere else; find where, and check it there.
5. **Size the code first** (`wc -l` per crate) so review effort goes where the weight is.
6. **Verify before believing a reviewer.** Every finding goes through `90-verify.md`. In the first pass, 13 of 22 reported findings needed correcting.
