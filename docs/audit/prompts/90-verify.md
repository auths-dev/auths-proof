# Prompt: verify reported findings

Use after the area reviewers (01–07) report. Give one agent the findings from
one area, or a single P0 or P1 finding. Paste the shared preamble from
`00-how-to-use.md` first.

Input: the findings as reported, and the commit they were made against.

For each finding:
1. **Read the code yourself.** Follow the cited path end to end. Line numbers drift, so find code by symbol.
2. **Split it into factual claims.** Mark each one true, false, or partly true, with `path:line`.
3. **Check whether it is already decided.** Look in `docs/audit/settled.md`; `docs/PROGRAM_BOARD.md` §4 (decisions) and §5 (not doing); `docs/product/SELF_HOSTED_CLAIM_LEDGER.md`; the non-goals of the relevant spec in `docs/specs/`; `SECURITY.md`; and `core/spec/v1/`. If the behavior is documented, the finding is at most a claim-accuracy problem.
4. **Check who can trigger it.** A hostile proof or request, a caller misusing an API, an operator, or nobody? Search for the callers.
5. **Look nearby for a worse instance.** The same pattern often appears in a demo, a sibling crate, or another language's verifier.
6. **Check the proposed fix.** Does it respect AGENTS.md (clean cutover, no compatibility shims, lowest valid layer), the boundary plan in `docs/target-state/`, and every principal method? Keyless methods use a new key for each signature.

Output for each finding:
- **Verdict:** confirmed, partly confirmed, rejected, or documented limit.
- **Severity:** P0–P3 from the preamble, and one line on why it differs from the reviewer's rating, if it does.
- **Evidence:** `path:line @ <short sha>` for each claim you checked.
- **Missed:** what the reviewer missed.
- **Fix:** one to three sentences on the proposed fix.

Rejecting a finding needs evidence as strong as confirming one. Don't modify files.
