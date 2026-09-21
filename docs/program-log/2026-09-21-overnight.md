# Overnight program log — 2026-09-21

- 2026-09-21 01:46 UTC — Epic 1 start — `f77f8f7`: The board, AP-SPEC-057, and independent review baseline are committed before the adversarial fixture work.
- 2026-09-21 01:50 UTC — Epic 1 provisional decision — `f77f8f7`: Noncanonical integer spellings are rejected at the native wire boundary before either language projects a typed integer; the alternative host-value reading loses lexical information in JavaScript.
- 2026-09-21 01:55 UTC — Epic 1 CI blocker — https://github.com/auths-dev/auths-proof/actions/runs/35552019150: A Python 3.11 macOS job was not started because GitHub reports failed account payments or an exhausted Actions spending limit.
- 2026-09-21 01:55 UTC — Epic 1 field-lab blocker — `b89d754`: The cross-repository demo workflows need a read-only private-repository checkout secret that is not configured, so no credential was created or substituted.
- 2026-09-21 01:55 UTC — Epic 1 title-audit blocker — `9b31882`: Its pushed title claims an independent trial absent from that diff, and the no-history-rewrite rule prevents correcting the original commit.
- 2026-09-21 01:57 UTC — Epic 4 start — `89b1beb`: A separate evidence branch began after Epic 1 was pushed, with no gateway or signing implementation claimed.
- 2026-09-21 01:57 UTC — Epic 4 trial blocker — `89b1beb`: The unfamiliar-participant clause requires a human and will remain open while the corpus and wording work proceed.
- 2026-09-21 01:57 UTC — Epic 3 adoption blocker — `89b1beb`: Twenty external repositories and organizational branch protection require people and are not being simulated overnight.
- 2026-09-21 01:57 UTC — Epic 4 draft PR opened — https://github.com/auths-dev/auths-proof/pull/124: The evidence work is stacked on PR #123 and remains draft with its human trial gate open.
- 2026-09-21 02:05 UTC — Epic 4 corpus progress — https://github.com/auths-dev/auths-proof/pull/124: Three real vendor operations have digest-pinned manual rejection walls, while mapper acceptance and recipe compilation remain not checked.
- 2026-09-21 02:10 UTC — Epic 4 wording progress — `842c363`: Formal, read/write, OIDC, and incumbent-response wording is narrowed on the evidence branch without claiming a completed human trial or gateway.
- 2026-09-21 02:12 UTC — Epic 1 CI blocker confirmed — https://github.com/auths-dev/auths-proof/actions/runs/35552488044: The generated-artifacts check annotation says the job never started because of Actions billing, and the other latest-revision checks are red or skipped without test results.
- 2026-09-21 02:12 UTC — Epic 4 CI blocker — https://github.com/auths-dev/auths-proof/pull/124: The stacked draft PR has no checks because automatic workflows target `main`, so its exact ref remains unqualified while billing is unavailable.
- 2026-09-21 02:16 UTC — Stop threshold — `842c363`: Epic 1, Epic 4, and the queued Epic 3 each have an owner-dependent §9 blocker, so no gate was declared done and no PR was merged.

## Morning report

| PR | Branch / epic | CI state | Green | Red or unqualified, and why |
| --- | --- | --- | --- | --- |
| [#123](https://github.com/auths-dev/auths-proof/pull/123) | `codex/self-hosted-developer-profiles` / Epic 1 | Red/skipped at `89b1beb` | No exact-revision gate proven green | [Generated-artifacts annotation](https://github.com/auths-dev/auths-proof/actions/runs/35552488044/job/106189733424) says billing prevented job start; fixture and packed-starter results are not checked. |
| [#124](https://github.com/auths-dev/auths-proof/pull/124) | `codex/epic-4-evidence` / Epic 4 | No checks at `842c363` | No hosted gate proven green | Stacked PR targets the Epic 1 branch; automatic workflows target `main`. Manual dispatch awaits usable Actions billing. |

### Epic 1 — freeze on evidence

1. GOAL READ-BACK — Identical adversarial decisions and an executable packed starter on one green revision; not credential isolation or provider qualification.
2. CODE CHECKS — Shared cases are in [the fixture](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/bindings/fixtures/self-hosted-profile/adversarial-boundary-v1.json:17); the [Python parser](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/bindings/python/python/auths/_profile_cli.py:60) and [TypeScript parser](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/bindings/typescript/tools/profile-cli.mjs:20) reject extra separators/BOM; [native decoding](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/product/profiles/auths-profile-mcp/src/lib.rs:100) compares canonical bytes; the [packed starter test](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof/bindings/typescript/test/package/packed-profile-cli.test.js:145) executes generated code. Hosted outcomes for this revision: **not checked**; jobs did not supply test evidence.
3. SPEC CLARITY — Numeric spelling could be judged after host parsing or at canonical wire decoding; the provisional choice is the narrower wire rule.
4. CONFLICTS — Pushed `9b31882` claims a completed independent trial its diff lacks; the done gate forbids that claim while the no-rewrite rule preserves the commit.
5. PROPOSED NEXT STEP — Restore Actions billing and rerun exact-revision CI; done when `89b1beb` yields test logs, then triage each failure. About 15 minutes of agent work after billing is restored, excluding CI time.

### Epic 4 — publish the evidence

1. GOAL READ-BACK — Publish manual vendor rejection evidence and qualified claims; no mapper acceptance, live effect, or simulated unfamiliar-user trial.
2. CODE CHECKS — No runtime code changed. The [corpus](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-epic4/bindings/fixtures/openapi-corpus/cases.json:7) names three vendor operations and candidate overrides; [its limits](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-epic4/bindings/fixtures/openapi-corpus/README.md:3) say compiler/provider outcomes are **not checked**. The [formal scope](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-epic4/formal/README.md:38), [read caveat](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-epic4/docs/specs/0053-declarative-credential-isolated-gateway.md:41), and [incumbent response](/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-epic4/docs/research/gtm/2026-09-21-unseating-incumbents-by-authorization-unit.md:240) are narrowed.
3. SPEC CLARITY — `--closed` root could mean `body` or an absolute pointer; candidate only. Corpus could mean full vendor bundles or digest-pinned manual slices; the latter makes the smaller claim. Both remain provisional.
4. CONFLICTS — The unfamiliar-user report cannot be supplied by this session; 053/056 are unbuilt, so candidate overrides cannot be called compiled recipes. PR #124's stacked base has no automatic CI.
5. PROPOSED NEXT STEP — Have an unfamiliar participant run the 0054 trial on the reviewed revision and publish a redacted report; done only with their actual observations. Roughly two hours of participant time.

### §4 PROVISIONAL decisions for owner review

- Numeric tokens: host-language value comparison **or** canonical-wire rejection; chose canonical-wire rejection.
- `--closed` root: `body` alias **or** absolute JSON pointer; left `body` as an unvalidated candidate and requires the mapper to reject ambiguity.
- Vendor corpus: whole upstream bundles **or** digest-pinned manual manifest; chose the manifest and withheld mapper-parity claims.

### §9 blockers

- Actions billing/spending limit: restore it; meanwhile no exact-revision green claim or CI rerun on the blocked account.
- Field-lab private checkout secret and final SDK pin: provision read-only `AUTHS_PROOF_READ_TOKEN` and pin the eventual green commit; meanwhile no new credential and no claim its two workflows passed.
- Pushed-title contradiction: owner must resolve the `9b31882` done-gate conflict without history rewriting; meanwhile Epic 1 stays open.
- Epic 4 unfamiliar participant and Epic 3 twenty external repositories/branch protection: recruit real people/organizations; meanwhile neither result is simulated.
- PR #124 hosted gate: after billing recovery, dispatch CI on its exact ref or arrange an approved gate; meanwhile it remains draft and unqualified.

Start with restoring Actions billing, because Epic 1's exact-revision result gates the later code epics and the field-lab freeze pin.
