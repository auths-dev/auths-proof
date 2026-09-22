# Program board

The single live status surface for auths-proof. Every session and agent
reads this first. Update it in the same commit as the work it describes.
Program definition: [AP-SPEC-057](specs/0057-evidence-program-for-the-exact-action-boundary.md).
Independent baseline: [How revolutionary is Auths Proof, really?](research/competition/2026-09-21-how-revolutionary-is-auths-proof.md)
(scores 3 / 6 / 4).

## Rules

1. WIP limit: two epics in flight — one code, one evidence/docs.
2. Done = an artifact link (CI run, report, commit whose diff holds the
   evidence). A merged spec is not done.
3. Specs are written when an epic starts, not before. Backlog items get a
   paragraph here, no more.
4. Check-ins use the five-item shape in §6. One decision per check-in.
5. Commit titles: `prove`, `complete`, `independent` need the evidence in
   the diff (0057 §2).
6. No merge of PR #123 while any required check is red or while
   auths-field-lab pins a different SDK revision (0052 §5).
7. One branch and one draft PR per epic, branched from the current HEAD of
   `codex/self-hosted-developer-profiles` (Epic 1 stays on that branch and
   PR #123). Never merge, never force-push, never rewrite pushed history.
8. Unattended runs: decisions already in §4 are applied as written. A new
   decision takes the narrower reading (fail closed, smaller claim), is
   logged in §4 as `PROVISIONAL`, and work continues. A decision that would
   widen a claim or a credential scope is not taken; it is logged in §9 as
   a blocker and the agent moves to the next unblocked item.
9. Live provider calls only through the existing field-lab `run-demo.sh`
   against the same disposable Airtable/Todoist resources, at most five
   runs per epic, only for an epic step that names a live call. Everything
   else is mocked. No new credentials are created or requested.
10. Hosted CI is the gate. While CI runs, work the next item that does not
    touch the same files. Three consecutive failures of the same check with
    no new evidence = blocker in §9, move on.

## 1. In flight

| Epic | Owner | Status | Evidence so far | Next check-in decision |
| --- | --- | --- | --- | --- |
| 0057 Epic 1 — freeze on evidence | merged PR #123 | engineering merged to main; separate owner review and literal historical field-lab hosted gate remain unclaimed | [PR #123](https://github.com/auths-dev/auths-proof/pull/123) merged as `a82b8ca` after the owner accepted green auths-proof CI and explicitly waived field-lab CI for that merge. Local exact-wheel tests and earlier live provider read-backs were exercised; field-lab hosted green was not established. The [third-adapter report](product/SELF_HOSTED_THIRD_ADAPTER_TRIAL.md) remains an agent trial, not unfamiliar human adoption. | Preserve the narrower evidence wording; do not retroactively call field-lab hosted CI or owner review complete. |
| 0057 Epic 4 — publish the evidence | codex session on `codex/epic-4-evidence` | in progress; human trial open, draft PR #124 red on older base | [Manual exact-ref CI](https://github.com/auths-dev/auths-proof/actions/runs/35646269081) ran; authoritative failed only on the dated-review naming allowance missing from its older base. Corpus, wording, and GTM revisions are on [draft PR #124](https://github.com/auths-dev/auths-proof/pull/124); mapper acceptance and the unfamiliar-user trial remain not checked. | After Epic 1 closes, merge its green fix forward without rewriting history and recruit an unfamiliar trial participant. |
| 0057 Epic 2 — gateway + hostile proof | `codex/developer-profile-gateway` | in progress; live mechanical gateway path, still unqualified | [Draft PR #125](https://github.com/auths-dev/auths-proof/pull/125) contains three SDK-generated recipe fixtures, compiler, one-use claim store, native-verification coordinator, customer-operated service, and Python/TypeScript proof-action clients. Local packaged-wheel runs reached disposable Airtable and Todoist resources; the ledger records same-UID, testkit-trust, and causation limits without publishing private dashboard links. [TypeScript package run 35684760605](https://github.com/auths-dev/auths-proof/actions/runs/35684760605), [Python package run 35684760610](https://github.com/auths-dev/auths-proof/actions/runs/35684760610), and [distinct-UID isolation run 35684978515](https://github.com/auths-dev/auths-proof/actions/runs/35684978515) passed. A restart-with-stale-sockets hostile case is pending hosted verification; invalid trusted context refuses installation. | Obtain exact-tip hosted green and restart/competing-instance evidence; external adoption remains open. |

## 2. Queued — single-agent order, with gates

Order for one agent working alone. Each row's start gate must hold before
its first commit; its done gate is the only thing that moves it to §1
"done". Estimates are human-sized; an agent may finish faster, but the
gates do not shrink.

| # | Epic | Start gate | Done gate | Branch |
| --- | --- | --- | --- | --- |
| 1 | 0057 Epic 1 — freeze on evidence | none | PR #123 green on one commit; §D fixture identical in Python, TS, native; TS starter executes; field-lab pinned to that commit and green; the claim ledger explicitly corrects any historical title whose diff lacks its claimed evidence | `codex/self-hosted-developer-profiles` (PR #123) |
| 2 | 0057 Epic 4 — publish the evidence (steps 1, 3, 4 only) | Epic 1 pushed (may run while its CI runs) | corpus for GitHub + two vendor documents under `bindings/fixtures/openapi-corpus/` with rejection walls; every §6 wording row in 0057 corrected at its cited location; GTM doc rewritten per 0057 Epic 4 step 4. Step 2 (unfamiliar-user trial) needs a human or a zero-context agent in a separate task; if neither is available, log in §9 | `epic-4-evidence` |
| 3 | 0057 Epic 2 — gateway + hostile proof (053 Epics 1–4, plus step 5 reads) | PR #123 merged to main and owner explicitly authorized this work; historical field-lab hosted green remains unclaimed | hostile-application suite reports zero unauthorized provider entries across restart and competing instances on one documented isolated deployment; recipe compiler accepts Airtable/Todoist/GitHub without Auths edits; ledger updated with what the gateway guarantees and its deployment assumptions; live Airtable/Todoist through the gateway (rule 9) | `codex/developer-profile-gateway` |
| 4 | 0057 Epic 3 — signing under any principal method | Epic 1 done gate; AP-SPEC-058 written as the first commit of this epic | one verifier action accepts proofs chained to `sigstore-keyless` and `did:key` with no KERI code path; delegation commands ported; demo from three principal methods. The "twenty external repositories" clause needs humans and is logged in §9, not faked | `epic-3-signing` |
| 5 | 0057 Epic 5 — bounded policy in the path | Epic 2 hostile suite passing | per-principal cases added to the hostile suite (inside A's bound, outside A's bound, inside B's bound) with zero unauthorized entries; 0025 status line names implemented tranches | `epic-5-policy` |
| 6 | AP-SPEC-056 implementation | Epic 2 recipe AST committed and Epic 4 corpus published | both packaged CLIs pass the whole corpus; every derived recipe passes `recipe check` | `epic-6-derivation` |

## 3. Backlog — one paragraph each, no spec yet

- **059 Commitment-bound effect evidence.** Derive the provider idempotency
  key from the action commitment so provider-signed webhooks/receipts
  (Stripe, GitHub) become third-party evidence binding effect to
  authorization. Turns `unknown` into `observed-by-provider`. Needs the
  gateway. First of the three "closed loop" mechanisms; smallest.
- **060 Evidence-conditioned authority.** A grant may require a fresh,
  signed observation predicate (equality, range, freshness; closed and
  typed, never a policy language) as a precondition the verifier enforces.
  Makes `expected → replacement` verifier law. Chain step N on step N-1's
  signed outcome. Touches 0025's territory; keep predicates closed.
- **061 End-to-end machine-checked verifier.** Extend the Lean/Aeneas
  surface through canonical decoding and signature verification with
  verified crypto. Months. After 059/060.
- **Reads through the gateway.** Read recipes, response projection
  (`allowed_fields`, `maximum_response_bytes` as in 0024 §10), disclosure
  receipts. Confidentiality additionally needs hermetic agent egress.
  Folded into Epic 2 step 5.
- **Grant-constrained decoding.** Project the grant (enum variants, ranges,
  schema) into the model's structured-output grammar so the agent cannot
  emit an out-of-grant action. SDK helper, 2–3 wk, UX not security.
- **Reference-monitor theorem.** Formal statement that for any agent
  function, every effect is inside the grant or no effect occurs. The
  novelty-axis result. After 061.
- **053 extensions the vendor corpus will demand:** typed query segments,
  omit-when-null bodies. Decide from Epic 4's rejection walls, not before.

## 4. Decisions log

| Date | Decision | Where recorded |
| --- | --- | --- |
| 2026-09-20 | "No generic HTTP executor" → "no runtime-supplied URL/method/headers/body; declared digest-bound recipes are a different mechanism" | 0052 §1, 0024 §4/§29, `f3a5757` |
| 2026-09-21 | Enum is a schema node, not a grant-level restriction; "authorized" = valid proof for the exact action under supplied trust | 0055 §1, ledger |
| 2026-09-21 | 053: gateway-validated logical operation ID in operator namespace; header allowlist; observation-only read-back; transport entry durably excluded | 053 §3.1–3.3, `d6d5601` |
| 2026-09-21 | SDK `confirmed` ≠ lifecycle `Committed`; gateway records `response-recorded` / `unknown` / `observed`, never `confirmed` | abstraction case 0007, 053 |
| 2026-09-21 | Header-borne API keys IN scope for 053/056; query, cookie, basic OUT | 0056 §3.1/§3.3 (053 wording amendment pending) |
| 2026-09-21 | Multi-host claim reuses `PostgresLifecycleStore`; singleton-lock limit is a 038 finding, not a new spec | 0057 §5 |
| 2026-09-21 | GTM verb is "become the format incumbents emit and accept", not "unseat" | 0057 §1, GTM doc pending Epic 4 |
| 2026-09-21 | Identity default: Sigstore keyless / OIDC workload in CI, `did:key` local, WebAuthn/HSM roots; KERI available, never default | Epic 3 |
| 2026-09-21 | Reject noncanonical numeric tokens at the native canonical-wire boundary before typed projection: `1.0`, `1e0`, `-0`, leading zeros, and underscores are rejected as raw JSON; typed fields see only canonical integers. | 0057 Epic 1 adversarial fixture; owner confirmed |
| 2026-09-21 | AP-SPEC-056 `--closed` root spelling remains an unvalidated candidate; the mapper must reject an ambiguous `body` alias versus absolute JSON pointer rather than guessing. | Epic 4 corpus; owner confirmed |
| 2026-09-21 | The vendor corpus is a digest-pinned manifest with measured operation rejections, not committed multi-megabyte upstream bundles; mapper parity requires exact local source bytes. | Epic 4 corpus; owner confirmed |
| 2026-09-21 | Preserve pushed history for `9b31882`; resolve its overclaiming title with an explicit forward correction in the claim ledger, which becomes the Epic 1 title-audit gate. | AP-SPEC-057 §2; claim ledger |
| 2026-09-21 | For PR #123's engineering handoff, stop pursuing `auths-field-lab` CI: the billing annotation is confined to that repo, while exact `auths-proof` CI is green and the demos passed local exact-wheel tests and live read-back. This owner direction does not itself amend AP-SPEC-057 Epic 1's stricter hosted-demo acceptance. | Owner direction; 0051 §10 and acceptance review |
| 2026-09-22 | The owner merged PR #123 on green auths-proof CI, waived field-lab CI for that merge, and directed gateway work from updated main. This permits Epic 2 to start without relabeling the historical field-lab hosted gate as passed; owner review and unfamiliar-user evidence stay open. | Owner direction; merged `a82b8ca`; AP-SPEC-053 |

## 5. Not doing

| Proposal | Reason | Recorded |
| --- | --- | --- |
| Full spec for 059/060/061 now | Depends on the gateway existing; would be wrong within days | this board §3 |
| 0024 work | Implemented; amendment was wording only | 0057 §5 |
| Multi-host store spec | 0038 Epic 2 + `PostgresLifecycleStore` exist | 0057 §5 |
| Universal gateway, identity platform, unified API, standalone receipts | Refused by 0024 §4, 053 §7, GTM | 0057 §5 |
| Merging PR #123 red | 0052 §5 | rule 6 |

## 6. Check-in shape

Every agent report uses exactly this, under two screens, `file:line` for
every code claim, "not checked" where applicable:

1. GOAL READ-BACK — the epic's acceptance in its own words, and what it
   does not cover.
2. CODE CHECKS — what was verified, cited.
3. SPEC CLARITY — sentences it had to guess at, both readings, its pick.
4. CONFLICTS — with any committed spec, ADR, or this board.
5. PROPOSED NEXT STEP — one bounded piece of work, done criterion, size.

The reply to a check-in is one decision and an update to §1.

## 7. Baseline disposition

This board, AP-SPEC-057, and the independent review enter the branch together
as `docs: add program board, evidence program, and review baseline`. The
previous Epic 1 binding-semantics work is separately committed as `bda2b07`.

## 8. Run log

Unattended runs append to `docs/program-log/<date>-<label>.md`, one entry
per epic transition and per blocker, each with a commit hash or CI run URL.
The morning report is the last section of that file, in the §6 shape, plus
a table of every PR opened with its CI state.

## 9. Blockers needing an owner decision

| Logged | Epic / step | What was needed | What the agent did instead |
| --- | --- | --- | --- |
| 2026-09-21 — RESOLVED | Epic 1 CI | GitHub Actions jobs could not start while the repository was private and paid minutes were unavailable. | Repository is public again; exact-revision runs `35552487976`, `35552488044`, `35552488080`, and `35552488096` were rerun for real logs. |
| 2026-09-21 — RESOLVED | Epic 1 field-lab checkout | The earlier private-repository checkout appeared to require a read token. | Public `auths-proof` needs no checkout token. No credential was provisioned; field-lab commit `7ecea03` removed the workflow token input and pinned green SDK commit `da5f470`. |
| 2026-09-21 — RESOLVED | Epic 1 title audit | `9b31882` says “complete independent adapter adoption trial” but its diff contains conformance tooling, not the participant report. | Preserved history and added a forward correction to the claim ledger under the AP-SPEC-057 §2 evidence-in-the-diff rule. The independent trial remains an Epic 4 blocker. |
| 2026-09-21 — RESOLVED | Epic 1 authoritative naming | The dated independent competition review and dated GTM research memos intentionally retain historical `Auths Proof` headings; adding allowances causes expected semantic-freeze drift. | Added exact path-and-token allowances in `release/public-naming.toml`, advanced only `auths.release.public-surface` and the inventory freeze from 259 to 262 across two follow-ups, and regenerated the inventory; did not edit the independent review or GTM research or weaken the global stale-name rule. Hosted [authoritative CI passed](https://github.com/auths-dev/auths-proof/actions/runs/35650010786). |
| 2026-09-21 | Epic 1 field-lab hosted CI | The private `auths-field-lab` repository's Actions billing state rejected jobs before startup, despite the owner reporting it fixed. | Exact-pinned Airtable [run 35664008498](https://github.com/auths-dev/auths-field-lab/actions/runs/35664008498), Todoist [run 35664008485](https://github.com/auths-dev/auths-field-lab/actions/runs/35664008485), and Tier 0 [run 35664008506](https://github.com/auths-dev/auths-field-lab/actions/runs/35664008506) received the payment/spending-limit annotation. The owner directed no further field-lab CI checks for PR #123. Local exact-wheel mocked tests passed 12/12 and 10/10; earlier live write/read-back succeeded. AP-SPEC-052 Epic 4's engineering evidence is recorded in the acceptance review, while AP-SPEC-057's distinct hosted done gate remains open, not inferred from local evidence. |
| 2026-09-21 — RESOLVED | Epic 1 formal evidence aggregation | [CI attempt 1](https://github.com/auths-dev/auths-proof/actions/runs/35660161157/attempts/1) could not download a phase artifact after GitHub intermediary returned 403; failed-jobs-only attempt 2 incorrectly looked for successful phase artifacts under its new attempt number. | Commit `73e0f72` selects the latest non-expired bounded artifact from the same run at or before the current attempt; [exact CI](https://github.com/auths-dev/auths-proof/actions/runs/35663793124) passed formal evidence aggregation and the final qualification summary. |
| 2026-09-22 | Epic 1 formal evidence retry validator | [Docs-tip CI](https://github.com/auths-dev/auths-proof/actions/runs/35668410277) passed translation, Kani, and Lean, but formal evidence attempt 1 hit GitHub artifact-download 403 and attempt 2 rejected the selected attempt-1 result because the native aggregator still required the current attempt number. | The source-attempt fix is bounded to artifact selection and aggregation: require the selected artifact's exact attempt in its contents, same run/head/closures, and a positive attempt not later than the current retry; targeted local test and generated closure checks passed. Hosted exact-tip verification is pending. |
| 2026-09-21 | Epic 1 independent owner review | AP-SPEC-051's final metadata gate calls for a human read of the Python/TypeScript API inventories and claim metadata. | The implementation agent published a manual source-level read-through, explicitly not human approval. The owner plans separate fresh LLM sessions for independent review; their findings and owner acceptance are pending, and LLM output will not be mislabeled human approval. |
| 2026-09-21 | Epic 4 step 2 | An unfamiliar participant must perform the AP-SPEC-054 trial and provide a redacted report. | Did not simulate a participant; corpus and wording work remain on draft PR #124, but the trial clause is open. |
| 2026-09-21 | Epic 3 acceptance | Twenty external repositories and one organization enforcing signed-commit verification require real adopters. | Did not simulate adopters or start AP-SPEC-058 before Epic 1's done gate. |
