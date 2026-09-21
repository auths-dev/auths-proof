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
| 0057 Epic 1 — freeze on evidence | codex session on `codex/self-hosted-developer-profiles` | independent engineering trial reported; final hosted CI and field-lab hosted CI open | Commit `da5f470` passed [CI](https://github.com/auths-dev/auths-proof/actions/runs/35650010786) and both package workflows. The acceptance corrections through `f5992ba` tighten conformance, diagnostics, and the bypass claim; AP-SPEC-055 is implemented without provider qualification. The public-surface [read-through](product/SELF_HOSTED_ACCEPTANCE_REVIEW.md) and [third-adapter trial report](product/SELF_HOSTED_THIRD_ADAPTER_TRIAL.md) are committed; the clean rerun on the hosted `f5992ba` wheel passed all fourteen mandatory cases and an exact local HTTP write/read-back. [Installed Python typing](https://github.com/auths-dev/auths-proof/actions/runs/35658997720/job/106530642333) found a nested generic class reusing outer `TypeVar`s, now moved to module scope pending hosted verification. [Repository preflight](https://github.com/auths-dev/auths-proof/actions/runs/35658997734/job/106530463732) identified semantic-freeze drift from those source/docs changes; only the binding and public-surface identities advanced in the bounded generated update. A TypeScript packed job received a GitHub artifact-service 403 before tests began. Field-lab PR #14 hosted jobs remain blocked before startup by the private-repo payment/spending-limit annotation. | Verify the typing correction and freeze snapshot on one final hosted SDK revision, then obtain runnable exact-pinned field-lab hosted jobs. |
| 0057 Epic 4 — publish the evidence | codex session on `codex/epic-4-evidence` | in progress; human trial open, draft PR #124 red on older base | [Manual exact-ref CI](https://github.com/auths-dev/auths-proof/actions/runs/35646269081) ran; authoritative failed only on the dated-review naming allowance missing from its older base. Corpus, wording, and GTM revisions are on [draft PR #124](https://github.com/auths-dev/auths-proof/pull/124); mapper acceptance and the unfamiliar-user trial remain not checked. | After Epic 1 closes, merge its green fix forward without rewriting history and recruit an unfamiliar trial participant. |

## 2. Queued — single-agent order, with gates

Order for one agent working alone. Each row's start gate must hold before
its first commit; its done gate is the only thing that moves it to §1
"done". Estimates are human-sized; an agent may finish faster, but the
gates do not shrink.

| # | Epic | Start gate | Done gate | Branch |
| --- | --- | --- | --- | --- |
| 1 | 0057 Epic 1 — freeze on evidence | none | PR #123 green on one commit; §D fixture identical in Python, TS, native; TS starter executes; field-lab pinned to that commit and green; the claim ledger explicitly corrects any historical title whose diff lacks its claimed evidence | `codex/self-hosted-developer-profiles` (PR #123) |
| 2 | 0057 Epic 4 — publish the evidence (steps 1, 3, 4 only) | Epic 1 pushed (may run while its CI runs) | corpus for GitHub + two vendor documents under `bindings/fixtures/openapi-corpus/` with rejection walls; every §6 wording row in 0057 corrected at its cited location; GTM doc rewritten per 0057 Epic 4 step 4. Step 2 (unfamiliar-user trial) needs a human or a zero-context agent in a separate task; if neither is available, log in §9 | `epic-4-evidence` |
| 3 | 0057 Epic 2 — gateway + hostile proof (053 Epics 1–4, plus step 5 reads) | Epic 1 done gate | hostile-application suite reports zero unauthorized provider entries across restart and competing instances on one documented isolated deployment; recipe compiler accepts Airtable/Todoist/GitHub without Auths edits; ledger updated with what the gateway guarantees and its deployment assumptions; live Airtable/Todoist through the gateway (rule 9) | `epic-2-gateway` |
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
| 2026-09-21 | Epic 1 field-lab hosted CI | The private `auths-field-lab` repository needs paid Actions minutes or a permitted visibility/billing change; the account refuses to start jobs. | Did not change repository visibility or billing. Airtable [run 35653685823](https://github.com/auths-dev/auths-field-lab/actions/runs/35653685823), Todoist [run 35653685841](https://github.com/auths-dev/auths-field-lab/actions/runs/35653685841), and Tier 0 [run 35653685769](https://github.com/auths-dev/auths-field-lab/actions/runs/35653685769) each ended in one second with the payment/spending-limit annotation; left Epic 1's done gate open. |
| 2026-09-21 | Epic 4 step 2 | An unfamiliar participant must perform the AP-SPEC-054 trial and provide a redacted report. | Did not simulate a participant; corpus and wording work remain on draft PR #124, but the trial clause is open. |
| 2026-09-21 | Epic 3 acceptance | Twenty external repositories and one organization enforcing signed-commit verification require real adopters. | Did not simulate adopters or start AP-SPEC-058 before Epic 1's done gate. |
