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
| 0057 Epic 1 — freeze on evidence | codex session on `codex/self-hosted-developer-profiles` | in progress; CI externally blocked | `ea54a9d` CLI renamed to `auths-profile`, doctor wording qualified; `af39df0` inventories aligned; `3aeb18e`, `526b6d4` signed packed consumers + recovery; `9784fb1` CI disk fix; `bda2b07` binding-semantics fix; `f77f8f7` evidence baseline; `b89d754` shared adversarial fixture and test consumers; `89b1beb` parser fixes and generated-starter execution test. The [exact-revision rollup](https://github.com/auths-dev/auths-proof/actions/runs/35552488044) is red/skipped; the generated-artifacts job annotation confirms a billing pre-start failure, so fixture and starter acceptance are not checked. Open: exact-revision CI (steps 1–3), field-lab secret and pin/workflows (step 4), immutable overclaiming title `9b31882` (step 5). | Can Actions billing be restored so the exact revision produces test evidence? |
| 0057 Epic 4 — publish the evidence | codex session on `codex/epic-4-evidence` | in progress; human trial open; no automatic CI on stacked PR | [Draft PR #124](https://github.com/auths-dev/auths-proof/pull/124) is stacked on PR #123 from `89b1beb`; manual corpus has GitHub `issues/create`, Todoist task creation, and OpenAI vector-store creation with source digests and first-level rejection walls. The formal scope summary, self-hosted/read caveats, OIDC comparison, all five incumbent-response rows, and GTM strategic verb are corrected on this branch; the previous pushed-title defect is explicitly unresolved. No mapper or recipe check has run; PR #124 has no automatic checks because the CI workflows target PRs against `main`. Step 2 still needs an unfamiliar human participant. | Can the override sets be validated once 053/056 exist, and can a human trial run on the reviewed revision? |

## 2. Queued — single-agent order, with gates

Order for one agent working alone. Each row's start gate must hold before
its first commit; its done gate is the only thing that moves it to §1
"done". Estimates are human-sized; an agent may finish faster, but the
gates do not shrink.

| # | Epic | Start gate | Done gate | Branch |
| --- | --- | --- | --- | --- |
| 1 | 0057 Epic 1 — freeze on evidence | none | PR #123 green on one commit; §D fixture identical in Python, TS, native; TS starter executes; field-lab pinned to that commit and green; no overclaiming title on the branch | `codex/self-hosted-developer-profiles` (PR #123) |
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
| 2026-09-21 | GTM verb is "become the format incumbents emit and accept", not "unseat" | 0057 §1, Epic 4 GTM revision |
| 2026-09-21 | Identity default: Sigstore keyless / OIDC workload in CI, `did:key` local, WebAuthn/HSM roots; KERI available, never default | Epic 3 |
| 2026-09-21 PROVISIONAL | Integer token readings: either compare host-language parsed values (which loses `1.0`/`1e0` spelling in JS) or reject noncanonical numeric tokens at the native wire boundary before typed projection. Choose the latter: `1.0`, `1e0`, `-0`, leading zeros, and underscores are rejected as raw JSON; typed fields see only canonical integers. | 0057 Epic 1 adversarial fixture; owner to confirm |
| 2026-09-21 PROVISIONAL | AP-SPEC-056 `--closed` root path could mean a `body` alias or an absolute JSON pointer. The manual corpus writes `--closed body` only as a candidate; an implemented mapper must reject it until one spelling is specified and tested, rather than auto-closing the object. | Epic 4 corpus; owner to confirm |
| 2026-09-21 PROVISIONAL | Vendor corpus could commit entire multi-megabyte upstream bundles or commit a digest-pinned manifest with measured operation rejections. Choose the smaller manifest claim; AP-SPEC-056 implementation must obtain exact local source bytes before claiming mapper parity. | Epic 4 corpus; owner to confirm |

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
| 2026-09-21 | Epic 1 CI | GitHub Actions billing/spending limit restored; Python 3.11 macOS job was not started on [run 35552019150](https://github.com/auths-dev/auths-proof/actions/runs/35552019150). | Kept the result marked infrastructure-blocked; continued source work without claiming green. |
| 2026-09-21 | Epic 1 field-lab | A read-only `AUTHS_PROOF_READ_TOKEN` for private auths-proof checkout must be provisioned in auths-field-lab Actions secrets. | Did not create or expose a credential; left the demo workflows unqualified. |
| 2026-09-21 | Epic 1 title audit | `9b31882` says “complete independent adapter adoption trial” but its own diff lacks the participant report; the done gate demands no such title, while the hard limit forbids rewriting pushed history. | Preserved history, will publish an honest erratum/report if evidence exists, and leaves that done-gate clause open for owner resolution. |
| 2026-09-21 | Epic 4 step 2 | A human unfamiliar with the implementation must perform the AP-SPEC-054 trial and provide a redacted report. | Did not simulate a participant; continued the corpus and wording steps while the trial clause stays open. |
| 2026-09-21 | Epic 3 external adoption | Twenty external repositories and one organization's branch protection require human/organization participation. | Did not create repositories or claim adoption; preserved the acceptance clause as open. |
| 2026-09-21 | Epic 4 hosted CI | PR #124 targets the Epic 1 branch while automatic CI workflows target PRs against `main`; a manual exact-ref dispatch would still require restored Actions billing. | Left PR #124 draft and its CI state unqualified; did not retarget to `main` or claim green. |
