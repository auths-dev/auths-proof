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
| 0057 Epic 2 — gateway + hostile proof | `codex/developer-profile-gateway` | done for the documented single-host development deployment; provider qualification and AP-SPEC-053 production-trust/adoption claims remain open | [Draft PR #125](https://github.com/auths-dev/auths-proof/pull/125) is green at `90973d64` in [exact-tip hosted CI](https://github.com/auths-dev/auths-proof/actions/runs/35690791146). Field-lab [commit `fbbeb58`](https://github.com/auths-dev/auths-field-lab/commit/fbbeb58) records the distinct-UID hostile run with three expected entries and zero unauthorized entries. Field-lab [commit `afa733b`](https://github.com/auths-dev/auths-field-lab/commit/afa733b) records fresh Airtable and Todoist writes through `--mode isolated`: both preflight isolation probes passed, Airtable returned `observed` with matching read-back, and Todoist returned `response-recorded` followed by independent task observation. The ledger limits this to the bound credentials, testkit trust, trusted Docker/host operator, and the single-host store. | Review the evidence and merge only on owner direction. The next newly unblocked evidence-program work is Epic 5; do not relabel this as provider qualification or production trust. |
| 0057 Epic 3 — signing under any principal method | merged in PR #129 (`9de31899`) | engineering implemented, steps 1–6; not accepted (two human clauses) | Hosted green on Linux and macOS through the Git signing protocol workflow for steps 1–4 (runs 35782280920, and later ones at `31b640b8`, `1f46f0db`, `6598e168`); step 6 [action self-test](https://github.com/auths-dev/auths-proof/actions/runs/35789962132) green. Step 5 acceptance test verifies `did:key`, OIDC-workload, and Sigstore-keyless under one root; the live OIDC job and full CI on the final tip are recorded in the PR. Public-good Sigstore and complete workload policies are closed in code; hosted live runs are recorded in the PR. Open: dogfooding this repository and the two human adoption clauses (§9). | Owner: decide root-key custody and branch protection for this repository. |
| 059 — commitment-bound provider evidence | merged in PR #130 (`4b53cd22`) | steps 1–4 implemented; step 5 (live Airtable through the isolated gateway) open | Local: `cargo test -p auths-gateway` (21 unit, 1 binary), Python and TypeScript gateway client tests, public-API inventories regenerated; hosted results recorded in the PR. The claim ledger states the claim and non-claim and that the live run is not done. | Operator: add a text field `auths_echo` to the disposable Airtable table, then run the isolated live journey with the updated field-lab recipe. |
| 060 — evidence-conditioned authority | merged in PR #133 (`1dc213de`); clients merged in PR #134 (`d9c41af6`); §15 on [draft PR #144](https://github.com/auths-dev/auths-proof/pull/144) | epic steps 1–4 implemented; §15 (SDK attach, Rust–Lean link) implemented, hosted CI pending; §16–§17 specified (K-of-N observer quorum over operator domains, per-extension attenuation) | #133 full CI green on `91864f96`; Rust, Go, and TypeScript agree on 148 vectors; Lean attenuation theorems registered. §15, local only: packed-wheel and packed-npm expected-before-replacement journeys pass against `auths-gateway-harness` (write authorized; changed value denied and stale observation indeterminate before any lease, in the SDK and at the gateway). 14 Lean refinement theorems link the 11 translated observation predicates to the model, and `cargo xtask formal` passes with 182 claims. SDK actions carry a bounded validity window (30 s by default, at most 300 s), so they verify at a later gateway clock. Readings are in 0060 §15.4. | §15: hosted CI green on #144 (queue item 8). §17 merged in PR #141; §16 is demand-gated (§3). Operator: live run. |
| 0057 Epic 5 — bounded policy in the path | `epic-5-policy` (step 1, draft PR #141); `epic-5-bounds` (step 2) | in progress: step 1 (0060 §17) and step 2 (0025 §24) on draft PRs | Step 1: handler-declared per-extension attenuation laws, 163 corpus vectors on which Rust, Go, and TypeScript agree, re-qualified kernel translation, and Lean theorems that delegation never widens authority given narrowing laws. Step 2: the `bounded-policy-commitment-v1` extension and link law (registry manifest `36`, 173 vectors in parity); a closed gateway evaluator registry; one argument-ceiling window-count evaluator with insert-once count slots in the attempt store; Lean proofs of fixed-context tightening and decider soundness, recorded as the product-layer premise; and the per-principal hostile suite (`bindings/fixtures/gateway/bounds-hostile.json`), whose refused cases have zero provider entries and zero leases. Local checks only; hosted CI pending on both draft PRs. | Review step 1, then step 2, which must merge after it. |
| AP-SPEC-056 Epics 1–2 — OpenAPI derivation | merged in [PR #136](https://github.com/auths-dev/auths-proof/pull/136) (`24e1df15`) | Epics 1–2 implemented; Epic 3 (a MAY) not started, reasons in 0056 §8.3 | Local only: `cargo test -p auths-openapi-derive` (87-case corpus, with the pinned vendor documents present), the Python suite on a built extension, TypeScript unit, integration, and package tests on a local WASM build, a clean CPython 3.9 wheel consumer, and `auths gateway recipe check` on derived recipes. Derivation ships as its own WASM module so the runtime verifier bundle keeps its size. Vendor cases do not run in hosted CI. Hosted CI green on #136. | Owner: review the PROVISIONAL readings in §4. |

## 2. Queued — single-agent order, with gates

Order for one agent working alone. Each row's start gate must hold before
its first commit; its done gate is the only thing that moves it to §1
"done". Estimates are human-sized; an agent may finish faster, but the
gates do not shrink.

| # | Epic | Start gate | Done gate | Branch |
| --- | --- | --- | --- | --- |
| 1 | 0057 Epic 1 — freeze on evidence | none | PR #123 green on one commit; §D fixture identical in Python, TS, native; TS starter executes; field-lab pinned to that commit and green; the claim ledger explicitly corrects any historical title whose diff lacks its claimed evidence | `codex/self-hosted-developer-profiles` (PR #123) |
| 2 | 0057 Epic 4 — publish the evidence (steps 1, 3, 4 only) | Epic 1 pushed (may run while its CI runs) | corpus for GitHub + two vendor documents under `bindings/fixtures/openapi-corpus/` with rejection walls; every §6 wording row in 0057 corrected at its cited location; GTM doc rewritten per 0057 Epic 4 step 4. Step 2 (unfamiliar-user trial) needs a human or a zero-context agent in a separate task; if neither is available, log in §9 | `epic-4-evidence` |
| 4 | 0057 Epic 3 — signing under any principal method | Epic 1 done gate; AP-SPEC-058 written as the first commit of this epic | one verifier action accepts proofs chained to `sigstore-keyless` and `did:key` with no KERI code path; delegation commands ported; demo from three principal methods. The "twenty external repositories" clause needs humans and is logged in §9, not faked | `epic-3-signing` |
| 5 | **In progress (current branch).** 0057 Epic 5 — bounded policy in the path. Step 1: AP-SPEC-060 §17 per-extension attenuation. Steps 2–3: AP-SPEC-025 §24 tranches 4–6 and the five hostile-suite cases of §24.4 | Epic 2 hostile suite passing | per-principal cases added to the hostile suite (inside A's bound, outside A's bound, inside B's bound) with zero unauthorized entries; 0025 status line names implemented tranches | `epic-5-policy` |
| 6 | AP-SPEC-056 implementation — done, PR #136 | Epic 2 recipe AST committed and Epic 4 corpus published | both packaged CLIs pass the whole corpus; every derived recipe passes `recipe check` | `epic-6-openapi-derivation` (merged) |
| 7 | Approval quorum in the SDK and gateway ("2 of 3 managers approve") | Epic 5 merged | Python and TypeScript expose `k_of_n` authorization plans as thin projections of the core `AuthorizationPlan` and collect member signatures; the gateway hostile suite shows 1 of 3 approvals refused before any credential lease and 2 of 3 authorized, with zero unauthorized entries. No core change | `approval-quorum` |
| 8 | AP-SPEC-060 §15 — SDK attach and the Rust–Lean link. **Implemented on draft PR #144 (§1); hosted CI pending** | Epic 5 merged | §15.1: packed Python and npm consumers attach a read-back observation and run the expected-before-replacement journey; §15.2: refinement proofs equate each translated predicate with its model counterpart, registered in the assurance manifest | `060-sdk-attach` |
| 9 | AP-SPEC-038 §9 — production trust | items 7–8 merged | the §9 acceptance: multi-host gateway store, custody, separation of duties | `038-production-trust` |

## 3. Backlog — one paragraph each; specs only where the owner directed

- **059 / 060** are implemented and merged; see §1.
- **060 §16 observer quorum.** Specified, not scheduled. It has value only once a second observer run by a different operator exists; today the gateway is the only observer. Start when such an operator exists. Approval quorum (queue item 7) is a different feature and needs no core change.
- **061 End-to-end machine-checked verifier.** Spec:
  [AP-SPEC-061](specs/0061-end-to-end-machine-checked-verifier.md) (draft,
  not started). Phased codec → crypto link → control flow, with a claim
  sentence per phase; ~5–8 months. Phases 0–1 do not depend on 059/060.
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
  Typed query segments also let 059 resolve an `unknown` create.
- **Multi-host gateway.** The gateway's attempt, evidence, and outcome state
  is single-host today. It moves to the qualified PostgreSQL store under
  AP-SPEC-038 §9.1.
- **Surface-area cost.** Formal, kernel, gateway, bindings, and signing have
  grown faster than adoption. Before each new epic, name what it retires or
  consolidates, and track the per-PR regeneration and freeze overhead.

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
| 2026-09-22 | Audited AP-SPEC-050–057 against merged `main`, the current gateway branch, their acceptance clauses, and recorded hosted/live evidence: 050 is partial, 051/052/054 retain review gates, 053 is partial, 055 is implemented, 056 remains unimplemented, and 057 is active with only Epic 2 complete in its bounded scope. | AP-SPEC-050–057 status headers; this board |
| 2026-09-22 | Owner directed AP-SPEC-058 to be written as Epic 3's first commit. That starts Epic 3 at the spec step only. Epic 1's historical field-lab hosted gate and owner review stay unclaimed. `auths.git-signature/1` is a new profile, separate from `auths.git/1`; the proof binds the unsigned payload digest, not the object ID; trust must come from outside the verified range; revocation applies where the record is present; verification is gate-time. | 0058 §§3.1–3.5, §8 |
| 2026-09-22 | Owner directed AP-SPEC-059, 060, and 061 to be written as drafts before their epics start, overriding the §5 "not doing" row, whose reason (no gateway) no longer holds. Writing a spec does not start an epic; the WIP limit still governs implementation. 059 keeps the 053 idempotency key and adds an echo field; 060 is a core wire change with observers separate from authority anchors; 061 phases 0–1 may start before 059/060. | 0059 §2, 0060 §3.3, 0061 §8 |
| 2026-09-22 | Owner directed Epic 3 implementation to start, which waives Epic 1's done gate for Epic 3 only, as the owner did for the #123 merge; Epic 1's historical field-lab hosted gate and owner review stay unclaimed. Step 1 fixed the envelope frame with explicit lengths and raised the armored limit to 200 KiB so both fields fit at their limits. | 0058 §3.3, §3.6 |
| 2026-09-23 | Owner directed 059 implementation after Epic 3 merged (#129). `observed-by-provider` requires the exact token and the verified value; the idempotency key stays per 053; readings are in 0059 §7.1. | 0059 §2, §7.1 |
| 2026-09-23 | Owner directed spec amendments with no shortcuts: 0038 §9 (gateway, observer, and Git signing in the production substrate; separation of duties; K-of-N observer quorum); 0060 §15 (SDK attach, Rust–Lean link), §16 (K-of-N observer quorum counted per operator domain), and §17 (per-extension attenuation, which lets delegates add observation requirements and narrow policy bounds); 0025 §24 (the tranches Epic 5 needs, using §17). Epic 5 now depends on 0060 §17. | 0038 §9, 0060 §15–§17, 0025 §24 |
| 2026-09-23 | PROVISIONAL, taken unattended as the narrower readings: the AP-SPEC-056 mapper spells the root body `.`; records `minLength` above 1, `pattern`, and `format` as unenforced; treats `anyOf [T, null]` as nullable and resolves it only by `--pick`; splits server base paths into fixed segments and drops one trailing slash; takes `operator_namespace` from a required `--operator-namespace` flag; writes `recipe.json`; reads JSON only; flattens nested closed objects to `_`-joined root fields because the compiler accepts root scalars only; makes `--max-items` unusable until the compiler accepts arrays; lets `--max-bytes` only narrow `maxLength`; refuses an override name shared by a parameter and a body property; and refuses to derive an operation declared `security: []`. | 0056 §8.1 |
| 2026-09-23 | PROVISIONAL, taken unattended for 0060 §15: `mcp-arguments-v1` moves from the gateway to `auths-profile-mcp`. The Python and WASM verifiers now carry two configurations, their own and `mcp-arguments-v1`, and the configuration a trusted context pins selects one, so SDK authoring reaches the same verdict as the gateway. The gateway test harness becomes a feature-gated process (`testkit-harness`) speaking the shared application-socket module. A changed record is shown both as refused by the SDK and as denied by the gateway for an agent that skips the SDK's check. | 0060 §15.4 |
| 2026-09-23 | Owner decision (2026-09-23) for 0060 §15, keeping the 30 s default: an SDK-prepared action is valid for `validity_seconds` after its evaluation time. The default is 30 s and the cap is 300 s, both held only in `auths-author`, and the window is cut to the terminal grant's expiry, so live SDK actions verify at a real gateway clock. The window is not a replay defence: the gateway's durable claim per namespace and operation ID is, inside and after the window. The challenge binds the deployment, and observation `max_age` is still judged at the gateway's clock. | 0060 §15.4 reading 7 |

## 5. Not doing

| Proposal | Reason | Recorded |
| --- | --- | --- |
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
| 2026-09-21 | Epic 3 acceptance | Twenty external repositories and one organization enforcing signed-commit verification require real adopters. | Did not simulate adopters. AP-SPEC-058 is now written on owner direction (§4, 2026-09-22); its §6 acceptance table keeps these two clauses human-owned. |
| 2026-09-22 | Epic 3 step 6 dogfood | Signing this repository's own agent commits and requiring the check here needs a root key the owner holds, `.auths/git/trust.cbor` committed to `main`, and a branch-protection rule. That is a trust-root and repository-policy decision. | Did not create a root of trust for the owner's repository or change branch protection. The action and its hosted self-test (`git-signing-action.yml`) show it passing on agent-signed commits and failing on an unsigned one in a scratch repository. Owner steps: `auths-git key init --label root`, then `auths-git trust init --root root --repository github.com/auths-dev/auths-proof --out .auths/git`; merge that; add the action as a required check. |
| 2026-09-22 — RESOLVED IN CODE | Epic 3 step 5 public-good Sigstore | Public-good Rekor signs with DER ECDSA; the kernel suite takes fixed-width low-S. | The Sigstore adapter converts log and entry signatures to fixed-width low-S before the unchanged strict suite, tested on a recorded public-good entry (AP-SPEC-046 §15). A production Fulcio/Rekor client and the hosted `live-sigstore` job were added; the hosted run's result is recorded in PR #129. The workload policy commitments were also fixed (AP-SPEC-045 §5, AP-SPEC-046 §15.7). |
