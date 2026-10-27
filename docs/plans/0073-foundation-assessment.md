# AP-SPEC-073: Initial implementation assessment

- **Status:** M0 source trace and acceptance inventory recorded; bounded delegation and temporal-evidence changes implemented, hosted verification pending. M0–M4 remain incomplete.
- **Date:** 26 October 2026.
- **Updated:** 27 October 2026.
- **Spec:** [Identity, authority, and enforcement foundation](../specs/0073-identity-authority-and-enforcement-foundation.md).
- **Baseline:** `9b1fe3c202a202750704730aebc47e0585a24470` from `codex/ap-spec-071`.
- **Branch:** `codex/identity-authority-foundation`.
- **Worktree:** `/Users/bordumb/workspace/repositories/auths-proof-base/auths-proof-identity-authority`.

## 1. Baseline custody

The worktree was created from the AP071 commit so the recent read/revocation and recovery work remains available. It does not include unrelated commits from other worktrees or untracked review files in the source checkout. No source checkout was reset or switched. The initial proposal changed documentation only; subsequent implementation is recorded below.

The containing `auths-proof-base` directory is not the Auths repository root. Git operations must use this worktree explicitly; invoking Git from the container directory discovers an unrelated ancestor repository. A standard Git worktree was therefore created against the verified Auths checkout rather than using a task-relative worktree tool pointed at the wrong repository.

## 2. Preliminary inventory

The following observations are grounded in source inspection at the baseline. Suggested dispositions are hypotheses for M0. They are not findings that the code is correct, deficient, or sufficiently tested.

| Surface | Existing evidence | Initial direction | Required follow-up |
| --- | --- | --- | --- |
| Authority attenuation | [`EffectiveAuthority`](../../core/crates/auths-authority/src/lib.rs) already carries root, subject, profile, permissions, validity, audiences, action constraints, budget ceiling, depth, assurance and status policy. | Retain as the starting point. | Map each proposed dimension to exact narrowing semantics, fixture, and formal link; distinguish static ceiling from shared consumption. |
| Verified action boundary | [`VerifiedAction`](../../core/crates/auths-verifier/src/lib.rs) has private fields and constructors reached through complete verification; proof plans and approval satisfactions already exist. | Retain and assess transition bindings. | Trace action → plan → admission → execution; identify which commitments survive every transition and which are missing. |
| Principal adapters | [`core/adapters`](../../core/adapters) contains workload OIDC, WebAuthn, and KERI adapters among other methods. | Retain the adapter boundary. | Separate existing control verification from proposed enrollment/rotation/recovery services; inspect time provenance and instance binding. |
| Gateway/task mechanisms | [`auths-gateway`](../../product/runtime/auths-gateway/src/lib.rs) has task activation, write confirmation, effect plans, and recovery attestation modules. | Evaluate before introducing a new engagement service. | Map task identity, cross-task rejection, descendant authority, budget ownership, and exact confirmation to F01–F11. |
| Pure gateway predicates | [`auths-gateway-kernel`](../../product/runtime/auths-gateway-kernel/src/lib.rs) describes extracted decision leaves and formal linkage. | Preserve concrete predicates and their evidence. | Inventory actual theorem/implementation correspondence; do not claim whole-runtime proof from individual leaves. |
| Durable state | [`auths-stores`](../../product/stores/auths-stores/src/lib.rs), [lifecycle](../../product/stores/auths-stores/src/lifecycle.rs), and [gateway attempts](../../product/stores/auths-stores/src/gateway_attempt.rs). | Assess central persistence ownership. | Establish transaction boundaries, power-loss guarantees, concurrency, rollback/restore behavior, and uncertain-capacity retention. |
| Credential custody | [`auths-custody`](../../product/integrations/auths-custody/src/lib.rs) and [gateway process custody](../../product/runtime/auths-gateway/src/bin/process_custody.rs). | Preserve separation; assess provider coupling. | Distinguish signing custody from provider credentials; trace credential-generation, account-subject, process, and egress enforcement. |
| Receipts/disclosure | [`auths-receipts`](../../product/receipts/auths-receipts/src/lib.rs) and [disclosure](../../product/receipts/auths-receipts/src/disclosure.rs). | Retain typed claims where their meaning fits. | Map release, acknowledgement, entry, and observation; inspect privacy commitments and inspect/execute consistency. |
| Language interfaces | [`bindings`](../../bindings). | Keep one Rust semantic owner. | Trace canonical commitments, input bounds, error classes, actual native calls, and adversarial conformance for F14. |
| Production integration policy | [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md), [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), [AP072](../specs/0072-agent-authored-adapter-studio-and-qualification.md). | Preserve existing paths while specifying future modes. | Native managed enforcement requires an explicit ADR; application-owned integration does not acquire a managed claim automatically. |

No row currently justifies deleting its subsystem. No claim-to-test coverage is marked complete merely because a corresponding source file exists.

## 3. M0 work queue

- [x] Record mission, threat model, proposed boundaries, first complete scenario, and explicit deferred decisions.
- [x] Identify the source revision and isolate the worktree.
- [x] Locate existing authority, verifier, task, persistence, custody, receipt, and binding surfaces.
- [x] Trace one AP071 action end to end and record exact types, owners, and commitment checks at each transition (section 6).
- [x] Make an initial F01–F16 source/test inventory, separating reported historical runs from unverified current-revision evidence (section 7). This does not close any acceptance criterion.
- [ ] Write the concrete multi-hop authority and cross-engagement composition contract using existing proof-plan semantics where possible.
- [x] Write budget conservation and revocation/entry histories before selecting a new admission API ([participant contract](0073-engagement-participant-contract.md)).
- [ ] Inventory time provenance, storage ordering, canonicalization, and configuration-sensitive caching; identify repeated interpretations that deserve central ownership.
- [ ] Specify the smallest identity lifecycle profile for the representative flow, including compromise/recovery consequences.
- [ ] Select the initial provider and deployment boundary, reusing an admitted execution family.
- [ ] Produce a retain/strengthen/replace/remove decision per affected subsystem, with evidence and affected invariants.
- [x] Select the first bounded implementation change and its required ADR, fixture, formal, compliance, and hosted CI updates (sections 8–10).

## 4. Required decision record per replacement

For each proposed replacement, record:

1. Current contract and exact source locations.
2. Concrete failure scenario or missing mission capability.
3. Why retaining or strengthening the existing boundary is insufficient.
4. New contract, owning layer, and dependencies.
5. Invariants preserved, strengthened, or intentionally changed.
6. Canonical/wire, bindings, storage, provider, and formal impacts.
7. Direct cutover and deletion scope, including obsolete-state rejection.
8. Required executable evidence and exact-revision results.

Unbounded architectural cleanup is not a deliverable. A complete, demonstrable authority path with explicit guarantees is.

## 5. Goal and handoff

Continue M0 from the worktree above. Read `AGENTS.md` and its required domain boundary plan before implementation. This assessment is the place to record new source findings and evidence, while AP-SPEC-073 holds the intended contract. Keep implementation status and design intent distinct.

On 27 October the user explicitly requested that completing this program become the agent's goal, including implementation. The active goal is to complete M0–M4 and F01–F16 with reproducible, appropriately scoped evidence, preserving sound existing boundaries and recording unresolved assumptions. Documentation and a passing narrow test are not completion.

No new production qualification or whole-system formal proof is claimed. Current verification results and continuation steps belong in section 10.

## 6. AP071 source trace: exact-confirmed write and related read

Source locations below describe baseline `9b1fe3c2`; symbol names remain the lookup anchors after edits.

| Boundary | Owner and source | Established by source inspection | Remaining AP073 question |
| --- | --- | --- | --- |
| Operator installation | [`GatewayEngine::task_write_session`](../../product/runtime/auths-gateway/src/engine.rs), baseline line 1261 | Canonical installation bytes, installed recipe membership, task trust availability, resource-field/verb binding, connection pins, private task ledger. | Installation supports one pinned agent and write connection; participant enrollment is not an existing generic identity lifecycle. |
| Human task activation | [`verify_task_activation`](../../product/runtime/auths-gateway/src/task_activation.rs), line 388; `TaskWriteSession::activate`, engine line 2020 | Native proof for the fixed task tool, actor equals card human, card matches operator pins, current connection/account and approved recipes checked before durable activation. | Machine initiation and independent human approval need distinct roles rather than renaming the existing human field. |
| Agent action verification | `submit_task_write`, engine line 1331; [`verify_sealed_for_audience`](../../product/runtime/auths-gateway/src/engine.rs), line 3417 | Active task reconstruction, native bounded proof verification at explicit time, gateway-owned audience, sealed canonical action. | Instance identity and downstream participant selection must stay bound to the task. |
| Request compilation | [`derive_exact_write_intent`](../../product/runtime/auths-gateway/src/task_write.rs), line 140 | Exactly one card agent; task ID/commitment, resource, recipe, connection identity/generation/subject; closed request commitment. | Do not replace these commitments with a loose generic intent. |
| Human exact approval | `verify_exact_write_confirmation`, same file, baseline line 261 | Fixed confirmation tool, equality with entire intent, independently verified human actor and authorized branch. | Approver role needs explicit separation from initiator in a machine-started engagement. |
| Reverification | `EngineIo::verify`, engine line 2930 | Re-derives the intent and compares it with the approved intent before the ordinary submission driver proceeds. | Preserve this check across any new participant protocol. |
| Durable task budget | `EngineIo::reserve_task_write`, engine line 2970; [`reserve_write_with_namespace`](../../product/runtime/auths-gateway/src/release_state.rs), baseline line 695 | Original task checks, replay across reads/writes, connection and scope checks, charged write slot. | This is a single-host task journal, not a multi-host parent/child budget authority. |
| Attempt and custody | [`submit::run`](../../product/runtime/auths-gateway/src/submit.rs), `SubmitAction` dispatch and `claim` | Pure order machine controls verification, claim, reload, lease, checkpoint and send; task reservation precedes separate attempt claim. | Two durable stores do not form one atomic transaction. Crash between them conservatively consumes capacity; any reclamation needs evidence. |
| Entry/outcome | Same driver; [`ClaimedGatewayAttempt`](../../product/runtime/auths-gateway/src/store.rs) | Response, not-entered and unknown have separate transitions; observation resumes without blindly re-entering a write. | Provider semantics and fence enforcement remain explicit external assumptions. |
| Read proof | [`verify_release_request`](../../product/runtime/auths-gateway/src/release_verify.rs) | One native-authorized branch, exact recipe audience/request, actor equals recipient, unsupported grant policy refused. | Baseline records only terminal issuer as the task human, incorrectly excluding an otherwise valid intermediate delegation. First change below broadens ancestry, not recipient scope. |
| Read admission | [`prepare_managed_read`](../../product/runtime/auths-gateway/src/release_execute.rs), baseline line 349; `reserve_verified_request` in release state | Task/recipe/account/generation, installed channel and key, native proof, durable provider-call reservation. | A new dynamic recipient cannot be inferred from chain membership; enrollment and card authority must expressly permit it. |
| Content release | `execute_managed_read_with_clock`, same file, baseline line 242; [`release_channel`](../../product/runtime/auths-gateway/src/release_channel.rs) | Rechecks at credential/read/release boundaries, projection limits, durable byte/release charge, authenticated channel and exact signed acknowledgement. | Check-and-send interleavings need a declared entry linearization point; repeated freshness reads alone are not a proof of atomic revocation. |

The source already separates verification, compilation, approval, reservation, entry and observation. No evidence here justifies replacing all of those stages with one universal effect struct or state machine.

## 7. Initial F01–F16 evidence inventory

**Evidence labels:** `source` means the implementation or test was inspected, not run. `historical report` means a checked-in account names a run/artifact; it is not verification of this branch. `pending` means current-revision acceptance remains unestablished. All sixteen criteria remain pending.

| ID | Existing source or report | Gap for this program |
| --- | --- | --- |
| F01 | `release_channel::tests::wrong_agent_key_cannot_open_a_content_channel`; `release_verify::tests::native_release_refuses_mismatched_recipient_and_accepts_task_scoped_grant` (source). | Multi-hop instance lifecycle and native enforcement audiences. |
| F02 | Core attenuation and denied delegation fixtures; new delegated-read depth/source tests (source). | Full engagement narrowing dimensions and generated/mutation corpus for participant grants. |
| F03 | `derive_exact_write_intent` checks card identity; `reserve_verified_request` checks task commitment; `release_commitment` separates contexts (source). | Explicit composition and information-flow contract across engagements, including read-to-send. |
| F04 | `release_state::tests::competing_last_write_claims_remain_spent_after_restart`, `paired_recipes_share_one_durable_write_budget_after_restart` (source). | Different downstream principals sharing a parent allocation; distributed partition/escrow evidence. |
| F05 | `release_state::tests::read_and_write_share_task_replay_and_revocation`; gateway attempt identity is operator namespace + logical operation (source). | Cross-executor permit replay and explicit audience/partition binding. |
| F06 | `task_write::tests::exact_human_signature_binds_the_native_agent_action_and_closed_request`; installed session test in `engine.rs` (source). | Bind participant grant/epoch and independent human approver without changing exact request semantics. |
| F07 | Explicit kernel evaluation time, WebAuthn undated-UV correction and centralized gateway clock cutover (source; hosted acceptance pending). | Verify native/binding provenance corpus and clock fault regressions on the final revision; review SPIFFE workload-attestation event semantics. No global trusted-time or rollback guarantee. |
| F08 | `release_state::tests::lost_ack_consumes_budget_and_cannot_redeliver`; [installed release crashes](../program-log/2026-10-26-ap071-installed-release-crash.md) (historical report). | Reproduce against final AP073 artifacts and participants. |
| F09 | Same crash report includes write-reservation gap; `submit.rs` separates uncertain entry; store recovery tests (source/report). | Explicit reservation/entry/revocation histories and fault coverage for each selected storage implementation. |
| F10 | `engine::tests::recorded_create_reconciles_child_without_reentering_provider_write` and `exact_confirmed_create_reconciles_after_proof_expiry` (source). | Preserve exact task lineage under new participants and independently reproduce provider cases. |
| F11 | `release_execute` tests revoke during materialization, lease and connection reload; task ledger `revoke` (source). | Ancestor/participant revocation and linearizable admission/entry contract under concurrency. |
| F12 | Principal adapters and connection rotation exist (source inventory). | End-to-end principal compromise/recovery with outstanding descendant grants, not merely provider credential rotation. |
| F13 | [Linux container boundary](../program-log/2026-10-26-ap071-container-boundary.md) and [container read/write](../program-log/2026-10-26-ap071-container-read-write.md) (historical reports). | Final artifact and multi-agent isolation; independent principal keys and result channels; output/model/log flows. |
| F14 | Native canonical corpus plus Python/TS conformance surfaces (source inventory). | Trace all public inspection/commitment paths and bounded decoding; exercise new semantics through released bindings. |
| F15 | File ledger uses lock, file fsync, atomic publication and directory fsync; qualification tracks accepted revocations (source). | Whole-store restoration/rollback protection, cache dependency closure, cross-process trusted epochs. |
| F16 | Typed release stages, receipt claims, entered/observed/unknown driver outcomes (source). | Complete human view of ancestry/roles and exact-revision outcome evidence for the new flow. |

The AP071 program has progressed beyond the older holistic review: checked-in Linux isolation and crash reports now exist. Their precise scope and artifact pins must be retained; neither absence in an old review nor presence of a report establishes this branch's acceptance.

## 8. Decisions for the first implementation slice

### D1: Preserve task identity and explicitly approved final recipient

Use the existing task ID and immutable card commitment as the initial engagement boundary. The task still names its final agent, key/channel, resources and budgets. There is no new wire object, runtime recipient override, or independent child task allocation in this first change.

Allow an already approved final agent to exercise a native-verified chain through intermediaries when the approving human issued a grant on that exact authorized chain. Every link remains subject to existing signature, parent, depth, attenuation, status, audience and canonical action checks. The human need not be the terminal issuer. A human merely appearing elsewhere in a bundle is insufficient.

This is useful in a hierarchy such as `service → human → agent A → agent B`, where the human explicitly approved B in the task card. It does not yet implement machine-initiated task activation with a separate approver, or let A choose a new unlisted B.

The source change keeps a sealed list of issuers extracted only from the single native-authorized branch. Task admission asks whether its human appears in that list. Existing recipient/card/account checks and the original task budget remain authoritative. It does not scan all supplied grants or merge separate branches.

This is a concrete extension of the existing release profile, not extraction of shared provider semantics. It needs no new package, token format, shared-policy exception, or production execution family. The kernel's existing chain verification remains the semantic owner. There is no claim of a new Lean proof for the post-verification ancestry projection; native integration tests and the existing verification boundary supply the initial evidence.

### D2: Keep budgets conservative while defining participant admission

The first change consumes the original task journal. A fresh delegated invocation cannot create a new pool. No refund is added for lost acknowledgement, unknown provider outcome, or the write-reservation/attempt-claim gap.

The subsequent participant design must choose one authoritative partition containing root task, participant lineage, revocation epoch, replay identity, and capacity. It must specify atomic admission before implementing a participant map. Ad hoc independent child journals are prohibited because they can multiply capacity.

### D3: Preserve deployment and identity scope honestly

Use existing native raw-key identities and operator-pinned trust for the first deterministic conformance cases, followed by separately isolated agent processes under an admitted HTTPS provider family. This provides principal control, not enterprise enrollment or hardware attestation. The first live candidate is the existing Airtable read/update family with a disposable resource and explicit operator credential limits; human provider-account delegation remains a separate claim requiring the appropriate provider setup.

No provider operation is authorized merely to discover credentials. Establish the selected live test's resource ownership, bounded effect, account and cleanup before execution. Existing private credentials are not test fixtures.

## 9. First change and verification contract

Change: replace terminal-human-issuer projection in `VerifiedReleaseRequest` with issuers on the exact native-authorized path. This fixes an unnecessary one-hop restriction while preserving explicit task approval of the final recipient.

Tests added in `release_verify.rs`:

- `delegated_read_requires_task_human_on_the_authorized_path_and_final_recipient`: a three-edge chain admits once; replay and a fresh operation after budget exhaustion fail; unrelated human, different recipient, and changed card commitment fail before charging.
- `delegated_read_cannot_redelegate_without_depth_or_change_the_approved_source`: native verification rejects exhausted delegation depth and substituted canonical source action.

The existing direct-grant tests remain. `compliance.toml` registers the new tests under gateway runtime enforcement. No codec, fixture bytes, provider grammar, package graph, or binding ABI changes in this slice.

Required verification: hosted CI on the pushed revision, including native tests and compliance/semantic-closure gates. If a gate fails, inspect it first and reproduce only the needed check locally under the repository policy. Do not mark F01/F02/F04/F05 complete from these two focused tests.

## 10. Execution log and next work

- **27 October 2026:** explicit goal recorded for full M0–M4 completion. Baseline and source checkout unchanged. AP071 PR #211 is still a draft; the new branch is not evidence that its unresolved production gates are closed.
- **27 October 2026:** source trace, initial acceptance inventory and first delegation-path decision recorded. First implementation and tests written; hosted results pending.
- **27 October 2026:** pushed `afd13814bfd8e50092f285df2b3da03903ff66f1` and opened [draft PR #212](https://github.com/auths-dev/auths-proof/pull/212), stacked on `codex/ap-spec-071`. It includes eight inherited AP071 commits beyond that branch's currently published head; the PR description records this explicitly. Hosted [run 40567547386](https://github.com/auths-dev/auths-proof/actions/runs/40567547386) passed generated-artifact classification but failed repository preflight on semantic-freeze drift. This is not a successful native-test run. The failed gate is being reproduced locally as repository policy permits.
- **27 October 2026:** recorded the [engagement participant contract](0073-engagement-participant-contract.md): separate initiation and approval, one authority tree and partition, ancestor budget conservation, durable entry/revocation ordering, and explicit rollback limits. Implementation and evidence remain pending.
- **27 October 2026:** pushed the inventory correction as `81c88b57` and explicitly dispatched hosted [run 40569732610](https://github.com/auths-dev/auths-proof/actions/runs/40569732610). Pushed temporal-evidence correction `211fd87d`; its exact-revision hosted acceptance remains pending. Recorded the [time ownership contract](0073-time-contract.md) for the next source cutover.

Semantic inventory correction for the first slice: `auths.identity.protocol` 137 → 138 and `auths.product.public-sdk-contract` 134 → 135 reflect their ownership of the changed compliance evidence declarations. Freeze version and `auths.release.public-surface` 393 → 394 record the inventory/counter changes. These are inventory identities, not a core wire version change. `cargo xtask semantic-freeze --update` completed after inspecting the hosted failure. Gateway source closure was regenerated through `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib semantic_closure_is_current` (one generation check passed, 307 tests filtered out); this builds the gateway test module but does not establish that its new behavioral tests pass. Prior qualification does not cover the new code digest.

Next: inspect hosted results and dispatch CI for the latest revision; resolve concrete failures without weakening checks. Verify the gateway clock cutover, then implement participant roles/schema and atomic ancestor accounting under the recorded contracts. Continue the binding, persistence and cache audit; do not replace those systems by inference from the narrow delegation change. The unused `auths-cache` API still needs an explicit retain/remove decision before adoption; no running cache bypass was established.

## 11. Cross-cutting ownership findings

| Contract | Baseline source observation | Disposition and required next evidence |
| --- | --- | --- |
| Wall-clock acquisition | `engine.rs::wall_clock_seconds`, `qualification.rs::DeploymentClock`, materializer and CLI clock reads, plus `auths-runtime` clock traits are separate. | Strengthen one explicit product clock contract for a selected execution path, preserving separate monotonic deadlines. Do not merge unrelated domain freshness policies by renaming traits. Inventory all call sites before cutover. |
| Historical event time | `auths-webauthn/src/lib.rs::assertion_claims` attaches `evaluation_time` to `user-verified` although credential observation has its own timestamp. | Resolve F07 at the evidence/assurance contract: the verification clock cannot manufacture event age. A shared clock alone does not fix this. Required tests must re-evaluate the same old assertion at two later times. |
| Task durability | `release_state.rs::write` fsyncs the temporary file, atomically persists it, then fsyncs the directory; `update` holds an exclusive file lock. | Retain these mechanics. The demonstrated claim is single-host ordering; a restored whole directory has no independent anti-rollback anchor. |
| Attempt/task atomicity | `submit.rs::claim` reserves the task first, then claims the separate provider attempt. | Preserve conservative spending while deciding whether a single transactional participant ledger is required. A missing attempt record alone does not justify reopening an operation after uncertain writes. |
| Revocation ordering | Task ledger mutation serializes with reservation and release entry; executor also re-reads active state before later I/O. | Define which durable admission/entry event wins against revocation. Re-reading before a send is not a cross-host linearization guarantee. Future tests must record both event orders. |
| Native inspection | TS `inspection.ts` now calls the packaged engine's `commitCanonicalV1`; Python `_inspection.py` calls native `commit_canonical_v1`. | Retain the native commitment path. The older review's FNV implementation is not present at this baseline. Independently assess caller-supplied inspection fields; diagnostic data must not mint authority. |
| Verification cache | `auths-cache::VerificationCacheKey` binds proof, canonical action, context and registry manifest, but has no separate executed-configuration field. A repository search found constructor calls only in that crate's tests. | Strengthen or retire this API before adopting it for security decisions. This inspection establishes an incomplete reusable key contract, not an observed gateway cache bypass. Distinguish it from the TS immutable-artifact cache. |
| Qualification | `QualificationGate` holds a sealed deployment clock and an exact deployment tuple; public state marks development versus required qualification. | Preserve fail-closed qualification and exact semantic-closure updates. New code is not qualified by old provider evidence. |

These findings identify owners and follow-up work, not a reason to create a new global framework. In particular, temporal evidence provenance belongs in core evidence contracts; clock acquisition and trust belong in the product boundary; provider freshness meaning stays profile-owned.

## 12. Temporal evidence correction

The next implementation slice addresses F07's observed WebAuthn defect at its
source. The assertion's signed UV flag carries no trusted event time. Native,
independent Go and independent TypeScript implementations now emit undated UV;
the existing central assurance evaluator refuses maximum-age requirements on
undated evidence. It still permits the fact for an unaged UV requirement.
Credential observation and asserted signing time are not substituted. Adapter
assurance revision 2 and its configuration domain commit the changed meaning.

The protocol and adapter specifications state the provenance rule. This is a
restriction of an unsupported freshness claim, not a fresh-ceremony service.
Such a service needs an exact challenge/assertion binding, a trusted temporal
observation and replay-aware outer authority. The gateway clock acquisition cutover is implemented below; its hosted
acceptance and SPIFFE workload-attestation timestamp interpretation remain open.

Evidence prepared:

- Native portable-ABI regression
  `webauthn_reverification_does_not_refresh_user_verification` exercises root and
  actor roles at times 50 and 59, with both unaged and one-second-age policies.
- Four canonical corpus cases cover the same dated-policy refusals in every
  corpus consumer. The corpus grows from 319 to 323 cases. Existing proof,
  action and body bytes and expected decision/code values are unchanged.
- `cargo xtask wire --update` generated the canonical outputs. The changed
  adapter configuration updates context/result commitments across the existing
  corpus; these are generated changes, not hand-edited CBOR.
- `cargo xtask semantic-digest` generated the shared test pin
  `323:deeed0ff7cb085ea1420aa15159ec13783413a156ae94cc1e5f7313beff02b07`.
  Generation is required to construct the change; it is not hosted acceptance
  or a claim that the independent implementations pass.

Inventory versions: core protocol 36 → 37, core fixture manifest 15 → 16,
freeze/public-surface 394 → 395. No portable wire encoding or signature
preimage changes. No new Lean theorem or full F07 closure is claimed. Hosted
native, independent and binding verification remains required.


## 13. Central gateway clock implementation and CI diagnosis

Hosted [run 40570861843](https://github.com/auths-dev/auths-proof/actions/runs/40570861843)
on `d295a09427e235729095a287dd9e035930094d31` passed generated-artifact
classification but failed preflight on fourteen gateway lint diagnostics. Native
behavioral acceptance was not reached. The diagnostics concern test-only helper
visibility, similar local names, API error documentation, one approval function's
size and a recovery function's existing boundary allowance attached to its
wrapper rather than its implementation. The correction preserves the checks,
extracts recorded-plan approval from execution, and adds the missing API docs.
A targeted gateway all-target/all-feature clippy reproduction is permitted by
that inspected hosted failure; no full local gate is substituted for CI.

The [time contract](0073-time-contract.md) now has its concrete gateway cutover:

- One sealed sample carries time and trust to qualification, admission, recovery,
  observation, critical reload and custody. Required execution refuses missing
  or untrusted samples even when recipe qualification is optional.
- Credential deadline conversion preserves fractional time and caps the source
  lease. Entry checks retain independent monotonic expiry and reject wall time
  before evaluation.
- Managed reads use the installed clock rather than a separate test callback.
  Clock/trust loss after credential acquisition stops provider entry and content
  disclosure while retaining the charged reservation.
- Readable but unsynchronized time remains usable for administrative bookkeeping
  so connection disabling is not blocked by synchronization failure. It cannot
  authorize execution.
- Six new clock/engine/read fault regressions and the relocated synchronization
  marker tests are registered in compliance. Behavioral results remain pending.

Gateway semantic closure must be regenerated after the last source change;
prior provider qualification is not evidence for this code. Inventory ownership
requires identity protocol 138 → 139, public SDK contract 135 → 136, and
freeze/public surface 395 → 396 for the source/compliance cutover. Core wire and
fixture versions do not change in this slice. F07 remains open pending hosted
results and the remaining evidence contracts; F01–F16 and M0–M4 are not declared
complete by this implementation.


The targeted local reproduction then exposed test/binary diagnostics that the
hosted lib failure had prevented CI from reaching. Corrections retain all
assertions: name closed read scenarios instead of four booleans, box oversized
futures, use checked time subtraction, separate fixture construction and named
assertion phases, group recovery CLI inputs, and preserve `NOFOLLOW` flag bits
without a potentially wrapping numeric cast. No lint category was disabled.
The existing recovery-boundary length allowance was relocated to its actual
implementation. `cargo clippy -p auths-gateway --all-targets --all-features -- -D
warnings` passed locally after these corrections. The CLI's non-executing
statement/review/bookkeeping timestamps also use the maintained acquisition
module; they do not assert synchronization or replace the installed execution
clock's trust gate.


Artifact generation exposed one additional consumer of the replaced clock API:
`xtask/src/release_launch.rs`. Its launch-readiness projection now filters trust
and obtains time from the same sample instead of separate `now`/`trust` calls.
The formal source closure binds this control-plane source, so its frozen-byte
identity advances 103 → 104 and its generated closure is refreshed. This does
not constitute new formal qualification. A repository-wide adapter-name search
found no other consumer of the removed gateway clock methods.

Generation completed: gateway semantic closure through
`AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --features loopback-provider
--lib semantic_closure_is_current` (one generation check passed; 329 behavioral
tests filtered out), followed by `cargo xtask semantic-freeze --update`. The
latter refreshed formal source and semantic inventory bytes. These are artifact
construction results, not a successful authoritative run.


## 14. Task initiation and independent approval

The clock cutover was pushed as `5fb478021edd961a5aa2d179b1b52efbf3fa506f`.
Hosted [run 40573770464](https://github.com/auths-dev/auths-proof/actions/runs/40573770464)
passed generated-artifact classification; repository preflight and formal
feedback were still running at the last observation. No behavioral acceptance
is inferred from that status.

The next source cutover follows the [task-role contract](0073-task-role-cutover.md).
Required initiator and approver principals replace the overloaded task/pin human
field. Task schema/domain 3, installation schema 4 and state schema 8 reject old
disposable representations. Activation and read ancestry use the initiator;
exact write, effect-plan and recovery approval use the approver. Distinct roles
cannot use bounded-upfront approval. The existing native verifier, task budget,
closed provider request, final agent and channel remain authoritative.

The Google employee vertical explicitly assigns its employee to both roles. Its
separate employee authority-package identity stays named `human_principal`;
renaming that unrelated identity would erase the vertical's meaning. Native
schema consumers, Python card/pin producers and commitment inputs cut over
together. No old-schema reader or default role is introduced.

Prepared native evidence includes a machine activation test with role/key
substitution and committed-role mutation negatives, same-role versus independent
upfront policy, obsolete card refusal, and an installed gateway write scenario
with different machine/human/agent keys. The installed scenario retains the
existing direct-human variant and checks that machine/agent confirmations fail
before a write charge or credential lease. With the loopback feature, the exact
human confirmation follows the real installed execution path and one bounded
provider effect. These are written tests, not yet passing evidence.

Compliance evidence changes advance identity protocol 139 → 140, public SDK
contract 136 → 137, and freeze/public surface 396 → 397. Native wire formats and
core fixture versions are unchanged. Participant enrollment, shared ancestry
accounting, isolation, lifecycle and all final F01–F16 acceptance remain open.

The installed machine-initiation regression still uses the existing root-issued
agent operation grant; it is not evidence for machine → A → B enrollment or
attenuation. Operator resource pins, native agent authority and separate exact
approval remain conjunctive. The forthcoming participant protocol must bind its
native parent/child grant commitments and ancestor accounting explicitly rather
than treating this role split as a delegation implementation.

Hosted run 40573770464 subsequently **passed repository preflight** on
`5fb47802`; the authoritative implementation suite started. This establishes
that revision's deterministic preflight, not passing behavioral, formal or
binding acceptance. Keep that run alive for feedback while publishing the role
slice, then run the complete gate on the new head.

Role-slice artifact construction completed through the gateway closure generator
(one generation test passed, 332 tests filtered out). The task descriptor now
owns one canonical commitment routine used by activation and reconstruction;
Python continues using the native canonicalization/commitment ABI with the new
domain. Full behavioral and cross-language acceptance remain pending.


## 15. Hosted dependency and evidence corrections

Run [40573770464](https://github.com/auths-dev/auths-proof/actions/runs/40573770464)
on `5fb47802` passed repository preflight, formal fast feedback and the OpenTofu
live job. The authoritative job stopped at stale proof-coverage measurement; it
did not establish passing workspace behavioral or binding acceptance. The
dependency and secret gates also failed. These failures are actionable and do
not block continued implementation of the broader program.

The dependency report identifies recently published RustSec advisories affecting
crypto-bigint/ctutils, rustls, rustls-webpki, Tokio, bundled WebPKI roots and the
zstd stack. The workspace and lockfile upgrade to patched releases. The
crypto-bigint fix requires P-256 0.14 and its supported dependency graph; no
advisory ignore, local crypto patch, unsafe exception or MSRV increase is added.
The upstream normalization API now always returns a signature, so verifier and
custody admission explicitly reject a signature whose normalized form differs
from the original. Signing producers retain low-S normalization. SEC1 naming
and signature-trait imports change with the library API; the accepted wire
format, canonical key shape and stable rejection codes remain unchanged.
Existing canonical P-256, high-S, malformed point, WebAuthn and custody fixtures
remain required hosted regression evidence, not assumed equivalence.

Upstream advisory sources:
[RustCrypto timing](https://rustsec.org/advisories/RUSTSEC-2026-0387.html),
[ctutils](https://rustsec.org/advisories/RUSTSEC-2026-0385.html),
[TLS secret formatting](https://rustsec.org/advisories/RUSTSEC-2026-0346.html),
[certificate path validation](https://rustsec.org/advisories/RUSTSEC-2026-0382.html),
[Tokio I/O safety](https://rustsec.org/advisories/RUSTSEC-2026-0386.html),
[zstd stream reuse](https://rustsec.org/advisories/RUSTSEC-2026-0391.html).

The four Gitleaks findings are inherited commit fingerprints: a Python public
import, two public Git revision references and a synthetic provider-shaped
record ID. Source inspection confirmed their non-secret meaning. Documented
fingerprint-specific entries preserve historical evidence and the provider
binding fixture without exempting any path or detection rule. The installed
scanner's Go build metadata identifies v8.28.0, matching hosted CI. Full-history
reproduction reports no leaks after the corrections. `cargo deny check` also
passes locally after the hosted failure and dependency upgrade. Neither is a
substitute for the final exact-revision hosted gate.

Artifact construction completed: architecture snapshots needed no graph-shape
changes; proof-coverage measurement was refreshed (110/1031 decision functions,
1289/11353 code lines, 15/82 check sites, with the pinned Study 006 reproduction
byte-identical). The gateway closure generator passed its one generation test
with 332 behavioral tests filtered out. Semantic inventory generation passed.
Identity protocol advances 140 → 141, external custody 5 → 6, public SDK 137 →
138, formal source closure 104 → 105, and freeze/public surface 397 → 398. These
are source identity changes, not a new protocol wire version or formal theorem.
The original 323-case canonical corpus is not regenerated for this dependency
update. Its existing bytes remain the regression oracle.

The earlier hosted revision also passed PostgreSQL and records-API live jobs.
Formal translation, Kani and compliance were still running at the last
observation. The dependency correction is ready for a new hosted revision after
that feedback is collected. All F01–F16 final acceptance remains open.


## 16. Closed participant partition reference

Security/dependency corrections were pushed as `a4a3c7af`. The next bounded
implementation introduces the test-only partition reference required by the
repository's vertical-first policy. It is linked from the
[participant contract](0073-engagement-participant-contract.md#8-closed-partition-reference-and-grant-binding-decision).
This is an oracle for the coming state cutover, not a shipping participant API.

The concrete model owns one immutable ancestry tree and one mixed-operation
journal. It derives ancestor usage from journal entries, preserves reserved,
spent and uncertain categories, and retains every revoked or terminal record.
No participant-specific store can supply fresh capacity. Scope authority binds
actual native grant IDs per resource; this avoids conflating the grant used
to enroll with the grants authorizing reads or writes. Eight native reference
tests include randomized histories and assert that refusals leave state
unchanged. These tests are written but not yet passing hosted evidence.

Required next implementation: canonical signed enrollment plus child possession;
exact per-scope native grant verification; bounded participant state in the
existing locked task ledger; integration at reservation, provider entry and
disclosure; then installed machine → A → B acceptance. The test-only reference
assumes authenticated inputs and cannot substitute for any of those boundaries.

Reference artifact construction passed: gateway closure generation compiled
the eight new tests while running only its generation test (340 behavioral
tests filtered out); proof-coverage and semantic-inventory generators also
passed. The reference is excluded from production and did not change the
measured decision closure or require a new frozen semantic identity.


## 17. Python producer timestamp boundary

The partition reference was pushed as `62daf644`. The earlier hosted compliance
job completed with four errors among 194 broker tests: Python 3.10 rejected
UTC `Z` timestamps in create/populate handoff consumers. The existing consumers
used several independent timestamp parsers; some normalized UTC and others
did not.

One demo-local `timestamps.parse_aware_timestamp` now owns bounded timestamp
syntax and timezone presence for all 16 producer/credential consumers. Its
accepted representation is an extended date/time with seconds, an optional
1–9 digit fraction, and either terminal uppercase `Z` or a signed hour/minute
offset. Invalid calendar/offset values are refused. Only terminal `Z` is
normalized for Python 3.10. Errors do not echo metadata. The parser neither
reads a clock nor assigns freshness, expiry or trusted-time meaning; those
policies remain at their existing callers. No Google logic enters the gateway.

An initial local broker-suite reproduction could not load the absent native
Python package and external dependencies. The focused Python 3.10 reproduction
then ran the four exact hosted failures plus three parser regressions in an
isolated environment with JSON Schema support: **seven tests passed**. The
whole broker/binding suite is still delegated to hosted CI with the freshly
built native wheel. Malformed double UTC designators exposed permissive
`fromisoformat` behavior during diagnosis; the shared lexical boundary now
rejects them before parsing, along with absent offsets and oversized inputs.

The earlier revision's Kani job also passed; formal translation was still
running at the last observation. None of these prior-revision results closes
current-head acceptance or the remaining F01–F16 work.


## 18. Native participant enrollment verification

The next implemented boundary converts native evidence into a privately
constructed `VerifiedParticipantEnrollment`. The parent authorizes the complete
proposal under its exact enrolled control grant; the child accepts the
canonical descriptor commitment under a linked child control grant. Separate
resource proofs establish the child holder, exact native parent/child grant
IDs, installed MCP service/tool and pinned resource handle for each scope.
The implementation reuses the existing sealed native verifier and canonical
codec. It does not fork identity authentication, grant attenuation or signing.

The new product contract binds parent/child instances, partition and engagement,
registered channel, resource grants, validity, depth and independent ceilings.
Bounds are checked before native verification; integer encoding also rejects
values outside JSON's exact integer range. Unsupported critical policies are
refused. The protocol and ten focused native/encoding tests are registered in
compliance under principal evidence integration, not as proof of a functioning
participant runtime. No core wire fixture or binding ABI changes in this slice.

This public verification API consumes authenticated parent/operator pins. The
installed task service does not yet call it. Durable activation must atomically
revalidate the snapshot against current ancestry, prevent ID reuse, enforce the
participant bound and preserve every ancestor's capacity. SDK authoring,
installed enrollment, admission/entry wiring, restart/race evidence and F01–F16
acceptance remain open.

Hosted run [40578407732](https://github.com/auths-dev/auths-proof/actions/runs/40578407732)
on `6e8e2036` passed generated-artifact classification but failed workspace
clippy in the Git-signing test fake: P-256's new signature-trait major version
no longer supplied the Ed25519 signing trait. The fake now explicitly imports
both maintained traits. Targeted `cargo clippy -p auths-git-signing --all-targets
--all-features -- -D warnings` passed. Downstream jobs were skipped by the
preflight gate; their failing aggregate statuses are not new execution
failures. Formal fast feedback was still running at the last observation.

Enrollment artifact construction passed: the gateway closure generator compiled
the new native tests while running its one generation test (350 behavioral
tests filtered out). Proof-coverage reproduction remained byte-identical and
the semantic-freeze inventory regenerated with explicit protocol/public-surface
versions. This is construction evidence only; native enrollment behavior and
full current-revision CI remain unqualified.


## 19. Bounded enrollment state and channel ownership

Native enrollment verification was pushed as `1e9dd198` and full CI dispatched
in [40581199216](https://github.com/auths-dev/auths-proof/actions/runs/40581199216).
At the last observation, generated-artifact classification passed; preflight
and formal feedback remained running. No behavioral qualification is inferred.

The next state component is `participant_enrollment/tree.rs`. It derives parent
pins from current immutable ancestry inside the enrollment transition and then
runs the maintained native verifier. Root/child revocation, ID/principal
non-reuse, retained-slot bounds and exact per-resource grant paths have one
owner. Canonical decoding checks independently supplied installation pins and
structural invariants; it preserves revoked/expired records. This is pure state
for the existing partition, not a separate store or installed enrollment API.

While connecting the tree, a channel-name allowlist proved insufficient:
a registered name alone did not establish that the channel belongs to the
proposed child. Trusted channel pins now bind recipient principal and instance
generation, checked against the signed descriptor. Transport dispatch must
later consume the same pins. No runtime destinations or provider semantics are
added to the protocol.

Nine new tests include native root → A → B → C enrollment, stale snapshot
revocation, replay/principal reuse, all retained slots, exact resource ancestry,
channel ownership and hostile serialized-state mutations. Artifact generation
compiled them and passed its one generation test (341 behavioral tests filtered
out in this invocation). The first construction attempt caught two invalid
JSON test-macro expressions, which were corrected. No behavioral test was run
locally or claimed passing. No new formal theorem or full-system guarantee is
claimed.

Remaining immediate work: authenticate initial root enrollment during activation;
embed this tree in the existing locked task state and bind its channels/resources
to installed recipes; cut over read/write admission and entry to the participant
and all-ancestor journal; expose enrollment through native SDKs and exercise
isolated machine/A/B processes. Complete M0–M4 and F01–F16 acceptance remains open.


Run 40581199216 subsequently failed repository preflight on two Clippy findings
in the test-only partition reference (`single_match_else`, `collapsible_if`).
The reference control flow was corrected without changing its transitions.
Targeted `cargo clippy -p auths-gateway --all-targets --all-features -- -D warnings`
passed after also correcting three semicolon diagnostics in the new tree tests.
Downstream execution jobs were skipped by preflight. This is a lint result,
not behavioral acceptance. Proof-coverage reproduction and semantic-inventory
generation also passed; the measured decision closure remains unchanged.

Final gateway closure construction with all features passed its one generation
test (359 behavioral tests filtered out). The gateway source closure and
semantic-freeze inventory were regenerated after the reference/test lint fixes.


## 20. Native root authority bootstrap

The previous goal turn made progress: it pushed `e4bcebcb` with the bounded
enrollment tree and dispatched full CI in
[40583279847](https://github.com/auths-dev/auths-proof/actions/runs/40583279847).
Current hosted evidence confirms generated-artifact classification, repository
preflight and secret scanning passed. Behavioral and formal jobs are live;
this is neither a blocker nor full qualification.

Ledger integration exposed a prerequisite: trusted root pins cannot substitute
for proof that the root controls its named grant and resource authority. The
public tree bootstrap now verifies a root-signed exact activation commitment
and one native resource witness per scope. Each branch must have the pinned
holder and exact grant, with validity and native depth covering the root.
The raw constructor is crate-private. Root and child enrollment share one
bounded-evidence leaf and the maintained native verifier.

The canonical root commitment covers immutable authority and installation,
excluding its own ID and mutable revocation. Callers must still independently
bind the pins to the signed engagement and installed resource/channel policy.
Bootstrap is not a capacity allocation, persistence transaction, public endpoint
or proof of independent human approval. Existing journal/admission paths still
await the direct participant cutover.

Five native bootstrap tests are authored. Gateway closure construction compiled
them and ran its one generation test (364 behavioral tests filtered out).
Construction caught a missing field in an oversized-proof fixture, which was
corrected. No hosted bootstrap behavioral pass is claimed. The next integration must
persist bootstrap and claims under one lock, prevent repeated initialization
from reopening root capacity, and apply all-ancestor accounting at reservation
and entry. Signed root/task association and installed channel enforcement are
required parts of that integration, not assumptions supplied by these tests.


Root bootstrap also exposed a control/resource namespace confusion: a provider
recipe and its matching profile lock could reuse a control service/tool name.
One new classification now owns both native control service constants and
refuses them in the shared recipe-lock validator (covering reads and writes)
and enrollment resource pins. Three negative tests use matching source/lock
substitutions and explicit control-grant resource pins. Ordinary provider
recipes remain positive controls. The existing profile-mismatch code is reused;
no Python/TypeScript protocol wrapper or ABI shape changes. The gateway semantic closure changes with compiler admission; the portable MCP
profile contract and its semantic identity remain unchanged. No provider-specific rule is
introduced. Artifact construction currently compiles all eight new tests while
running only its generation test (367 behavioral tests filtered out).


## 21. First hosted participant behavior and fixture corrections

Run 40583279847 passed preflight, secret/dependency gates, and OpenTofu,
PostgreSQL and records-API live jobs. The authoritative gateway suite reported
318 passed, 16 failed and 26 ignored. All eight partition-reference tests
passed, including randomized histories; that is scoped reference evidence,
not a production state-machine proof. Formal and compliance jobs remain live
at the last observation.

Fourteen enrollment/tree failures stopped at `action-outside-validity`: the
shared signed-action helper uses a two-hour window, while the new fixture's
grants covered a shorter interval. The fixture now issues grants covering that
same action window, keeping product participant windows narrower. The native
verifier's containment rule is unchanged. One child-acceptance test then exposed
an earlier channel-generation refusal: its operator pins now explicitly permit
the proposed new instance, so the test reaches and asserts refusal of the old
child acceptance. Its name now describes its actual generation/ceiling/ID cases.

Two clock failures occurred in the final post-revocation retry assertion. The
clock fault remained active, so the gateway correctly refused on time before
reaching the task state. Tests now assert the clock refusal, restore the clock,
and then assert durable revocation. They additionally verify no new credential
lease or provider entry across retries and no accounting refund.

After inspecting hosted failures, targeted local reproductions passed: **25
participant enrollment/tree/root tests** and **two clock-loss tests**. New root
bootstrap cases share the corrected native fixture and are included in that
local result. The two new provider-compiler namespace tests are compiled but
not yet behaviorally verified. Gateway artifact construction and coverage
reproduction have passed; final source-closure regeneration follows the fixes.
An intermediate semantic-freeze update refused reuse of the same inventory
version after additional changes; final versions advance explicitly instead
of weakening that gate. Full exact-revision CI and all remaining implementation
milestones are still required.

Final artifact construction after these corrections passed: one gateway closure
generation test (367 behavioral tests filtered out), byte-identical coverage
reproduction, and semantic-freeze inventory generation at version 402. Hosted
run 40583279847 also subsequently passed compliance and formal fast feedback;
formal translation and Kani were still running. The full run still fails its
authoritative job, so none of these component successes closes final acceptance.
