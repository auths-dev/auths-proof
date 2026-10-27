# AP-SPEC-073: Initial implementation assessment

- **Status:** M0 source trace and acceptance inventory recorded; first bounded delegation change implemented, verification pending. M0–M4 remain incomplete.
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
- [ ] Write budget conservation and revocation/entry histories before selecting a new admission API.
- [ ] Inventory time provenance, storage ordering, canonicalization, and configuration-sensitive caching; identify repeated interpretations that deserve central ownership.
- [ ] Specify the smallest identity lifecycle profile for the representative flow, including compromise/recovery consequences.
- [ ] Select the initial provider and deployment boundary, reusing an admitted execution family.
- [ ] Produce a retain/strengthen/replace/remove decision per affected subsystem, with evidence and affected invariants.
- [ ] Select the first bounded implementation change and its required ADR, fixture, formal, compliance, and hosted CI updates.

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
| F07 | Qualification clock contract and explicit kernel evaluation time (source). | WebAuthn UV evidence currently uses evaluation time in its assurance event; audit provenance before claiming freshness. A test clock is not sufficient evidence. |
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

Next: verify the first change, then finish the participant/initiator/approver and atomic budget/revocation contracts before extending the task schema. Continue the time, binding, persistence and cache audit; do not replace those systems by inference from this narrow delegation change.
