# AP076 implementation and evidence record

Objective: implement every requirement of [AP-SPEC-076](../specs/0076-explicit-state-ownership-and-concurrency.md),
obtain successful GitHub CI on the completed revision, and merge that revision.
Partial batches do not close this objective.

Baseline: `2fa22cc350956a82fe0e770d456f4455e58b6f6c` (merged PR #216).
Branch: `codex/explicit-state-ownership-spec`.

## Current authoritative status

[PR #217](https://github.com/auths-dev/auths-proof/pull/217) contains the complete
candidate implementation at `0045219ed61ca5790b9fe1510bec212cda81d260` and a
collected repair batch. The initial approval/exporter cohort exposed lint and
error-projection failures. The completed-source cohort additionally exposed the
identity-only dependency closure, synchronous Python construction, Python 3.12
cleanup scheduling, strict typing, and a stale proof-coverage measurement. Each
has a concrete repair; final completed-head checks and merge remain required.

No intermediate revision was pushed while writing the implementation. Hosted
checks on `0045219e` passed gateway isolation, operator packaging, SDK recipes,
recipe qualification, both maintained provider demos and the configured TLS
PostgreSQL cohort. The stalled Python workflow was cancelled rather than left
running; the repair reproduces and fixes its Python 3.12 scheduler behavior.

| Requirements | Implementation / test owner | Evidence disposition |
| --- | --- | --- |
| A1–A6; sections 4–5 | TypeScript `approvals.ts`, `internal/approval-operation.ts`, `test/helpers/approval-state-contract.mjs`; unit and installed-package consumers | Candidate implementation/tests written; initial GitHub cohort failed; final verification pending. |
| B1–B4; section 6 | `auths-operations-otel/src/exporter.rs`, `exporter/tests.rs` | Candidate implementation/tests written; initial GitHub cohort failed; final verification pending. |
| C1–C7; section 7 | Python and TypeScript client, attached-agent, identity and transport owners | Candidate implementation and source/installed-package schedules written; integration audit and final verification pending. |
| D1; section 8.1 | `submit.rs`, `store.rs`, `store/mutation_phase_tests.rs`; retained native mutation, recovery, receipt and file/TLS PostgreSQL corpora | Closed phase payloads and hostile persisted-state corpus written; generated evidence and final verification pending. See [payload ownership](0076-payload-ownership.md). |
| D0; section 8.4 | [AP-SPEC-077](../specs/0077-administrative-recovery-protocol.md) | Concrete authority, command, transition, conflict and durability contract written; implementation acceptance remains separate. |
| D2–D4; sections 8.2–8.3 | `credential_journal.rs`, `connection.rs`, `candidate_runtime.rs`, `engine.rs`, gateway CLI; owners below | Recovery/status/resume, phase-bearing cleanup notes, conservative retirement and qualification recovery written; interruption and competing-operator tests written; final verification pending. |
| P1; section 10 | Root `AGENTS.md` explicit state ownership and stateful change checklist | Policy text added; per-batch evidence and final audit pending. |
| Section 11; user objective | Completed-source CI, PR state and merge commit | Draft PR #217; no merge or successful full-source CI claimed. |

## Verification discipline

Follow root AGENTS.md: finish each coherent implementation/test batch, push it,
and use GitHub CI as the first default verification. Collect hosted failures
together before bounded local diagnosis and a coherent repair. Do not replace
required checks with narrower checks, or count intentionally gated production
qualification as established by this engineering work.

The final-batch bounded reproductions passed the full workspace/all-targets/
all-features Clippy check, TypeScript contract check, unit suite (84 tests),
focused workflow/adapter/lifecycle regression batch (45 tests), and the new
installed-package lifecycle/adapter checks (23 tests). WASM and binding vectors
were rebuilt as prerequisites. The gateway semantic closure, TypeScript public
declarations and semantic freeze are regenerated using their maintained
constructors. The collected repair additionally passes all 57 TypeScript package
tests and the complete Python 3.12 source suite (460 passed, 11 existing skips),
with Python lint and strict typing. The Python reproduction uses a short local
temporary path for macOS Unix sockets. Async lifecycle/workflow tests have an
outer diagnostic bound, and the hosted Python suite has an explicit step budget.
The bounded gateway run exposed an outdated CLI inventory and unpublished
qualification temporaries after process termination. Their complete repair batch
passes the inventory constructor and all six qualification tests, including the
full first/replacement interruption matrix, seeded orphan cleanup and competing
imports. The file-store conformance case initially hit its deadline during the
parallel filesystem batch; its unchanged internal process race passes when run
without unrelated test load. Other gateway targets passed in that diagnostic
batch. No assertion or production deadline was relaxed. Journal/floor content,
file-sync, replacement and parent-sync points are included in the termination
trace. The final acknowledgement repair also passes the candidate interruption
fixture, installation recovery/replay and qualification construction/concurrency
checks, plus gateway Clippy. Its replay test checks both file and parent-directory
synchronization before a new acknowledgement. The full qualification import
matrix remains required on the completed hosted head. These results do not
replace completed-head hosted evidence; acceptance remains tied to the exact
completed-head checks below.


The `4a8ba4d9` cohort passed every supporting SDK, demo, isolation, operator and
TLS PostgreSQL workflow. Its repository gate identified two further roots: the
new rmcp advisory and a managed-interface fixture still listing the old CLI.
The [dependency repair](0076-dependency-repair.md) directly upgrades the official
model dependency, removes unused server features and rejects all newly exposed
continuation fields. Dependency policy, 23 profile tests, WebAssembly compile and
workspace/all-target/all-feature Clippy pass locally. The managed-interface
constructor now records the two recovery help entries; its execution passes.
Architecture, gateway closure, proof measurement and semantic records are
regenerated atomically. The completed-head required CI remains the acceptance
boundary, including the full qualification interruption matrix.

## Concrete evidence owners

Paths in this section are relative to the repository root. Each owner is a
candidate until the completed revision passes its hosted gate.

| Protocol boundary / schedule | Test owner and observable contract |
| --- | --- |
| Approval admission, mutation, invalidation, exact deadlines and rollback | `bindings/typescript/test/helpers/approval-state-contract.mjs`, consumed by unit and packed-package tests: retained request binding, one pending operation and no stale approval. |
| Export cohorts, capacity, joined failure, reentry and unwind | `product/operations/auths-operations-otel/src/exporter/tests.rs`: one owned batch, exact shared outcome and retained unavailable work. |
| Shared opening/closing, private waiter cancellation, overdue cleanup and explicit safe retry | `bindings/typescript/test/helpers/resource-lifecycle-contract.mjs` and `bindings/python/tests/test_resource_lifecycle.py`: deterministic completions and clocks; original generation outcomes remain stable. |
| Public owned/borrowed adapters and active transport use | TypeScript `test/helpers/adapter-lifecycle-contract.mjs` (source and installed package), Python `test_resource_lifecycle.py`: destruction follows real operation settlement and only unresolved safe cleanup repeats. |
| Factory abandonment and attachment publication racing shutdown | TypeScript workflow `test/integration/workflow/{client,attach}.test.js`, packed lifecycle contract and Python `tests/test_workflow.py`: late resources stay owned, no late publication or premature signer destruction. |
| Submission, journal phase payloads, commands, receipts and counters | Gateway `src/store/mutation_phase_tests.rs` plus existing mutation/native-generated-history, recovery, fault, receipt and file/TLS PostgreSQL tests. Canonical wire projection is retained; illegal field combinations reject. |
| Draft, retained inputs, manifest, journal and installation custody/native/floor boundaries | Gateway `tests/qualification_gate.rs::ap076_recovery::installation_recovers_or_explicitly_quarantines_every_interruption_boundary`: trace each boundary, terminate the process, resume exact identity or explicitly quarantine unknown custody creation; repeated status and restart. |
| Acknowledging an exact generation-floor replay after an interrupted prior write | Same module's `installation_replay_acknowledges_floor_sync_after_restart`: interrupt before/after replay synchronization, resume exact inputs and immediately restart. Matching bytes alone never substitute for synchronization acknowledgement. |
| Read-bearing first installation, custody/floor and proposal publication | Gateway `tests/candidate_cli.rs::candidate_installation_fault_matrix`, invoked by the existing first-installation fixture: staging never publishes a native connection; exact replay preserves draft/proposal identity. |
| Candidate acquisition/publication guards, competing operations and lost native acknowledgements | Gateway `src/effect_candidate_tests.rs`, `src/effect_candidate_staging_tests.rs`, native file/TLS PostgreSQL candidate/fault histories: status uses the same guards, native publication retains its existing revision/fence authority. |
| Mutation/deletion write-ahead phases and competing claims | Gateway `src/credential_journal.rs` tests: reopen pending creation/deletion, refuse contradictory transitions and retain unacknowledged obligations. |
| Retirement interval, unknown custody reply, repeated and competing cleanup | Gateway `src/engine.rs::tests::administration` file and configured TLS PostgreSQL administrative recovery contract: hold unknown creation, reload binding after delay, exact deletion only, no custody leases/provider entry. |
| Every first/replacement qualification file/sync/rename and floor boundary | Gateway `tests/qualification_gate.rs::ap076_recovery`: boundary trace + termination matrix, exact bundle re-import/recovery, repeated recovery and restart; native/local revocation memory never regresses. |
| Competing qualification imports and acknowledged restart | Same qualification test module: concurrent identical command processes and stable post-restart projection; retained candidate cannot be replaced by conflicting input. |

Process termination evidence exercises the supported file synchronization model;
it does not simulate physical power loss or establish storage hardware flush
guarantees. Native commit/reply-loss and TLS evidence remain separate required
checks. Neither local resource ownership nor recovery observation grants provider
entry or changes the qualification authority.

## Completion audit

Before merge, inspect every specification requirement and gate against current
source, tests, fixtures/manifests, hosted job results and PR head identity. Record
the exact accepted head and hosted evidence in PR #217's acceptance attestation,
linked above, so recording CI results does not itself change the tested source
revision. This file maps implementation and test ownership; the PR's completed
head checks and merge record determine acceptance. A successful initial batch
does not prove the remaining batches or satisfy the whole objective.
