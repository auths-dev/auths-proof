# AP076 implementation and evidence record

Objective: implement every requirement of [AP-SPEC-076](../specs/0076-explicit-state-ownership-and-concurrency.md),
obtain successful GitHub CI on the completed revision, and merge that revision.
Partial batches do not close this objective.

Baseline: `2fa22cc350956a82fe0e770d456f4455e58b6f6c` (merged PR #216).
Branch: `codex/explicit-state-ownership-spec`.

## Current authoritative status

No verification result is claimed yet. Approval/exporter implementation and
regressions are being assembled as one batch before hosted verification.
SDK lifecycle, payload and administrative-recovery work remain required.

| Requirements | Implementation / test owner | Evidence disposition |
| --- | --- | --- |
| A1–A6; sections 4–5 | TypeScript `approvals.ts`, `internal/approval-operation.ts`, `test/helpers/approval-state-contract.mjs`; unit and installed-package consumers | Candidate implementation/tests written; GitHub verification pending. |
| B1–B4; section 6 | `auths-operations-otel/src/exporter.rs`, `exporter/tests.rs` | Candidate implementation/tests written; GitHub verification pending. |
| C1–C7; section 7 | Python and TypeScript client, attached-agent, identity and transport owners | Not implemented. |
| D1; section 8.1 | Submission phases and mutation-journal payloads, native differential corpus | Not implemented. |
| D0; section 8.4 | Administrative-recovery protocol, command/transition and durability/interruption matrices | Design incomplete; no runtime recovery cutover yet. |
| D2–D4; sections 8.2–8.3 | Installation, candidate publication, retirement, qualification import; file/native backend evidence | Not implemented. |
| P1; section 10 | Root `AGENTS.md` explicit state ownership and stateful change checklist | Policy text added; per-batch evidence and final audit pending. |
| Section 11; user objective | Completed-source CI, PR state and merge commit | No PR or merge result claimed. |

## Verification discipline

Follow root AGENTS.md: finish each coherent implementation/test batch, push it,
and use GitHub CI as the first default verification. Collect hosted failures
together before bounded local diagnosis and a coherent repair. Do not replace
required checks with narrower checks, or count intentionally gated production
qualification as established by this engineering work.

## Completion audit

Before merge, inspect every specification requirement and gate against current
source, tests, fixtures/manifests, hosted job results and PR head identity. Update
this record with exact evidence and unresolved limitations. A successful initial
batch does not prove the unimplemented batches or satisfy the whole objective.
