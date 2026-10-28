# AP-SPEC-074 implementation and evidence ledger

## Durable goal

Implement all of [AP-SPEC-074](../specs/0074-bound-effects-and-recovery-state-machine.md)
in this checkout, on `codex/effect-recovery-foundation`. Finish the immutable
native bound effect and the gateway's sole recovery/transaction owner, including
mutation, bounded acquisition, separate recipient disclosure, exact approval,
fresh entry authorization, immutable evidence and truthful native projections.
Cut maintained consumers over directly; remove competing managed decisions.
Preserve the native verifier, reviewed recipe compiler, conservative recovery,
durable adapter guarantees and source-linked formal claims.

Complete P0–P4 and A01–A22 with actual transport, process restart, file and
PostgreSQL concurrency/fault evidence, differential recipes, installed bindings,
formal/refinement links and bounded performance measurements. Commit coherent
changes. Finish source, fixtures and documentation before pushing explicitly to
`origin codex/effect-recovery-foundation`, opening a draft PR against main and
observing required hosted workflows on the exact head. Repair failures; do not
merge or deploy. Local generation needed to construct artifacts is permitted;
do not duplicate hosted build/test/lint/formal gates before the first push.

Never touch the paused AP073 checkout or import its unfinished implementation.
Do not expand participant trees, federation, token systems or agent delegation.
No stage is complete merely because types, documentation or a happy path exist.

## Baseline and working record

- Implementation started 28 October 2026 from clean HEAD
  `ec7defb3dbcee1fdcc2839989bdbc4d9110a912d` (specification/handoff commits over
  the specified main baseline `e2d10a74fa0be5e6bfe2b9f698632c835cd7b11b`).
- Read repository contract, mandatory abstraction plan and full specification.
- No AP073 files inspected or changed. No subagents dispatched.
- Existing source inspected: native sealed action, gateway verifier/compiler,
  submission driver, transition/recovery leaves, file/PostgreSQL attempt store,
  lifecycle preparation/acknowledgement contracts, AP070 admission/executor/receipt.
- Verification: no tests, builds, lint, formal gates or hosted workflows run yet.

## Phase gates

| Phase | State | Outstanding gate |
| --- | --- | --- |
| P0 | Owner decision and limits documented | Keep consumer inventory current during cutover |
| P1 | Pending | Native binding, approval and complete first mutation cutover |
| P2 | Pending | Explicit reservation/grant reducer, atomic fencing, both adapters |
| P3 | Pending | Native acquisition/disclosure/ACK; remove Python semantic owner |
| P4 | Pending | Differential/local journey, installed bindings, formal links, CI |

## Acceptance ledger

`Authored` means scenario source exists, not that it passed. `Executed` requires
the exact tested revision and a reproducible result. External qualification is a
separate claim. No AP074 acceptance case is currently executed or qualified.

| Case | Required evidence | Implementation / authored / executed | Limitation or next work |
| --- | --- | --- | --- |
| A01 | Same bound identity and exact request across review/approval/send | Pending / no / no | Cut over mutation |
| A02 | Independent mutation of every binding dimension | Pending / no / no | Freeze canonical corpus |
| A03 | Concurrent/restart replay, conflict, approval reuse | Pending / no / no | Full binding comparison |
| A04 | Final count/byte/sum capacity, file and PostgreSQL | Pending / no / no | Atomic journal admission |
| A05 | Crash at every persistence/transport boundary | Pending / no / no | Process failpoint journey |
| A06 | Sync/rename, partial batch, ambiguous commit/CAS | Pending / no / no | Fault injection |
| A07 | Revoke between acquisition and disclosure | Pending / no / no | Separate disclosure gate |
| A08 | ACK loss, restart, no redelivery, late ACK | Pending / no / no | Typed ACK protocol |
| A09 | ACK substitution in every dimension | Pending / no / no | Authenticated exact ACK |
| A10 | Timeout/denial/response/state-match distinction | Pending / no / no | Native projection |
| A11 | Missing/multiple/unrelated/incomplete reconciliation | Pending / no / no | Bounded independent observation |
| A12 | Revocation/configuration races with both entries | Pending / no / no | Shared transaction order |
| A13 | Lock wait and independent evidence expiries | Pending / no / no | Clock/full verifier inside boundary |
| A14 | Valid threshold selection changes | Pending / no / no | Pin selected evidence |
| A15 | Recovery actor differs; original authority revoked | Pending / no / no | Separate recovery authority |
| A16 | Cross-task/recipe/partition substitution | Pending / no / no | Scope and epoch binding |
| A17 | Sentinel privacy across errors/logs/public bindings | Pending / no / no | Private audit/public separation |
| A18 | Canonical/malformed/duplicate/limit binding corpus | Pending / no / no | Native codecs/thin wrappers |
| A19 | Stripe/Airtable and acquisition/disclosure differential | Pending / no / no | Retained independent references |
| A20 | Generated histories and shipping predicate refinement | Pending / no / no | Update linked artifacts |
| A21 | Tombstones, stale state, supported rollback floors | Pending / no / no | Epoch/retention evidence |
| A22 | Installed single-human/single-agent full journey/UI | Pending / no / no | Native runtime and local sockets |

## Deployment assumptions retained

Durability relies on acknowledged filesystem sync/rename and PostgreSQL commits.
Neither an in-memory test nor a Rust permit establishes malicious-process
isolation. Provider state matching does not establish exclusive causation.
Recipient authentication is a transport assumption. Whole-store rollback is
outside the guarantee without an independent monotonic anchor; a restored
database cannot attest to its own freshness. No new live-provider qualification
or deployment claim is made by AP074 source work.
