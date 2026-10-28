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
changes. The user's subsequent instruction on 28 October overrides the initial
push timing: commit the current slice, push explicitly to
`origin codex/effect-recovery-foundation`, open a new draft PR against main, then
continue with incremental commits. Finish source, fixtures and documentation
before observing required hosted workflows on the exact head. Repair failures; do not
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
- P0 committed as `43832adc`.
- P1 source: canonical private binding, native evidence-selection commitment,
  effect-free mutation compilation and separate exact Ed25519 human approval.
  Native signature validation does not replace resource authority or live entry.
- Source tests authored for identity mutations, canonical/duplicate/limit cases,
  approval substitution/expiry and a real native signed-proof compilation path.
- Draft PR: https://github.com/auths-dev/auths-proof/pull/213, initially pushed at
  `005dfd42`. GitHub connector PR creation lacked permission; authenticated `gh`
  created the draft. No workflow results have been inspected.
- The targeted native fixture-generation test completed with one passing test
  after correcting an invalid empty precondition declaration in the test recipe.
  Command: `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact observed_tests::effect_native_tests::native_compilation_approval_and_reverification_keep_exact_request`.
  Artifact: `bindings/fixtures/gateway/effect-binding.json`. This run used
  `005dfd42` plus the committed null-precondition fixture correction; its scope
  is compilation, canonical round-trip and exact approval, not A01 completion.
  This local run constructs the required canonical artifact; it is not a broad
  pre-push verification run. No hosted workflows observed or formal gates run.
- Initially the new effect module was not connected to submission. The installed
  approval cutover below now replaces that proof/action-only interface. P1 is
  still open for review completeness, full binding persistence and integration
  evidence; the existing reservation/entry lifecycle has not been replaced yet.
- Added entry validation over the retained original proof/action. It re-runs the
  full verifier, compares the complete newly compiled binding, and checks the
  original human approval at the supplied transaction time. The installed exact
  approver policy is itself in the effect identity. The same native fixture
  generation test passes after this change, including independently expiring
  resource authority while human approval remains current. Transactional wiring
  and fencing are still pending; this API alone makes no linearization claim.
- Native private review now renders the sealed command through the same
  projection as offline recipe review. It carries the exact effect identity and
  canonical binding; no binding/UI request reconstruction is needed. Review
  data explicitly contains private content and has a separate 128 KiB limit.
- Spec hardening committed and pushed as `c75e16ba`: deployment containment,
  review completeness, concrete fencing requirements, compositional properties,
  operational recovery and the future delegation boundary.
- Required operator `EffectPolicy` now pins partition, epoch and approver. The
  engine constructor validates it; installation `/6` and operator attestation
  `/2` require and authenticate it. Native `effect-policy` emits canonical
  configuration; `install` and `operator-request` require `--effect-policy`.
  `GatewayEngine::compile_effect` reads the installed connection and deployment
  clock without provider I/O, custody or reservation. Entry fencing and replacing
  the baseline submission path remain pending.
- Native fixture generation passed again while producing `effect-policy.json`,
  including the private-review assertions previously authored but unexecuted.
  Policy refusal and operator-attestation substitution cases are authored, not
  yet executed. No hosted workflows have been observed.
- Maintained install callers now pass explicit policy input. Synthetic operator
  rehearsal uses the native synthetic fixture; live rehearsal and example
  journeys require operator-selected policy files. The production reference
  journey requires `AUTHS_QUALIFICATION_EFFECT_POLICY` before infrastructure or
  provider work. Live approval-channel integration remains pending; no synthetic
  approver is installed implicitly into a live journey.
- The installed mutation and commissioning APIs now require native exact effect
  approval. The shared driver owns `ApprovedEffect`, accesses its single sealed
  command, and revalidates original proof/approval against prepared configuration
  before claim and before send. Its clock now uses the existing deployment clock.
  These checks are not a transaction fence. Full binding is not yet persisted in
  the attempt journal; ancillary reads and replay observation still need their
  separately authorized acquisition/recovery cutover.
- Application socket `/2` requires bounded canonical approval bytes; `/1` and
  missing approvals are rejected. Python/TypeScript wrappers carry those native
  bytes without hashing or signing. Private `effect-review` and `effect-approval`
  CLI commands expose native review/signing data and canonical envelope assembly.
  Source tests cover obsolete/missing/oversized frames and installed wrong-signer
  or expired approval with zero custody/transport calls; these tests are authored,
  not executed. Test-only post-verification driver oracles use explicitly synthetic
  approvals and establish no human or installed-authority claim.
- The targeted native generator passed while constructing the `/2` frame and
  `effect-approval-request.json`. Running the native CLI to construct
  `effect-approval.json` succeeded and its bytes equal the native signed corpus.
  This artifact construction also compiled the gateway binary. No broad local
  suite or hosted workflow was run/observed. Installed binding journeys, example
  proof preparation/review, qualification consumers and semantic closure/formal
  regeneration still require updates for the new approval round trip.

## Immediate implementation continuation

The specification hardening pass adds explicit deployment non-bypassability,
versioned review completeness, adapter-specific fencing, six compositional
safety obligations, bounded operational recovery and a future AP073 composition
boundary. These strengthen A01/A02/A04/A06/A11–A13/A15–A18/A20–A22 without
claiming new executed evidence. The existing review and revalidation APIs do
not yet meet review-completeness or transactional-fencing gates. The adapter
mechanism remains an explicit open decision in ADR 0017 before P2 cutover.

1. Complete the versioned semantic review contract and full operator review round
   trip in maintained consumers. Installed submit and commissioning now require
   exact approval, but the native raw review projection does not yet establish
   the newly required mandatory-field presentation contract. Update installed
   binding tests and example/qualification authoring so original proof bytes are
   preserved from review through submission; never synthesize human approval in
   an ordinary application wrapper.
2. Store the complete immutable binding in the existing attempt journal, with
   replay keyed independently of the effect digest. Reuse the approved effect's
   single owned command for send and reporting; reject changed binding as conflict.
3. Refactor the existing transition/order owner to distinguish reservation from
   durable entry. The current `Attempting` state must not remain the authority
   for both. Validate full native authority and exact approval after acquiring
   the store transaction lock; fence connection/configuration against the same
   transaction. Publish consumed permits only after durable acknowledgement.
4. Then finish acquisition/disclosure/ACK and AP070 direct cutover, installed
   bindings, adapter fault/concurrency/process evidence and formal links.
5. Regenerate semantic closure and all affected canonical/formal artifacts once
   source stabilizes. Required hosted workflows have deliberately not been
   observed yet. The draft's current CI is not completion evidence.

The native artifact-generation run last passed for `7c79532a` plus the installed
approval and native signing/frame fixture changes recorded above. CLI canonical
envelope generation then passed against that same native corpus. These cover
compilation, canonical policy/binding, private review and exact approval data,
not installed transport or transactional admission. Subsequent refusal tests
and input-zeroization edits are source-authored only. All unfulfilled AP074 gates
remain open, and the goal remains active.

## Full-binding journal cutover (in progress)

- Mutation admission now receives the sealed `ApprovedEffect`; the unchecked
  request-only claim helper exists only under test/testkit compilation.
- Attempt schema `/4` persists canonical full binding and original exact signed
  approval in the immutable fixed fields. Historical signature validation and
  redundant namespace/operation/action/recipe checks reject corrupt state.
- The sole replay key includes installed namespace, partition and epoch plus
  operation ID, and deliberately excludes the effect digest. Full binding
  collisions produce `gateway.effect.operation-conflict`; equal bindings remain
  replay even when approval is renewed. Neither replaces the initial bytes.
- Every installed CLI store open receives operator policy; the engine rejects
  a different store policy. Existing native budget counter identities remain
  unchanged so new operation epochs do not reset grant capacity.
- File reads now limit bytes before allocating/decoding records and rollback
  files. This is a read bound, not yet the required bounded lock/transaction.
- Shared file/PostgreSQL conformance source adds restart, changed selected
  authority/recipe/action, renewed approval, partition/epoch isolation and
  original-byte preservation checks. These new behavioral cases are authored,
  not executed. Existing reference expectations distinguish conflict from replay.
- Required local artifact generation passed for `cd3a3448` plus this journal
  source: `pending_vectors::attempts::attempt_scenarios_v3_are_current` (one
  test) and `observed_tests::effect_native_tests::native_compilation_approval_and_reverification_keep_exact_request`
  (one test), each via `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact ...`.
  The native corpus now includes the canonical scoped operation key. Native CLI
  envelope generation also passed after correcting its policy type import;
  output remains byte-identical to the native approval corpus. No hosted CI, broad local suite, formal gate or actual adapter conformance run is claimed.
- P1 still needs semantic review completeness and integration evidence. P2
  still needs atomic fencing and a consumed permit. Identical replay's existing
  observation path must be replaced by independently authorized bounded recovery;
  the updated reference cases do not establish that future contract.

## P2 fence preparation

The concrete fence design is recorded in ADR 0017 before entry behavior changes.
File and PostgreSQL adapters now expose one bounded snapshot-and-replace
operation. All PostgreSQL gateway mutations acquire the same table-scoped
advisory transaction lock, including connection updates and allocation sweeps.
File locking uses the existing shared writer lock with bounded acquisition.
The native decision runs once under that lock, before durable replacement; a
callback failure, deadline or ambiguous commit returns no acknowledgement.
The API cannot itself issue an entry permit.

Read sets are bounded to 64 distinct records with a non-expiring first target.
File reads use lock-held helpers to avoid recursive lock acquisition.
PostgreSQL uses READ COMMITTED snapshots after acquiring the lock, retains
sorted batch insertion and explicitly commits replacements and sweeps. Two-second
lock/decision bounds preserve tighter installed SQL timeouts; sub-millisecond
pool values are rejected instead of rounding to disabled timeouts.

The shared conformance source now races each of replacement, insertion and
sweeping against a held fence, checks the next snapshot sees the predecessor,
and checks a refused decision preserves the target and is never retried.
These tests are authored but not executed. Required semantic-closure artifact
generation passed after fixing an error-type inference ambiguity introduced by
the store error conversion; it compiles the source but does not exercise these
adapter races. Final regeneration after the millisecond-bound correction also
passed: `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact semantic_closure::tests::semantic_closure_is_current` (one artifact-generation
test), on `96e47805` plus this fence source. This is compilation/artifact evidence,
not execution of file/PostgreSQL conformance or final-entry behavior.

Remaining P2 work: shared configuration/revocation record and every writer's
participation, Reserved/EntryGranted reducer and immutable audit event, checking
all reservation membership and final native authority under the fence, and
issuing/consuming a permit only from a new acknowledged transition. The old
Attempting send path is not represented as compliant final entry.

## Shared configuration checkpoint

- Added the non-expiring shared configuration record and PostgreSQL schema `/7`.
  Its installed pin covers recipe, trust, effect policy, connection/workload,
  profile, qualification contract and compiled semantic closure. Bound-effect
  `/2` and compiler `/2` bind that pin; obsolete binding formats are refused.
- Trusted installation initializes the record. Explicit native operator review
  and activation require both candidate identity and the exact prior revision.
  Activation and qualification publication share the adapter writer fence.
- Shared qualification memory monotonically retains sequence/time floors and
  revoked signers/qualifications across restarts and configuration changes.
  Bounded-set or revision saturation persists denial, never authorization with
  forgotten entries. Hosts with a different bundle or installation fail closed.
- Compilation and entry preparation use early shared checks. These are not the
  final grant transaction. Reserved/EntryGranted, audit facts, reservation
  membership checks and consumed transport permits remain outstanding.
- File/PostgreSQL source conformance covers missing state, stale hosts, competing
  revision tokens, restart, permanent revocation and saturation. These behavioral
  tests are authored, not executed. Qualification test callers now publish
  operator reloads explicitly instead of mutating only their process cache.
- Required artifact generation passed on `4e0f435d` plus this configuration
  source: `configuration::tests::native_configuration_fixture_is_current`,
  `vectors::schemas::schema_vectors_are_current` and
  `vectors::verification::verification_vectors_are_current` (one test each).
  The native CLI regenerated `effect-approval.json` byte-identically to the
  binding corpus and compiled the updated binary. Final source-closure generation
  `semantic_closure::tests::semantic_closure_is_current` passed (one test).
  These are artifact construction, not adapter race, formal or hosted CI evidence.

## Phase gates

| Phase | State | Outstanding gate |
| --- | --- | --- |
| P0 | Owner decision and limits documented | Keep consumer inventory current during cutover |
| P1 | In progress | Finish installed first mutation cutover and native fixtures |
| P2 | Adapter and shared configuration implemented | Reservation/grant reducer and fenced permit wiring |
| P3 | Pending | Native acquisition/disclosure/ACK; remove Python semantic owner |
| P4 | Pending | Differential/local journey, installed bindings, formal links, CI |

## Acceptance ledger

`Authored` means scenario source exists, not that it passed. `Executed` requires
the exact tested revision and a reproducible result. External qualification is a
separate claim. No AP074 acceptance case is currently executed or qualified.

| Case | Required evidence | Implementation / authored / executed | Limitation or next work |
| --- | --- | --- | --- |
| A01 | Same bound identity and exact request across review/approval/send | Partial / partial / compilation-only | Execution cutover pending |
| A02 | Independent mutation of every binding dimension | Pending / no / no | Freeze canonical corpus |
| A03 | Concurrent/restart replay, conflict, approval reuse | Partial / adapter cases / no | Execute concurrent binding conflicts and recovery cutover |
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
| A16 | Cross-task/recipe/partition substitution | Partial / adapter cases / no | Full task-scope and installed boundary evidence |
| A17 | Sentinel privacy across errors/logs/public bindings | Pending / no / no | Private audit/public separation |
| A18 | Canonical/malformed/duplicate/limit binding corpus | Partial / native tests / native valid fixture only | Binding parity and negative corpus pending |
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
