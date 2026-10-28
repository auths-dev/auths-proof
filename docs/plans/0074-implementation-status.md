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

The checkpoint sections below are historical records; the phase and acceptance
ledgers at the end describe current closure. Do not treat earlier "pending"
notes as a reason to reimplement a later completed source cutover.

1. Finish independently authorized bounded observation and full native recovery
   actions/charge/evidence projections. Public `Reserved` and zero-provider-I/O
   application replay are now implemented. Preserve immutable
   admission/grant history and the one-use transport boundary already wired.
2. Complete typed acquisition, separate recipient disclosure and exact ACK in
   the existing native owners. Bind and account for all credential-bearing
   ancillary reads. Remove the competing AP070 Python decision owner and cut
   maintained bindings over directly.
3. Finish the installed authenticated review/approval journey. The native
   versioned review contract and literal renderer are now wired; frontend
   capability, transport/channel authentication and failure evidence remain.
4. Add/complete installed authority expiry/revocation/configuration races,
   adapter commit/ack faults and process/transport failpoints, plus differential
   and generated-history evidence for A01–A22. Synthetic native fixtures are
   deliberately narrower evidence.
5. Regenerate final translated/refinement/performance artifacts and observe
   required hosted CI only after implementation, fixtures and documentation are
   complete. No hosted results have been observed yet. Full Todoist pinned-input
   re-execution remains pending, without blocking other implementation work.

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

The configuration checkpoint is committed and pushed as `8dbd9939`. A follow-up
source audit found the PostgreSQL health projection still reported literal schema
6; it now derives the version from the active schema constant. Required semantic
closure regeneration passed after that correction (one artifact-generation test).

## Mutation entry grant checkpoint

- Attempt `/5` now creates `Reserved`; the existing transition owner alone
  permits `Reserved -> EntryGranted` and freezes its private grant audit.
  Post-grant state cannot become `NotEntered`. A restart projects a grant to
  unknown while retaining reservations as reservations in the journal.
- The existing step machine requires an acknowledged `GrantEntry` before `Send`.
  The runtime checks native original authority, exact approval, connection,
  configuration, qualification, time and all count/sum slots under one fence.
  Qualification evidence is frozen once to exclude process-local reload races.
  Commissioning checks the current permanent budget against its acknowledged
  pre-custody floor and merges retained revocation state in the same read set.
- Every managed write port, including HTTPS, consumes a sealed one-use permit
  and derives the request from its retained command. An ambiguous commit yields
  no permit. Transport failures after the grant retain unknown, even before send.
- Native `effect-entry.json` generation passed on `3cbe3ad8` plus this source:
  one file-backed grant, stale second-grant refusal, immutable audit and
  crash-before-send projection. The generator also emits valid native stage and
  transition fuzz seeds; previous-schema seeds are retained as negative inputs.
  This synthetic post-verification corpus does not prove installed authority.
- Updated attempt-scenario and final semantic-closure generators passed. Native
  CLI approval-envelope generation also passed and matched the unchanged corpus. New
  file/PostgreSQL concurrent-grant, reducer and property-test source is authored;
  broad suites, installed races, formal gates and hosted CI remain unexecuted.
- P2 remains open: resumable reservations with fresh authority/approval, explicit
  revisions, full private audit/projection treatment, installed clock/revocation
  races and all persistence/transport failpoints. Formal translated output must
  be regenerated against the changed shipping predicates. P3/P4 and all complete
  acceptance gates remain open. No AP073 or delegation work was performed.

## Reservation restart and revision checkpoint

- Attempt `/6` adds a required revision bounded to exact JSON integers. The
  shipping transition predicate requires exactly one increment for every update,
  rejects stale/skipped revisions and fails closed at saturation. CAS still
  compares the complete previous bytes; the revision is not a rollback anchor.
- An equal binding in `Reserved` can reopen without replacing its initial
  approval, claim, first checkpoint or count/sum slots. Existing grants and
  terminal records remain replay; changed full bindings remain conflicts.
  Reopening produces no transport capability.
- Grant audit `/2` freezes the approval actually used, its fresh authorization
  start time, grant revision and fresh pre-entry evidence. The grant rechecks
  current native authority under the fence using the resumed submission's
  deadline. Historical admission approval remains immutable, and post-grant
  snapshots expose the reads used for that grant.
- Required native `effect-entry.json` generation passed on `fd8803c0` plus this
  source: `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact
  store::entry_tests::native_entry_fixture_is_current` (one generator test).
  The expanded synthetic file-backed sequence exhausts its count/sum capacity,
  checkpoints, reopens after the initial approval and submission deadline expire,
  refuses stale deadline/approval, grants once with fresh evidence, retains the
  original slots and audit, and refuses another grant. Canonical stage/transition
  fuzz seeds were regenerated. This is not installed proof or provider evidence.
- Attempt-scenario and semantic-closure artifact generation also passed (one
  generator test each). Remote artifact commit `8201545d` was preserved before
  final closure generation. No broad suite or hosted workflow was observed.
- Equivalent PostgreSQL restart source is authored, not executed. Public pending
  projections, independent recovery authorization, installed fault/race evidence,
  acquisition/disclosure/ACK and translated formal artifacts remain open.

## Native review-contract checkpoint

- Recipe source `/3` requires `auths.effect-review-contract/1`; source `/2`
  is refused. Every non-binding profile argument must have one compatible
  presentation, with a bounded trusted label and explicit unit for integers.
  Native binding fields, exact destination/request, installation, reservations,
  limits, recovery declarations and uncertainty are always present in private
  review. Consequences are mandatory operator-owned recipe data. The gateway
  performs no provider-name inference or unit conversion.
- Recipe review `/3`, private effect review `/2`, private signing output `/2`
  and effect compiler `/3` make the cutover explicit. Review semantics participate
  in the recipe digest and effect identity. There is one native full-value
  renderer (`auths.literal-complete-review/1`), bounded to 1 MiB. It emits literal
  ASCII JSON, escapes control/bidi/Unicode content, never interprets markup,
  and refuses unknown renderer versions or oversized output. The CLI publishes
  signing-request files only after complete local review output succeeds.
- Native required artifact generation passed on `6d38bb1c` plus this source:
  `recipe::tests::native_review_contract_fixture_is_current` and
  `observed_tests::effect_native_tests::native_compilation_approval_and_reverification_keep_exact_request`
  (one generator each). The former emits valid recipe fuzz seeds and exact
  negative review inputs for missing fields/consequences, unsupported version,
  wrong type, control labels and duplicate fields. The latter includes a hostile
  bidi/content sentinel, lossless literal-render round trip and renderer refusal.
  These establish native compilation/presentation only, not installed human
  approval or human understanding. Entry and semantic-closure generators passed.
  Native CLI approval-envelope construction passed and matched the regenerated
  signed effect corpus exactly; it also compiled the updated binary.
- OpenAPI derivation emits a source `/3` draft with incomplete consequences and
  integer units. It cannot compile until an operator supplies those facts.
  Derivation tests use explicitly synthetic declarations for transport comparison;
  they do not turn descriptions from an untrusted document into review authority.
- OpenAPI corpus artifact generation completed for local documents and pinned
  GitHub/OpenAI inputs. Todoist's current URL does not match its pinned bytes;
  the two full-vendor cases were explicitly skipped during generation. Its
  derived recipe/review/output commitments were updated from the native-generated
  excerpt after verifying the previously committed vendor and excerpt recipes
  and profiles were byte-identical (the corpus requires this equivalence).
  Existing vendor provenance remains unchanged. Full pinned-vendor re-execution
  is pending; no digest pin was changed and ordinary configured verification
  still fails for missing/mismatched files. Inputs retained for later generation:
  `/tmp/auths-ap074-openapi-inputs` (GitHub/OpenAI only).
- Remaining review work is the installed authenticated approval-channel journey,
  supported frontend rendering and failure boundaries, privacy checks, and
  cross-language/installed evidence. P2–P4 remain open and no complete A01–A22
  acceptance claim follows from this checkpoint.

## Replay projection checkpoint

- Application replay of a granted or terminal effect now reads only its full
  matching native binding and returns the retained journal outcome. It never
  enters the credential/observation path. A reserved effect remains resumable
  only through fresh approval/authority and the single-winner grant already
  implemented. Changed bindings remain explicit conflicts.
- The public native result adds `reserved` and its bounded journal revision.
  An unacknowledged grant reloads the journal: pre-grant state is reserved,
  committed grant state is unknown, and unavailable/corrupt state is
  indeterminate (`gateway.attempt.state-unavailable`). None returns a permit.
  Python and TypeScript decode the native variant; they do not decide recovery.
- Native `replay-projection.json` artifact construction passed on `ed907973`
  plus this source using `scenario_tests::native_replay_projection_fixture_is_current`.
  It drives the real file store and submission driver with a synthetic command
  oracle, concurrent reopened-store replay, pre-commit failure, post-commit lost
  acknowledgement and unavailable reread. Counts show zero replay custody/read/
  write calls and no journal change. It also constructs native valid/invalid
  reservation decoding cases consumed by authored binding tests.
- Qualification execution forbids replay leases and new confirmation credit.
  Maintained family corpora, live harness expectations and examples now distinguish
  historical outcomes from binding conflicts. Retained operator observation tests
  explicitly invoke that path rather than using replay. That existing operator
  path, automatic post-write reads and other ancillary reads still need independent
  bounded native acquisition authority/accounting; this checkpoint does not close
  A11/A15, installed bindings, full adapter faults or the authenticated journey.
- Attempt-scenario, stable-code, custody and final semantic-closure corpus
  construction also passed via their exact native artifact generators. Binding tests, broad conformance,
  translated formal artifacts and hosted CI are not yet executed. No AP073 work
  or delegation occurred.

## Independent recovery compilation checkpoint

- Bound-effect `/3` and compiler `/4` use one sealed mutation/acquisition sum,
  one native verifier, one exact approval and one complete private renderer.
  Fixed-window mutation reservations remain fixed; source-lifetime read
  reservations declare separate attempt-count and response-byte obligations.
- A protected observable journal record supplies the source identity, exact GET,
  response-derived locator when available, projection and echo. The new native
  read call binds that contract and a distinct read operation. Fresh reader
  authority is independent of the source writer. Mutation recipes cannot claim
  the reserved native recovery-read tool, and mutation admission rejects reads.
- Installed `effect-recovery-call` authors the private native call;
  `effect-review --recovery-of` compiles its independently signed proof using
  current installed configuration, connection and deployment time. Both are
  effect-free: no credential lease, provider read, reservation or journal update.
- Required `native_recovery_acquisition_fixture_is_current` generation passed:
  real signed native proofs and file-derived source target; expired writer,
  distinct reader, exact read review/approval, approval expiry/substitution,
  changed source/contract/limit/namespace/operation refusal, reserved mutation
  tool refusal, mutation-admission refusal and unchanged source journal. The
  source grant uses a synthetic oracle and performs no provider send. This is
  compilation evidence, not installed recovery execution or A15 closure.
- Mutation binding, entry, attempt-scenario and stable-code native artifact
  generators passed. Native CLI approval-envelope construction passed and
  matched the regenerated signed corpus exactly. These runs used `eb3c31fb`
  plus this compiler source; remote artifact commit `31a825d0` was inspected and
  preserved by fast-forward. After the final boxed protocol representation,
  recovery compilation and `semantic_closure::tests::semantic_closure_is_current`
  generation both passed on `31a825d0` plus this source (one generator each).
- Acquisition admission, conserved charging, fenced entry, evidence freshness
  and transport remain unwired. The compiler currently refuses changed source
  connection/generation and managed bounded-policy extensions; safe credential
  replacement and enforcement of read-policy bounds are still required work.
  Existing direct operator re-observation and all ancillary reads still need
  replacement. No full acceptance gate, broad local suite or hosted CI is claimed.

## Recovery acquisition journal checkpoint

- Attempt journal `/7` has one common immutable header, approval history, entry
  audit and codec with closed mutation/acquisition state alternatives. Both
  protocols use the existing kernel transition predicate and adapter fence.
  Acquisition cannot acquire mutation observation facts or change protocol.
  Support bundle `/2` projects protocol and stage separately.
- Recovery admission atomically inserts the read claim and one permanent
  `auths.effect-allocation/1` slot charging one invocation and the bound maximum
  response bytes. All read IDs share the source's 16-slot capacity. Equal replay
  retains the original allocation; exhaustion records an uncharged refusal;
  sweeping never refunds source-lifetime allocation. PostgreSQL source schema
  `/8` admits this non-expiring kind; obsolete disposable schemas are rejected.
- A read grant fences the read record, exact observable source, allocation and
  installed authority/configuration/connection dependencies. Only acknowledged
  persistence returns a one-use read permit. Lost permits project unknown and
  cannot be reconstructed. Bounded response bytes remain private; public facts
  distinguish acquisition response from mutation observation and disclosure ACK.
- `GatewayEngine::acquire_recovery` now connects native read approval, admission,
  custody, final grant, permit-consuming transport and response recording.
  Recipes needing additional credential reads fail closed until those reads
  have their own acquisition accounting. No application/operator execution route
  or source-evidence refinement has been cut over by this checkpoint.
- The native recovery artifact generator passed on `964764f2` plus this source:
  real signed reader proofs, file journal, repeated reservation without charging,
  single grant and stale contender refusal, reopen after permit loss, concurrent
  competition for the last 15 of 16 slots, no sweep refund, bounded private
  response/replay and mixed-protocol support projection. Entry validation and
  provider response are synthetic. This is not installed authority, actual
  provider transport, independent-process or PostgreSQL execution evidence.
- Mutation entry/replay, attempt scenarios, stable/production codes, custody and
  qualification schema/verification artifact generators also passed on this
  source. Native mutation binding and final semantic-closure construction passed;
  CLI approval-envelope construction matched the signed corpus exactly. The new
  kernel protocol negative tests and revised Kani oracle are
  authored, not executed. Translated formal artifacts and hosted CI remain open.
- Still required: admission/current-configuration ordering, safe replacement
  credentials and managed read-policy bounds, freshness-bound refinement of the
  source, all ancillary read cutovers, typed disclosure/ACK, authenticated UI and
  bindings, installed fault/race evidence and final formal/CI gates. No A01–A22
  acceptance criterion is closed by this checkpoint.

## Phase gates

| Phase | State | Outstanding gate |
| --- | --- | --- |
| P0 | Owner decision and limits documented | Keep consumer inventory current during cutover |
| P1 | Binding, approval and native review contract wired | Installed authenticated approval journey, frontend rendering and integration evidence |
| P2 | Mutation grant and reservation restart wired | Public projections, independent recovery, installed fault/race evidence and formal links |
| P3 | Recovery acquisition journal and runtime entry wired | Ancillary read/source-evidence cutover, disclosure/ACK; remove Python semantic owner |
| P4 | Pending | Differential/local journey, installed bindings, formal links, CI |

## Acceptance ledger

`Authored` means scenario source exists, not that it passed. `Executed` requires
the exact tested revision and a reproducible result. External qualification is a
separate claim. No AP074 acceptance case is currently executed or qualified.

| Case | Required evidence | Implementation / authored / executed | Limitation or next work |
| --- | --- | --- | --- |
| A01 | Same bound identity and exact request across review/approval/send | Partial / partial / native fixture only | Installed transport and review-completeness evidence pending |
| A02 | Independent mutation of every binding dimension | Pending / no / no | Freeze canonical corpus |
| A03 | Concurrent/restart replay, conflict, approval reuse | Partial / adapter cases / no | Execute concurrent binding conflicts and recovery cutover |
| A04 | Final count/byte/sum capacity, file and PostgreSQL | Partial / partial / narrow file fixture | Full adapter concurrency and all units pending |
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
| A15 | Recovery actor differs; original authority revoked | Partial / native compiler and file journal / synthetic entry only | Source refinement, revocation and installed execution |
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
