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

## Recovery evidence and operator cutover checkpoint

- Journal `/8` links newly recorded source evidence to the independently
  authorized acquisition effect, operation, revision, original receipt time and
  exact private response digest. It preserves source binding, actor attribution,
  grant, response history and charges. Source/read/allocation and the deployment
  clock are checked under the existing adapter fence; no new transaction owner
  or provider capability is introduced by evidence recording.
- Evidence is fresh through age 30 seconds; older or future-dated bytes cannot
  newly refine a source. HTTP error, wrong version, malformed/missing/multiple
  records and duplicate JSON members are unusable. Value equality without the
  expected echo cannot resolve an unknown write. Recipe observation parsing now
  rejects duplicate members at every depth while retaining its byte/depth bounds.
- Exact supported echo/value evidence can refine an unknown mutation. Its private
  provenance is immutable; repeated recording after expiry returns history with
  the original time and charges. The source's retained contract remains available
  for exact read replay after refinement; new read entry still requires an
  eligible source under the grant fence.
- Removed `GatewayEngine::reobserve` and the operator `reobserve` command. Admin
  request/response `/2` exposes `recover` with a second bounded native
  proof/action/approval frame and `recovery-record` for previously acquired
  evidence without provider/custody I/O. Both submission channels reuse one
  bounded input decoder. The former operator driver is a test-only reference.
  Automatic post-write and other ancillary/application read paths still require
  cutover; they are not made compliant by removing the operator endpoint.
- Native recovery report `/1` exposes separate source/acquisition stages,
  revisions, retained count/byte capacity and evidence disposition. It excludes
  provider bytes, locators, echo, action commitments and private response digests.
  This report is not a content-disclosure capability.
- `recovery-refinement.json` extends the signed-proof/file-journal corpus with
  unusable/inconclusive cases, age 30/31 and future-receipt boundaries, simultaneous
  refinement (one update and one exact history result), expired-writer history,
  unchanged receipt time/charges, recipe substitution refusal, redacted reports
  and closed admin frame grammar. Provider bodies, entry validation and the
  controllable clock remain synthetic. Installed sockets/provider transport,
  lock-wait expiry, PostgreSQL, crash/ACK-loss and full binding evidence are open.
- Required native recovery/entry/replay, attempt-scenario, stable/production-code,
  custody and qualification schema/verification artifact construction passed.
  Final CLI approval-envelope construction matched the signed corpus; final
  semantic closure generation passed on `1322d182` plus this source. Remote bot
  commit `1322d182` changed only formal qualification source-closure hashes and
  was preserved by fast-forward. No broad local suite or hosted CI was run.
- This source does not close A01–A22. Safe credential replacement, managed read
  bounds, ordered admission, remaining read cutovers, disclosure/ACK, complete
  UI/bindings, generated histories, final formal/release artifacts and hosted CI
  remain required.

## Submission observation cutover checkpoint

- Removed automatic post-write observation from the shared submission order and
  driver. A recorded response stops with `ResponseRecorded`; unknown transport
  stays conservative. Removed the obsolete mode enum, resume/read-back phases
  and actions, and test-only operator entry from the shipping driver.
- Direct `ObservableGatewayAttempt` observation-writing methods are now
  crate-private and test-only. The shipping evidence refinement path is the
  source/read/allocation recovery fence. Retained record/store conformance
  mechanics request their observation explicitly from a test oracle and make no
  AP074 read-authority claim.
- Updated authored scenario stages, credential/read/lease counts and exact
  request lists, plus measured qualification replay expectations. The generated
  replay corpus now measures a successful response with one lease, one write,
  zero provider reads and no evidence; its replay performs no additional I/O
  and preserves the complete snapshot. Python/TypeScript parity consumers also
  decode this native response case.
- Required native replay, attempt-scenario and final semantic-closure artifact
  construction passed (one exact generator each), on `9f717d39` plus this source.
  The replay generator exercises the new response/no-read assertions; the
  scenario generator constructs expected corpus data, not adapter conformance.
  No broad local suite or hosted CI has been run. Existing installed/harness
  journeys with automatic-observation expectations still require explicit
  independent acquisition/approval cutover, so full-suite readiness is not
  claimed. Generated/translated formal links remain pending. No acceptance
  gate closes.
- Next: bound/account prerequisite and application reads, ordered admission,
  replacement credentials/read-policy limits, disclosure/ACK, maintained
  consumer/UI cutover and complete installed/fault/formal/CI evidence.

## Prerequisite declaration checkpoint

- Compiler `/5` now commits the full ordered prerequisite acquisition plan in
  the mutation transport identity and retains the original closed read values
  beside the verified command. Native private review renders each typed purpose,
  exact request, response limit, one-call allowance, transport/freshness bounds
  and no-disclosure declaration. Old compiler bindings are refused directly.
- Account comparisons pin the installed account commitment/domain; denied reads
  pin their ordinal and refused statuses; ceiling reads resolve verified values;
  pre-entry reads pin pointers and selected native authority. The seven-read
  maximum excludes onboarding probes and post-write observations.
- A new signed native fixture covers Stripe's four prerequisites and Airtable's
  pre-entry plan. Initial generation caught fixture-only trust namespace and
  delegation-depth errors, now corrected. The shared test trust helper now uses
  the requested MCP service instead of the default harness service. It does not
  broaden installed trust.
- Required native prerequisite, effect/review/approval, recovery acquisition,
  mutation-entry and replay artifact generators passed on `119d1f78` plus this
  source (one exact test each). Entry generation refreshed the signed journal
  and transition fuzz seeds. Native CLI approval-envelope construction matched
  the signed corpus, and final semantic-closure generation passed. These are
  artifact-construction results, not full-suite or hosted CI evidence.
- Preserved remote bot commit `7c7ff71b` by fast-forward after inspecting its
  isolated qualification source-closure hash update. No hosted workflow results
  have been inspected.
- This is compilation/approval work, not durable read accounting. Existing raw
  prerequisite calls remain an explicit open cutover. They must next consume the
  retained compiler requests through the shared journal, capacity accounting and
  one-use permits. No A01–A22 criterion closes; installed UI/bindings, disclosure,
  replacement credentials, ordered admission, faults and formal/CI remain open.

## Durable prerequisite checkpoint

- Journal `/9` now has a closed recovery/prerequisite acquisition-plan variant.
  Both use the existing shared codec, reducer, permanent count/byte allocation,
  fenced entry and response persistence. PostgreSQL storage schema stays `/8`;
  its current record kinds suffice. Obsolete attempt records are rejected.
- A prerequisite's component key binds the parent logical operation and compiler
  ordinal, so a changed binding cannot evade replay by changing its digest.
  Its bounded canonical transport witness proves approved plan membership but
  cannot construct a transport request. Only the retained sealed read reaches
  the permit and transport.
- Read grants fence the child, still-reserved parent, allocation and current
  native dependencies. Submission's account, denied, pre-entry and ceiling
  reads now consume these permits. Responses are evaluated only after durable
  recording. Lost permits/responses remain charged and cannot be reminted.
- Final mutation entry fences every required child response and allocation and
  refuses missing, uncertain, future or stale evidence. Receipt timestamps are
  immutable; signed pre-entry observations and ceiling bases use the earlier
  acquisition grant time conservatively. Seven reads add 14 dependencies, for
  at most 52 of the existing 64-record fence bound.
- `prerequisite-entry.json` adds eight file-journal histories across native
  Stripe/Airtable plans: recorded response, missing read, lost permit and stale
  response. Equal reservations preserve capacity, competing handles cannot
  both grant, reopening returns history, substituted membership fails, and
  future/stale reads are unusable. This uses explicit-time oracle grants and
  synthetic bodies with zero provider calls. In particular, the Airtable case
  does not establish installed pre-entry requirement eligibility.
- Required artifact generators passed (one exact test each): prerequisite
  compilation/entry, independent recovery, mutation entry/fuzz seeds, native
  replay projection and semantic closure. Earlier compilation attempts caught
  stale test-only raw-read calls and zeroizing-buffer type mismatches, corrected
  before generation passed. No broad local suite or hosted CI was observed.
- Still open: ordered initial admission, tighter selected observer evidence
  validation at the final fence, full prerequisite fault/transport/PostgreSQL
  evidence, application/onboarding reads, safe credential replacement and read
  policy bounds, disclosure/ACK, Python-owner removal, installed UI/bindings,
  formal/performance and final CI. No A01–A22 criterion closes at this checkpoint.

## Final prerequisite evidence checkpoint

- Installed mutation entry now evaluates the required response purposes under
  the existing writer fence after native revalidation and acquisition membership
  checks. It reuses the existing account/denied, recipe ceiling/ratio and native
  selected-observation predicates; no second evaluator or transport owner.
- Signed pre-entry observations must verify canonically against the pinned
  observer and match the exact acquired subject, facts and original grant time.
  Selected native ages and anchor validity are evaluated at the fenced time;
  the acquisition's 30-second ceiling cannot relax them. The installed
  configuration commitment now includes the gateway's selected observer.
- Relative-ceiling basis, response digest and time must match the retained read,
  and original argument, ratio and binding checks still apply. Missing or extra
  checkpoint evidence is refused. Account, ceiling and pre-entry JSON share
  recovery's bounded duplicate-rejecting decoder.
- New native predicate artifacts cover 15 Airtable evidence cases and 15 Stripe
  guard/checkpoint cases. They include canonical invalid signatures, changed
  signer/subject/facts/time, selected-age limit/limit-plus-one, account/currency
  mismatch, excess capability, altered basis/digest/time, missing/extra evidence
  and duplicate JSON members. Stripe compilation now uses a known synthetic
  account commitment for a genuine matching comparison in this test corpus.
- The exact prerequisite compilation/entry/guard generator, signed-observation
  predicate generator and semantic-closure generator passed. The new signature
  case decodes and re-encodes a canonical observation with altered signature
  bytes, so it specifically exercises signature refusal. Construction caught
  test-import/parser-visibility issues, corrected before generation passed.
  No broad local suite or hosted CI was inspected.
- These are native signed effects and synthetic response/predicate results, not
  installed lock/process/provider or PostgreSQL evidence. The test-only store
  grant oracle intentionally remains separate from installed native entry.
  No A01–A22 acceptance case closes. Ordered admission, remaining read routes,
  replacement credentials/read bounds, disclosure/ACK and Python removal,
  authenticated UI/bindings, full faults/formal/performance and CI remain open.

## Ordered initial admission checkpoint

- Mutation, independent recovery and prerequisite claims now validate native
  authority/approval and current connection/configuration/qualification under
  the same writer fence as their atomic claim and capacity insert. The adapter
  decision can stamp only the first record's bytes; other batch fields remain
  fixed. Initial admission time is sampled inside the fence.
- Count/sum frontier discovery remains bounded candidate selection. Insertion
  checks target vacancy and validates immutable sum predecessors under the
  fence. Acquisition admission checks the eligible source in the same snapshot.
  Mutation admission uses at most 55 of the existing 64 records. The existing
  two-second lock/decision bounds and file rollback manifest remain in use.
- Runtime callers now supply installed validation before claim publication;
  recovery preparation precedes admission and is reused for entry. Transport
  grant timestamps are sampled after admission, while the original monotonic
  turn deadline remains enforced. No admission result itself grants transport.
- The new fixture caught expiry being checked while constructing a replacement
  candidate before reading existing history. Replay now loads retained history
  first, preserving the original reservation and charges after approval expiry;
  a later grant still requires eligible current approval and native authority.
- `effect-admission.json` covers real file batch atomicity, missing/changed
  dependencies, a dependency writer ordered before admission, collision/replay
  suppression of the decision, admission time, expired-approval refusal without
  writes, retained count/sum charges and expired-entry refusal. Native authority
  uses an explicit-time approval oracle; dependency bytes are synthetic. The
  same conformance source is authored for PostgreSQL, not executed locally.
- Required artifact construction passed: new native admission, prerequisite
  compilation/entry/guard, independent recovery, mutation entry/fuzz seeds and
  replay projection (one exact generator each). Construction also caught and
  corrected test Arc/zeroizing-buffer type mismatches. Final semantic closure
  is regenerated with this checkpoint. No broad local suite or hosted CI was
  observed, and no A01–A22 gate closes.
- Remaining implementation: application/onboarding reads, safe credential
  replacement and read-policy bounds, controlled disclosure/authenticated ACK,
  Python-owner removal and authenticated UI/bindings. Complete installed
  authority/adapter/process faults, differential/formal/performance and final
  hosted evidence remain required.

## Application recovery route checkpoint

- Removed the unapproved provider `read-back` request from the production
  engine, application protocol, CLI and Python/TypeScript client methods.
  Observation `/3` exposes local outcome/pre-entry history only; `/2` is refused.
  Application `auths.gateway-recover/1` carries a source operation and the same
  bounded native proof/action/exact-approval envelope as operator recovery.
- The application adapter calls `GatewayEngine::recover` directly. It returns
  only the native redacted recovery report or native refusal, never provider
  response bytes or a newly signed provider field. Existing source eligibility,
  native verification, exact approval, capacity, fencing and refinement still
  apply. This is not general content acquisition or recipient disclosure.
- CLI `app-recover` and SDK `recover` methods use this frame. Thin clients return
  bounded native JSON bytes unchanged; authored parity tests use the native
  frame corpus. The old synthetic observation reference now lives only in
  direct tests and the private test harness control socket, never the shared
  application route. Maintained reference consumers and current docs reflect
  that restricted scope. The synthetic submission harness refuses recovery
  rather than pretending to implement installed authority.
- Native artifact construction passed: application socket framing/dispatch and
  production CLI/socket round trip, including the harness feature build. The
  counting/refusal server establishes decoder, routing and exact transport
  bytes; it does not establish installed authorization or provider execution.
  Retired submit/admin/read-back fuzz seeds are explicit rejection cases, with
  current submit/recovery seeds generated from the native envelope.
- Test-only raw claim/approval helpers no longer compile into the standalone
  harness when unused. Final source closure is regenerated with this slice.
  No broad local suite, language suite or hosted CI was run/observed, and no
  A01–A22 acceptance gate closes.
- Remaining: onboarding/rotation reads and recovery ancillary reads, safe
  credential replacement, managed read-policy limits, general acquisition and
  controlled disclosure/ACK, Python-owner removal, authenticated UI/bindings,
  and complete installed/process/PostgreSQL/fault/formal/performance/CI evidence.

## Managed recovery read budget checkpoint

- Independent recovery compilation now consumes selected native count/sum
  policies instead of refusing all managed bounds. The bounded argument is
  exactly `maximum_response_bytes`; every sum reserves the full approved
  response ceiling. Mutation recipe spend requirements remain mutation-owned.
  Read count/byte identities are separate from mutation count/amount identities.
- Mutation and recovery use the same fixed-window candidate arithmetic, slot
  encoding, sum-predecessor checks and final membership validation. Recovery
  admission inserts managed slots and the permanent source allocation in one
  fenced batch. Replays add no charge; failed contention inserts nothing.
  Prerequisites do not reserve the parent policy again.
- Compiler `/6` binds the managed reservations. Journal `/10` retains immutable
  acquisition counter membership and rejects the old layout. Decode checks
  exact counter keys against the signed binding; final entry checks actual
  slot identity, ownership, cumulative amount and window with current native
  authorization under the fence. Public snapshots report policy counter counts
  alongside the source allocation without exposing private keys or content.
- `recovery-policy-budgets.json` contains three real file histories: final count,
  final byte sum and sum admission after an already charged unknown read. Each
  races two independently approved operations for the last capacity, retains
  exactly one winner, refuses substituted membership and old-window entry,
  preserves lost-permit charges through reopening, and requires a newly
  approved binding for a fresh window. Wrong argument, too-small ceiling and
  too-small sum policies are refused. Entry uses an explicit-time oracle, not
  an installed provider or PostgreSQL deployment.
- Required recovery, mutation binding/approval, prerequisite compilation/entry
  and predicates, admission, mutation entry/fuzz, attempt scenario and replay
  artifact generators passed. Application frame/CLI and final semantic closure
  regeneration also passed. The native binding generator now writes and checks
  the exact approval envelope alongside its signing request. No broad local
  gate or hosted CI has been run. No A01–A22 acceptance criterion closes at this checkpoint.
- Remaining read implementation: onboarding/rotation and recovery ancillary
  reads, plus safe replacement credentials. General acquisition, controlled
  disclosure/authenticated ACK, Python-owner removal, authenticated UI/bindings,
  full installed/process/PostgreSQL/fault/formal/performance and hosted evidence
  remain required.

## Recovery credential prerequisite checkpoint

- Recovery compilation now includes the installed recipe's account and
  denied-capability reads in its immutable request commitment and native
  review. Compiler `/7` uses the complete acquisition transport witness;
  journal `/11` rejects superseded recovery plans. The installation-only
  credential probe remains an onboarding obligation.
- Mutation and recovery share the credential-plan compiler, prerequisite
  record/allowance, consumed-permit acquisition helper and account/capability
  predicates. A child can enter only while its mutation or independent recovery
  parent is reserved. Another prerequisite cannot be its parent. Recovery final
  entry fences all required children/allocations and evaluates their purpose
  and freshness alongside native authority, original source and managed slots.
- The production recovery runtime no longer rejects recipes wholesale for
  declared credential checks. It acquires and records them in order, stops on
  a failed account/capability predicate, and validates them again at final
  entry. Child replay loads original evidence; unknown children cannot remint
  permits. Their explicit allowances do not charge the parent's managed budget
  again. At most five recovery children give a maximum 48-record entry fence.
- `recovery-prerequisites.json` covers recorded, missing, lost-permit, stale,
  wrong-account and excess-capability histories using native Stripe recovery
  proofs and real file state. Native actual-purpose evaluation is reported
  separately from oracle entry. The corpus checks full human review, exact
  recompile, missing-parent refusal, corrupted membership witnesses, retained
  child charges and restart projections. It does not claim installed provider
  transport or PostgreSQL evidence.
- The prerequisite/recovery artifact generators passed after correcting a
  missing type import and making the Stripe source fixture retain its required
  response-derived refund locator. The fixture does not invent an observable
  target for a source without that locator. Binding/approval, mutation entry,
  admission, attempt/replay, code inventory, application framing and production
  CLI/socket generators also passed. Final source closure is regenerated with
  this checkpoint. No broad local gate or hosted CI has been observed.
- Remaining: first-install and candidate-rotation read authorization/journaling,
  safe replacement credentials, general acquisition, disclosure/ACK, Python
  decision removal, authenticated UI/bindings and full installed/process/adapter/
  formal/performance/CI acceptance. No A01–A22 criterion is fully closed.

## Candidate credential compilation checkpoint

- Compiler `/8` adds the reserved native candidate-check tool and sealed target.
  The full proposed connection and exact predecessor/absence are pinned; a
  rotation preserves descriptor, account, authorizations and administrative
  state. Native verification, selected authority, managed read bounds, binding
  construction and exact approval share the existing recovery compilation path.
- Candidate plans retain recipe order (probe/account/denied), with the final
  declared read as the primary acquisition and prior reads as declared children.
  No-read recipes cannot invent a network operation. Private review includes
  the actual GET/HEAD and full descriptor/previous state. Source-lifetime keys
  use connection ID, credential generation and reference commitment; changing
  the operation or timestamp cannot reset the 16-attempt allowance.
- The native candidate corpus covers first install, active and disabled
  rotations, HEAD final reads and probe-only checks; it rejects substituted
  candidate/predecessor/recipe/contract/limits/extra arguments, changed connection,
  expired or reused approval, revoked predecessors and changed rotation accounts.
  Existing mutation/recovery admission and orphan-child routes refuse candidates.
  Probe predicates accept the exact value and reject wrong/duplicate JSON values.
- This is compilation and explicit refusal evidence, not candidate execution.
  Staged custody, current-or-absence fencing, candidate admission, ordered reads,
  safe publication and onboarding/rotation CLI cutover remain required. The
  runtime still uses the previous onboarding checks until that direct cutover.
  Journal `/11` is unchanged; no candidate journal decoder is introduced here.
- Required native artifact construction passed for candidate compilation and
  the changed compiler identity's binding, approval, recovery, prerequisites,
  admission/entry, replay, attempt and code fixtures. Application framing passed.
  The CLI generator exposed macOS inheritance of the listener's nonblocking flag;
  the accepted test stream now explicitly uses blocking I/O with its existing
  five-second deadline. CLI regeneration and final source closure then passed
  on `15b3cad1` plus this source. No broad local gate or hosted CI was run; no
  A01–A22 acceptance criterion closes.

## Candidate acquisition journal/runtime checkpoint

- Journal `/12` adds candidate source plans to the shared acquisition owner.
  Admission pins the actual expected predecessor or first-install absence;
  ordinary and candidate entry share native verification/configuration/approval
  checks. Candidate checks preserve disabled state and still require the exact
  workload/profile. Revocation or any predecessor replacement prevents later
  child and primary grants. The source/native dependency on the same connection
  row is read once, with both predicates evaluated against that snapshot.
- Entry audit `/3` records absence separately from a present record commitment.
  Native candidate histories exposed the previous all-present audit assumption;
  the explicit layout change makes first-install grants representable without
  weakening mandatory dependency checks. Old layouts are refused.
- The engine candidate acquisition API leases the exact staged credential after
  admission and uses the shared ordered-read helper. It validates earlier probe,
  account and capability responses before primary entry; final entry repeats
  their actual predicates/freshness. Response/unknown facts retain allocations
  and never grant publication. Cross-proposal allocation collision checks prevent
  a credential identity from changing its already established byte ceiling.
- The native candidate artifact generator covers first install, active/disabled
  rotation, HEAD-final and probe-only variants using actual native fence checking
  and real file state. Histories cover missing/bad/stale children, predecessor
  changes before admission/child/main entry, lost main permits, replay and reopen.
  Configuration/clock and response bodies are synthetic; no installed provider,
  publication or PostgreSQL claim is made. A capacity fixture initially reused
  equal limits; its probe-only recipe now changes the limit to exercise refusal.
- Artifact construction passed on `f0a364fd` plus this source: 36 candidate
  journal histories and three cross-proposal capacity cases; recovery/prerequisite
  compilation, binding/approval, actual prerequisite predicates, admission/entry,
  replay, attempt, code/custody, application frame/CLI and final semantic closure.
  One extraction build required correcting a moved helper's module qualifier;
  the new capacity case required actually differing byte ceilings. These were
  corrected before successful regeneration. No broad local suite or hosted CI
  was run or observed.
- Remaining onboarding work: durable staging/authoring CLI, retained final-purpose
  validation and safely fenced publication, then removal of the old raw check
  paths. General acquisition/disclosure/ACK, safe recovery credential replacement,
  Python-owner removal, authenticated UI/bindings and full acceptance evidence
  remain open. No A01–A22 criterion is fully closed.

## Candidate publication checkpoint

- The operator API publishes exact staged candidate records through the existing
  store writer fence. It validates the root/child records and allocations, fresh
  native authority/approval/configuration/qualification, actual final and child
  credential predicates, and predecessor/absence before connection insertion or
  replacement. No acquisition state, charge or evidence timestamp changes.
- Exact already-current state has a separate result with no causal attribution,
  capability or evidence refresh. The runtime checks exact custody beforehand
  and reloads through the generation-floor owner before scheduling retirement.
  Independent custody availability is not claimed atomic with shared state.
  Publication errors do not claim the connection write definitely did not occur.
- Candidate artifact construction passed on `57332c58` plus this source: 80
  native file-journal histories, including publication success/replay and
  refusals for bad final purpose/version, unknown primary, stale primary/child,
  expired approval, changed configuration and changed predecessor. Response
  bodies, clock and installed configuration remain synthetic. This is not
  installed provider/custody, process-fault or PostgreSQL evidence.
- Code inventory and final semantic-closure artifact construction also passed.
  No broad local gate was run. The publication API is an operator method only;
  no application framing or existing provider request identity changes.
- Durable staging/proposal CLI and removal of raw onboarding/rotation paths
  remain next. General acquisition/disclosure/ACK, safe recovery replacement,
  Python-owner removal, authenticated UI/bindings and full acceptance evidence
  remain open. No A01–A22 criterion is closed and no hosted CI was observed.

## Private candidate proposal checkpoint

- Added `auths.gateway-credential-candidate/1`, bounded canonical private JSON
  containing exact candidate/predecessor CBOR and recipe digest. It preserves
  the target for future CLI approval/restart steps without serializing authority,
  custody, a check result or a transport capability. The native decoder derives
  the plan from the pinned recipe and revalidates the connection relationship.
- The five-target native generator now passes the decoded proposal into every
  signed compilation and journal/publication history. It authors exact-roundtrip
  and wrong-schema/recipe/record/predecessor, unknown/duplicate/noncanonical and
  oversize refusals. Initial artifact compilation exposed a test assertion's
  demand for private-plan Debug; the assertion now compares equality without
  adding a private-data Debug implementation.
- Native candidate artifact generation passed after the assertion correction:
  five proposal roundtrips/negative sets and all 80 journal/publication histories.
  Final semantic closure is regenerated with this source. No broad local gate
  or hosted CI was run; no acceptance criterion closes at this checkpoint.
- Staging and CLI cutover remain pending; this format alone does not implement
  them. No new schema migration, legacy reader or alternate execution path was
  added. Existing candidate compiler/binding/journal identities are unchanged.

## Candidate rotation staging and CLI checkpoint

- `stage_candidate_rotation` checks installed configuration, current exact
  connection, non-revocation, prefix, read plan, current custody and generations
  before storing a successor. Durable cleanup notes precede the custody write.
  It never leases, reads a provider, publishes, or discards another staged secret.
  The fixed deployment-clock proposal can be persisted through approval/restart.
- Added production `candidate-stage-rotation`, `effect-candidate-call`,
  `effect-review --candidate`, `candidate-acquire` and `candidate-publish` CLI
  commands using native owners. Stage/publish use operator custody identity;
  acquisition uses runtime read identity. Proposals/calls are new mode-0600
  files. Existing output and permissive proposal files are refused.
- Read-bearing recipes now refuse the old `rotate`/`rotate-prepare`/
  commitment-only `rotate-commit` routes before I/O. Recipes without reads keep
  the offline operator path. Joining an already-published connection confirms
  its exact credential reference without any provider read. First-install raw
  checks and maintained deployment/qualification journey cutovers remain open.
- Independent operator processes exposed persistent file-custody snapshot
  overwrites. The existing custody owner now reloads bounded canonical state
  under a stable cross-process sidecar lock. File-lock contention fails
  immediately; stale handles cannot overwrite committed candidates or hide a
  completed deletion. Reads allocate once into zeroizing buffers, with length
  bounds and exact EOF checks. No new dependency, credential identity or
  lifecycle owner is introduced; shared connection/custody atomicity is not claimed.
- Native artifact construction passed on `861271a3` plus this source: five
  durable staging cases (active/disabled, revoked, missing cleanup journal,
  bad prefix), same-secret replay/different-secret refusal, custody reopen,
  unchanged connection/witness and refusal of unapproved guarded rotation.
  The 80 native candidate journal/publication histories and code/custody
  inventories passed as well. Initial generator errors were a missing semicolon
  and a fixture directory lacking mode 0700; both were corrected.
- The production CLI artifact passed with actual competing processes, one
  staging winner, held-custody-lock refusal, exact native call bytes, output
  preservation and owner-private permissions. Its initial compile required a
  borrowed operation string; its synthetic installation then needed the same
  pinned qualification root and empty loaded bundle as the production loader.
  Those fixture inputs were corrected instead of weakening configuration checks.
- After the file-custody change, native staging regeneration passed again,
  including stale-reader observation of a completed deletion; the independent
  CLI process generator also passed again. Final source closure was regenerated
  after all source edits.
- These are scoped file/CLI facts, not a fully approved installed provider
  rotation, AWS/PostgreSQL conformance or process-crash qualification. First
  installation, full approved provider journeys, safe recovery credentials,
  general acquisition/disclosure/ACK, Python-owner removal, authenticated UI and
  complete fault/formal/performance/hosted evidence remain required. No A01–A22
  acceptance criterion closes. No broad local gate or hosted CI was run.

## First-install staging and onboarding cutover checkpoint

- Read-bearing `install` now persists the existing canonical connection format
  as a private draft, stages exact generation-one custody and saves a private
  proposal. The shared connection stays absent until approved acquisition and
  fenced publication. Draft identity/account/descriptor/timestamps survive
  process restart. `candidate-stage-installation` explicitly resumes from it.
- The stage initializes durable cleanup notes before custody and pins the host
  floor to the exact unpublished candidate. An existing matching secret supports
  retry after ambiguous custody acknowledgement; conflicting secrets or floors
  refuse. Candidate compilation/acquisition/publication require the existing
  floor. Runtime cannot repair it; explicit operator restaging may initialize
  an unpublished floor. Independent custody/floor/output failures retain cleanup
  obligations and do not imply that custody was never written.
- Removed production raw onboarding exports and the install checker. The old
  closed evaluator remains test-only; the pure probe predicate remains shipping.
  The offline install helper now requires the recipe and refuses declared reads
  before custody. Join requires cleanup notes before confirmation. Development
  loopback selection moves from install to approved candidate acquisition.
- Native candidate artifact construction passed on `1c23ca31` plus this source,
  retaining all 80 journal/publication histories and adding five first-install
  staging histories: exact reopen/restage, bad prefix, existing connection,
  substituted floor and corrupt cleanup journal. The actual CLI generator passed
  with `testkit-harness,loopback-provider`, covering installation, an independent
  resume process, identical proposal bytes, private files and conflicts.
- Initial generator failures were missing test-oracle imports, an incorrect
  result-field assertion, comparing process-specific witness scopes across two
  engines, and a test variable shadowing the recipe lock. Corrections retain
  each process's own zero-I/O witness and the intended refusal assertions.
- Required generators: `observed_tests::effect_native_tests::candidate_tests::native_candidate_compilation_fixture_is_current`
  (library), `native_candidate_cli_fixture_is_current` (candidate_cli integration
  target), code inventories and final semantic closure. These construct scoped
  artifacts; they are not broad local gates, installed approved provider
  qualification or hosted evidence. No hosted CI has been observed.
- Final candidate/code/custody generation passed (four exact tests); the
  production CLI artifact passed (one exact test), and final semantic closure
  passed (one exact test). Fetch found upstream bot commit `67506ada`, updating
  only the prior custody source's formal closure. It was inspected and retained
  by fast-forward without observing hosted workflow results.
- Remaining: maintained deployment/example scripts and complete approved
  installation/rotation journeys; safe recovery credential replacement; general
  acquisition/disclosure/ACK; Python-owner removal; authenticated UI/bindings;
  full process/adapter/differential/formal/performance/hosted evidence. No A01–A22
  acceptance criterion closes at this checkpoint.

## Approved candidate process journey checkpoint

- Added a real production-CLI journey over private installation files, file
  custody, generation floor, cleanup journal and actual local HTTP sockets.
  Test-only fixed-key native authoring supplies real canonical proof/action and
  trust; `effect-candidate-call`, `effect-review`, `effect-approval`, acquisition
  and publication still use the shipping compiler, verifier and transaction
  owners. No oracle entry predicate or hand-built approved binding is used.
- `candidate-process-journey.json` records six histories: successful first
  installation with active rotation; rotation of a disabled predecessor; bad
  probe; wrong account; excess final capability; and lost primary response.
  The provider counts and checks exact request lines, version/credential headers
  and absence of account-scope headers. Successful first install and rotation
  each make exactly four declared GETs. Earlier failed predicates stop later
  reads. Failed/unknown evidence cannot publish a connection.
- Independent acquisition processes race the same operation: one set of reads
  reaches the provider. A new process replays retained history without re-entry;
  every non-connection journal record and allocation remains byte-identical
  across replay and publication. Lost final response retains unknown and its
  invocation charge. Exact publication replay reports `already-current` without
  provider I/O. Disabled rotation preserves state while advancing generation.
- Invalid approval and old exact approval for a new operation cause no provider
  calls. Approval alone cannot publish. Native literal review includes every
  credential request; public acquisition output is scanned for credential and
  account sentinels. The test signer simulates an external reviewer and makes no
  human-presence, live-provider, process-isolation or PostgreSQL claim.
- Exact artifact generation passed on `ed557dab` plus this source:
  `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --features testkit-harness,loopback-provider --test candidate_journey -- --exact approved_candidate_process_journey_fixture_is_current`.
  The final six-case run passed in 7.27 seconds. Final semantic-closure artifact
  generation also passed (one exact test). Initial test failures required
  clearing macOS's inherited nonblocking socket flag and using the existing
  `disable --store-only` command. Test cleanup avoids a second panic during
  unwinding. No production check or predicate was weakened to pass the journey.
- Maintained caller inventory still includes Stripe/Airtable demos, qualification
  production/live/custody-fault scripts and the refund-approval example. Their
  mutation-only trust/grants need explicit candidate read authority and exact
  approval; production first install also needs the qualification bootstrap
  order preserved. Merely replacing install/rotate command names is insufficient.
  The no-read operator simulation retains its offline path.
- This closes the previously missing local approved candidate transport evidence,
  not P3 or A01–A22. General acquisition/disclosure/ACK, safe recovery credentials,
  maintained consumers, authenticated UI/bindings and full adapter/fault/formal/
  performance/hosted evidence remain required. Hosted CI has not been observed.

## Native disclosure acknowledgement and reducer checkpoint

- Extended the existing kernel transition owner with typed disclosure and a
  distinct terminal `Acknowledged` stage. ACK bytes are separate from provider
  response/observation fields. All protocols retain immutable identity,
  allocation, grant and monotonic revision checks. Disclosure cannot acquire
  provider facts; mutation/acquisition cannot carry ACKs. The provider outcome
  presence predicate refuses the disclosure terminal stage.
- Native `auths.gateway-disclosure-ack/1` binds effect, source, protected content,
  raw-key recipient, channel, delivery instance, projection, ceiling and actual
  byte count. It uses existing canonical/domain commitment and strict Ed25519
  verification, derives the recipient through the existing raw-key descriptor,
  rejects duplicate/unknown/noncanonical/obsolete/oversized input before use,
  and returns a sealed historical assertion. Debug is redacted and encoded
  buffers are zeroized. Verification supplies no execution authority.
- Late evidence requires no current-authority or time argument. It must still
  match the retained delivery and protected content length and pass the shared
  reducer. Exact repeated ACKs are read-only comparisons of consistent terminal
  history; they do not advance revision, change evidence or issue another grant.
- Exact artifact construction passed on `cac8c75b` plus this source:
  `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact effect::disclosure_tests::native_disclosure_acknowledgement_fixture_is_current`.
  The final run passed one test in 0.03 seconds. Its fixture covers 576 protocol/
  stage pairs, four disclosure histories, immutable state-field substitutions,
  revision saturation, changed binding dimensions, independently re-signed ACK
  assertions, foreign signatures, exact byte-count limits and malformed codecs.
  The initial compiler error combined raw-key construction and principal
  derivation errors with incompatible Result types; each is now mapped at its
  own boundary. Final semantic-closure generation passed one exact test.
- Kani source includes disclosure, the new ACK field and an exact terminal-replay
  obligation. Kani and translated Lean/refinement evidence have not been run
  or regenerated; they remain P4 work. No broad local gate or hosted CI was run.
- This is a native evidence/reducer slice, not an installed release path. Content
  acquisition/custody, disclosure compilation/approval, transactional admission
  and entry, authenticated recipient transport, persistent ACK recording and
  AP070 Python-owner removal remain required. Synthetic fixed allocations in
  this corpus do not establish durable accounting or actual byte delivery. No
  A01–A22 acceptance criterion closes.

## Explicit content acquisition compiler checkpoint

- Added the digest-bound opt-in `content` capability with its own
  `auths.gateway-content-read/1` schema. It selects one string/enum resource,
  existing fixed/verified path and account headers, bounded sorted literal query
  pairs, and UTF-8 or JSON-string projection. The operator review includes the
  complete declaration. An absent declaration cannot compile content reads;
  the reserved native read tool cannot be installed as a mutation tool.
- Added `ContentReadTarget` and `compile_content_acquisition` to the existing
  acquisition compiler. Fresh native read proof, full private target/connection,
  source allowance, managed policy counters, prerequisites, exact approval and
  complete native review share the existing effect owner. Full revalidation
  recompiles content effects. Mutation/recovery/candidate admission cannot be
  borrowed by a content effect. No content transport or permit was added here.
- Source allowance keys bind recipe, connection ID, credential generation/
  reference and exact resource/account arguments, excluding logical operation
  IDs and administrative metadata. The full connection still binds the approval.
  The native corpus checks that disable/enable timestamp changes preserve keys
  while old bound approval refuses the changed installation. Durable allocation
  enforcement remains part of the next journal work, not a compiler claim.
- Pure projection returns exact private zeroizing bytes, requires status 200,
  declared media type and optional UTF-8 charset, and rejects malformed UTF-8,
  duplicate JSON, missing/non-string projections and both raw/projected limits.
  Six typed response codes distinguish these facts from native authority denial.
- Exact artifact construction passed on `72fe870e` plus this source:
  `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact observed_tests::effect_native_tests::content_tests::native_content_compilation_fixture_is_current pending_vectors::codes::code_inventory_is_current`.
  The final two-test run passed in 0.06 seconds. The corpus uses real native
  proof/approval signatures for both projections, fresh/expired recompile,
  different resource/connection/limit, extra arguments, approval reuse and stable
  capacity keys; it checks the declared projection limits and all six error
  codes. Final semantic-closure generation passed one exact test.
- Initial fixture construction used a nonexistent review method and accidentally
  supplied content source as profile-schema fields. The fixture now invokes
  `render_literal` and edits the recipe source while preserving its profile lock.
  No production check was weakened. No broad local gate, Kani, Lean or hosted CI
  ran. This is compilation/pure projection evidence only.
- Fetch found bot commit `5b9d9ecd`, changing only formal source-closure hashes
  for the prior ACK/kernel source. It was inspected and retained by fast-forward;
  no hosted result was inspected.
- Next requirements are the content plan in the shared journal, response metadata
  and protected retention, separately authorized disclosure entry/transport/ACK
  persistence, standalone read-only installation and AP070 metadata predicates/
  consumer cutover. The existing recipe still includes a mutation declaration;
  this opt-in content capability is not a claim that standalone read-only
  installation or the Google domain cutover is complete. A01–A22 remain open.

## Content acquisition journal and transport checkpoint

- Content now has a typed plan in the existing acquisition owner. It binds the
  exact current connection, resource capacity, request/projection and credential
  prerequisites. Admission and final grant share the existing native fence and
  permanent count/byte allocations. Content cannot borrow candidate/recovery
  admission or ordinary response evidence. Current connection changes refuse.
- Added engine compilation/acquisition APIs using the existing preparation,
  custody and acquisition sequence. Terminal replay precedes transport/custody
  preparation. Public results remain acquisition facts without raw bytes,
  content commitments or a disclosure permit.
- The sealed content permit sends the compiler-owned GET and fixed query over
  the pinned transport. It requests identity encoding and disables automatic
  decompression; other request paths retain their query prohibition. A distinct
  response phase privately retains bounded raw bytes, status, version agreement,
  receipt time and missing/single/invalid media/encoding facts (128 bytes each).
  It maps to the existing kernel response stage, not a new reducer. Oversized
  responses and lost permits retain unknown and full charges. Partial read
  accumulation is zeroized on error.
- Exact artifact construction passed on `eafd6a2b` plus this source:
  `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib -- --exact observed_tests::effect_native_tests::content_tests::native_content_journal_fixture_is_current observed_tests::effect_native_tests::content_tests::native_content_compilation_fixture_is_current`.
  The final two-test run passed in 2.04 seconds. The new fixture uses installed
  native entry validation, the file adapter and eight real loopback HTTP calls,
  checks 16 permanent allocations and seventeenth refusal, one-use grants,
  reopened replay/unchanged bytes, exact queries and request headers, retained
  response metadata, record downgrade rejection and public sentinel privacy.
  Source/connection equality is checked separately. An initial compile failure
  used a nonexistent policy key method; the test now uses the existing native
  `GatewayAttemptKey::for_operation`. No production check was weakened.
- This is not a full engine/CLI process journey, PostgreSQL/fault evidence,
  content projection provenance, protected content commitment or disclosure.
  Protected projected-content construction must consume the recorded metadata
  and reject bad encoding/media/version/projection without refetch. Read-only
  installation, AP070 metadata and Python-owner removal, maintained consumers,
  authenticated UI/bindings and P4 evidence remain. No A01–A22 case closes.
- After the bounded-buffer zeroization change, final generation of
  `native_content_journal_fixture_is_current` and
  `semantic_closure::tests::semantic_closure_is_current` passed together (two
  exact tests, 2.15 seconds). No broad local gate or hosted CI has been run or
  observed. Bounded decoded response buffers and partial transport accumulation
  are zeroized on drop. Fetch found no new upstream commits.

## Protected content projection checkpoint

- The previous goal turn made progress (`71fd4f7f`, committed/pushed); this
  continuation adds protected content to that same response transaction.
  Attempt `/13` rejects all obsolete `/12` state, without a compatibility reader.
  A complete content response now retains either protected readiness or the
  exact typed projection refusal. Neither result grants disclosure authority.
- The compiler and retained-response paths share one pure projection leaf.
  Retained version agreement, identity encoding and exact media/projection are
  enforced; empty content is valid. Encoded/wrong-media/malformed/over-limit
  responses stay recorded and charged. Public snapshots expose only byte count
  or stable refusal; response-version/encoding have distinct native codes.
- Protected content uses the pinned workspace HMAC-SHA256 primitive plus native
  domain/canonical framing, with a fresh private 32-byte key and exact source,
  projection, byte count and private content digest. Loads reproject and verify
  the keyed commitment (or recompute the refusal); replay preserves the key and
  original record bytes. No plaintext digest, key, commitment or body is public.
  Existing journal access protection remains required; no encryption or defense
  against a malicious journal/key administrator is claimed.
- Exact artifact generation passed on `71fd4f7f` plus this source: content
  compilation/journal, code inventory, attempt scenarios, prerequisite entry
  and native entry/fuzz seeds (six exact generators, 9.31 seconds). The initial
  compile failure used a nonexistent pointer helper; it now invokes the existing
  response-pointer and escape validators. A schema-edit script initially read
  ripgrep stdin rather than the tree; it was corrected to an explicit `.` root.
- The strengthened `native_content_journal_fixture_is_current` generator then
  passed (one test, 3.30 seconds). Version-2 evidence contains fifteen real HTTP
  cases: repeated/empty/exact/over-limit/invalid UTF-8 content, identity/gzip/
  duplicate encodings, wrong/missing media, missing required version, HTTP denial
  and oversized response, plus lost permit and seventeenth source refusal.
  It rejects key/tag/length/schema/body/version/media mutations and swapping
  protected material between independently valid sources containing the same
  bytes. Reopened replay leaves the private key and complete record unchanged.
- `cargo xtask arch --update` completed required dependency-snapshot generation;
  the reviewed delta is only `auths-gateway -> hmac` (no package or other edge
  changes). Building that generator surfaced existing unused observation/raw-read
  helpers, now gated to their test/testkit consumers instead of shipping unused
  production read interfaces. Final semantic-closure generation passed (one exact
  test, 0.28 seconds). These are artifact construction, not broad local gates or
  hosted CI evidence. Fetch found no upstream commits; no hosted results were
  inspected.
- Next: sealed retained source and native disclosure compilation, then shared
  disclosure admission/entry, authenticated transport and persistent ACKs. The
  standalone read-only installation, AP070 metadata/owner cutover, full
  engine/CLI/UI/binding journey and P4 adapter/fault/differential/formal/performance
  evidence remain required. No A01–A22 case closes at this checkpoint.

## Sealed source and disclosure compiler checkpoint

- Based on `10a548ee`, added journal-only `RetainedContent` provenance with no
  public plaintext accessor/deserializer. It requires validated ready content;
  rejected/unknown responses remain ineligible and no source read is repeated.
- Native `auths_gateway_disclosure_v1` compilation binds exact source/commitment,
  projection/length, raw-key recipient, channel and delivery instance. It verifies
  a separate native proof, uses existing complete private review/exact approval
  and full fresh recompile, and has no provider credential prerequisites.
- Added disjoint disclosure count/byte declarations, sixteen lifetime deliveries
  per source, and existing managed policy arithmetic on the release byte argument.
  Changing operation/recipient/channel does not create a new lifetime allowance.
  These remain obligations until disclosure journal admission is implemented.
- Required artifact construction executed two exact generators: content journal
  and code inventory. Both passed (3.03 seconds execution after compilation).
  The journal fixture still performs fifteen real local HTTP reads and adds
  separate native release/approval/ACK cases for empty and nonempty content.
  Cases cover managed budgets, wrong budget arguments, old read authority,
  changed recipient/channel/instance/partition, reused approval, full recompile
  and expired approval. No content or private correlations enter the artifact.
- Final content-journal and semantic-closure artifact generators passed together
  (two tests, 3.06 seconds). Review includes the source resource arguments and
  projection contract, not just opaque commitments. Preserved upstream generated
  formal closure commit `622a58fe` by fast-forward before this commit.
- Disclosure entry, authenticated delivery, persistent ACKs and the full P3/P4
  cutover remain incomplete. No acceptance case is closed by compilation.
  No broad local gate, formal execution or hosted CI observation was run.

## Shared source-allocation checkpoint

- Based on pushed disclosure compiler commit `93f4915c`.
- Extracted the existing source count/byte declaration leaf and canonical
  append-only allocation row/key/occupied-slot validation into the existing
  effect/capacity and store/capacity owners. Acquisition source eligibility,
  lifecycle, schema and charges are unchanged; disclosure declarations now use
  the same arithmetic with their own units and source keys.
- Required content-journal and recovery-acquisition artifact generators both
  passed (two tests, 3.64 seconds); their fixtures remained byte-for-byte current.
  No new provider calls, admission authority, retry or refund rule is introduced.
- Candidate, prerequisite and semantic-closure artifact generators also passed
  (three tests, 37.73 seconds). Behavioral fixture bytes stayed unchanged; only
  the native semantic closure changed with the source extraction.
- This reduces duplication needed by disclosure admission; it does not yet
  implement that admission or a delivery grant. P3/P4 and A01–A22 remain open.

## Disclosure journal checkpoint

- Based on `15d0bb8d`, added a closed disclosure protocol to the shared journal,
  reducer projection and support listing. Journal `/14` rejects obsolete `/13`;
  related source, qualification claims and generated schema/fuzz fixtures move
  together with no migration reader.
- Native engine proposal/compile/admit APIs now use sealed retained provenance,
  exact approval and the existing installed authority/configuration fence. Atomic
  admission reserves the shared permanent source allocation and selected native
  count/byte slots. It emits no content, credential lease or delivery permit.
- Durable ACK recording validates exact retained binding/length and the original
  grant via the common reducer. Exact replay is revision-preserving; concurrent
  CAS conflicts have one bounded reload. Late history after connection disable
  remains recordable. The production authenticated grant is still unwired.
- Required artifact construction passed five exact generators in 9.69 seconds:
  content journal (including new disclosure journal), code inventory, attempt
  scenarios, prerequisite compilation and native entry/fuzz corpus. The fixture
  executes installed file admission, duplicate concurrency, source/connection/
  approval refusal, sixteen source allocations and independent policy exhaustion,
  conflicting binding, reopening and no disclosure/public private correlations.
- ACK persistence tests use explicitly synthetic retained grants, never real
  recipient authentication or sends. They cover pre-grant/foreign ACK refusal,
  concurrent identical ACKs, late unknown refinement, immutable revision/charges
  and reopened replay. No process/PostgreSQL/isolation/complete A08 claim.
- Final content/disclosure journal and semantic-closure generators passed
  together (two tests, 4.91 seconds), including ten record mutations and the
  immediate obsolete schema. The byte-policy case exhausts its sum while count
  capacity remains; public refusals distinguish it from source exhaustion.
- Production recipient authentication and final grant/transport, AP070 owner and
  binding/UI cutovers, complete P4 evidence and hosted CI remain outstanding.
  No A01–A22 case is closed by this checkpoint; no broad local or hosted gate ran.

## Authenticated disclosure entry and transport checkpoint

- Based on pushed `3f23e5f3`. The preceding status-only turn changed no source;
  this continuation finishes the pending native grant and Unix transport slice.
- `UnixDisclosurePolicy` commits exact gateway/recipient UIDs and a private channel
  identifier. Both peers check OS credentials; the recipient signs a fresh
  challenge over the full bound delivery statement under an authentication domain
  distinct from ACK. The owned socket remains sealed through the final grant.
- Final disclosure entry uses the existing writer fence and sole reducer. It
  revalidates retained source/MAC, native proof/approval/configuration, permanent
  source allocation and managed policy membership before persisting the immutable
  authentication transcript plus entry audit. Only acknowledged persistence
  returns the one-use send permit. Attempt `/15` rejects obsolete `/14` and
  granted records lacking valid authentication. Historical decode creates no
  socket or permit. Public projections remain redacted.
- `GatewayEngine::disclose` composes admission, fresh recipient authentication,
  final native entry and exact retained-byte delivery. Recipient code explicitly
  ACKs after complete receipt or retains native evidence for late recording.
  Authentication/ACK frames are bounded to 4,096 canonical bytes, content to
  65,536 and exact projected length. Five-second handshake/fifteen-second session
  deadlines supplement, never replace, native fenced authority time.
- Required artifact construction passed five exact generators in 8.94 seconds:
  content journal (now also producing `disclosure-delivery.json`), code inventory,
  attempt scenarios, prerequisite compilation and native entry/fuzz corpus.
  Extended content/delivery generation then passed in 5.31 seconds. New source
  evidence uses actual Unix socket pairs and the installed native file fence over
  a real retained HTTP response. It covers actual receipt/ACK, lost ACK, reopened
  no-redelivery, late ACK, dropped permit, competing authenticated channels with
  one winner, and connection/configuration/approval/source changes after
  authentication. It also refuses wrong UID/key/nonce, malformed/duplicate/
  unknown/noncanonical/oversized authentication and corrupted retained proofs.
- The configuration-change fixture initially named a nonexistent store variant
  and passed a raw key. It now uses `EffectConfiguration` and the native key
  wrapper; the repaired artifact passed without changing production checks.
- Final content/disclosure and semantic-closure artifact construction passed
  together (two exact tests, 5.31 seconds). Fetch found no upstream commits.
- The earlier synthetic-grant ACK corpus remains explicitly scoped historical
  unit evidence. New socket/file evidence is not an independent-process crash,
  PostgreSQL, hostile-agent isolation, full engine/CLI/UI or A07/A08/A22 closure.
  These, AP070 source-owner removal, standalone read-only installation, maintained
  consumers and complete P4 evidence remain required. No broad local gate,
  formal execution or hosted CI observation was run. AP073 remains untouched.

## Native content application, CLI and control-binding checkpoint

- Based on pushed `d5cfeb99`; the preceding goal turn made concrete progress and
  left a clean worktree. This continuation adds the maintained application path
  over that native disclosure runtime, not another executor or state owner.
- Content acquisition now projects resource arguments from the native-verified
  action. The existing acquisition compiler shares its body below that sealed
  result. Native fixture parity confirms the same binding as explicit-target
  compilation; candidate and recovery artifacts remain unchanged.
- Four closed application envelopes expose content acquisition, disclosure,
  redacted history and late ACK. Native admission returns history/refusal or Ready;
  Ready only transfers the owned socket to native authentication and fresh final
  entry. The transport inherits the application deadline. Control loss cannot
  recreate a permit. Historical queries check recipe/namespace/partition/epoch;
  acquisition/disclosure facts are typed, private content stays in its owner.
- The Rust recipient client checks gateway UID/channel/key before sending private
  proof/approval. CLI `content-acquire`, `content-history`,
  `disclosure-acknowledge` and `disclosure-receive` call native operations. Receipt
  saves new 0600 content and ACK files before sending ACK and reports only
  `recipient-ack-sent`, never durable server persistence. Review supports content
  and disclosure targets and can save the exact private recipient binding.
- Python/TypeScript control methods carry acquisition/history/ACK envelopes and
  return native bytes without effect hashing, projection, signing, accounting or
  retry logic. Their fixture and bounds tests are authored, not executed. The
  recipient protocol remains Rust-owned; full installed binding/UI integration
  and native call-authoring CLI work remain open.
- Required native application frame/content compilation/content journal artifact
  generation passed three tests in 5.89 seconds. The first build caught two missed
  `DisclosureConnection` deadline destructures; both peers now honor the parent
  deadline. No production check was weakened to repair compilation.
- `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --test application_content_cli -- --exact native_application_content_cli_fixture_is_current`
  passed (one generator, 0.89 seconds). It executes the production CLI for three
  control envelopes against real refusal sockets; it does not exercise installed
  engine authority, recipient CLI delivery or actual provider I/O.
- The native socket/file delivery generator now exercises the production recipient
  client with an explicit control-frame shim, plus real approved native file grants.
  It is not an installed application-dispatcher claim. Native history is tested
  against retained snapshots and wrong-recipe refusal. The frame generator covers
  closed routing, duplicate/obsolete/unknown/override/oversize refusal and writes
  four maintained fuzz seeds; the fuzz dispatcher is updated for those schemas.
- Final required artifact generation passed six exact tests in 34.94 seconds:
  application content frame, content compilation/journal, candidate compilation,
  recovery acquisition and semantic closure. Candidate/recovery artifacts stayed
  byte-for-byte unchanged. No Python/TypeScript suite, broad local gate, formal
  execution or hosted CI observation ran. No A01–A22 case is closed. AP073 remains
  untouched; full installed process/adapters/UI and AP070 owner cutover remain.

## Native call authoring and complete CLI process composition checkpoint

- Based on `189bb1ea`. The preceding user turn was a status-only response, not
  implementation progress; this continuation revalidated the clean worktree and
  performed the next implementation/evidence step. No AP073 files or agents used.
- Native `content_authorization_call` uses the existing bounded duplicate-free
  JSON parser and `ContentReadTarget` against the installed connection. Native
  `disclosure_authorization_call` uses `DisclosureTarget` from retained source
  provenance. CLI `effect-content-call` and `effect-disclosure-call` save native
  canonical calls to new absolute 0600 files. No duplicate contract/hash, proof,
  approval, reservation, custody lease or transport authority is introduced.
- `content_journey.rs` generates `content-process-journey.json` through actual
  production CLI/daemon processes, native signed proofs/exact approvals, local
  file custody/journal and a counting loopback HTTP double. Test-only fixed-key
  trust authoring explicitly admits a bounded same-service tool set; each signed
  action/grant retains a single permission and undergoes native verification.
- The journey acquires content, authenticates a recipient CLI, saves exact bytes
  and canonical ACK in 0600 files, confirms durable ACK, kills/restarts the daemon
  and proves history replay produces neither new output files nor provider reads.
  A second native recipient process receives bytes and retains ACK without sending
  it; both peers are killed. Reopen reports unknown with one delivery/32 bytes
  retained. Replay returns history without delivery; exact late ACK refines the
  same charged journal, and repeated ACK is idempotent.
- The same daemon then performs an exactly approved write and a separately
  authorized recovery GET. The provider echo produces native `observed-by-provider`
  evidence, distinct from state-match evidence and the original HTTP response.
  Three total provider requests are asserted. Write/recovery replay adds none.
  A separate operator process disables the connection before another approved
  disclosure; it refuses with no content/ACK output. Historical ACK remains visible.
- Public control results exclude content/credential sentinels. Resource authoring
  rejects duplicate, extra, nonobject and 65,537-byte inputs, accepts the 65,536-byte
  boundary and preserves existing output files. The native recipient trust channel
  remains a test fixture, not an authenticated human UI or isolated hostile agent.
- Artifact generation initially caught fixture API/import mistakes, the query's
  expected percent encoding, and an incorrect test expectation that echo-linked
  observation also sets state-match. The final assertions retain the native
  distinction; production verification/reducer predicates were not weakened.
- Executed artifact command:
  `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --features testkit-harness,loopback-provider --test content_journey -- --exact native_content_process_journey_fixture_is_current`.
  Final complete process/crash/resource-boundary generation passed one test in
  3.08 seconds (one subprocess helper filtered from the parent run and invoked
  explicitly as a separate recipient process inside the journey).
- Required exact native content compilation, candidate compilation, recovery
  acquisition and semantic-closure generation passed four tests in 32.62 seconds.
  Content/candidate/recovery fixtures stayed byte-for-byte unchanged; the source
  closure and embedded digest were refreshed. The final process fixture was
  generated after the resource limit and output-preservation assertions landed.
  No local broad build/test/lint/formal suite was run.
- This strengthens A07/A08/A22 with real file/process composition; no entire
  acceptance row closes. Authenticated UI, installed Python/TypeScript packages,
  hostile UID/egress containment, PostgreSQL, remaining crash/race/fault points,
  full recovery operations, AP070 ownership removal, differential/formal/performance
  and required hosted evidence remain outstanding. No broad local gate or CI
  observation was performed.

## Standalone content-only installation checkpoint

- Based on pushed `c80902ab`, the previous process-composition increment. This
  continuation implements the missing read-only installation needed before AP070
  can move its managed reads to the native owner.
- Source `/3` may omit `write` only with the reserved native content tool and a
  valid required content capability. The compiler rejects mutation observation,
  echo, pre-entry/preconditions, relative ceiling and spend bounds in that case.
  Its lock admits binding/resource/account fields only; existing credential and
  registered-header validation remain authoritative.
- Lowering now has a closed `Mutation(Box<WritePlan>) | ContentOnly` alternative.
  ContentOnly has no write plan, and mutation construction refuses it before
  request/custody/transport. Native acquisition, disclosure, candidate credential
  checks and the journal/reducer are reused. No dummy write URL/body, GET write
  method, second read executor or provider dispatch was added.
- Rust review method and mutation recovery APIs now return Option. Content-only
  review/audit render absent mutation method/recovery rather than an imaginary
  recorded-write capability, with empty write path and zero body allowance. The
  content GET declaration remains explicit. All affected Rust/fuzz callers were
  cut over directly; existing mutation JSON/source identities are unchanged.
- `native_read_only_recipe_fixture_is_current` writes source/lock/review under
  `bindings/fixtures/gateway/content-only`, a negative read-only corpus and native
  fuzz seed. It covers missing content, custom tool, mutation adjuncts and write
  injection under the reserved read tool, plus absence of a native write plan.
- `native_read_only_process_journey_fixture_is_current` installs the real daemon
  with read/release-only native trust, refuses mutation review/submission and
  mutation recovery from acquired content, then performs exactly one counted
  provider GET and separate authenticated recipient disclosure/ACK.
- Final required artifact generation passed six exact native tests in 32.17
  seconds: read-only source, existing review contract, content/candidate/recovery
  compilation and semantic closure. Existing mutation review, content compilation,
  candidate and recovery artifacts remained byte-for-byte unchanged. The final
  read-only and mixed read/write process generators passed two tests in 3.05
  seconds; the previous mixed process artifact also remained unchanged. No broad
  local test/build/lint/formal suite was run.
- The user's subsequent explicit request to investigate/fix CI authorizes earlier
  CI triage. A CI subagent works only in an isolated checkout and reports commits
  for integration after this increment; it does not modify the main worktree.
  Final required hosted verification on the completed specification remains open.
- No complete A01–A22 case closes. Google metadata/reference parity, refresh
  custody, AP070 Python state-owner removal, installed language/UI, hostile
  containment and complete adapter/fault/formal/performance evidence still remain.

## User-requested CI triage and inventory correction checkpoint

- After the explicit user request to delegate CI failures, an isolated CI agent
  inspected hosted failures at `c80902ab`. Main implementation continued without
  shared-file edits. The first isolated fix `991c223d` was reviewed and integrated
  as `9c939036` after the read-only increment `cfaa8596` was committed.
- That fix updates the Python gateway export inventory from 17 to 18 (total 190),
  the TypeScript declaration digest, Python 3.9 runner matrices/artifact names to
  Ubuntu 24.04, and both qualification family corpus/contract source hashes.
  Qualification assumptions and declarations were preserved. The agent reports
  the API snapshot check and six focused qualification tests passing; exact
  commands/hosted job links are to be recorded with its completed report.
- Hosted preflight also found the semantic freeze stale. Required artifact
  construction `cargo xtask semantic-freeze --update` identified nine changed
  subjects. Freeze 391 and only those subject versions were advanced; regeneration
  succeeded. The current formal source closure did not change. This refresh is
  not a formal proof execution or a completed hosted gate.
- Remaining reported CI roots include stale native/installed tests expecting
  implicit observation, obsolete raw re-observation simulation calls, and demos
  lacking exact native effect approval/installation policy. CI fixes must use
  actual native authorization/recovery or truthful response-only expectations;
  tests/approvals may not be bypassed. Investigation continues in the isolated
  checkout, with deeper maintained demo integration still part of AP074.

## AP070 concrete metadata reference checkpoint

- Based on pushed `1ccfc09a`. The native content-only installation is available;
  the next provider-specific gap is the metadata gate preceding a Drive content
  GET. Current AP070 Python admission/release still remains to be removed.
- The Drive reader now calls one pure concrete metadata validator returning a
  closed document/plain-text representation. Custody, transport, status/media,
  task checks and state decisions remain outside that validator. Existing request
  selection uses the typed result. The existing 16 KiB bound is checked again;
  malformed MIME and excessive decimal conversions return typed refusal.
- A deterministic domain corpus freezes identity, download restriction, MIME,
  optional size/trashed semantics, malformed/nonobject inputs and byte boundaries.
  It explicitly labels historical duplicate/alternate-encoding, nonboolean trash
  and Unicode decimal acceptance as cases requiring stricter native refusal.
  Matching a weak historical parser is not a native acceptance requirement.
- Required artifact construction:
  `PYTHONPATH=demos/google-employee-delegation/broker/src AUTHS_UPDATE_FIXTURES=1 python3 demos/google-employee-delegation/broker/tests/test_google_metadata_reference.py`
  passed one generator in 0.002 seconds. It imports only the pure domain contract;
  no native package, Google credential, provider call or cloud account is used.
- This is concrete reference evidence ahead of extraction, not a completed native
  metadata gate or AP070 cutover. Full native/compiler/journal/freshness parity,
  both supported content paths, token refresh custody, bindings/UI and removal of
  the competing Python shared state owner remain open. No A01–A22 gate closes.

## Phase gates

| Phase | State | Outstanding gate |
| --- | --- | --- |
| P0 | Owner decision and limits documented | Keep consumer inventory current during cutover |
| P1 | Binding, approval and native review contract wired | Installed authenticated approval journey, frontend rendering and integration evidence |
| P2 | Ordered admission, mutation grant/restart and linked recovery refinement wired | Full public recovery actions, installed fault/race evidence and formal links |
| P3 | Acquisition/disclosure runtime, call authoring and CLI process composition wired | Installed bindings/authenticated UI, Google metadata/refresh and AP070 Python owner removal |
| P4 | Partial CLI process journey | Differential, full faults/adapters, installed bindings/UI, formal/performance links and CI |

## Acceptance ledger

`Authored` means scenario source exists, not that it passed. `Executed` requires
the exact tested revision and a reproducible result. External qualification is a
separate claim. No complete AP074 acceptance gate is currently closed or externally qualified.

| Case | Required evidence | Implementation / authored / executed | Limitation or next work |
| --- | --- | --- | --- |
| A01 | Same bound identity and exact request across review/approval/send | Partial / partial / native fixture only | Installed transport and review-completeness evidence pending |
| A02 | Independent mutation of every binding dimension | Pending / no / no | Freeze canonical corpus |
| A03 | Concurrent/restart replay, conflict, approval reuse | Partial / adapter and candidate process cases / local candidate concurrency/restart executed | Complete mutation/conflict and PostgreSQL evidence |
| A04 | Final count/byte/sum capacity, file and PostgreSQL | Partial / partial / narrow file admission, prerequisite and managed read charge fixtures | Full adapter concurrency and all units pending |
| A05 | Crash at every persistence/transport boundary | Partial / real daemon/recipient crash after receipt before ACK / charged unknown and exact late ACK executed | Remaining persistence/send boundaries and PostgreSQL |
| A06 | Sync/rename, partial batch, ambiguous commit/CAS | Pending / no / no | Fault injection |
| A07 | Revoke between acquisition and disclosure | Partial / socket-file and real daemon process corpus / separate operator disable prevents recipient CLI delivery | Full revocation scopes and adapter races |
| A08 | ACK loss, restart, no redelivery, late ACK | Partial / socket-file and daemon/recipient process corpus / both peers killed after receipt before ACK; charged unknown, no redelivery, late ACK executed | Remaining crash/persistence boundaries and PostgreSQL pending |
| A09 | ACK substitution in every dimension | Partial / native signed ACK corpus / exact dimension and re-signed substitutions executed | Live Unix handshake now exercised; independent-process and complete delivery integration pending |
| A10 | Timeout/denial/response/state-match distinction | Partial / candidate HTTP histories / six local process histories | Complete mutation, observation and disclosure projections |
| A11 | Missing/multiple/unrelated/incomplete reconciliation | Partial / native file corpus / synthetic response only | Installed transport and complete recovery projections |
| A12 | Revocation/configuration races with both entries | Partial / socket-file disclosure gate / dependency changes after authentication and competing live grants executed | Full independent-process races on both adapters pending |
| A13 | Lock wait and independent evidence expiries | Partial / prerequisite age and signed-observation cases / narrow file and native predicate fixtures | Installed lock-wait, independent expiry and adapter races pending |
| A14 | Valid threshold selection changes | Pending / no / no | Pin selected evidence |
| A15 | Recovery actor differs; original authority revoked | Partial / native compiler and file refinement / synthetic entry only | Revocation and installed execution |
| A16 | Cross-task/recipe/partition substitution | Partial / adapter cases / no | Full task-scope and installed boundary evidence |
| A17 | Sentinel privacy across errors/logs/public bindings | Partial / candidate output sentinels / local acquisition stdout/stderr | Full logs, receipts and binding privacy evidence |
| A18 | Canonical/malformed/duplicate/limit binding corpus | Partial / native tests and cross-language control cases / native closed content-frame corpus executed | Full binding parity and negative corpus execution pending |
| A19 | Stripe/Airtable and acquisition/disclosure differential | Pending / no / no | Retained independent references |
| A20 | Generated histories and shipping predicate refinement | Partial / 576 typed stage pairs, ACK histories and Kani source / pure corpus executed | Full generated concurrent histories and source-linked formal artifacts pending |
| A21 | Tombstones, stale state, supported rollback floors | Pending / no / no | Epoch/retention evidence |
| A22 | Installed single-human/single-agent full journey/UI | Partial / real daemon and CLI / read, recipient disclosure, exact write and independent observation executed with simulated signing | Installed language packages, authenticated human UI and hostile isolated agent still required |

## Deployment assumptions retained

Durability relies on acknowledged filesystem sync/rename and PostgreSQL commits.
Neither an in-memory test nor a Rust permit establishes malicious-process
isolation. Provider state matching does not establish exclusive causation.
Recipient authentication is a transport assumption. Whole-store rollback is
outside the guarantee without an independent monotonic anchor; a restored
database cannot attest to its own freshness. No new live-provider qualification
or deployment claim is made by AP074 source work.
