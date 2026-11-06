# AP073 execution and assurance ledger on merged AP074

## Objective, baseline and preservation

Complete AP-SPEC-073 M0–M4 and F01–F16, including the installed machine → A → B
journey, independent exact human approval, recovery, identity lifecycle,
federation/native-resource conformance and exact-revision assurance gates.
Do not merge or deploy. This file is the continuation ledger, not a completion
claim or a substitute for implementation.

Baseline: merged AP074 `68987975ac2bea6879c944b2ef6c5300702406ca`.
Working branch: `codex/ap073-native-delegation`.
Preserved AP073 checkpoint: `97163513` on
`codex/identity-authority-foundation`, including all previously uncommitted
native revalidation work. Its earlier full assessment and participant contracts
remain retrievable at that immutable revision. No paused source was reset or
deleted. No predecessor or AP074 run is current AP073 acceptance evidence.

The native goal service confirmed an active goal pointing to the user's full
objective file on 6 November 2026. This ledger retains the complete objective;
one bounded implementation batch does not reduce its completion criteria.

## Retain, strengthen, replace and remove

| Surface | Disposition and source-backed reason |
| --- | --- |
| `engine::verify_native`, `bounds::authorized_chains` | Retain full native verification and its selected branch path. Identity/enrollment checks cannot create a second verifier. |
| `effect::{BoundEffect,ApprovedEffect,EffectBinding}` | Strengthen scope and ancestor reservation binding. Current compilers produce `Scope::Unscoped`; the data-only `Task` alternative is insufficient for exact participant admission. |
| `entry::{InstalledEntry,EntryValidation}` | Extend the existing dependency set and fresh after-lock checks for enrollment/ancestor revocation. Do not copy the predecessor's revalidation owner. |
| `store::GatewayAttempts`, `GatewayAttemptStore` | Retain atomic admission, immutable history and consumed entry permits. Add engagement state as a bounded dependent native record; reject unsupported combined transactions. |
| `store::{acquisition,disclosure,capacity}` | Strengthen retained task/ancestor charge membership and scope/recipient linkage; preserve unknown and lifetime allocations. |
| Predecessor `participant_enrollment` | Review/reuse native parent/child/resource proof relation and immutable bounded tree. Adapt its verification boundary and remove dependencies on old task state. |
| Predecessor `release_state`, `task_write`, Google custody | Exclude from the continuation. Separate task/attempt ownership conflicts with AP074. Provider-specific assumptions cannot enter shared gateway logic. |
| AP070 Python broker | Preserve independent application-owned reference and narrower claims. It supplies no managed permit, credential or journal evidence. |
| `auths-lifecycle`, core identity adapters, bindings | Reuse exact contracts after source comparison. No new identity method, token language or compatibility framework is justified. |

Ownership and finite bounds are specified in [ADR 0018](../adr/0018-engagement-delegation-on-bound-effects.md).

## Requirement-by-requirement acceptance matrix

This table is the original continuation baseline, retained to distinguish its
initial gaps from later results. The dated construction sections below record
implemented/observed slices; exact-head hosted acceptance remains pending. Do not
interpret every baseline row as an instruction to reimplement completed work.

| ID | Required evidence and existing owner | Remaining work |
| --- | --- | --- |
| F01 | Native holder/audience checks; exact selected path in `bounds`; recipient authentication in `effect/disclosure_auth` | Bind installed participant/instance/executor and refuse substitution before custody or disclosure. |
| F02 | Core grant attenuation; candidate native enrollment relation and bounded tree | Canonical/malformed/mutation corpus across every enrollment dimension and multi-hop depths; link formal predicates to shipping source. |
| F03 | Existing acquisition/disclosure source binding | Exact engagement scope in all effect compilers, source/recipient flow validation and cross-task/cross-recipe refusal histories. |
| F04 | Existing atomic fixed-window/lifetime allocation and adapter fences | Typed task and ancestor charges, sibling final-capacity races across processes on file and PostgreSQL; explicit coordinated/escrow limits. |
| F05 | Existing permanent replay key and consumed native permits | Participant/executor audience binding and cross-executor replay/retained-permit cases across restart. |
| F06 | Existing exact effect approval and complete native review | Include complete participant ancestry/instance/scope/charges in approved binding; native negative corpus for every substitution dimension. |
| F07 | Existing explicit kernel time and native final-entry validation | Port the reviewed stale WebAuthn evidence correction if absent; participant validity and evidence expiry during actual lock wait; installed binding parity. |
| F08 | Existing disclosure Unknown/ACK distinctions | Multi-agent ACK loss/restart and late genuine ACK refinement without redelivery or refund. |
| F09 | Existing atomic operation/charge admission and durable grants | Add participant dependencies to crash/file fault/TLS PostgreSQL ambiguous-commit matrices without reconstructing permits. |
| F10 | Existing independent current recovery acquisitions | Bound child lineage and unique/incomplete/multiple response-less create reconciliation, preserving participant scope and no write retry. |
| F11 | Existing common writer fence for configuration/connection withdrawal | Enroll/revoke ancestors within that owner; process schedules for revocation before/after participant admission and final entry. |
| F12 | Existing principal adapters and connection generation floors | First identity lifecycle contract, compromise/recovery and invalid descendant tests; recovery must not revive old authority. |
| F13 | Existing installed Linux boundary/interface inventory | Isolated machine/A/B keys/channels and credential/log/error/model/egress probes; record deployment assumptions. |
| F14 | Existing Rust-owned canonical APIs and binding fixture machinery | New native public inspection/construction surfaces, bounded malformed corpus and installed Python/TypeScript parity. |
| F15 | Existing epochs/generation floors and retained replay/unknown facts | Dependency-complete cache behavior and restored/stale participant state refusal under declared independent-floor assumptions. |
| F16 | Existing truthful public history/private audit and native literal review | Full participant ancestry/roles, human review and installed multi-agent timeline; no upgraded receipt claims. |

## Work batches and exit criteria

1. **M0/M1: reconcile and establish native participant relation.** Restore the full
   specification with AP074 ownership. Review/reuse exact native parent control,
   child acceptance, resource grant suffix, finite tree and canonical decoders.
   Write the entire structural, signature, widening and stale/invalid-input
   corpus together. Exit requires source-linked tests and a reviewed contract;
   a proposal/tree remains non-executable until the next batch connects it.
2. **M1/M2: integrated scope/admission.** Extend native effect identity and
   current entry dependencies, shared adapter records and atomic typed charges.
   Write all native compiler, sibling-budget, cross-task and ordered-revocation
   cases before combined verification. Exit requires actual native paths on both
   maintained adapters, with unchanged AP074 single-grant/Unknown semantics.
3. **M3: installed multi-agent journey and recovery.** Use the admitted content
   and mutation recipe families, independent approver, separate machine/A/B
   processes and actual provider/recipient transport. Extend crash/reconciliation
   and binding/UI paths. Exit requires all applicable F scenarios exercised and
   evidence that distinguishes entered, received, acknowledged and observed.
4. **M4: lifecycle and broader enforcement.** Specify and implement the first
   identity recovery/federation profile and native-resource enforcement ADR,
   conformance and isolated journey. Explicitly decide supported coordinated
   versus offline escrow behavior; unsupported modes fail closed and may not be
   silently dropped from the program. Preserve trust-domain separation.
5. **Whole-program closure.** Regenerate canonical fixtures and inventories in
   one planned batch. Publish genuine AP073 work to its own reviewable PR and
   run the repository's GitHub-first applicable CI, formal, binding, packaging,
   conformance and installed journey gates. Inspect exact-revision results only
   after completing implementation as requested. Never push to merged PR213.

No broad behavioral, lint, formal or CI gate has run on this continuation.
The required artifact constructors are recorded separately below; all acceptance
criteria remain open until their full exact-revision evidence is established.

## Execution log

- **6 November 2026:** read full user objective; confirmed active goal and clean
  continuation at merged AP074. Reconciled scope without importing old task
  execution owners. The preceding goal turn made preservation progress by
  committing `97163513` and creating the continuation branch; the user then
  paused. This turn resumes under the newly active full objective.


## Native enrollment batch: source and required artifact constructors

The restored native participant relation uses `engine::verify_native` with an
expected audience derived from installed control/resource pins, preserving the
installed anchors and required configuration. It verifies separate parent
control, child acceptance and resource grants. `EnrollmentTree` retains bounded
ancestry, revoked identities and ID/principal non-reuse. Its scope verifier
compares the exact selected native root-to-leaf suffix, literal resource and
engagement/recipe/partition audience. Future-created-child witnesses cannot
establish a literal runtime target without independent managed lineage evidence.
Private tree/pin/identity Debug output is redacted.

The recipe compiler now excludes the shared native control-service namespaces,
even when a source and lock deliberately agree. No old task or release ledger,
provider branch, materializer or alternate permit was imported. This batch does
not yet add executable managed delegation, persisted enrollment/admission,
ancestor charging, native resource enforcement or current entry-fence dependencies.
Resource witnesses currently refuse grant extensions and native budget ceilings;
that restriction must be reconciled with admitted bounded resource policies in
the integrated compiler batch rather than bypassed.

Planned batch evidence: 33 native example/corpus cases, two generated properties,
and the three-recipe control-namespace refusal matrix. Required local artifact
construction is limited to the native enrollment corpus and semantic closure,
using the existing `AUTHS_UPDATE_FIXTURES=1` constructors after writing this batch.
It is required to construct the committed artifacts under the GitHub-first
exception; it does not replace hosted behavioral, binding, formal or installed
journey gates. Record their actual results before claiming those artifacts.


### Confirmed integration gaps from the merged source

- AP074 `EffectBinding` still serializes a data-only `Task` commitment but every
  maintained compiler emits `Unscoped`; acquisition/disclosure targets refuse
  task scope. Replace that placeholder with complete participant/scope evidence
  in the integrated compiler; decoding metadata alone cannot authorize it.
- Native `SourceCapacity` currently covers one source's call and byte allowance.
  Ancestor/task charges must use the same atomic native admission and intact
  final-entry membership checks, without creating a mutable usage ledger beside
  attempts. Include every inserted row and predecessor dependency in the existing
  64-record fence bound; exhaustion refuses rather than skipping ancestors.
- `EntryValidation::dependencies` currently owns connection, effect configuration
  and optional commissioning dependencies. Participant state and revocation must
  join that read set and its writer protocol; pre-lock tree verification alone
  cannot establish F11.
- Merged `core/adapters/auths-webauthn/src/lib.rs::assertion_claims` still assigns
  `evaluation_time` to `user-verified`. The preserved AP073 correction (`211fd87d`,
  included in `97163513`) removes the fabricated event time and versions assurance
  semantics/configuration. This confirmed F07 gap must be restored with its
  native/binding evidence, not treated as an AP074-established property.


### Artifact construction result, 6 November 2026

Both required constructors passed after the complete native enrollment batch was
written and formatted:

- `AUTHS_UPDATE_FIXTURES=1 CARGO_BUILD_JOBS=4 cargo test -p auths-gateway --lib participant_enrollment::tests::native_participant_enrollment_fixture_is_current`
  generated `bindings/fixtures/gateway/engagement/enrollment.json`. It contains
  actual signed parent, child and resource inputs for valid, wrong-instance and
  wrong-resource cases, plus explicit private-attribution and non-entry limits.
- `AUTHS_UPDATE_FIXTURES=1 CARGO_BUILD_JOBS=4 cargo test -p auths-gateway --lib semantic_closure_is_current`
  refreshed the native manifest and its source digest.

The gateway's default-feature library test target compiled. These two filtered
artifact constructor executions do not establish the rest of the written native
cases, generated properties, installed bindings, concurrency, formal or hosted
acceptance. No CI push/observation, merge, deployment or provider operation was
performed. Full M0–M4/F01–F16 remains active.


## Shared engagement configuration batch

The previous turn made source and artifact progress in `606f9747`; it was not
AP073 closure. This batch adds native enrollment configuration to the same
adapter store and writer fence. No operation/usage ledger, execution permit or
approval authority is added. The root contract directly cuts over to version 3
with a shared authority namespace/partition, exact connection commitments and
registered native channel commitments. The tree cuts over to version 3; old
prelaunch root/tree forms are refused.

The complete planned source/test batch covers: root commitment substitution in
all new dimensions; native controller/sibling/ancestor withdrawal restrictions;
file and TLS PostgreSQL bootstrap, concurrent enrollment, reopen, retained
revocation, configuration withdrawal and clock rollback; an actual committed
write with a lost acknowledgement; and clock advancement inside the adapter's
native decision callback. Private snapshots must retain history without granting
new eligibility. All cases are written before the required corpus/semantic
artifact constructors run. Broader hosted gates remain deferred until the full
implementation is ready, as requested.

The operation effect compiler, atomic ancestor reservations and final-entry
participant dependency read set still need integration. Adding protected
configuration alone does not close F04/F09/F11 or permit a scoped provider call.


### Additional reviewed boundaries in this batch

Known raw-key/`did:key` aliases now use the existing central
`principals_overlap` relation at descriptor validation, retained-ID publication
and stored-tree validation. Distinct identifiers for the same recognized key
cannot create independent participants. Other identity methods retain their
explicit existing comparison limits; process uniqueness still needs protected
instance keys and deployment evidence. Two native/serialized adversarial cases
are included in the batch, bringing its new configuration/control cases to 14.

The root corpus cuts over to `auths.participant-enrollment-vectors/2` and now
contains a natively verified version 3 root activation and resource witness,
not an arbitrary synthetic root commitment. Broader adapter and fault cases
remain source-authored until their required hosted execution.

**F16 audit gap:** the protected enrollment configuration currently retains
immutable descriptors, ancestry and withdrawal state, but not the full original
control proofs or a per-transition native-input/time receipt. It is historical
configuration data, not independent cryptographic evidence of each past consent
or revocation decision. The complete audit/export work must bind the original
native inputs, trusted context and decision time (and truthfully report missing
inputs) before making an independent enrollment-audit claim. Do not infer that
claim from successful decoding or a signed operation receipt.


The batch also includes the required private configuration-record corpus
constructor, `native_engagement_configuration_fixture_is_current`. It builds
actual file-adapter records through native root bootstrap, child enrollment and
withdrawal; reopens the adapter and checks that replay/expiry sweeping do not
reactivate or delete that history. The corpus labels its missing original-proof
retention and its lack of operation/permit claims. This is the third required
artifact constructor, alongside the revised root/enrollment corpus and semantic
closure. It does not execute the remaining concurrent/TLS/fault cases or qualify
independent enrollment audit.


### Confirmed configuration artifacts, 6 November 2026

After the full planned source/test batch was written, all three required local
artifact constructors passed: `native_participant_enrollment_fixture_is_current`,
`native_engagement_configuration_fixture_is_current`, and
`semantic_closure_is_current`, each through `AUTHS_UPDATE_FIXTURES=1
CARGO_BUILD_JOBS=4 cargo test -p auths-gateway --lib <filter>`. The native default
library target compiled with 336 cases; only the three named constructors ran.
The retained logs are `/tmp/ap073-configuration-batch-{root-enrollment,configuration,semantic-closure}.log`.
The orchestration process is terminal. No broader concurrency, PostgreSQL,
binding, formal or hosted gate is claimed. No push or CI observation occurred.

The pause/resume changed goal scheduling only. On resumption the native goal
service reports `active`; the current source and constructor logs were reread.
Full M0–M4/F01–F16 remains open.


## F07 WebAuthn freshness batch

Before extending the scoped effect compiler, restore the independently preserved
`211fd87d` correction as a direct source cutover on AP074. The reviewed current
`auths-assurance::evaluate_with_implications` already requires an observation
time for any maximum-age constraint. Leave the historical UV event undated;
do not add a gateway-only clock interpretation or a second freshness evaluator.
Native adapter assurance revision 2 and configuration domain
`webauthn-v1/assurance-v2` commit the change. Registration-derived claims retain
their existing observation times and explicit registration validity checks.

The complete planned batch includes native claim invariance over evaluation and
asserted-signing times; root/actor portable ABI cases at two times, both with
and without maximum age; four canonical age-limited root/actor corpus vectors;
matching independent Go/TypeScript behavior; protocol/profile documentation;
and a regenerated shared core corpus and native gateway semantic closure.
No old canonical binaries or obsolete adapter configuration readers are copied.
The only planned local executions construct required artifacts: `cargo xtask
wire --update`, `cargo xtask semantic-digest` (the Go aggregate fixture pin),
and `AUTHS_UPDATE_FIXTURES=1 cargo test -p auths-gateway --lib
semantic_closure_is_current`. Broader ABI/binding/conformance behavior and F07's
participant clock/fence obligations remain hosted closure work. Global semantic
freeze/source-closure and qualification evidence must be refreshed against the
final full source batch; stale qualification artifacts establish no AP073 claim.


### F07 required artifact result, 6 November 2026

All three planned constructors finished successfully in the same batch:
`cargo xtask wire --update` generated 1,617 files for the 323-vector corpus;
`cargo xtask semantic-digest` produced
`323:deeed0ff7cb085ea1420aa15159ec13783413a156ae94cc1e5f7313beff02b07`,
now pinned in the independent Go corpus test; and the filtered gateway
`semantic_closure_is_current` constructor passed. Logs are
`/tmp/ap073-webauthn-{core-wire,semantic-pin,gateway-closure}.log`. Inspection of
the generated manifest confirms each root/actor recheck pair has identical
signed proof/action bytes, distinct context bytes and the native
`indeterminate/assurance-requirement-not-met` outcome. The unaged native fixture
remains authorized in the semantic projection. Core protocol/corpus version
counters are advanced; final global freeze/source/qualification refresh remains
required with the complete implementation.

The new adapter and portable-ABI regression tests are source-authored, not run.
The independent Go/TypeScript executables, installed bindings, full conformance,
participant timing/fence tests, formal and hosted gates have not run. F07 remains
open for those wider obligations. No push, CI observation, provider operation,
merge or deployment occurred.


## Integrated effect-scope source batch

Extend the existing effect policy/compiler and entry owner rather than adding a
second task permit. This batch writes the operator-bound complete root/executor,
native audience, selected mutation grant path and literal resource, immutable
ancestry, typed planned charge keys, complete review, actor/approver separation,
and fenced configuration dependency before executing its required constructors.
It directly versions effect/policy shapes (4/2), preserving root/tree version 3.

The planned new cases are six native tests in `effect_engagement_tests.rs`:
installed root/tree/connection/expiry refusals; executor/approval substitution
with shared charge keys; nine malformed ancestry/charge variants and obsolete
schema refusal; a canonical native effect corpus; actor self-approval refusal;
and entry snapshot composition across current, revoked, missing and future-time
enrollment. Snapshot composition is not evidence of cross-process scheduling.
The fixture helper uses actual signed root activation, child consent, resource
grants and the maintained native verifier. It performs no provider operation.

Local execution is restricted to required artifact construction after this full
source/test batch: the new `native_engagement_effect_fixture_is_current`, the
existing `native_compilation_approval_and_reverification_keep_exact_request`
(base effect/policy/approval artifacts), and `semantic_closure_is_current`.
Other AP074 artifacts affected by final schema/semantic identities, the global
freeze/source qualification, installed bindings and broad hosted behavior remain
part of the final whole-program constructor and verification batch. No old
fixture is evidence for the changed source.

**Open required integration:** common journal admission/entry must persist and
validate each lifetime ancestor allocation atomically with the operation. The
installed entry owner refuses scoped transport until that exists. Information
compilers refuse a required engagement rather than emitting `Unscoped`.
Their resource/source/recipient relations, bounded extension witnesses, actual
file/PostgreSQL races and crash schedules remain required. All F01–F16 stay open;
this is a source increment toward the full goal, not a completion claim.


### Scope constructor result and source review

The initial complete constructor cohort exposed two compile errors: a missing
configuration dependency field on the candidate runtime owner and a borrowed
review temporary in the native fixture helper. Both were repaired together.
The second cohort passed all three required constructors: the new native
engagement effect, the existing base mutation effect/policy/approval, and gateway
semantic closure. The default-feature library target compiled 342 tests; only
the three constructors ran. Logs are `/tmp/ap073-effect-scope-repair-{scope,base-effect,semantic-closure}.log`.
The canonical new effect contains two real enrolled ancestors and their typed
planned write charges. It explicitly excludes provider-entry/accounting claims.

Source review additionally made scope lookup compare the installed literal
resource before rejecting ambiguous matches, so distinct installed resources
sharing a service/tool need not conflict at the lookup stage. The full native
scope verifier still repeats the exact handle/grant comparison. Narrow fixture
length lint annotations document two complete native setup cases. Refresh the
semantic manifest after these final source edits; do not cite the previous
digest for them. No hosted CI, broad behavioral tests, bindings, provider I/O,
merge or deployment has occurred, and AP073 remains incomplete.


### Final artifact acknowledgement for the scope batch

After the final source review edits, the same three required constructors passed
again as one affected batch. Logs are
`/tmp/ap073-effect-scope-final-{scope,base-effect,semantic-closure}.log`.
The native engagement corpus, base effect/policy/approval corpus and semantic
manifest now match this source. The other five new cases were compiled but not
executed. No broad local or hosted verification is implied.

### Next journal integration boundary

The next source batch must put typed immutable ancestor allocation references
in the existing generic `Record<S>` header (with a direct attempt-schema cutover),
and append bounded permanent allocation slots using the existing
`EffectAllocation` kind. A shared fenced admission helper must publish the
operation, selected ancestor slots and existing protocol counters together,
then each grant must verify those exact retained references under its own native
entry fence. Count, disclosed-byte and protocol units remain distinct; zero
bytes still charges a disclosure count. Counter keys exclude recipe/workload;
allocation references cannot be reconstructed as permits. Unknown and revoked
history retains all slots. Collision retries may choose only unoccupied bounded
slots and must never retry an ambiguous persistence acknowledgement.
No independent task journal, mutable usage ledger or store decorator should be
introduced. The 34-reservation/64-record limits and deadline still apply; refuse
unsupported combined sets. Remove the current scoped-entry refusal only after
this owner and its file/PostgreSQL, replay, concurrency, lost-ACK and crash cases
are implemented and mapped. Information scope/source/recipient compilation must
then join the same contract, preserving all AP074 evidence distinctions.


## Atomic ancestor journal batch

The preceding turn made source/artifact progress in `dceaad4c`; the goal remains
active and all M0–M4/F01–F16 criteria remain in scope. The current worktree began
clean. This batch extends the common generic journal header, not a separate
mutable task ledger. Attempt schema 17 carries immutable references to permanent
ancestor/unit allocations. Mutation, acquisition and disclosure admission use
one fenced insert helper, and all three grant owners verify those exact rows in
their existing final fences. Configuration/time/native/approval checks remain
in `EntryValidation`; durable adapter acknowledgement still precedes a permit.

The complete planned source/test batch includes:

- actual native root activation and two independent child consents persisted
  through `EngagementConfiguration`, sharing one root write unit;
- file and TLS PostgreSQL claim, replay, acknowledged grant, dropped-handle
  restart projection, sibling exhaustion and no partial sibling charge;
- concurrent independently opened adapters, with both selecting vacant slots
  before their real fences, for one winner at the root's last unit;
- real committed claim/grant with lost acknowledgement delivery, conservative
  history, no duplicate charges and no reconstructed permit;
- missing allocation snapshots; native root withdrawal before claim or entry;
- feature-gated real file I/O failures at all three operation/ancestor target
  installs, and TLS PostgreSQL server rejection at every insertion position;
- pure allocation-prefix arithmetic/representation cases including zero bytes,
  byte exhaustion, changed ceilings and substituted units; this primitive test
  does not claim scoped information authority;
- an actual file admission/grant corpus with original native mutation inputs,
  allocation rows and explicitly named private record projections. Random nonces
  are omitted from projections, never replaced in restorable journal bytes.

The first scoped mutation prototype exposed another confirmed integration gap:
AP074 prerequisite acquisition records retain the parent mutation binding. Write
charges cannot stand in for participant read charges. The common journal refuses
that scoped composition until typed prerequisite charges and lineage are
implemented. Information scope/source/recipient compilation remains refused.
No unsupported path may silently emit unscoped effects or spend the wrong unit.

After all source/tests are written, local execution is limited to required
artifact construction: `native_engagement_admission_fixture_is_current`, revised
`native_engagement_effect_fixture_is_current`, and `semantic_closure_is_current`.
The remaining new tests, PostgreSQL, actual process schedules, installed bindings,
formal source/refinement and hosted acceptance remain pending their final full
batch. Other AP074 artifacts affected by schema 17 require native regeneration
in the complete final fixture batch. No predecessor result closes these claims.


### Initial ancestor constructor results and replay-race review

The first complete constructor cohort exposed three compile errors confined to
new test support: the existing store-kit constructor is `open`, and both fault
adapter callbacks must use the existing lifetime-aware `GatewayFenceDecision`
alias. These were repaired together with a redundant import. The second cohort
passed all three required constructors with `loopback-provider,testkit-harness`:
real file native admission/grant/reopen, revised scoped effect corpus, and
semantic closure. The feature-complete library target compiled 436 cases;
only the three constructors ran. Logs are
`/tmp/ap073-ancestor-repair-{admission,effect,semantic-closure}.log`.

Source review then identified a lookup/capacity race: an identical winner may
consume the final ancestor unit between the initial history read and slot scan.
The common owner now delegates an already-present operation to exact-binding
replay instead of reporting its reservation as exhausted. Two additional
file/PostgreSQL cases model the earlier lookup absence while every subsequent
read observes the maintained committed store. They are explicit boundary
schedules, not actual process-concurrency evidence. Refresh the affected
constructor cohort after this source repair. Broad behavior and PostgreSQL
remain unexecuted locally; no CI push/observation has occurred.


### Final acknowledged ancestor artifacts

After the replay-race repair, all three required constructors passed as one
cohort with `loopback-provider,testkit-harness`. The feature-complete library
target compiled 438 cases; only `native_engagement_admission_fixture_is_current`,
`native_engagement_effect_fixture_is_current` and `semantic_closure_is_current`
ran. Logs are `/tmp/ap073-ancestor-final-{admission,effect,semantic-closure}.log`.
Inspection confirms two actual ancestor allocation rows, real schema-17 grant
facts and a correctly named projection omitting the random nonce. The case
checks the public reopen projection is Unknown, retains the underlying private
EntryGranted fact, refuses replay and exhausts a sibling without partial charge.
No permit was sent, credential leased or provider contacted.

Remaining acceptance is still substantial: execute the authored file/PG
races/faults and real process schedules; integrate scoped information, source,
recipient/channel and prerequisite charge lineage; complete managed recovery,
binding/installed journey, lifecycle/federation/native-resource contracts and
source-linked formal evidence; regenerate the complete affected corpus and
release inventories; then publish and inspect exact-head hosted CI as requested.
No broad local gate, PostgreSQL execution, push, CI observation, merge or
deployment occurred in this batch. All F01–F16 remain open for their full scope.

## Scoped information batch, 6 November 2026

The next bounded implementation extends the same effect/compiler and journal
owners to literal-resource content, independent recovery reads and separately
authorized disclosure. It directly cuts over to bound-effect 5/compiler 10 and
engagement-scope 2; no obsolete reader is retained. Root/tree formats remain 3
because their representations are unchanged. Resource witnesses now interpret
the content action's verified nested resource arguments. Compilers accept only
full native authority, the exact installed native grant suffix and active
enrollment. Recovery/disclosure obtain resource identity from protected retained
source provenance and refuse another engagement/root/account/recipe or an
unscoped escape. They do not reuse the original source actor's authority.

Disclosure also binds the active enrolled recipient path, registered channel,
instance generation and consented resource metadata. Native sender authority
and independent human approval remain required; live recipient authentication
is still a separate final-entry obligation. Disclosure reservations charge the
distinct sender/recipient ancestor union for count and actual projected bytes,
with common ancestry counted once. This is an exposure ceiling on both sending
and receiving. Empty content retains count charges. The same atomic journal
admission and final grant owner persist/verify these declarations; no task ledger
or provider branch is introduced.

Planned source/tests include real file and TLS PostgreSQL adapters, native
content/direct-action compiler equivalence, foreign resource and unenrolled
native-holder refusal, cross-engagement source refusal, recipient/channel
substitution, current recipient withdrawal, zero-byte disclosure count, ancestor
read/disclosure exhaustion without partial charges, exact replay/reopen and
dropped read grant projecting Unknown. A recovery case withdraws the original
writer through maintained native configuration and separately admits/grants a
current sibling reader under the final fence. These fixtures use controlled
time and injected synthetic complete response facts after dropping an actual
read permit. They establish no HTTPS provider or live recipient behavior.

The required canonical constructor will carry an explicitly named diagnostic
projection of disclosure scope/charges, omitting randomized content MACs and
dependent identities; it is not a restorable edited journal record. Whole native
bindings and real records are compared during the case itself. The existing
mutation effect/admission corpora and source closure must be refreshed together.
Execution results are pending; no new behavioral or hosted pass is claimed.

Remaining full-program requirements include typed prerequisite read lineage
(still refused rather than charged as writes), created-resource lineage and
uncertain-create reconciliation, original enrollment proof/context/time audit
history, live scoped delivery/ACK loss, actual process schedules, cross-recipe
sharing/isolation, installed multi-hop machine→A→B bindings journey, lifecycle/
federation/native-resource contracts, source-linked formal refinement and final
complete fixture/release inventories. No previous AP074 gate substitutes for
these requirements. All F01–F16 remain open for their full scope.

### Information constructor initial results

The complete feature-enabled library target compiled 445 cases without compile
errors. The initial cohort refreshed the mutation effect, admission and source
closure artifacts successfully. The information constructor exposed two fixture
expectation errors: a foreign resource must first satisfy the recipe's identifier
syntax, and an exact disclosure reservation replay returns retained Reserved facts
rather than an error. Neither returns a delivery permit. The fixture now uses the
existing valid other-resource constant and checks the returned stage plus exact
unchanged retained bytes. Independent empty-content, writer-withdrawal/recovery
and recipient-withdrawal cases are collected as one constructor cohort; all three
passed in the initial repair run. Full information construction is pending the
corrected replay assertion; no PostgreSQL, transport or hosted pass is claimed.

### Acknowledged scoped information artifacts

After the complete fixture repair, the four required constructors passed with
`loopback-provider,testkit-harness`: `native_engagement_information_fixture_is_current`,
`native_engagement_effect_fixture_is_current`,
`native_engagement_admission_fixture_is_current` and
`semantic_closure_is_current`. Logs are
`/tmp/ap073-information-final-{information,effect,admission,semantic-closure}.log`.
The feature-complete library target compiled 445 cases; only these four filtered
constructors ran. The information constructor actually executes its independent
file-backed empty-content, current-recipient-withdrawal, original-writer-withdrawal
and full information lifecycle cases before writing the artifact. It confirms
current sibling recovery authority can be granted after the original writer is
withdrawn; read grant loss reopens Unknown; disclosure replay returns unchanged
reservation facts; common root exposure is charged once; exhaustion creates no
partial operation/ancestor rows. No read or disclosure permit is sent to transport.
All responses are explicitly injected synthetic facts, not provider evidence.

The new canonical `bindings/fixtures/gateway/engagement/information.json` contains
native data plus named diagnostic projection, with its unestablished claims listed.
Broader authored tests and PostgreSQL did not run locally. Full native binding,
corpus/freeze/qualification, installed multi-hop and source-linked formal work
remain required. No push or CI observation occurred; full AP073 remains active.

## Native prerequisite lineage batch

The confirmed prerequisite gap is addressed in the existing effect and journal
owners, without an independent task ledger or a second grant authority. The
direct bound-effect 6/compiler 11 cutover adds ordered typed prerequisite budgets
to the same exact approved parent description. The native compiler binds each
closed read index, response-byte ceiling and complete ancestor read declaration.
Existing request membership witnesses independently compare the index and full
closed request commitment. Each prerequisite's distinct child journal record
atomically reserves read units against the shared ancestor read keys, alongside
its source allowance. The parent mutation's write allocations are neither reused
as reads nor charged again. The typed state owner chooses the exact declaration
set and checks retained rows at entry under the same native configuration fence.
Unknown and failed prerequisites retain capacity; they never authorize blind
retry or release. Decoding remains historical data, not native authorization.

The full planned batch includes file and TLS PostgreSQL parent/child admission,
exact replay, durable child grant loss/reopen, actual committed claim/grant with
lost reply delivery, current root withdrawal before child grant, malformed typed
budgets, substituted write allocations and out-of-range prerequisite membership.
The native fixture constructs real grants but drops every permit; it does not
establish HTTP behavior, provider predicates or completion of a guarded mutation.
The acknowledgement fault adapter wraps maintained store commits and changes
only reply delivery. It is not an actual process-crash experiment.

After all source/tests are written, the required constructor cohort is the new
native engagement prerequisite artifact, refreshed native engagement information,
mutation effect and admission artifacts, native unscoped prerequisite compilation,
and gateway semantic closure. Other affected AP074 corpora, global inventories,
qualification, bindings, formal and hosted gates remain pending final full-program
regeneration/verification. No new execution pass is claimed at this point.

### Acknowledged prerequisite artifacts

All six required constructors passed in the initial combined cohort with
`loopback-provider,testkit-harness`: native engagement prerequisite, information,
mutation effect and admission; native prerequisite compilation; semantic closure.
The feature-complete library target compiled 447 cases; only these six filtered
constructors ran. Logs are
`/tmp/ap073-prerequisite-initial-{prerequisite,information,effect,admission,native-prerequisite,semantic-closure}.log`.
The new engagement prerequisite artifact contains the exact parent binding,
typed planned read budgets, actual ancestor read allocation rows and conservative
child Unknown snapshot. Its lifecycle, lost claim/grant replies and current
withdrawal cases all executed on maintained file stores. They compare retained
rows across replay/reopen and confirm the parent write bytes remain unchanged.
Substituting parent write references or another child index fails native journal
decoding. Every issued permit is dropped; no provider request or predicate result
is asserted. The existing unscoped prerequisite compilation/entry artifacts were
also regenerated through their native constructor.

No new PostgreSQL, actual process-crash, broad local gate, binding/formal gate,
push or CI observation occurred. Full AP073 remains active, with original
control-evidence audit history, managed created-resource/reconciliation,
live scoped delivery and cross-process/cross-recipe schedules, installed
machine→A→B journey, lifecycle/federation/resource contracts, final whole-program
artifact/release inventories and exact-head assurance still required.

## Original native control-evidence batch

The next bounded batch addresses the previously confirmed F16 original-input
retention gap in the existing configuration owner. Configuration schema 2 binds
an ordered original-evidence/context reference and fenced clock sample to every
changed root/enrollment/withdrawal revision and its before/after tree commitments.
The existing immutable store stages content-addressed private chunks in fixed
atomic groups and acknowledges their manifest before publication. The final
control fence reloads manifests, current configuration and tree, samples time
and repeats full native verification. No preparation record authorizes anything;
failed/ambiguous preparation leaves the old authority state unchanged. Permanent
store integrity/durability is an explicit assumption, and interrupted preparation
may leave inert private orphans. No concurrent orphan-pruning path is added.

An operator-private audit export includes the complete original native inputs
and exact contexts. The offline verifier requires independently supplied root
pins, original contexts and a trusted acknowledged checkpoint, then replays the
maintained native relations for every transition. Stored contexts are not trust
anchors. The result is historical data; a recorded time/digest does not establish
external timestamp truth, checkpoint authenticity, whole-store rollback detection
or present authority. Those deployment obligations remain open. Missing or
corrupt evidence is an explicit export/verification error, never an unsupported
success claim or reconstructed permit.

The planned complete test batch includes real file and TLS PostgreSQL history /
reopen; exact checkpoint/context/root checks; missing, duplicate, reordered,
corrupted and oversized evidence; forged child acceptance with recomputed storage
hashes and even a deliberately trusted forged metadata head; expired native
control at a changed recorded time; historical audit after current expiry;
actual retained chunk corruption; lost preparation and final control replies;
missing publication manifests under the final fence; arbitrary-byte decoder
properties; and opaque blob custody spanning more than one 64-row atomic group.
The old artificial saturated-revision test is replaced with a check that revision
must match the actual finite retained history; malformed history cannot become a
valid snapshot. Compliance inventories include the new private types, schemas
and authored evidence paths. Source-authored tests are not passing-run evidence.

Only the required artifact-construction cohort will run locally after the whole
batch is written: new native audit; revised native configuration; engagement
information, prerequisites, effect and admission; semantic closure. These use
controlled fixture clock/checkpoints, real file storage and native verification.
They claim no externally anchored timestamp/checkpoint, actual process crash,
PostgreSQL execution, installed containment or transport. Full AP073 M0–M4/F01–F16,
source-linked formal refinement, complete corpus/global release identities and
exact-head hosted acceptance remain in scope. No CI push/observation is authorized
until the complete implementation/spec work is finished.

### Initial control-audit constructor cohort

The first complete seven-constructor cohort could not compile because a new
property assertion nested a captured `format!` inside `proptest`'s diagnostic
macro. All seven commands reported that same test-support expansion error; no
constructor runtime result was established. The repair computes the redacted
string before the property assertion. The full affected cohort will run again;
no behavior or hosted gate is claimed from the failed compile.

### Native replay result and final decoder review

After the diagnostic-macro repair, all seven required constructors passed with
`loopback-provider,testkit-harness`. The library target compiled 452 cases; only
the seven filtered constructors ran. Logs are
`/tmp/ap073-audit-repair-{audit,configuration,information,prerequisite,effect,admission,semantic-closure}.log`.
The new audit constructor's independent file history and acknowledgement cases
both executed, including native rejection of a forged child proof even with
recomputed blob/configuration hashes and a deliberately trusted forged head.
It also exercised actual retained chunk corruption and private export refusal.
These are controlled native/store cases, not external checkpoint/timestamp or
PostgreSQL evidence.

Final decoder review tightened the central bounded-sequence reader so it skips
rather than materializes the first excess private item before refusing the
sequence. The native audit constructor now also refuses a 65-blob envelope.
Refresh the required constructor cohort after this source change. Broader
multi-batch blob custody and arbitrary-byte properties remain authored/unrun
locally, together with PostgreSQL and full hosted/formal/binding acceptance.

### Final acknowledged original-control audit artifacts

After the bounded-sequence change, all seven required constructors passed as one
cohort with `loopback-provider,testkit-harness`. The feature-complete library
target compiled 452 cases; only the seven filtered constructors ran. Logs are
`/tmp/ap073-audit-final-{audit,configuration,information,prerequisite,effect,admission,semantic-closure}.log`.
Inspection of the new 50,348-byte native audit corpus confirms four actual
configuration revisions and five distinct original-input/context blobs, including
one deduplicated exact canonical context. Full native root/enrollment/withdrawal
replay, forged child proof/recorded-time refusal, checkpoint/root/context checks,
private retained-chunk corruption, reopen after expiry and lost preparation /
publication reply cases executed on maintained file stores. No operation record,
credential lease, provider request or transport permit was constructed by the
audit fixture. The revised configuration corpus now labels its original evidence
references and points to the complete private audit corpus.

This establishes the bounded original-control retention/replay subrequirement
under explicit trusted-input, clock and permanent-store assumptions. It does not
close full F16, bind an external trusted checkpoint/timestamp, detect whole-store
rollback, or establish PostgreSQL, actual process-crash, multi-batch blob custody,
arbitrary-byte properties, installed/binding/formal or hosted behavior. The latter
source-authored cases remain pending their prescribed final verification. Full
AP073 M0–M4/F01–F16 remains active; no push, CI observation, merge or deployment
occurred. Remaining work includes managed created-resource lineage/reconciliation,
live scoped delivery/ACK loss and cross-process/cross-recipe schedules, installed
machine→A→B with independent human exact approval and binding parity, lifecycle /
federation/native-resource contracts, complete corpus/global release identities
and source-linked formal/exact-head hosted evidence.

## Scoped live disclosure and ACK batch

The next bounded batch connects the already-integrated native scope/ancestor
owners to actual local recipient authentication, one-use disclosure transport
and historical acknowledgement. The portable scope fixture's synthetic UID
policy is not a live transport authority. Test setup now authors complete native
root activation, child consent and resource proofs against an explicitly supplied
channel commitment. Live cases use the actual gateway/recipient effective UID
and registered recipient key. The original portable fixture remains unchanged.
This is test setup, not a production override or alternate verifier.

The full source/test batch uses maintained file and TLS PostgreSQL adapters,
full native current entry and separate exact approval, actual Unix native client
handshakes and opaque wire capture. Source content is retained through an actual
native acquisition grant followed by injected synthetic complete response facts;
its permit is dropped and no HTTP/custody claim is made. Cases cover successful
ACK; received content with lost ACK and a late exact ACK; dropped delivery permit;
actual committed grant with lost reply; native sender/recipient withdrawal after
authentication and before grant; recipient withdrawal after an acknowledged grant;
competing live authenticated channels for one reservation; wrong recipient key;
wrong OS peer UID; and claim acknowledgement loss followed by fresh native entry.
The earlier-grant case deliberately preserves AP074 semantics: subsequent
withdrawal cannot retroactively cancel a committed one-use capability.

Every case compares actual retained rows and source/ancestor charges. Wire capture
checks all bytes after the challenge, including partial frame prefixes: refusal,
replay and grant-ack loss must send zero content-frame bytes. A retained unknown
or a newly authenticated socket cannot reconstruct a permit. A late genuine ACK
may refine history without sending content, renewing authority or refunding any
source/ancestor reservation. Invalid ACKs and exact ACK repeats leave retained
bytes unchanged. A public snapshot contains neither the planted content nor
private principal identities.

The planned portable live-information artifact is explicitly a named private
projection of actual snapshot/wire facts. It excludes host-dependent UID/channel
identities, effect/source IDs, content MACs, random nonces and signatures; it is
not edited/restorable journal bytes. Same-process UID checks establish neither
independent instance/key isolation nor a separate-process deployment. The actual
installed machine→A→B/human/binding journey, process crash schedules, PostgreSQL
execution, full refinement and hosted gates remain required.

After the complete batch is written, required local artifact construction is the
new native live-delivery constructor and the existing native information, scope
mutation/admission and semantic-closure constructors. No current execution result,
full F08/F11 closure or CI claim is established by this source-authored plan.

### Initial live disclosure artifacts

All five required constructors passed with `loopback-provider,testkit-harness`:
new native live delivery, existing information, mutation scope effect/admission
and semantic closure. The feature-complete target compiled 454 library cases;
only these five filtered constructors ran. Logs are
`/tmp/ap073-live-initial-{live,information,effect,admission,semantic-closure}.log`.
The native live constructor actually executed all eleven independent file-backed
cases. Its opaque capture checks zero post-challenge content-frame bytes for
before-grant withdrawal, key/UID refusal, replay and dropped/unacknowledged grant.
Actual delivery precedes exact ACK or unknown/late ACK refinement. The competing
channels case records exactly one content frame. Every case retains six distinct
sender/recipient ancestor allocation rows, with common root counted once.
The compile reported one redundant trait import in the new test module; remove
it and refresh the same required artifact cohort before committing. No broader
PostgreSQL, process, binding, formal or hosted result follows from these cases.

### Final acknowledged scoped live artifacts

After removing the redundant import, all five required constructors passed
without compile warnings in the same cohort with
`loopback-provider,testkit-harness`. Logs are
`/tmp/ap073-live-final-{live,information,effect,admission,semantic-closure}.log`.
The feature-complete target compiled 454 library cases; only the five filtered
constructors ran. The 9,596-byte native live-information corpus contains all eleven
actual file/socket histories, using genuine full current native validation and
registered channel/key binding. Successful/late-ACK histories show one durable
grant and one content frame. Lost grant replies and dropped permits show a retained
private EntryGranted fact, public Unknown and zero content frames. Before-grant
actor/recipient withdrawal and wrong key/UID show zero grants/content frames while
retaining the original six ancestor rows. Competing channels deliver one frame;
late ACK refinement and exact ACK replay preserve charges and never redeliver.
The corpus explicitly omits host UIDs, private IDs and randomized material rather
than editing restorable journal data. No provider credential was leased or HTTPS
request sent; retained source-response facts are synthetic.

This supplies scoped native live-channel evidence for parts of F08/F11 under the
same-process fixture boundary. It does not establish separate-process containment,
actual process crashes, PostgreSQL execution, installed binding behavior or full
AP073 acceptance. Those remain required together with multi-hop machine→A→B /
human approval, managed created-resource lineage/reconciliation, cross-recipe
process schedules, lifecycle/federation/native-resource contracts and complete
source-linked formal/global release/exact-head hosted evidence. No push, CI
observation, merge or deployment occurred. The full persistent goal stays active.

### Native installed control path: bounded implementation batch

The installed engine/application path now shares `EngagementControlEvidence`
with the original audit codec and the existing fenced configuration owner.
`participant_control` accepts only native enrollment/withdrawal under the policy's
installed root. Root bootstrap remains a separate operator API; clients cannot
choose root/context/time/capacity. Historical exact retries return the original
retained revision, including after withdrawal or expiry. This receipt is never
current eligibility or a provider/disclosure permit. Missing/corrupt original
evidence fails explicitly; lost persistence replies are indeterminate.

The native CLI gains bounded authoring, scoped-policy installation, app control,
operator bootstrap and checkpoint-matched audit export/offline replay. Python and
TypeScript carry native evidence/result bytes without alternate verification or
canonical-identity logic. Two installation readers and two writers now share one
codec: 64 KiB native effect policy plus 4 KiB non-policy metadata. This closes the
previous 4 KiB whole-manifest reader mismatch. Control input reserves envelope
space before base64 expansion rather than increasing the shared socket bound.

The complete planned constructor cohort is: actual engine/file/Unix control;
native CLI authoring/manifest; managed CLI inventory; operator-boundary catalog;
installed managed-interface catalog; original control audit;
configuration; information; prerequisite; effect; admission; live disclosure;
semantic closure. Each constructor produces required repository artifacts, not a
substitute for the hosted gate. Binding tests consume the native control corpus
and check byte forwarding plus the same native transport cap. PostgreSQL control
cases are authored separately and require the configured hosted environment.
The TypeScript public API snapshot must be generated from built declarations.

Coverage includes app-root rejection, actual independently consented enrollment,
installed connection authoring, native denial of changed proof bytes, injected
outer configuration rejection, native withdrawal, historical retries without
reactivation, matching audit replay after expiry, reopening retained original
receipts, commit-ACK loss and exact retry, competing identical controls, absent
scoped installation, empty credential store, zero provider-attempt rows, canonical
authoring and oversized metadata refusal. Fixed public fixture keys, same-process
Unix sockets and injected store ACK loss are explicit test boundaries.

No result is recorded for this cohort yet. Full installed machine→A→B/human
journey, separate-process/key/UID isolation, process crashes, cross-recipe shared
authority schedules, managed created-resource lineage/reconciliation, lifecycle,
federation/native-resource conformance, source-linked formal/global release and
final exact-head hosted verification remain required. No push or CI observation
is authorized before the implementation/spec is complete.

### Acknowledged native control and interface artifacts

The first complete thirteen-constructor cohort passed twelve cases and exposed
one invalid public-key fixture in native CLI policy authoring. The test input was
corrected to derive an actual Ed25519 public key through the maintained signing
library. One unused test import was removed. The native control constructor also
now exercises the transport cap and an app disconnection after request delivery:
the native control finishes and exact replay locates its original revision.

All thirteen constructors then passed without compile warnings with
`loopback-provider,testkit-harness`. Logs are
`/tmp/ap073-control-final-{control,cli,inventory,admin,interface,audit,configuration,information,prerequisite,effect,admission,live,semantic-closure}.log`.
The library target compiled 457 cases; ten filtered library constructors ran,
alongside two binary constructors and one installed-daemon interface constructor.
The new control corpus is 22,425 bytes and contains twelve actual file/socket
cases. The CLI corpus is 492 bytes. Existing installed-daemon evidence now also
exercises the new control schema against an unscoped installation, asserting no
new credential/provider entry. Its original authenticated HTTP/disclosure flow
still passes; it does not establish an installed enrolled hierarchy.

TypeScript declarations and the public API snapshot were generated successfully
using `npm run build` and `node tools/public-api.mjs --update`; logs are
`/tmp/ap073-control-initial-typescript-{declarations,public-api}.log`.
Python/TypeScript control transport tests are written against the native corpus
but have not been run locally. No PostgreSQL, general package/formal/release or
hosted gate is claimed. A final static review replaced one unnecessary context
clone; its affected control and semantic-closure constructors are refreshed
together in `/tmp/ap073-control-review-{control,semantic-closure}.log`.
Both refreshed constructors passed without compile warnings.

This closes the installed **control surface** subrequirement using the existing
native evidence/configuration owner. The remaining full-program requirements
listed above are unchanged; the persistent goal remains active.

### Native hierarchical control and entry: next bounded batch

The native scope fixture now authors either the existing siblings or a genuine
machine→A→B chain through the same proof-building owner. Each child retains its
actual parent commitment, and action signing follows the retained native ancestry.
Root control/resource depth is two, A narrows to one, B to zero. Every original
parent/acceptance/resource proof is carried unchanged through the actual engine
and app socket. This is test authoring infrastructure, not a production alternate
delegation mechanism or credential owner.

The new hierarchy constructor refuses B before A is enrolled, enrolls A and B at
distinct acknowledged revisions, compiles B's three-grant resource suffix, and
obtains an exact independent human fixture approval over three ancestors. The
existing journal claims and charges all three ancestors. Native withdrawal of A
then wins the shared entry fence: B gets no permit, original charges stay retained,
and retry of B's original enrollment returns its old revision without reactivation.
Original control/audit history is replayed with independent trusted inputs.
PostgreSQL runs the same authored schedule when configured.

Required artifact constructors, after the full batch is written: new hierarchy,
existing control, scope effect/admission, information/prerequisite/live disclosure
(shared authoring helper changed), and semantic closure. The existing portable
sibling corpus must remain unchanged. No constructor result is claimed yet.
Fixed public keys, same-process Unix peers, no provider send and no installed
binding/containment claim are explicit. The full installed journey, additional
failure schedules and M4/formal/global/hosted requirements remain open.

The complete initial hierarchy cohort passed seven of eight constructors; the
new hierarchy reached its final replay assertion and showed that the test had
incorrectly expected reservation reopening itself to refuse. AP074 intentionally
permits the original Reserved handle to reopen without a fresh charge or entry
authority. The test now checks the stronger actual boundary: after A's native
withdrawal, both the original and reopened handles fail the fresh shared entry
fence, retaining all three charges. No production transition was changed to
satisfy an incorrect test expectation. The affected hierarchy/control and
semantic-closure constructors are refreshed together after this repair.

### Acknowledged native multi-hop artifacts

The repaired hierarchy, existing control and semantic-closure constructors all
passed without warnings with `loopback-provider,testkit-harness`; logs are
`/tmp/ap073-hierarchy-final-{hierarchy,control,semantic-closure}.log`.
The earlier complete cohort's other five scope/admission/information/prerequisite/
live constructors passed in `/tmp/ap073-hierarchy-initial-*.log`. All prior sibling
corpus bytes remain unchanged. The library compiled 459 cases; these filtered
artifact constructors, not the complete suite, were executed.

Static review added a cross-check that generic action authoring for B reproduces
the genuine three-grant native hierarchy proof/action exactly. The affected
hierarchy and semantic-closure constructors passed again without warnings in
`/tmp/ap073-hierarchy-review-{hierarchy,semantic-closure}.log`.
The new 1,039-byte `engagement/hierarchy.json` records three participants, three
native resource grants, exact independent approval, three unchanged permanent
ancestor charges, premature B refusal, parent-withdrawal denial at both original
and reopened entry fences, original B revision 3 versus current revision 4, and
native original-audit replay. Provider entry count is zero by construction.

This adds multi-hop native runtime evidence for parts of F02/F05/F06/F11/F16. It
does not establish private agent keys, distinct processes/UIDs, installed binding
authoring, provider effects, actual process crashes, PostgreSQL execution or the
full installed representative journey. Those and the other full-program gates
remain required. No push, hosted CI observation, merge or deployment occurred.

### Installed connection-to-policy provisioning gap

Tracing the installed multi-agent journey exposed a concrete prerequisite:
root scopes bind the actual native connection record, while the initial
installation fixes its effect policy before creating that connection. There was
no native way to review a scoped replacement policy without editing the private
manifest. Extend the existing configuration review/activation commands with
`--effect-policy` instead of adding an engagement-specific configuration owner.
Review loads the complete candidate without publishing it. Activation binds the
candidate digest, existing admission partition and current shared revision,
uses the existing native CAS, then publishes the canonical local manifest only
after the shared acknowledgement. Operator loading uses the existing separated
operator custody access; no credential lease/provider call is needed.

Interruption between acknowledgement and local publication leaves old settings
ineligible and requires a fresh explicit review/activation. A local manifest lock
serializes policy and operator-attestation publication. Its owner/file/link/mode
checks are extracted from the existing qualification-state lock mechanism, which
now uses the same leaf helper. No second admission, usage or revocation owner is
introduced. The private lock is coordination, not an authorization record.

The full planned batch is written before constructor execution: actual CLI
installation/connection-root authoring; read-only candidate review; changed
candidate, stale revision and partition-reset refusal; native acknowledgement
without manifest publication followed by fresh reviewed recovery; two real
operator processes racing one revision; private lock unsafe inode cases; updated
managed CLI and installed interface inventories; existing candidate journey and
content process journey to cover the shared engine loader; semantic closure.
The installation fixture deliberately does not bootstrap/enroll its root or
claim agent/provider/UID/language behavior. Its fixed public proof metadata is
authoring data only. This prerequisite unblocks the still-required installed
fresh-key machine→A→B/independent-reviewer/binding/provider journey; it does not
replace that acceptance requirement. No constructor result is claimed yet.

### Acknowledged native policy-cutover artifacts

All nine required constructors have successful results with
`loopback-provider,testkit-harness`: native policy installation; CLI bounds/locks
and inventory; managed installed interface; credential-candidate process journey;
content process, read-only process and capacity process journeys; semantic closure.
Only these filtered artifact constructors ran, not the complete suites. Logs are
`/tmp/ap073-policy-initial-{cli,inventory,candidate}.log`,
`/tmp/ap073-policy-final-{interface,content,readonly,capacity}.log`, and
`/tmp/ap073-policy-review-{installation,semantic-closure}.log`.
The initial cohort exposed a test use of a crate-private recipe accessor; the
public review accessor replaced it. The next cohort reached the interruption
checkpoint and exposed that the test's independently constructed engine omitted
the build-pinned qualification root. Supplying the same root made the exact
native candidate digest match; the equality assertion remains intact.

Final review strengthened connection evidence to compare prepared pins with the
native canonical connection loaded from the actual installed store, and checks
0600 mode after both ordinary and winning concurrent manifest publication. The
affected installation/semantic-closure constructors passed again without warnings.
The 831-byte `engagement/installation.json` excludes random installation values
and explicitly disclaims provider, enrollment, language, UID, process-kill and
power-loss evidence. The 572-byte CLI corpus now includes actual unsafe lock
inode refusals. Existing provider/read/disclosure/capacity corpus bytes remain
unchanged. No Python/TypeScript package, PostgreSQL, formal, release or hosted
result follows from this batch. No push or CI observation occurred.

The real provisioning gap is closed by the existing configuration owner. Next,
complete the installed workflow with fresh per-process resource-owner, machine,
A/B and reviewer keys, installed Python/npm transports, native enrollment and
exact approval, provider effects and the required hostile/recovery schedules.
That work is still required alongside the remaining M4/formal/global gates; the
full AP073 goal remains active.

### Installed fresh-key process journey: construction batch

The next whole batch authors the native installed journey rather than adapting
the public fixed-seed native fixtures into a containment claim. Resource owner,
machine, A, B and reviewer keys are generated inside five separate installed
Python/npm processes. Only public keys and signatures enter the orchestrator.
Public native authoring APIs own grant IDs, preimages, canonical actions, proof
assembly and control evidence. The daemon remains the only credential/execution
owner. Scripted human-role signing is explicitly not human-presence evidence.

The actual path uses the new connection-to-policy provisioning flow, native root
bootstrap, parent control plus child acceptance/resource proofs, scoped content
acquisition, native authenticated disclosure/ACK to A, exact independent mutation
approval and one counting-provider write. It authors premature-B and app-root
refusals, wrong-reviewer refusal, shared-root second-writer refusal, restart replay,
subtree withdrawal, historical enrollment retry, new-review refusal after
withdrawal, and native original-control audit export/replay. Fresh credential and
content canaries are absent from public metadata, logs and recipient inputs before
release. Acquisition metadata never substitutes for a disclosure permit.

The existing package job builds and copies the compiled orchestrator into its
checksum-verified source-free handoff. Its receiving job explicitly runs the
ignored constructor with installed wheel/npm inputs and distinct Linux UIDs,
empty capability bounds and no-new-privileges. State and cross-role memory probes
are strict in that mode. Local artifact construction builds/installs the same
packages but establishes no UID isolation. The package build OS is pinned to the
Ubuntu 24.04 runtime's glibc baseline. The existing counting provider now accepts
fresh content without changing prior fixture defaults; daemon readiness waits for
an actual connectable listener so restart cannot mistake a stale inode for ready.

The complete planned construction cohort is: independently collect native
executable/wheel/full npm-WASM construction failures; installed process artifact;
existing content, read-only, capacity, managed-interface and candidate process
artifacts; current semantic closure. Native/profile/binding wire schemas are
unchanged. New evidence schema is `auths.installed-delegation-process-vectors/1`.
No result is claimed yet. Do not infer hosted, PostgreSQL, broad formal/release or
full M0–M4/F01–F16 completion from this construction batch.

The first complete constructor cohort built the installed wheel and full npm/WASM
package and regenerated all five existing content/interface/installation artifacts.
It exposed a bootstrap cycle: data-only content-call construction loaded current
enrollment even though root activation needs that call as a resource witness.
The repair shares the same configuration/connection/time loader between data-only
construction and compilation, with enrollment loading retained exclusively on
compilation. The journey now asserts both pre-activation witness construction and
refusal of a genuine signed witness's managed review before root activation,
with no approval files or provider I/O. This is a construction-boundary repair,
not an exception to enrollment or final-entry authority. Both daemon lifetimes'
logs are checked for the fresh credential/content canaries. The source-free job
also checks the handoff's exact source commit and retains its payload manifest
beside the generated evidence. Final repaired construction results follow below.

### Repaired installed constructor result

The local artifact construction succeeded using the built/installed wheel and
full npm/WASM package. Rust formatting succeeded. The final required cohort
passed the installed journey, content, read-only, capacity, managed-interface,
installation and candidate process artifact constructors; semantic closure was
regenerated before the final native executable build. Logs are retained in
`/tmp/ap073-installed-consumer-initial/` (`installed-repaired.log`,
`repaired-*.log`, `candidate-repaired.log`), with the semantic constructor at
`/tmp/ap073-installed-semantic-closure.log`. Initial native module-path/API and
borrow errors were repaired as collected build failures. Existing canonical
process outputs remained unchanged. The new canonical installed-process artifact
is 920 bytes and excludes randomized keys, identities, times and private data.

This run executed the complete installed scenario with fresh process-held keys
and public SDK transport. It used the same local UID; it establishes no Linux
DAC or sibling-memory isolation. The separately wired source-free hosted mode,
PostgreSQL, exhaustive crash schedules, human presence, live qualification,
M4, global binding/formal/release checks and full acceptance remain unestablished.
No broad gate, push or CI observation ran. The full goal remains active.

### Installed process crash/recovery batch: planned evidence

Extend the installed constructor as one whole batch, with two fresh independent
installations and schema `auths.installed-delegation-process-vectors/2`. Preserve
the retained-response path. For the second path the credential-checking HTTP
double validates/applies the exact write, signals that fact and withholds all
response bytes while the orchestrator kills/reaps the real daemon. The installed
Python client must see protocol/transport uncertainty. Restarted exact replay
must report native Unknown, retain the shared one-write limit against A and
perform no second PATCH. Each path then obtains independent native recovery
read authority plus exact independent approval through the installed client;
provider linkage may refine historical facts but never grants a write or refund.

Both paths also stop a native recipient after authenticated receipt/own private
ACK persistence, kill the daemon and recipient, and check permanent delivery
accounting, no files/plaintext on historical reconnection, original npm late-ACK
recording/replay, and retained historical facts after participant withdrawal.
A's seed reaches only its own same-UID native child through private stdin; no
private seed/ACK/plaintext is passed to the orchestrator before disclosure. The
child uses the maintained native recipient client, not a new verifier. The
counting provider fault is test-only and does not enter the gateway.

Map to F05/F08/F09/F11/F13/F16, without claiming all those scenarios closed.
Required constructor cohort: installed process, prior content/read-only/capacity,
managed interface, installation and candidate artifacts, plus semantic closure
if production source changes. This batch changes no production source or wire
contract, so the already current semantic closure is unaffected. No results are
claimed before that complete cohort runs. Distinct Linux UIDs, PostgreSQL,
other crash boundaries, managed child lineage, lifecycle/federation/native
resource conformance and formal/global hosted gates remain required.

The first whole construction cohort preserved all six existing process artifacts.
The installed cases exposed a test expectation mismatch: native recovery replay
truthfully reports `already-recorded`, preserving all source/acquisition facts,
times and accounting. The corrected assertion compares every other field
unchanged. Running both independent cases then exposed a Python fixture error
that referenced an unassigned request variable only on transport failure; parsing
the request before invocation repaired that error without weakening native checks.
Both complete cases passed after those repairs. Final review adds all three
remaining assertion gaps together: exact lost-ACK plaintext receipt, gateway
process-memory denial in hosted distinct-UID mode, and a separately signed,
reviewed third disclosure refused after original late ACK plus replay, proving
that acknowledgement cannot replenish shared capacity. This final constructor
result is recorded below; it is not a new production accounting mechanism.

### Installed crash/recovery constructor result

The final installed constructor passed both complete fresh-key cases, including
exact recipient bytes, no capacity refund after late ACK, Unknown after the
actual post-write gateway crash, shared-limit refusal while Unknown, separately
authorized provider-link recovery and replay without additional provider calls.
The 3,014-byte version-2 artifact records only checked portable facts; each
installation used one local UID. The final log is
`/tmp/ap073-installed-crash/installed-reviewed.log` (10.78 s).
The six independent existing constructors passed in the same whole batch and
retained their canonical bytes: content, read-only, capacity, managed interface,
installation and candidate (`/tmp/ap073-installed-crash/*.log`). Only the affected
installed constructor was repeated after test-only repairs/final review. Native
construction compiled without diagnostics and Rust formatting passed. Wheel/npm
payloads were reused from the prior successful construction because no binding
or production source changed in this batch. Semantic closure is unchanged.

No hosted isolation, PostgreSQL, broad behavioral/formal/release gate, push or
CI observation was performed. These checked process schedules do not establish
power-loss/fsync semantics or every pre-claim/admission crash boundary. Required
remaining engineering includes managed-created-child lineage/reconciliation,
cross-recipe shared-capacity process schedules, the remaining admission/revocation
and stale-floor cases, lifecycle/compromise/recovery and additional-domain/native
resource conformance, complete binding/fixture parity and source-linked formal
assurance. Exact-head hosted gates remain last, after implementation is complete.
The full AP073 goal remains active and incomplete.

### Cross-recipe native process batch: planned contract and checks

Source inspection confirms that the shared enrollment row and typed ancestor
allocation identities exclude recipe identity, while each installation retains
its own exact recipe, connection and configuration partition. Add actual native
engine processes over both maintained adapters to exercise that composition,
rather than inferring it from key equality or same-recipe sibling tests.

The complete planned batch includes two independently compiled recipe/service/tool
contracts, two actual connection records, two configuration partitions and one
native root with separate control, child acceptance and per-recipe resource
suffixes. Both siblings share one root write. A simultaneous two-process request
race must create exactly one provider write and the winner's two ancestor rows;
reopen/exact replay must not add either. Wrong-recipe proof/approval substitution
must fail before provider transport. A separate explicitly authenticated engagement
on the same store/connections gets its own capacity, while the spent first root
remains exhausted and its proof cannot cross that boundary.

Four ordered cross-recipe schedules use the maintained transparent PausedStore
around actual adapter transactions: after reservation commit and after entry
commit, each with ordinary release or actual SIGKILL. Another recipe publishes
the native root withdrawal before release/reopen. Unentered descendants cannot
enter; committed entries retain the documented earlier-grant ordering, and a
crashed entry remains Unknown without resend. Original approval bytes and every
ancestor allocation remain retained. Hooks never replace or rerun native fence
decisions. These are full engine/HTTP processes with public fixed fixture keys,
not installed hostile-UID containment or power-loss claims.

The helper in native_process_tests gains only an optional explicit connection
fixture; all prior defaults remain unchanged. The native enrollment test author
signs the complete two-recipe relation with the same maintained codec/verifier.
No task ledger, provider branch or alternate approval/entry authority is added.
The TLS PostgreSQL workflow explicitly invokes the new ignored process matrix;
its result remains pending until actual execution, and is not a committed file
adapter artifact relabeled as PostgreSQL.

Required local construction cohort after all code/test/docs/CI changes: new file
process artifact and current semantic closure, prior native process-capacity and
engagement enrollment/admission/hierarchy artifacts affected by shared fixtures,
and installed/content/interface/installation/candidate process artifacts. Run only
these required constructors to construct committed evidence; defer broad local
and hosted gates until the complete program is implemented. Initial results are
not yet established. Full F01–F16/M0–M4 remains required.

The initial whole construction cohort passed all eleven prior artifact
constructors. The new six-case matrix first encountered three fixture setup
guards: missing owner-private directory mode, an invented non-canonical base64url
connection ID, and reusing the already provisioned custody file for a second
fixture engine. The inputs now use explicit 0700 mode, native canonical encoding
of bounded public fixture ID bytes, and a separate private custody copy per
independent fixture engine. The shared authorization store remains unchanged.
The matrix then exposed an accepted test socket inheriting nonblocking mode on
macOS. Explicit blocking accepted sockets and a bounded 15-second header deadline
support the deliberately paused post-entry schedule. No production guard or
native decision was weakened. All six cases passed at
`/tmp/ap073-cross-recipe-socket-repair.log` (7.40 s), creating the 2,220-byte file
artifact. Final current semantic-closure/artifact-cohort results follow below.

### Acknowledged cross-recipe process artifacts

Retrospective execution-count correction: thirteen commands returned success,
but two native admission/hierarchy filters selected zero tests. That cohort
therefore established eleven actual constructor/check executions, not thirteen.
The six-case cross-recipe corpus did run and pass. Its actual companions were
prior native process
capacity, enrollment, content, read-only, content capacity, managed interface,
installation, candidate and installed
multi-agent process artifacts; and the semantic-closure equality check with
update disabled. Final logs are `/tmp/ap073-cross-recipe-final/*.log`; the
required native build log contains no compiler diagnostics. Rust formatting
passed. Existing canonical artifacts retained their bytes. The new 2,220-byte
file corpus excludes private fixture identities, random custody filenames,
worker IDs and execution-witness nonces. The gateway semantic manifest/digest
includes the new source and changed test helper.

The matrix directly establishes the six declared file-adapter engine/process
histories and the associated provider/custody/transport/allocation assertions.
It does not establish TLS PostgreSQL execution, installed UID containment,
human presence, live provider qualification, power-loss durability, disconnected
escrow, whole-store rollback protection or full AP073 acceptance. The identical
PostgreSQL process matrix is explicitly wired but remains unrun. No broad local
gate, push or hosted CI observation occurred. Managed-created-child lineage /
response-less creation reconciliation, lifecycle/federation/native-resource
conformance, the remaining stale-floor/cross-protocol/crash cases, binding parity,
source-linked formal evidence and final exact-head hosted gates remain required.

### Native created-resource selection/recovery batch

F10 remains open: prior generic recovery compares one object at a known locator;
response-less creation requires a bounded complete-list uniqueness relation.
ADR 0019 and abstraction case 0010 define the smaller parsing/cardinality
promotion and explicitly retain provider completeness, marker integrity and
identifier lifetime assumptions. Historical Google task owners remain independent
comparison evidence, not managed credentials, state or permits.

The entire planned source/test/CI batch adds a closed optional observation
selection: strict bounded pointers, 1–64 items, exact marker and verified-parent
matching, scalar/sole-parent-array shape and one/two declared completeness checks.
Absent-member completeness requires an existing immediate parent object. Missing
or malformed relevant fields, duplicate matches, incomplete listings, invalid
escapes, ambiguous JSON and bounds violations select nothing. The native parser
and an independent Python oracle cover records/data/files response shapes without
claiming live provider equivalence.

The selection definition joins native observation plans and exact recovery
contracts. Actual native source/read/allocation refinement persists the selected
identity privately only with the original recovery evidence. Decoding rechecks
that identity against the retained provider projection. Public results expose no
identity, marker or raw response hash. A genuine current reader may refine a
withdrawn writer's historical source; staleness and unusable evidence preserve
Unknown and all capacity. Native source/read/admission owners are unchanged.

Planned evidence includes a malformed/boundary/property projection corpus;
recipe-compiler refusal matrix; nine file/TLS PostgreSQL native source/read cases
(unique, zero, multiple, incomplete, wrong parent, malformed JSON, version
mismatch, stale evidence and withdrawn writer), exact replay and privacy checks;
independent Python comparison; native semantic closure; and affected prior
recovery/content/process artifacts. Complete this batch before running its
constructors; no result is claimed here. Only required artifact construction
runs locally, with hosted/general gates deferred as requested.

This batch does not remove CreatedChild execution refusal. Dependency-complete
lineage compilation/final fencing, actual response-less HTTP create and downstream
scope use, adversarial installed journeys, lifecycle/federation/native-resource
conformance, remaining rollback assumptions, bindings/formal/global gates are
still required. Selection or a serialized candidate is not authority. Full
AP073 acceptance remains active and incomplete.

#### Execution-count correction and shared validation review

Initial creation commands exposed an assurance error: Rust's `--exact` returns
success for an absent selector. The incorrectly shortened native paths omitted
`observed_tests::effect_native_tests::engagement_tests`. Creation recovery and
prior information filters selected zero tests. The prior cross-recipe cohort's
admission/hierarchy commands did the same (the six-case cross-recipe test and
installed process tests did execute). Those native claims remain pending until
correctly selected execution; a zero-test exit is not evidence.

The actual compiled registry now supplies exact names, and local constructor
results must contain exactly one passing, unignored test before being counted.
CI's existing checked-selector loop now owns the cross-recipe and new creation
matrix selectors. Installed package CI and its local builder similarly reject
zero-test results. This reuses the maintained checking path, not a parallel gate.

Review also centralizes the identical 1–256-byte/no-control opaque handle
predicate for enrollment, selection and retained identity in resource_identity.
All response-pointer consumers use the existing native validator, strengthened
to strict RFC 6901 escapes and no control characters; creation does not carry a
second pointer parser. These are shared bounded validation contracts, not new
provider semantics. The independent Python oracle intentionally remains separate.

#### Correctly selected constructor results before final regeneration

The registry/count-checked cohort actually executed 16 existing and projection
constructors once each. Native admission, hierarchy and information evidence now
have real executions, superseding the earlier zero-test commands. The new
recovery constructor initially exposed an omitted required `query` member and a
shared fixture-authoring bug: the synthetic action used the default namespace
instead of the compiled recipe namespace. Both fixture owners are repaired
centrally; native namespace verification remains mandatory.

The correctly selected new native constructor then passed all nine source/read
cases and seven recipe refusals, including canonical-but-inconsistent selected-ID
substitution being rejected as corrupt. The independent Python oracle agreed on
all 38 initial projection cases. Final corpus review replaces weak duplicate
empty arrays with two valid-candidate first/last-wins counterexamples (39 cases),
and strengthens the native malformed-response case similarly. Final regeneration
will count every execution; these preliminary results do not establish the
subsequently edited source, PostgreSQL, property tests or hosted gates.

#### Final creation projection/recovery artifact construction

After the complete repair batch, semantic closure regeneration executed one
actual constructor, then the required executable build succeeded. The final
registry/count-checked cohort ran 18 constructors: selection; native creation
recovery; admission; hierarchy; information; prior recovery acquisition; mutation
differential; review contract; enrollment; cross-recipe process; content capacity;
content process; installation; managed interface; read-only process; candidate
process; installed multi-agent process; and update-disabled semantic equality.
Every command executed exactly one passing test. The native creation constructor
asserts all nine cases and seven compiler refusals. The independently executed
Python oracle agrees on all 39 final projection cases.

Logs are `/tmp/ap073-creation-final/` and
`/tmp/ap073-creation-final-results.log`; build and semantic logs have the matching
`/tmp/ap073-creation-final-` prefix. Installed actors reused the existing unchanged
SDK packages with the new native executable; this is not exact-head package
acceptance. Semantic closure changes intentionally alter bound effect IDs, so
recovery-compilation and independent-mutation fixtures were regenerated by their
maintained constructors. No public SDK shape changed.

These are artifact-construction results only. No broad local suite, PostgreSQL,
property/formal gate, hosted qualification or CI has been run for this batch.
No push has occurred. Dependent child scope/final-fence execution and the remaining
M0–M4/F01–F16 work remain required; this batch cannot close the full goal.

### Original acquisition provenance before dependent-scope promotion

The next source review exposed a prerequisite to enabling child operations:
mutation decoding reprojects retained bytes, but an ordinary history lookup
did not reload the original acquisition and permanent source-lifetime rows.
A locally consistent selected ID cannot substitute for that original native
read. This bounded batch makes the existing mutation loader validate the source,
original acquisition and finite allocation set under the maintained writer
fence. Its inspection aborts without writing, refreshing timestamps, consuming
capacity or reconstructing permits. Historical read expiry or writer withdrawal
does not erase valid provenance; fresh consumer authority remains separate.

The entire planned evidence batch extends both nine-case native matrices with
five canonical, independently valid acquisition substitutions (status, version,
receipt time, response bytes and revision), checks ordinary and approved-effect
history paths, exact restoration and unchanged source/charges. Artifact schema
becomes version 2. Required constructor regeneration covers native semantic
closure, creation recovery and the previously affected native/process artifacts
in one registry/count-checked cohort. Hosted PostgreSQL/general gates remain
deferred until spec implementation completes. No result is claimed yet.

The complete provenance batch constructed successfully: semantic regeneration
executed one test, required executable construction succeeded, and all 18
registry/count-checked constructors executed exactly once and passed. Both
unique-selection cases checked all five independently valid acquisition
substitutions through ordinary and approved-effect lookup, then restored exact
bytes and checked unchanged source/ancestor charges. Version-2 creation recovery
evidence records that count. Logs: `/tmp/ap073-created-history-results.log` and
`/tmp/ap073-created-history-final/`. This is synthetic artifact construction;
PostgreSQL, general/formal/hosted gates remain unrun. Native `CreatedChild`
execution remains refused pending consumer compilation and final fencing.

### Dependency-bound child scope and native final entry batch

The next complete coding batch connects the source/read history owner to the
existing native effect/admission/entry owners. Pending declarations pin complete
producer replay context and exact parent scope. One private typed projection
binds original source/read/effects/revisions/allocation and selected identity.
The compiler retains the declaration and checks the actual native consumer
argument. Admission and final entry reload all three original dependencies and
recompute the projection without nested store I/O. Ordinary history lookup and
entry reuse one pure original-history relation. The common replay-key leaf is
shared by policy lookup and explicit producer context. No task ledger, alternate
verifier, provider dispatch or SDK authority is introduced.

The initial relation supports an exact-parent producer and one dependency edge;
recursive pending parents are explicitly unsupported. Production remains data
only. The ADR records this finite boundary and the same-connection requirement.
Existing exact scopes retain their representation; obsolete incomplete pending
declarations are rejected rather than decoded through compatibility machinery.

Planned evidence is the complete nine-case native recovery matrix with pending
content/disclosure scopes installed before create: nonunique sources refuse the
consumer; unique cases reject 18 lineage substitutions before admission, reject
a changed original read at the final fence after reservation, reopen the exact
unentered reservation after original-byte restoration without another charge,
record one native child acquisition and reserve (without delivering) disclosure.
The corpus becomes version 3. Current native proof, independent exact approval,
shared ancestor charges, replay, current withdrawal and private/public boundaries
remain exercised. All code, tests, docs, inventory and CI are written before
constructors run. Required regeneration covers semantic closure, both new native
artifacts and the affected prior constructor cohort. Actual HTTP create/child
execution, installed actors, PostgreSQL and global/formal gates remain required;
no new result is claimed here.

The consumer batch completed required artifact construction without a repair
cycle: semantic regeneration ran one actual test, required executable construction
succeeded, and all 18 registry/count-checked constructors passed exactly once.
The version-3 nine-case native artifact contains both unique consumer histories,
each with 18 named lineage substitutions refused, producer/read replay-key reuse
refusal, stale original-read refusal after reservation, exact restoration with
no new charge, native child acquisition replay and disclosure reservation with
no delivery permit. Other cases have no resolved candidate and refuse child
compilation. The independent Python oracle still agrees on all 39 projection
cases. No HTTP provider is called by the new native cases. Logs:
`/tmp/ap073-created-consumer-results.log` and
`/tmp/ap073-created-consumer-final/`; semantic/build logs have the matching prefix.

The production code inventory includes the generic unavailable-history denial.
No public SDK payload or alternate authorizer was added. Pending declarations
now reject incomplete producer replay pins; exact scopes retain their existing
representation. Source-linked formal, PostgreSQL, real create/child HTTP and
installed F10 work, lifecycle/federation/native-resource conformance and exact-head
hosted gates remain open. No push or CI observation has occurred.

### Installed response-less creation and dependent HTTP use: next bounded batch

The remaining F10 transport gap will use the maintained installed multi-agent
constructor, not another task owner or key fixture. Keep the existing retained
mutation and post-write-crash cases; add four fresh installations whose actual
HTTP create is applied before the gateway is killed without a response. Their
independently approved native recovery reads return zero, duplicate, incomplete
or uniquely linked candidates. Each uses five independently generated process
keys in installed Python/npm actors and the same native daemon, control tree,
exact reviewer, disclosure transport, restart and ancestor accounting.

Install additional pending content/disclosure scopes before creation, pinning
the actual connection and complete producer replay context. The existing native
parent-scope authoring helper computes the acyclic commitment; no independent
implementation or new application authority is needed. The deterministic HTTP
double alone gains a concrete create/list contract. Shared production gateway
logic remains entirely recipe data.

Before producer resolution and for all unusable listings, a genuine signed child
request must fail review without approval artifacts or provider I/O. Only the
unique case may obtain independent exact approval and fetch the exact child
once. Replay must fetch nothing, another child must fail before provider entry,
and public receipts/errors/logs must expose neither private content, credential
nor selected ID/raw digest. Creation never repeats or refunds the one shared
write; existing disclosure ACK-loss/late-ACK and withdrawal checks remain.

The installed artifact becomes version 3 with six checked cases. Source-free CI
retains its five-UID/capability isolation and source manifest requirements. Map
and finish the complete recipe, provider double, root/witness, recovery/child,
privacy, evidence, docs and inventory edits before required constructors. The
whole checked constructor cohort will collect independent failures together.
No execution result is claimed for this planned batch. Hosted PostgreSQL, formal
and exact-head acceptance plus broader lifecycle/federation/native-resource work
remain required; no push/CI observation occurs until spec implementation ends.

The complete installed batch is now written, including all four listing outcomes,
pre-resolution refusal, exact child GET/replay/foreign-child checks, redaction and
all previous installed assertions. The shared HTTP double keeps its prior default
contract and adds only a test-owned concrete creation/list relation. Version-3
compliance registrations cover both the gateway and installed demo consumer.
Shipping Rust and bindings are unchanged from c9e1b03d; the existing source-linked
semantic artifact therefore needs equality checking, not regeneration. Build the
required constructors together, then run the 18 registry/count-checked artifact
cohort (including all affected shared-double process artifacts and the six-case
installed constructor), collecting all independent failures before repair.

The first installed-creation construction collected all failures: 17 constructors
passed; the installed constructor retained its two old successful cases and all
four new creation installations refused A enrollment before provider access.
The common fixture cause is scope ordering: new `created-*` scopes were appended
after `scope-*`, while signed participant scopes must be strictly sorted. Native
validation correctly refused that descriptor. Normalize root scope order once
before committing or signing root/participant/witness evidence. Keep the initial
inactive-root probe explicitly on the exact parent content scope, so its failure
cannot instead be explained by an unresolved pending source. No native validation
or product limit is changed. Rerun the existing full constructor cohort and all
six installed cases together after this coherent fixture-authoring repair.

After the ordering repair, all six installations pass enrollment. The collected
four creation failures moved to one strict HTTP-double assertion: it expected
`fields.parent_id`, while the declared ValueExpr produces top-level `parent_id`.
The native recipe and original native fixtures already declare and consume that
verified body argument. Correct the concrete double to assert top-level parent
equality and derive its listing from that actual received parent; keep exact
payload-field count two, enforce the complete outer object size (two for create,
one for the prior mutation) and preserve exact status/echo/path checks. This
repairs the reference's request contract, without relaxing production checks.
The prior 17 artifact constructors and two original installed cases passed.
Rerun the same complete cohort and six installed scenarios after this repair.

The strict body-contract repair completes the required constructors: all 18
registry/count-checked artifact commands executed once and passed. The installed
constructor independently completed all six cases in 37.83 seconds, including four
actual HTTP creates applied before a real gateway crash with no response. Native
restart retained Unknown. Separate exact-approved HTTP reads returned zero,
duplicate, incomplete and unique listings; only unique obtained a child review
and one exact child HTTP acquisition. Premature/unusable/foreign child reviews
produced no approval artifacts or extra provider calls. Child replay did not
refetch; no case repeated its one create. Existing ACK-loss/late-ACK, wrong
reviewer, shared write limit, restart, withdrawal and audit assertions passed.

The version-3 installed artifact records six independent five-key installations.
All local cases report `distinct_uids=false`; reuse of unchanged installed SDK
packages plus the current native executable constructs this evidence, not an
exact-head package/isolation qualification. Logs are
`/tmp/ap073-installed-creation-body-results.log` and
`/tmp/ap073-installed-creation-body-final/`; constructor build uses the matching
`/tmp/ap073-installed-creation-body-build.log`. No shipping Rust changed in this
batch; semantic equality passed without regeneration. The two earlier failed
cohorts remain documented, not counted as passes.

This establishes the defined local installed HTTP creation/child-use slice. The
synthetic child ID is fixture-known rather than confidentially discovered. It
does not establish live provider truth, separate-UID confinement, PostgreSQL,
every crash schedule, arbitrary recursive lineage, identity lifecycle, federation,
native-resource qualification, source-linked formal closure or full AP073 gates.
Those remain required. No push or hosted CI observation has occurred.

### First identity lifecycle contract: commissioned successor and stable capacity

[ADR 0020](../adr/0020-commissioned-instance-recovery-and-budget-continuity.md)
records the concrete next M4/F12 boundary. A fresh enrollment alone cannot be
called transparent key recovery: with a larger parent allowance it could reset
the predecessor's narrower lifetime budget. The selected first profile uses an
independently commissioned standby principal/channel, acknowledged native subtree
withdrawal, then a typed successor enrollment with fresh parent/resource grants
and new-holder acceptance. Old descendants remain invalid. Root recovery, changed
parent, arbitrary commissioning, expired-authority revival and offline escrow
are explicitly unsupported, never inferred from another epoch.

Keep ceilings immutable across a successor chain and derive one capacity origin
from its first fresh enrollment. Current principal/instance and historical budget
identity are distinct facts in the same effect owner. The existing allocation
key uses that origin, preserving the exact permanent rows/ceiling contract without
a second ledger, migration or refund. The tree must require a withdrawn retained
predecessor, same live direct parent, exact next generation, nonoverlapping fresh
principal, narrowed time/scope/depth and one successor per retained node.

The ADR maps the complete implementation/adversarial/adapters/installed/binding/
formal batch before execution. No lifecycle runtime change or passing evidence
is claimed yet; it is an implementation contract rather than M4 acceptance.
Native resource/federation and all exact-head hosted gates remain in scope.

Lifecycle implementation has begun as one unverified coding batch. The closed
`EnrollmentLifecycle` is mandatory in participant-enrollment/2: Fresh is new
authority; Recover explicitly names the withdrawn predecessor. Tree/4 validates
the same-parent/next-generation/fresh-grants/narrowing/unchanged-ceilings relation,
unique successor and finite historical origin on both insertion and decoding.
Effect scope/3 binds current enrollment and capacity enrollment separately, and
bound-effect/7 compiler/12 is the direct cutover. The existing ancestor-capacity
key uses only the derived original capacity enrollment. This preserves immutable
row ceilings rather than weakening their equality checks or inventing another
usage store. No build, artifact constructor or gate has run for this incomplete
batch. Finish all lifecycle cases, native adapters, installed standby actors,
wire/fixture/inventory/spec/binding/formal changes before construction.

The lifecycle batch now includes a full native pure-tree matrix (not yet run):
withdrawal prerequisite, fourteen invalid successor proposals, a two-successor
chain retaining one original capacity identity, fork refusal, old holder and
descendant native proof refusal, new holder proof acceptance, retained decoding
and tampered withdrawal refusal. No store/transport claim follows from that
module. The installed constructor is being extended to a seventh scenario with
a separately commissioned sixth process/key: active-predecessor refusal, real
restart gaps around withdrawal/enrollment, historical revision replay, old
approval refusal, current instance versus original capacity in the native review,
one remaining child read, exhausted original child allowance with a still-live
parent positive control, and subsequent parent withdrawal of the successor.
The existing six installed scenarios stay in the same planned cohort.

No lifecycle constructor has run. Complete file/PostgreSQL native conservation
and fault schedules, fixture/schema/spec/compliance/binding changes and source-
linked assurance before construction. Product-instance withdrawal does not
globally revoke mathematically valid raw-key grants at unrelated resources;
ADR 0020 makes the required scoped-resource/common-state boundary explicit.

The seventh installed scenario deliberately composes lifecycle with the existing
unique lost-create case: the old B creates and independently reconciles a child,
then is withdrawn. The sixth process/key accepts successor authority and alone
performs the one child read, retaining the original producer/read lineage and
old capacity origin. Old approval, exhausted original read allowance and a
second create remain refused; a separately approved parent read shows remaining
parent capacity. This adds no scenario or runtime provider capability beyond
the mapped seven-case batch, and tests the interaction rather than only two
separate happy paths. The native store matrix additionally preserves a genuinely
Unknown mutation across two successor changes and lost publication replies.


### Lifecycle batch frozen for artifact construction (not acceptance)

The mapped batch now includes fifteen invalid native successor proposals, closed
lifecycle decoding, exact-JSON generation endpoints and a fully signed successor
chain at the actual sixteen-retained-participant bound. Every accepted prefix
must retain its first capacity origin and reject its predecessor's native proof;
the next commissioned successor must fail without changing the full tree.
The bound-effect constructor also exercises missing/substituted/duplicate capacity
identities, alongside its existing malformed ancestry cases.

File and PostgreSQL share three native histories: normal publication, lost
withdrawal acknowledgement and lost successor acknowledgement. They preserve
reserved old reads and an actual Unknown mutation, spend only the original
remainder across two recoveries, include an independently successful sibling
positive control and replay the original private control audit. The installed
seventh case adds a sixth independently held key and composes unique lost-create
history with successor child use, retained counters and actual daemon restarts.
Python/npm/WASM transports remain opaque native-evidence carriers; there is no
second lifecycle verifier in a binding. Their exact-head packaging/parity gate
remains hosted. Existing five-key cases are retained unchanged in scope.

Construction mapping: regenerate the semantic closure from shipping source,
build the native library/CLI plus content/candidate/application recovery artifact
constructors, enumerate compiled registries and require exactly one executed test
for each selected constructor. Regenerate affected native effect, enrollment,
review, information, mutation, recovery and process artifacts together. Do not run
unrelated tests or local broad gates. A failed independent constructor is retained
in the cohort report and repaired with the complete failure set. PostgreSQL,
source-free UID containment, formal, global and release gates run on the eventual
full-spec hosted cohort, not as local pre-push acceptance.

Source-linked assurance boundary: `EnrollmentTree::validate_lifecycle` and
`capacity_origin` implement the new relation. `EngagementScope::compile` (the current
scope compiler), actor/recipient path construction and native entry revalidation
consume the protected tree; `EngagementScope::reservations` retains the existing
allocation owner. Existing kernel conservation/transition theorems are conditional
on their supplied counter identities and do not prove this new product relation.
The native boundary/chain/fault constructors exercise shipping Rust; they are not
formal refinement. A checked source-linked non-resurrection/origin-conservation
claim remains an explicit full-program assurance gap. No new formal theorem,
constructor result or lifecycle acceptance is claimed by this mapping.

The first lifecycle construction cohort executed 34 registered selectors exactly
once: 32 passed, including all seven installed HTTP scenarios (49.85 seconds).
The two new lifecycle constructors failed. The pure descendant helper inherited
a validity interval wider than its deliberately narrowed parent. The store helper
incorrectly treated direct insertion as the participant endpoint's historical
replay API: native insertion correctly returned Replay. Repair the descendant
interval and use the maintained `recorded_control` original-evidence lookup in
the store histories. Actual participant endpoint replay remains exercised by the
installed scenario. Do not weaken native duplicate-insertion or parent narrowing.
The initial compile also exposed two private-value comparisons requiring Debug;
test assertions now compare without formatting private accounting identities.
No production refusal was relaxed. Initial build/cohort logs are retained in
`/tmp/ap073-instance-recovery-final-build.log`,
`/tmp/ap073-instance-recovery-results.log` and
`/tmp/ap073-instance-recovery-final/`. No passing result is claimed for the two
repaired constructors until the coherent rerun completes.


The corrected 34-selector cohort passed 33 constructors, including all native
file/fault histories and all seven installed scenarios. The remaining pure
constructor exposed real Serde behavior: an internally tagged unit variant accepts
extra fields despite enum-level deny_unknown_fields. Use an empty struct `Fresh
{}` variant instead, keeping the same canonical JSON while enforcing the closed
shape before canonical comparison. Add scalar and extra-recovery-field refusals.
No compatibility parser is added. All source/fixture constructors affected by the
semantic closure change remain in the next cohort; the malformed decoder result
is not hidden by changing its expectation. The preceding cohort logs remain at
`/tmp/ap073-instance-recovery-corrected-final/`.


### Commissioned instance recovery construction result

The closed-shape repair passed all **36** required artifact constructors, each
resolved from the compiled registry with exactly one test passed and zero ignored.
The cohort includes the two older native configuration/audit artifacts discovered
to retain obsolete tree/descriptors, in addition to the prior 34 selectors. No
obsolete current enrollment/tree/effect schemas remain in the gateway corpus.
The pure native artifact records fifteen invalid successors, closed malformed
lifecycle refusals, exact generation endpoints, a two-successor chain and the
actual retained-node limit (fourteen successors after the first child).
The three real file-backed histories preserve original read/write rows, reserved
entry refusal, original Unknown, the original three-read ceiling and two recovery
changes, including both publication acknowledgement-loss schedules. They use
native historical lookup; they do not emulate the participant endpoint's replay.

The installed artifact/4 records all seven successful real HTTP/process scenarios,
including a six-key successor case that combines lost-create reconciliation,
retained producer/read provenance, successor-only child use, old-approval refusal,
restart gaps, original control replay and exhausted-original-capacity refusal.
Original five-key scenarios remain successful. Local distinct_uids is false;
packages were reused unchanged, so this is not exact-head package or Linux
containment acceptance. Independent Python projection still agrees on all 39
creation-selection vectors. No live provider or human presence claim is made.

Successful construction logs are `/tmp/ap073-instance-recovery-closed-final/`,
`/tmp/ap073-instance-recovery-closed-results.log` and matching build log. Prior
failed cohorts remain recorded above. Semantic closure equality passed after
regeneration. Canonical artifacts were written by their native constructors.
No broad local gate, PostgreSQL, formal qualification, push or hosted CI observation
has occurred. Full F01–F16/M0–M4 remains active, including federation/native-resource
conformance, source-linked assurance, rollback/cross-protocol cases and exact-head
binding/global/release gates. This commit closes the defined local commissioned
lifecycle slice, not the full program or global raw-key revocation.


### Coordinated federation batch mapped before construction

ADR0021 separates independent resource-owner consent from transport/organizational
trust and from the still-required native-records qualification boundary. Reuse
the existing cross-recipe native fixture and real process schedules; add an
explicit test-only federated topology with three distinct issuer keys, including
one genuine did:key owner. Test authoring uses maintained adapters/evidence and
native signatures, not injected verifier results. The original one-issuer corpus
remains in the same cohort. No shipping provider branch, SDK lifecycle verifier,
new package, credential port or state owner is introduced.

Write seven federated cases: independent mixed-method trust/refusal corpus, real
final shared-unit race, independent-engagement positive control, and four root
withdrawal/crash orderings before/after entry. The negative corpus removes each
owner separately, substitutes resource paths, corrupts native signatures, removes
control evidence, withholds control-root trust, disallows the did:key owner's
method and substitutes installed root pins. Genuine current trust/proof must
compile and execute one real HTTP effect; negative cases must produce zero
provider calls and zero ancestor allocations. Raw/did key equivalence is checked
as identity overlap, not claimed as a new native alias-enrollment proof.

File and ignored asserted-configured PostgreSQL share these histories, wired to
the existing checked-selector hosted step. Construct the canonical federation
artifact plus the prior 36 affected native artifacts after all changes are written;
regenerate semantic closure first, use compiled registries and assert exactly one
executed test per constructor. This is repository artifact construction only.
No local broad/PG/formal/package gate or hosted observation is authorized before
full spec implementation. Formal models do not establish topology honesty,
operator consent, external rollback floors or native-records qualification.
No new result is claimed yet. Native resource implementation, source-linked formal
closure, remaining cross-protocol/floor cases and final exact-head gates stay open.

Pre-construction review adds one essential control to the same federation batch:
owner A signs a genuine, independently valid native proof for the exact B command.
The ordinary native verifier must accept it under the explicit multi-owner trust,
while B's enrolled compiler must refuse its substituted pinned grant suffix.
This distinguishes scope/path enforcement from a trivial wrong-service rejection.
No behavioral constructor has run for this batch yet; the initial artifact build
compiled successfully before this source-review addition. Regenerate the closure
and rebuild once for the complete cohort.

The first 37-selector federation construction cohort passed 36 constructors.
Within the federation constructor, six complete process histories passed; the
trust-boundary case passed its native refusal assertions (including accepted
foreign-owner substitution) but its final positive replay attempted to load an
approval file the helper had not saved. Save the normal exact native approvals
before that positive/replay control. Preserve every negative assertion and all
six schedules; no production authorization or persistence behavior changes.
Logs remain under `/tmp/ap073-federation-complete-final/` and the matching results
log. No passing canonical federation artifact is claimed for that failed cohort.


### Coordinated federation construction result

All **37** exact-counted artifact constructors passed in the repaired cohort.
`engagement/federation.json` records seven genuine native histories with three
distinct issuer keys (control, raw-key resource A, did:key resource B). The native
positive control performed one real private HTTP write; missing/wrong trust,
method, signatures, evidence, root and resource path cases produced no provider
I/O or ancestor allocation. An accepted owner A's native-valid proof for the exact
B action was refused by B's pinned enrolled suffix. The other six histories
exercise real independent gateway processes: one shared final-capacity winner,
an explicit independent-engagement control, and withdrawal before/after entry
with resume/SIGKILL/restart. Shared charges and Unknown remain conservative.

The original one-issuer corpus, commissioned recovery, created-child use and all
seven installed SDK scenarios also passed in this cohort. Independent Python
still agrees on all 39 created-resource projection cases. Semantic closure was
regenerated and its equality constructor passed. Logs are
`/tmp/ap073-federation-repaired-final/`,
`/tmp/ap073-federation-repaired-results.log` and the matching build log. These are
required repository-artifact constructors, not broad local acceptance checks.
The preceding failed cohort remains recorded above.

This establishes the selected coordinated federation slice under explicit
operator/topology assumptions; it does not prove independent human consent,
separate-UID confinement, TLS PostgreSQL, disconnected escrow, global revocation,
whole-store rollback detection, native-records qualification or source-linked
formal closure. Those scoped gates/implementation gaps remain required for full
AP073 acceptance. No push, hosted CI observation, merge or deployment occurred.


### Native records bounded closure batch (unverified)

ADR0022 selects the existing gateway plus real records service composition, not
another native execution framework. Move the demo's existing native proof fixture
and records-only persistent lifecycle registry into feature-gated domain testkit
ownership; both the demo and installed native conformance consume it. Default
records builds do not include fixture issuance/keys. A small fixture signer port
receives public evidence/signatures from the existing owner/A/B processes.
Central records presentation preparation supplies identical signing preimages
for local and external keys; verification remains at the resource.

The eighth installed case uses a real records ledger/service. Its approved
canonical native create action and exact exchanged-proof commitment fit existing
bounded recipe fields; no giant proof field, chunking, dynamic header or shared
provider branch is added. Native proof bytes are retained unverified inputs,
never allow verdicts; the resource re-verifies them at a fresh explicit server
clock. The native policy retains separate provider usage while the existing
AP073 journal alone owns participant/ancestor admission, withdrawal and Unknown.
Initial parent state is independent operator setup. Native parent/child reads,
B's child create, lost response, restart, independent listing, child use and old
scope withdrawal join the existing installed journey. Credential-free/wrong-token
HTTP requests fail before protected calls. Six service-level negative cases use
real native verification for proof, presentation, action, audience, time and
configuration; typed refusal/Err returns no projection or protected usage.

Construction batch: finish all source, wire/inventory/spec/CI and adversarial
assertions, format, construct the intentional dependency graph/lock artifacts,
then regenerate semantic closure. Build the existing gateway artifact targets
and records API library constructors together. Add the external-presentation
constructor to the prior 37-selector cohort; installed artifact/5 must contain
all eight actual cases. Require compiled-registry resolution and exactly one
executed test per selector. Preserve existing product canonical fixtures; hosted
AP024 tests must exercise unchanged demo behavior. No behavioral constructor,
build, architecture constructor, broad gate or hosted CI has run for this new
batch yet. The initial format attempt found a duplicate existing SDK dependency;
remove that redundant declaration, keeping the existing SDK dependency intact.

The goal audit still has native conformance construction, source-linked assurance
and the final exact-head hosted cohort open. Earlier completed evidence must not
be reimplemented merely because the initial baseline table still says pending.
Do not expand into another runtime, provider abstraction or identity framework.


Native batch construction prelude completed: the intentional architecture and
lockfile artifacts were generated (only the new domain testkit/dev dependency
edges; no dependency version changes), and all required native targets compiled
without diagnostics. Before executing behavioral constructors, source review
separates B's proposed child payload from the private parent sentinel. The native
write action is carried through B's submission, so copying the private parent
content into that action would defeat the intended information-flow experiment.
Use an independently public child payload and assert the private parent sentinel
and its encodings/hashes are absent from the native action. The baseline parent
remains private and is delivered only through the existing controlled disclosure.
No behavioral constructor result is claimed yet; rebuild the changed integration
target before the complete 38-constructor artifact cohort.


The 38-selector native-records constructor cohort passed 37. The installed
constructor retained seven passing scenarios; the new native case failed during
its independent parent setup because the copied native policy still selected
the old demo executor audience. The native policy correctly refused the mismatch.
Set its explicit audience to the same installed resource audience; keep all
verification checks intact. Add stable refusal-code context to the setup assertion
without printing private actions or contents. This changes only the integration
fixture. Rerun the affected installed constructor (all eight scenarios) and
semantic closure equality; do not repeat the 37 unaffected constructors whose
source and artifacts have not changed. Logs remain in
`/tmp/ap073-native-records-final/` and the matching result/build logs.


The affected installed rerun again retained seven passing scenarios and refused
the native parent setup with presentation-invalid. The fixture had confused two
identifier contracts: the canonical raw-key principal of the native proof and
the records presentation's existing `key:ed25519:<public-key-hex>` label. They use
the same signing key here, but are distinct encodings. Centralize that domain
presentation label in `RecordsPresentationV1::signer_principal`, used by its
preparation function, the existing demo and the native fixture policy. Keep core
principal-method IDs unchanged; never treat the presentation label as one. The
wire bytes of existing presentations remain the same. Recheck the affected
presentation constructor alongside the installed journey and semantic equality;
37 other native artifact constructors remain unchanged in source/results.


The identity-label repair passed external presentation and semantic equality.
All native records work, resource usage and the eight-case workflow reached the
final report, which exposed a fixture-count mismatch: the existing direct-provider
loop probes machine/A/B, while the new native report expected all five roles plus
its wrong-token probe. Extend the common loop to owner and reviewer as well,
including their distinct-UID file probes, and assert the exact six refusals in the
native case. Keep the existing agent probes; do not lower the expected isolation
coverage to hide the mismatch. This affects only the installed constructor; its
presentation and semantic source/results are unchanged. Preserve the failed
identity cohort logs under `/tmp/ap073-native-records-identities-final/`.


### Gateway-protected native records construction result

The installed constructor now passed all **eight** actual scenarios (54.40 seconds)
with exactly one executed test. Native records conformance performed one child
create through the real records service and sealed persistent store, two distinct
native read actions, gateway response loss/crash/restart, independent listing,
bound child use, replay and ancestor withdrawal. Six native preflight mutations
were refused without protected usage/projection. Five real installed roles and
one substituted dispatch credential received HTTP refusals; all were retained as
exact counted facts. The private parent payload is absent from B's native write
request. Original mutation/creation/recovery cases remain passing.

`engagement/installed-process.json` is artifact/5 with eight completed cases.
The new presentation artifact passed after the domain presentation-label helper
was centralized, and semantic equality passed. The prior 37 unaffected native
constructors passed in the first cohort; only affected selectors were rerun for
repairs. Logs remain in `/tmp/ap073-native-records-final/`,
`/tmp/ap073-native-records-identities-final/` and successful installed
`/tmp/ap073-native-records-probes-final/`, with their matching build/result logs.
All counts reflect executed registered tests rather than exit-zero empty filters.

The records demo reuses its existing authoring/records registry through the gated
domain testkit; native external signing returns no private actor keys. Presentation
wire bytes are unchanged. Intentional optional/dev dependency snapshots and lock
entries were constructed without version upgrades. The resource adapter is test
and conformance code; no records dispatch, callback or native profile interpreter
was introduced in the shared gateway. Local cases have distinct_uids=false and
reuse unchanged installed packages. They do not establish exact-head rebuilt
packages, Linux confinement, provider HTTPS/crash recovery, human intent or
production recipe qualification. No broad local/PG/formal gate, push or hosted
CI observation has occurred.

The current assurance/acceptance owner map is
[0073-assurance-map.md](0073-assurance-map.md). Remaining bounded engineering is
its exact-source ancestor arithmetic link and reverse stale-prefix checkpoint
case, followed by source/evidence freeze and final exact-head hosted gates.
The map explicitly distinguishes native product tests from actual translated
proofs and from independently authenticated deployment floors.


### Final bounded assurance linkage batch, before construction

The owner audit found that ancestor accumulation used equivalent local checked
addition/filtering while ordinary gateway sums already called the translated
`auths_bounded_policy::kernel::chain_sums_admit` leaf. Reuse that exact existing
guard on the one retained counter and use the existing checked-add leaf for the
stored cumulative total. This preserves zero-byte/zero-ceiling arithmetic,
immutable row policy, slot limits and common transaction ownership; it adds no
new model, provider dispatch or state machine. The existing sum/add refinement
statements now directly cover the arithmetic callsite, conditional on faithful
origin/prefix/store inputs. No theorem is claimed for the entire product glue.

Capture an actual retained root-only audit prefix, then assert that it is refused
against the later independently retained withdrawal checkpoint. Keep the existing
new-archive/old-head refusal, original proof replay, missing evidence and trust
substitution cases. The restore protocol still requires an external trusted head;
a whole coherent store cannot certify its own freshness.

Construction mapping: the changed audit constructor; native ancestor admission,
hierarchy, read/disclosure/prerequisite, lifecycle-recovery and created-child
allocation artifacts; real cross-recipe and federated file histories; existing
semantic-closure identity. PostgreSQL counterparts and zero-byte allocation unit
boundaries stay in the authoritative hosted cohort. Regenerate only required
identities and affected canonical artifacts; do not run a broad local test gate.
All source and assertions for this two-change batch are now written. No passing
result is claimed yet. Once construction finishes, source/evidence freeze and
exact-head hosted acceptance are the remaining work; no new framework is planned.


### Bounded assurance construction completed; source freeze and publication

All twelve affected registered artifact constructors passed with exactly one
executed test and zero ignored per selector. This includes the audit prefix/head
negative, ancestor admission/hierarchy/information/prerequisite/live delivery,
instance and created-child recovery, cross-recipe and federated file histories,
semantic equality, and the installed test containing all eight scenarios. The
batch results and per-selector logs are `/tmp/ap073-assurance-closure/` and
`/tmp/ap073-assurance-closure-results.log`; the required constructor build log is
`/tmp/ap073-assurance-closure-build.log`. The installed scenario collection uses
the unchanged local installed SDK consumer; separate-UID and rebuilt exact-head
packages are not established by this local run.

The source now directly invokes the already refined sum/add leaves. The audit
artifact retains both directions of stale checkpoint mismatch. No full-product
formal theorem, automated whole-store rollback detector, gateway provider
interpreter, or extra execution owner was introduced. The supported contracts
and F01–F16 evidence owners are in the assurance map and ADRs0018–0022.

Constructed semantic source closure, assurance source citations and release
freeze identities are metadata, not proof acceptance. Required local artifact
construction is complete. Remaining acceptance is the exact-head hosted CI,
formal, PostgreSQL, bindings, packaging, source-free isolation and release gates.
No broad local gate was substituted for GitHub. The complete implementation is
ready for publication to its own draft PR; no merge or deployment is authorized.


### First hosted cohort: bounded repair mapping

Published implementation `fb576449` in draft PR215. Hosted generated-artifact
preflight and distinct-UID gateway isolation passed. The first failures were:

- Python source-contract job: the AP074 independent mutation report retained the
  previous native corpus digest. Regenerate with its unchanged independent Python
  oracle; do not change expected decisions or relax report equality.
- Disposable provider simulations: the test-only `approve_driver_with_plan`
  assembled real prerequisite declarations but left their binding budgets empty.
  Current admission correctly refuses these incomplete synthetic bindings, so the
  Stripe oracle never enters and the race waiter never reaches its read barrier.
  Populate the central fixture helper using `Prerequisites::budgets` as the native
  compiler already does. Keep shipping admission strict and preserve both exact
  write-count and pending-read race assertions.

Repair verification batch: exact registered Stripe simulation and file race,
artifact report regeneration/equality and its focused independent tests, required
semantic-closure construction/equality, then final hosted acceptance. Collect any
additional independent failures from this same cohort before publishing repairs.
The baseline hosted results are evidence at `fb576449`, not final-head acceptance.


The same cohort's repository preflight exposed a third root cause: compliance
recognized only literal unparameterized `#[tokio::test]`, so actual compiled
multi-thread tests were rejected. Extend that central source-inventory check to
recognize configured Tokio attributes and preserve its existing helper/macro
anchor convention. The inventory is source linkage, not proof of compiled test
execution; owning gates still establish actual registered tests and results.
Add a regression for each maintained attribute form and existing helper anchors,
then rerun the complete inventory path without changing compliance anchors.


The packaged Stripe demo also exposed its stale self-test reader: the expected
private binding schema was still `/3`, whereas this source directly emits `/7`.
Update both maintained gateway demo self-test oracles to the single current `/7`
schema; retain exact namespace/operation/action-byte checks and reject obsolete
schemas. Do not add a legacy reader or derive the expected schema from the
untrusted binding. Both installed demo workflows must rerun on the repair head.


Hosted PostgreSQL completed with three failures: the synthetic prerequisite race
and aggregate-bounds first-entry case share the incomplete test binding fixed
above; the attempt-scenario corpus still declared `/16` while both reader and
current journal require `/17`. Update that declarative corpus metadata to `/17`;
keep the same 27 scenarios and expected outcomes. Native successor recovery,
created-resource recovery and existing native authority/observation tests passed
in the configured PostgreSQL cohort. The original full gate remains failed until
the repaired exact head reruns it.


Focused local repair evidence passed: exactly one registered Stripe simulation,
file pending-prerequisite race, 30-case aggregate-bounds suite, 27-case attempt
suite, semantic equality, configured-attribute inventory regression and complete
registered compliance inventory per selector. The independent Python comparator
regenerated only corpus/source digest metadata (all 28 request and 26 response
comparisons unchanged), and its hostile-mutation test passed. Logs are
`/tmp/ap073-first-ci-repair-*.log`; the two required scoped build logs are
`/tmp/ap073-first-ci-repair-build.log` and
`/tmp/ap073-compliance-repair-build.log`. No PostgreSQL or Docker demo was rerun
locally. Hosted reruns are required for all repaired consumers and final heads.
These reproductions do not close authoritative/formal/package gates skipped by
the failed repository preflight. Update only changed source/freeze metadata and
publish the collected repair batch; preserve the complete acceptance matrix.


### Second hosted cohort: Clippy closure batch

Revision `34e24d4a` passes the originally failing Python source-contract and
provider simulation jobs plus generated identities and distinct-UID gateway
isolation. Repository preflight reaches workspace Clippy and reports 22 gateway
lints plus one missing panic-doc section in the records fixture authoring API.
Map all diagnostics before reproducing: box the oversized disclosure future,
use method references, make the borrowed-only scope purpose Copy, use let-else
and equivalent conditional forms, name the existing admission callback type,
extract scope validation and enrollment snapshot lookup without reordering native
checks, and separate the created-resource review projection. Document fixture
panics explicitly. Keep the two complete atomic grant-entry protocols intact:
function-local expected line-count lints explain the durable-acknowledgement
boundary rather than splitting it just for a length limit. Original-evidence
control transitions intentionally own evidence through their publication fences;
function-local expected ownership lints record that contract. No security check,
wire schema, fixture expectation, store transaction or test count is relaxed.

All source changes for this lint batch precede verification. Reproduce the failed
workspace Clippy command to collect any remaining independent diagnostics, then
run affected native evidence and regenerate only required source identities.
The formal, PostgreSQL and packaged-demo cohorts continue independently; their
results are not inferred from a passing lint check.


The full failed-command reproduction first reached a 103-line WebAuthn ceremony
test. Combine its two identical claim-presence assertions into a loop over both
unchanged expected names; retain stale-time/signature/preimage assertions. This
is test-only organization and changes no principal method behavior or claims.
Continue the same collected workspace lint reproduction to expose downstream
test-target diagnostics before publication.

The downstream test-target cohort reports 85 gateway diagnostics, primarily 54
oversized test futures retaining complete signed fixtures. Box those specific
awaited fixture futures without changing their protocol calls, cancellation order
or assertions; keep production future linting enabled. Complete unit-expression
semicolons, use explicit variant patterns, remove an unused async marker, and
correct names/iteration/static helper calls. Opaque private types retain no Debug
surface; compare their complete serialized fixture values/bytes for equality.
Keep explicit signed fixture constructors and adversarial matrices whole with
function-local expected length lints, and document intentionally owned test-case
inputs. Do not waive test execution, change hostile-case outcomes or suppress a
crate-wide lint. This whole test-only repair batch precedes the next reproduction.


The same published cohort passed configured TLS PostgreSQL qualification and the
source-free installed Linux delegation selector: exactly one test passed with
zero ignored (14.82s), containing all eight distinct-UID scenarios. Airtable's
36-case self-test also passed. The job later failed only while uploading the
root-owned 0600 redacted AP073 report. Transfer ownership of that one known report
to the host owner of its package manifest; do not broaden modes, recurse through
private directories, or alter credential custody. The next exact-head run must
retain and independently inspect the report, so this is not yet final acceptance.

Clippy then reached 16 integration/binary test diagnostics plus test-module
placement. Correct similar identifiers, unit semicolons, an unnecessary closure
drop, use placement and opaque policy equality. Keep complete process-launch/HTTP
fixture constructors reviewable with narrowly explained expected lints; the UID
assertion intentionally guards an opt-in Linux-only mode while default fixtures
compile on macOS. Move the compliance test module after its implementation. All
these changes and the one-file upload-ownership repair precede reproduction.

The full `cargo clippy --workspace --all-targets --all-features -- -D warnings`
reproduction now passes. Its final log is
`/tmp/ap073-second-ci-clippy-repair.log`; no crate-wide lint exemption was added.
Required verification/construction mapping for the helper extraction and test
organization: native enrollment/effect/approval, ancestor admission/control/
hierarchy, acquisition/disclosure/prerequisites/live delivery, created-selection/
recovery, instance recovery, cross-recipe/federation and semantic equality. Also
exercise the unchanged WebAuthn ceremony and records presentation assertions.
Resolve every actual compiled selector and assert exactly one pass, zero ignored;
fixture equality runs without update mode except required semantic construction.
Hosted PostgreSQL, source-free Linux package/browser and formal gates must rerun
on the repair head; this local reproduction is not final acceptance.


All seventeen mapped native/records/WebAuthn fixture-equality regressions passed
with exactly one executed test and zero ignored each, with update mode disabled.
No expected artifact output changed. Logs and results are
`/tmp/ap073-second-ci-affected/` and
`/tmp/ap073-second-ci-affected-results.log`; its constructor build is
`/tmp/ap073-second-ci-affected-build.log`. Required semantic identity construction
preceded these checks and equality passed on the new source. Full workspace
Clippy also passed. The source maps now refer to PR215's exact-head required
checks as the final acceptance record instead of embedding an enduring pending
or passing status in the specification. Rebuild/freeze only changed identities,
publish this complete repair batch, and require all applicable hosted gates on
that revision. Historical passing PostgreSQL and source-free Linux results do
not substitute for final-head results; no merge or deployment is authorized.


### Third hosted cohort: retained evidence and exact secret-scan findings

At revision `12b54e9f`, repository preflight, both SDK package/runtime matrices,
Airtable and Stripe installed demos, gateway UID isolation, dependency policy and
configured TLS PostgreSQL qualification pass. Retrieved the Airtable evidence
archive `13500920296` from run `42213007499`; verified its GitHub SHA-256 digest
`99e5ac10b4d846fc90012414e5de73ee2b014e65341b41d60189fb47d339dc94`.
Its package manifest names this exact revision. The uploaded delegation report
is artifact/5 with all eight cases and distinct_uids=true throughout; native
records reports six preflight refusals, zero protected preflight effects, one
create and two native reads. The packaged owner/browser report is also bound to
this revision. This now establishes retained hosted evidence at this head,
including the previously failing private report handoff. Formal/authoritative/
compliance gates are still pending; no whole-program acceptance is inferred.

The full-history Gitleaks job finds four generic-api-key matches. Reproduced with
the exact v8.28.0 Go module and a redacted JSON report, printing only file/line/
fingerprint metadata. Three are record_key_hex in historical native enrollment
configuration fixtures (commits `430122ac`, `065150dc`, `28ca7e82`); one is the
operation_key_hex public replay key in the AP074 merge occurrence `68987975`.
Inspected all matched fields and their constructors: each is a deterministic
64-hex SHA-256 lookup identity derived from public synthetic policy/namespace/
partition/engagement/operation inputs. None is a signing key, provider credential
or private content. The fixture wire identities are required; preserve their
bytes. Add only the four exact historical fingerprints with source-linked
comments, consistent with existing reviewed public-digest entries. No path,
regex, rule or general allowlist is added. Stage only this repair and its ledger,
run the required exact staged-diff scan, and keep collecting any other failures
from the current cohort before publication.
