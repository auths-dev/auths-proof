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

All entries are **open**. Existing source below identifies reusable mechanisms,
not evidence that multi-agent coverage has passed on this branch.

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
