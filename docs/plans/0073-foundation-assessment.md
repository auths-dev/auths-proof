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
