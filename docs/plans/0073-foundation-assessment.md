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
