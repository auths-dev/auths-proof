# AP-SPEC-077: Administrative recovery protocol

Status: implementation contract for AP-SPEC-076 D0 and D2–D4. This document
specifies behavior; completed implementation and verification are tracked in
`docs/plans/0076-implementation-status.md`. It grants no production qualification.

## 1. Owners and authority

| Existing fact/owner | Meaning and permitted use |
| --- | --- |
| Private installation manifest, recipe, lock, trusted context, effect policy and operator attestation | Exact local configuration and operator identity. Manifest presence alone is neither a published connection nor custody availability. |
| `candidate-installation.cbor` | Retained initial connection identity/timestamps and approved descriptor; resume must reuse it. It cannot authorize credential reads or connection publication. |
| Native `SharedConnection` record and independently retained generation floor | Current connection, revocation, credential generation/commitment and restore protection. Their atomic revisions/fences order publication and application entry across hosts. |
| `CandidateCredentialTarget`, exact proof/action/approval and native acquisition records | Exact candidate identity and independently approved check evidence. Only the existing candidate publication fence decides sufficient fresh evidence and one-use publication. |
| `CredentialJournal` | Bounded write-ahead set of exact generations that might exist in custody. A note is a cleanup obligation, never evidence of credential possession, deletion, publication, or provider effect. |
| Credential journal phases | `Retained`, `MutationPending`, `DeletionPending`, `DeletionIncomplete`, `DeletionConfirmed`. A pending creation is never automatically collected/forgotten: an exception or dead process cannot prove that external custody creation stopped. |
| Credential adapter | Exact generation possession/commitment and exact deletion acknowledgement. Unavailability/exception retains uncertainty. No list API is cleanup authority. |
| Qualification verifier memory and native effect-configuration floor | Monotonic accepted revocations/release facts. Neither filesystem rollback nor an old bundle may lower them. |
| Qualification `.next`, current and `.previous` directories | Retained candidate, published local inputs and retired local inputs. Directory names confer no qualification; every candidate is reverified under the pinned root and retained floors. |

Recovery status is a read-only projection of these existing facts. There is no
new administrative journal, executor, provider entry permit, retry entitlement,
or parallel configuration authority. Local status may report unavailable rather
than guess when a native/custody read fails. It never claims negative custody
from an absent local file. Existing effect, acquisition, mutation, restore-floor,
revocation and operator-separation rules remain in force.

## 2. Commands, identities and outputs

All commands use the existing trusted operator CLI boundary and owner-private
state directory. Remote operator commands retain their authenticated operator
socket boundary; no application route may invoke recovery. Secrets enter only
through the existing bounded stdin mechanism and never appear in recovery JSON.
Private file reads reject symlinks, foreign ownership, inappropriate permissions,
wrong schemas and oversized inputs. A new prelaunch format rejects obsolete
state rather than translating it.

| Command | Input, action and repeat result |
| --- | --- |
| `recovery-status --state-dir DIR [--candidate FILE --proof FILE --action FILE --approval FILE]` | No custody/provider mutation, credential lease or provider read. Return the closed projection below; local lock/note reads may synchronize the existing journal without changing its semantic content. Candidate inspection requires all four candidate/proof/action/approval files together. Exact current/superseded target observations need no renewed approval or provider I/O; readiness inspection binds the exact native acquisition identity and uses the same validation guards as publication. Expired approval cannot hide an already-current exact target observation. A supplied canonical candidate is bound to the installed recipe, exact connection and native predecessor/current revision. Omit candidate-specific readiness when no candidate was supplied; never infer approval from proposal-file existence. |
| `install` with existing arguments | Fresh installation only. An existing manifest returns `gateway.install.already-installed`. Partial retained inputs are refused unless the operator explicitly supplies `--resume`. |
| `install --resume` with the same complete installation arguments and `--credential-stdin` | Validate all original approvals/configuration before comparing existing files. Retain or compare exact bytes, reuse retained draft identity/timestamps, and complete only missing steps. Any existing different input returns `gateway.install.resume-conflict` without overwriting it. A manifest with the exact configuration is an input to native/custody inspection, not success by itself. The supplied secret must match any existing exact generation; it cannot replace conflicting custody. |
| `candidate-stage-installation` / `candidate-stage-rotation` | Existing trusted command and canonical proposal output. Repeat with the same secret/draft/current predecessor returns the same candidate identity. Different secret at the staged generation fails with the existing generation/credential conflict; never revoke/replace the staged generation to make retry succeed. Output-file existence is handled by exact-byte comparison. |
| `candidate-acquire` | Existing exact proof/action/approval. Existing native acquisition record decides replay/conflict/unknown; recovery never re-enters a read from a stored unknown outcome. No automatic reacquisition occurs during status or publish. |
| `candidate-publish` | Existing exact candidate/proof/action/approval. Native checks and atomic publication remain authoritative. Exact already-current target plus the required native acquisition identity returns the existing AlreadyCurrent disposition, a state observation rather than causal attribution to this invocation. A later revision/revocation or different target is conflict, even if a local proposal remains. Lost acknowledgement requires authoritative inspection/replay of this exact publication, never a fabricated permit. |
| `rotate-prepare`, `rotate-commit`, `rotate`, `disable`, `enable`, `revoke` | Preserve current guards and native revisions. Prepared custody is not published custody. A stale prepare/commit cannot overwrite a later generation or revive revocation. Status/inspection after a lost acknowledgement reports the authoritative current record; a successful current state alone does not prove which competing request caused it. |
| `credential-collect` | Existing exact-generation cleanup command. Snapshot current native record and journal, wait a complete minimum retirement interval on this process's monotonic clock, then reload the same native revision before deletion. Process restart starts a new complete interval. Delete at most 16 eligible generations per call, retain every unconfirmed obligation, and report completed versus remaining/incomplete separately. |
| `qualification-import --state-dir DIR --from DIR` | Verify the complete supplied bundle under installed pins and both retained floors. Stage exact bytes durably before advancing floors. Repeated exact inputs complete an interrupted publication or return already-published; different staged inputs conflict. A partial staged bundle is completed by explicitly importing its original complete signed bundle; existing bytes must match. A corrupt or conflicting retained candidate is quarantined rather than overwritten. |
| `qualification-recover --state-dir DIR` | Explicitly finish the retained verified `.next` bundle or clean retired `.previous` after verified current publication. Reverify under current pins/floors. No network, credential lease, provider read or floor decrease. Missing/inconsistent accepted inputs return unavailable and require a fresh explicit import that meets all retained floors. Never restore `.previous` as automatic rollback. |

`recovery-status` emits `auths.gateway-recovery/1`, with an installation state,
optional candidate state, cleanup state, qualification state, the current native
revision/generation when readable, and a closed list of legal next command names.
It emits no secrets, unbounded paths, opaque provider response bodies or tokens.
Bound output to 1 MiB, generations to the journal's 64 entries, and command lists
to the commands in this table. A required unavailable authority sets the relevant
component to `unavailable` and gives a non-success command result. Corrupt input
sets `quarantined`; it is never interpreted as empty/fresh state. Components may
be independently incomplete. Publication success and pending cleanup coexist.

## 3. Installation and candidate transitions

| Derived state / command | Guard and durable/effect ordering | Successor/result |
| --- | --- | --- |
| Uninitialized / fresh install | Validate recipe digest, lock, trust, effect policy, deployment/custody policy, operator attestation and separation first. Acquire private installation lock. Generate initial identity/timestamps once and durably retain draft before custody. Retain exact input files before manifest. | InputsRetained; subsequent steps below. |
| InputsRetained / fresh install | Refuse existing partial input set. | Unchanged; explicit resume required. |
| InputsRetained / resume | Compare every existing input and manifest byte with the supplied validated inputs. Use the same retained draft; never generate another ID. Durably write missing files, then manifest. A mismatched/malformed retained draft is quarantined, not replaced. | ConfiguredUnpublished. |
| ConfiguredUnpublished / stage | Durably initialize/register exact cleanup generation before any custody write. Establish exact custody without replacing a different commitment. Initialize/check native candidate floor. Persist exact canonical proposal before reporting staged success. | CandidateStaged; error retains cleanup note and possibly custody. |
| ConfiguredUnpublished / offline installation without credential reads | Same write-ahead custody/floor ordering, then existing native insert/CAS. Reload the native record/floor after acknowledgement. | Published only if exact current binding is readable; otherwise unavailable/unknown publication. |
| CandidateStaged / inspect | Read exact native acquisition/check facts. No checks are run. Distinguish incomplete, refused, ready, published, superseded and unavailable. “Ready” is advisory at read time; publish rechecks all guards. | No mutation. |
| CandidateStaged / acquire | Existing exact native acquisition admission, credential binding, one-use entry and result persistence. Refusal/unknown remains a retained native fact. | ChecksIncomplete, ChecksRefused or ReadyForPublication, derived without inventing retries. |
| ReadyForPublication / publish | Recheck operator/native approval, freshness, exact predecessor, generation floor, custody commitment and qualification/effect configuration inside existing atomic publication fence. | Published with native disposition; obsolete predecessor => conflict; missing/failing check => refusal/unavailable. |
| Published / exact publish replay | Require the existing native replay guards and current exact target; AlreadyCurrent is a state observation, not an attestation that this invocation caused publication. No new acquisition, custody write or provider entry. | AlreadyPublished/replay. |
| Published / later rotation, disable or revoke | Native revision and generation checks decide; service entry uses existing fence. | Current native successor, never a local-file prediction. |
| Any / corrupt or inaccessible required evidence | No authority recovery by guessing, zeroing a floor or overwriting custody. | Quarantined/unavailable; fail closed. |

Initial installation is durably acknowledged only after exact native publication
and its required floor are acknowledged and re-readable. Candidate staging may
be acknowledged earlier as **staged**, explicitly not installed/serviceable.
A local manifest can survive a failed install; status must say unpublished or
unavailable rather than installed. A missing manifest after partial input writes
is resumable only through the exact validated installation command.

## 4. Credential retirement and collection

The cleanup projection has `NonePending`, `AwaitingDelay`, `DeletionPending`,
`DeletionIncomplete`, `DeletionConfirmed`, and `Unavailable`. It is orthogonal
to current publication and is derived from the existing exact-generation journal,
current native record, and this process's monotonic observation interval.
`DeletionConfirmed` means an exact adapter deletion was acknowledged and its
journal note removal durably acknowledged; a lost note-removal reply leaves a
conservative possible obligation until a fresh journal read.

| Event | Required behavior |
| --- | --- |
| New possible custody generation | Register and synchronize journal note before install/replace/confirm can create custody. A full/unreadable journal refuses new custody mutation. |
| Native successor publication | Retain superseded exact generations for at least `CredentialRetirementDelay::FIXED`. Do not equate successful CAS with successful cleanup. |
| Restart or collector creation | Lose no journal notes. Begin a new complete monotonic delay after snapshotting the native revision. No wall-clock deadline permits earlier deletion. |
| Delay elapsed | Reload current record and floor; require the same exact native binding as the snapshot. Changed generation/state => `gateway.admin.generation-conflict`, retain notes, no deletion under stale authority. |
| Eligible exact generation | Delete only a noted generation not newer than the native generation and not the active credential; revocation permits deletion of its current credential after the same delay. A staged unpublished successor is not an obsolete published generation and is retained. |
| Adapter deletion succeeds | Durably remove only that exact journal note. Never remove the note before acknowledgement. |
| Deletion fails or acknowledgement is lost | Retain note; report `gateway.admin.credential-deletion-incomplete`. Continue independent eligible cleanup within the bounded batch; aggregate incomplete result. Do not claim no effect or delete another generation as compensation. |
| Journal note removal fails | Retain/inspect obligation and report journal unavailable. Repeated exact revoke is allowed only under the adapter's existing idempotent exact-generation contract. |
| Competing collectors | Local journal lock serializes note updates; exact idempotent revoke and native revision guards make overlap safe across hosts. No collector can delete the active or unobserved newer generation. Each reports its own acknowledged removals and remaining obligations. |
| No eligible notes | Return completed zero without custody listing or deletion. An unreadable journal is unavailable, never zero. |

The phase-bearing journal is `auths.gateway-credential-journal/2`, a direct
prelaunch cutover. Register an exact note, durably claim MutationPending before
custody creation, and return it to Retained only after that owned operation
settles with acknowledged completion or a typed custody refusal whose port
contract certifies that this invocation made no change. Network, persistence,
unsafe-state and lost-reply errors retain uncertainty. A second creation cannot overwrite a
pending/deleting operation. Collection durably claims DeletionPending, records
failure as DeletionIncomplete, or persists DeletionConfirmed before forgetting
the note. Crash before creation acknowledgement retains MutationPending and
reports `gateway.admin.credential-operation-unconfirmed`; automatic collection
must not guess that an external request stopped. This is a quarantined cleanup
condition requiring provider-administrator resolution, not an application retry
or proof of non-effect. This version deliberately offers no command that clears
such uncertainty by assertion or by observing an instant of absence.

Each host reports and retains its own write-ahead obligations. Hosts sharing
external custody can have separate notes for the same generation; local cleanup
success does not assert that every other host's pending write has stopped or
that custody can never reappear. Every custody writer must retain its own pending
note across uncertain completion. No acknowledged global empty-custody claim is
made from one host's journal.

The in-memory retirement queue is scheduling only. Failed entries remain queued;
restart recovery comes from the durable journal. No new timestamp ledger is
required: the conservative complete-delay rule satisfies the existing minimum
safety bound without trusting wall-clock continuity. Credentials can be retained
longer after restart; this is an explicit operational cost, not an ambiguity.

## 5. Qualification transition and durability order

Private file construction uses the reserved `.auths-pending-` namespace until
atomic publication to the official name. These unpublished temporaries carry no
accepted input or authority. Bundle readers exclude this namespace while still
bounding the total directory inventory. Under `qualification.lock`, staging
removes only reserved temporary regular files belonging to this UID, with private
permissions and one link, then synchronizes their directories. Other entries
are never deleted by temporary cleanup; unsafe reserved-file metadata fails
closed. Official retained inputs are compared exactly
and never removed to restage. Interruption during this temporary cleanup is
idempotently recoverable by the same explicit import. An incomplete retained
bundle still requires its original complete authenticated source bundle.

The closed projection is `Empty`, `Staged`, `FloorsAdvanced`, `CurrentPublished`,
`RetiredCleanupPending`, or `Unavailable`. Read verification of actual files and
retained/native floors supplies the state; no marker grants authority.

The importer/recoverer takes one private `qualification.lock` for the entire
host transaction. The live reloader uses the same lock while reading/updating
local verifier memory. It must not reenter that lock through its own helper.
Across hosts, native effect-configuration/floor CAS remains authoritative; local
file locks make no multi-host claim.

1. Read pins, previous verifier memory and complete candidate; verify signature,
   deployment/recipe tuple, bounded membership, revocation and monotonic rules.
   Refused input changes nothing.
2. Materialize every `.next` member using private create/compare files. Never delete an existing accepted candidate to restage it. Sync each
   file, each records/attestations directory, the `.next` directory and installation
   parent. Re-read and reverify complete staged bytes before changing any floor.
3. If both current and retired inputs exist, verify current against both existing floors and durably clean the retired input before advancing floors. Otherwise retain all evidence on failure. Publish the existing native effect-qualification floor/configuration and
   durably advance local verifier memory. These are monotonic. A failure between
   them is unavailable publication; recovery must reconcile upward using the
   retained verified bundle. Never lower either floor to make the old bundle work.
4. Preserve the retained `.next` and any `.previous` through interrupted publication. Missing current is fail closed; recovery completes the same reverified candidate. A fresh import is permitted when no conflicting `.next` remains.
5. Rename current to `.previous` when present; sync installation parent. Rename
   `.next` to current; sync installation parent. Verify the resulting current
   bundle against both floors before reporting publication success.
6. Remove `.previous` and sync installation parent. A failure here is
   `RetiredCleanupPending`, with publication retained; repeated recovery performs
   cleanup without repeating floor advancement or claiming rollback.

No atomic transaction is claimed across native store, filesystem and custody.
The command's acknowledgement names the reached state. “Imported” requires native
and local floor acknowledgement, durable current-directory publication and
read-back verification. Retired cleanup failure is reported separately. Success
must survive immediate process/host restart under the storage assumptions below.
A lost native reply requires reload; `.next` cannot manufacture that reply.

When `.next` exists, recovery re-verifies it and resumes the monotonic sequence.
When only `.previous` exists and current is missing, publication is unavailable;
there is no automatic rename-back. When current is valid at both floors, recovery
may remove retired input and report current publication. A new valid import can
repair unavailable publication only by meeting or raising retained floors.

## 6. Competing administrators and live entry

| Race | Ordering and loser result |
| --- | --- |
| Two local installs/resumes | `installation.lock` spans all retained file/custody/native steps. Same exact resumed inputs inspect/complete the winner; different inputs conflict before custody mutation. |
| Two hosts install the same provider/alias | Existing native insert/floor publication chooses one exact connection. Loser reloads, reports conflict and retains its cleanup notes; it does not adopt the winner's credential or ID. |
| Stage versus publish | Native candidate predecessor/generation and exact custody commitment order them. File proposal overwrite is prohibited unless identical. Staging is never publication evidence. |
| Rotate versus revoke; enable/disable versus rotate | Existing native CAS/fences order changes. Stale revision loses and reloads. Revocation is terminal and cannot be undone by stale rotation/enable. |
| Retire versus rotate/revoke | Collector reloads after its full delay. Changed binding aborts that collection; retry begins a new snapshot/delay. Exact-generation idempotent deletion cannot remove a later active generation. |
| Two qualification imports on one host | Qualification lock serializes. Identical input resumes; conflicting pending accepted input is unavailable/conflict until explicit completion or a fully verified new import meeting floors. |
| Qualification imports on different hosts | Native floor/configuration CAS orders authority. Each host must meet the winning native floor before service can qualify; a local directory publication cannot override a losing native update. |
| Recovery/status versus another writer | Status is a bounded observation, not a snapshot transaction across systems. A detected mismatch reports unavailable/reload. Every mutating command rechecks native revision under its existing fence. |
| Application entry versus admin change | Preserve counted in-flight entry and native final reload/fence. An old admitted operation retains its generation for the safety interval; no new entry can rely on an invalidated configuration/generation. Cleanup never manufactures or repeats entry. |

## 7. Supported durability model and interruption matrix

Support process termination and host restart on local durable filesystems with
atomic same-filesystem rename and working file/directory synchronization, and the
existing native file backend / TLS PostgreSQL durable transaction contract.
Reject unsupported topology rather than treating remote filesystem semantics as
local atomicity. The credential adapter's acknowledgement is its existing exact
custody contract; Auths cannot make an external service transactional with local
files. Disk corruption, absent hardware flush guarantees and compromised custody
remain unavailable/security boundaries, not recoverable success assumptions.

Every listed boundary requires termination immediately **before and after** the
operation, restart from retained state, repeated recovery, and an immediate
restart after acknowledged success. Run applicable native cases on file and TLS
PostgreSQL. Observations must include no forbidden provider entry, exact current
binding/floors, custody generations, journal obligations and command outcome.

| Boundary | Required restart observation and legal next action |
| --- | --- |
| Initial draft file content/sync/parent sync | No custody yet; exact draft retained or unavailable; resume must not create a new ID over retained input. |
| Each retained recipe/lock/context/attestation/root write and sync | Partial inputs are not serviceable; exact resume compares/writes missing inputs. Conflict/corruption quarantines. |
| Manifest rename/write and parent sync | Manifest alone is configured-unpublished. Native/custody inspection decides; no success inferred from presence. |
| Journal initialization/register replacement, file sync and parent sync | Custody mutation starts only after durable note acknowledgement; partial journal is unavailable. |
| Custody install/replace/confirm and lost reply | Exact note remains. Resume compares commitment; conflicting custody is never overwritten. |
| Candidate floor commit/acknowledgement | Reload floor; no generation rollback or fabricated candidate publication. |
| Proposal write/sync and parent sync | Same candidate is recoverable or exact restaging reproduces it; different existing output conflicts. |
| Candidate acquisition entry/result commits and lost replies | Existing native one-use/unknown rules; status/publish never re-enters reads. |
| Native connection publication CAS, commit and reply | Reload/replay exact publication. Successful acknowledgement survives restart; ambiguity never creates another entry permit. |
| Retirement interval start/expiry/reload | Restart begins a full interval; changed binding prevents deletion. |
| Each exact custody revoke and reply | Note retained until acknowledged exact deletion; lost reply remains incomplete and safe exact retry only. |
| Each journal note removal and synchronization | Confirmed removal stays removed after success; ambiguity reloads journal and retains conservative uncertainty. |
| Every qualification `.next` file/subdirectory/parent synchronization | Old accepted configuration remains or fails closed; staged incomplete input cannot advance floors. Re-import exact complete bundle. |
| Reserved unpublished temporary cleanup and directory synchronization | No accepted input is removed. Repeat the same complete import under the qualification lock; unsafe temporary metadata quarantines. |
| Native qualification floor commit/reply, then verifier-memory replacement/sync | Retain `.next`; reload/reconcile upward. Old bundle cannot qualify below either floor. |
| Remove old `.previous` and parent sync | Current must already be verified; interruption cannot trigger rollback. |
| Current-to-previous rename and parent sync | Missing current is unavailable; explicit recovery uses verified `.next`, never assumes previous is current. |
| Next-to-current rename and parent sync | Reverify current against both floors; unacknowledged publication is inspected, not guessed. |
| Previous removal and parent sync after publication | Current remains valid; leftover cleanup is explicit and repeatable. |
| Acknowledged install/publish/import/cleanup followed immediately by restart | Exact acknowledged state/floors/confirmed deletions remain; any pending independent cleanup remains separately visible. |

## 8. Design review and acceptance

This is the concrete amendment required by AP076 section 8.4. Its authority map
and ordering were checked against current install/private-file synchronization,
`CredentialJournal`, `GatewayEngine::collect_credentials`, native candidate
publication, qualification import and retained verifier memory at the PR #216
baseline. The safety argument uses existing native authority plus conservative
write-ahead obligations; it adds no assumption that an error proves non-effect.

Runtime acceptance still requires the full matrix above, source cutover and
schema/fixture/formal-link updates where affected, competing-operator tests and
fully successful hosted CI on the completed PR head. Design completion does not
claim runtime implementation or production qualification. The implementation
record must name concrete test owners for every row before merge. The concrete
boundary-to-owner map is maintained in the [AP076 implementation record](../plans/0076-implementation-status.md#concrete-evidence-owners), including process-termination,
native lost-acknowledgement and configured TLS PostgreSQL evidence as separate
claims.
