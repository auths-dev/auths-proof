# ADR 0017: One bound effect and gateway recovery owner

- Date: 28 October 2026
- Status: Implementation decision for AP-SPEC-074; evidence gates remain open

The gateway already owns production provider writes. AP070 separately decides
read admission, release and conservative accounting in Python/SQLite. The
lifecycle package has useful preparation and durable-acknowledgement contracts,
but its profile states include partial effects and proven non-effect with
different recovery semantics. None can be treated as interchangeable merely
because each has a journal.

Keep pure managed transitions in `auths-gateway-kernel::transition`, orchestration
in `auths-gateway::submit`, and the logical journal in `auths-gateway::store`.
Extend those owners; do not introduce a parallel executor or task ledger.
`auths-stores` implements durable PostgreSQL mechanisms. The existing file
adapter stays beside the gateway until moving it has a concrete dependency
benefit. Store adapters never decide provider truth or refund policy.

The gateway owns the canonical bound effect, built from the native sealed action
and closed recipe output. It includes selected branch/evidence identity, trust,
scope, installation, typed charges and protocol. Exact approval signs that
identity after compilation; the signature is not an input to its own identity.
The stored effect is data. Only a successful new durable entry transition yields
a non-cloneable, non-deserializable, consumed transport capability.

Retain lifecycle identity/commitment helpers only where their exact contract
matches. `PreparationBindingV1` is not reused as the effect: its optional
connection/evidence and single principal do not encode disclosure/source/channel,
selected native branches, exact compiler output or typed reservation units.
`ProviderCallAuthorizationV1::from_durable(&DurableTransitionV1)` illustrates
acknowledgement validation but a borrowed acknowledgement can be reused. AP074
must consume the newly applied acknowledgement exactly once. Do not change
reference consumers' lifecycle meaning to make these APIs fit.

The extraction is limited to identity preservation, finite typed reservation
arithmetic, single grant and immutable evidence. This is a domain-independent
product mechanism; the smaller-than-three-production-consumer exception is
justified by these exact properties, not inferred provider similarity. Provider
result interpretation remains in closed reviewed recipe declarations and
independent references. The [comparison case](../research/domains/abstraction-cases/0009-bound-effect-and-recovery.md)
defines divergences and the evidence still required before promotion is complete.

File and PostgreSQL admission must order configuration/revocation with entry.
Read-and-CAS of just the attempt does not fence a concurrently changed connection.
The transaction derives current state, samples the deployment clock after lock
acquisition, validates full native authority and pinned dependencies, and commits
the grant and charges before acknowledgement. A committed revocation blocks later
grants; an earlier grant may still be exercised. Process-local in-flight counters
alone do not establish the multi-process order.

Before the durable mutation cutover, this ADR must record the implemented file
lock and PostgreSQL transaction scopes, lock order, versioned dependency records,
configuration/revocation writer participation, after-lock clock sampling,
verification deadlines and durable acknowledgement. The P2 design below fixes
that mechanism; its source implementation alone does not satisfy final entry
until the shared configuration record and grant owner are connected. The present
attempt CAS and connection reload do not satisfy it.
Cross-store state requires demonstrated fencing; unsupported atomicity fails
closed. Capacity reserved earlier is checked for intact conservation at grant,
not allocated a second time.

The installed gateway boundary must exclude untrusted agents from provider
credentials, journal mutation, operator channels and alternate managed transport.
Keep an interface inventory and exercise it from a separate restricted process.
Rust sealed values do not establish process isolation, and independent provider
writers or a malicious trusted host/operator are outside this containment claim.

Native review must implement a versioned recipe-bound completeness contract.
Missing mandatory fields or an unsupported renderer prevents approval; signing
an effect digest alone does not establish complete presentation. Domain profiles
own the meanings and units of mandatory fields. Faithful presentation makes no
claim about human comprehension.

Recovery exposes bounded observation work, retained charges and escalation.
Administrative annotations are not provider evidence; no administrative path can
convert post-grant uncertainty into non-entry or silently release capacity.
Future delegated scope and ancestor charges feed this same admission authority,
under atomicity or demonstrated fencing, without a second task/effect journal.
This is an integration boundary only; AP073 remains outside the implementation.

Acquisition, disclosure and mutation are closed typed alternatives. Ancillary
credential/account/preflight/observation reads are linked bounded acquisitions.
Each disclosure has its own recipient authority, source binding and charge.
An ACK records recipient evidence and never creates another delivery grant.
State-match observation may coexist with unknown causation.

Cut over directly and reject obsolete disposable journal formats. No legacy
decoder, conversion, dual-write path or compatibility switch. Preserve rollback
floors and PostgreSQL transaction rollback; these are current safety semantics.
Retain reference implementations and original formal evidence only with accurate
scope. Acceptance requires A01–A22, updated source-linked proofs and hosted CI;
this ADR itself is not evidence that those gates passed.

## Installed mutation journal identity cutover

Attempt record `auths.gateway-attempt/4` retains the complete native canonical
binding and original canonical exact approval as immutable fixed fields. The
existing transition predicate compares those fixed bytes; a later observation
or outcome cannot substitute them. Historical approval validation uses the
recorded evaluation time and the approver pinned in that binding, not a new
approval supplied by a replay. This preserves evidence; it does not grant entry.

The only operation lookup key is the repository domain commitment
`auths.effect-replay-key/1` over canonical `(namespace, partition, epoch,
operation)`. It excludes the effect digest. An insertion collision loads and
validates the retained record and compares the complete binding: equality is
replay, inequality is `gateway.effect.operation-conflict`. Neither changes the
record or allocates another slot. Malformed state is unavailable, never replay
success or a free operation. There is no legacy lookup or decoder.

The runtime constructs the attempt owner from the same installed effect policy
as the engine and refuses a mismatch. Support listings filter the installed
partition/epoch within their bounded scan. Native count/sum counter keys remain
unchanged: changing an operation epoch must not reset a shared grant's capacity.
Old attempt tombstones remain durable. A higher epoch is an independently
installed namespace, not evidence of rollback protection or permission to retry
an old unknown operation. Store conformance source covers both adapters, but
its new binding/scope cases have not yet been executed on hosted CI.

This cutover does not replace `Attempting` with a durable entry grant, provide a
configuration fence, or finish independent recovery authority. Those remain the
explicit P2 requirements above.

## P2 adapter fence design

The gateway keeps lifecycle interpretation in its existing transition owner.
The adapter adds one mechanism: read a bounded set of records under the common
writer fence, invoke one bounded in-process decision, and durably replace the
first record before returning. The decision receives opaque snapshots, performs
no provider, custody or nested store I/O, and returns only the replacement bytes.
The adapter calls it at most once and never retries a failed/ambiguous commit.
The gateway alone interprets those bytes and may consume a newly acknowledged
`Reserved -> EntryGranted` transition to construct one non-cloneable permit.
Reading `EntryGranted` from disk cannot construct that permit.

File scope is the existing host-wide `.replace.lock`. Every insert, batch,
replacement, sweep and fenced decision uses it; fenced snapshots use lock-held
read helpers instead of acquiring the lock recursively. Acquisition uses
nonblocking flock attempts with a two-second deadline. The decision's work is
bounded by the native input limits and a two-second elapsed deadline; the store
checks the deadline before publication. Atomic replacement uses synced temporary
bytes, rename and directory sync. A failure after publication returns no permit;
the surviving grant prevents reminting after restart. OS scheduling and storage
sync are trusted platform operations, not preemptible hard real-time guarantees.

PostgreSQL scope is an advisory transaction lock keyed by the qualified gateway
record table's OID and a fixed gateway domain. All gateway insert, replacement
and expiry-sweep writers acquire it before row work; this includes connection
revocation and credential rotation. Row insertion retains sorted key order.
The fence uses READ COMMITTED: snapshots are loaded only after the advisory lock
is acquired, so a committed predecessor is visible. Local lock, statement and
idle-transaction timeouts bound database waits and preserve any tighter installed
pool timeout; values below SQL's millisecond precision are rejected rather than
silently disabling a deadline. The same two-second decision
limit applies before UPDATE and COMMIT. COMMIT must acknowledge durability before
the caller receives success. Pool failures, serialization errors, timeouts and
ambiguous commits return no permit. No transaction spans credential access or a
provider call. Shared-store throughput is deliberately serialized initially;
partitioned locks require later evidence for shared-budget and configuration
interactions, not an opportunistic optimization.

The final decision's bounded read set must contain the attempt, its connection,
the shared installed-configuration/revocation record and every reserved counter
slot. The native owner samples the deployment clock after obtaining those
snapshots, revalidates the original proof, exact approval and current policy,
checks pinned configuration/revocation and intact reservation membership, then
records the grant and audit event in the same attempt replacement. Reserved
slots become consumed by the grant stage, without allocating or charging them
twice. Unsupported split-store installations fail closed.

A new shared configuration record must pin recipe/compiler, trust context,
operator effect policy and qualification/revocation versions. Installation,
qualification refresh and operator configuration writers must participate in
the same fence; a host's cached configuration must match that record. Local
manifest comparison and process-local revocation caches are insufficient.
The primitive described here is only preparation: until the shared record,
writer participation and grant reducer are connected, the current engine does
not claim this final-entry guarantee.

## Shared installed configuration and permanent qualification memory

The sixth closed gateway record kind, `effect-configuration`, is non-expiring.
Its key commits to namespace, partition and epoch independently of the candidate
configuration. The installed pin commits to recipe, native verifier trust,
operator effect policy, connection identity, workload, profile, qualification
contract and gateway semantic closure. Bound-effect `/2` includes that pin;
compiler identity `/2` rejects approvals over the earlier binding format.
PostgreSQL schema `/7` directly replaces `/6`; no old-schema reader is retained.

Only trusted install/join initializes a missing record. Joining an existing
record must match its pin. Changing the pin requires explicit operator review
of both the candidate and a commitment to the entire previous record, followed
by activation under the writer fence. A concurrent publication invalidates that
review token. Application frames expose neither initialization nor activation.

Qualification import/reload publishes the authenticated bundle identity and
permanent revocation memory through that same fence before reporting success.
Accepted sequence/issue-time floors take maxima; signer and qualification
revocations take unions. The record bounds these sets to the native release
limits (64 signers and 1024 qualifications). Saturation persists a terminal
blocked marker; neither an empty local cache nor configuration activation can
reset it. Each record is canonical and bounded to 128 KiB. Revision saturation
also blocks authorization. This preserves bounded work without forgetting a
revocation and then authorizing from a truncated set.

A host adopts shared memory and must hold the published bundle identity before
ordinary qualification or separate commissioning-permit verification. Shared
memory itself grants neither. Publishing an unloaded bundle can disable other
hosts until their inputs are synchronized; this is a deliberate fail-closed
availability tradeoff. Earlier local verifier-state files remain rollback
witnesses, not an alternate shared admission authority.

Compilation and entry preparation now perform early checks. The final grant
must still repeat these checks over the configuration snapshot under its own
attempt fence. No final-entry guarantee is claimed by these early checks.

## Mutation grant source cutover

Attempt schema `/5` separates `Reserved` from `EntryGranted`. Admission creates
only a reservation. The existing kernel transition owner requires immutable
entry-audit bytes for every post-grant stage and forbids post-grant non-entry.
The existing submission step machine now has an explicit `GrantEntry` action;
only its successful acknowledgement can lead to `Send`.

`ClaimedGatewayAttempt::grant_entry` holds the common adapter fence while it
checks the exact attempt bytes, installed connection, shared configuration and
every reserved count/sum slot. Commissioning additionally reads its permanent
budget record and checks it against the acknowledged pre-custody floor. The
native validation samples the deployment clock after lock acquisition, freezes
one published qualification bundle plus monotonic memory, re-runs the original
proof and exact approval, and checks the connection/workload/profile and time
bounds. A concurrent process-local reload cannot replace that frozen evidence.
No provider, custody or nested store I/O runs in the decision. Deployment clock
sampling retains the clock implementation's explicit platform assumptions.

Reservation membership checks cover exact key, kind, operation, window, slot,
amount and capacity, including the one-to-one correspondence with native count
and sum obligations. The grant allocates no second slot. Its private immutable
audit includes the effect identity, grant time and domain-separated commitments
to dependency snapshots. The adapter must acknowledge durable publication before
one non-cloneable/non-deserializable permit is constructed. Every managed write
port, through the final HTTPS transport, consumes that permit and obtains its
request from the retained native command. Callers cannot supply substitute bytes.

After a grant, even a transport failure before a socket opens is unknown; it
cannot become `NotEntered`. A lost commit acknowledgement returns no permit.
Reading a granted record after restart projects unknown and never remints one.
The native corpus exercises one file-backed grant, stale-grant refusal and
crash-before-send projection; separate file/PostgreSQL race tests are authored.
This is not yet full P2 evidence. Reopening a reservation with fresh approval,
explicit journal revisions, installed after-lock expiry/revocation races,
ambiguous-commit fault injection and translated/refinement regeneration remain
open. Acquisition/disclosure and independent recovery are later cutovers.


## Reservation restart and immutable approval history

Attempt `/6` requires monotonic exact-JSON-integer revisions. Every update uses
both the complete predecessor bytes and one revision increment; saturation
refuses progress. An identical reserved operation may reopen with its existing
allocation. It does not acquire entry authority and cannot reopen a granted or
terminal operation. Full-binding differences still conflict.

A renewed exact approval does not rewrite the admission approval or first
pre-entry checkpoint. Grant audit `/2` separately freezes the actual approval,
fresh authorization start time, revision and fresh reads used at final entry.
The original proof is revalidated under the fence, using the new submission's
bounded deadline. The public snapshot uses the grant's pre-entry evidence after
entry. Stale handles lose the same atomic replacement; stored grants still
cannot recreate transport permits. Count/sum slots are checked and retained,
never charged a second time by resumption.

The synthetic native file corpus now covers restart beyond the first approval
and submission deadline, fresh approval, unchanged exhausted-capacity slots,
immutable initial evidence and refusal of a second grant. PostgreSQL parity
source is authored; installed authority, process faults and full recovery
remain separate evidence gates. A revision in the same store cannot detect
whole-store rollback.


## Recipe-owned review semantics

Source `/3` adds one mandatory versioned review declaration. Native validation
requires complete typed field coverage, bounded printable labels, explicit
integer units and operator-authored consequences. These are presentation facts,
not gateway-interpreted financial or provider semantics. The recipe digest and
effect compiler `/3` bind them to the exact effect. Compilation refuses a draft,
unknown version, duplicate/missing field, incompatible type or unsafe label.

Private review `/2` carries the declaration's values from the sealed command,
complete request, structured binding and actual connection identity/generation.
The native literal renderer escapes untrusted text as JSON data and refuses
unsupported versions or output limits. The CLI emits only that safe presentation
with its exact signing statement and writes the request file after output succeeds.
This is a local presentation guarantee, not proof of an authenticated external
reviewer or of human understanding; installed channel/UI evidence remains open.

OpenAPI derivation owns transport shape only. Its generated review declaration
has empty consequences/units and cannot compile until the operator completes
it. Test-only declarations support independent transport comparisons without
silently approving business meaning from untrusted descriptions. The full
Todoist vendor input currently fails the pinned digest; equivalent frozen native
excerpt outputs update the render artifacts while full vendor execution remains
explicitly pending. No source pin or verification rule was weakened.


## Public replay and unacknowledged grants

The mutation submission driver returns stored facts for equal bindings that
already have a grant or terminal result. Replay stops before a credential lease
and cannot invoke the operator observation path. An equal pre-grant reservation
may continue only through the separate fresh authorization and grant checks.

The native result represents that reservation explicitly with its bounded
revision. If admission or grant acknowledgement is unavailable, reload the exact
bound journal: reserved remains reserved; a retained grant without conclusive
response remains unknown; missing/corrupt/unavailable state is indeterminate.
These reads cannot return a permit or infer non-entry. Historical observation
returned on replay must not be counted as a new read-back confirmation.

The old explicit operator observation mechanics remain temporarily reachable
only on the operator surface. They are not the final AP074 recovery contract:
that direct path, automatic post-write observations and all ancillary reads must
be replaced by independently authorized bounded acquisitions before completion.


## Independently authorized recovery compilation

Bound-effect `/3` and compiler `/4` retain one shared identity and exact approval
owner, with sealed mutation/acquisition compiler alternatives. The source
journal supplies protected request/locator provenance; the new native read proof
supplies current authority. The read contract pins the exact GET, source binding,
observation projection, echo and finite bounds. Mutation recipes cannot use the
reserved read tool name, and mutation admission refuses a sealed acquisition.
Neither decoded source data nor compilation can mint a transport permit.

Source-lifetime reservations bind acquisition count and maximum response bytes
separately. Their keys include the immutable source effect and unit, excluding
the new read operation so new IDs cannot reset the declared capacity. The native
contract allows at most 16 attempts, at most 65,536 response bytes per attempt,
15 seconds per transport, and 30 seconds of evidence age. Entry accounting and
evidence freshness enforcement remain pending; a declaration is not evidence
that those boundaries have been executed.

The first compiler requires the same source connection commitment and credential
generation. Rotation or a narrower replacement credential currently refuses
compilation; safe replacement recovery still needs its own reviewed contract.
Managed bounded-policy extensions also fail closed until acquisition accounting
can enforce them. These are incomplete implementation boundaries, not permission
to drop the full acquisition/recovery requirements of AP074.

The installed operator can author the private native read call and compile it
for review using the same deployment clock, current configuration, and connection
checks as mutation compilation. The literal renderer and signing-request path
remain shared. No new provider endpoint or read execution is introduced by this
checkpoint; direct operator re-observation and ancillary reads still require
the acquisition admission/entry cutover before completion.


## Recovery acquisition journal and entry

The next cutover uses attempt journal `/7`: a common immutable header and entry
history with a closed typed mutation/acquisition payload. It uses the same
transition predicate, record codec and durable transaction ports. Acquisition
responses cannot become mutation observations through a protocol or stage tag.
Support bundle `/2` distinguishes the protocol in both counts and retained stages.

One atomic admission stores the read claim and a permanent allocation holding
one invocation and the maximum response bytes. The allocation binds distinct
count and byte keys to the source effect; new read IDs share its fixed 16 slots.
The existing file batch and PostgreSQL transaction implement this insert.
PostgreSQL source schema `/8` adds the non-expiring allocation kind directly;
there is no migration/legacy reader. Sweeping does not refund allocations.

The final read grant uses the existing writer fence over the read attempt,
source attempt, allocation and current installed dependencies. It rechecks the
exact source-derived target and fresh read authority. A durable acknowledgement
returns a one-use permit that the bounded transport consumes; a persisted grant
alone returns unknown history. Response bytes stay in the private journal and
do not themselves refine the mutation or authorize content disclosure.

The runtime path refuses recipes requiring additional credential reads until
those have their own accounted acquisition paths. Source-evidence freshness,
credential replacement, managed bounds, public execution routes and removal of
existing raw observation/ancillary paths remain required work. The native file
corpus uses synthetic entry validation and response bytes; it is narrow durable
mechanism evidence, not an installed authority or transport claim.


## Retained recovery evidence and operator cutover

Journal `/8` adds immutable acquisition provenance to source observation facts.
The existing adapter fence checks source/read/allocation and samples the deployed
clock before the same transition predicate can advance the mutation. Read
receipt time is preserved. Newly recorded evidence must have age 0–30 seconds;
exact already-recorded history does not expire or refresh. Unknown sends require
supported provider linkage; state equality alone does not establish execution.
Duplicate object members are refused by the bounded native observation decoder.

The production operator `reobserve` path is removed. Admin request/response `/2`
uses `recover` with a separately signed native read and exact approval, or
`recovery-record` with already retained read evidence and no external I/O.
Application and operator input frames share a bounded native decoder. Redacted
recovery report `/1` separates read facts, source facts and evidence disposition
without private content, locators or commitments. The old observation mechanics
remain only as an explicit store-conformance test oracle. The shipping submission
step machine has no read-back/resume mode: recording a response stops it, and
observation requires the independent recovery acquisition. Ancillary/application
reads remain the next production cutovers. The native corpus is file-journal mechanism evidence
with synthetic entry/response/clock inputs, not installed transport qualification.


## Prerequisite acquisition compilation

Compiler `/5` retains each mutation prerequisite as a closed compiler request
and a typed purpose. The ordered plan is part of the mutation transport
commitment and appears in native private approval review. Account reads pin the
installed account commitment and comparison domain; denied reads pin their
ordinal and refused statuses; relative-ceiling reads resolve the verified
argument and bind values; pre-entry reads pin their pointers and complete
selected native authority. There is no deserializer or application constructor
for this compiler output.

The maximum plan is seven reads, each allowed once with its exact response bound,
a 15-second transport deadline, a 30-second evidence-age ceiling and no release
of content. Existing proof freshness conditions can be stricter. Onboarding
probes are outside this mutation plan. The same exact-approval and native
recompilation machinery binds these declarations; no separate token format or
approval owner is introduced.

This checkpoint does not implement prerequisite admission or grants. The
existing raw prerequisite calls still require direct cutover to journaled,
charged acquisition entries and one-use permits. The parent approval is evidence
for only its enumerated recipe-derived reads; it is not general read authority
or authority to repeat an uncertain read. The native fixture establishes signed
compilation/review only, not entry eligibility, accounting, transport or the
installed human channel.


## Durable prerequisite acquisitions

Journal `/9` stores a closed acquisition-plan alternative: independently
approved recovery, or one enumerated prerequisite of the exact approved
mutation. Both use the existing acquisition states, transition predicate,
permanent allocation slots, fenced grant and response persistence. There is no
new approval envelope, task ledger or retry decision owner. Old journal records
are refused directly; the PostgreSQL storage schema remains `/8` because its
existing record kinds and transaction contract suffice.

A prerequisite record retains the parent binding and exact approval plus its
ordinal and a bounded canonical transport membership witness. Decoding checks
the witness against the parent transport commitment and checks the declaration's
one-call, response-byte, transport, freshness and no-disclosure limits. Audit
witnesses never construct transport requests. The permit carries the original
sealed compiler read. The component replay key derives from the parent's logical
operation key and ordinal, not its effect digest; a changed binding cannot
create another component under the same operation. Its permanent allocation
charges one invocation and the full response ceiling, including unknown entry.

The acquisition grant fence includes its record, the reserved parent, its
allocation and current native entry dependencies. A parent that already entered
or became not-entered cannot issue a prerequisite permit. Only acknowledged
publication returns a permit. Concurrent stale handles, replay and reopened
entry grants cannot issue another. Recorded responses retain their receipt
time; pre-entry evidence uses the earlier grant time conservatively. Loading
history does not refresh either timestamp.

Submission's account, denied-capability, pre-entry and relative-ceiling reads now
consume these permits. It evaluates a response only after durable recording. The
final mutation fence includes every required child record and allocation and
refuses missing, uncertain or stale responses. Seven prerequisites add at most
14 dependencies; together with 34 mutation slots, the parent and three installed
dependencies this uses at most 52 of the existing 64-record fence limit.

This source cutover does not close installed evidence: tighter native observer
freshness at the final lock boundary, complete selected-evidence provenance,
ordered initial admission, all application/onboarding reads and disclosure still
need completion. The file fixture uses native compilation but explicit-time
oracle grants and synthetic responses; it is not provider transport, installed
native entry or PostgreSQL qualification.


## Final prerequisite evidence validation

The installed mutation fence now reuses the existing account, denied-capability,
relative-ceiling and selected-observation predicates on the exact retained child
responses. The acquisition validator returns typed, bounded evidence only after
checking its parent binding, plan, allocation, recorded grant and original times.
The installed entry validator runs these predicates after full native authority
validation and before publishing the mutation grant, at the same sampled time.

For pre-entry observations, the existing canonical signature verifier checks the
pinned observer. Every signed subject, fact set and observation time must match
the exact acquired response projection and its conservative grant time. The
selected requirements are resolved again from the approved native command and
current pinned trust, then evaluated with their own maximum ages and anchor
validity. The 30-second acquisition ceiling cannot override a tighter native
requirement. No observer signing, custody or provider I/O occurs under the fence.
The existing four-observation limit and bounded canonical decoder bound this
additional signature work. The selected gateway observer identity is now included in the installed
configuration commitment as well as checked against native observer trust.

Relative-ceiling checkpoints must match the retained response's basis, digest
and original grant time, and still satisfy the original ratio and bound values.
Extra observation or basis checkpoint data is refused when the compiled plan
has no corresponding prerequisite. Account, ceiling and pre-entry JSON now use
the same bounded duplicate-rejecting response decoder as recovery observations.

The native predicate fixtures cover canonical signature substitution, subject,
observer, fact and timestamp mismatch, tighter age boundaries, missing/extra
observations, account mismatch, capability excess, bound currency/ratio changes,
checkpoint substitution and duplicate JSON. They use signed native effects and
synthetic provider bodies, not an installed transaction or transport. Independent
process lock-wait histories and both adapter fault/race suites remain required.

## Ordered initial admission design

Initial effect admission uses an extension of the existing insert-once batch
mechanism. Under the same file lock or PostgreSQL advisory transaction lock,
the adapter checks the proposed keys for conflicts, reads a bounded dependency
set, invokes one native decision and publishes the claim and all capacity rows
atomically. The decision may replace only the first record's opaque bytes;
keys, kinds, expiries and remaining capacity rows stay fixed. Existing keys
return their original conflict index without invoking the admission decision.
The combined insertion/dependency set retains the existing 64-record limit,
and the same two-second fenced decision deadline applies. No nested store,
credential or provider I/O is permitted in the decision.

The native decision reuses final-entry authority/configuration validation,
sampling time after the writer fence is held. A new record's `evaluated_at` is
that admission time, not the earlier candidate compilation time. All current
approval, native proof, configuration, connection and qualification constraints
must hold before a charge is published. Subsequent entry remains a separate
fresh check and one-use permit. Equal replay returns immutable history and does
not rerun admission or charge again.

Counter frontiers remain bounded candidate selection outside the fence. The
insert transaction confirms target vacancy; immutable sum predecessors are
included in the dependency snapshot and their validated cumulative amounts must
match the proposed charge. Full native recompilation rejects a changed window
before publication, so expired-slot collection cannot authorize an old-window
admission. Exhausted claims are also recorded only after the same ordered
checks. Acquisition admission additionally fences the eligible source record.


Mutation admission has at most one claim, 34 capacity rows, 17 sum predecessors
and three native dependencies: 55 records within the existing 64-record bound.
The later entry boundary retains its independent 52-record maximum. Retained
history is checked before constructing a new candidate so an expired current
approval cannot hide an existing reservation; that handle still requires fresh
entry validation. Runtime grant timestamps are sampled after admission rather
than reused from the earlier candidate evaluation.

`effect-admission.json` constructs real file-store ordering and atomicity
histories with an explicit-time approval oracle. It does not establish installed
native revocation, PostgreSQL execution or process fault qualification. The same
adapter conformance source is available for the hosted PostgreSQL fixture.


## Application recovery cutover

The application observation socket must not turn caller-supplied recipe path
arguments into unapproved credential-bearing reads. Remove its `read-back`
request and CLI/SDK convenience methods directly. `observe` retains only local
outcome and pre-entry history projections. A new closed application recovery
frame supplies the source operation and the existing bounded native
proof/action/exact-approval envelope; it calls the same engine recovery method
as the operator interface and returns only the native redacted recovery report
or native refusal. It cannot supply a URL, request body, credential or time.
No provider body or newly signed provider value is disclosed by this route.

The old observation evaluator remains a test-only reference, reachable only
through direct tests and the private synthetic harness control plane. It is
removed from the shared application protocol even in harness builds. General
acquisition/disclosure and the installed approval journey remain separate
unfinished requirements; this cutover must not present a report as disclosure
or a provider response as a successful mutation.

## Managed recovery read budgets

Recovery compilation consumes the same selected native bounded branch and the
same tightening, count and sum arithmetic as mutation compilation. Its numeric
policy argument is exactly `maximum_response_bytes`; a sum reserves that full
response ceiling, including lost responses. The mutation recipe's spend-sum
requirement does not apply to the separate recovery action. Read-policy count
and byte counters use distinct domain-separated identities from mutation
count/amount counters, retaining namespace, subject, evaluator, partition and
fixed-window components. Epochs and operation IDs do not reset these budgets.

The existing slot candidate, slot encoding, sum-predecessor check and reservation
membership logic is shared inside the gateway store. Admission inserts one
acquisition journal record, its permanent source allocation and every managed
slot atomically. A collision advances only its candidate; no partial insert or
refund is possible. Final entry validates every slot with fresh native authority
inside the same fence. Prerequisite reads retain their parent's declared
allowance and do not charge the parent's managed policy again.

At most sixteen bounded links produce 32 managed reservations plus two source
reservations, preserving the 34-reservation limit. Admission requires at most
34 inserted records, 16 predecessors, one source and three native dependencies
(54 total); entry requires at most 38 records. Both fit the existing 64-record
fence. Journal `/10` rejects the superseded acquisition layout. Compiler `/6`
binds the read's managed reservation set. Independent acquisition/disclosure,
credential replacement and installed race/fault evidence remain separate work.

## Recovery credential prerequisites

An independently authorized recovery read uses the same installed account and
capability checks as mutation. Its native request commitment and human review
include an ordered account/denied-capability acquisition plan derived from the
pinned recipe and connection. The installation-only probe remains a separate
onboarding obligation. The recovery action's source and recipe commitments fix
which declarations are eligible; approval binds their complete resolved bytes.

Use the existing prerequisite records, one-call/full-byte allocations, component
keys, shared reducer and consumed transport permits. A child may name a reserved
mutation or a reserved independent recovery acquisition; it cannot name another
child. The parent must remain reserved at child entry. Recovery's final entry
fences all required child records/allocations, freshness and actual account or
capability results, together with its managed policy slots and original source.
A failed or lost child never authorizes replayed I/O. Ancillary reads consume
only their explicit child allowance; the parent managed read policy is not
charged for every component.

Compiler `/7` binds the complete read transport witness. Journal `/11` rejects
old recovery plans and authenticates child membership against either closed
parent protocol. Recovery has at most five prerequisites, for at most 48 final
entry records including 32 managed slots and three native dependencies. The
existing seven-prerequisite and 64-record bounds remain unchanged. No operator
attestation is silently promoted into native effect authority: first-install
and candidate-rotation authorization remain separate unfinished cutovers.

## Candidate credential check compilation

Candidate checks are a distinct acquisition target. They do not borrow the
current writer's proof or turn an operator attestation into native authority.
The target pins the candidate connection descriptor, expected previous record
(or absence on first install), and exact recipe-declared checks. The native
reserved tool `auths_gateway_candidate_check_v1` requires its own proof and exact
human approval. Compilation performs no custody or provider I/O.

The ordered provider sequence remains probe, account, denied-capability reads.
The final declared read is the main acquisition; preceding reads are the same
bounded prerequisite declarations used elsewhere. This keeps every child before
parent entry without inventing an aggregate provider response. Each purpose
retains its concrete predicate, and a complete main response will still need
its purpose evaluated before credential publication. Recipes with no network
checks remain an offline operator path; compilation cannot invent a read.

Lifetime capacity is keyed by candidate credential identity (connection ID,
credential generation and reference commitment), not operation ID or timestamps.
The maximum is sixteen explicitly approved attempts, each with one main-response
ceiling and declared one-call child allowances. Current native count/byte policies
also apply. This checkpoint adds compilation and review only. Candidate staging,
fresh absent/current-record fencing, shared journal admission, actual checks and
publication are required before production onboarding can use this target.


## Candidate acquisition admission and execution

Candidate checks now use a typed plan in the existing acquisition journal.
Their source dependency is the exact expected connection row, including a
fenced absence for first install. The same native entry checker handles a
published connection or a sealed candidate; candidate reads may preserve a
disabled predecessor, but require the pinned workload/profile and refuse
revocation or any predecessor change. Child entry checks both its reserved
parent and the candidate's current connection dependency. Final primary entry
also checks all retained child predicates and freshness.

The source and native connection dependency can name the same physical row.
The fence reads it once and maps that snapshot to both checks. This is index
bookkeeping, not a second validation authority. Entry audit `/3` records a
checked absence as null, distinct from a present record's commitment. Journal
`/12` rejects the superseded encoding. No missing dependency is implicitly
accepted; the typed candidate predicate alone admits first-install absence.

Lifetime allocations are append-only and retain a fixed byte ceiling for one
credential identity. A competing proposal with that identity cannot change the
ceiling after an allocation exists. The shared read runtime executes ordered
prerequisites, evaluates retained native evidence, consumes one primary permit
and records response/unknown. Mutation prerequisites, recovery and candidates
use the same helper. `acquire_candidate_credential` leases only the exact already
staged candidate and returns redacted acquisition facts. It does not publish the
credential. CLI staging, final-purpose validation, safely fenced publication and
removal of the old onboarding/rotation read routes remain required.


## Candidate credential publication

Publication uses the existing insert/replace writer fence over the connection,
root and child acquisition records/allocations and native dependencies. It is an
explicit trusted operator action, with no application route and no new lifecycle
state. The primary response now receives its actual recipe purpose check, just
like each retained child. All timestamps remain original; publication cannot
renew evidence or spend capacity again. Missing/unknown, bad and stale evidence,
changed configuration and changed predecessor refuse the write.

The runtime verifies exact staged custody, invokes this fence and reloads the
published connection through the generation-floor owner before scheduling
superseded credential retirement. Independent custody availability is not part
of the store's atomicity guarantee. Every later lease still checks the exact
credential binding. `AlreadyCurrent` is an exact-state observation for an
explicit retry, including lost acknowledgement; it makes no causal claim and
issues no capability. Staging/CLI cutover and installed custody/transport fault
coverage remain separate required work.


## Private candidate proposal persistence

`auths.gateway-credential-candidate/1` stores exact canonical candidate and
predecessor connection bytes plus the pinned recipe digest. The bounded native
decoder reconstructs only proposal data and derives the closed check plan from
the installed recipe. It validates the first-install or rotation relationship
and rejects noncanonical/duplicate/unknown/obsolete data. No persisted proof of
current custody, predecessor, authority or completed checks is implied. This
format prepares the operator CLI to retain a stable target across approval and
restart without adding a second execution path or serializable capability.


## Candidate staging and operator CLI

Rotation staging now records cleanup obligations before a non-overwriting
custody replace, preserving the current connection and secret. The exact native
proposal feeds call authoring, `effect-review --candidate`, acquisition under
runtime read identity and publication under operator identity. Read-bearing
recipes refuse the old unapproved rotation/commit routes; no-read recipes retain
an explicit offline operator flow. Joining an already-published secret uses
exact reference confirmation and does not acquire new provider evidence.

Independent CLI processes exposed a local file-custody lifetime problem:
previous handles retained snapshots that could overwrite a later successor.
The existing persistent custody owner now uses a stable sidecar lock, reloads
bounded canonical state under it, and fails immediately on lock contention.
Atomic database rename remains the persistence boundary. Readers refresh before
selecting the exact credential; a completed deletion cannot be hidden by a stale
process cache. This is a store mechanism, with no change to credential identity,
read authorization or publication policy. Staged/CLI fixtures cover real file
custody, independent competing processes, held-lock refusal and stale handles;
they do not establish AWS, PostgreSQL or full process-crash qualification.


### First-install staging and floor binding

A read-bearing first install now stores a private canonical connection draft
before its manifest or custody mutation. The draft fixes the connection identity,
account, descriptor and timestamps, and carries no read or publication authority.
The existing candidate runtime derives the credential reference with the native
custody commitment, initializes/registers cleanup notes, stores only an absent
exact generation and binds the host floor to that unpublished generation-one
record. The shared connection remains absent until fenced candidate publication.
An exact custody `holds` result supports explicit retry from the same retained
draft after an ambiguous write acknowledgement; another secret cannot replace it.

`install` saves `candidate-installation.json`; `candidate-stage-installation`
resumes from `candidate-installation.cbor` into a new private output file. Only
this explicit operator action may initialize the installation's configuration,
cleanup journal or floor. Candidate compilation, acquisition and publication
check an existing floor, and ordinary entry still requires a live connection.
There is no cross-store atomicity claim: a floor or output failure may leave
custody with a retained cleanup obligation and no published connection.

Production raw onboarding exports are removed. The previous checker remains a
test-only reference; the pure probe predicate remains shared by managed entry.
The offline install helper refuses recipes with reads before custody, while
join records cleanup notes before confirming an exact already-published secret.
The loopback option moves from unapproved install to approved candidate acquisition
and is limited to development installations in feature-enabled builds.

Native staging artifacts exercise absent connection, exact restart, conflicting
secret, bad prefix, corrupt cleanup notes, substituted floor and runtime refusal
to repair a missing floor. The production CLI artifact exercises actual install
and a separate resume process. Full approved provider journeys, process faults
and PostgreSQL evidence remain separate unfinished requirements.


## Recipient acknowledgement ownership

`effect::disclosure` constructs and verifies the bounded native
`auths.gateway-disclosure-ack/1` statement. Recipient identity is the existing
raw-key principal derived from the statement's nonweak Ed25519 public key and
must equal the immutable disclosure binding. The exact protected-content length
comes from authoritative retained data, not the ACK. Successful verification
returns a sealed historical assertion, never a transport capability. It accepts
no clock/current-authority input, permitting late evidence after expiry or
revocation. This cannot authorize a new delivery.

`auths-gateway-kernel::transition::valid_transition` remains the sole transition
owner. Disclosure shares the fixed identity/allocation/revision/grant contract
and adds a separate immutable acknowledgement field and terminal stage. It
cannot acquire provider responses, pre-entry observations, locators or mutation
facts. Provider journal projections supply an empty acknowledgement field.
`exact_acknowledgement_replay` is a read-only equality predicate on consistent
terminal disclosure history, not a second state transition rule. Persistence
must still fence the original record; duplicate ACKs must return retained bytes
and revision without rewriting or recharging.

This checkpoint implements the evidence contract and pure relation. The
protected-content owner, disclosure admission/entry, recipient transport and
runtime journal projection remain required before this is a managed release
path. Kani oracle source includes disclosure; source-linked Lean regeneration
and refinement are still open P4 obligations, with no new proof claim.


## Explicit content recipe compilation

General content reads are an explicit digest-bound recipe capability rather
than reinterpreted credential checks or mutation observations. The versioned
`content` declaration is optional within the existing source envelope; absent
recipes retain their original canonical bytes/digest and cannot compile content
reads. The declaration has its own closed schema and complete operator review.
`recipe::content` validates resource fields, fixed query pairs and bounded
UTF-8/JSON-string projection. It reuses the existing path/header lowering,
percent encoder and duplicate-rejecting provider parser. No provider-name branch
or new runtime callback is introduced.

`effect::content` participates in the same native acquisition compilation,
review, exact approval and fresh recompile owner. Its native read call binds the
explicit resource/account arguments and full private contract. A sixteen-entry
source allowance excludes logical operation IDs and administrative metadata;
it includes recipe, connection ID, credential generation/reference and exact
resource/account arguments. The full connection record still binds approval,
so administrative changes demand recompilation without silently refreshing that
allowance. Fixed-window native managed bounds are additionally retained.

Content projection returns private bytes and typed response errors, not a
receipt or release grant. Runtime must authenticate/retain HTTP metadata and
content under the journal contract and issue a distinct disclosure capability.
The initial compiler slice supplied no admission/entry; the following section
records that integration. Read-only installation, AP070 metadata predicates,
recipient transport and protected projected-content custody remain required
before migrating the maintained demo.


## Content acquisition journal and transport

The content plan is a concrete variant of the existing acquisition journal.
Its current source is the exact connection row, checked under the same fence as
native authority, configuration, qualification, all source/policy allocations
and credential prerequisites. The plan validates its reconstruction data against
the full signed request/projection commitments; decoding it grants no authority.
The engine uses the common acquisition driver. A content permit can enter only
the metadata-preserving content GET path and is consumed once.

Content responses have a distinct private journal variant mapped to the existing
kernel acquisition response stage. They retain bounded raw bytes and typed
media/encoding facts, without upgrading them to usable content or a disclosure.
Missing, duplicate, oversized and non-text header values cannot become a valid
single header. Transport requests identity encoding and explicitly disables
automatic decompression. Query support is confined to the compiler-owned content
request; other transports retain their previous URL restriction. No new retry,
transition owner, decoder compatibility path or generic request callback is added.

The `content-journal.json` corpus exercises installed native entry against the
file adapter, actual loopback HTTP, durable source exhaustion and reopened
journal replay. Protected projected-content construction, separate disclosure,
full engine/CLI process journeys, PostgreSQL faults and AP070 differential
cutover remain required; this evidence grants no provider qualification.


## Protected content in the response transaction

Attempt `/13` extends the existing content response fact with one closed
protected/refused result. Projection and key generation happen before the same
response acknowledgement; a crash cannot leave a published content identifier
without its retained response, or re-create a provider permit. Loading recomputes
projection/refusal from the bound contract and retained transport facts. No
separate content lifecycle, external write, schema migration or retry rule is
introduced. Ready projected bytes are reconstructed only inside the native owner.

The receipt disclosure protector is a storage port, and MCP execution references
are bound to another protocol; neither supplies the required content commitment.
The gateway therefore uses the already-pinned workspace `hmac` primitive with
SHA-256 and the existing native canonical/domain codec. A fresh private 32-byte
key scopes each commitment to one source effect, projection, exact length and
private content digest. The key is stored under the same private-journal policy,
not returned in public snapshots. The snapshot exposes only readiness/length or
a stable refusal. This is hiding against public offline guesses while the key is
private; it is not journal encryption or protection against malicious journal
administration. No new cryptographic algorithm or general protection framework
is extracted.

`content-journal.json` now includes fifteen HTTP cases, empty/exact/over-limit
content, bad UTF-8/version/encoding/media, original-byte replay, altered protected
fields and substitution from another valid acquisition with identical content.
The same pure projection leaf serves compiler-only and durable response paths.
Disclosure still needs separate native authority, approval, accounting, recipient
channel authentication and the shared final-entry fence.

## Sealed source and separately authorized disclosure compilation

`GatewayAttempts::retained_content` reconstructs only private provenance after
normal journal decoding, response projection and constant-time MAC validation.
No public plaintext accessor, provider read or delivery authority is exposed.
`DisclosureTarget` fixes recipient raw-key identity, channel and instance over
that source. Fresh native authorization uses a reserved release tool; exact
approval and entry-time re-verification use the existing bound-effect owner.
The old source proof is history, never a release permission.

Count and byte units are explicitly disjoint from acquisition and mutation.
Sixteen source-lifetime deliveries share capacity regardless of changed operation
ID, recipient or channel. Empty content remains an actual zero-byte delivery
with one count. Managed policy bounds use the same arithmetic leaf with closed
protocol domains; no provider semantic dispatch or new lifecycle is introduced.
This source/compilation slice does not create a transport or journal grant.
The shared store must next fence retained source facts, current release authority,
recipient authentication and these reservations at the unique delivery grant.

The content journal fixture constructs both empty and nonempty sources using
real local HTTP, then exercises native release compilation, review, fresh exact
approval, full recompile, managed count/byte declarations, ACK binding and changed
recipient/channel/instance/partition/operation refusals. It establishes no actual
delivery, persistent ACK, isolated-agent or PostgreSQL claim.

### Shared source allocation leaf

`effect/capacity.rs` now owns the fixed source count/byte declaration arithmetic,
with the protocol supplying its typed units. `store/capacity.rs` owns the existing
canonical append-only allocation record, key and occupied-slot validation. The
acquisition protocol continues to derive source eligibility, source identities,
limits and transitions; disclosure supplies its distinct units and source keys.
No schema, journal authority, admission decision or refund rule changes. The
empty-disclosure ceiling convention does not alter nonempty acquisition bytes.
This extracts the identical bounded record mechanism rather than copying the
acquisition allocator into a second disclosure ledger.

## Disclosure admission and historical ACK journal

Attempt `/14` adds the closed disclosure state to the existing `JournalProtocol`
projection. The existing kernel reducer remains the sole transition decision;
file/PostgreSQL adapters retain their existing fenced insert/replace/CAS contract.
The plan is data only and validates source scope, installation, projection, exact
length, recipient key and typed reservations against the bound effect. Admission
loads and validates the retained acquisition under the same writer fence as native
configuration/authority. It atomically inserts one permanent source allocation
and the existing count/sum policy slots. No disclosure ledger, callback, provider
request or second capacity authority is introduced. Obsolete `/13` is rejected.

The protocol's immutable ACK field is verified on every decode. Historical ACK
recording needs an existing grant and the common reducer, not fresh execution
authority. A concurrent identical ACK can be recognized after one bounded reload;
revision and charges remain unchanged. Public snapshots and support listings keep
provider/acquisition/recipient facts distinct and contain no private correlations.
Engine proposal/compile/admit operations have no delivery capability or custody.
The final recipient-authenticated grant and one-use transport remain unwired.

`disclosure-journal.json` constructs real HTTP source content then executes native
installed file admission, duplicate claim concurrency, changed source/connection/
approval refusal, policy/source exhaustion and reopened replay. Corrupt plan fields,
cross-protocol records and obsolete schemas refuse. ACK cases use explicitly
synthetic retained grants, exercise the real durable CAS/decoder/reducer, and assert
pre-grant/foreign refusal, concurrent exact replay and late evidence after disabling
the connection. They do not establish recipient authentication, actual send,
independent-process isolation or PostgreSQL qualification.
