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
