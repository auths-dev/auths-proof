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
