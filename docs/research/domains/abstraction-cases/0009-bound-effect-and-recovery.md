# Case 0009: Bound effect identity and durable recovery

Status: AP074 implementation contract; behavioral and performance evidence pending.
Owner: product gateway/kernel, per [ADR 0017](../../../adr/0017-bound-effect-and-recovery-ownership.md).

## Baseline consumers and dispositions

| Surface | Current semantics | Disposition |
| --- | --- | --- |
| Native `VerifiedAction` | Canonical action, proof/context/plan, selected branches and evidence | Retain sole native authority source |
| Gateway `verify_detailed` / `VerifiedCommand` | Native projection, bounds, compiler output | Consolidate immutable effect here |
| `recipe.rs` / kernel `construct` | Closed deterministic bytes, credential slot, observation plan | Retain compiler; bind entire output |
| `submit.rs` / kernel `order` | Write ordering, credential/preflight reads, replay observation | Extend current driver; make all external entries explicit |
| Gateway store / kernel `transition` | Claim and counters atomic; `Attempting` conflates reservation and entry | Replace conflation with explicit durable grant |
| Kernel `recovery` / `outcome` | Response/state match/provider link are distinct; no lost-claim retry | Retain truth and no-retry semantics |
| File attempt adapter | Private files, flock, fsync/rename, batch rollback, CAS | Retain durability; add bounded transactional validation/fencing |
| PostgreSQL gateway records | Atomic batch, byte CAS, commit acknowledgement | Retain mechanism; extend shared transaction boundary |
| Lifecycle `operation` / `sealed` | Preparation commitments, validated store ACK, profile-specific lifecycle | Reference semantics; no second managed gateway owner |
| AP070 `AdmissionStore` / `ProviderAttemptLedger` | SQLite task counters, challenge/release decisions, per-GET records | Remove shared decisions in native cutover |
| AP070 `execute_read` / `ReceiptStore` | Provider-specific fetch, release orchestration, Python receipt claims | Thin consumer of native stages and projections |
| TS `gateway.ts`, Python native runtime, gateway app/admin | Socket/binding routes and views | Expose native construction and state; no local effect hashes |
| AP070 Drive adapter | Metadata/content GETs and provenance checks | Retain independent provider reference; managed I/O uses closed recipe |
| Gateway observer / audit / harness / commissioning | Signed observations, audit facts, local fixtures, bounded operator authority | Update identities and stages atomically; do not bypass commissioning bounds |

## Comparison and extraction classification

| Dimension | Stripe refund | Airtable update | AP070 read/disclosure | Lifecycle reference |
| --- | --- | --- | --- | --- |
| Exact action | Verified MCP refund fields | Verified MCP record fields | Verified API read scope | Concrete profile command |
| Request | POST form, derived idempotency | PATCH JSON, no idempotency | Metadata/content GET then recipient bytes | Domain-defined |
| Recovery locator | Response-derived refund ID | Verified record ID | Source effect + protected content + recipient channel | Domain-defined |
| Unknown write recovery | No locator without response | Exact echo at verified locator may add evidence | No automatic refetch/redelivery | May support concrete non-effect proof |
| Approval | Exact compiled mutation | Exact compiled mutation | Bounded upfront consent then exact release binding | Profile-specific |
| Accounting | Count and currency-partitioned sum | Count | Calls, provider attempts/response bytes, disclosure bytes | Reservations/obligations |
| Outcome | HTTP response is not refund proof | Matching state is not causation | Acquisition is not delivery; ACK is recipient fact | Proven partial/applied/not-applied |
| Shared subset | Immutable identity, atomic claim, single grant, immutable evidence | Same | Same | ACK validation pattern only |

This is an identical-mechanism extraction only for the last row. Provider
semantics and concrete approvals are divergent. No provider tag, callback or
untyped map selects a transition. Smaller primitives alone cannot atomically
couple replay identity, admission capacity and grant publication; the reducer
and journal transaction therefore share one explicit contract.

The retained oracles are Stripe's reference integration, the Airtable recipe
fixtures and independently expressed AP070 read/release scenarios. Differential
tests must compare observable commands, refusals, charges and evidence, not just
two calls to the new implementation. Source paths include
`examples/stripe-refund-approval/recipe.json`, `demos/airtable-gateway/recipe.json`
and `demos/google-employee-delegation/broker/`.

## Encoding, limits and state contract

Canonical effect encoding is native-owned and versioned; duplicate/unknown
fields, noncanonical encodings and unsupported versions fail closed. Private
effect identity is domain separated from public receipt identity. Exact approval
excludes its signature from the value signed. Replay key is namespace, epoch,
logical operation; effect identity is compared after lookup, never used to evade
that lookup. Optional task-free scope has an explicit tag distinct from task scope.

| Surface | Existing bound retained / AP074 bound to enforce |
| --- | --- |
| Proof / action | Gateway 4 MiB / 64 KiB; native configured bounds also apply |
| Trusted context | Native configured bound; hard maximum 16 MiB, default 2 MiB |
| Effect canonical metadata including compiled output | 65,536 bytes; reject before decoding |
| Namespace / logical operation | Existing canonical ASCII 64 / 128 bytes |
| Resource / recipient / channel / scope label | One per operation, each at most 512 UTF-8 bytes |
| Compiler write body | Existing 16,384 bytes |
| Recipe source / lock | Existing 65,536 bytes each |
| Path / template | Existing 16 segments, 64 nodes, depth 6; bounded final URL 8,192 bytes |
| Headers | Existing recipe maximum two provider headers; total compiled headers at most 8, names 64 and values 1,024 bytes |
| Selected branches/evidence | Native configured collection bounds; total effect encoding bound also applies |
| Reservations | Existing maximum 34 counters; typed units and exact window |
| Provider response / private retained bytes | 65,536 bytes per operation; content not retained by default |
| Pre-entry observations | Existing 4, each native maximum 4,096 bytes |
| Journal record / atomic batch | Existing 262,144 bytes / 64 entries |
| Events / ACK | 64 events per operation / 4,096 canonical bytes per ACK |
| Exact human approval | 4,096 canonical bytes; at most 3,600 seconds, with exclusive expiry |
| Installed effect policy | `MAX_EFFECT_POLICY_BYTES`: 4,096 canonical bytes before decoding; partition at most 512 bytes; explicit nonzero safe-integer epoch; valid nonweak Ed25519 approver |
| Private human review | 131,072 bytes including exact request and binding; never a public receipt |
| Observation attempts | At most 16 explicitly admitted linked operations |
| Transaction lock deadline | 5 seconds; sample time after lock; refuse on deadline |
| Native verification work | Native configured work-unit limit plus transaction deadline |
| Driver | Existing 64 steps |
| Transport | Existing 15-second maximum; no redirects or write retries |
| Claim contention / file recovery | Existing 32 claim rounds / 8 recovery rounds |
| Recovery scan / public receipt | 1,024 records per page / 16,384 bytes |

Tighter existing limits win. New limits above are implementation requirements,
not claims that baseline code enforces them. Bounds must be checked before
allocation, including persisted files (baseline `fs::read` checks too late).

The reducer permits reserve → refuse-before-entry or reserve → unique grant.
Provider acquisition/mutation may then record response or unknown; disclosure
may record exact ACK or unknown. Late exact evidence is additive/idempotent.
No unknown→not-entered, refund, new grant or automatic retry edge exists.
Independent observation adds a typed fact without replacing response/ACK or
original actor. Conserved capacity is available + held + consumed = allocated;
unknown keeps charges. Pre-entry refusal only releases declared releasable units.

## Cutover and evidence

Replace affected formats and call sites in one bounded PR. No production
compatibility path, migration or dual journal. Reference models remain explicitly
test-only. Formal work must update translated shipping predicates and refinement
links, not claim a hand-written model proves runtime code. Adapter assumptions
include lock/commit durability, clock trust, recipient authentication and provider
observation integrity; whole-store rollback without an external anchor is excluded.

Required executable/formal properties are E01–E05 and R01–R10. Measurements must
cover verification, compilation, transaction/lock time, bounded memory and scans
for both recipes and read/disclosure. No measurements have yet been executed.
Actual results and exact revisions belong in the
[acceptance ledger](../../../plans/0074-implementation-status.md).

## Adapter fence mechanism

The existing attempt adapters now have one bounded snapshot-and-replace
operation. Its decision callback is in-process native validation over opaque
snapshots, not a provider/profile dispatcher or an extension plugin. It runs
once while the same lock excludes connection replacement, allocation insertion
and expiry sweeping; it returns one record replacement. No provider or custody
call may run under the lock, and no error is retried automatically. File
publication and PostgreSQL COMMIT must acknowledge before returning success.

Both maintained adapters share a 64-record read bound and two-second lock and
decision ceilings; tighter installed PostgreSQL deadlines are preserved.
The source conformance suite orders replacement, insertion and sweep writers
against a held decision and checks failure atomicity. This source has not yet
been exercised in hosted CI. The mechanism does not itself interpret effect
identity, grant entry or establish multi-host revocation freshness. The shared configuration record now participates in the fence, retains bounded
permanent qualification memory and requires explicit operator CAS activation.
Connecting its snapshot to the one-use grant owner remains P2 work, as specified
in ADR 0017. Early host checks are not final-entry evidence.


The mutation source now connects this primitive to the existing transition and
submission owners: reservation and durable grant are separate, fixed grant audit
bytes cannot change, and transport consumes a capability issued only after the
fenced replacement acknowledges. The same retained command supplies the request.
Slot membership is checked without reallocation. The native synthetic grant
corpus proves its narrow file-store sequence; it does not establish installed
multi-process fencing, all fault boundaries or the still-open recovery cutover.


Reservation resumption now remains in that same owner: equal reserved bindings
reopen unchanged, and grant audit `/2` appends the fresh approval/read facts while
preserving admission history. Attempt `/6` advances exactly one revision per
replacement. The synthetic file corpus exercises restart after the initial
approval/deadline, retained count/sum slots at exhausted capacity and one fresh
grant. PostgreSQL equivalent source is authored, not executed. These mechanics
do not establish acquisition, disclosure, independent observation authority or
installed end-to-end guarantees.


Review completeness is now a closed presentation mechanism shared by the
maintained recipes: typed complete field coverage, bounded labels/units and a
literal native renderer. Domain consequences and units remain operator-owned
recipe data; the gateway neither converts units nor infers meaning by provider.
Recipe/effect identities bind that declaration. Native negative and rendering
corpora cover missing/type/version/label/duplicate cases and hostile text.
Installed reviewer authentication, frontend parity and domain qualification
remain separate gates; the OpenAPI mapper deliberately emits an unusable draft
until its review facts are supplied.


### Replay projection evidence checkpoint

Both mutation families now return granted/terminal history without replay I/O.
The pure order predicate stops on replay; the runtime compares the full native
binding before projecting journal state. A new `reserved` result retains the
pre-grant distinction and bounded revision. Ambiguous acknowledgement never
constructs a permit, including when a successful reread finds a committed grant.

`bindings/fixtures/gateway/replay-projection.json` is generated by the native
submission driver and real file adapter with synthetic verified commands. It
covers concurrent reopened-store replay, no-commit/committed-ack-loss and failed
reread, exact external counters and malformed reservation projections. It is
narrow mechanism evidence; installed authority and PostgreSQL fault evidence
remain open. Existing explicit operator observation tests retain their original
scope and are not evidence of independent AP074 recovery authorization.


## Recovery compiler checkpoint

The native recovery compiler reuses the verified-action, canonical binding,
exact approval and complete literal-review owners. It does not reuse mutation
authority or its request type. A protected journal target supplies the source
identity and closed observation GET; a distinct native reader authorizes that
exact target and its count/byte/time limits. The reserved native read tool cannot
be installed as a mutation recipe.

`recovery-compilation.json` is generated from signed native proofs and an actual
file-backed source record. It covers an expired original writer, a different
reader, exact read approval, source/contract/limit substitution refusal and no
source mutation. Its source entry uses a test oracle and sends no provider
request. It proves compilation only: conserved acquisition charging, fresh
transactional read entry, credential replacement, installed review channels and
bounded observation execution remain open evidence gates.


## Recovery acquisition mechanism checkpoint

The shared journal now encodes typed mutation/acquisition payloads under one
header, codec and transition predicate. The concrete recovery-read payload
binds the full source, request and capacity plan. It does not reuse mutation
observation facts or introduce a second transition reducer. Permanent allocation
slots conserve one call and its maximum bytes together; the source effect, not
the read operation ID, owns capacity. The final existing adapter fence compares
the exact source/claim/allocation and fresh authority before granting a permit.

`bindings/fixtures/gateway/recovery-entry.json` is constructed by the native
recovery fixture using signed proofs and the real file adapter. Its entry check
and provider response are synthetic. It exercises same-reservation replay,
stale grant refusal, permit loss/reopen, 16 concurrent contenders for 15 remaining
slots, permanent retention, private response history and mixed-protocol stage
projection. It establishes neither provider execution nor installed revocation,
PostgreSQL parity, process crash behavior, source-evidence freshness or disclosure.
Those remain required independent evidence and cutover gates.


## Evidence refinement comparison

The concrete recovery-read response is evaluated against its original closed
source contract inside the shared source/read/allocation fence. No response field
selects a provider implementation. The existing typed read-back distinction is
retained: exact echo plus expected value can link provider evidence; equality
without that echo cannot resolve an unknown mutation. Duplicate object members
are rejected instead of silently choosing one value. This parsing hardening is
a bounded observation leaf, not a new provider-semantic evaluator.

`recovery-refinement.json` covers unusable/missing/multiple/duplicate responses,
unrelated echo and noncausal equality, freshness boundaries, concurrent/idempotent
recording, source attribution/charge retention and report privacy. It also freezes
the closed replacement operator-frame grammar. These are native file-journal
results with synthetic response, clock and entry validation; independent process,
installed transport, PostgreSQL and final differential evidence are still needed.


## Submission and independent observation boundary

Mutation submission now ends at a recorded response or conservative unknown
outcome. The shared order leaf contains no automatic read-back, observation
lease mode or operator resume entry. The driver cannot promote a response into
provider evidence. Historical observation-writing helpers are crate-private and
compiled only for tests; the shipping recovery fence owns evidence refinement.

The retained record/store oracle requests observation explicitly and makes no
AP074 acquisition-authority claim. The native replay corpus separately measures
one response-producing write with one lease and zero provider reads, no provider
evidence, and a replay that adds no I/O or journal revision. The scenario corpus
removes the former second lease, repeated credential checks and post-write read.
Installed journeys, ancillary read admission and final translated/refinement
artifacts remain required before this boundary has complete acceptance evidence.


## Prerequisite declaration comparison

The Stripe reference contributes account and denied-capability checks plus a
relative-ceiling read; Airtable contributes the pre-entry read. Compiler `/5`
retains the existing closed requests rather than reconstructing provider paths.
The shared fields are exact method/URL/headers, one-call and response-byte
allowances, transport/freshness bounds and absence of disclosure. Evaluation
purposes remain tagged: account equality, expected refusal, selected pre-entry
requirements and relative arithmetic are not interchangeable response meanings.

`prerequisite-compilation.json` uses signed native proofs and exact approvals to
freeze both plans, including account-scope header placement, resolved bound
values, exclusion of the onboarding probe, native recompilation and obsolete
compiler refusal. The Airtable case has no pre-entry observation requirement;
it tests compilation, not admission eligibility. The fixture has no provider,
custody, durable acquisition or human-channel claim. Runtime accounting,
independent differential execution and installed evidence remain required.


## Prerequisite journal cutover

The same acquisition transition/adapter mechanism now handles the two compared
prerequisite plans. Their authority differs from recovery: a prerequisite uses
its exact parent's approved enumeration while the parent remains reserved;
recovery uses an independent read proof/approval and an eligible unresolved
source. A closed plan variant and source check preserve that distinction.
Neither path decodes audit data into a transport request or grants disclosure.

`prerequisite-entry.json` records file-journal histories for both compiled plans:
missing reads, recorded responses, lost permits and stale responses. Equal
reservations retain their charges, only one concurrent handle wins entry,
reopening cannot remint a permit, response times are preserved, and final write
entry requires fresh recorded child facts and their original allocations.
Membership-witness substitution is rejected. Grants use an explicit-time oracle
and responses are synthetic; no provider calls occur. The Airtable compilation
case still has no native pre-entry requirement and does not establish installed
mutation eligibility. Differential semantic evaluation, actual transport,
process faults, PostgreSQL and tighter observer freshness remain exit gates.
