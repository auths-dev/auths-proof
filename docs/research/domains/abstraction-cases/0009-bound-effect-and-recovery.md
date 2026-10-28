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


## Prerequisite evidence at entry

The final gate does not add an alternate response evaluator: it calls the same
account/denied predicates, recipe ceiling reader, ratio kernel, signed observation
verifier, requirement selection and native freshness/condition predicates already
used by the maintained paths. Journal membership provides the response and its
original time; the installed gate checks the resulting evidence under the writer
fence. Existing synthetic store oracles explicitly omit installed authority and
remain test-only.

`prerequisite-evidence.json` adds 15 native signed Airtable cases, including a
2-second selected freshness bound within the 30-second acquisition ceiling.
`prerequisite-guard-evidence.json` adds 15 Stripe response/checkpoint cases. The
positive Stripe input now has a known synthetic account commitment, allowing an
actual matching account check rather than an unopenable placeholder. These are
executed predicate fixtures; their scope excludes installed process/transport,
transaction lock waits, PostgreSQL and full differential qualification.


## Ordered initial admission

Mutation count/sum claims and recovery/prerequisite acquisitions now use one
bounded snapshot-and-insert mechanism under the existing writer fence. The
adapter owns atomicity only; the gateway reuses its native entry validator to
establish authority before publishing any claim or charge. Mutation sum
predecessors and acquisition source eligibility remain typed, distinct checks.
No schema, allocation algebra, retry owner or transport reconstruction is added.

The file artifact `effect-admission.json` covers expired-approval refusal with
no claim/capacity writes, admission-time stamping, immutable replay after expiry,
retained count/sum charges, missing/changed dependencies, batch collisions and a
writer-before-admission dependency order. Authority uses the explicit-time
approval oracle; opaque dependency bytes exercise adapter ordering, not native
revocation semantics. The same conformance source is authored for PostgreSQL.
Installed authority races, process faults and performance remain required.


## Application provider-read cutover

The application `read-back` request previously had neither native proof nor
exact approval and could make credential/account checks and a provider read.
It is removed from production, the shared application frame, CLI and SDKs.
The existing native recovery engine now also serves a closed application frame
with separate proof/action/approval. It preserves source/read distinctions and
returns only the already-defined redacted report. The same bounded decoder and
engine serve operator and application callers; no second decision owner exists.

`application-recovery-frame.json` constructs real Unix socket decoder/dispatch
histories with a counting refusal oracle, including obsolete schemas, omitted
or malformed approvals, invalid source IDs and transport substitution.
`application-recovery-cli.json` captures the production CLI's exact request and
response over a real socket. These are transport artifacts, not installed proof,
provider, disclosure or end-to-end acceptance evidence. The independent old
observation evaluator remains confined to test-only reference/control paths.

### Managed read reservation extension

Mutation count/amount and recovery call/response-byte budgets share checked
fixed-window arithmetic, ordered slot candidates, immutable cumulative sums,
atomic insert and final membership validation. They do not share units or counter
identities. Recovery sums mean the complete approved response ceiling; mutation
sums keep their recipe-defined argument. Source-lifetime recovery allocation is
an additional independent limit. Prerequisites charge their declared child
allowance without repeating the parent's managed spend reservation.

This extension reuses the existing store mechanism rather than adding a budget
owner. The admission transaction includes every managed slot and the source
allocation; replay and contention create no partial charge. The native recovery
corpus must cover count/sum exhaustion, retained unknown charges, window changes,
source/allocation collisions and missing/substituted membership. Full adapter
concurrency and performance acceptance remain open until executed evidence is
recorded in the AP074 ledger.

### Credential prerequisites of independent recovery

The account/denied-capability subset is identical between mutation and recovery:
closed recipe reads, expected installed account, refused HTTP statuses, version
checks, one invocation and full response ceiling, durable receipt, and 30-second
conservative evidence age. Both paths now use the same compiler subset, journal,
permit-consuming acquisition helper and native evidence predicates. Mutation
keeps its additional pre-entry/relative-ceiling semantics. First-install probes
and candidate credentials remain an independent authorization obligation.

A recovery parent's request commitment authenticates its complete prerequisite
witness. The existing child membership decoder accepts the closed mutation or
recovery parent protocol and refuses disclosure; the source fence refuses a
child as a parent. Final entry requires all child evidence under the same fence.
The six-case recovery prerequisite corpus records the native predicate result
separately from oracle journal grants, so synthetic wrong-account/capability
histories cannot masquerade as installed entry-denial evidence. Installed
transport, PostgreSQL and final formal/performance gates remain open.


## Candidate credential compilation checkpoint

Candidate first-install and rotation checks now reuse recovery's native MCP
verification, branch/observer separation, managed read-bound admission and
bound-effect construction. The target comparison stays distinct: recovery pins
a retained mutation, while candidate compilation pins a staged descriptor and
exact predecessor/absence. The existing recipe owns probe/account/capability
meaning. Ordered child plans reuse the closed prerequisite declarations; the
last actual request is the primary acquisition. No callback or aggregate
provider response is introduced. Probe parsing now uses the same bounded,
duplicate-rejecting decoder as the other native evidence predicates.

`candidate-compilation.json` compares first install, active/disabled rotation,
HEAD-final and probe-only plans using signed native actions. It records full
review and substitution refusals, exact approval/reverification, stable lifetime
keys under operation/time changes, and refusal through the existing mutation,
recovery and orphan-child routes. It is compiler/predicate and route-refusal
evidence only. The candidate journal admission, staged custody, ordered current
or absence validation, transport and publication cutover remain required; this
checkpoint does not promote an operator attestation into native read authority.


## Candidate acquisition runtime checkpoint

The candidate plan is now another closed source alternative of the existing
acquisition owner, with connection/predecessor eligibility kept distinct from
recovery's source mutation. Physical dependency deduplication preserves both
source and native checks on the same snapshot. Native authority, qualification,
exact approval and workload/profile checks remain in `entry.rs`; disabled
candidate rotation is explicit and cannot authorize an ordinary mutation.
The shared acquisition runtime consumes the same permits and retained-response
predicates. There is no new reducer, provider callback or public content path.

`candidate-journal.json` records actual native fenced validation with signed
proofs and real file persistence for first install, active/disabled rotation,
HEAD-final and probe-only plans. Histories cover absent/changed predecessors,
changes before child/main grants, missing/bad/stale child evidence, lost main
permits and restart. Cross-proposal capacity checks preserve the credential's
first byte ceiling. Configuration and time are test-controlled; provider bodies
are synthetic. These artifacts do not establish installed provider execution,
PostgreSQL conformance, final-check acceptance or credential publication.


### Retained candidate evidence at publication

The candidate publication change composes the existing connection insert/replace
fence, typed acquisition evidence and concrete credential-purpose predicates.
It adds no acquisition phase, callback-based lifecycle or provider-specific
publication policy. First install checks absence; rotation checks exact previous
bytes and preserves administrative state. The common native fence validates the
same proof, approval, configuration and qualification used at entry, while
retained primary/child grants bound evidence age. Exact already-current state is
reported without asserting fresh evidence or attributing publication to a retry.

The native file corpus adds successful publication/replay and refusals for bad
final purpose/version, unknown primary, stale primary/children, expired approval,
changed configuration and changed predecessor. Acquisition snapshots and charges
remain unchanged across publication. This evidence remains narrower than process
faults, installed custody/provider execution or PostgreSQL conformance.


### Staging and local custody serialization

The staged rotation path preserves the existing concrete connection/credential
relationship. It records the cleanup generation, stores without overwriting a
candidate, and hands its private proposal to the shared native read owner.
No provider semantics move into custody. The operator CLI directly uses native
call compilation, review, acquisition and publication; unapproved rotation is
limited to recipes with no network checks. Published-secret join is exact
credential confirmation without acquisition.

The persistent file credential store now orders operations with a stable
cross-process sidecar lock and reloads bounded state. This is an existing store
mechanism correction needed by independent operator/runtime processes, not a
new lifecycle owner. The production CLI corpus drives two competing staging
processes and a held-lock refusal. Native staging evidence checks stale handle
refresh and conflicting successor refusal. Broader fault and adapter evidence
remains required before AP074 acceptance closes.


### First-install source cutover

Installation now uses the same sealed candidate and native acquisition owner as
rotation. Its concrete difference is the expected absence of a live connection
and an explicit generation-one host floor. The private draft is the existing
canonical connection record, not another lifecycle format. The cleanup journal,
custody reference commitment and floor retain their existing owners. Only the
operator staging action initializes missing installation state; managed candidate
execution checks it and cannot repair it.

The raw onboarding I/O wrapper is removed from production exports and CLI calls;
its pre-cutover evaluator is retained under `cfg(test)` as the closed reference.
The production `install` command stages read-bearing recipes without publication.
Native file evidence and independent CLI restart evidence cover exact restaging,
conflicting secret refusal, explicit absence, cleanup ordering and floor checks.
No provider predicate is inferred from successful staging, and these artifacts
do not close the installed approved provider, fault or PostgreSQL obligations.


### Approved candidate process evidence

The production CLI now has a six-case process/HTTP artifact, generated by
`tests/candidate_journey.rs`. Native test authoring creates real proof/action
bytes with explicitly public fixed keys; the runtime still performs native
verification, exact review/approval, durable acquisition and fenced publication.
Separate CLI processes exercise first install, active/disabled rotation, replay,
competing acquisitions, invalid/reused approval, failed probe/account/final
capability and response loss. Actual external request counts and byte-preserved
journal/allocation snapshots provide evidence independently of intermediate
runtime flags. The local provider remains a domain-specific test reference;
no provider branching or test authoring enters the shipping default runtime.

This strengthens the existing mechanism comparison without adding a production
abstraction or claiming human presence, deployment isolation, PostgreSQL faults
or live provider qualification. Maintained deployment/demo consumers still need
the exact authority/approval and qualification bootstrap cutover.


## Recipient evidence and disclosure reducer checkpoint

The shared predicate now admits only the disclosure edges reserved→not-entered,
reserved→entry-granted, entry-granted→unknown/acknowledged and
unknown→acknowledged. Fixed allocation bytes and grant bytes survive every edge;
ACK is a separate terminal fact. Exact repeated evidence is a read-only lookup.
Acquisition/mutation cannot carry ACK bytes, and disclosure cannot carry HTTP or
observation facts. Existing provider outcome signing refuses the ACK stage.

The native Ed25519 ACK contract binds every release dimension and exact protected
content length, using the existing raw-key principal derivation, canonical codec
and domain-separated commitment. It adds no token system, recipient registry or
provider-specific branch. Recipient evidence is historical and independent of
current execution authority; the future entry fence must separately establish
that authority before releasing any content.

`disclosure-acknowledgement.json` is generated from real native signatures and
the shipping transition predicate: 576 same/cross-protocol stage pairs, four
histories, changed field/signature/encoding cases and read-only replay. Its
retained content identities and journal projections are synthetic. It is neither
AP070 differential equivalence nor a durability, actual delivery, authenticated
channel or process-isolation claim. Those remain required for the direct consumer
cutover. Kani source is extended, not executed; translated Lean/refinement work
remains pending.


## Content acquisition compiler comparison

AP070 separates exact resource selection, bounded UTF-8 response validation and
later release. Its provider-specific metadata predicates (ID, trash state,
download capability and MIME-dependent endpoint) are additional domain semantics
and are not erased by the new content declaration. They still need reviewed
closed declarations/reference evidence before the AP070 runtime cutover.

The identical subset implemented here is a fixed-origin GET over verified
resource/account values, literal query parameters, and bounded UTF-8 or one
JSON-string projection. Path/header/percent construction and JSON duplicate
rejection reuse the existing gateway mechanisms. The new declaration has one
resource field, sixteen path segments, eight sorted unique query pairs, 64-byte
ASCII query names, 512-byte query values, the existing 8,192-byte URL bound and
65,536-byte response/content ceilings. It rejects response locators and operation
IDs as content resources. Query values are encoded data; no callback interprets
them. The ADR's narrow primitive exception applies to this construction subset,
not to Google metadata semantics or to a general provider qualification claim.

`content-compilation.json` uses native signatures, exact approval and recompile
for both projections. It exercises resource/installation/limit changes,
operation-independent and administrative-metadata-independent capacity keys,
expired/reused approval refusal, operator/native review, malformed source/query/
pointer rejection and all six typed response failures. Projection copies exact
bytes without truncation into a zeroizing buffer and gives no disclosure permit.
This evidence does not establish durable source allocations, actual provider
transport, content custody, standalone read-only deployment, AP070 differential
parity or a recipient release. Those remain part of P3/P4.


## Content acquisition durable comparison

The shared mechanism is the existing acquisition admission/entry/replay order,
with the connection row as source and the compiler's resource capacity keys.
Content keeps a distinct response carrier: status, version agreement, raw bytes,
receipt time and bounded media/encoding facts. Credential-purpose evaluation and
mutation observation cannot consume this carrier. It establishes neither an
AP070 metadata predicate nor recipient delivery. Fixed reviewed query parameters
are sent only through a sealed content permit, using the same pinned-origin,
no-proxy/no-redirect transport policy and explicit identity encoding.

`content-journal.json` is constructed by native signed authority/approval,
installed entry validation and the file adapter, with eight real local HTTP
requests. It checks exact query/Accept/encoding headers, raw-body bounds,
duplicate/missing/encoded/wrong-media response metadata, retained HTTP denial,
one-use grants, reopen replay without record changes, permanent charges after
lost permits and refusal of attempt seventeen. A typed-record downgrade is
rejected. Synthetic credential/provider data stays private; the artifact contains
only public snapshots and synthetic response header facts. This is not an
independent-process, PostgreSQL, full engine, protected-content/disclosure,
AP070 equivalence or isolation claim. These evidence gates remain open.


## Protected projection comparison

The durable content owner now invokes the same bounded projection leaf as the
compiler corpus after checking retained version and encoding facts. The domain
boundary remains unchanged: no Google file-ID/trash/canDownload/MIME predicate is
inferred. JSON-string projection is data-only and duplicate rejecting; UTF-8 is
exact and never lossy or truncated. Ready content is reconstructible from the
immutable raw response and contract, while refusal stays a distinct retained
fact. This performs no additional provider read or recipient delivery.

The hiding commitment is a direct composition of the pinned HMAC-SHA256 primitive,
native canonical tuples and native domain commitments. Its private per-source
key and source/projection/length/content binding are explicit. It does not reuse
the unrelated MCP execution-reference format or turn a receipt-protection port
into a semantic owner. The protected journal remains a deployment assumption.
`content-journal.json` version 2 covers fifteen actual HTTP responses plus lost
permit/exhaustion, typed response refusal, key/tag/length/body/metadata mutation,
foreign-source material, old-schema refusal and unchanged replay. Random keys
and tags are never emitted into the canonical fixture; only checked facts and
public redacted statuses are stored. This is still narrow file-adapter evidence,
not PostgreSQL, independent-process or AP070 differential qualification.

### Retained source to release compiler

The native disclosure compiler now consumes sealed content provenance loaded
from the acquisition journal. Unlike provider acquisition, it has no credential
prerequisite or provider request. Unlike a mutation, it binds an exact retained
projection to a recipient/channel/instance and uses disclosure count/byte units.
The identical mechanisms remain native verification, selected dependencies,
canonical binding, complete review, exact approval and full recompilation.
Managed policy arithmetic is reused under closed, disjoint protocol domains.

The source lifetime is the retained acquisition, with sixteen delivery counts
across recipient/channel/operation changes and exact-length byte declarations.
This is a bounded implementation contract, not an inferred provider semantic.
The content journal corpus provides actual source transport plus separate
release compilation/ACK comparisons for empty and nonempty content. Runtime
entry, capacity enforcement and recipient-channel behavior remain unqualified;
no generic workflow/callback or new ledger is introduced by this extraction.

The source allocation leaf is now physically shared: protocol owners supply
count/byte units and source commitments; the existing capacity module owns the
append-only row encoding/key and occupied-row equality check. No policy or
source-eligibility callback is introduced. Required content/recovery native
artifacts regenerate byte-for-byte unchanged after this extraction; disclosure
compilation uses the same bounded reservation arithmetic with disjoint units.

### Disclosure journal instance

Disclosure now supplies typed state/plan projections to the same journal protocol
and kernel reducer as acquisition and mutation. Source provenance is checked under
the existing writer fence, alongside selected native dependencies and permanent
source/fixed-window slots. The count/sum arithmetic, immutable allocation encoding,
replay-key comparison and CAS transition owner remain shared. Provider evidence and
recipient ACK bytes remain divergent typed fields; no generic success outcome is
introduced. The native engine reserves and delivers through the sealed Unix
channel boundary below.

The file corpus adds real-source admission/exhaustion/replay and decoder mutations.
A synthetic retained-grant assumption enables real ACK persistence/concurrency and
late-history comparisons; it is explicitly not live recipient authentication or
transport evidence. The original corpus does not establish transport; complete differential and
performance gates remain outstanding.


### Authenticated local disclosure instance

The new Unix transport reuses kernel UID observations and pinned cryptographic
primitives, adding a closed fresh challenge over the exact native delivery
statement. It does not repurpose provider response evidence or generic exchange
server authentication as recipient possession. A proposed channel policy and a
serialized historical transcript are data; only the owned authenticated stream
can participate in the final native fenced decision. Only its acknowledged grant
constructs a one-use content permit. The source projection and protected-content
validator remain the acquisition owner; recipient code cannot supply a second
plaintext or destination to the send function.

The identical shared leaves remain native verification/recompile, exact approval,
writer fencing, source/counter allocation membership, durable acknowledgement and
immutable entry/evidence transitions. The distinct disclosure instance fixes a
local UID/key/channel handshake and exact byte length with explicit bounded
framing and deadlines. It adds no provider dispatch or policy callback. The real
socket-pair/file artifact exercises ACK loss, late evidence, fresh-authentication
replay, dropped permit, one-winner concurrency and dependency changes before the
final fence. Independent processes/adapters, complete recipe differential and
performance evidence remain required by the extraction and AP074 exit gates.


### Application and thin-client cutover

Content application inputs no longer supply a resource map beside the signed
native action. The acquisition compiler's existing body is shared below sealed
verification, allowing content target reconstruction from that same verified
command. This is one compilation owner; old explicit-target callers and new
native-action callers produce identical bindings in the native corpus. Native
history and ACK recording are exposed without capability reconstruction.

The application control switch invokes existing native admission and then hands
one owned socket to the existing authenticated delivery owner. It does not infer
readiness, authorization or receipt from a transport label. Rust client/CLI code
alone executes recipient authentication and signs ACKs after receipt. Python and
TypeScript carry bounded envelopes and native result bytes; no shared semantic
predicate, hash, signature or capacity rule moves into those wrappers. Frame,
CLI refusal and native-client/file evidence have explicit narrow scopes. Full
installed consumer, reference differential and isolation gates remain required.


### Native authoring and process composition evidence

The content/disclosure authoring commands reuse the native target constructors
and canonical MCP encoding. The existing bounded duplicate-free JSON decoder is
reused only for mechanical parsing; resource meaning remains in the reviewed
recipe capability. No new recipe operation dispatch, hash owner, policy callback
or transition rule is introduced. Test-only trust authoring now accepts an
explicit bounded same-service tool set, while each real signed action/grant has
its exact permission and still passes native verification.

`content-process-journey.json` adds real CLI/daemon composition over the file
adapter: separate acquisition/release, actual recipient ACK, restart no-redelivery,
crash after recipient receipt before ACK, late evidence, approved write and
independent read-back, and separate-process disable before release. The artifact
records three actual provider requests and redacted native facts. Public fixed
keys simulate actors; neither installed UI/language integration, isolated hostile
agent containment nor PostgreSQL/full fault coverage is inferred. Differential
reference and bounded performance exit gates remain open.
