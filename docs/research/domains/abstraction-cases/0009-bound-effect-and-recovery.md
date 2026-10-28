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
