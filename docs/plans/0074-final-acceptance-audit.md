# AP074 final acceptance audit

This is the current requirement-to-producer map, superseding stale outstanding
work descriptions in historical checkpoints. It does not supersede the spec,
remove a test or establish that authored checks passed. The final coding batch
is implemented and its artifacts are constructed; exact-head hosted verification
is pending. Every row
below therefore remains **unverified on the completed revision**.

Native test files below are in `product/runtime/auths-gateway/src/`. The
PostgreSQL lifecycle workflow explicitly runs both durable adapters, including
ignored PostgreSQL selectors, and retains real execution logs. A selector must
execute once with one pass and zero ignored; a skipped or zero-match invocation
is not evidence. Application-owned AP070 remains independent. AP073 is untouched.

## Architecture and phase deliverables

| Requirement | Authoritative implementation/deliverable | Required closure evidence |
| --- | --- | --- |
| P0 | Spec ownership map, `docs/adr/0017-bound-effect-and-recovery-ownership.md`, `docs/research/domains/abstraction-cases/0009-bound-effect-and-recovery.md`, `0074-differential-contracts.md`, maintained field/limit/state tables | Audit native managed owners and independent reference consumers; architecture/compliance gates |
| P1 | `effect.rs`, `effect/`, native approval/private complete review; application protocol and thin Python/TypeScript wrappers | Native signed compilation/review/binding corpus plus installed exact approved request |
| P2 | `store.rs`, typed protocols, `transition.rs`, `entry.rs`, `configuration.rs`; file/PostgreSQL adapters | Actual independent-process capacity, crash, dependency, retention, corrupt-state and durability-fault cohorts |
| P3 | Native acquisition/disclosure, separate source/recipient/channel approval, one-use grants and exact ACK | Real HTTP/Unix transports, independent read/release charges, revocation, lost ACK and late evidence; installed read/release journey |
| P4 | Second recipe, independent reference comparisons, installed journey, private/public audit, formal links, cost producers | All A rows and complete exact-head hosted gates; publication on draft PR213, no merge/deploy |

## Effect and recovery invariants

| Requirements | Native owner and independent evidence families |
| --- | --- |
| E01 | Sealed verified command and bound effect; `effect_native_tests.rs`, `native_mutation_replay_tests.rs`, installed owner journey compare actual requests |
| E02 | Complete native binding/authority comparison; `effect_binding_boundary_tests.rs`, `effect_review_approval_tests.rs`, `native_scope_tests.rs`, real retained-input conflicts |
| E03 | Shared operation key and durable binding conflict; native process capacity, retained replay and generated concurrent histories |
| E04 | Native verifier, exact approval and fenced current validation remain separate; all three entry-order matrices exercise expiry/withdrawal after admission |
| E05 | Native review/history projections, strict shared result corpus, public/private audit separation; installed Python/TypeScript/UI and sentinel/privacy cohorts |
| R01 | Shared typed transition owner and transaction contract; architecture/source inventory and source-linked translated predicates |
| R02–R03 | Acknowledged atomic admission and final grant precede permit construction; SIGKILL, sync/rename errors, SQL-prefix aborts and lost COMMIT replies on all protocols |
| R04 | Count/sum/lifetime allocation rows are atomic with admission and retained through uncertainty; actual capacity/fault/cleanup and generated history oracles |
| R05–R06 | Separate response, observation and ACK states; crash/response-loss/partial-upload/late-ACK cases preserve Unknown and charges without retry |
| R07 | All three native entry-order cohorts race connection/configuration/epoch and clock changes under actual adapter fences |
| R08 | Immutable prior record/evidence assertions; exact ACK substitutions and independent recovery history preserve source facts |
| R09 | Independent recovery actor/read approval and bounded acquisition; `native_recovery_actor_tests.rs` and its limits/history children |
| R10 | Strict one-format journal decoder, malformed/obsolete native replay corpus, retention tombstones, shared epoch and independently retained generation floors |

The six compositional proof/runtime obligations and assumptions are mapped in
`0074-assurance-map.md`. Ranges group requirements sharing producers; no invariant
is waived by grouping. Pure proofs do not establish codecs, signatures, store
durability, deployment isolation, clocks, recipients or external provider truth.

## Executable acceptance rows

| Row | Concrete producer families and expected observations |
| --- | --- |
| A01 | Native compilation/approval fixture, mutation replay and installed owner journey: same effect and exact request at review, approval and real send |
| A02 | Independent binding and changed-review signed corpora; native scope/read/release/ACK substitutions: old approval refuses, fresh valid control succeeds or unsupported scope refuses before entry |
| A03 | Native process/capacity, retained replay and generated concurrent histories: at most one entry; same-key changed binding conflicts; fresh-key old approval refuses |
| A04 | Native acquisition, mutation and disclosure budget matrices on file/PostgreSQL: final count/byte/sum capacity admits exactly the permitted total and preserves all prior rows |
| A05 | Native acquisition/mutation/disclosure crash matrices; guarded mutation adds 15 parent and 28 child schedules per adapter; partial-upload relay forwards exactly one approved body byte before SIGKILL, retains Unknown/charges and never resends |
| A06 | All three native file-fault, PostgreSQL partial-batch and real COMMIT-reply-loss cohorts: failed/ambiguous acknowledgement returns no new permit; reopened state is authoritative |
| A07 | Source acquisition then real disclosure worker/operator revocation race: refusal has zero wire bytes after authentication, while grant-first retains delivery semantics |
| A08 | Disclosure crashes, lost ACK/commit replies and genuine late ACK: no redelivery, no refund; exact late evidence refines original history |
| A09 | Native ACK corpus and separate gateway/recipient process corpus: re-signed identity/channel/content/source substitutions leave facts and charges unchanged |
| A10 | Native candidate/recovery/partial-upload and installed projections: denied response, timeout, response loss, HTTP response, state match and declared linkage remain distinct |
| A11 | Recovery limits/history: zero/multiple/unrelated/incomplete matches unresolved; exact supported link adds evidence without writes; exhausted calls/bytes/time, aged evidence and unavailable state retain charges/escalation |
| A12 | Acquisition, mutation and disclosure entry-order matrices: independent operators race revocation, configuration and epoch before/after actual fenced grant; stale worker cannot create a new grant |
| A13 | All three entry-order lock waits plus prerequisite freshness: independent approval, resource and observer expiry is sampled under the lock; original signed bytes/times remain unchanged |
| A14 | Genuine threshold authoring and all three entry-order matrices: proof stays Authorized through another branch but changed selected authority cannot reuse old exact approval |
| A15 | Independent writer/reader recovery and retained history: expired/revoked writer grants no recovery write; bounded separately authorized read preserves attribution and charges |
| A16 | Native managed scope, shared-store partition/recipe tests and binding substitutions: no cross-task/recipe/partition alias; unsupported delegated participants refuse without another authority |
| A17 | Public mutation privacy, sentinel output and installed inventory/audit: private facts stay in operator export; public effect/content references use hiding commitments; no secret/proof/body sentinels in public surfaces |
| A18 | Native binding/review/ACK/frame limits, 209 shared Rust/Python/TypeScript result vectors and new strict journal corpora: canonical positives and malformed/duplicate/obsolete/limit negatives agree at the surfaces exposing each type |
| A19 | `qualification/reference/ap074_differential.py` and `ap074_information_differential.py`: two maintained mutation recipes (28 requests/26 responses), 22 acquisition/disclosure comparisons, unchanged independent references and explicit claim differences |
| A20 | Shipping gateway-kernel transition/order/recovery predicates, pinned Charon/Aeneas translation, compiled Lean audit, Kani, refinement/property/mutation suites and generated real concurrent native histories |
| A21 | Native retention, epoch fence and independent floor: retained terminal/reserved facts survive expired slot cleanup; stale controls and database-only generation rollback cannot recreate entry; missing/malformed floors refuse |
| A22 | Source-free installed demo owner journey, native SDK/content journey and Linux unprivileged complete interface inventory: consent/decline/substitution controls, read/release/write/observation/replay/unknown and truthful UI; no alternate managed credential/permit route |

This composition does not require every negative through every UI and adapter
combination. It does require each row's actual boundary, both durable adapters
where stated, installed binding/UI integration and complete non-bypassability
inventory. Native authority tests cannot substitute for installed integration;
installed happy paths cannot substitute for native adverse concurrency/faults.

## Verification and artifact checklist

1. Finish all coding before any constructor or verification run, per AGENTS.md.
2. Construct the new nine selectors plus the changed dependency/entry/epoch
   fixtures and the five stale compilation constructors reported by the CI agent.
   Collect every independent failure; repair one coherent batch without weakening
   assertions. The four mutation prerequisites are account, two denied reads and
   relative ceiling. The onboarding probe is separately candidate-authorized.
3. Refresh gateway semantic closure, generated compliance/API identities and
   required release metadata once after the source/fixture batch is complete.
   Review generated changes; never copy decoded hosted assertion byte arrays.
4. Run required verification on the completed source. The CI agent owns hosted
   inspection and holistic repairs; retain exact source/tree/closure identities,
   selector counts, adapter logs, differential reports, cost/history artifact
   hashes, installed inventory and formal/release evidence.
5. Resolve required `cargo xtask ci` component gates: formatting, architecture,
   repository hygiene, build/tests/Clippy, core/MSRV/ABI, wire/compatibility,
   bindings/packages/demos, WASM/fuzz, compliance and applicable release/formal
   source freshness/adequacy. Inspect conditional skips for applicability.
6. Audit every row against final exact-head evidence before claiming complete.
   Hosted runner capacity cancellations remain missing evidence, not passing
   platform coverage. No live provider credential, merge or deployment is needed.

## Supported claim boundaries

File storage is a trusted single-host durability/fencing boundary; PostgreSQL
requires the maintained TLS/transaction configuration and participating writers.
SIGKILL and modeled syscall faults do not prove power-loss behavior. The partial
upload test observes application-level prefix delivery, not kernel backpressure
or provider atomicity. Generation rollback detection requires independently
retained floors; restoring the whole store and every anchor together remains
unsupported. Browser automation proves the authenticated owner protocol and UI
controls, not human attention. Local recipe/custody fixtures do not qualify a
live provider. These are explicit premises, not excuses to omit acceptance tests.

AP070 Google metadata/OAuth/productization remains optional future integration.
Its independent Python/SQLite broker receives no managed permits/credentials and
its receipts carry none of AP074's managed guarantees.

## Local construction and repair execution

All 22 planned artifact selectors executed. The first aggregate had 21 passes and
one invalid test signing window. The repair aggregate and final binding constructor
passed after correcting that window and using an existing registered header; the
closed header registry was preserved. All 13 binding dimensions now execute even
when another case fails, before the constructor reports the combined failures.
All new file/TLS PostgreSQL crash, upload, journal, epoch and floor cases passed.

The complete gateway library run executed 298 passing tests, three failures and
63 ignored tests. Both application failures were stale generated fuzz/frame bytes
transitively using the changed approval fixture; their authoritative constructors
now pass. The other failure was `Unavailable` from a raw file-store race under
concurrent local I/O. The unchanged exact file-store conformance selector passes
in isolation. No production deadline, failure handling or assertion was relaxed.
The final six-selector repair cohort passed, including both dependency adapters
with epoch activation retaining the same approver, both frame constructors,
file-store conformance and source closure. The full concurrent run is not relabeled
as passing. The final hosted broad/adapter/platform cohort remains required.

Gateway all-target/all-feature Clippy, workspace formatting and semantic freeze
checks passed in the aggregate verification phase. The one subsequent source
change isolates epoch from approver replacement in the acquisition test; its two
adapter constructors passed. Source closure is refreshed after that change.
Release metadata advances only the reported identity/public-SDK/public-surface
subjects to 172/168/431, with freeze431. These local results construct and check
the change; they do not close final exact-head hosted or external qualification.
