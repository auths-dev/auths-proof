# Epic 2 — Qualify the PostgreSQL Lifecycle Store

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** Epic 1 and AP-SPEC-026

**Blocks:** Epics 3, 5, 7, 8, and 9

## Outcome

Turn the existing correctness-reference PostgreSQL adapter into a bounded,
TLS-only, pooled, multi-host production store without changing lifecycle
meaning. Prove linearizable all-or-none reservation, honest acknowledgement,
crash recovery, failover behavior, corruption detection, saturation behavior,
backup, and restore.

## Zero-context starting point

Read:

- `product/runtime/auths-lifecycle/src/model.rs`;
- `product/runtime/auths-lifecycle/src/transition.rs`;
- `product/runtime/auths-lifecycle/src/sealed.rs`;
- `product/runtime/auths-lifecycle/src/codec.rs`;
- `product/stores/auths-stores/src/lifecycle.rs`;
- `product/stores/auths-stores/migrations/postgres_lifecycle_v3.sql`;
- `product/stores/auths-stores/tests/postgres_lifecycle.rs`;
- `product/fixtures/v1/lifecycle/`; and
- `docs/specs/0026-reservation-and-execution-state-semantics.md`.

Current behavior:

- `LifecycleStore::transact` accepts one `StoreTransactionV1` and returns a
  `StoredTransitionV1`.
- `execute_store_transaction` validates the adapter acknowledgement before it
  creates a `DurableTransitionV1`.
- `PostgresLifecycleStore` currently holds one blocking `postgres::Client`
  behind a process mutex, uses `NoTls`, locks one singleton metadata row,
  reloads all records, applies the pure transition, writes one canonical row,
  and acknowledges only after commit.
- The current ignored integration test proves final-capacity serialization,
  restart replay/conflict, transaction abort, and atomic multi-intent failure.

The singleton database lock is a valid correctness baseline. Do not replace it
with row-level capacity locking until measurements prove it is the bottleneck
and differential tests can prove the optimized implementation equivalent.

## Product constraint

Production store setup must feel like a Stripe integration, not database
framework assembly:

```rust
let store = PostgresLifecycleStore::connect(PostgresStoreConfig::from_env()?)?;
```

The default constructor is TLS-only, bounded, and ready for multiple runtime
processes. Callers do not choose transaction isolation, lock order, retry
policy, schema SQL, or acknowledgement semantics.

Errors expose stable safe categories and recommended actions. They never echo
the connection string, SQL, host, username, record bytes, or database error.

## UX

The operator configures one validated `PostgresStoreConfig`, runs `auths
doctor`, and receives a closed readiness result. Pool sizing, TLS identity,
schema identity, and bounded timeouts are visible in a safe summary; connection
material and raw driver errors are never displayed. The normal application SDK
does not expose the store at all—`execute` and `resume` use it through the Rust
runtime.

## Architecture

```text
runtime A ----+
runtime B ----+--> bounded connection pool --> PostgreSQL primary
runtime C ----+             |                       |
                            |                       +--> synchronous standby
                            |
                            +--> transaction:
                                 checkout deadline
                                 lock contract row
                                 load + validate
                                 pure apply_transition
                                 write canonical record
                                 COMMIT
                                 validate acknowledgement
```

The database stores canonical lifecycle bytes plus redundant indexes and
digests. Rust lifecycle code remains authoritative. SQL constraints and
indexes are defense in depth, not an alternate transition implementation.

## APIs and types

Replace the string constructor directly; do not keep a deprecated overload.

```rust
pub struct PostgresStoreConfig {
    connection: SecretConnectionString,
    tls: PostgresTlsConfig,
    pool: PostgresPoolConfig,
    maximum_records: usize,
    rules: Vec<LifecycleCapacityRuleV1>,
}

pub struct PostgresTlsConfig {
    root_certificate: PathBuf,
    expected_server_name: ServerName,
}

pub struct PostgresPoolConfig {
    minimum_connections: u16,
    maximum_connections: u16,
    checkout_timeout: Duration,
    statement_timeout: Duration,
    lock_timeout: Duration,
    idle_timeout: Duration,
}

impl PostgresLifecycleStore {
    pub fn connect(config: PostgresStoreConfig)
        -> Result<Self, LifecycleStoreConfigurationError>;
    pub fn load(&self, workflow: &WorkflowId)
        -> Result<Option<LifecycleRecordV1>, StoreError>;
    pub fn probe(&self) -> Result<PostgresStoreHealth, StoreError>;
}
```

`SecretConnectionString` must not implement `Debug`, `Display`, `Clone`,
serialization, or equality. Its bytes are zeroized on drop where the selected
driver permits ownership. Configuration summaries expose only
`postgresql-v1`, pool bounds, TLS-required, and schema/contract identities.

Extend closed store outcomes so callers can distinguish:

- unavailable connection/database;
- pool saturated or checkout timeout;
- transaction conflict/deadlock;
- statement or lock timeout;
- schema/contract mismatch;
- corrupt canonical state/index/digest;
- hard record/work limit; and
- invalid acknowledgement.

Map driver errors by SQLSTATE and operation stage into these values. Unknown
driver errors map to unavailable. Never expose raw driver text through public
SDKs or telemetry.

## Storage contract

The candidate schema keeps:

- one immutable contract metadata row;
- one row per workflow containing workflow ID, revision, state code, canonical
  record bytes, and SHA-256 digest;
- fixed checks on identifier length, revision, state range, byte length, and
  digest length; and
- no trigger or stored procedure that implements Auths state transitions.

Startup must:

1. connect with certificate and server-name verification;
2. set application name without tenant/request data;
3. verify server version and required transaction features;
4. install the current prelaunch schema only into an empty database;
5. verify `schema_version` and `contract_id` exactly;
6. set bounded session statement/lock/idle-in-transaction timeouts;
7. run a read-only canonical integrity sample; and
8. fail readiness on mismatch.

There are no in-place migrations in this prelaunch epic. A changed schema gets
a new schema version and contract identity; disposable development databases
are recreated.

## Implementation steps

- [ ] Add centrally versioned Rustls-compatible PostgreSQL pooling dependencies
  to the workspace after license/MSRV/advisory review. Use a maintained pool;
  do not implement an ad hoc connection scheduler.
- [ ] Replace `Mutex<Client>` with a bounded pool whose checkout has a hard
  deadline.
- [ ] Remove the production `NoTls` path. Test-only plaintext helpers, if
  unavoidable for unit tests, remain private under `cfg(test)` and are not
  reachable through shipping constructors.
- [ ] Parse pool and TLS inputs into closed bounded types in `auths-config`.
- [ ] Apply session timeouts on every new connection and verify them in the
  connector's initialization hook.
- [ ] Preserve singleton contract-row serialization for the first measured
  implementation.
- [ ] Reload and validate canonical records while holding the contract lock;
  enforce `maximum_records` before allocation.
- [ ] Ensure every failed validation, pure transition, SQL write, trigger,
  connection loss, or commit abort leaves no acknowledged mutation.
- [ ] Treat an error during or after commit as unavailable/indeterminate to the
  caller; exact replay on the next attempt determines whether the transition
  committed.
- [ ] Add a read-only `probe` that checks connection, contract row, and bounded
  integrity without claiming authorization or provider health.
- [ ] Add privacy-safe pool saturation, checkout, transaction, conflict,
  timeout, corruption, and commit metrics through `auths-operations`.
- [ ] Update architecture, compliance, semantic-freeze, dependency snapshots,
  and release subjects for intentional dependency/schema changes.

## Fault harness

Add `demos/testkit/auths-production-testkit` only if the harness is reused by
Epics 3, 8, and 9; otherwise keep the initial harness under
`product/stores/auths-stores/tests/`. A new package must be classified in
`architecture.toml` and `compliance.toml`.

The Docker test topology contains:

- one TLS-enabled PostgreSQL primary;
- one synchronous standby or a documented failover proxy/test topology;
- three independently killable Rust client processes;
- a network fault proxy for connection cuts and partitions; and
- a clean restore target.

The harness records only generated workflow IDs and aggregate outcomes. It
must exercise:

- 1,000 concurrent transaction deliveries across three processes;
- simultaneous claims for the final additive and exclusive capacity;
- atomic failure of a multi-intent reservation;
- exact replay and conflicting replay from different hosts;
- process death before transaction, during write, during commit, and after
  server commit before client acknowledgement;
- pool exhaustion and checkout timeout;
- PostgreSQL restart and primary failover;
- connection cuts during load, write, and commit;
- deadlock and lock timeout injection;
- malformed bytes, digest mismatch, index mismatch, oversized rows, duplicate
  metadata, and schema mismatch;
- `pg_dump`/base-backup according to the reference topology and restore into a
  clean environment; and
- rollback to an older snapshot detected by an external backup-generation or
  deployment commitment, never accepted silently.

For every schedule assert:

- no false durable acknowledgement;
- no two incompatible revisions both succeed;
- no capacity over-allocation;
- no partial multi-intent reservation;
- exact replay recovers uncertain commit acknowledgement;
- corrupt state never produces `DurableTransitionV1`; and
- restored canonical records produce the same lifecycle and receipt digests.

## Performance gate

Measure at the frozen Epic 1 load envelope. Report checkout, lock-wait,
transaction, and end-to-end p50/p95/p99 plus saturation throughput.

If singleton serialization passes the declared envelope, keep it. If it fails,
open a separate abstraction case file before introducing incremental capacity
tables or partitioned locking. The optimized store must run the same generated
transaction corpus against the in-memory reference and singleton PostgreSQL
implementation and compare decisions, revisions, capacity, events, receipts,
and work bounds exactly.

## Validation commands

```text
cargo test -p auths-lifecycle
cargo test -p auths-stores
AUTHS_LIFECYCLE_POSTGRES_URL=<dedicated-test-url> \
  cargo test -p auths-stores --test postgres_lifecycle -- --ignored
cargo xtask arch
cargo xtask compliance
cargo xtask semantic-freeze
```

The production fault harness must also have one CI job that provisions the TLS
database topology and uploads a redacted result artifact.

## Exit gate

This epic is complete when the TLS-only pooled adapter passes the multi-host
fault matrix, backup/restore reproduces exact canonical records, uncertain
commit acknowledgement resolves through exact replay, limits and saturation
are measured, no secret reaches errors or telemetry, and the candidate
manifest binds the exact schema and store implementation identities.
