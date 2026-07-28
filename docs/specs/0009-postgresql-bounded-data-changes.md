# 0009: Auths for bounded PostgreSQL data changes

Status: Proposed  
Target: MVP plus public end-to-end demonstration  
Profile: `auths.postgresql.bounded-update/1`  
Product package: `product/integrations/auths-postgresql`  
Demo: `demos/postgresql-data-change`

## 1. Decision

Build one vertical PostgreSQL product package that lets an untrusted agent propose a typed, bounded data update without possessing a database credential.

The first profile updates an already resolved set of rows in one table and tenant. It is not arbitrary SQL. The trusted package compiles a canonical mutation intent into fixed parameterized SQL, rechecks every row inside a transaction, records an execution ledger row atomically with the mutation, and commits only when exact cardinality and after-state checks pass.

## 2. Product claim

Database roles can permit `UPDATE` on a table or column. Row-level security can constrain which rows a role sees or modifies. Auths adds authority for one exact transition:

> update precisely these primary keys, in this tenant, from these committed prior values to these exact new values, under this schema and policy configuration, once, before expiry.

The proposing agent receives no connection string, password, client certificate, cloud database token, or reusable query capability.

## 3. Goals

The MVP must:

1. define a typed mutation language with no raw SQL field;
2. bind authorization to database, schema, table, tenant, row identities, before state, after state, and cardinality;
3. enforce schema, role, row-security, and session assumptions;
4. acquire mutation credentials only after claim;
5. recheck and mutate within one serializable transaction;
6. write a unique in-database execution ledger atomically with the update;
7. roll back on any mismatch;
8. create privacy-aware receipts;
9. expose required and executed verifier configuration; and
10. demonstrate the exact transition in a real PostgreSQL deployment.

## 4. Non-goals

The MVP does not support:

- raw SQL;
- `INSERT`, `DELETE`, `MERGE`, DDL, `TRUNCATE`, `COPY`, or `CALL`;
- joins or subqueries supplied by the agent;
- multiple tables;
- updates without a tenant key;
- expressions as new values;
- stored procedures or writable functions;
- tables with unapproved triggers or generated side effects;
- database administration;
- schema migration; or
- access to arbitrary production data.

## 5. Threat model

The profile must prevent:

- widening a predicate after authorization;
- changing one primary key;
- crossing tenants;
- updating an additional column;
- changing a value between inspection and mutation;
- exploiting `search_path`;
- bypassing row-level security;
- invoking a trigger or function with hidden effects;
- changing session settings or transaction isolation;
- executing the same mutation twice;
- treating a serialization retry as permission to derive a different action; and
- leaking row values into public receipts.

## 6. Vertical package

```text
product/integrations/auths-postgresql/
  Cargo.toml
  src/
    lib.rs
    action.rs
    value.rs
    canonical.rs
    schema.rs
    evidence.rs
    profile.rs
    compiler.rs
    executor.rs
    ledger.rs
    receipts.rs
    errors.rs
  migrations/
    auths_execution_ledger.sql
  tests/
    fixtures/
    conformance/
```

PostgreSQL identifiers, types, catalogs, transactions, rows, RLS, SQL generation, and error mapping stay inside the package. Core remains database-neutral.

## 7. Typed mutation intent

```text
PostgresBoundedUpdateIntentV1 {
  profile
  database_audience
  database_name
  schema_name
  table_name
  tenant_column
  tenant_value
  primary_key_columns
  rows
  assignments
  expected_row_count
  schema_fingerprint
  policy_fingerprint
  required_configuration
  expires_at
  nonce
}

RowPreconditionV1 {
  primary_key
  before_value_commitments
  row_version
}

AssignmentV1 {
  column
  typed_value
}
```

There is deliberately no SQL string, operator, function, ordering, limit, returning expression, or free-form predicate.

Rows are sorted canonically by their typed primary-key encodings. Columns are sorted by canonical identifier. Duplicate rows or assignments are malformed.

## 8. Typed values and canonicalization

The MVP supports only an explicit type allowlist, initially:

- boolean;
- signed bounded integers;
- UTF-8 text with byte limits;
- UUID;
- fixed-precision decimal with declared scale;
- UTC timestamp with fixed precision; and
- enumerated text values declared by configuration.

Floating-point, arrays, JSON mutation, binary blobs, ranges, composite values, and database expressions are deferred.

Canonical values preserve type. Text `"1"`, integer `1`, and decimal `1.00` are different. Unicode normalization policy, timestamp precision, decimal scale, and null handling are fixed by the profile version.

## 9. Discovery and evidence

The protected read path resolves the candidate rows and returns:

- authenticated server and database audience;
- database, schema, table, and relation OID;
- primary-key and tenant-key definitions;
- column names, types, nullability, defaults, and generated status;
- schema fingerprint;
- enabled trigger inventory and definitions;
- row-security enabled/forced state;
- applicable policy fingerprint;
- executor role identity and relevant privilege fingerprint;
- current row primary keys and committed before values;
- row-version value or configured concurrency token;
- expected cardinality;
- server version;
- observation timestamp; and
- evidence-source configuration.

The read path may return row values to the authorized local UI for the synthetic demo. General receipts and logs use commitments by default.

Evidence is stale when any committed row, schema, policy, trigger, role, or concurrency token changes.

## 10. Schema and policy restrictions

The target table must:

- have an approved primary key;
- have an immutable tenant-key column included in every action;
- have row-level security enabled and forced for the executor role, unless the configuration explicitly selects an equally strict isolated database;
- have no unapproved trigger;
- have no rewrite rule;
- have no writable generated column among assignments;
- have no foreign-table or partition-routing behavior unsupported by the profile; and
- use only supported column types.

The executor role must not:

- own the table;
- have `BYPASSRLS`;
- have DDL, `TRUNCATE`, `CREATE`, role-management, replication, or broad function-execution privileges;
- change `session_authorization`; or
- access other tenants through a different code path.

## 11. Canonical action

The final action adds resolved evidence commitments:

```text
PostgresBoundedUpdateV1 {
  intent
  database_server_identity
  relation_oid
  executor_role
  row_set_digest
  before_state_digest
  after_state_digest
  compiled_statement_template_digest
  evidence_digest
  observed_at
}
```

`compiled_statement_template_digest` commits to the trusted package’s fixed SQL template version, not an agent-provided statement.

## 12. Required and executed configuration

```text
PostgresVerifierConfigurationV1 {
  profile
  canonicalization_version
  allowed_database_audiences
  allowed_databases
  allowed_relations
  tenant_column_by_relation
  primary_key_columns_by_relation
  allowed_assignment_columns
  allowed_value_constraints
  maximum_rows
  maximum_evidence_age_seconds
  maximum_authorization_lifetime_seconds
  required_isolation_level
  required_row_security
  allowed_trigger_fingerprints
  statement_timeout_ms
  lock_timeout_ms
  receipt_schema_version
}
```

The decision contains both `required_configuration` and `executed_configuration`. They must be canonically identical.

A mandatory unit test authorizes three rows with `maximum_rows = 3`, verifies using an otherwise identical configuration with `maximum_rows = 4`, and expects `verifier-configuration-mismatch` before claim or credential acquisition.

## 13. Transaction protocol

After proof verification and successful claim, the executor:

1. obtains a protected short-lived database credential;
2. opens a new connection with a pinned driver;
3. begins a `SERIALIZABLE`, read-write transaction;
4. sets a fixed role, fully qualified object names, empty or fixed `search_path`, statement timeout, lock timeout, and application name;
5. verifies server, database, role, schema, policy, and trigger fingerprints;
6. inserts the unique action digest into `auths_execution_ledger`;
7. selects the committed primary keys for the committed tenant `FOR UPDATE`;
8. verifies exact row count, row identities, concurrency tokens, and before-state digest;
9. executes a parameterized `UPDATE` against those exact keys and tenant;
10. uses `RETURNING` to verify exact cardinality and after-state digest;
11. finalizes the ledger row with the result commitment; and
12. commits.

Any mismatch or database error rolls back both the mutation and ledger insertion.

The driver must use protocol parameters. Quoting identifiers in trusted generated SQL is not permission to accept agent SQL.

## 14. In-database execution ledger

The product migration creates a protected table conceptually equivalent to:

```text
auths_execution_ledger (
  action_digest PRIMARY KEY,
  claim_id UNIQUE,
  profile,
  relation_oid,
  tenant_commitment,
  row_set_digest,
  before_state_digest,
  after_state_digest,
  affected_rows,
  committed_at,
  receipt_digest
)
```

The executor role may insert a row only through the package’s fixed transaction path and may read by action digest for reconciliation. Application roles cannot alter ledger records.

The external Auths claim prevents concurrent execution before credential use. The in-database unique ledger and atomic commit prove whether the database effect committed. Neither replaces the other.

## 15. Serialization and replay

A serialization failure means the transaction did not commit. The executor may retry the same verified action only when:

- the durable claim remains owned by the same execution;
- retry count and total duration are bounded;
- every precondition is rechecked;
- no action bytes or configuration change; and
- the ledger proves no prior commit.

If rechecking finds changed state, the action fails stale and requires new evidence and authorization.

Client disconnect after `COMMIT` is an ambiguous outcome. Reconciliation reads the ledger using a fresh connection. It must not blindly issue the update again.

## 16. Privacy and receipts

### Decision receipt

Contains action digest, proof identity, required/executed configuration, evidence digest and age, relation and tenant commitments, row count, verdict, code, and stage.

### Transaction receipt

Contains claim ID, database audience commitment, relation OID, row-set digest, before/after digests, affected count, transaction outcome, ledger commitment, server version, and timestamps.

### Observation receipt

Contains a fresh read-back commitment and whether it equals the authorized after state.

Production receipts do not expose primary keys, tenant values, or column values by default. The synthetic public demo may display its own seeded records while receipts remain representative of private defaults.

## 17. Stable codes

- `malformed-mutation`
- `unsupported-profile`
- `unsupported-value-type`
- `proof-invalid`
- `verifier-configuration-mismatch`
- `evidence-stale`
- `database-audience-mismatch`
- `schema-fingerprint-mismatch`
- `policy-fingerprint-mismatch`
- `trigger-fingerprint-mismatch`
- `relation-mismatch`
- `tenant-mismatch`
- `row-set-mismatch`
- `before-state-mismatch`
- `row-limit-exceeded`
- `column-not-authorized`
- `value-constraint-failed`
- `already-claimed`
- `credential-unavailable`
- `transaction-conflict`
- `cardinality-mismatch`
- `after-state-mismatch`
- `database-execution-failed`
- `execution-outcome-unknown`

## 18. End-to-end demo

### Scenario

Use a dedicated PostgreSQL database containing synthetic support or analytics records. The primary scenario authorizes:

> mark exactly three named stale demo accounts as reviewed, changing only `review_status` from `pending` to `reviewed`.

The UI shows:

- the three resolved rows before execution;
- the typed mutation and allowed column;
- proof and configuration verdict;
- transaction and ledger state;
- the three rows after commit; and
- linked decision and transaction receipts.

### Experiments

- exact three-row transition;
- an extra row added;
- tenant changed;
- one before value changed;
- forbidden column added;
- new value outside the configured enum;
- schema or RLS policy changed;
- verifier configuration changed; and
- replay after commit.

Controls and results remain adjacent. The visitor should see precisely which rows were authorized and whether the transaction committed without scrolling to a separate result section.

### Frontend delivery contract

The frontend is a required part of the implementation, not optional follow-up work. A backend-only implementation, API explorer, static mockup, or page that never reaches the native transaction executor does not satisfy this specification.

Follow the established GitHub and Radicle demo interaction model:

- one primary workbench places selectable experiments beside the current verdict and transaction result;
- selecting an experiment immediately updates the exact typed row changes and predicted decision;
- executing it calls the deployed native backend and renders its returned stable code, configuration commitments, claim state, database effect, and receipt links;
- loading, unavailable, denied, indeterminate, authorized, committed, reconciled, and replay states are visibly distinct;
- the successful path performs the real sandbox transaction, while every denied path proves that no database mutation occurred; and
- desktop and mobile layouts keep the control that caused a result adjacent to that result.

Browser-level end-to-end tests must start from the rendered page and exercise readiness, exact commit, at least one material denial, replay, post-commit row read-back, and receipt inspection through the same public API routes used in production. Static DOM assertions and backend-only integration tests are necessary but insufficient.

Completion requires a publicly reachable frontend URL and a publicly reachable native API deployment. Opening `index.html` through `file://`, serving only on localhost, committing Vercel/Fly configuration without deploying it, or deploying a frontend whose API is unavailable does not satisfy this specification. Before handoff, test the public Vercel URL against the public Fly deployment and record the tested URLs and release identifiers.

### Deployment and design

Use `auths-proof-site` visual language and plain, factual copy. Deploy the frontend on Vercel, the native service on Fly.io, and a dedicated synthetic PostgreSQL database with encrypted transport, restricted networking, backups appropriate to demo data, and an idempotent reset mechanism.

The agent-facing service and frontend have no database mutation credential. The native service exposes health/readiness without testing destructive access. Configuration documents CORS, regions, connection pooling, migration ownership, secret injection, database reset, retention, and incident shutdown.

## 19. Testing

### Unit and conformance

- typed value canonicalization;
- Unicode, decimal, timestamp, null, and identifier edge cases;
- hard row, value, and payload limits;
- duplicate keys and columns;
- required/executed configuration mismatch;
- schema, policy, trigger, row-set, before-state, and after-state fixtures;
- generated parameterized SQL snapshots;
- browser/native decision parity;
- stable error mapping.

### Integration

- exact commit and atomic ledger insert;
- changed row before lock;
- concurrent updater;
- concurrent duplicate Auths execution;
- RLS denial;
- forbidden role privileges;
- serialization retry;
- statement and lock timeout;
- trigger or schema change;
- disconnect before and after commit;
- reconciliation through ledger;
- transaction rollback leaves neither mutation nor ledger row.

### Security

- SQL injection strings remain values;
- `search_path` attacks fail;
- credentials are absent from frontend, logs, errors, traces, and receipts;
- executor role cannot update another table or tenant;
- agent cannot submit SQL or change session parameters; and
- denial paths never acquire a mutation credential.

### CI

Enforce package boundaries, deterministic fixtures, migration checks, supported PostgreSQL version matrix, offline conformance tests, separate live database tests, WASM/native dependency separation, and workspace Rust policies.

## 20. Acceptance criteria

1. The agent proposes a typed mutation without database credentials.
2. The action commits to exact rows, tenant, before state, after state, schema, policy, and configuration.
3. The executor claims before acquiring a credential.
4. Exact preconditions are rechecked inside the mutation transaction.
5. Mutation and ledger commit atomically.
6. Any extra row, field, tenant, or value denies or rolls back.
7. Replay cannot produce a second database effect.
8. Ambiguous commit outcomes reconcile from the ledger.
9. Receipts preserve privacy while proving cardinality and state commitments.
10. Browser and native verdicts match.
11. The public demo shows a real PostgreSQL state transition.
12. Core crates remain independent of PostgreSQL.
13. The deployed frontend completes exact, denial, replay, row-observation, and receipt flows against the deployed native backend.
14. Browser-level end-to-end tests fail if frontend/backend wiring, CORS, readiness, interaction, or result rendering breaks.

## 21. Deferred work

- inserts and deletes;
- cross-table transactions;
- arbitrary predicates;
- stored procedures;
- JSON and array updates;
- CDC-backed observations;
- logical replication evidence;
- database migrations;
- data-warehouse adapters;
- human-readable privacy proofs; and
- shared relational abstractions extracted only after a second database engine validates them.
