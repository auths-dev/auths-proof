# AP-SPEC-042: PostgreSQL connection and protected update preflight

## 1. Status and authority

Prelaunch normative specification for `auths.postgresql.connection/1`,
`auths.postgresql.update-preflight/1`, and
`auths.postgresql.bounded-update/1`.

This specification is subordinate to AP-SPEC-040's generic local-agent
protocol and durable ordering and complements AP-SPEC-0009's PostgreSQL action,
evaluation, transaction, reconciliation, and receipt semantics. Where this
document is more restrictive, this document controls the public PostgreSQL
profile package. The relaunch is a clean break: no legacy caller-supplied row
evidence, SQL, bearer credential, or compatibility route is retained.

The purpose of the preflight is to turn a small caller request into trusted,
bounded catalog and row evidence without performing provider I/O during the
later update operation's prepare phase.

## 2. Public workflow

The generated SDK exposes two independently authorized operations:

```text
prepared = postgresql.updatePreflights.create({
  relation,
  tenantKey,
  assignments
})

result = postgresql.updates.execute({
  preparedUpdate: prepared.preparedUpdate
})
```

Python uses `update_preflights.create(...)` and `updates.execute(...)` with the
same generated role types. A caller supplies neither a password nor a token
issued by Auths for the PostgreSQL provider. `preparedUpdate` is an opaque,
short-lived reference to product-owned prepared evidence; it is not a provider
credential or proof of authority.

The preflight and update are separate profile operations with separate proof
decisions, operation IDs, receipts, credential scopes, idempotency keys, and
recovery handles. Successfully preparing an update does not authorize it.

## 3. Connection contract

`auths.postgresql.connection/1` binds exactly one connection to:

- one canonical TLS server identity;
- one database;
- one executor role;
- one TLS server name; and
- one exact certificate-authority bundle digest under
  `auths.postgresql.tls/1`; and
- the byte-sorted exact scope set below.

The JCS descriptor identity is
`auths.postgresql.connection-descriptor/1`. The only launch scope set is:

```text
[
  "postgresql.bounded-update.execute/1",
  "postgresql.update-preflight.create/1"
]
```

Unknown, missing, duplicate, unsorted, or additional scopes invalidate the
descriptor. The descriptor contains no password, client key, credential-store
locator, prepared-update token, or caller-resolvable secret reference.

The account commitment is SHA-256 over a domain separator and
length-delimited server identity, database, executor role, TLS server name,
TLS policy, and certificate-authority digest. Both profiles
bind the connection ID, generation, provider kind, account commitment,
descriptor commitment, and credential commitment into the sealed operation.
Alias resolution supplies only this non-secret metadata and performs no
provider I/O.

Protected onboarding installs a bounded libpq credential/service blob with a
mandatory PEM certificate-authority bundle whose SHA-256 exactly equals the
descriptor commitment. The TLS client trusts only that committed bundle; it
never adds the public WebPKI root set. The
adapter validates the descriptor and credential independently. Every lease
re-reads the connection registry and secret generation and checks the exact
profile scope. Preflight receives read/catalog privileges plus only the row
selection needed by the configured profile. Update receives only the existing
bounded mutation privileges. Neither credential is exposed through the SDK,
prepared record, logs, or receipts. Deployments may use distinct underlying
roles for the two scopes; scope equality, not byte equality of credentials, is
the contract.

### 3.1 Deployment-owned profile configuration

Verifier configuration is neither caller input nor connection metadata. The
deployment supplies it through AP-SPEC-040's agent configuration under this
exact closed table shape:

```toml
[agent.profile_configurations."auths.postgresql.update-preflight/1"]
format = "auths.postgresql.verifier-configuration/1"
path = "/etc/auths/profiles/postgresql-bounded-update-v1.json"
sha256 = "<64 lowercase hexadecimal characters>"
maximum_bytes = 524288

[agent.profile_configurations."auths.postgresql.bounded-update/1"]
format = "auths.postgresql.verifier-configuration/1"
path = "/etc/auths/profiles/postgresql-bounded-update-v1.json"
sha256 = "<the same digest>"
maximum_bytes = 524288
```

Both entries are mandatory and must name the same format, path, digest, and
maximum. `maximum_bytes` must be in `1..=524288`. The path is absolute UTF-8,
contains no `.` or `..` component, and is not beneath the agent's mutable state
directory. The table rejects unknown fields, duplicate profile references,
unregistered profile references, relative paths, non-lowercase digests, and
multiple entries that alias one path with unequal metadata.

Before binding the local socket, startup opens the path with no-follow
semantics, requires one regular file, rejects group/other-writable files and a
file writable by the local caller identity, reads at most
`maximum_bytes + 1`, checks stable file identity/size across the read, verifies
SHA-256, requires canonical domain bytes, and invokes the statically registered
PostgreSQL configuration validator. Any failure aborts startup. The validated
bytes, digest, secure path metadata, and file identity form an immutable
`ProfileConfigurationBinding`; there is no live reload. Changing configuration
requires an agent restart and makes existing prepared records unusable.

The shared config loader validates only file safety, bounds, format identity,
and digest. Build-time static roster dispatch calls the concrete PostgreSQL
validator; no trait object, callback, registry plugin, or domain branch is
added to shared lifecycle code. `ProfileOperationContext` receives the exact
immutable binding for its profile. Prepare parses that binding locally and
binds its digest into the canonical action without provider I/O. After command
sealing and before credential lease, the agent securely re-reads the same path,
repeats the file/digest checks, and requires byte equality with the startup
binding. Inequality is a pre-provider configuration failure and requires
restart; the operation never falls back to a connection descriptor or caller
value.

## 4. Restricted public API

`api/profile-api.json` is the wire authority. Its launch roles are:

```text
Assignment {
  column: canonical unquoted PostgreSQL identifier
  value: bounded UTF-8 text value
}

UpdatePreflightInput {
  relation: "schema.table"
  tenantKey: bounded tenant value
  assignments: 1..32 Assignment
}

PreparedUpdate {
  preparedUpdate: opaque registered-token
  actionDigest: lowercase SHA-256
  matchedRows: 1..256
  expiresAt: Unix seconds
}

PreparedUpdateInput {
  preparedUpdate: opaque registered-token
}

UpdateResult {
  affectedRows: 1..256
  afterStateDigest: lowercase SHA-256
}
```

`relation` is exactly two `PgIdentifier` values separated by one dot.
`Assignment.column` is a `PgIdentifier`. No quoted identifiers, search path,
wildcards, predicates, operators, expressions, casts, SQL fragments, or
caller-selected tenant column are accepted. The verifier configuration owns
the tenant column and permitted assignments for each relation. This launch API
maps all assignment and tenant values to the configured PostgreSQL text type;
adding other `TypedValueV1` variants requires a new profile version.

Assignments are sorted by column during canonicalization; duplicates fail.
Input strings undergo the AP-SPEC-040 UTF-8 checks and the domain's required
NFC validation. There is no lossy normalization.

## 5. Update-preflight profile

### 5.1 Identity and effect

The profile is `auths.postgresql.update-preflight/1`, effect
`postgresql.update-preflight.create`, credential scope
`postgresql.update-preflight.create/1`, and client method
`updatePreflights.create`.

It is a provider-reading effect. The operation is not a shortcut around
AP-SPEC-040: its own prepare phase must complete proof verification, evaluation,
durable decision, reservation, and command sealing before it leases a
credential or queries PostgreSQL.

### 5.2 Canonical preflight action

The domain canonicalizer parses the relation and assignments, resolves the
connection's non-secret snapshot, loads the installed verifier configuration,
and produces `PostgresUpdatePreflightActionV1` containing:

- profile identity;
- exact connection ID, generation, account and descriptor commitments;
- database audience and database name;
- schema and relation names;
- configured tenant column and the committed tenant value;
- sorted text assignments;
- configured maximum rows, permitted columns, evidence maximum age, and
  prepared-record lifetime;
- verifier-configuration digest; and
- the generic request/session commitments required by AP-SPEC-040.

This construction performs no credential request, network access, DNS, socket
open, SQL, catalog lookup, or row lookup. Policy evaluates this bounded read
request and the requested mutation shape before any provider access.

### 5.3 Sealed discovery command and provider access

After the durable decision and generic reservation, sealing:

1. generates a cryptographically random `pupd_` registered-token with at least
   256 bits of entropy;
2. durably reserves its SHA-256 store key for the operation ID;
3. seals and durably records the exact discovery command, including the token
   hash, action digest, fixed query identities, and all bounds;
4. re-reads the exact prepared-store reservation, connection snapshot, and
   verifier configuration;
5. proves equality with the evaluated action;
6. leases scope `postgresql.update-preflight.create/1`; and
7. records the PostgreSQL entry marker before executing the sealed command.

The fixed discovery transaction reads the configured catalog, role, RLS,
policy, trigger, privilege, primary-key, row-version, and candidate-row facts.
It does not execute caller SQL and does not mutate provider state. The domain
builds and validates the complete `PostgresEvidenceV1`,
`PostgresBoundedUpdateIntentV1`, compiled parameterized statement template,
and `PostgresBoundedUpdateV1` from that observation.

The provider result is durably recorded before profile observation. A success
is returned only after the prepared record in section 7 is atomically `ready`.
The returned `actionDigest`, `matchedRows`, and `expiresAt` are copied from that
record. Zero rows, more than 256 rows, stale evidence, unsafe catalog/role/RLS
facts, a forbidden assignment, or any configuration mismatch denies and does
not create a usable token.

## 6. Bounded-update profile

The profile remains `auths.postgresql.bounded-update/1`, effect
`postgresql.bounded-update.execute`, credential scope
`postgresql.bounded-update.execute/1`, and client method `updates.execute`.
Its only public input is `PreparedUpdateInput`.

During prepare, after connection metadata resolution, the domain performs a
local-only lookup by the token's SHA-256 store key. It rejects missing,
expired, non-ready, already claimed, wrong-principal, wrong-profile,
wrong-connection, wrong-generation, wrong-account, wrong-descriptor, or
malformed records. It revalidates canonical bytes and every stored digest. It
then uses the stored `PostgresBoundedUpdateV1` as the canonical authorization
action. The token is never itself the action and never grants authority. This
lookup performs no provider I/O and requests no credential.

After decision and generic reservation, command sealing atomically changes the
prepared record from `ready` to `claimed(operationId)`. Re-entry by that same
operation ID is idempotent; every other operation is denied. Sealing then
re-reads the record, connection snapshot, and verifier configuration, proves
exact equality, and leases the execute credential.

After the provider entry marker, the existing SERIALIZABLE gateway rechecks
the catalog fingerprints, role/RLS facts, exact primary-key row set, row
versions, and before-value commitments inside the transaction. Only then may
it execute the fixed compiled statement. Cardinality and after-state checks,
provider-result durability, observation, reconciliation, and linked receipts
remain exactly those of AP-SPEC-0009.

The record becomes `consumed(operationId)` only with the terminal successful
operation. A pre-provider terminal denial releases a claim only when durable
state proves PostgreSQL was not entered. Possible entry retains the claim
until reconciliation is conclusive. The update is never automatically retried
under a new operation ID.

## 7. Prepared-update store

The PostgreSQL vertical owns a durable `PreparedUpdateStore`; it is not added
as a callback, trait object, or domain-aware branch in the shared runtime.
Build-time static wiring supplies it only to the PostgreSQL profile functions.

Each bounded record contains, at minimum:

```text
schema = auths.postgresql.prepared-update/1
tokenSha256
ownerPrincipalCommitment
preflightOperationId
connectionId
connectionGeneration
accountCommitment
descriptorCommitment
credentialCommitment
canonicalActionBytes
actionDigest
evidenceBytes
evidenceDigest
verifierConfigurationBytes
verifierConfigurationDigest
compiledStatementTemplateDigest
matchedRows
createdAt
expiresAt
state = reserved | ready | claimed(operationId) | consumed(operationId) | expired
```

Canonical action, evidence, and configuration bytes are independently decoded,
re-encoded, bounded, and digest-checked at every transition. The store never
contains a PostgreSQL credential or raw caller token. Reservation, readiness,
claim, release, consumption, and expiry transitions are compare-and-swap and
durable. Token lookup is constant-time with respect to stored keys.

The default lifetime is 300 seconds and the hard maximum is 900 seconds. A
record is never valid beyond the source connection generation or configuration
version. Expiry is fail-closed and cleanup cannot turn an unresolved execution
into retry-safe state. Per-principal record count and byte quotas must be no
weaker than the profile manifest's durable quotas.

## 8. Recovery, receipts, and stable failures

Preflight recovery first checks its generic journal and then the reserved token
key. `ready` reconstructs the exact success; `reserved` after possible provider
entry is recovery-required until discovery/store reconciliation completes.
Discovery may be repeated only for the same sealed preflight command and must
replace no ready record.

Neither decision nor execution receipts contain tenant values, assignment
values, row values, credentials, canonical evidence bytes, or the plaintext
prepared token. They commit the token hash, action/evidence/configuration
digests, connection generation, affected row count, provider-entry truth, and
prepared-record transition.

Profile fragments own at least:

- `postgresql.preflight-denied`;
- `postgresql.preflight-outcome-unknown`;
- `postgresql.update-denied`; and
- `postgresql.update-outcome-unknown`.

Unknown prepared tokens project through the bounded-update denial family and
do not reveal whether a token exists for another principal or connection.

## 9. Required implementation and qualification

The implementation is incomplete until all of the following exist:

1. a concrete read-only discovery gateway and least-privilege credential path;
2. the durable `PreparedUpdateStore` and state machine above;
3. concrete static local-agent functions
   `update_preflights_create_*` and `updates_execute_*` generated by the roster;
4. `AgentConfig.profile_configurations`, secure startup loading, immutable
   `ProfileConfigurationBinding`, static PostgreSQL validation, and pre-entry
   re-read/equality enforcement from section 3.1;
5. descriptor/fixture support for both exact scopes;
6. Rust error-registry definitions matching both profile fragments;
7. crash tests immediately before and after every durable/provider boundary;
8. mutation tests for every binding, expiry, replay, row/catalog drift, and
   cross-principal substitution invariant; and
9. a live PostgreSQL contract proving preflight, approval, one execution,
   denial, replay behavior, recovery, and receipt verification.

Until those gates pass, both profiles remain statically advertised only as
unavailable; no stub may return a fabricated prepared token or update result.
