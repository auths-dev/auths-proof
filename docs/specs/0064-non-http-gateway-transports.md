# AP-SPEC-064: Non-HTTP gateway transports, PostgreSQL first

- **Status:** Draft, written on owner direction on 2026-09-28 before its
  epics started. No epic has started. §13's readings are PROVISIONAL until
  the owner reviews them.
- **Depends on:** [AP-SPEC-063](0063-generalized-gateway.md) (the recipe
  `/2` machinery, the admission step machine, one spend limit, the operator
  plane, connection record `/2`, outcome and audit `/2`, and the formal
  obligations of its §11), [AP-SPEC-053](0053-declarative-credential-isolated-gateway.md)
  (gateway, approval by digest, execution and claim truth),
  [AP-SPEC-059](0059-commitment-bound-provider-evidence.md) (the echo token),
  [AP-SPEC-0009](0009-postgresql-bounded-data-changes.md) and
  [AP-SPEC-042](0042-postgresql-connection.md) (the PostgreSQL vertical's
  semantics), [AP-SPEC-0008](0008-opentofu-saved-plan-apply.md) and
  [AP-SPEC-043](0043-opentofu-connection.md) (the OpenTofu vertical's
  semantics), [AP-SPEC-061](0061-end-to-end-machine-checked-verifier.md)
  §3.4 (extraction rules),
  [ADR 0012](../adr/0012-declarative-credential-isolated-gateway-boundary.md),
  [ADR 0013](../adr/0013-recipe-capabilities-and-sum-budget.md), and the
  [boundary plan](../target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md).
  The `exec` phase also depends on an external release: a digest-pinned
  [Proofbound Runtime](https://github.com/bordumb/proofbound-runtime) release
  with typed network egress (§6.4).
- **Enables:** a production path for PostgreSQL writes, with credential
  isolation, a conditional write, and an ambiguous commit that always
  resolves when the database is reachable; and, as a later phase, a narrowly
  scoped OpenTofu saved-plan apply (§6). Both lost their production path
  under 063 §12 option A.
- **Retires:** recipe source `/2` and its digest domain
  `auths.gateway-compiled-recipe/2`; review `/2`; recovery capability `/1`;
  attempt record `/3`; outcome `/2`; audit bundle and report `/2`; connection
  descriptor `auths.gateway-connection-descriptor/1`; and the "no production
  path" sentences for PostgreSQL and OpenTofu in ADR 0012, the boundary plan,
  0008, 0009, 042, and 043 (§11).
- **Scope:** product layer only: `product/runtime/auths-gateway` (a new
  `transport/` module with `https.rs`, `postgresql.rs`, and `exec.rs`),
  `product/runtime/auths-connections` (descriptor `/2`),
  `product/tools/auths-openapi-derive` (writes `/3`), `auths-node gateway
  recipe check`, the Python and TypeScript gateway clients (outcome `/3`),
  `product/integrations/auths-postgresql` and
  `product/integrations/auths-opentofu` as test-only references,
  `formal/Auths/Product/`, and a new example under `examples/`. No core
  change.
- **Normative language:** **MUST**, **MUST NOT**, **SHOULD**, and **MAY** specify
  implementation requirements

## 1. Decision and claim

063 §12 option A made the gateway the single provider-write path. A provider
that is not reached over HTTPS lost three things: credential isolation, an
Auths-run executor, and proved admission. Only the self-hosted adapter path
(AP-SPEC-054) remains for it, and there the application holds the
credential. The owner wants parity: the same recipe authoring and the same
security for such providers.

This spec makes the gateway's transport a closed set of **protocol-level
transports**. Each transport is a mechanism that speaks one wire protocol and
its generic semantics, and every provider-specific value stays recipe data.

| Transport | Protocol | Phase | Section |
| --- | --- | --- | --- |
| `https` | HTTP/1.1 over pinned TLS, as 053 and 063 specify | today, moved under the recipe's `https` section | §3 |
| `postgresql` | PostgreSQL frontend/backend protocol 3.0, extended query only, over pinned TLS | first | §5 |
| `exec` | POSIX process execution under Proofbound Runtime (`pbr`), restricted to a closed program registry | later, gated on a `pbr` release with typed egress; a network-free interim before it | §6 |

### 1.1 A transport is not a provider

A **provider** is the meaning of one remote resource: that a Stripe refund
moves money, or that `app.demo_accounts.review_status` records a review.
A **transport** is a wire protocol and the generic semantics every user of
that protocol shares.

- For HTTP, those are methods, status classes, redirects (never followed),
  and the `Idempotency-Key` header.
- For PostgreSQL, they are transactions, isolation levels, `SQLSTATE` classes,
  parameter binding, unique-index behavior, and the system catalogs.

The gateway already knows HTTP's generic semantics and none of Stripe's.
In the same way, the `postgresql` transport knows how to run a
parameterized single-row statement in a serializable transaction and read the
role catalog. It does not know what any table, column, or value means. The
schema, table, column names, types, and key choice are recipe data that the
author writes, the compiler bounds, the review shows, and the operator
approves by digest (053 §3.1).

This keeps ADR 0012 intact:

- the interpreter still loads no third-party code;
- it accepts no runtime statement, identifier, URL, header, or body;
- it leases no secret to a callback; and
- it branches on a closed **transport** tag and never on a provider or
  operation tag.

The boundary plan forbids a shared API that dispatches on an operation tag.
A transport tag is not an operation tag, for three reasons:

- it selects a wire protocol, not an effect;
- each transport's code path is closed and typed; and
- two recipes on one transport differ only in data.

§6.1 shows where this argument stops holding: an open `exec` transport would
put effect semantics into an operator-chosen binary. That is the pattern ADR
0012 rejected, so this spec does not admit it.

### 1.2 Claim, once implemented

- Every 063 claim holds for every transport, unchanged, except the non-claim
  "a conditional write", which §5.7 narrows to the `https` transport.
- **Conditional write.** For a `postgresql` recipe, the gateway records
  `observed-by-provider` only when the database acknowledged `COMMIT` of one
  `SERIALIZABLE` transaction, or a later fence found this action's marker. In
  that transaction:
  - the declared table's schema fingerprint equalled the approved one, read
    while the transaction held a lock that excludes DDL on the table;
  - for an `update-row` recipe, exactly one row matched the verified primary
    key, tenant, and row version, and every declared before-value equalled
    its verified expectation;
  - for an `insert-row` recipe, the insert did not violate a constraint;
  - the statement affected exactly one row, and its `RETURNING` values
    equalled the verified values; and
  - a commit marker holding this action's token was inserted.
- **Complete recovery.** A `postgresql` write whose outcome is ambiguous
  resolves to exactly `observed-by-provider` or `not-committed` the first
  time a fence (§5.9) runs against a reachable database and its lock wait
  ends within the fence timeout. It never stays `unknown` for any other
  reason. The resolution never re-sends the write.
- **Database-enforced de-duplication.** While the marker table is intact, a
  logical operation commits at most once, even after the gateway store is
  wiped or restored.
- **Credential introspection.** At onboarding and at every lease, the
  gateway checks by catalog introspection that the connected role:
  - is exactly the approved role, on the approved database, on a primary;
  - has no elevated attribute and belongs to no role;
  - owns no relation, schema, or function;
  - can write no relation other than the declared table and the marker
    table; and
  - can write exactly the declared columns of the declared table.
- **Statement construction.** The statement text is a function of the
  approved recipe alone. No verified argument byte reaches the statement
  text; each reaches the database only as a bound protocol parameter. This
  is machine-checked against a Lean model (§8.1).
- The OpenTofu phase (§6) claims less: §6.1 and §6.13 state what it cannot
  claim.

### 1.3 Not a claim

- Every 063 §1 non-claim other than "a conditional write" stands for every
  transport.
- **Durability beyond the primary.** The gateway forces local
  `synchronous_commit = on` in the transaction. A failover to an asynchronous
  standby can still lose an acknowledged commit, and the gateway's record of
  `observed-by-provider` then names a transaction the new primary does not
  hold.
- **Function bodies.** The fingerprint covers the definitions of functions
  that the table's triggers, defaults, checks, and policies reference, as
  read at the lock. `CREATE OR REPLACE FUNCTION` takes no lock on the table,
  so a body changed between the fingerprint read and `COMMIT` is not
  detected.
- **Privileges during the transaction.** The introspection runs before the
  transaction. A `GRANT` that widens the role between the introspection and
  `COMMIT` is not detected; a revocation can only narrow what commits.
- **Marker integrity.** The gateway checks that its own role cannot update,
  delete, or truncate the marker table. It cannot check what other roles,
  including the table owner, do to it. A deleted marker voids both the
  de-duplication and a later fence's `observed-by-provider`.
- **Meaning.** That the committed row means what the author intended. The
  gateway compares text representations and counts rows; it interprets no
  column.
- **Authorship** of a marker row. The token is 059's unkeyed echo.

## 2. Evidence and the abstraction boundary

### 2.1 What the boundary plan requires here

The plan requires three things:

- vertical-first semantics;
- a written comparison before any extraction; and
- extraction of the identical subset only.

A transport is a new kind of gateway capability. Each transport rests on one
domain's vertical, so each is a "smaller promotion" that needs an ADR
("Domain to shared product"). Epic 1 writes **ADR 0014, "Admit protocol-level
transports into the data-only gateway"**. It amends ADR 0012 and ADR 0013 and
adds a section for each transport to abstraction case 0007. A reviewer may
reject `exec` (§6) without blocking `postgresql`, and may reject either
statement shape (§5.5) without blocking the other.

### 2.2 The PostgreSQL vertical is the reference

`product/integrations/auths-postgresql` stays a test-only reference (063
§12), and each `postgresql` mechanism is compared against it.

| Mechanism | Classification | Vertical evidence | Stays operation-owned |
| --- | --- | --- | --- |
| Statement templates (§5.5) | Protocol mechanism; identifiers are recipe data | `compile_statement` in `compiler.rs` (fully qualified, quoted `PgIdentifier`s, every value a `$n::text` parameter, a lock `SELECT … FOR UPDATE` then `UPDATE … RETURNING`); `compiler_never_interpolates_values` | Which table, columns, and key |
| Serializable conditional write (§5.7) | Protocol mechanism | 0009 §13 steps 3–10; the row-version predicate in `compile_statement` | What a row version or before-value means |
| Commit marker (§5.9) | Protocol mechanism | `auths_internal.auths_execution_ledger` (`migrations/auths_execution_ledger.sql`), written atomically with the mutation (0009 §14) | — |
| Fence (§5.9) | Protocol mechanism over PostgreSQL's documented unique-index wait | None in the vertical, which reconciled by reading the ledger (0009 §15) and is unsound against an in-flight transaction (§13, reading 5). The ADR must argue this one from PostgreSQL's documented semantics and the Lean model of §8.3 | — |
| Role and privilege introspection (§5.3) | Protocol mechanism over the system catalogs | 0009 §10's executor-role restrictions; the "executor role identity and relevant privilege fingerprint" evidence of 0009 §9 | Which role the operator provisions |
| Schema fingerprint (§5.4) | Protocol mechanism | `schema_fingerprint` and `policy_fingerprint` in 0009 §7 and §9, and `schema.rs` | Which schema is approved |
| Pinned TLS connection (§5.1) | Protocol mechanism | 042 §3 (one committed CA bundle, no WebPKI roots); `tokio-postgres-rustls` in the PostgreSQL store (`product/stores/auths-stores`) | — |

The `insert-row` shape has no vertical evidence, because 0009 §4 excluded
`INSERT`. Epic 3 therefore first extends the reference with a test-only
`compile_insert` and its fixtures in `auths-postgresql` (vertical-first), and
only then admits the shape.

### 2.3 The OpenTofu vertical is the reference for §6

`product/integrations/auths-opentofu` provides:

- the fixed argument vector with a scrubbed environment and no shell (0008
  §13);
- the pre-apply state recheck (0008 §12); and
- the state lineage and serial evidence (0008 §15).

§6 reuses these three and nothing else. The plan projection and its
restrictions (0008 §9–§10) are OpenTofu-domain semantics. They stay in the
reference and never enter the gateway (§6.1).

### 2.4 What is shared and what is transport-specific

| Shared, unchanged | Transport-specific |
| --- | --- |
| Native verification; admission steps 1–8, 11, and 12 of 063 §5.5 | Credential checks at step 9 |
| The atomic claim; count and sum slots (063 §6) | Request construction at step 13 |
| Retention rule (063 §4.5) where a transport declares retention | Result recording at step 14 |
| Operator plane (063 §7); connection record `auths.provider-connection/2`; credential generations | The recovery evidence and its transitions |
| Observer signing; audit recount; code inventory; fuzz infrastructure | Per-transport outcome facts (§4.4) |

Every shared item keeps its code and its theorems. §4 lists the only places
where a shared item learns about transports.

## 3. Recipe source `/3`

### 3.1 The transport abstraction

A recipe declares exactly one transport and carries exactly one typed
section, whose key equals the transport's name.

```json
{
  "schema": "auths.gateway-recipe-source/3",
  "profile_schema_digest": "<64 lowercase hex>",
  "service": "account-review",
  "tool": "mark_reviewed_v1",
  "operator_namespace": "account-review",
  "bounds": {},
  "transport": "postgresql",
  "postgresql": { "...": "§5.5" }
}
```

- **Shared fields.** `schema`, `profile_schema_digest`, `service`, `tool`,
  `operator_namespace`, and `bounds` keep their 063 rules. For every
  transport, `bounds.sum.argument` and `bounds.sum.partition` must name
  fields that the transport's write consumes: the body or account-scope header
  for `https`, and a statement parameter for `postgresql`. An `exec` recipe
  may not declare `bounds` (§6.7).
- **`https` section.** It holds every other 063 `/2` field, with 063 §3.2's
  rules unchanged: `credential`, `origin`, `provider_headers`,
  `account_scope`, `relative_ceiling`, `write`, `observation`, `echo`,
  `pre_entry`, and `preconditions`.
- **`postgresql` section.** Specified in §5.5.
- **`exec` section.** Specified in §6.7.

### 3.2 Why `/3` and not an additive `/2` rule

An additive rule ("a `/2` recipe without `transport` means `https`") would be
a default that keeps the old shape readable. That is a compatibility reader,
which `AGENTS.md`'s prelaunch rule forbids. Moving every HTTP field under
`https` also makes the compiler's closure rule local: an HTTP field in a
`postgresql` recipe becomes an unknown field of the wrong section, not a
field silently ignored. Every recipe changes digest and needs a new approval
and new actions, as 063 §3.3 already required once. No reader accepts `/2`
(§13, reading 1).

### 3.3 Compile rules

`CompiledRecipe::compile` (`product/runtime/auths-gateway/src/recipe.rs`)
parses the source once into a typed AST, a Rust enum with one variant per
transport, and refuses anything outside these rules with the listed code.
Rules not listed are 063 §3.2's.

| Field | Rule | Code |
| --- | --- | --- |
| `schema` | Exactly `auths.gateway-recipe-source/3`; `/1` and `/2` refused | `gateway.recipe.invalid-source` |
| `transport` | Exactly `https`, `postgresql`, or `exec` | `gateway.recipe.invalid-transport` |
| Sections | Exactly one of `https`, `postgresql`, `exec` is present, and its key equals `transport`; an HTTP field at the top level is refused | `gateway.recipe.transport-section-mismatch` |
| `postgresql.*` | §5.5 | `gateway.recipe.postgresql.*` (§7) |
| `exec.*` | §6.7 | `gateway.recipe.exec.*` (§7) |

Every profile field must still be consumed, for `postgresql` by a statement
parameter (`gateway.recipe.unsafe-template` otherwise). The 64 KiB source
bound stays.

### 3.4 Digest, review, and cutover

- **Digest.** The digest is SHA-256 over `auths.gateway-compiled-recipe/3`, a
  NUL byte, and the RFC 8785 serialization of the validated source, with
  absent optional fields omitted.
- **Review.** `auths-gateway review` and `auths-node gateway recipe check`
  print `auths.gateway-recipe-review/3`. It keeps every `/2` field under
  `https` and adds, for `postgresql`:
  - the rendered statement texts, exactly as sent, with `$n` placeholders;
  - each parameter's position, type, and source field;
  - the marker table;
  - the timeouts;
  - the recovery capability of §4.2; and
  - the sentences "values reach the database only as bound parameters", "the
    write is conditional on the predicates shown", and "an acknowledged
    commit can be lost by a failover to an asynchronous standby".
- **Fixtures.** The three fixtures under `bindings/fixtures/gateway/`, the
  north-star recipe, and the derivation corpus's expected recipes are
  regenerated as `/3` `https` recipes in the same change.
- **Derivation.** `product/tools/auths-openapi-derive` writes `/3` with
  `"transport": "https"`.

## 4. What the shared machinery learns

The design goal was that shared machinery learns nothing but a transport tag.
That holds for admission, limits, and the operator plane. It does not hold
for the outcome and the attempt record. The PostgreSQL recovery evidence
proves a non-effect that no HTTP recipe can prove, so they gain one stage,
`not-committed`, beside the tag.

### 4.1 Admission step machine

063 §11.2's `next_step` keeps its states and theorems. Its event alphabet at
steps 9, 13, and 14 is already abstract: "credential checks passed" or
"failed with code", "sent", "complete result", and "no complete result".
Each transport maps its own events onto that alphabet:

| 063 §5.5 step | `https` | `postgresql` (§5.6) | `exec` (§6.11) |
| --- | --- | --- | --- |
| 9 | Lease; prefix guard; account read; denied reads | Lease; T0–T4: connect, pinned TLS, authenticate, introspect, fingerprint | Lease; stage artifacts; `init` and `state-before` under `pbr` |
| 10 | Pre-entry read; relative ceiling | Nothing | Nothing |
| 13, transport entry | The first byte of the write request | T5: the first byte of `BEGIN` | Start of `pbr run` of `apply` |
| 13, point of possible effect | Transport entry | Starting to write the `COMMIT` message (T10) | Transport entry |
| 14 | Status and digest, or `unknown` | `observed-by-provider`, `not-committed`, or `unknown` (§5.9) | Exit status and accepted `pbr` receipts, or `unknown` |
| 15 | At most one read-back | Nothing; the evidence came from the transaction | Post-apply state read |

The `postgresql` transport alone separates transport entry from the point of
possible effect. A failure between them is proved harmless: without a
`COMMIT` message, PostgreSQL aborts an explicit transaction when its session
ends. A new transport-local leaf (§8.2) governs the steps between them.

### 4.2 Recovery capability `/2`

`recovery_capability` returns `auths.gateway-recovery-capability/2`, which
adds `transport` and one class:

```json
{
  "schema": "auths.gateway-recovery-capability/2",
  "transport": "postgresql",
  "class": "fenced-commit",
  "state_observation": "transaction",
  "provider_link": "commit-marker",
  "unknown_resolution": "fence",
  "lost_claim_reentry": {"deduplication": "commit-marker"},
  "pre_entry_reread": false,
  "write_is_conditional": true
}
```

- **`https`.** The class and fields are 063 §4.2's, and
  `write_is_conditional` is `false`.
- **`postgresql`.** Every recipe is `fenced-commit` with the values above.
  `write_is_conditional` is `true` for both shapes. `update-row` is
  conditional on the key, tenant, version, and before-values; `insert-row` on
  every constraint in the fingerprint.
- **`exec`.** Every recipe is class `observed`, with `state_observation`
  `state-read` (apply) or `render-check` (the plan check, §6.14), `provider_link` `none`, `unknown_resolution` `none`,
  `lost_claim_reentry` `{"deduplication": "none"}`, and
  `write_is_conditional` `false` (§6.12).

### 4.3 Limits

063 §6 is unchanged: the count, the sum, partitions, scopes, fixed windows,
and never-released slots. A `postgresql` `not-committed` still consumes its
operation ID and its slots, even though its non-effect is proved (§13,
readings 13 and 14). An optional **tenant binding** (§5.5, `tenant.scope_bound`)
reuses 063 §5.9's admission rule with the tenant field in place of the
account-scope field.

### 4.4 Outcome `/3`

`auths.gateway-outcome/3` replaces `/2`. Its fact set changes meaning, so
`/2` is removed and requirements that name it fail closed (063 §13, reading
1). The facts of 063 §8.1 stay with these changes:

| Fact | Type | Present when |
| --- | --- | --- |
| `transport` | text: `https`, `postgresql`, `exec` | Always |
| `stage` | text | Always: 063's five stages, plus `not-committed` |
| `refusal` | text, at most 128 bytes | `not-entered` or `not-committed` |
| `http-status` | uint, 100–599 | `https` only, as 063 |
| `response-digest` | bytes (32) | `https` as 063; `postgresql` the result digest of §5.8 when a `RETURNING` row was read; `exec` `opentofu-plan-check/1` the render digest of §6.14 |
| `sqlstate` | text, exactly 5 bytes of `[0-9A-Z]` | `postgresql`, `not-committed` after an `ErrorResponse` |
| `exit-status` | uint, 0–255 | `exec`, when the final `pbr` run's child exited |
| `runtime-receipts-digest` | bytes (32) | `exec`, when at least one `pbr` receipt was accepted (§6.10) |
| `state-serial` | uint, at most 2^53 − 1 | `exec`, when the post-apply state read succeeded |
| `evidence-digest` | bytes (32) | `observed-by-provider`; for `postgresql` the evidence record of §5.8 |

At most 14 of an observation's 16 facts are used. The consumers of 063 §8.1
change in one cutover: `observer.rs`, `engine.rs`, `audit.rs`, the custody
test, the Python and TypeScript clients, the north-star example, and
`compliance.toml`. `bindings/fixtures/gateway/outcome-v3.json` replaces
`outcome-v2.json`, adding every `postgresql` and `exec` stage and fact
combination.

### 4.5 Attempt record `/4`

`auths.gateway-attempt/4` replaces `/3`, and a `/3` record is `Corrupt`. It
adds `transport`, the stage `not-committed`, and per-transport result
fields:

- `postgresql`: `result_digest`, `sqlstate`, and `fence`, which is `found`,
  `fenced`, or `other-action`; and
- `exec`: `exit_status`, `runtime_receipts` (the accepted `pbr` receipt
  commitments in run order), `render_digest` for the plan check, and
  `state_before` and `state_after`, each `{lineage, serial, digest}`.

The worst case stays below 063 §9.1's 262 144-byte bound. `valid_transition`
gains these rows, each checked exhaustively by Kani:

| From | To | Condition |
| --- | --- | --- |
| `attempting` | `not-committed` | `postgresql`, after transport entry: the database reported an error or `ROLLBACK`, the gateway rolled back on a failed check, the session ended before `COMMIT` was sent, or a fence proved no commit |
| `attempting` | `observed-by-provider` | `postgresql`: `COMMIT` acknowledged with tag `COMMIT`, or a fence found this action's marker |
| `unknown` | `not-committed` | `postgresql`: a fence committed a tombstone, or found another action's marker |
| `unknown` | `observed-by-provider` | `postgresql`: a fence found this action's marker |
| `response-recorded` | `observed` | `exec`: a post-apply state read (§6.12), or the plan check's fixed checks (§6.14) |

`not-committed` is terminal. 063 §4.3's rows for `https` are unchanged. Every
transition is still a compare-and-swap on the exact stored bytes.

### 4.6 Operator plane

063 §7 is unchanged: listeners, admin mutations without waiting, connection
record `/2` in the shared store, generations, join, rotate, key-identity
separation, the authenticated operator, and admin commands. Two things
change:

- **Descriptor `/2`.** The connection record's descriptor bytes become
  `auths.gateway-connection-descriptor/2`, which carries a transport section
  (§5.11, §6.5). `/1` is retired.
- **`reobserve`.** For `postgresql`, `reobserve {operation_id}` runs the fence
  (§5.9). For `exec`, it answers `gateway.reobserve.not-observable`.

### 4.7 Audit `/3`

`auths.gateway-audit-bundle/3` and `auths.gateway-audit-report/3` add
`transport` to each entry's `provider_result` and accept outcome `/3`. For a
`postgresql` entry, the audit:

- requires `evidence-digest` for `observed-by-provider` and `refusal` for
  `not-committed` (`audit.postgresql-evidence-missing`);
- recomputes the operation key and the action token from the re-verified
  action; and
- when the bundle carries the evidence record, requires it to digest to
  `evidence-digest` and to name that key and token
  (`audit.postgresql-evidence-invalid`, `inconsistent`).

An auditor with read access to the marker table re-checks the token directly
(§5.8). `verified` keeps its meaning: authorized and entered.

## 5. The `postgresql` transport

### 5.1 Connection, pinned TLS, and no proxy

The transport is implemented in `product/runtime/auths-gateway/src/transport/postgresql.rs`
on `tokio-postgres` and `tokio-postgres-rustls`, both already workspace
dependencies. It uses no libpq, and reads no environment variable, service
file, or password file. In particular, it ignores `PGHOST`, `PGSSLMODE`,
`PGSERVICEFILE`, `PGPASSFILE`, and `HTTPS_PROXY`.

- **Endpoint.** One `host` (a DNS name, or an IPv4 or IPv6 literal) and one
  `port` from the descriptor (§5.11). A DNS name is resolved once per
  connection by the transport's resolver. An address that is unspecified,
  multicast, or broadcast is refused (`gateway.postgresql.connect-failed`).
  There is no proxy, no alternative host list, and no fallback.
- **Connect.** TCP within 10 seconds, with keepalive after 5 seconds idle.
  Then `SSLRequest`. A server that answers `N` is refused
  (`gateway.postgresql.tls-refused`).
- **TLS.** TLS 1.3 only. The server certificate must satisfy all of:
  - its SubjectPublicKeyInfo SHA-256 equals one of the descriptor's 1–2
    `spki_sha256` pins;
  - its subjectAltName includes `server_name`, which is also sent as SNI; and
  - its validity period contains the gateway clock.

  No WebPKI or system root is consulted, so the pin is the trust
  (`gateway.postgresql.tls-pin-mismatch`).
- **Startup.** `StartupMessage` with exactly `user` = the descriptor's role,
  `database`, `application_name` = `auths-gateway`, and `client_encoding` =
  `UTF8`. No `options` parameter is sent.
- **Authentication.** The client accepts only these requests:
  - `SASL` offering `SCRAM-SHA-256-PLUS`, run with `tls-server-end-point`
    channel binding, for a `scram-sha-256-plus` credential; or
  - `AuthenticationOk` directly after the TLS handshake, for a
    `tls-client-certificate` credential.

  Any other request (cleartext, MD5, GSS, SSPI, SCRAM without channel
  binding, or `AuthenticationOk` for a password credential) closes the
  connection with nothing sent (`gateway.postgresql.auth-refused`).
- **Session checks.** `ParameterStatus` must report:
  - `server_version_num` at least 140000 (PostgreSQL 14 through 18 are
    supported, 13 having reached end of life);
  - `server_encoding` `UTF8`;
  - `standard_conforming_strings` `on`; and
  - `integer_datetimes` `on`.

  Otherwise the connection is refused (`gateway.postgresql.server-unsupported`).
- **Queries.** Every statement uses the extended query protocol: `Parse` with
  an unnamed statement and explicit parameter type OIDs, `Bind`, `Describe`,
  `Execute`, and `Sync`. The simple query protocol is never used.

### 5.2 Credentials

| `credential.kind` | Secret stored | Use |
| --- | --- | --- |
| `scram-sha-256-plus` | The role's password, 16–1 024 bytes of UTF-8 without NUL | SCRAM-SHA-256-PLUS only |
| `tls-client-certificate` | A PEM certificate chain and a PKCS#8 Ed25519 or ECDSA P-256 private key, at most 16 KiB | TLS client authentication; the server must map the certificate to the role |

The secret stays in #155's zeroizing types, is leased at step 9 (063 §5.5),
and is dropped when the connection closes. It is never logged, recorded, or
returned. Tokens issued by cloud IAM (for example RDS IAM authentication) are
sent as cleartext passwords, so they are refused (§12).

### 5.3 The credential guard: role and privilege introspection

HTTP has no provider-neutral permission introspection, which is why 063 §5.8
settles for denied reads. PostgreSQL has one, in its catalogs. So a
`postgresql` recipe declares no probe or denied reads. After authentication,
the guard runs these fixed statements in one `BEGIN READ ONLY` transaction
that it always ends with `ROLLBACK`. Every value in them is a parameter.

| # | Check | Pass | Code |
| --- | --- | --- | --- |
| G1 | `SELECT current_user, session_user, current_database(), pg_is_in_recovery()`, and the `oid` of `current_database()` in `pg_database` | Role and database equal the descriptor, the OID equals `database_oid`, and the server is not in recovery | `gateway.postgresql.identity-mismatch`, `gateway.postgresql.server-unsupported` |
| G2 | `rolsuper`, `rolcreaterole`, `rolcreatedb`, `rolreplication`, `rolbypassrls` of `current_user` in `pg_roles` | All false | `gateway.postgresql.role-attribute` |
| G3 | Rows of `pg_auth_members` whose `member` is `current_user` | None: the role belongs to no role, predefined roles included (§13, reading 6) | `gateway.postgresql.role-membership` |
| G4 | Relations in `pg_class`, schemas in `pg_namespace`, and functions in `pg_proc` owned by `current_user` | None | `gateway.postgresql.ownership` |
| G5 | Relations of kind `r`, `p`, `v`, `m`, or `f`, other than the target and the marker, for which `has_table_privilege(current_user, oid, p)` holds for any `p` in `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE` | None | `gateway.postgresql.privilege-excess` |
| G6 | On the target table: `has_table_privilege` for each of `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `REFERENCES`, `TRIGGER`; and `has_column_privilege(…, 'UPDATE')` for every non-dropped column | `update-row`: `SELECT` true, column `UPDATE` true exactly for the `set` columns and the version column, and every other privilege false. `insert-row`: `SELECT` and `INSERT` true, and every other privilege false | `gateway.postgresql.privilege-excess`, `gateway.postgresql.privilege-missing` |
| G7 | On the marker table: the same seven privileges | `SELECT` and `INSERT` true, the other five false | as G6 |
| G8 | `has_schema_privilege(current_user, n, 'CREATE')` for the target's schema, the marker's schema, and `public`; `has_database_privilege(current_user, current_database(), 'CREATE')` | All false | `gateway.postgresql.privilege-excess` |

- **Cost.** G5 is one query over `pg_class`, bounded by the statement
  timeout. A catalog too large to scan within it fails closed
  (`gateway.postgresql.guard-unavailable`).
- **Evidence.** The guard records only its code. Its inputs never enter the
  attempt record.
- **Scope of the claim.** `has_table_privilege` and `has_column_privilege`
  include privileges granted to `PUBLIC`, and G3 excludes inherited roles, so
  G5–G8 describe what the role can write. They do not describe what the
  role can read, and they cannot describe `SECURITY DEFINER` functions
  executable by `PUBLIC`. The gateway calls none; the only functions it
  invokes are `set_config`, `pg_is_in_recovery`, `has_*_privilege`, and the
  `pg_get_*def` readers.

### 5.4 Schema fingerprint

The fingerprint pins what the target table does when written.

- **Definition.** It is SHA-256 over `auths.gateway-postgresql-fingerprint/1`,
  a NUL byte, and the RFC 8785 serialization of one JSON object. The object
  holds eight sorted arrays of rows, one per query below, each row an array
  of text or null values. Every query binds the table's OID as `$1`.
- **Queries:**
  1. `pg_class`: `relkind`, `relpersistence`, `relrowsecurity`,
     `relforcerowsecurity`, the owner's `rolname`, and `relispartition`;
  2. `pg_attribute` joined to `pg_attrdef`: for every non-dropped column
     with `attnum > 0`, `attname`, `format_type(atttypid, atttypmod)`,
     `attnotnull`, `attidentity`, `attgenerated`, and
     `pg_get_expr(adbin, adrelid)`;
  3. `pg_constraint`: `conname`, `contype`, and `pg_get_constraintdef(oid)`;
  4. `pg_trigger` with `NOT tgisinternal`: `tgname`, `tgenabled`, and
     `pg_get_triggerdef(oid)`;
  5. `pg_rewrite`: `rulename` and `pg_get_ruledef(oid)`;
  6. `pg_policy`: `polname`, `polcmd`, `polpermissive`, the sorted role
     names, `pg_get_expr(polqual, polrelid)`, and
     `pg_get_expr(polwithcheck, polrelid)`;
  7. `pg_inherits`: parents and children, by qualified name;
  8. for every `pg_depend` row with a `pg_proc` referent whose dependent is a
     default, constraint, trigger, or policy of the table: the function's
     qualified name and `pg_get_functiondef(oid)`.
- **Bounds.** At most 1 024 rows and 262 144 bytes in total; more fails
  closed (`gateway.postgresql.fingerprint-unavailable`).
- **Kind.** The table must be of kind `r`, an ordinary table, so a view,
  foreign table, or partitioned parent is refused. It may have no rule (query
  5 returns no rows). Both are checked from the rows
  (`gateway.postgresql.fingerprint-mismatch`).
- **When.** At onboarding (§5.11), `install` prints the fingerprint and
  requires `--postgresql-fingerprint <hex>` to equal it. At every write, the
  gateway reads it again inside the write transaction, after
  `LOCK TABLE … IN ROW EXCLUSIVE MODE` (T6, §5.6). That lock conflicts with
  every lock mode that `ALTER TABLE`, `CREATE TRIGGER`, `CREATE POLICY`, and
  `CREATE RULE` take, so the schema cannot change between the read and
  `COMMIT`.
- **Mismatch.** Inside the transaction, a mismatch rolls back as
  `not-committed` with `gateway.postgresql.fingerprint-changed`.

The marker table's shape is checked the same way, by a fixed fingerprint that
the gateway itself defines (§5.9).

### 5.5 Statement templates

The `postgresql` section:

```json
"postgresql": {
  "credential": {"kind": "scram-sha-256-plus"},
  "statement": {
    "shape": "update-row",
    "schema": "app",
    "table": "demo_accounts",
    "key": [{"column": "account_id", "type": "uuid", "field": "account_id"}],
    "tenant": {"column": "tenant_id", "type": "text", "field": "tenant", "scope_bound": true},
    "version": {"column": "row_version", "field": "row_version"},
    "expect": [{"column": "review_status", "type": {"enum": {"schema": "app", "name": "review_state", "labels": ["pending", "reviewed"]}}, "field": "from_status"}],
    "set": [{"column": "review_status", "type": {"enum": {"schema": "app", "name": "review_state", "labels": ["pending", "reviewed"]}}, "field": "to_status"}]
  },
  "marker": {"schema": "auths_gateway", "table": "commit_markers"},
  "timeouts": {"statement_ms": 5000, "lock_ms": 2000}
}
```

**Identifiers.** Every schema, table, column, and type name matches
`[a-z_][a-z0-9_]{0,62}` and does not start with `pg_`. It is fixed at
compile time and always emitted double-quoted and schema-qualified. The
alphabet contains no `"`, so quoting is unambiguous. This is the vertical's
`PgIdentifier` rule and quoting, which Epic 3 moves into a leaf both use
(`gateway.recipe.postgresql.invalid-identifier`).

**Types.** A closed set, each with one canonical text form that the gateway
validates before the claim (`gateway.postgresql.value-invalid`, before
claim). Enum labels are 1–63 bytes of `[a-z0-9_]`.

| Type | Verified argument | Canonical text | Cast (as `compile_statement`) |
| --- | --- | --- | --- |
| `boolean` | JSON boolean | `true` or `false` | `CAST($n::text AS boolean)` |
| `smallint`, `integer`, `bigint` | JSON integer within the type's range | Decimal, as `mcp-arguments-v1` already requires | `CAST($n::text AS <type>)` |
| `text` | JSON string of 0–4 096 bytes, without NUL | The string | `$n::text` |
| `uuid` | JSON string, lowercase `8-4-4-4-12` hexadecimal | The string | `CAST($n::text AS uuid)` |
| `enum` | JSON string among 1–64 declared labels | The label | `CAST($n::text AS "<schema>"."<name>")` |

`numeric`, `timestamptz`, `json`, `bytea`, arrays, and null are not bindable
(§12). A column of another type can only be read.

**Shape `update-row`.** Three statements, whose text is `compile_statement`'s
for a one-row intent (§5.13):

```sql
SELECT <R> FROM "s"."t"
 WHERE "tenant"::text = $1::text AND (("k1"::text = $2::text AND … AND "row_version" = CAST($m::text AS bigint)))
 FOR UPDATE
UPDATE "s"."t" SET "c1" = <cast $j>, …, "row_version" = "row_version" + 1
 WHERE <the same predicate> RETURNING <R>
```

- **`R`.** The sorted, de-duplicated `"col"::text AS "col"` list over the
  key, `expect`, `set`, and version columns.
- **Parameters.** In the vertical's order: tenant, key columns, version,
  then one per `set` entry. `tenant` is optional; without it the predicate
  omits the tenant term, and the reference is used with a constant tenant
  column (§5.13).
- **`key`.** 1–4 columns, which must be exactly the columns of the table's
  primary-key constraint, in the fingerprint's order.
- **`version`.** A `bigint NOT NULL` column.
- **`expect`.** 0–8 columns.
- **`set`.** 1–16 columns. It may not include key, tenant, or version
  columns.
- **Sizes.** At most 32 parameters and 32 returned columns.

**Shape `insert-row`.** One statement:

```sql
INSERT INTO "s"."t" ("c1", …, "cn") VALUES (<cast $1>, …, <cast $n>) RETURNING <R>
```

- **`values`.** 1–32 `{column, type, field}` entries.
- **`generated`.** 0–4 `{column, type}` entries, which name columns the
  database fills (an identity column or default) and returns. They are
  recorded as a locator, like 063's `response-locator`.
- **`R`.** The sorted list over the `values` and `generated` columns.
- **Excluded.** No `ON CONFLICT` clause. A constraint violation rolls back
  (§5.7).

**Always emitted around both shapes**, with fixed text:

```sql
BEGIN ISOLATION LEVEL SERIALIZABLE, READ WRITE
SELECT set_config($1, $2, true), set_config($3, $4, true), …
LOCK TABLE "s"."t" IN ROW EXCLUSIVE MODE
INSERT INTO "ms"."mt" ("operation_key", "action_token", "result_digest") VALUES ($1, $2, $3)
COMMIT
```

The `set_config` pairs are fixed by the gateway, not the recipe:

- `search_path` = `` (empty);
- `statement_timeout` and `lock_timeout` from `timeouts`;
- `idle_in_transaction_session_timeout` = `20000`;
- `synchronous_commit` = `on`;
- `row_security` = `on`;
- `TimeZone` = `UTC`; and
- `DateStyle` = `ISO, YMD`.

Their values are parameters too.

**What is refused.** No other statement text is constructible. A
multi-statement string, DDL, `DELETE`, `TRUNCATE`, `MERGE`, `COPY`, `CALL`,
a function call outside the fixed list, a subquery, and a join are refused
by construction, because the AST has no field that could express them.
`statement.shape` outside the two values is
`gateway.recipe.postgresql.invalid-shape`.

**Other compile rules:**

| Rule | Code |
| --- | --- |
| A `field` must be a top-level profile field whose schema type matches the declared type (integer for the integer types, string for `text`, `uuid`, and `enum`, boolean for `boolean`), and no field may bind two parameters | `gateway.recipe.postgresql.invalid-column-binding` |
| A column may appear at most once across `key`, `tenant`, `version`, and `set` | `gateway.recipe.postgresql.invalid-column-binding` |
| `marker` names two identifiers, and the marker table differs from the target | `gateway.recipe.postgresql.invalid-marker` |
| `timeouts.statement_ms` is 100–30 000 and `lock_ms` is 100–10 000; defaults 5 000 and 2 000 | `gateway.recipe.postgresql.invalid-timeouts` |
| `tenant.scope_bound` requires a `text` or `enum` tenant | `gateway.recipe.postgresql.invalid-column-binding` |

**Tenant binding.** With `scope_bound: true`, admission (063 §5.5 step 3)
requires a bounded branch in which every link's policy carries a `scope`
whose argument is the tenant field and lists the verified value, as 063 §5.9
does for the account scope. Otherwise the submission is refused before the
claim, with `gateway.postgresql.tenant-unbound` or
`gateway.policy.scope-denied`.

### 5.6 Transaction protocol

After step 9's lease, one connection carries the whole submission.

| Step | Message sequence | On failure |
| --- | --- | --- |
| T0 | TCP, `SSLRequest`, TLS with pin check (§5.1) | Recorded `not-entered` with its code |
| T1 | `StartupMessage` | as T0 |
| T2 | Authentication (§5.2) | as T0 |
| T3 | `ParameterStatus` checks | as T0 |
| T4 | Guard G1–G8 (§5.3) in `BEGIN READ ONLY … ROLLBACK` | as T0 |
| — | 063 §5.5 steps 11 and 12 (reload, entry deadline) | Recorded `not-entered` |
| T5 | `BEGIN ISOLATION LEVEL SERIALIZABLE, READ WRITE`; this is transport entry | Any failure from here until T10 is `not-committed` |
| T6 | `set_config` pairs; `LOCK TABLE … IN ROW EXCLUSIVE MODE`; fingerprint queries (§5.4) | `not-committed`, `gateway.postgresql.fingerprint-changed` or the error's code |
| T7 | `update-row` only: the lock `SELECT … FOR UPDATE`. It must return exactly one row, and each `expect` column's text must equal its canonical verified value | Zero rows: `not-committed`, `gateway.postgresql.condition-false`. An unequal value: `gateway.postgresql.before-mismatch` |
| T8 | The write with `RETURNING`. It must return exactly one row, and every returned column must match (§5.8) | `gateway.postgresql.row-count` or `gateway.postgresql.returning-mismatch` |
| T9 | The marker `INSERT` of §5.9, with this row's result digest | `SQLSTATE 23505`: `not-committed`, `gateway.postgresql.operation-already-resolved` |
| T10 | Start writing the `COMMIT` message; await `CommandComplete` | See below |

- **Failures before T10.** On any failed check the gateway sends `ROLLBACK`
  and records `not-committed`. An `ErrorResponse` records its `SQLSTATE`.
  These classes have their own codes:
  - `40001` and `40P01`: `gateway.postgresql.serialization-failure`, never
    retried (§13, reading 3);
  - `55P03`: `gateway.postgresql.lock-timeout`;
  - `57014`: `gateway.postgresql.statement-timeout`;
  - `23xxx`: `gateway.postgresql.constraint-violation`;
  - any other class: `gateway.postgresql.database-error`.

  If the session ends before the gateway starts writing `COMMIT`, the stage
  is `not-committed` with `gateway.postgresql.session-lost-before-commit`.
  PostgreSQL aborts an explicit transaction whose session ends without
  `COMMIT`, so this is a proved non-effect.
- **T10 outcomes:**

  | Result | Stage |
  | --- | --- |
  | `CommandComplete` with tag exactly `COMMIT` | `observed-by-provider` |
  | `CommandComplete` with tag `ROLLBACK` (PostgreSQL's answer to `COMMIT` in an aborted transaction), or an `ErrorResponse` | `not-committed`, `gateway.postgresql.commit-refused`, with the `SQLSTATE` when present |
  | Anything else: timeout, reset, TLS alert, or a closed connection after the gateway started writing `COMMIT` | `unknown` |

- **Deadlines.** The whole T5–T10 span shares 063's 15-second transport
  total. When it expires before T10, the gateway closes the connection and
  records `not-committed`; when it expires after T10 starts, it records
  `unknown`.
- **Order.** The gateway MUST NOT pipeline `COMMIT` behind an unanswered
  statement. It sends `COMMIT` only after T7–T9's responses are complete and
  checked. §8.2 proves this order.

### 5.7 The conditional write

063 §1 says "a write is never conditional", because no HTTP mechanism lets the
gateway make the provider's acceptance depend on a predicate. PostgreSQL has
one: one transaction. Under `SERIALIZABLE`, the commit of T5–T10 is refused
unless the transaction's reads and writes are equivalent to some serial
order. So the predicates of T6–T9 hold at the commit point, not merely at a
read before it. The `postgresql` transport therefore makes this claim:

> A `postgresql` write commits only if, at its serialization point, the
> table's fingerprint equalled the approved one, the verified key, tenant,
> and version selected exactly one row whose declared before-values equalled
> the verified expectations (`update-row`), the write affected exactly one
> row whose returned values equalled the verified values, and no marker for
> the logical operation existed.

For `insert-row`, "conditional" means conditional on the constraints the
fingerprint pins. A verified value that collides with a unique constraint
rolls back.

**Non-claims.** The meaning of the row version and the before-values is the
author's. The function-body and privilege-widening gaps of §1.3 remain.

### 5.8 Evidence and read-back

- **Result digest.** The `RETURNING` row is encoded as an RFC 8785 JSON
  object from column name to text, or to null, and the result digest is
  SHA-256 over `auths.gateway-postgresql-result/1`, a NUL byte, and that
  encoding.
- **Row bound.** A row larger than 65 536 bytes in total rolls back as
  `gateway.postgresql.returning-mismatch`.
- **Match rule at T8:**
  - every key, tenant, and `set` column equals its canonical verified value;
  - for `update-row`, the version equals the verified version plus one;
  - for `insert-row`, every `values` column equals its verified value; and
  - each `generated` column is non-null, at most 255 bytes, and recorded.
- **Evidence record.** `auths.gateway-postgresql-evidence/1` is an RFC 8785
  object:

  ```json
  {
    "schema": "auths.gateway-postgresql-evidence/1",
    "operation_key": "<64 hex>",
    "action_token": "<64 hex>",
    "result_digest": "<64 hex>",
    "commit": "acknowledged",
    "generated": {"id": "8123"}
  }
  ```

  `commit` is `acknowledged` (T10) or `fence-found` (§5.9). The record is
  stored in the attempt, and its SHA-256 is the outcome's `evidence-digest`.
- **Row values.** None beyond `generated` are stored, so an outcome shows
  digests, not data (0009 §16).
- **Auditor re-check.** An auditor with read access to the marker table
  re-checks with `SELECT action_token, result_digest FROM <marker> WHERE
  operation_key = <key>`, recomputing the key and token from the action.
  `auths-gateway echo-verify` gains `--postgresql-marker <file>`, which reads
  that row exported as JSON and prints `match`, `mismatch`, or `absent`
  under 063 §8.4's rules.

### 5.9 Recovery class `fenced-commit`

**The marker table.** The operator creates it once from the DDL that
`auths-gateway postgresql marker-ddl --schema <s> --table <t> --role <r>`
prints. The gateway never runs DDL. The DDL is:

```sql
CREATE TABLE "s"."t" (
    operation_key BYTEA PRIMARY KEY CHECK (octet_length(operation_key) = 32),
    action_token  BYTEA NOT NULL CHECK (octet_length(action_token) = 32),
    result_digest BYTEA NOT NULL CHECK (octet_length(result_digest) = 32)
);
REVOKE ALL ON "s"."t" FROM PUBLIC;
GRANT SELECT, INSERT ON "s"."t" TO "r";
```

Its fingerprint (§5.4) must equal the fixed value this DDL produces, checked
at T4 and inside the fence (`gateway.postgresql.marker-invalid`).

**Values.** The marker `INSERT` binds three values, in binary format with
type OID `bytea`:

- `operation_key` = SHA-256 of `auths.gateway-postgresql-marker/1`, NUL,
  namespace, NUL, operation ID;
- `action_token` = 059's `echo_token` of the action commitment; and
- `result_digest` = §5.8's result digest.

**The fence.** A replay or an operator `reobserve` of a `postgresql` record
in `attempting` or `unknown` runs the fence. The fence is sound at any time
(§8.3). If it runs before an in-flight original reaches T9, its tombstone
makes the original's T9 fail, and both record `not-committed`. To avoid
waiting behind an in-flight original, the gateway runs a fence only once the
record is at least 35 seconds past its entry deadline (`evaluated_at` + 60).
That margin is the 15-second transaction total plus the 20-second idle
timeout, after which the original is past T10 or aborted.

1. Lease the credential, then run T0–T4. A failure leaves the record
   unchanged and answers `gateway.postgresql.fence-unavailable`.
2. `BEGIN ISOLATION LEVEL READ COMMITTED, READ WRITE`; `set_config` of
   `lock_timeout` = `10000` and the fixed pairs.
3. `INSERT` into the marker the row (`operation_key`, the **tombstone** token,
   32 zero bytes). The tombstone token is SHA-256 of
   `auths.gateway-postgresql-fence/1`, NUL, `operation_key`. Its domain
   differs from every echo token's.
4. Handle the result:

   | Result | Meaning | Action | Stage |
   | --- | --- | --- | --- |
   | `INSERT 0 1`, then `COMMIT` acknowledged with tag `COMMIT` | No marker existed. The original can now never commit, because its T9 would violate the key | Record | `not-committed`, `gateway.postgresql.fenced` |
   | `SQLSTATE 23505` | A marker exists | `ROLLBACK`; in a new read-only transaction, `SELECT action_token, result_digest` for the key | this action's token: `observed-by-provider` (`fence-found`); the tombstone: `not-committed`, `gateway.postgresql.fenced`; any other token: `not-committed`, `gateway.postgresql.marker-other-action` |
   | `55P03`, `57014`, a session loss before `COMMIT`, or any other error | The original's transaction still holds the key, or the database is unreachable | `ROLLBACK` if possible | unchanged; `gateway.postgresql.fence-unavailable` |
   | Session loss after starting to write the fence's `COMMIT` | The tombstone may or may not have committed | none | unchanged; a later fence resolves it, because step 3 then finds the tombstone or inserts it |

**Why the fence is exact.** It rests on three facts:

- PostgreSQL's unique-index check makes an inserter wait for any in-progress
  transaction that inserted the same key, and then fail if that transaction
  committed or proceed if it aborted (PostgreSQL documentation, "Index
  Uniqueness Checks").
- The original sends `COMMIT` only after its T9 marker insert completed (§5.6).
- `operation_key` is unique per logical operation.

Every interleaving of the original and a fence therefore ends in exactly one
of two states. Either the original's marker commits, and the fence finds it.
Or the fence's tombstone commits, and the original can never commit. The
first committed insert of the key wins, and the other fails. §8.3 proves this
over a Lean model of the unique index. Waiting for an original that is still
in progress is bounded by `lock_timeout` and ends in `fence-unavailable`, not
in a guess.

**Why not `txid_status()`.** The owner's direction named `txid_status()`, whose
current name is `pg_xact_status(xid8)`. It would need the transaction ID
recorded durably before `COMMIT`, which is a store write inside the
transaction window. Its answer is `NULL` once the ID passes the commit-log
horizon. After a failover to a standby that never received the transaction,
the new primary can reuse the ID for another transaction, and report its
outcome instead. The marker is keyed by the logical operation, survives
failover as data, and needs no pre-commit write to the gateway store (§13,
reading 5).

**What the class proves:**

| After | Result |
| --- | --- |
| A complete `COMMIT` response | `observed-by-provider`, or `not-committed` with the database's refusal |
| Any failure before `COMMIT` was written | `not-committed`, proved by the absence of `COMMIT` |
| `unknown` | The first fence that completes gives `observed-by-provider` or `not-committed`; until then, `unknown` |
| Gateway store loss, then re-entry of the same logical operation | T9 fails with `23505`: `not-committed`, `gateway.postgresql.operation-already-resolved`; the marker survives the gateway store |

**Idempotency.** No declaration licenses a second write. A fence never sends
the write. 063 §4.5's retention rule does not apply to `postgresql` recipes,
which declare no retention, because the marker is permanent. The marker table
grows by one 96-byte row per logical operation and is never collected, as
claims are not (063 §6.5).

### 5.10 Resource bounds

| Bound | Value |
| --- | --- |
| Connect, TLS, and startup | 10 s together |
| Guard and fingerprint | Each statement within `statement_ms`; T0–T4 within 20 s |
| Write transaction T5–T10 | 063's 15 s transport total; `statement_ms` and `lock_ms` per statement |
| Idle in transaction | 20 s, set in the transaction |
| Fence | `lock_timeout` 10 s; the whole fence within 30 s |
| Parameters | At most 32; text at most 4 096 bytes each and 16 384 bytes in total |
| Backend messages | Each at most 1 MiB; at most 64 `NoticeResponse` and 64 `ParameterStatus` messages per connection, each logged at most as its `SQLSTATE`; more closes the connection (`gateway.postgresql.protocol-violation`) |
| Result | Exactly one row of at most 65 536 bytes |
| Connections | One per submission or fence, never pooled across submissions; they count toward the store pool in 063 §7.1's descriptor check |

A backend message that does not fit the expected sequence (an unexpected
`CopyInResponse`, `NotificationResponse`, or a second row) closes the
connection. Before T5 it records `not-entered`, from T5 until T10
`not-committed`, and after T10 `unknown`
(`gateway.postgresql.protocol-violation`).

### 5.11 The connection-record descriptor

`auths.gateway-connection-descriptor/2`, canonical under RFC 8785, is stored
as the connection record's descriptor (063 §7.3):

```json
{
  "schema": "auths.gateway-connection-descriptor/2",
  "namespace": "account-review",
  "recipe_digest": "<64 lowercase hex>",
  "transport": "postgresql",
  "postgresql": {
    "host": "db.internal.example",
    "port": 5432,
    "server_name": "db.internal.example",
    "spki_sha256": ["<64 lowercase hex>"],
    "database": "app",
    "role": "auths_account_review",
    "database_oid": 16384,
    "sasl_mechanism": "scram-sha-256-plus",
    "schema_fingerprint": "<64 lowercase hex>"
  }
}
```

- **Rules.**
  - `host`: 1–253 bytes;
  - `port`: 1–65 535;
  - `spki_sha256`: 1–2 unique pins;
  - `database` and `role`: identifiers under §5.5's rule;
  - `sasl_mechanism`: must equal the recipe's `credential.kind`.

  The `https` section holds `/1`'s credential header.
- **Account commitment.** SHA-256 of `auths.gateway-postgresql-account/1`,
  NUL, `database`, NUL, `role`, NUL, and the decimal `database_oid`.
- **Onboarding.** `install`, `install --join`, and `rotate` run T0–T4 and the
  marker check with the candidate secret before storing it. They refuse with
  these codes:
  - `gateway.install.postgresql-tls`;
  - `gateway.install.postgresql-guard`, carrying the guard's code;
  - `gateway.install.postgresql-fingerprint`;
  - `gateway.install.postgresql-marker`; and
  - the `gateway.admin.*` equivalents for `rotate`.

  `install` takes `--postgresql-host`, `--postgresql-port`,
  `--postgresql-server-name`, `--postgresql-spki` (repeatable, at most 2),
  `--postgresql-database`, `--postgresql-role`, and
  `--postgresql-fingerprint`. It reads `database_oid` at onboarding and prints
  it for the operator to confirm.
- **Fingerprint command.** `auths-gateway postgresql fingerprint` prints the
  current fingerprint for a candidate installation without storing anything.
- **Development.** 063 §13 reading 30's development store applies unchanged.

### 5.12 Submission order

063 §5.5 applies with §4.1's mapping. For a `postgresql` recipe:

- steps 1–8 are unchanged;
- step 9 is lease, then T0–T4;
- step 10 is empty;
- steps 11–12 are unchanged;
- step 13 is T5–T10;
- step 14 records the result; and
- step 15 is empty.

A replay of a `not-committed` or `observed-by-provider` record answers from
the record, as 063 §4.4 does for terminal stages.

### 5.13 Differential oracle

`auths-postgresql`'s `compile_statement` is the oracle for `update-row`. The
epic 3 test `postgresql_statements_match_reference` builds, for every fixture
recipe and 10 000 generated recipes and argument maps in the one-row subset:

- a `PostgresBoundedUpdateIntentV1` and `PostgresVerifierConfigurationV1`
  from the recipe, with one row, the tenant, and `expect` as before-values;
  and
- the gateway's lock `SELECT` and `UPDATE`.

It requires that the gateway's `SELECT` equals the oracle's `lock_sql` byte
for byte, and its `UPDATE` equals `update_sql`. It also requires the
parameter vectors to be equal in position, source, and canonical text. A
recipe without `tenant` maps to a reference configuration whose tenant
column is `key[0]`, which yields the same predicate with one redundant term.
The comparison then covers only the `SET` list, the `RETURNING` list, and
the key and version terms.

For `insert-row`, the oracle is `compile_insert`, which epic 3 adds to the
reference first (§2.2). The oracle's executor fixtures (`service.rs`,
`test_support.rs`) also run against the gateway's transport in the
PostgreSQL workflow: the exact commit, the changed row, the concurrent
updater, the injection strings, the `search_path` attack, and the timeouts.
They must reach equal commit or rollback results, and equal row states
afterwards.

## 6. The `exec` transport

### 6.1 Evaluation: an open `exec` transport is not data-only-safe

The owner asked for `exec` for OpenTofu, and for an explicit answer if it
cannot be made data-only and safe. The answer has two parts.

**An open `exec` transport cannot be made data-only-safe.** Suppose a recipe
named a digest-pinned binary with argument templates filled from verified
fields. Then three things follow:

- The effect is the binary's code, not recipe data. The gateway could prove
  the argument vector closed, but not the requests the program then makes.
  That is ADR 0012's first rejected alternative, loading developer code into
  the credential-owning runtime, with a binary in place of an adapter.
- The credential is handed to that code. For HTTP and PostgreSQL, the secret
  never leaves the gateway process.
- No request-construction theorem (063 §11.5, §8.1 here) is possible for the
  program's own traffic.

**For OpenTofu specifically, four further limits hold even with a pinned
binary:**

1. **Provider requests.** Provider plugins, which are third-party binaries,
   choose the provider requests from the plan.
2. **Plan contents.** A saved plan can carry provisioners and deferred data
   sources, which run code during `apply`. Refusing them would need the
   gateway to interpret OpenTofu's plan format. That is tool semantics, and
   the boundary plan keeps it in `auths-opentofu`'s plan projection, not in
   the gateway.
3. **Partial effect.** `apply` changes many resources non-atomically, so
   there is no conditional write and no proved non-effect.
4. **Egress.** A host allowlist cannot tell an operator's bucket from
   another bucket on the same object-storage host.

**The narrower alternative, specified below.** `exec` is admitted only with a
closed program registry, `EXEC_PROGRAMS` in `transport/exec.rs`, like 063
§5.1's `PROVIDER_HEADERS`. Its one entry is `opentofu-saved-plan-apply/1`.
The entry has these properties:

- no argument template: every argument vector is a constant of a
  digest-pinned `pbr` plan (§6.8);
- verified fields only select artifacts, by digest equality (§6.6), and
  state preconditions, by equality (§6.11);
- every child runs under Proofbound Runtime (§6.2), with no shell or other
  executable in its execute authority, so provisioners that execute locally
  and `external` data sources fail;
- egress only to declared endpoints, enforced and recorded by `pbr` (§6.4);
  and
- a claim class weaker than `https` and `postgresql`, stated in §6.13.

A second entry, `opentofu-plan-check/1`, is the network-free interim of
§6.14. Adding a registry entry needs an ADR amendment that names the program,
its vertical evidence, its fixed invocations, and hostile fixtures. The owner
may also decline this phase: `postgresql` does not depend on it.

### 6.2 Owner decision: Proofbound Runtime is the sandbox

**Decided 2026-09-28 by the owner.** The `exec` transport runs every child
under [Proofbound Runtime](https://github.com/bordumb/proofbound-runtime)
(`pbr`), which is to gain typed network egress. This decision is not
PROVISIONAL. §6.3 records the comparison that stands beside it.

**What `pbr` provides today.** Version 0.1.0 is released, and the 0.2 line is
a candidate. For one declared plan, `pbr` provides:

- an exact executable and loader closure;
- an explicit environment allow-list, whose receipt records names and never
  values;
- Landlock filesystem authority;
- seccomp with `no_new_privs`;
- cgroup v2 limits: `pids`, and in the 0.2 line memory and swap;
- a fresh output root and bounded standard streams; and
- a canonical execution receipt, which the separately built `pbr-verify`
  checks and `pbr-accept` evaluates against an adopter policy.

It runs without root on native Linux, on `x86_64` and `aarch64`. On macOS it
can validate plans and inspect receipts but not execute them. Sources:
`pbr` README, and its specifications 0001, 0007, 0010, 0013, and 0014.

**Why it is chosen:**

- It records the enforced boundary in a receipt that an auditor re-checks
  offline with an independent verifier. The other options enforce, but leave
  no verifiable account.
- It needs no root and no system manager.
- Its authority model lines up with the recipe: a closed command, named
  inputs, named environment, and declared limits.
- Its specification 0008 already defines how an Auths receipt commits to a
  `pbr` receipt.

The `pbr` receipt becomes provider-side evidence in outcome `/3` (§4.4) and
audit `/3` (§4.7).

**What `pbr` lacks for OpenTofu.** Three gaps:

- Its plans fix `network` to `deny` (0001 §5.2).
- `execute` holds exactly one path (`schemas/execution-plan-v2.cddl`), and
  OpenTofu starts provider plugin binaries.
- Its first network profile (ADR 0004, `AuthenticatedServiceSession`) allows
  one connector-owned session to one service, with no reconnect. OpenTofu
  needs several endpoints, several sessions, and end-to-end TLS from the
  provider plugin.

So the `exec` apply phase depends on a future `pbr` capability (§6.4). A
narrower interim phase (§6.14) needs only part of it.

### 6.3 Comparison of existing sandboxes

Surveyed on 2026-09-28. Epic 7 re-confirms each cited version before relying
on it.

| Option (version surveyed) | Linux production fit | Root needed | Maturity and audits | Egress to declared endpoints | Read-only root and scratch | Credential to the child only | Verifiable record | macOS development | Verdict |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **Proofbound Runtime `pbr`** (v0.1.0 released; 0.2 candidate) | Native Linux `x86_64` and `aarch64` | No: a delegated cgroup v2 subtree | Young; built claim-first under Proofbound, with four source-refined claims, Lean models, Kani, and native attack catalogs; no third-party audit | Not yet: `network = "deny"`; typed egress is the dependency of §6.4 | Landlock read, write, and execute authority; a fresh output root | The environment allow-list, with values from the launching process and names only in the receipt | **Yes**: a canonical receipt, `pbr-verify`, and `pbr-accept` | Plan validation and receipt inspection only; execution in a Linux VM | **Chosen by the owner** |
| systemd service sandboxing (v262; floor 255) | Every mainstream distribution | The system manager starts units; needs a polkit rule | The most widely deployed service sandbox; no public audit found | `PrivateNetwork=` plus a relay and an allowlisting proxy; `IPAddressAllow=` is by IP only | `RootDirectory=`, `ProtectSystem=strict`, `StateDirectory=` | `LoadCredential=` into a per-service ramfs | No | None natively | Not chosen: it enforces but records nothing an auditor can verify, and needs system-manager privilege |
| gVisor `runsc` (20260921.0) | Very good; reduces host-kernel attack surface | Yes for OCI; rootless `runsc do` has no network stack | Google production; no public third-party audit found | `--network=none` plus `--host-uds`; no name filter | OCI read-only root | OCI environment or mount | No | Docker Desktop or VM | Not chosen: needs root, has no credential channel or receipt |
| Firecracker (v1.17.0) or Kata Containers (4.2.0) | Strong but heavy | Jailer as root, plus `/dev/kvm` | AWS Lambda and Fargate; no public audit found | Tap device plus a proxy | Guest image | Guest environment or file | No | No KVM on macOS; often none in CI | Not chosen: KVM and guest images for one CLI process |
| bubblewrap (v0.13.0; setuid builds removed in 0.12.0) | Good, no cgroups | Unprivileged user namespaces | Flatpak; past setuid CVEs (CVE-2020-5291, CVE-2017-5226, CVE-2026-41163) | `--unshare-net` plus a relay only | `--ro-bind`, `--bind` | `--ro-bind-data FD` | No | VM only | Not chosen: no resource limits or record |
| nsjail (3.6; 3.5 shipped a seccomp regression) | Good; Kafel seccomp, cgroups, rlimits | Namespaces unprivileged; cgroups need root | Google CTF; infrequent releases | netns, MACVLAN, pasta; by IP or port | Mount configuration | Environment | No | VM only | Not chosen: no record; release cadence |
| minijail (linux-v18, 2023-05) | ChromeOS-centric | Varies | No release tag since 2023 | netns only | Yes | Environment | No | No | Not chosen: no current releases outside ChromeOS |
| Landlock with landrun (0.1.17) | An extra layer | No | In-kernel; no audit found | TCP port only | Filesystem rules | Environment | No | No | Not chosen alone; `pbr` already uses Landlock |
| OCI runtimes runc (1.5.2) or crun (1.30.1) with a seccomp profile | Good | Yes, or rootless | Ubiquitous; no OSTIF audit of either | netns plus relay | OCI read-only | OCI | No | Via VM | Not chosen: a bundle per run, and no record |

**How OpenTofu and Terraform runners isolate runs:**

| Runner | Isolation |
| --- | --- |
| HCP Terraform | A single-use VM per run |
| Spacelift | A fresh container per run |
| Scalr | A container or pod per run |
| Terrakube | A Kubernetes Job per run |
| Atlantis | No per-run sandbox; its security documentation warns that malicious providers and `external` data sources can exfiltrate credentials |
| OpenTofu | No sandbox of its own |

None restricts egress to provider endpoints, and none emits a verifiable
account of the boundary. Isolation per run is the proven pattern, and each
`pbr` run is one.

**Sources:**

- https://github.com/bordumb/proofbound-runtime (README; specifications 0001,
  0007, 0008, 0010, 0013, 0014; ADR 0004)
- https://github.com/systemd/systemd/releases and https://systemd.io/CREDENTIALS/
- https://github.com/google/gvisor/releases
- https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md
- https://github.com/containers/bubblewrap/releases
- https://github.com/google/nsjail
- https://docs.kernel.org/userspace-api/landlock.html
- https://ostif.org/audits/
- https://developer.hashicorp.com/terraform/cloud-docs/workspaces/run/run-environment,
  https://docs.spacelift.io/concepts/worker-pools/docker-based-workers,
  https://docs.scalr.io/docs/drivers,
  https://docs.terrakube.io/getting-started/deployment/ephemeral-agents,
  and https://www.runatlantis.io/docs/security
- https://opentofu.org/docs/cli/config/config-file/ and https://endoflife.date/opentofu
- https://pkg.go.dev/net/http#ProxyFromEnvironment

### 6.4 External dependency: `pbr` typed network egress

The apply phase (§6.5–§6.13) depends on a capability that `pbr` will specify
in its own repository, as a future `pbr` specification, "typed network
egress". Egress belongs in `pbr`, not the gateway (owner decision): `pbr` owns
network authority and service identity (its 0013 §6), and a second egress
mechanism in the gateway would make the receipt's account of the boundary
incomplete. The gateway MUST NOT add its own egress mechanism for `exec`.

**Minimum capability 064 needs from `pbr`.** Each item is a condition of the
epic 7 start gate.

| # | Capability | Why OpenTofu needs it |
| --- | --- | --- |
| E1 | **Declared endpoints only.** A plan may declare 1–16 egress endpoints. Each endpoint gives a lowercase DNS name, a TCP port, and the host-identity rule that `pbr` can enforce for it. That rule is a TLS SNI match or an IP set resolved and recorded by `pbr`, whichever `pbr` specifies as enforceable | Providers and the state backend reach several API hosts |
| E2 | **Everything else denied.** No other Internet connection, DNS request, UDP, raw socket, Unix socket outside declared roles, inherited socket, or `io_uring` path | The claim of §6.13 rests on it |
| E3 | **Endpoints in the receipt.** The execution receipt records each declared endpoint, its host-identity rule, and its enforcement mechanism, and `pbr-verify` checks them. The receipt does not claim that `pbr` authenticated the remote service, unless `pbr` did | The gateway compares the receipt's endpoints with the recipe's (§6.9) |
| E4 | **Child-originated TLS through several sessions.** The child and its descendants may open several connections per endpoint and run their own TLS end to end. This is a mode distinct from ADR 0004's single connector-owned session | Go providers open several connections and verify certificates themselves |
| E5 | **A multi-executable closure.** `execute` may list up to 17 exact executables: the OpenTofu binary plus up to 16 provider plugins, each with a digest in the receipt, and no directory-wide execute authority. Execution through a symbolic link that resolves to a listed file is allowed | OpenTofu starts one plugin process per provider, through links into an unpacked filesystem mirror |
| E6 | **A process limit above 1.** `processes` up to at least 512, because `pids.max` counts threads and Go programs start many | OpenTofu and each plugin are multi-threaded Go programs |
| E7 | **Secret environment values.** Values of allow-listed names come from the launching process, reach the child, and are never recorded, logged, or written to the output root; the receipt records names only. This is the owner's stated behavior; 0001 §5.3 lists secret support as deferred, so the egress release must confirm it | Provider credentials reach plugins as environment values (§6.8) |

**Pinning.** `auths-proof` consumes `pbr` only as a digest-pinned release
archive, never as a source tree or a sibling path (`AGENTS.md`). The
descriptor's `exec.runtime` section is install data:

```json
"runtime": {
  "release": "vX.Y.Z",
  "target": "x86_64-unknown-linux-gnu",
  "archive_sha256": "<64 hex>",
  "pbr_sha256": "<64 hex>",
  "pbr_verify_sha256": "<64 hex>",
  "pbr_accept_sha256": "<64 hex>",
  "assurance_bundle_sha256": "<64 hex>",
  "acceptance_policy_sha256": "<64 hex>"
}
```

- **Install.** `auths-gateway exec install-runtime --archive <file>` checks
  the archive's SHA-256 against `archive_sha256`, then extracts it to
  `/opt/auths-gateway/pbr/<release>/`, which must be a new directory. It then
  checks every binary's digest and records them.
- **Serve.** At every start, `serve` re-checks the three binaries' digests
  (`gateway.serve.exec-runtime-mismatch`). It runs `pbr doctor
  --cgroup-root <delegated root>` and requires every mechanism the plans use
  (`gateway.serve.exec-runtime-unready`). It refuses on any other platform
  (`gateway.serve.exec-platform`).
- **Upgrade.** Changing `pbr` is a new descriptor, which means a reinstall.
- **Source.** The archive digests come from `pbr`'s reviewed release document
  for that release, as its README does for v0.1.0.

### 6.5 Binary and provider pinning

- **Binary.** OpenTofu is pinned by the SHA-256 of `/opt/auths-gateway/tofu/<digest>/tofu`,
  recorded in the descriptor and in every `pbr` receipt as the plan's
  executable.
- **Providers.** Each plugin is pinned three ways:
  - as a listed executable of the plan (E5), with its digest in the receipt;
  - by the file digests of an unpacked filesystem mirror at
    `/opt/auths-gateway/tofu-providers/<digest>/`, a read authority of every
    plan; and
  - by the bundle's `.terraform.lock.hcl`, which `init -lockfile=readonly`
    enforces.
- **CLI configuration.** The configuration file, a read input, names one
  `filesystem_mirror` and no `direct` method.
- **Forbidden settings.** `TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE` is
  never set, and no `plugin_cache_dir` is configured.
- **Modules.** Only local module sources are allowed. A remote module fails,
  because no registry host may be an endpoint (§6.7).
- **Shell.** No shell, interpreter, or other executable is in any plan's
  execute authority, so a `local-exec` provisioner or `external` data source
  fails. OpenTofu starts `/bin/sh` for them, and Landlock denies it.

The descriptor's `exec` section (§4.6) holds every pin:

```json
"exec": {
  "program": "opentofu-saved-plan-apply/1",
  "tofu_sha256": "<64 hex>",
  "tofu_version": "1.12.6",
  "mirror_manifest_sha256": "<64 hex>",
  "cli_config_sha256": "<64 hex>",
  "plan_sha256": {"init": "<64 hex>", "state-before": "<64 hex>", "state-after": "<64 hex>", "apply": "<64 hex>"},
  "runtime": { "...": "§6.4" }
}
```

- **Mirror manifest.** The sorted `(path, mode, sha256)` list of the mirror.
- **Version.** `tofu_version` must be in a series with security support at
  install: 1.11 or 1.12 as surveyed (§13, reading 28). `serve` checks
  `tofu version -json`, run as its own `pbr` plan, against it.
- **Ownership.** The binary, mirror, and configuration are owned by root and
  not writable by the gateway's user.
- **When checked.** `serve` checks every digest at start
  (`gateway.serve.exec-runtime-mismatch`).

### 6.6 Artifacts and plan-digest binding

The action's verified fields include `plan_sha256` and `config_sha256`, each
64 lowercase hex characters, plus `state_lineage` (a lowercase UUID) and
`state_serial` (an integer in 0..=2^53 − 1). The recipe names these four
fields (§6.7).

- **Delivery.** The submission frame (063 §7.1) carries an `artifacts`
  object with `plan_b64` and `config_b64`, unpadded base64url, inside the
  existing 8 MiB frame bound. The plan is at most 4 MiB and the bundle at
  most 1 MiB raw (§13, reading 22).
- **Binding, before the claim.** SHA-256 of the plan bytes must equal
  `plan_sha256`, and SHA-256 of the bundle bytes must equal `config_sha256`
  (`gateway.exec.artifact-digest-mismatch`). Sizes are checked
  (`gateway.exec.artifact-oversize`).
- **Bundle format.** The bundle must be a POSIX ustar archive of 1–64
  regular files, each of mode `0644`, with relative paths of at most 255
  bytes in `[A-Za-z0-9._/-]`. It has no `..` segment, no absolute path, no
  duplicate, no link, and no device. It includes `.terraform.lock.hcl`, and
  no `.terraform` directory or `*.tfvars` file
  (`gateway.exec.artifact-invalid`).
- **Plan bytes.** The gateway checks only their digest, never their format.
  OpenTofu parses them inside `pbr`.
- **Staging.** After the claim, the gateway writes three files to the fixed
  directory `/var/lib/auths-gateway/exec/input/` (§13, reading 26):
  - the plan, as `plan.tfplan`;
  - the extracted bundle, as `config/`; and
  - the canonical action bytes, as `action.cbor`.

  These are read inputs of every plan, so each `pbr` receipt's input
  inventory records their digests. That is `pbr` 0008's binding of the
  confined run to the authorizing action.
- **Cleanup.** The input and output directories are deleted after the final
  stage is recorded. Plans can contain sensitive values, so nothing but
  digests enters the attempt record.

### 6.7 Recipe section

```json
"exec": {
  "program": "opentofu-saved-plan-apply/1",
  "artifacts": {"plan": "plan_sha256", "config": "config_sha256"},
  "state": {"lineage": "state_lineage", "serial": "state_serial"},
  "credentials": [
    {"name": "aws_access_key_id", "environment": "AWS_ACCESS_KEY_ID"},
    {"name": "aws_secret_access_key", "environment": "AWS_SECRET_ACCESS_KEY"}
  ],
  "egress": [
    {"host": "sts.us-east-1.amazonaws.com", "port": 443},
    {"host": "s3.us-east-1.amazonaws.com", "port": 443}
  ],
  "limits": {"run_seconds": 900, "memory_mib": 2048}
}
```

| Field | Rule | Code |
| --- | --- | --- |
| `program` | A key of `EXEC_PROGRAMS`: `opentofu-saved-plan-apply/1`, or the interim `opentofu-plan-check/1` (§6.14) | `gateway.recipe.exec.unregistered-program` |
| `artifacts`, `state` | Each names a distinct top-level profile field of the stated type; `state` is absent for `opentofu-plan-check/1` | `gateway.recipe.exec.invalid-binding` |
| `credentials` | 1–8 entries for apply, and none for plan-check. `name` matches `[a-z][a-z0-9_]{0,31}`, and names are unique. `environment` matches `[A-Z][A-Z0-9_]{0,63}`, is unique, and is not one of §6.8's fixed variables or any `TF_*` name | `gateway.recipe.exec.invalid-credential` |
| `egress` | 1–16 unique entries for apply, and none for plan-check. `host` is a lowercase DNS name of at most 253 bytes, with no wildcard and no IP literal, and is none of `registry.opentofu.org`, `registry.terraform.io`, `github.com`, or `objects.githubusercontent.com`. `port` is 443 | `gateway.recipe.exec.invalid-egress` |
| `limits` | `run_seconds` 60–3 600, `memory_mib` 256–8 192 | `gateway.recipe.exec.invalid-limits` |
| `bounds` (top level) | Absent | `gateway.recipe.exec.bounds-not-allowed` |

Every profile field must be consumed by `artifacts` or `state`.

### 6.8 Invocations, plans, and credential delivery

Each invocation is one `pbr run` of a constant plan. The plans are install
data, not code. `auths-gateway exec plans --manifest <manifest>` prints each
plan's logical fields as JSON: command, arguments, working directory, read,
runtime-read, write, execute, environment names, egress endpoints, and
limits. The operator encodes them with `pbr`'s own plan SDK from the pinned
release, and `install` records each plan's SHA-256.

At every `serve` start, the gateway requires two things for each plan
(`gateway.serve.exec-plan-mismatch`):

- that it passes `pbr plan check`; and
- that the normalized explanation `pbr plan check` prints equals the logical
  fields, field by field.

The gateway contains no `pbr` plan encoder. All paths are fixed, so plan
bytes do not vary by run, and runs are serialized per installation (§13,
reading 26).

| Plan | Command | Write root | Extra read authority | Network |
| --- | --- | --- | --- | --- |
| `init` | `tofu -chdir=/var/lib/auths-gateway/exec/input/config init -input=false -no-color -lockfile=readonly -backend=true` | `…/exec/out-init` | — | The recipe's endpoints |
| `state-before`, `state-after` | `tofu -chdir=… state pull` | `…/exec/out-state-before` or `…/out-state-after` | `…/out-init`, read-only | The recipe's endpoints |
| `apply` | `tofu -chdir=… apply -input=false -no-color -lock=true -lock-timeout=10s /var/lib/auths-gateway/exec/input/plan.tfplan` | `…/exec/out-apply` | `…/out-init`, read-only | The recipe's endpoints |

- **Common authority.** Every plan's read authority includes the input
  directory, the mirror, the CLI configuration, and the CA bundle. Its
  execute authority is the OpenTofu binary and the pinned plugins, and
  nothing else.
- **Environment names.** The fixed names, plus the declared credential names.
- **Limits.** `processes` 512, `memory_bytes` from `memory_mib`, `swap_bytes`
  0, and `wall_time_ms` 300 000 for `init` and the state reads, or
  `run_seconds` × 1 000 for `apply`. `stdout_bytes` is 16 MiB for the state
  reads and 1 MiB otherwise; `stderr_bytes` is 1 MiB.
- **Read-only data directory.** `state pull` and `apply` run with the `init`
  data directory read-only. Epic 8 confirms that the pinned OpenTofu series
  runs them without writing there. If it does not, `pbr` must also let a
  plan declare a copy of an earlier run's output root, bound by that run's
  receipt, as a writable seed. That is then an eighth start-gate item.
- **Fixed environment.** The gateway spawns `pbr run` with a cleared
  environment plus exactly these fixed values:
  - `TF_DATA_DIR=/var/lib/auths-gateway/exec/out-init/data`;
  - `TF_CLI_CONFIG_FILE`;
  - `TF_IN_AUTOMATION=1` and `TF_INPUT=0`;
  - `CHECKPOINT_DISABLE=1`;
  - `HOME` inside the plan's write root; and
  - `SSL_CERT_FILE`.
- **Credentials.** The gateway adds each declared credential's value under
  its `environment` name, leased from the credential store after the claim
  (063 §5.5 step 9). `pbr` passes only allow-listed names to the child, and
  its receipt records names only (E7). The values exist in the environment of
  the gateway-owned `pbr` process and the child, never on disk, in an
  argument, or in a receipt (§13, reading 23).
- **Unsupported providers.** A provider that reads secrets only from a file
  cannot be used (§12).

### 6.9 Egress

Enforcement is `pbr`'s (§6.4). The gateway declares the recipe's endpoints in
each plan and, after each run, requires the receipt's recorded endpoints to
equal them exactly (`gateway.exec.receipt-rejected` otherwise). Whether a
denied connection happened is not visible to the gateway beyond what the
receipt records. A denied connection is the provider's error inside
OpenTofu, and the gateway does not interpret it.

### 6.10 Receipts and output bounds

After each run, the gateway:

1. reads `pbr run`'s result projection for the receipt path, the commitment,
   and the execution ID;
2. runs the pinned `pbr-verify --expected-commitment <commitment>` on the
   receipt;
3. runs the pinned `pbr-accept` with the installed acceptance policy (`pbr`
   0010). That policy requires exact equality of the plan ID, the executable
   digest, the compiled-policy digest, `pids.max`, `memory.max`,
   `memory.swap.max`, and reusable eligibility, and it binds the pinned
   release's assurance bundle; and
4. requires the receipt's input inventory to contain `action.cbor`,
   `plan.tfplan`, and the bundle files with their verified digests, and its
   endpoints to equal the recipe's.

A failure at any step is `gateway.exec.receipt-rejected`. For `init` or a
state read, that is recorded `not-entered`. For `apply`, the run happened but
its account is not trusted, so the stage is `unknown`.

- **Evidence stored.** Receipt bytes go to the gateway's evidence directory,
  keyed by commitment, and are exported in the audit bundle. The attempt
  record stores the commitments in run order. The outcome's
  `runtime-receipts-digest` (§4.4) is SHA-256 over
  `auths.gateway-runtime-receipts/1`, a NUL byte, and the 32-byte commitments
  in run order. An auditor re-runs `pbr-verify` on each exported receipt with
  its commitment, which the signed outcome carries through that digest, as
  `pbr`'s ADR 0002 requires.
- **Output.** The streams are those `pbr` captured, bounded by the plan's
  limits, with their digests and truncation recorded in the receipt. The
  gateway reads the state reads' stdout for `/lineage` and `/serial`. A
  truncated stream is unavailable. Output is never returned to the
  application.

### 6.11 Submission order for `exec`

| 063 step | `exec` action | On failure |
| --- | --- | --- |
| 1–8 | Unchanged; artifact binding before the claim (§6.6) | As 063 |
| 9 | Lease; stage artifacts; run `init` and require exit 0 and an accepted receipt; run `state-before` and require exit 0, an accepted receipt, and a JSON `/lineage` equal to `state_lineage` and `/serial` equal to `state_serial` | Recorded `not-entered`: `gateway.exec.launch-failed`, `gateway.exec.init-failed`, `gateway.exec.receipt-rejected`, `gateway.exec.state-unavailable`, or `gateway.exec.state-stale` |
| 10 | Nothing | — |
| 11–12 | Unchanged | As 063 |
| 13 | Start `pbr run` of `apply`; this is transport entry | `pbr` refuses before child release (a `denied` or `launcher-failed` outcome whose receipt shows no child start): `not-entered`, `gateway.transport.not-entered` |
| 14 | `pbr run` returned an accepted receipt: record `response-recorded` with `exit-status` and the receipt commitments. Otherwise (`timed-out`, `incomplete`, a rejected receipt, or a lost process): `unknown` | — |
| 15 | Run `state-after` once and record `observed` (§6.12) | Read unavailable: the stage stays `response-recorded` |

- **Pre-apply state read.** It restores, in the gateway, the stale-plan
  refusal that 063 §12 removed from production, as data-only equality on two
  JSON values. OpenTofu's own stale-plan check still runs inside `apply`.
- **Order.** §8.4 proves that `apply` starts only after the state read
  matched and the artifacts' digests were checked.

### 6.12 Evidence and recovery class

`exec` recipes use 063's existing class `observed`. No new recovery class is
added.

- **Observation.** After a complete run, `state-after` gives `observed` with
  `match` when both hold:
  - `/lineage` equals `state_lineage`; and
  - `/serial` is greater than `state_serial`.

  Otherwise it gives `observed` with `mismatch`. The outcome carries
  `state-serial`, and the attempt stores `state_before` and `state_after`,
  each with the SHA-256 of the pulled state.
- **What `match` shows.** That OpenTofu wrote a newer state in the same
  lineage after the run. It does not show that every planned change was
  applied, or that any provider resource has any value.
- **`unknown`.** It stays `unknown`, and 063's rule of no `unknown → observed`
  edge applies: after a partial apply, the state shows only what OpenTofu
  recorded. `reobserve` answers `gateway.reobserve.not-observable`.
- **No provider link.** OpenTofu offers no place to carry 059's token into
  the provider records of an arbitrary plan. The `pbr` receipts bind the
  confined run to the action (§6.6), which is a link between the gateway and
  the run, not between the run and the provider.

### 6.13 What the `exec` transport cannot claim

- That the credential is secret from the approved plan's provider plugins.
  It is isolated from the application and from the gateway's other
  credentials, not from the code that uses it.
- Closed request construction for provider traffic. Only the plans, argument
  vectors, and environment names are proved closed (§8.4).
- Atomicity, a conditional write, or a proved non-effect.
- That egress to an allowlisted multi-tenant host went only to the operator's
  own resources.
- That the plan contains only the changes a reviewer intended. Reviewing the
  plan is the approvers' duty, bound by `plan_sha256`, and §6.14's check can
  help them.
- Anything `pbr`'s own non-claims exclude: a malicious host administrator, a
  compromised kernel, side channels, and the correctness of Linux, Landlock,
  or seccomp (`pbr` 0001 §3.3).

### 6.14 Interim: network-free plan check

**Purpose.** Until a `pbr` release meets §6.4, OpenTofu `apply` stays on the
self-hosted adapter path (AP-SPEC-054), where the application holds its own
credentials. The gateway offers one narrower program entry,
`opentofu-plan-check/1`. It is fully specified here, and it needs neither
credentials nor network.

**What it attests.** Under the pinned OpenTofu binary and providers, inside
`pbr` with network denied, the plan with digest `plan_sha256` and the bundle
with digest `config_sha256` render to JSON with digest D. The render
reports no error, and it names the pinned OpenTofu version. The outcome
signs D. An approver who reviews that JSON can then confirm that it is the
rendering of the plan they approve. This addresses 0008 §3's plan-summary
confusion without any provider access.

**`pbr` requirements.** Only E5 (the multi-executable closure) and E6 (the
process limit above 1), because rendering starts the provider plugins to
read their schemas. It needs no network. If a `pbr` release meeting E5 and
E6 does not exist either, the interim is the self-hosted path alone, and the
gateway offers nothing for OpenTofu.

**Recipe.** §6.7 with `program: "opentofu-plan-check/1"`, the two
`artifacts`, no `state`, no `credentials`, no `egress`, and `limits`.

**Plans.** Two constant plans, with network `deny` and the §6.8 authority
without credentials:

- `check-init`: `tofu -chdir=… init -input=false -no-color -lockfile=readonly
  -backend=false`; and
- `check-show`: `tofu -chdir=… show -json /var/lib/auths-gateway/exec/input/plan.tfplan`,
  with `stdout_bytes` 16 MiB.

**Order.**

- Steps 1–8 are as §6.11.
- Step 9 has no lease, stages the artifacts, and runs `check-init`. It
  requires exit 0 and an accepted receipt, and records `not-entered` with
  `gateway.exec.init-failed` or `gateway.exec.receipt-rejected` otherwise.
- Step 13 runs `check-show`.
- Step 14 records `response-recorded`, with `exit-status`, the receipt
  commitments, and `response-digest` D. D is the SHA-256 of the complete
  stdout, which must not be truncated.
- Step 15 evaluates three fixed checks on that JSON and records `observed`
  with `match` if all hold, `mismatch` otherwise:
  - `/errored` is `false`;
  - `/terraform_version` equals the descriptor's `tofu_version`; and
  - `/format_version` is a string whose bytes before the first `.` are `1`.
- A rejected receipt or a lost run is `unknown`.

**Backend independence.** Epic 7i confirms that the pinned OpenTofu series
runs `show` of a saved plan after `init -backend=false` without contacting
the backend. If it does not, the plan check is not offered, and the interim
is the self-hosted path alone.

**Determinism.** Epic 7i requires two renders of each fixture plan to be
byte-identical, so an approver's local render with the same pinned binaries
reproduces D.

**Claims and non-claims.** It claims the three checks and the digest binding
above. It claims nothing about the plan's effects, its safety, or its
freshness against the state backend, which it never contacts.

## 7. Stable codes

Codes marked "recorded" appear in the attempt's `refusal`; codes marked
"before claim" return `not-entered` with nothing stored.

| Code | Where |
| --- | --- |
| `gateway.recipe.invalid-transport`, `.transport-section-mismatch` | compile |
| `gateway.recipe.postgresql.invalid-identifier`, `.invalid-shape`, `.invalid-type`, `.invalid-column-binding`, `.invalid-marker`, `.invalid-timeouts` | compile |
| `gateway.recipe.exec.unregistered-program`, `.invalid-binding`, `.invalid-credential`, `.invalid-egress`, `.invalid-limits`, `.bounds-not-allowed` | compile |
| `gateway.postgresql.value-invalid`, `.tenant-unbound`; `gateway.exec.artifact-digest-mismatch`, `.artifact-oversize`, `.artifact-invalid` | before claim |
| `gateway.postgresql.connect-failed`, `.tls-refused`, `.tls-pin-mismatch`, `.auth-refused`, `.server-unsupported`, `.identity-mismatch`, `.role-attribute`, `.role-membership`, `.ownership`, `.privilege-excess`, `.privilege-missing`, `.guard-unavailable`, `.marker-invalid`, `.fingerprint-unavailable`, `.fingerprint-mismatch` | recorded `not-entered`, at step 9 |
| `gateway.postgresql.fingerprint-changed`, `.condition-false`, `.before-mismatch`, `.row-count`, `.returning-mismatch`, `.serialization-failure`, `.lock-timeout`, `.statement-timeout`, `.constraint-violation`, `.database-error`, `.operation-already-resolved`, `.session-lost-before-commit`, `.commit-refused`, `.fenced`, `.marker-other-action` | recorded `not-committed` |
| `gateway.postgresql.protocol-violation` | recorded `not-entered` or `not-committed`, by step (§5.10) |
| `gateway.postgresql.fence-unavailable` | replay and `reobserve`; record unchanged |
| `gateway.exec.launch-failed`, `.init-failed`, `.receipt-rejected`, `.state-unavailable`, `.state-stale` | recorded `not-entered`, at step 9 (`.receipt-rejected` after `apply` leaves the stage `unknown`, §6.10) |
| `gateway.install.postgresql-tls`, `.postgresql-guard`, `.postgresql-fingerprint`, `.postgresql-marker`; `gateway.admin.postgresql-tls`, `.postgresql-guard`, `.postgresql-fingerprint`, `.postgresql-marker` | install, admin |
| `gateway.serve.exec-runtime-mismatch`, `.exec-runtime-unready`, `.exec-plan-mismatch`, `.exec-platform` | serve |
| `audit.postgresql-evidence-missing`, `.postgresql-evidence-invalid` | audit |

Existing codes keep their meaning, except `gateway.transport.not-entered`,
which also covers a `pbr run` of `apply` that refused before child release.
`bindings/fixtures/gateway/codes.json` becomes `auths.gateway-codes/2` and
lists every code with a producing fixture case. Its closure rule (063 §13,
reading 39) covers the new families whole: `gateway.postgresql.`,
`gateway.exec.`, `gateway.recipe.postgresql.`, and `gateway.recipe.exec.`.

## 8. Formal obligations

The rules of 063 §11 apply unchanged:

- decision logic lives in small pure leaves under AP-SPEC-061 §3.4's
  extraction rules;
- the leaves are translated through the pinned Aeneas route;
- each has a refinement theorem to a Lean model in `formal/Auths/Product/`;
- claims are registered in `formal/assurance-manifest-v1.toml`;
- the axioms are `propext`, `Quot.sound`, and `Classical.choice`; and
- `--error-on-warnings` and `-warnings-as-errors` are on from the first
  commit.

Every 063 §11 theorem is re-proved over the extended stage and event sets
with its statement unchanged.

### 8.1 Statement construction (epic 3)

String formatting does not translate, so the leaf builds tokens.
`pg_statement_plan(recipe: &CompiledPgRecipe) -> StatementPlan` returns, for
each statement of §5.5, a `Vec<SqlToken>`. `SqlToken` is a closed enum:

- `Keyword(Kw)`, over a closed keyword set;
- `Ident(IdentRef)`, an index into the recipe's validated identifiers;
- `Placeholder(u8)`;
- `Punct(P)`, over `(`, `)`, `,`, `.`, `=`, `+`, and `::`; and
- `Literal(Lit)`, over the closed literal set `1`, `text`, and `bigint`.

`pg_parameters(recipe, arguments) -> Option<Vec<Param>>` returns the typed
parameters, and `render(&[SqlToken], identifiers) -> Vec<u8>` is the total
serializer. Model: `formal/Auths/Product/StatementConstruction.lean`. The
theorems hold for every compiled recipe and every argument map:

- `statement_text_independent_of_arguments`: `render ∘ pg_statement_plan`
  takes no argument, so two argument maps give byte-identical statement
  texts. This is "no injection by construction". No argument byte can reach
  the text.
- `identifiers_fixed`: every `Ident` token names an identifier of the
  compiled recipe, rendered as `"` + its bytes + `"`; and
  `quoted_identifier_unambiguous` shows that the identifier alphabet excludes
  `"` and NUL.
- `tokens_from_shape_grammar`: each token sequence is a production of its
  shape's grammar (§5.5). It contains no `;`, no keyword outside the shape's
  set, and exactly one statement.
- `placeholders_dense_and_typed`: the placeholders are exactly `$1`…`$n`,
  each used at least once, with `n` equal to the parameter count. Each
  parameter's type OID matches its cast.
- `values_only_as_parameters`: every consumed argument appears in exactly
  one parameter, as its canonical text, and nowhere else in the plan.
- `write_affects_declared_table`: the only `UPDATE` or `INSERT` targets
  `"schema"."table"`, and the only other write targets the marker.

`CompiledRecipe::compile`'s parsing stays covered by the hostile corpus and
fuzzing (§9.4), as in 063 §11.5.

### 8.2 Transaction order (epic 4)

The leaf is `pg_next(state: PgState, event: PgEvent) -> PgDecision` in
`transport/postgresql_order.rs`. The connection code performs I/O only as it
directs. Model: `formal/Auths/Product/PostgresTransaction.lean`. The theorems
hold over every event trace:

- `commit_requires_checks`: `COMMIT` is written only after, in this
  transaction:
  - the fingerprint matched;
  - `update-row`'s lock row count was 1 and every `expect` matched;
  - the write returned exactly one matching row; and
  - the marker insert succeeded.
- `no_commit_after_error`: after any `ErrorResponse` or failed check, the only
  statement written is `ROLLBACK`.
- `no_pipelined_commit`: `COMMIT` is never written while a statement's
  response is incomplete.
- `observed_requires_commit_tag`: `observed-by-provider` follows a T10 only
  on tag exactly `COMMIT`.
- `unknown_only_after_commit_written`: `unknown` is reachable only after the
  gateway started writing `COMMIT`; every earlier failure is `not-entered`
  (before T5) or `not-committed`.
- `guard_before_entry`: T5 happens only after G1–G8 passed on this
  connection.

`lease_requires_verified_claim` (063 §11.2) composes with
`guard_before_entry` into the transport's premise for the reference-monitor
theorem.

### 8.3 The fence (epic 4)

The model is `formal/Auths/Product/FencedCommit.lean`. It interleaves one
original transaction, any number of fences, and a session loss at any point.
It rests on an explicit model of the unique index: at most one committed row
per key, and an insert of a key held by an in-progress transaction waits
until that transaction ends. The leaf `fence_result(insert: InsertOutcome,
found: Option<[u8; 32]>, this_token, tombstone) -> FenceStage` maps the
fence's observations to a stage. The theorems:

- `commit_exclusive`: in every interleaving, at most one of "the original
  commits" and "a fence commits a tombstone" happens.
- `fence_found_implies_commit`: `observed-by-provider` from a fence implies
  that the original committed.
- `fenced_implies_never_commits`: `not-committed` from a fence implies that
  the original commits in no extension of the trace.
- `resolution_complete`: a fence that neither times out nor loses its session
  records `observed-by-provider` or `not-committed`.
- `fence_never_writes_target`: no fence event writes the target table.
- `unknown_resolves_only_by_fence`: for class `fenced-commit`, `unknown` leaves
  only through a fence result.
- `recovery_capability_v2_total`: every declaration maps to exactly one
  capability, and `write_is_conditional` is `true` exactly for `postgresql`.
- `not_committed_final` and 063's `terminal_stages_final`, extended.

### 8.4 `exec` invocation (epics 7i and 8)

The leaf is `exec_invocation(descriptor: &ExecDescriptor, plan: PlanKind,
credentials: &[LeasedName]) -> Invocation`, together with `exec_next` for
§6.11's and §6.14's orders. An `Invocation` is the pinned `pbr` path, the
plan's pinned digest, and the environment. Model:
`formal/Auths/Product/ExecInvocation.lean`. The theorems:

- `plan_constant`: each invocation names a plan whose digest is the
  descriptor's for that kind, independent of every verified argument; the
  `pbr` argument vector is a constant.
- `environment_from_declaration`: each environment's names are exactly the
  fixed set plus the declared credential names. Fixed values are constants,
  credential values come only from the leased credentials, and no verified
  argument appears in the environment.
- `plan_check_credential_free`: an `opentofu-plan-check/1` invocation carries
  no credential name and names a plan with network `deny`.
- `artifacts_bound`: the staged plan and bundle are bytes whose SHA-256 equal
  the verified fields.
- `apply_requires_fresh_state`: `apply` starts only after `init` exited 0 and
  the state read matched `state_lineage` and `state_serial`.
- `at_most_one_apply`: each claim starts `apply` at most once, including
  under replay.

### 8.5 Kani, fuzz, property tests, and residual assumptions

- **Kani**, exhaustive over finite domains:
  - `valid_transition` with the rows of §4.5;
  - `recovery_capability` `/2`;
  - `fence_result` over every insert outcome and token relation;
  - the §4.4 fact-presence rule; and
  - `pg_next` for traces of up to 12 events.
- **Fuzz targets,** added to `auths-gateway-fuzz`:
  - `target_gateway_recipe_v3` checks that `compile` never panics and that
    digests are stable;
  - `target_gateway_pg_statement` checks, on fixture recipes and arbitrary
    arguments, that the rendered text equals the fixture's text and the
    parameters round-trip; and
  - `target_gateway_pg_backend` checks that parsing an arbitrary backend
    message sequence never panics and reaches a fail-closed stage.
- **Property tests:**
  - injection strings (quotes, `;`, `$1`, NUL, `--`, Unicode confusables) as
    every argument leave the statement text unchanged;
  - text of every type round-trips through PostgreSQL in the lifecycle
    workflow;
  - a model-based race runs an original and 1–3 fences with random session
    loss against a real PostgreSQL. It must resolve to exactly one commit
    decision and never contradict the table's final state.
- **Residual assumptions,** recorded in the manifest and the claim ledger,
  in addition to 063 §11.7's:
  - PostgreSQL's documented unique-index wait and transaction abort on
    session end;
  - `SERIALIZABLE` as documented;
  - the fidelity of `tokio-postgres`'s message framing;
  - the durability boundary of §1.3; and
  - for `exec`, `pbr`'s stated assumptions and non-claims (`pbr` 0001
    §3.3), the fidelity of `pbr-verify` and `pbr-accept`, and §6.13.

## 9. Reuse and the boundary-plan evidence gate

### 9.1 The gate for each transport

- **`postgresql`.** One domain consumer, one vertical (`auths-postgresql`),
  and a written comparison in case 0007 per §2.2's rows. It is therefore a
  smaller promotion under an ADR (ADR 0014), whose argument is that each
  mechanism is PostgreSQL protocol behavior, identical for every schema, with
  every schema choice as recipe data. The differential oracle (§5.13) is the
  plan's "differential tests against every existing implementation". The
  vertical's evaluator, fixtures, and demo stay as the test-only oracle.
- **`exec`.** One domain and two program entries (apply and the interim plan
  check), admitted by the same ADR as a separate decision. §6.1 is its "why composition of smaller primitives is
  insufficient" and §6.13 its excluded assumptions.

### 9.2 What does not move into the gateway

- The vertical's multi-row updates, typed values beyond §5.5's table,
  evidence preflight (042 §5), and receipts stay in `auths-postgresql`.
- OpenTofu's bundle validation beyond §6.6's archive rules, the plan
  projection, and its restrictions stay in `auths-opentofu`.

### 9.3 The checklist

For both transports:

1. **Consumers.** One vertical each.
2. **Identical semantics.** The listed protocol mechanisms.
3. **Only similar.** Recovery: HTTP's `linked` class and PostgreSQL's
   `fenced-commit` are both "provider-held evidence", but their evidence and
   transitions differ, so they stay separate classes.
4. **Operation tag.** None; there is a closed transport tag.
5. **New provider outcome.** A new transport outcome needs a stage only if it
   proves something new, as `not-committed` does.
6. **Codes.** Each transport keeps its codes.
7. **Fixtures.** The vertical corpora.
8. **Layer.** Product, the lowest valid one.
9. **Cutover evidence.** The oracle comparison.
10. **Formal claims.** Stronger for `postgresql`, weaker for `exec` (§6.13).
11. **Reversibility.** Each transport is a separate module behind the closed
    enum, and removable before release without a second runtime path.

### 9.4 Hostile corpus

`bindings/fixtures/gateway/recipes-hostile-v3.json` holds these cases:

- an HTTP field in a `postgresql` recipe;
- two sections;
- `transport` without its section;
- a quoted identifier, `pg_` prefix, 64-byte identifier, or upper-case
  identifier;
- `DELETE` as a shape;
- a key that is not the primary key;
- a `set` column that is the version;
- a `numeric` type;
- 33 parameters;
- a marker equal to the target;
- `statement_ms` 0 and 30 001;
- an unregistered program;
- a registry host in `egress`;
- an IP literal in `egress`;
- `TF_LOG` as a credential environment;
- `bounds` on `exec`;
- nine credentials; and
- a plan-check recipe with `credentials` or `egress`.

`bindings/fixtures/gateway/postgresql-scenarios.json`
(`auths.gateway-postgresql-scenarios/1`) runs in the PostgreSQL workflow on
versions 14 and 18:

- the exact commit;
- `condition-false` (stale version);
- `before-mismatch`;
- `returning-mismatch`, by a trigger that alters the value after its
  fingerprint was pinned, which the fingerprint then refuses at T6;
- `fingerprint-changed` (a trigger added before T6);
- `serialization-failure` from two racing gateways, exactly one committing;
- `operation-already-resolved` after a wiped gateway store;
- a session killed before `COMMIT` (`not-committed`);
- a session killed during `COMMIT`, then a fence finding the marker;
- a session killed during `COMMIT` of a rolled-back transaction, then a
  fence recording `fenced`;
- a fence racing an in-flight original, exactly one of commit and tombstone;
- a fence timing out behind a held lock (`fence-unavailable`);
- guard failures for each of G1–G8 (a `BYPASSRLS` role, a member of
  `pg_write_all_data`, an owner, `DELETE` granted, an extra column `UPDATE`,
  `PUBLIC` `INSERT` on another table, a standby, and a wrong database OID);
- a TLS pin mismatch;
- an MD5-only and a cleartext-only server;
- SCRAM without channel binding;
- injection strings in every parameter;
- a `search_path` attack (an unqualified shadowing function in `public`);
- the tenant outside the grant; and
- the statement and lock timeouts.

Every refused case before T5 has zero transactions begun, and every
`not-committed` case leaves the table and the marker unchanged, checked
through a separate connection.

## 10. Epics and done gates

Order: 1, 2, 3, 4, 5, 6 for `postgresql`; then 7i, 7, and 8 for `exec`.

- **Epic 7i** starts after epic 6 is done, once the owner accepts ADR 0014's
  `exec` decision and a digest-pinned `pbr` release meets E5 and E6.
- **Epic 7** starts only when a digest-pinned `pbr` release meets every item
  of §6.4 (E1–E7), consumed as a release archive.

If no such release exists, OpenTofu stays on the self-hosted path, and epics
7 and 8 wait. Board rules 1, 2, 7, and 10 apply. Done means an artifact: hosted
CI on the exact revision, or a commit whose diff holds the evidence.

Sizes are agent time at the speed 063's epics ran (spec to seven merged epics
in three days), excluding hosted-CI wall time:

- S is up to half a day;
- M is half a day to a day; and
- L is one to two days.

| Epic | Work | Size | Done |
| --- | --- | --- | --- |
| 1. Case file and fixtures | ADR 0014; case 0007 transport sections with §2.2's comparison; `recipes-hostile-v3.json`, `postgresql-scenarios.json`, `outcome-v3.json`, and the `codes.json` `/2` entries; the vertical's `compile_insert` reference and its fixtures | M | The vectors exist and fail against current code; the ADR and case file are reviewed |
| 2. Recipe `/3` and evidence cutover | §3 and §4 with the `https` transport only: compiler, review `/3`, recovery capability `/2`, attempt `/4`, outcome `/3`, audit `/3`, descriptor `/2`, the clients, the north-star example, derivation, and every regenerated fixture; no behavior change for HTTP | M | The north-star journey and every 063 suite are green on `/3`; Rust, Python, and TypeScript agree on `outcome-v3.json`'s `https` entries; 063 §11's theorems are re-proved over the extended stages with `cargo xtask formal` green |
| 3. PostgreSQL statement construction | §5.5: the AST, the types, `pg_statement_plan`, `pg_parameters`, `render`, and the differential oracle (§5.13); §8.1 | L | `postgresql_statements_match_reference` passes on the corpus and 10 000 generated cases; every hostile recipe fails with its code; §8.1 is proved and registered with `cargo xtask formal` green |
| 4. PostgreSQL transport and recovery | §5.1–§5.4 and §5.6–§5.10: connection, pinned TLS, SCRAM-PLUS and client certificates, the guard, the fingerprint, the transaction protocol, the marker, the fence, and the store transitions; §8.2 and §8.3; the Kani harnesses and fuzz targets | L | `postgresql-scenarios.json` passes on PostgreSQL 14 and 18 in the PostgreSQL workflow, with every refusal before T5 showing zero transactions and every `not-committed` leaving no change; the fence race resolves to exactly one decision in 1 000 randomized runs; §8.2 and §8.3 are proved and registered |
| 5. PostgreSQL operator plane | §5.11: descriptor `/2`, `install`, `--join`, and `rotate` with the guard; `postgresql marker-ddl` and `postgresql fingerprint`; `reobserve` running the fence; tenant binding in admission | M | A second host joins only with the matching secret; `rotate` refuses a candidate that fails the guard; a disable through process A stops entries in process B; `reobserve` resolves an `unknown` scenario; a tenant outside the grant refuses with zero leases |
| 6. PostgreSQL journey | A new `examples/postgresql-account-review/` that runs 0009 §18's scenario through the gateway from the packed wheel: the exact update, a stale version, a before-value change, a replay, a lost-`COMMIT` fence, and an offline audit; the claim ledger entry uses §1's claim and non-claim wording; the status notes of 0009 and 042 are amended | M | The journey is green in hosted CI from the packed wheel; the audit shows `observed-by-provider` and `not-committed` entries with their evidence; the ledger entry exists |
| 7i. `pbr` integration and network-free plan check | ADR 0014's `exec` decision accepted; `exec install-runtime` and the descriptor's `runtime` and `exec` pins (§6.4, §6.5); the plan manifests and `serve`'s `pbr plan check` comparison (§6.8); the receipt pipeline with `pbr-verify` and `pbr-accept` (§6.10); outcome `runtime-receipts-digest`; `opentofu-plan-check/1` (§6.14); version pins re-confirmed with sources | M | In a Linux CI job on the pinned `pbr` release: a fixture plan checks `match` with two byte-identical renders; a substituted binary, plugin, or plan file refuses at `serve`; a plan outside the closure is refused by `pbr` and recorded; a shell provisioner fails inside `pbr`; the audit re-verifies every exported receipt with its commitment; §8.4's plan-check theorems are proved and registered |
| 7. `exec` egress integration | On the `pbr` release meeting E1–E7: the apply-phase plans with endpoints and credential names; the receipt endpoint comparison (§6.9); hostile tests: a connection to an undeclared host, DNS from the child, UDP, a private address, a credential name not declared (absent in the child), the credential absent from the receipt, the output root, and the arguments, and a receipt whose endpoints differ from the recipe's | M | The hostile suite is green in hosted CI on the pinned release, and every probe that should fail does, with the refusal visible in the receipt where `pbr` records it |
| 8. OpenTofu saved-plan apply | §6.5–§6.13: artifacts, the four plans, credential delivery, the state checks, outcomes, and the rest of §8.4; the read-only data-directory check of §6.8; a journey against a local S3-compatible backend and an allowlisted test endpoint, with the provider pinned in the mirror; status notes of 0008 and 043 amended | L | The journey applies a saved plan once and records `observed` with `match`; a stale serial refuses at step 9 with `gateway.exec.state-stale` and zero `apply` starts; a substituted plan refuses before the claim; a replay starts no second `apply`; §8.4 is proved and registered |

## 11. Conflicts with committed documents

Each amendment lands with the epic that causes it.

| Document | Conflict | Resolution |
| --- | --- | --- |
| ADR 0012, decision and consequences | "A domain whose provider is not reached over HTTPS, such as PostgreSQL or OpenTofu, has no production path" | ADR 0014 amends it: such a domain has a production path through an admitted transport; the interpreter's rules (no third-party code, no runtime request, no callback, no provider tag) stand. Lands in epic 2 for the rule and epic 6 for PostgreSQL's status |
| Boundary plan, "Vocabulary" paragraph | The same sentence | Rewritten with ADR 0014: "a domain whose provider speaks a protocol with no admitted transport has no production path" |
| ADR 0013 | Lists the recipe capabilities as optional HTTP fields | ADR 0014 adds transports as a separate kind of capability; ADR 0013's ten capabilities become fields of the `https` section |
| 063 §1, "Not a claim" | "A conditional write" | Scoped to `https`; §5.7 |
| 063 §4.2 | `write_is_conditional` always `false` | Recovery capability `/2`: `true` for `postgresql` |
| 063 §4.3, §4.4 | No `unknown` resolution except for `linked` recipes; no `not-committed` stage | §4.5's rows and §5.9's fence |
| 063 §4.5 | The retention rule for every recipe that declares idempotency | Unchanged for `https`; `postgresql` declares no retention, and its de-duplication is the marker |
| 063 §5.5 | Transport entry is the point of possible effect | §4.1 separates them for `postgresql` |
| 063 §8.1, §8.3 | Outcome and audit `/2` | Outcome and audit `/3` (§4.4, §4.7) |
| 063 §13, reading 10 | Recipe `/2` | Recipe `/3` (§13, reading 1) |
| 063 §16 | "A non-HTTP transport … needing its own ADR and case file" | This spec, ADR 0014, and the case 0007 sections |
| 053 §1 | First scope: HTTPS static credentials in one header | Unchanged for `https`; `postgresql` and `exec` add their own credential kinds |
| 0009 §15 | A serialization failure may be retried under conditions | The gateway never retries (§13, reading 3); 0009 stays the reference |
| 0009 §4, §7 | Up to many rows; `INSERT` excluded | One row; `insert-row` is admitted after the reference gains `compile_insert` (§2.2) |
| 0009, 042, 0008, 043 status notes | "no gateway recipe can express it" | Amended by epics 6 and 8 to name the transport and what it does not keep |
| settled.md | "gateway writes aren't conditional on the record being unchanged" | Scoped to the `https` transport |
| Proofbound Runtime 0001 §5.2, plan `/2`'s single `execute` path, and ADR 0004 (external repository) | Network fixed to `deny`; one executable; one connector-owned session | Not amended here. §6.4 lists what `pbr` will specify in its own repository; epic 7 waits for that release |
| Board rule 3 | Specs are written when an epic starts | The owner directed this one ahead, as with 059–061 and 063 (board §4, 2026-09-28) |

## 12. Non-goals

| Non-goal | Reason |
| --- | --- |
| An open `exec` transport, or argument templates | §6.1: effect semantics would live in an operator-chosen binary |
| Multi-row statements, `DELETE`, `MERGE`, `ON CONFLICT`, joins, subqueries, and statements beyond §5.5's two shapes | Each needs a new vertical reference and comparison first; a multi-row write also needs a set-valued parameter the extraction rules and oracle do not cover |
| `numeric`, `timestamptz`, `json`, `bytea`, arrays, and null as bound types | Their text forms depend on typmod, session settings, or encoding, so the `RETURNING` equality of §5.8 would need per-type canonicalization this spec does not define; a recipe that needs one is refused |
| Retrying a serialization failure | A retry is a second attempt at the write; the gateway's guarantee is at most one attempt per claim (063 §4.6) |
| Cloud IAM database tokens and other cleartext-password authentication | Cleartext authentication has no channel binding; §5.2 admits only SCRAM-SHA-256-PLUS and client certificates |
| Connection poolers in front of the database | The fence relies on server-side session and lock semantics; a transaction-mode pooler preserves them, but the gateway cannot verify which pooler is present, and the pin names the server it reaches |
| Standby reads or writes | G1 refuses a server in recovery |
| Releasing count or sum slots on a proved non-effect | 063 §13 readings 2 and 17 stand; release needs a new evaluator and theorem |
| Interpreting OpenTofu plans in the gateway | Tool semantics stay in `auths-opentofu` (§6.1) |
| Providers that read secrets only from files | §6.8 delivers credentials as environment values under declared names, and a secret file would sit on disk in a read root |
| Kernel-escape resistance for `exec` | Outside `pbr`'s claim (`pbr` 0001 §3.3); it would need a VM layer |
| Running `exec` natively on macOS | `pbr` executes only on native Linux; macOS can validate plans and inspect receipts, and developers use a Linux VM |
| An egress mechanism in the gateway | Egress belongs in `pbr` by owner decision (§6.4) |

## 13. Readings and decisions (PROVISIONAL)

Board rule 8 applies: each pick is the narrower reading (fail closed, smaller
claim) unless noted, and none widens a claim or a credential scope. Three
owner decisions of 2026-09-28 are not listed, because they are not
PROVISIONAL:

- Proofbound Runtime is the `exec` sandbox (§6.2);
- `pbr` gains typed network egress, specified in its own repository (§6.4);
  and
- the `exec` apply phase is gated on a digest-pinned `pbr` release with that
  capability, and consumes it as a release archive (§10).

| # | Question | Readings | Pick |
| --- | --- | --- | --- |
| 1 | How recipes gain a transport | (a) `/3`, with `transport` required and HTTP fields under `https`; (b) an additive `/2` rule where absence means `https` | (a): (b) is a compatibility default the prelaunch rule forbids (§3.2) |
| 2 | The outcome's new facts and stage | (a) outcome `/3`; (b) optional facts in `/2` | (a): the fact set changes meaning (063 §13, reading 1) |
| 3 | A serialization failure | (a) `not-committed`, never retried; (b) retried within the claim, as 0009 §15 allowed | (a) |
| 4 | Whether a `postgresql` recipe must declare the marker | (a) required; (b) optional, with class `recorded` without it | (a): without it no ambiguous commit resolves and no lost claim is de-duplicated |
| 5 | How an ambiguous commit resolves | (a) a fence that commits a tombstone marker; (b) `pg_xact_status` of a transaction ID recorded before `COMMIT`; (c) a read-only marker lookup | (a). Not the narrower reading on writes, since it adds one row to the gateway-owned marker table per resolution. (b) needs a store write inside the transaction window, answers `NULL` past the commit-log horizon, and can report a reused ID's outcome after a failover. (c) is unsound against an in-flight original, which can insert its marker after the lookup and commit. Only (a) is exact (§8.3) |
| 6 | Role memberships | (a) none allowed, predefined roles included; (b) memberships allowed, checked through inherited privileges | (a) |
| 7 | The scope of the privilege check | (a) every relation in the database, at onboarding and every lease; (b) the target and marker only | (a); it costs one catalog query per lease |
| 8 | Authentication methods | (a) SCRAM-SHA-256-PLUS and client certificates; (b) also SCRAM without channel binding | (a) |
| 9 | Bindable types | (a) §5.5's closed set; (b) also `numeric` and `timestamptz` with declared canonical forms | (a) (§12) |
| 10 | Rows per write | (a) exactly one; (b) up to 256, as the vertical allowed | (a) |
| 11 | `DELETE` | (a) excluded; (b) a `delete-row` shape | (a): no vertical reference |
| 12 | `ON CONFLICT` | (a) excluded; (b) `DO NOTHING` | (a): `DO NOTHING` returns zero rows and would need a second success meaning |
| 13 | Slots after `not-committed` | (a) never released; (b) released on proved non-effect | (a), as 063 readings 2 and 17 |
| 14 | The operation ID after `not-committed` | (a) consumed; (b) re-enterable | (a): the claim's guarantee is at most one attempt, and the marker also refuses a re-entry after a fence |
| 15 | Where the schema fingerprint lives | (a) the descriptor, as environment data; (b) the recipe | (a): the recipe stays portable across environments, and the operator approves both by digest; statement text still depends on the recipe alone |
| 16 | When the guard runs | (a) at onboarding and every lease, fences included; (b) at onboarding only | (a) |
| 17 | A standby | (a) refused; (b) allowed for fences | (a) |
| 18 | `synchronous_commit` | (a) forced `on` in the transaction; (b) the server's setting | (a) |
| 19 | Fences on `attempting` records | (a) allowed from 35 s after the entry deadline; (b) only on `unknown` | (a): the fence is exact against an in-flight original, and a crashed process leaves `attempting` |
| 20 | Tenant binding | (a) optional per recipe; when declared, every link's scope must list the tenant; (b) always required | (a): not every table is tenant-partitioned, and a recipe without it is still bounded by its key and version |
| 21 | The `exec` transport | (a) a closed registry, holding the apply entry and the interim plan-check entry; (b) any digest-pinned binary with argument templates | (a) (§6.1) |
| 22 | How `exec` artifacts arrive | (a) in the submission frame within 8 MiB, bound by digest before the claim; (b) a separate staging channel | (a): no new channel or state; plans above 4 MiB are refused |
| 23 | `exec` credential delivery | (a) environment values under declared names, passed by `pbr`'s allow-list and recorded by name only; (b) secret files in a read root | (a): (b) puts the secret on disk and in a receipt's input inventory by digest |
| 24 | The pre-apply state check | (a) the gateway's equality check plus OpenTofu's own; (b) OpenTofu's only | (a) |
| 25 | `exec` recovery | (a) 063's class `observed`, with no `unknown → observed` edge; (b) a new class that resolves `unknown` from the state serial | (a): a newer serial after a lost run cannot show whether the plan fully applied |
| 26 | `exec` run paths and concurrency | (a) fixed paths and one run at a time per installation, so the `pbr` plans are constant install data; (b) per-run paths, with plans generated by the gateway | (a): the gateway then contains no plan encoder and depends on no unpublished `pbr` package; `exec` throughput is one run at a time |
| 27 | macOS development | (a) `postgresql` native; `exec` plans validated and receipts inspected natively, runs in a Linux VM; (b) a native macOS sandbox for `exec` | (a): `pbr` does not execute on macOS, and no other macOS sandbox gives equivalent evidence |
| 28 | Supported OpenTofu versions | (a) the series with security support at install, 1.11 and 1.12 as surveyed; (b) any | (a) |
| 29 | Egress | (a) exact hostnames on port 443, declared as `pbr` endpoints; (b) wildcards or IP ranges | (a) |
| 31 | What stays on the self-hosted path until `pbr` meets §6.4 | (a) OpenTofu `apply`, with the gateway offering only the network-free plan check; (b) an interim apply sandbox from other tools, such as systemd with an allowlisting proxy | (a): (b) would be a second sandbox path, replaced later, whose runs leave no verifiable record |
| 32 | The `pbr` receipt check | (a) `pbr-verify` and `pbr-accept` with an installed, digest-pinned acceptance policy; (b) `pbr-verify` alone | (a): it re-checks the plan, executable, compiled policy, limits, and eligibility against pinned values, with `pbr`'s own tool |
| 30 | `bounds` on `exec` recipes | (a) refused; (b) allowed on a verified integer field | (a): nothing in an `exec` write consumes an amount, so a sum would bound a label, not an effect |

## 14. Verification and release boundary

Hosted CI on the exact revision is the gate. This spec runs no checks and
asserts no outcome. Until the named epic is green, no document may say the
following:

| Until | No document may say |
| --- | --- |
| Epic 4 is green | The gateway writes to PostgreSQL, makes a conditional write, or resolves an ambiguous commit |
| Epic 3 is green | Statement text is machine-checked to be independent of arguments |
| Epic 5 is green | The PostgreSQL credential is checked by introspection at every lease across processes |
| Epic 6's ledger entry exists | PostgreSQL writes have a production path again |
| Epic 7i is green | The gateway checks OpenTofu plans |
| Epic 8 is green | The gateway runs OpenTofu `apply` |

Every such statement also carries §1.3's non-claims, or §6.13's for `exec`.
Until a `pbr` release meeting §6.4 is pinned, no document may say that `pbr`
enforces egress for the gateway.
