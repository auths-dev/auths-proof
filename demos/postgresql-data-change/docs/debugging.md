# Fail-closed debugging

- `verifier-configuration-mismatch`: compare the complete required and executed
  policy objects in the decision receipt. A `maximum_rows` change from 3 to 4
  must stop before proof verification, claim, credentials, or transactions.
- `schema-fingerprint-mismatch`, `policy-fingerprint-mismatch`, or
  `trigger-fingerprint-mismatch`: quarantine execution, inspect catalog DDL
  through the migration identity, and issue new evidence and authorization
  after an intentional change.
- `row-set-mismatch` or `before-state-mismatch`: another actor or stale
  observation changed candidates, keys, versions, or values. Do not widen the
  predicate; discover and authorize a new action.
- `already-claimed`: inspect the external claim and database ledger. A replay
  never acquires a credential or submits the update again.
- `transaction-conflict`: bounded retries may use only the identical action,
  claim, configuration, and preconditions.
- `execution-outcome-unknown`: query the ledger by action digest through a fresh
  connection. Never blindly resubmit.
- `/readyz` unavailable: check TLS roots, `sslmode=require`, private network,
  database availability, and role existence. Readiness performs no mutation.

Search logs and receipts for the executor password, connection-string userinfo,
CA private keys, tenant values, primary keys, and row values. Any occurrence is
a security incident. The service never formats or logs the protected
credential.

## Executable local diagnostics

From `demos/postgresql-data-change`, with the two synthetic passwords in the
environment or an ignored `.env`:

```sh
docker compose up --build -d
npm ci
npx playwright install chromium
npm run check
npm run test:live-recovery
npm run test:live-database
npm run test:live-contract
npm run test:e2e
```

`test:live-recovery` covers receipt failure before credential acquisition,
pre-transaction failure, rollback after update, ambiguous commit, API
replacement, fresh ledger/row reconciliation, and replay.
`test:live-database` checks actual executor privileges, cross-tenant RLS,
SQL-injection input as a literal tenant value, hostile `search_path` shadowing,
zero/exact/boundary-plus-one cardinality, a real serializable conflict, lock
and statement timeouts, schema and trigger drift, atomic ledger rollback, and
the exact commit. The serialization case holds the target row in a concurrent
transaction, waits until the Auths transaction is blocked, advances the
concurrency token, and proves that retrying the same verified action fails
closed rather than deriving a new action. The live contract covers every
native denial and concurrent claim race. The browser suite covers row
read-back, inline JSON, the designed receipt page, and invalid receipt IDs.
