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
