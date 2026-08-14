# PostgreSQL failover, backup, and restore

The candidate owns schema `auths.lifecycle.postgresql/3`. The node installs it
only into an empty database and refuses every mismatch. There is no migration
or compatibility mode.

## Backup

1. Ensure recovery backlog is bounded and record the candidate digest.
2. Take a provider-native physical backup with WAL archiving or an equivalent
   snapshot plus point-in-time log.
3. Record backup digest, database system identity, start/end LSN, encryption
   key reference, retention, and candidate digest outside the database.
4. Verify restore permissions from a separate recovery identity.

## Restore proof

1. Restore into a clean isolated database at the chosen recovery point.
2. Start one node with provider egress disabled.
3. Require `/ready` to verify schema identity before any route is exposed.
4. Compare lifecycle record commitments, receipt identifiers, terminal counts,
   and recovery backlog with the source evidence.
5. Resume only work classified as recoverable; never replay terminal effects.
6. Run offline receipt verification, then destroy the recovery environment.

## Failover

During loss of the writer, readiness must go false. Provider calls without a
durable reservation remain forbidden. After promotion, the store probe must
confirm it is not a read-only recovery server before readiness returns.
