# Deployment and database runbook

## Database ownership

Run migrations through a separate operator or migration identity. From the
repository root:

```sh
psql "$MIGRATION_DATABASE_URL" \
  --file demos/postgresql-data-change/database/bootstrap.sql
psql "$MIGRATION_DATABASE_URL" \
  --file product/integrations/auths-postgresql/migrations/auths_execution_ledger.sql
psql "$MIGRATION_DATABASE_URL" \
  --file demos/postgresql-data-change/database/verify.sql
```

Provision the `auths_executor` login password through the database secret
manager after bootstrap. It must remain `NOSUPERUSER`, `NOCREATEDB`,
`NOCREATEROLE`, `NOINHERIT`, `NOREPLICATION`, and `NOBYPASSRLS`; it must not own
the target table. The bootstrap grants only selected reads and updates to
`review_status` plus the concurrency token. RLS is enabled and forced.

The demo targets PostgreSQL 17 and pins the Rust driver to
`tokio-postgres` 0.7.18 with `rustls`. The connection string must set
`sslmode=require`. Public Web PKI roots are used by default. For a private CA,
mount its PEM bundle read-only and set `AUTHS_POSTGRESQL_CA_FILE`, or inject the
same bytes through the protected `AUTHS_POSTGRESQL_CA_PEM` secret.

## Local real-database path

Create an untracked `.env` next to `compose.yaml` with strong, unique
`POSTGRES_ADMIN_PASSWORD` and `AUTHS_EXECUTOR_PASSWORD` values, then run:

```sh
docker compose \
  --file demos/postgresql-data-change/compose.yaml \
  up --build -d
```

The certificate helper creates a short-lived local CA and a server certificate
with `postgres` and `localhost` SANs. The API receives the CA certificate
read-only, not the private CA key. PostgreSQL requires TLS and SCRAM. The
Compose serves the complete browser-to-native-to-database demo at
`http://localhost:4175`. Port 8080 exposes the API directly only for
diagnostics.

Reset only through the migration identity:

```sh
psql "$MIGRATION_DATABASE_URL" \
  --file demos/postgresql-data-change/database/reset.sql
```

Reset is idempotent: it removes noncanonical synthetic rows, restores exactly
the three repository-owned records, and clears the synthetic execution ledger.
It is intentionally absent from the public API. Compose mounts it read-only at
`/demo/reset.sql` in the database container so CI and operators exercise the
same artifact.

## Fly and Vercel

Create an encrypted Fly volume for `/data`, then inject
`AUTHS_POSTGRESQL_CONNECTION_STRING` through `fly secrets`. Use a dedicated
managed database, private networking where available, encrypted transport,
automated backups appropriate to synthetic demo data, and an executor password
not shared with migrations or resets.

Deploy the native service with `fly.toml`, then deploy `web/` to Vercel. Update
these origins together:

- `AUTHS_POSTGRESQL_ALLOWED_ORIGIN` in Fly;
- API destinations and `connect-src` in `web/vercel.json`.

Never enable wildcard CORS. `/readyz` must report `tls-postgresql`, not fixture
mode. Before publishing release evidence, exercise through the public frontend:
readiness, exact commit, a material denial, replay, after-state rows, inline
receipt, and `/receipts/{id}`.

Record tested URLs, Fly image reference, Vercel deployment identifier,
PostgreSQL server version, migration digest, and test timestamp in a private
copy of `release-evidence.template.json`. Do not claim public acceptance until
both URLs have been tested together.

## Retention and shutdown

Shared lifecycle records and JSONL receipts live below
`AUTHS_POSTGRESQL_STATE_DIR` on the encrypted volume. Receipts contain
commitments rather than tenant, key, or column values. Retain outcome-unknown
lifecycle records at least through the database ledger reconciliation window.
The obsolete prelaunch `claims.json` file must be removed before deploying the
cut-over revision; startup rejects it rather than migrating it.

During an incident:

1. revoke or rotate the executor credential;
2. stop the native machines;
3. preserve lifecycle records, receipts, and the database ledger;
4. reconcile every `outcome-unknown` action by digest;
5. reset synthetic data only after reconciliation.

Never delete a lifecycle record or ledger entry merely to make a retry
succeed.
