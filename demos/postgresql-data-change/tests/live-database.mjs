import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const demoDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const baseUrl = (process.env.AUTHS_POSTGRESQL_E2E_URL ?? "http://localhost:4175").replace(/\/$/, "");
const executorPassword = process.env.AUTHS_EXECUTOR_PASSWORD;
assert.ok(executorPassword, "AUTHS_EXECUTOR_PASSWORD is required for the restricted-role checks");

function compose(arguments_, fault = "none") {
  return execFileSync("docker", ["compose", ...arguments_], {
    cwd: demoDirectory,
    env: {
      ...process.env,
      AUTHS_POSTGRESQL_FAULT: fault,
      AUTHS_POSTGRESQL_RECEIPT_FAULT: "none",
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
}

function adminSql(sql) {
  return compose([
    "exec",
    "-T",
    "postgres",
    "psql",
    "-v",
    "ON_ERROR_STOP=1",
    "-At",
    "-U",
    "migration_admin",
    "-d",
    "auths_demo",
    "-c",
    sql,
  ]).trim();
}

function executorSql(sql) {
  return compose([
    "exec",
    "-T",
    "-e",
    `PGPASSWORD=${executorPassword}`,
    "postgres",
    "psql",
    "-q",
    "-v",
    "ON_ERROR_STOP=1",
    "-At",
    "-h",
    "127.0.0.1",
    "-U",
    "auths_executor",
    "-d",
    "auths_demo",
    "-c",
    sql,
  ]).trim();
}

function resetDatabase() {
  compose([
    "exec",
    "-T",
    "postgres",
    "psql",
    "-v",
    "ON_ERROR_STOP=1",
    "-U",
    "migration_admin",
    "-d",
    "auths_demo",
    "-f",
    "/demo/reset.sql",
  ]);
}

function snapshot() {
  return adminSql(`SELECT
    count(*) FILTER (WHERE review_status = 'pending')::text || '|' ||
    count(*) FILTER (WHERE review_status = 'reviewed')::text || '|' ||
    (SELECT count(*)::text FROM auths_internal.auths_execution_ledger)
  FROM app.demo_accounts WHERE tenant_id = 'tenant-demo';`);
}

async function waitUntilReady() {
  const deadline = Date.now() + 90_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/readyz`, { cache: "no-store" });
      if (response.ok && (await response.json()).database === "tls-postgresql") {
        return;
      }
    } catch {
      // Compose may still be replacing the API.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.fail(`PostgreSQL API did not become ready at ${baseUrl}`);
}

async function post(pathname, body = {}, expectedStatus = 200) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  assert.equal(
    response.status,
    expectedStatus,
    `${pathname}: ${response.status} ${JSON.stringify(payload)}`,
  );
  return payload;
}

async function newSession() {
  return post("/api/v1/sessions");
}

function holdAuthorizedRowLock() {
  const sql = `BEGIN;
    SELECT set_config('application_name', 'auths-demo-lock-holder', false);
    SELECT account_id FROM app.demo_accounts
      WHERE account_id = '00000000-0000-0000-0000-000000000001'::uuid
      FOR UPDATE;
    SELECT pg_sleep(10);
    COMMIT;`;
  const child = spawn(
    "docker",
    [
      "compose",
      "exec",
      "-T",
      "postgres",
      "psql",
      "-v",
      "ON_ERROR_STOP=1",
      "-At",
      "-U",
      "migration_admin",
      "-d",
      "auths_demo",
      "-c",
      sql,
    ],
    {
      cwd: demoDirectory,
      env: {
        ...process.env,
        AUTHS_POSTGRESQL_FAULT: "none",
        AUTHS_POSTGRESQL_RECEIPT_FAULT: "none",
      },
      stdio: ["ignore", "ignore", "inherit"],
    },
  );
  return new Promise((done, failed) => {
    child.once("exit", (code) =>
      code === 0 ? done() : failed(new Error(`lock holder exited ${code}`)),
    );
    child.once("error", failed);
  });
}

function beginConcurrentUpdater() {
  const child = spawn(
    "docker",
    [
      "compose",
      "exec",
      "-T",
      "postgres",
      "psql",
      "-q",
      "-v",
      "ON_ERROR_STOP=1",
      "-At",
      "-U",
      "migration_admin",
      "-d",
      "auths_demo",
    ],
    {
      cwd: demoDirectory,
      env: {
        ...process.env,
        AUTHS_POSTGRESQL_FAULT: "none",
        AUTHS_POSTGRESQL_RECEIPT_FAULT: "none",
      },
      stdio: ["pipe", "ignore", "inherit"],
    },
  );
  child.stdin.write(`BEGIN;
    SET application_name = 'auths-demo-serialization-holder';
    SELECT account_id FROM app.demo_accounts
      WHERE account_id = '00000000-0000-0000-0000-000000000001'::uuid
      FOR UPDATE;\n`);
  return {
    commit() {
      child.stdin.end(`UPDATE app.demo_accounts
        SET row_version = row_version + 1
        WHERE account_id = '00000000-0000-0000-0000-000000000001'::uuid;
        COMMIT;\n`);
    },
    finished: new Promise((done, failed) => {
      child.once("exit", (code) =>
        code === 0 ? done() : failed(new Error(`concurrent updater exited ${code}`)),
      );
      child.once("error", failed);
    }),
  };
}

async function waitForAuthorizedRowLock() {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (
      adminSql(`SELECT count(*) FROM pg_stat_activity
        WHERE application_name = 'auths-demo-lock-holder'
          AND state = 'active';`) === "1"
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.fail("the database did not observe the row-lock holder");
}

async function waitForActivity(predicate, failure) {
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline) {
    if (adminSql(`SELECT count(*) FROM pg_stat_activity WHERE ${predicate};`) === "1") {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.fail(failure);
}

compose(["up", "-d", "--build"]);
compose(["up", "-d", "--force-recreate", "api"]);
await waitUntilReady();
adminSql(`DROP TRIGGER IF EXISTS auths_drift_trigger ON app.demo_accounts;
  DROP FUNCTION IF EXISTS app.auths_drift_trigger();
  ALTER TABLE app.demo_accounts DROP COLUMN IF EXISTS auths_drift_marker;`);
resetDatabase();

const roleFacts = executorSql(`WITH configured AS (
    SELECT set_config('app.tenant_id', 'tenant-other', false)
  )
  SELECT current_user || '|' ||
    (SELECT count(*)::text FROM app.demo_accounts, configured) || '|' ||
    has_database_privilege(current_user, current_database(), 'CREATE')::text || '|' ||
    has_schema_privilege(current_user, 'app', 'CREATE')::text || '|' ||
    has_table_privilege(current_user, 'app.demo_accounts', 'TRUNCATE')::text || '|' ||
    has_column_privilege(current_user, 'app.demo_accounts', 'email', 'UPDATE')::text || '|' ||
    rolsuper::text || '|' || rolbypassrls::text
  FROM pg_roles WHERE rolname = current_user;`);
assert.equal(roleFacts, "auths_executor|0|false|false|false|false|false|false");
assert.equal(
  executorSql(`WITH configured AS (
      SELECT set_config('app.tenant_id', 'tenant-demo'' OR true --', false)
    )
    SELECT count(*) FROM app.demo_accounts, configured;`),
  "0",
);
assert.equal(
  executorSql(`BEGIN;
    SET LOCAL app.tenant_id = 'tenant-demo';
    SET LOCAL search_path = pg_temp, app;
    CREATE TEMP TABLE demo_accounts (review_status text);
    INSERT INTO demo_accounts VALUES ('pending');
    UPDATE demo_accounts SET review_status = 'reviewed';
    SELECT count(*) FROM app.demo_accounts WHERE review_status = 'pending';
    ROLLBACK;`),
  "3",
);
assert.equal(
  executorSql(`WITH configured AS (
      SELECT set_config('app.tenant_id', 'tenant-other', false)
    ), attempted AS (
      UPDATE app.demo_accounts
      SET review_status = 'reviewed'
      FROM configured
      WHERE tenant_id = 'tenant-other'
      RETURNING account_id
    )
    SELECT count(*) FROM attempted;`),
  "0",
);
assert.equal(snapshot(), "3|0|0");

resetDatabase();
const schemaSession = await newSession();
adminSql("ALTER TABLE app.demo_accounts ADD COLUMN auths_drift_marker text;");
const schemaDrift = await post(
  `/api/v1/sessions/${schemaSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(schemaDrift.stable_code, "before-state-mismatch");
assert.equal(schemaDrift.credential_acquired, true);
assert.equal(schemaDrift.transaction_started, true);
assert.equal(snapshot(), "3|0|0");
adminSql("ALTER TABLE app.demo_accounts DROP COLUMN auths_drift_marker;");

resetDatabase();
const triggerSession = await newSession();
adminSql(`CREATE FUNCTION app.auths_drift_trigger() RETURNS trigger
  LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
  CREATE TRIGGER auths_drift_trigger BEFORE UPDATE ON app.demo_accounts
  FOR EACH ROW EXECUTE FUNCTION app.auths_drift_trigger();`);
const triggerDrift = await post(
  `/api/v1/sessions/${triggerSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(triggerDrift.stable_code, "before-state-mismatch");
assert.equal(triggerDrift.credential_acquired, true);
assert.equal(triggerDrift.transaction_started, true);
assert.equal(snapshot(), "3|0|0");
adminSql(`DROP TRIGGER auths_drift_trigger ON app.demo_accounts;
  DROP FUNCTION app.auths_drift_trigger();`);

adminSql(`INSERT INTO app.demo_accounts
  (account_id, tenant_id, display_name, email, review_status, row_version)
  VALUES ('00000000-0000-0000-0000-000000000004', 'tenant-demo',
          'Boundary Four', 'four@example.invalid', 'pending', 4);`);
const widened = await post("/api/v1/sessions", {}, 503);
assert.equal(widened.code, "database-unavailable");
assert.equal(snapshot(), "4|0|0");
adminSql(`DELETE FROM app.demo_accounts
  WHERE account_id = '00000000-0000-0000-0000-000000000004'::uuid;`);

resetDatabase();
const zeroSession = await newSession();
adminSql(`UPDATE app.demo_accounts SET review_status = 'reviewed', row_version = row_version + 1
  WHERE tenant_id = 'tenant-demo';`);
const zeroResult = await post(
  `/api/v1/sessions/${zeroSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(zeroResult.stable_code, "cardinality-mismatch");
assert.equal(zeroResult.transaction_started, true);
assert.equal(snapshot(), "0|3|0");

resetDatabase();
const lockedSession = await newSession();
const lockFinished = holdAuthorizedRowLock();
await waitForAuthorizedRowLock();
const lockedResult = await post(
  `/api/v1/sessions/${lockedSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(lockedResult.state, "indeterminate");
assert.equal(lockedResult.transaction_started, true);
await lockFinished;
assert.equal(snapshot(), "3|0|0");

resetDatabase();
const conflictSession = await newSession();
const concurrentUpdater = beginConcurrentUpdater();
await waitForActivity(
  "application_name = 'auths-demo-serialization-holder' AND state = 'idle in transaction'",
  "the concurrent updater did not acquire its row lock",
);
const conflictedExecution = post(
  `/api/v1/sessions/${conflictSession.session_id}/execute`,
  { variant: "exact" },
);
await waitForActivity(
  "application_name = 'auths-postgresql-bounded-update/1' AND wait_event_type = 'Lock'",
  "the Auths transaction did not block on the concurrent updater",
);
concurrentUpdater.commit();
await concurrentUpdater.finished;
const conflicted = await conflictedExecution;
// The first attempt is aborted by PostgreSQL with SQLSTATE 40001. The retry
// recompiles nothing and rechecks the original exact row/version predicates,
// which now match zero rows and therefore fail closed on cardinality.
assert.equal(conflicted.stable_code, "cardinality-mismatch");
assert.equal(conflicted.credential_acquired, true);
assert.equal(conflicted.transaction_started, true);
assert.equal(snapshot(), "3|0|0");

resetDatabase();
compose(["up", "-d", "--force-recreate", "api"], "statement-timeout");
await waitUntilReady();
const timeoutSession = await newSession();
const timedOut = await post(
  `/api/v1/sessions/${timeoutSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(timedOut.state, "indeterminate");
assert.equal(timedOut.stable_code, "database-execution-failed");
assert.equal(timedOut.credential_acquired, true);
assert.equal(timedOut.transaction_started, true);
assert.equal(snapshot(), "3|0|0");
compose(["up", "-d", "--force-recreate", "api"]);
await waitUntilReady();

resetDatabase();
const exactSession = await newSession();
const exact = await post(
  `/api/v1/sessions/${exactSession.session_id}/execute`,
  { variant: "exact" },
);
assert.equal(exact.state, "committed");
assert.equal(exact.stable_code, "authorized");
assert.equal(snapshot(), "0|3|1");

resetDatabase();
console.log(`PostgreSQL live privilege, RLS, boundary, and lock contract passed: ${baseUrl}`);
test("live_privilege_rls_boundary_and_lock_contract", () => assert.ok(true));
