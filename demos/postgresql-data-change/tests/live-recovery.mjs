import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const demoDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const baseUrl = (process.env.AUTHS_POSTGRESQL_E2E_URL ?? "http://localhost:4175").replace(/\/$/, "");

function compose(arguments_, fault = "none", receiptFault = "none") {
  return execFileSync("docker", ["compose", ...arguments_], {
    cwd: demoDirectory,
    env: {
      ...process.env,
      AUTHS_POSTGRESQL_FAULT: fault,
      AUTHS_POSTGRESQL_RECEIPT_FAULT: receiptFault,
    },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
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
      // The proxy and API are replaced independently.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.fail(`PostgreSQL API did not become ready at ${baseUrl}`);
}

async function request(pathname, body = {}) {
  const response = await fetch(`${baseUrl}${pathname}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  assert.equal(response.ok, true, `${pathname}: ${response.status} ${JSON.stringify(payload)}`);
  return payload;
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

function databaseSnapshot() {
  return compose([
    "exec",
    "-T",
    "postgres",
    "psql",
    "-At",
    "-U",
    "migration_admin",
    "-d",
    "auths_demo",
    "-c",
    `SELECT
       count(*) FILTER (WHERE review_status = 'pending')::text || '|' ||
       count(*) FILTER (WHERE review_status = 'reviewed')::text || '|' ||
       (SELECT count(*)::text FROM auths_internal.auths_execution_ledger)
     FROM app.demo_accounts
     WHERE tenant_id = 'tenant-demo';`,
  ]).trim();
}

async function recreateApi(fault = "none", receiptFault = "none") {
  compose(["up", "-d", "--force-recreate", "api"], fault, receiptFault);
  await waitUntilReady();
}

async function executeFreshSession() {
  const session = await request("/api/v1/sessions");
  const path = `/api/v1/sessions/${session.session_id}/execute`;
  return { session, path, result: await request(path, { variant: "exact" }) };
}

compose([
  "up",
  "-d",
  process.env.AUTHS_DEMO_PREBUILT === "true" ? "--no-build" : "--build",
]);
await waitUntilReady();

resetDatabase();
await recreateApi("none", "before-credential");
const persistenceFailure = await executeFreshSession();
assert.equal(persistenceFailure.result.state, "indeterminate");
assert.equal(persistenceFailure.result.stable_code, "database-execution-failed");
assert.equal(persistenceFailure.result.credential_acquired, false);
assert.equal(persistenceFailure.result.transaction_started, false);
assert.equal(databaseSnapshot(), "3|0|0");

resetDatabase();
await recreateApi("before-transaction");
const beforeTransaction = await executeFreshSession();
assert.equal(beforeTransaction.result.state, "indeterminate");
assert.equal(beforeTransaction.result.transaction_started, true);
assert.equal(databaseSnapshot(), "3|0|0");
const failedReplay = await request(beforeTransaction.path, { variant: "exact" });
assert.equal(failedReplay.stable_code, "already-claimed");
assert.equal(failedReplay.transaction_started, false);
assert.equal(databaseSnapshot(), "3|0|0");

resetDatabase();
await recreateApi("after-update-rollback");
const rolledBack = await executeFreshSession();
assert.equal(rolledBack.result.state, "indeterminate");
assert.equal(rolledBack.result.transaction_started, true);
assert.equal(databaseSnapshot(), "3|0|0");

resetDatabase();
await recreateApi("before-commit-unknown");
const interruptedBeforeCommit = await executeFreshSession();
assert.equal(interruptedBeforeCommit.result.state, "indeterminate");
assert.equal(interruptedBeforeCommit.result.stable_code, "not-committed");
assert.equal(interruptedBeforeCommit.result.transaction_started, true);
assert.equal(databaseSnapshot(), "3|0|0");
const resolvedNoCommit = await request(interruptedBeforeCommit.path, { variant: "exact" });
assert.equal(resolvedNoCommit.stable_code, "already-claimed");
assert.equal(resolvedNoCommit.transaction_started, false);
assert.equal(databaseSnapshot(), "3|0|0");

resetDatabase();
await recreateApi("after-commit-unknown");
const immediatelyReconciled = await executeFreshSession();
assert.equal(immediatelyReconciled.result.state, "reconciled");
assert.equal(immediatelyReconciled.result.stable_code, "authorized");
assert.equal(immediatelyReconciled.result.credential_acquired, true);
assert.equal(immediatelyReconciled.result.transaction_started, true);
assert.equal(databaseSnapshot(), "0|3|1");
const immediateReplay = await request(immediatelyReconciled.path, { variant: "exact" });
assert.equal(immediateReplay.state, "replay");
assert.equal(immediateReplay.stable_code, "already-claimed");
assert.equal(immediateReplay.transaction_started, false);
assert.equal(databaseSnapshot(), "0|3|1");

resetDatabase();
await recreateApi("after-commit-unreconciled");
const uncertain = await executeFreshSession();
assert.equal(uncertain.result.state, "indeterminate");
assert.equal(uncertain.result.stable_code, "execution-outcome-unknown");
assert.equal(uncertain.result.transaction_started, true);
assert.equal(databaseSnapshot(), "0|3|1");

await recreateApi();
const reconciled = await request(uncertain.path, { variant: "exact" });
assert.equal(reconciled.state, "reconciled");
assert.equal(reconciled.stable_code, "authorized");
assert.equal(reconciled.credential_acquired, true);
assert.equal(reconciled.transaction_started, false);
assert.equal(databaseSnapshot(), "0|3|1");

const replay = await request(uncertain.path, { variant: "exact" });
assert.equal(replay.state, "replay");
assert.equal(replay.stable_code, "already-claimed");
assert.equal(replay.credential_acquired, false);
assert.equal(replay.transaction_started, false);
assert.equal(databaseSnapshot(), "0|3|1");

resetDatabase();
console.log(`PostgreSQL durable rollback/restart/reconcile contract passed: ${baseUrl}`);
test("live_durable_rollback_restart_reconcile_contract", () => assert.ok(true));
