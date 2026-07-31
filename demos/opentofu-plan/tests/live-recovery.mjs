import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";
import test from "node:test";

const demoDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const baseUrl = (process.env.AUTHS_OPENTOFU_E2E_URL ?? "http://localhost:4174").replace(/\/$/, "");

function compose(arguments_, fault = "none") {
  return execFileSync("docker", ["compose", ...arguments_], {
    cwd: demoDirectory,
    env: { ...process.env, AUTHS_OPENTOFU_FAULT: fault },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  });
}

async function waitUntilReady() {
  const deadline = Date.now() + 120_000;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/readyz`, { cache: "no-store" });
      if (response.ok && (await response.json()).planner === "live-opentofu") {
        return;
      }
    } catch {
      // The reverse proxy may retain the old API connection while it is replaced.
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  assert.fail(`OpenTofu API did not become ready at ${baseUrl}`);
}

async function request(pathname, body, expectedStatus = 200) {
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

function providerObjects(sessionId) {
  const filename = `session-${sessionId}.json`;
  const providerRoot = "/data/auths-opentofu";
  const expectedPath = `${providerRoot}/objects/${filename}`;
  return compose([
    "exec",
    "-T",
    "api",
    "find",
    providerRoot,
    "-maxdepth",
    "2",
    "-path",
    expectedPath,
    "-type",
    "f",
    "-print",
  ]).trim();
}

async function recreateApi(fault) {
  compose(["up", "-d", "--force-recreate", "api"], fault);
  await waitUntilReady();
}

compose([
  "up",
  "-d",
  process.env.AUTHS_DEMO_PREBUILT === "true" ? "--no-build" : "--build",
]);
await waitUntilReady();

await recreateApi("before-apply");
const failedSession = await request("/api/v1/sessions", {});
const failedPath = `/api/v1/sessions/${failedSession.session_id}/execute`;
const failed = await request(failedPath, { variant: "exact" }, 500);
assert.equal(failed.error.code, "execution-failed");
assert.equal(providerObjects(failedSession.session_id), "");
const blockedRetry = await request(failedPath, { variant: "exact" });
assert.equal(blockedRetry.result.decision.code, "already-claimed");
assert.equal(blockedRetry.result.opentofu_called, false);
assert.equal(providerObjects(failedSession.session_id), "");

await recreateApi("after-apply-unreconciled");
const uncertainSession = await request("/api/v1/sessions", {});
const uncertainPath = `/api/v1/sessions/${uncertainSession.session_id}/execute`;
const uncertain = await request(uncertainPath, { variant: "exact" });
assert.equal(uncertain.result.decision.class, "indeterminate");
assert.equal(uncertain.result.decision.code, "execution-outcome-unknown");
assert.equal(uncertain.result.claim.stage, "outcome-unknown");
assert.equal(uncertain.result.credential_called, true);
assert.equal(uncertain.result.opentofu_called, true);
assert.notEqual(providerObjects(uncertainSession.session_id), "");

await recreateApi("none");
const reconciled = await request(uncertainPath, { variant: "exact" });
assert.equal(reconciled.result.decision.code, "authorized");
assert.equal(reconciled.result.opentofu_called, false);
assert.equal(reconciled.result.resulting_state.converged, true);
assert.equal(reconciled.result.resulting_state.state_committed, true);

const replay = await request(uncertainPath, { variant: "exact" });
assert.equal(replay.result.decision.code, "already-claimed");
assert.equal(replay.result.opentofu_called, false);
assert.notEqual(providerObjects(uncertainSession.session_id), "");

console.log(`OpenTofu durable fault/restart/reconcile contract passed: ${baseUrl}`);
test("live_durable_fault_restart_reconcile_contract", () => assert.ok(true));
