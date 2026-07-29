import assert from "node:assert/strict";
import test from "node:test";

const baseUrl = (process.env.AUTHS_OPENTOFU_E2E_URL ?? "http://localhost:4174").replace(/\/$/, "");

async function request(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: { "content-type": "application/json", ...options.headers },
  });
  const body = await response.json();
  assert.equal(response.ok, true, `${path}: ${response.status} ${JSON.stringify(body)}`);
  return body;
}

const ready = await request("/readyz");
assert.equal(ready.planner, "live-opentofu");

const expectedCodes = new Map([
  ["swapped-plan", "plan-artifact-mismatch"],
  ["source-changed", "auths-proof-denied"],
  ["workspace-changed", "workspace-mismatch"],
  ["backend-changed", "backend-identity-mismatch"],
  ["stale-state", "state-serial-mismatch"],
  ["state-lock-held", "evidence-stale"],
  ["destroy-added", "destroy-denied"],
  ["dependency-changed", "dependency-not-pinned"],
  ["expired-plan", "evidence-stale"],
  ["configuration-changed", "verifier-configuration-mismatch"],
]);

for (const [variant, expectedCode] of expectedCodes) {
  const session = await request("/api/v1/sessions", { method: "POST", body: "{}" });
  const response = await request(`/api/v1/sessions/${session.session_id}/execute`, {
    method: "POST",
    body: JSON.stringify({ variant }),
  });
  assert.equal(response.result.decision.class, "denied", variant);
  assert.equal(response.result.decision.code, expectedCode, variant);
  assert.equal(response.result.credential_called, false, variant);
  assert.equal(response.result.opentofu_called, false, variant);
}

const racedSession = await request("/api/v1/sessions", { method: "POST", body: "{}" });
const racedPath = `/api/v1/sessions/${racedSession.session_id}/execute`;
const raced = await Promise.all([
  request(racedPath, { method: "POST", body: '{"variant":"exact"}' }),
  request(racedPath, { method: "POST", body: '{"variant":"exact"}' }),
]);
assert.equal(
  raced.filter((response) => response.result.decision.code === "authorized").length,
  1,
);
assert.equal(
  raced.filter((response) => response.result.decision.code === "already-claimed").length,
  1,
);
assert.equal(
  raced.filter((response) => response.result.opentofu_called).length,
  1,
);

console.log(`OpenTofu live contract passed: ${baseUrl}`);
test("live_native_denial_and_concurrent_claim_contract", () => assert.ok(true));
