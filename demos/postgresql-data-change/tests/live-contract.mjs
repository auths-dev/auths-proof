import assert from "node:assert/strict";
import test from "node:test";

const baseUrl = (process.env.AUTHS_POSTGRESQL_E2E_URL ?? "http://localhost:4175").replace(/\/$/, "");

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
assert.equal(ready.database, "tls-postgresql");

const expectedCodes = new Map([
  ["extra-row", "row-set-mismatch"],
  ["tenant-changed", "tenant-mismatch"],
  ["before-changed", "before-state-mismatch"],
  ["forbidden-column", "column-not-authorized"],
  ["changed-parameter", "after-state-mismatch"],
  ["unauthorized-table", "relation-mismatch"],
  ["value-outside-enum", "value-constraint-failed"],
  ["policy-changed", "policy-fingerprint-mismatch"],
  ["schema-changed", "schema-fingerprint-mismatch"],
  ["trigger-changed", "trigger-fingerprint-mismatch"],
  ["configuration-changed", "verifier-configuration-mismatch"],
]);

for (const [variant, expectedCode] of expectedCodes) {
  const session = await request("/api/v1/sessions", { method: "POST", body: "{}" });
  const response = await request(`/api/v1/sessions/${session.session_id}/execute`, {
    method: "POST",
    body: JSON.stringify({ variant }),
  });
  assert.equal(response.state, "denied", variant);
  assert.equal(response.stable_code, expectedCode, variant);
  assert.equal(response.credential_acquired, false, variant);
  assert.equal(response.transaction_started, false, variant);
}

const racedSession = await request("/api/v1/sessions", { method: "POST", body: "{}" });
const racedPath = `/api/v1/sessions/${racedSession.session_id}/execute`;
const raced = await Promise.all([
  request(racedPath, { method: "POST", body: '{"variant":"exact"}' }),
  request(racedPath, { method: "POST", body: '{"variant":"exact"}' }),
]);
assert.equal(
  raced.filter((response) => ["committed", "reconciled"].includes(response.state)).length,
  1,
);
assert.equal(
  raced.filter((response) => ["replay", "denied"].includes(response.state)).length,
  1,
);
assert.equal(raced.filter((response) => response.transaction_started).length, 1);

console.log(`PostgreSQL live contract passed: ${baseUrl}`);
test("live_native_denial_and_concurrent_claim_contract", () => assert.ok(true));
