import assert from "node:assert/strict";
import test from "node:test";
import {
  authsEvent,
  createSupportBundle,
  emitAuthsEvent,
} from "../../dist/observability.js";

const input = {
  name: "auths.verification.completed",
  timestamp: 100,
  correlationId: "request-1",
  operation: "verify",
  stage: "verification",
  outcome: "succeeded",
  attributes: { code: "authorized" },
};

test("telemetry schema rejects sensitive and unbounded fields", () => {
  assert.equal(authsEvent(input).schemaVersion, "auths.telemetry/1");
  for (const key of [
    "proof", "signature.bytes", "private-key", "provider_body", "credential", "customer.id",
  ]) {
    assert.throws(() => authsEvent({ ...input, attributes: { [key]: "value" } }), /not safe/);
  }
  assert.throws(() => authsEvent({ ...input, attributes: { code: "x".repeat(257) } }), /too large/);
});

test("exporter failure is observational and support bundles are deterministic", async () => {
  await emitAuthsEvent({ emit() { throw new Error("offline"); } }, input);
  const event = authsEvent(input);
  const first = createSupportBundle({
    sdkVersion: "1",
    runtime: "node",
    wasm: { authoringAbi: 1, identityAbi: 1 },
    capabilities: ["b", "a", "a"],
    events: [event],
  });
  const second = createSupportBundle({
    sdkVersion: "1",
    runtime: "node",
    wasm: { authoringAbi: 1, identityAbi: 1 },
    capabilities: ["a", "b"],
    events: [event],
  });
  assert.deepEqual(first, second);
  assert.doesNotMatch(JSON.stringify(first), /proof|signature|credential/i);
});
