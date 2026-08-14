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

test("telemetry schema rejects sensitive and unbounded fields", async () => {
  assert.equal((await authsEvent(input)).schemaVersion, "auths.telemetry/2");
  for (const key of [
    "proof", "signature.bytes", "private-key", "provider_body", "credential", "customer.id",
  ]) {
    await assert.rejects(authsEvent({ ...input, attributes: { [key]: "value" } }), /invalid-body/);
  }
  await assert.rejects(authsEvent({ ...input, attributes: { code: "x".repeat(257) } }), /invalid-body/);
});

test("exporter failure is observational and support bundles are deterministic", async () => {
  await emitAuthsEvent({ emit() { throw new Error("offline"); } }, input);
  const event = await authsEvent(input);
  const first = await createSupportBundle({
    sdkVersion: "1",
    runtime: "node",
    wasm: { authoringAbi: 1, identityAbi: 1 },
    capabilities: ["b", "a", "a"],
    events: [event],
  });
  const second = await createSupportBundle({
    sdkVersion: "1",
    runtime: "node",
    wasm: { authoringAbi: 1, identityAbi: 1 },
    capabilities: ["a", "b"],
    events: [event],
  });
  assert.deepEqual(first, second);
  assert.doesNotMatch(JSON.stringify(first), /proof|signature|credential/i);
});
