import assert from "node:assert/strict";
import test from "node:test";
import { doctor } from "../../dist/index.js";

test("doctor reports bounded packaged-runtime facts", async () => {
  const report = await doctor({ mode: "development", state: "in-memory" });
  assert.equal(report.status, "ready");
  assert.equal(report.portableAbi.compatible, true);
  assert.deepEqual(report.profiles, ["mcp/1"]);
  assert.deepEqual(report.warnings, [
    "development custody and trust are not production",
    "in-memory state is not production durable",
  ]);
  const serialized = JSON.stringify(report);
  for (const forbidden of ["credential", "privateKey", "signature", "proofCbor", "commandBytes"]) {
    assert.equal(serialized.includes(forbidden), false);
  }
});
