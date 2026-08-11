import assert from "node:assert/strict";
import test from "node:test";
import { adapterConformance } from "../../dist/testkit/index.js";

const metadata = {
  implementationId: "example.telemetry",
  implementationVersion: "1.2.3",
  contract: { kind: "telemetry", version: "1" },
  runtimes: ["node"],
  supportOwner: "example-team",
  securityClaims: ["redacts Auths inputs"],
};

test("adapter certification requires and executes every contract case", async () => {
  const executed = [];
  const report = await adapterConformance({
    metadata,
    cases: ["redaction", "bounded", "exporter-failure"].map((id) => ({
      id,
      run() { executed.push(id); },
    })),
  });
  assert.deepEqual(executed, ["redaction", "bounded", "exporter-failure"]);
  assert.deepEqual(report.passed, executed);
  await assert.rejects(() => adapterConformance({ metadata, cases: [] }), /missing/);
});
