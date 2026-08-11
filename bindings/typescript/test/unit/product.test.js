import test from "node:test";
import assert from "node:assert/strict";
import { createAuths, ExecutionReference } from "../../dist/index.js";
import { mcp } from "../../dist/mcp.js";

test("product waist accepts only integration-owned composition and authority values", async () => {
  const authority = mcp.allowTools(["publish_report"]);
  const action = mcp.callTool({ name: "publish_report", arguments: { week: 32 } });
  assert.deepEqual(authority.tools, ["publish_report"]);
  assert.equal(action.name, "publish_report");
  await assert.rejects(
    () => createAuths({ mode: "development", diagnostics: [] }),
    /not created by an integration/,
  );
  assert.throws(
    () => new ExecutionReference(Symbol("forged"), "mcp1.forged"),
    /sealed/,
  );
});
