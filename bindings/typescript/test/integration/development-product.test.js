import { mkdtemp, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import assert from "node:assert/strict";
import { development } from "../../dist/integrations.js";
import { mcp } from "../../dist/mcp.js";

test("development composition executes exact authority and rejects broader tools before I/O", async () => {
  let calls = 0;
  const provider = mcp.developmentProvider({
    tools: {
      async publish_report(input) {
        calls += 1;
        return { published: input.name };
      },
    },
  });
  const auths = await development.createAuths({
    authority: mcp.allowTools(["publish_report"]),
  });
  try {
    const result = await auths.execute({
      action: mcp.callTool({ name: "publish_report", arguments: { name: "weekly" } }),
      provider,
      requestId: "weekly-32",
    });
    assert.equal(result.kind, "completed");
    assert.equal(calls, 1);
    const denied = await auths.execute({
      action: mcp.callTool({ name: "delete_report", arguments: { name: "weekly" } }),
      provider,
    });
    assert.equal(denied.kind, "denied");
    assert.equal(calls, 1);
    assert.ok(auths.diagnostics.every((value) => value.length <= 256));
  } finally {
    await auths.close();
  }
});

test("recoverable development state resumes reconciliation without provider re-entry", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-recovery-"));
  const authority = mcp.allowTools(["publish_report"]);
  let calls = 0;
  const ambiguous = mcp.developmentProvider({
    tools: {
      async publish_report() {
        calls += 1;
        return { effect: "possible", cause: "unknown" };
      },
    },
  });
  try {
    const first = await development.createRecoverableAuths({ directory, authority });
    const firstActor = first.actor;
    const pending = await first.execute({
      action: mcp.callTool({ name: "publish_report", arguments: { name: "weekly" } }),
      provider: ambiguous,
      requestId: "recover-weekly-32",
    });
    assert.equal(pending.kind, "recoverable");
    await first.close();
    const reconciled = mcp.developmentProvider({
      tools: { async publish_report() { throw new Error("must not re-enter"); } },
      async reconcile() {
        return { effect: "applied", result: { published: "weekly" } };
      },
    });
    const second = await development.createRecoverableAuths({ directory, authority });
    assert.deepEqual(second.actor, firstActor);
    const completed = await second.resume({ reference: pending.reference, provider: reconciled });
    assert.equal(completed.kind, "completed");
    assert.equal(calls, 1);
    await second.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("development reservations admit one concurrent provider entry", async () => {
  let calls = 0;
  const provider = mcp.developmentProvider({
    tools: { async publish_report() { calls += 1; return { published: true }; } },
  });
  const auths = await development.createAuths({ authority: mcp.allowTools(["publish_report"]) });
  try {
    const action = mcp.callTool({ name: "publish_report", arguments: { name: "weekly" } });
    const results = await Promise.all([
      auths.execute({ action, provider, requestId: "concurrent-weekly-32" }),
      auths.execute({ action, provider, requestId: "concurrent-weekly-32" }),
    ]);
    assert.deepEqual(results.map((result) => result.kind).sort(), ["completed", "exact-replay"]);
    assert.equal(calls, 1);
  } finally {
    await auths.close();
  }
});

test("recoverable development state rejects corrupted recovery records", async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-corrupt-recovery-"));
  const authority = mcp.allowTools(["publish_report"]);
  try {
    const first = await development.createRecoverableAuths({ directory, authority });
    const pending = await first.execute({
      action: mcp.callTool({ name: "publish_report", arguments: {} }),
      provider: mcp.developmentProvider({
        tools: { async publish_report() { return { effect: "possible", cause: "unknown" }; } },
      }),
      requestId: "corrupt-recovery-32",
    });
    assert.equal(pending.kind, "recoverable");
    await first.close();
    const recovery = (await readdir(directory)).find((name) => name.startsWith("recovery-"));
    assert.ok(recovery);
    await writeFile(join(directory, recovery), "{");
    const second = await development.createRecoverableAuths({ directory, authority });
    await assert.rejects(
      second.resume({
        reference: pending.reference,
        provider: mcp.developmentProvider({ tools: { async publish_report() {} } }),
      }),
    );
    await second.close();
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
