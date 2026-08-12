import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { installPackedSdk } from "./helpers/packed-install.mjs";

test("packed package executes the primary product path", async () => {
  const { directory } = await installPackedSdk("auths-typescript-node-");
  try {
    await writeFile(join(directory, "smoke.mjs"), `
      const { development } = await import("@auths-dev/sdk/integrations");
      const { mcp } = await import("@auths-dev/sdk/profiles");
      let calls = 0;
      const provider = mcp.developmentProvider({ tools: {
        async publish_report() { calls += 1; return { published: true }; },
      } });
      const auths = await development.createAuths({
        authority: mcp.allowTools(["publish_report"]),
      });
      try {
        const result = await auths.execute({
          action: mcp.callTool({ name: "publish_report", arguments: { report: "weekly" } }),
          provider,
        });
        if (result.kind !== "completed" || calls !== 1) throw new Error("closed execution failed");
        process.stdout.write(JSON.stringify({ kind: result.kind, calls }));
      } finally {
        await auths.close();
      }
    `);
    const output = execFileSync(process.execPath, ["smoke.mjs"], {
      cwd: directory,
      encoding: "utf8",
      stdio: "pipe",
    });
    assert.deepEqual(JSON.parse(output), { kind: "completed", calls: 1 });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
