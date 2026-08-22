import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { installPackedSdk } from "./helpers/packed-install.mjs";

test("packed package exposes the local-agent root and rejects superseded effect subpaths", async () => {
  const { directory } = await installPackedSdk("auths-typescript-node-");
  try {
    await writeFile(join(directory, "smoke.mjs"), `
      const root = await import("@auths-dev/sdk");
      const runtime = await import("@auths-dev/sdk/profile-runtime");
      const removed = [];
      for (const path of ["mcp", "mcp/node", "github"]) {
        try { await import("@auths-dev/sdk/" + path); }
        catch (error) {
          if (error?.code === "ERR_PACKAGE_PATH_NOT_EXPORTED") removed.push(path);
          else throw error;
        }
      }
      process.stdout.write(JSON.stringify({
        connect: typeof root.connect,
        profileRuntime: runtime.PROFILE_CLIENT_RUNTIME,
        removed,
      }));
    `);
    const output = execFileSync(process.execPath, ["smoke.mjs"], {
      cwd: directory,
      encoding: "utf8",
    });
    assert.deepEqual(JSON.parse(output), {
      connect: "function",
      profileRuntime: "auths.profile-client-runtime/1",
      removed: ["mcp", "mcp/node", "github"],
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
