import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { installPackedSdk } from "./helpers/packed-install.mjs";

const entryPoints = JSON.parse(
  await readFile(new URL("../../../public-topology-v1.json", import.meta.url), "utf8"),
).layers.flatMap((layer) => layer.typescript);
const removed = [
  "advanced", "approvals", "authority", "custody", "diagnostics", "framework",
  "github", "inspection", "integrations", "lifecycle", "mcp", "mcp/node", "observability", "plans",
  "profile-kit", "profiles", "runtime", "service", "trust", "workflow",
];

test("packed package exposes only the reviewed public topology", async () => {
  const { directory } = await installPackedSdk("auths-typescript-consumer-");
  try {
    await writeFile(join(directory, "consumer.mjs"), `
      for (const entry of ${JSON.stringify(entryPoints)}) await import(entry);
      const root = await import("@auths-dev/sdk");
      const names = Object.keys(root).sort();
      const expected = ${JSON.stringify([
        "AuthsError", "AuthsOperationError", "ClientStateError", "ConflictError",
        "DeniedError", "NotAppliedError", "PartialError", "ReceiptIntegrityError",
        "RecoveryRequiredError", "UnavailableError", "connect", "isAuthsError",
        "recoveryHandleFromBytes", "runtimeInfo",
      ])};
      if (JSON.stringify(names) !== JSON.stringify(expected)) {
        throw new Error("root drifted: " + names.join(","));
      }
      for (const path of ${JSON.stringify(removed)}) {
        try {
          await import("@auths-dev/sdk/" + path);
          throw new Error("removed subpath resolved: " + path);
        } catch (error) {
          if (error?.code !== "ERR_PACKAGE_PATH_NOT_EXPORTED") throw error;
        }
      }
      process.stdout.write(JSON.stringify({ entryPoints: ${entryPoints.length}, root: names }));
    `);
    const output = execFileSync(process.execPath, ["consumer.mjs"], { cwd: directory, encoding: "utf8" });
    assert.deepEqual(JSON.parse(output), { entryPoints: entryPoints.length, root: [
      "AuthsError", "AuthsOperationError", "ClientStateError", "ConflictError",
      "DeniedError", "NotAppliedError", "PartialError", "ReceiptIntegrityError",
      "RecoveryRequiredError", "UnavailableError", "connect", "isAuthsError",
      "recoveryHandleFromBytes", "runtimeInfo",
    ] });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
