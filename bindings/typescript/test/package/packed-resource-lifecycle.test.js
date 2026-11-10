import test from "node:test";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { installPackedSdk } from "./helpers/packed-install.mjs";
import { resourceLifecycleContract } from "../helpers/resource-lifecycle-contract.mjs";
test("AP076 resource ownership in the installed source-free package", async (t) => {
  const { directory } = await installPackedSdk("auths-resource-owner-");
  try {
    const lifecycle = await import(pathToFileURL(join(directory, "node_modules/@auths-dev/sdk/dist/internal/resource-lifecycle.js")).href);
    await resourceLifecycleContract(t, lifecycle);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
