import test from "node:test";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { installPackedSdk } from "./helpers/packed-install.mjs";
import { adapterLifecycleContract } from "../helpers/adapter-lifecycle-contract.mjs";
test("AP076 adapters from the installed source-free package", async (t) => {
  const { directory } = await installPackedSdk("auths-adapter-lifetimes-");
  try {
    const load = (path) => import(pathToFileURL(join(directory, "node_modules/@auths-dev/sdk/dist", path)).href);
    const [protocol, identity] = await Promise.all([load("protocol.js"), load("identity/adapters.js")]);
    await adapterLifecycleContract(t, { ...protocol, ...identity });
  } finally { await rm(directory, { recursive: true, force: true }); }
});
