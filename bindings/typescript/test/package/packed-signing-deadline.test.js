import test from "node:test";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { installPackedSdk } from "./helpers/packed-install.mjs";
import { signingDeadlineContract } from "../helpers/signing-deadline-contract.mjs";

test("AP078 signing deadlines in the installed source-free package", { timeout: 120_000 }, async (t) => {
  const { directory } = await installPackedSdk("auths-signing-deadline-");
  try {
    const signing = await import(pathToFileURL(join(directory, "node_modules/@auths-dev/sdk/dist/internal/signing.js")).href);
    await signingDeadlineContract(t, signing);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
