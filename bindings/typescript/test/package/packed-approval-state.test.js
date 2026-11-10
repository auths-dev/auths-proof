import test from "node:test";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { installPackedSdk } from "./helpers/packed-install.mjs";
import { approvalStateContract } from "../helpers/approval-state-contract.mjs";

test("AP076 approval transitions in the installed package without repository source", async (t) => {
  const { directory } = await installPackedSdk("auths-approval-state-");
  try {
    const approvals = await import(pathToFileURL(join(directory, "node_modules/@auths-dev/sdk/dist/approvals.js")).href);
    await approvalStateContract(t, approvals);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
