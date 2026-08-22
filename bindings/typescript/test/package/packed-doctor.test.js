import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { installPackedSdk } from "./helpers/packed-install.mjs";

test("packed package runs the bounded doctor command", async () => {
  const { directory } = await installPackedSdk("auths-typescript-doctor-");
  try {
    const output = execFileSync(
      process.execPath,
      [join(directory, "node_modules", "@auths-dev", "sdk", "dist", "doctor-cli.js"), "doctor"],
      { cwd: directory, encoding: "utf8", stdio: "pipe" },
    );
    assert.match(output, /Auths SDK\s+1\.0\.0-rc\.1/);
    assert.match(output, /Portable ABI\s+compatible/);
    assert.match(output, /Profiles\s+opentofu\.saved-plan-apply\/1, postgresql\.bounded-update\/1, stripe\.refund\/1/);
    assert.doesNotMatch(output, /credential|private.?key|signature|proof.?bytes|command.?bytes/i);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
