import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

test("packed SDK generates and checks a typed external exact-tool consumer", async () => {
  const { directory } = await installPackedSdk("auths-typescript-profile-");
  const cli = join(directory, "node_modules", "@auths-dev", "sdk", "tools", "profile-cli.mjs");
  const profile = join(directory, "profile");
  execFileSync(process.execPath, [cli, "profile", "init", "--language", "typescript",
    "--name", "example-create", "--directory", profile], { cwd: directory });
  const manifest = join(profile, "profile.toml");
  execFileSync(process.execPath, [cli, "profile", "check", manifest], { cwd: directory });
  const generated = await readFile(join(profile, "generated.ts"), "utf8");
  assert.match(generated, /invoke_v1/);
  assert.match(await readFile(join(profile, "adapter.ts"), "utf8"), /ApplicationAdapter/);
  assert.match(await readFile(join(profile, "run.ts"), "utf8"), /runOnce/);
  await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      strict: true, target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
      lib: ["DOM", "ES2022", "ESNext.Disposable"], noEmit: true,
    },
    include: ["profile/**/*.ts"],
  }));
  compileConsumer(directory);
  await writeFile(join(profile, "generated.ts"), `${generated}\n// drift\n`);
  assert.throws(() => execFileSync(process.execPath, [cli, "profile", "check", manifest],
    { cwd: directory, stdio: "pipe" }));
});
