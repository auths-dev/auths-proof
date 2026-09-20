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
  const source = await readFile(manifest, "utf8");
  const original = '[arguments.fields.value]\ntype = "string"\nmin_bytes = 1\nmax_bytes = 256\n';
  assert.ok(source.includes(original));
  await writeFile(manifest, source.replace(original,
    '[arguments.fields.value]\ntype = "enum"\nvariants = ["open", "closed"]\n'));
  execFileSync(process.execPath, [cli, "profile", "generate", manifest], { cwd: directory });
  execFileSync(process.execPath, [cli, "profile", "check", manifest], { cwd: directory });
  const generated = await readFile(join(profile, "generated.ts"), "utf8");
  assert.match(generated, /invoke_v1/);
  assert.match(generated, /enumField\(\["open","closed"\]\)/);
  assert.match(await readFile(join(profile, "adapter.ts"), "utf8"), /ApplicationAdapter/);
  assert.match(await readFile(join(profile, "run.ts"), "utf8"), /runOnce/);
  await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
    compilerOptions: {
      strict: true, target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext",
      lib: ["DOM", "ES2022", "ESNext.Disposable"], noEmit: true,
    },
    include: ["profile/**/*.ts", "consumer.ts"],
  }));
  await writeFile(join(directory, "consumer.ts"), `
    import type { ExampleCreate } from "./profile/generated.js";
    const valid: ExampleCreate = { value: "open" };
    // @ts-expect-error an undeclared variant cannot type-check
    const invalid: ExampleCreate = { value: "unknown" };
    void valid; void invalid;
  `);
  compileConsumer(directory);
  await writeFile(join(profile, "generated.ts"), `${generated}\n// drift\n`);
  assert.throws(() => execFileSync(process.execPath, [cli, "profile", "check", manifest],
    { cwd: directory, stdio: "pipe" }));
});
