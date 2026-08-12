import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, rm, writeFile } from "node:fs/promises";
import { basename, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

const recipesRoot = fileURLToPath(new URL("../../../recipes/typescript/", import.meta.url));
const recipes = [
  "01-authenticate-identity.ts",
  "02-verify-authority.ts",
  "03-execute-exact-action.ts",
  "04-delegate-to-agent.ts",
];

test("the first four recipes compile against the packed package alone", async () => {
  const { directory } = await installPackedSdk("auths-typescript-recipes-");
  try {
    for (const recipe of recipes) {
      await cp(join(recipesRoot, recipe), join(directory, recipe));
    }
    await writeFile(join(directory, "node.d.ts"), `
      declare module "node:fs/promises" {
        export function readFile(path: string): Promise<Uint8Array>;
      }
      declare const process: { readonly env: Record<string, string | undefined> };
    `);
    await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        exactOptionalPropertyTypes: true,
        lib: ["DOM", "ES2022", "ESNext.Disposable"],
        module: "NodeNext",
        moduleResolution: "NodeNext",
        outDir: "build",
        strict: true,
        target: "ES2022",
        types: [],
      },
      include: ["*.ts", "node.d.ts"],
    }));
    compileConsumer(directory);
    for (const recipe of [recipes[0], recipes[2], recipes[3]]) {
      const output = execFileSync(
        process.execPath,
        [join("build", basename(recipe, ".ts") + ".js")],
        { cwd: directory, encoding: "utf8", stdio: "pipe" },
      );
      assert.match(output, /"outcome"/);
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
