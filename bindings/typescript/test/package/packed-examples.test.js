import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { cp, readdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { compileConsumer, installPackedSdk } from "./helpers/packed-install.mjs";

const examplesRoot = fileURLToPath(new URL("../../examples/", import.meta.url));

test("every example compiles and runs against the packed package alone", async () => {
  const { directory } = await installPackedSdk("auths-typescript-examples-");
  try {
    const names = (await readdir(examplesRoot, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort();
    assert.ok(names.length >= 4, `expected the maintained examples, found ${names.join(",")}`);

    for (const name of names) {
      await cp(join(examplesRoot, name), join(directory, "examples", name), { recursive: true });
    }

    // The consumer project sees the installed declarations only: no path
    // mapping, no rootDir into the repository, no Auths source on disk.
    await writeFile(join(directory, "tsconfig.json"), JSON.stringify({
      compilerOptions: {
        declaration: false,
        exactOptionalPropertyTypes: true,
        lib: ["DOM", "ES2022", "ESNext.Disposable"],
        module: "NodeNext",
        moduleResolution: "NodeNext",
        outDir: "build",
        rootDir: "examples",
        strict: true,
        target: "ES2022",
        types: [],
      },
      include: ["examples/**/*.ts"],
    }));
    compileConsumer(directory);

    await writeFile(join(directory, "run-quickstart.mjs"), `
      import { runQuickstart } from "./build/quickstart/index.js";
      const reviewed = [];
      const result = await runQuickstart(async (fields) => {
        reviewed.push(fields.map((field) => field.label).join("|"));
        return true;
      });
      if (result !== "records/update_record") {
        throw new Error("packed quickstart returned " + result);
      }
      if (reviewed.length === 0) throw new Error("packed quickstart skipped human review");
      process.stdout.write(JSON.stringify({ result, reviewed }));
    `);
    const output = execFileSync(process.execPath, ["run-quickstart.mjs"], {
      cwd: directory,
      encoding: "utf8",
      stdio: "pipe",
    });
    const executed = JSON.parse(output);
    assert.equal(executed.result, "records/update_record");
    // The quickstart reviews the root grant, the delegated child grant, and the
    // tool call itself, so the tool review must appear among them.
    assert.ok(
      executed.reviewed.some((labels) => labels.includes("Tool")),
      `packed quickstart reviewed ${JSON.stringify(executed.reviewed)}`,
    );

    const resolved = execFileSync(
      process.execPath,
      ["-e", "process.stdout.write(import.meta.resolve('@auths-dev/sdk'))"],
      { cwd: directory, encoding: "utf8", stdio: "pipe" },
    );
    assert.ok(
      resolved.includes("/node_modules/@auths-dev/sdk/"),
      `example run resolved the SDK outside the installed package: ${resolved}`,
    );
    assert.equal(resolved.includes(fileURLToPath(new URL("../../src/", import.meta.url))), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
