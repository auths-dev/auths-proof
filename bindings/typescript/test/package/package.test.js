import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

test("package exposes bounded public surfaces and includes contributor docs", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(Object.keys(manifest.exports).sort(), [
    ".",
    "./advanced",
    "./mcp",
    "./profile-kit",
    "./testkit",
  ]);
  assert.ok(manifest.files.includes("docs"));
  assert.ok(manifest.files.includes("wasm/auths_proof_wasm_bg.wasm"));
  assert.equal(manifest.files.some((entry) => entry.includes("test/")), false);
});

test("compatibility barrels contain exports only", async () => {
  for (const name of ["index.ts", "mcp.ts", "profile-kit.ts", "workflow.ts"]) {
    const source = await readFile(new URL(`../../src/${name}`, import.meta.url), "utf8");
    assert.doesNotMatch(
      source,
      /(^|\n)\s*(?:import|const|let|var|class|function|async function)\s/m,
      `${name} contains runtime implementation`,
    );
  }
});

test("published entry points omit package coordination hooks", async () => {
  const forbidden = [
    "createDelegatedAttachedAgent",
    "engineForClient",
    "registerProfileRuntime",
    "resourcesForAttachedAgent",
    "signerForClient",
    "trustedContextForClient",
  ];
  for (const modulePath of ["../../dist/index.js", "../../dist/advanced.js"]) {
    const exports = await import(modulePath);
    for (const name of forbidden) {
      assert.equal(name in exports, false, `${modulePath} exported ${name}`);
    }
  }
});
