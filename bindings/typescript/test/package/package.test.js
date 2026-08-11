import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { npmSync } from "./helpers/packed-install.mjs";

test("package exposes bounded public surfaces and includes contributor docs", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(Object.keys(manifest.exports).sort(), [
    ".",
    "./approvals",
    "./authority",
    "./custody",
    "./diagnostics",
    "./identity",
    "./inspection",
    "./lifecycle",
    "./mcp",
    "./observability",
    "./profile-kit",
    "./profiles",
    "./runtime",
    "./testkit",
    "./trust",
    "./verify",
  ]);
  assert.ok(manifest.files.includes("docs"));
  assert.ok(manifest.files.includes("sdk-runtime-contract.json"));
  assert.ok(manifest.files.includes("sdk-capability.json"));
  assert.ok(manifest.files.includes("performance-baseline.json"));
  assert.ok(manifest.files.includes("wasm/auths_proof_wasm_bg.wasm"));
  assert.equal(manifest.files.some((entry) => entry.includes("test/")), false);
  assert.deepEqual([...manifest.files].sort(), [
    "CONTRIBUTING.md",
    "README.md",
    "dist",
    "docs",
    "performance-baseline.json",
    "sdk-capability.json",
    "sdk-runtime-contract.json",
    "wasm/auths_proof_wasm.d.ts",
    "wasm/auths_proof_wasm.js",
    "wasm/auths_proof_wasm_bg.wasm",
    "wasm/auths_proof_wasm_bg.wasm.d.ts",
  ]);
});

test("packed contents carry the published artifacts and no source or tests", async () => {
  const listing = npmSync(["pack", "--dry-run", "--json"], {
    cwd: fileURLToPath(new URL("../../", import.meta.url)),
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  const [packed] = JSON.parse(listing);
  const entries = packed.files.map((file) => file.path);

  for (const required of [
    "package.json",
    "dist/index.js",
    "dist/index.d.ts",
    "dist/approvals.js",
    "dist/authority.js",
    "dist/custody.js",
    "dist/diagnostics.js",
    "dist/identity.js",
    "dist/inspection.js",
    "dist/lifecycle.js",
    "dist/mcp.js",
    "dist/observability.js",
    "dist/profile-kit.js",
    "dist/profiles.js",
    "dist/runtime.js",
    "dist/testkit/index.js",
    "dist/trust.js",
    "dist/verify.js",
    "wasm/auths_proof_wasm.js",
    "wasm/auths_proof_wasm_bg.wasm",
    "README.md",
    "performance-baseline.json",
    "sdk-capability.json",
    "sdk-runtime-contract.json",
  ]) {
    assert.ok(entries.includes(required), `packed artifact omitted ${required}`);
  }

  // The published subject is the built wrapper plus its WASM bytes. Source,
  // tests, fixtures, and tooling must not travel with it.
  for (const entry of entries) {
    assert.equal(
      /^(src|test|tools|examples|api|node_modules)\//.test(entry),
      false,
      `packed artifact leaked ${entry}`,
    );
    assert.equal(entry.endsWith(".map"), false, `packed artifact leaked source map ${entry}`);
    assert.equal(entry.endsWith(".tgz"), false, `packed artifact nested a tarball: ${entry}`);
  }
});

test("public facade barrels contain exports only", async () => {
  for (const name of ["authority.ts", "custody.ts", "index.ts", "mcp.ts", "profile-kit.ts", "profiles.ts", "workflow.ts"]) {
    const source = await readFile(new URL(`../../src/${name}`, import.meta.url), "utf8");
    assert.doesNotMatch(
      source,
      /(^|\n)\s*(?:import|const|let|var|class|function|async function)\s/m,
      `${name} contains runtime implementation`,
    );
  }
});

test("identity entry point has no higher-layer imports", async () => {
  const source = await readFile(new URL("../../src/identity.ts", import.meta.url), "utf8");
  assert.doesNotMatch(
    source,
    /from\s+["'].\/(?:approvals|plans|profiles|workflow|verifier)\b/,
  );
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
  for (const modulePath of [
    "../../dist/index.js",
    "../../dist/verify.js",
    "../../dist/inspection.js",
    "../../dist/diagnostics.js",
  ]) {
    const exports = await import(modulePath);
    for (const name of forbidden) {
      assert.equal(name in exports, false, `${modulePath} exported ${name}`);
    }
  }
});
