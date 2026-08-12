import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { npmSync } from "./helpers/packed-install.mjs";

test("package exposes bounded public surfaces and includes contributor docs", async () => {
  const manifest = JSON.parse(
    await readFile(new URL("../../package.json", import.meta.url), "utf8"),
  );
  assert.deepEqual(Object.keys(manifest.exports).sort(), [
    ".",
    "./framework",
    "./identity",
    "./integrations",
    "./profiles",
    "./testkit",
    "./verify",
  ]);
  assert.ok(manifest.files.includes("docs"));
  assert.ok(manifest.files.includes("sdk-runtime-contract.json"));
  assert.ok(manifest.files.includes("sdk-capability.json"));
  assert.ok(manifest.files.includes("performance-baseline.json"));
  assert.ok(manifest.files.includes("wasm/auths_proof_wasm_bg.wasm"));
  assert.deepEqual(manifest.bin, { auths: "./dist/doctor-cli.js" });
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
    env: { ...process.env, npm_config_cache: join(tmpdir(), "auths-package-test-npm-cache") },
    stdio: ["ignore", "pipe", "ignore"],
  });
  const [packed] = JSON.parse(listing);
  const entries = packed.files.map((file) => file.path);

  for (const required of [
    "package.json",
    "dist/index.js",
    "dist/index.d.ts",
    "dist/framework.js",
    "dist/doctor-cli.js",
    "dist/doctor.js",
    "dist/identity.js",
    "dist/integrations.js",
    "dist/profiles.js",
    "dist/testkit/index.js",
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
  for (const name of ["framework.ts", "profiles.ts"]) {
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

test("identity and verification dependency closures exclude effect workflow code", async () => {
  const forbidden = /\/(?:approvals|custody|plans|profiles|workflow)(?:\/|\.|$)/;
  for (const entry of ["identity.js", "verify.js"]) {
    const closure = await sourceClosure(new URL(`../../dist/${entry}`, import.meta.url));
    assert.equal(
      closure.some((path) => forbidden.test(path)),
      false,
      `${entry} loaded an effect workflow module: ${closure.join(", ")}`,
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
  for (const modulePath of [
    "../../dist/index.js",
    "../../dist/verify.js",
    "../../dist/identity.js",
    "../../dist/framework.js",
  ]) {
    const exports = await import(modulePath);
    for (const name of forbidden) {
      assert.equal(name in exports, false, `${modulePath} exported ${name}`);
    }
  }
});

async function sourceClosure(entry) {
  const pending = [entry];
  const seen = new Set();
  while (pending.length > 0) {
    const current = pending.pop();
    if (seen.has(current.href)) continue;
    seen.add(current.href);
    const source = await readFile(current, "utf8");
    for (const match of source.matchAll(/(?:from\s+|import\s*)["'](\.[^"']+)["']/g)) {
      pending.push(new URL(match[1], current));
    }
  }
  return [...seen].map((url) => new URL(url).pathname);
}
