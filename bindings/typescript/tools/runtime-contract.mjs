import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("sdk-runtime-contract.json", root), "utf8"));
const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
const wasmDeclarations = await readFile(new URL("wasm/auths_proof_wasm.d.ts", root), "utf8");
const { SDK_RUNTIME_CONTRACT } = await import(new URL("dist/runtime-contract.js", root));

assert.equal(manifest.schema, "auths.runtime-contract/1");
assert.equal(manifest.package, packageJson.name);
assert.equal(manifest.sdkVersion, packageJson.version);
assert.deepEqual(Object.keys(packageJson.exports).sort(), [...manifest.requiredSubpaths].sort());
assert.deepEqual([...new Set(manifest.capabilities)].sort(), manifest.capabilities);
assert.equal(SDK_RUNTIME_CONTRACT.authoringAbi, manifest.authoringAbi);
assert.equal(SDK_RUNTIME_CONTRACT.identityAbi, manifest.identityAbi);
assert.deepEqual(SDK_RUNTIME_CONTRACT.profiles, manifest.profiles);
assert.deepEqual(SDK_RUNTIME_CONTRACT.capabilities, manifest.capabilities);
for (const name of manifest.requiredWasmExports) {
  assert.match(wasmDeclarations, new RegExp(`export function ${name}\\(`), `WASM omitted ${name}`);
}
for (const version of [manifest.authoringAbi, manifest.identityAbi]) {
  assert.equal(Number.isSafeInteger(version), true);
  assert.equal(version > 0, true);
}
