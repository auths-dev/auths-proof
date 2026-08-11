import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(await readFile(new URL("sdk-compatibility.json", root), "utf8"));
const packageJson = JSON.parse(await readFile(new URL("package.json", root), "utf8"));
const wasmDeclarations = await readFile(new URL("wasm/auths_proof_wasm.d.ts", root), "utf8");
const { SDK_COMPATIBILITY } = await import(new URL("dist/compatibility.js", root));

assert.equal(manifest.schema, "auths.compatibility/1");
assert.equal(manifest.package, packageJson.name);
assert.equal(manifest.sdkVersion, packageJson.version);
assert.deepEqual(Object.keys(packageJson.exports).sort(), [...manifest.requiredSubpaths].sort());
assert.deepEqual([...new Set(manifest.capabilities)].sort(), manifest.capabilities);
assert.deepEqual(SDK_COMPATIBILITY.authoringAbi, manifest.authoringAbi);
assert.deepEqual(SDK_COMPATIBILITY.identityAbi, manifest.identityAbi);
assert.deepEqual(SDK_COMPATIBILITY.profiles, manifest.profiles);
assert.deepEqual(SDK_COMPATIBILITY.capabilities, manifest.capabilities);
for (const name of manifest.requiredWasmExports) {
  assert.match(wasmDeclarations, new RegExp(`export function ${name}\\(`), `WASM omitted ${name}`);
}
for (const range of [manifest.authoringAbi, manifest.identityAbi]) {
  assert.equal(Number.isSafeInteger(range.minimum), true);
  assert.equal(Number.isSafeInteger(range.maximum), true);
  assert.equal(range.minimum <= range.maximum, true);
}
