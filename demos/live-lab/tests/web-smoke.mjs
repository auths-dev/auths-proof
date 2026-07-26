import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  configurationState,
  copyAndFlipLast,
  hex,
  short,
} from "../web/lab-core.js";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const site = resolve(process.argv[2] ?? join(repository, "target/live-demo/site"));

const original = Uint8Array.from([1, 2, 3]);
const changed = copyAndFlipLast(original);
assert.deepEqual(original, Uint8Array.from([1, 2, 3]));
assert.deepEqual(changed, Uint8Array.from([1, 2, 2]));
assert.equal(hex(original), "010203");
assert.equal(short("0123456789abcdef", 8), "01234567…cdef");
assert.equal(configurationState("a", "a"), "match");
assert.equal(configurationState("a", "b"), "mismatch");

const html = await readFile(join(site, "index.html"), "utf8");
for (const id of [
  "verdict",
  "variants",
  "runtime-outcome",
  "replay-outcome",
  "required-config",
  "executed-config",
  "developer-panel",
]) {
  assert.match(html, new RegExp(`id="${id}"`));
}

const { loadAuths } = await import(
  pathToFileURL(join(site, "vendor/index.js")).href
);
const auths = await loadAuths({
  moduleUrl: pathToFileURL(
    join(site, "vendor/wasm/auths_proof_wasm.js"),
  ).href,
  wasmInput: await readFile(
    join(site, "vendor/wasm/auths_proof_wasm_bg.wasm"),
  ),
});
const scenario = JSON.parse(
  await readFile(join(site, "assets/scenario.json"), "utf8"),
);
assert.equal(scenario.variants.length, 4);
for (const variant of scenario.variants) {
  const [proof, action, context, nativeResult] = await Promise.all([
    readFile(join(site, variant.files.proof)),
    readFile(join(site, variant.files.action)),
    readFile(join(site, variant.files.context)),
    readFile(join(site, variant.files.result)),
  ]);
  const browser = auths.verify(proof, action, context);
  assert.equal(browser.kind, variant.native.decision);
  assert.deepEqual(Buffer.from(browser.resultCbor), nativeResult);
}
