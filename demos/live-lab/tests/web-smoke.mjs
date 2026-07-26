import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  configurationState,
  copyAndFlipLast,
  hex,
  runtimeDisplay,
  short,
} from "../web/lab-core.js";

const repository = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const site = resolve(
  process.argv[2] ?? join(repository, "target/live-demo/site"),
);

const original = Uint8Array.from([1, 2, 3]);
const changed = copyAndFlipLast(original);
assert.deepEqual(original, Uint8Array.from([1, 2, 3]));
assert.deepEqual(changed, Uint8Array.from([1, 2, 2]));
assert.equal(hex(original), "010203");
assert.equal(short("0123456789abcdef", 8), "01234567…cdef");
assert.equal(configurationState("a", "a"), "match");
assert.equal(configurationState("a", "b"), "mismatch");
assert.deepEqual(runtimeDisplay("valid"), {
  first: "READY",
  replay: "NOT RUN",
  executorInvocations: 0,
  receiptCount: "0 decision · 0 execution",
});
const completedRuntime = {
  entered: true,
  response: { outcome: "completed" },
  executor_invocations: 1,
  decision_receipts: 1,
  execution_receipts: 1,
};
assert.deepEqual(runtimeDisplay("valid", completedRuntime, 1), {
  first: "COMPLETED",
  replay: "READY",
  executorInvocations: 1,
  receiptCount: "1 decision · 1 execution",
});
assert.deepEqual(
  runtimeDisplay(
    "valid",
    {
      ...completedRuntime,
      response: { outcome: "refused", kind: "consumed-challenge" },
    },
    2,
  ),
  {
    first: "COMPLETED",
    replay: "CONSUMED-CHALLENGE",
    executorInvocations: 1,
    receiptCount: "1 decision · 1 execution",
  },
);
assert.deepEqual(
  runtimeDisplay("tampered-proof", {
    entered: false,
    executor_invocations: 0,
    decision_receipts: 0,
    execution_receipts: 0,
  }),
  {
    first: "DENIED",
    replay: "NOT ENTERED",
    executorInvocations: 0,
    receiptCount: "0 decision · 0 execution",
  },
);
assert.throws(
  () => runtimeDisplay("tampered-proof", completedRuntime),
  /crossed the native executor boundary/,
);
assert.throws(
  () => runtimeDisplay("valid", completedRuntime, 2),
  /replay transition/,
);

const html = await readFile(join(site, "index.html"), "utf8");
for (const id of [
  "verdict",
  "verdict-summary",
  "variants",
  "runtime-outcome",
  "replay-outcome",
  "required-config",
  "executed-config",
  "developer-panel",
  "native-button",
  "native-status",
  "session-status",
]) {
  assert.match(html, new RegExp(`id="${id}"`));
}

for (const designHook of [
  'class="site-header"',
  'class="wordmark"',
  'class="experiment-section workbench-section"',
  'class="workbench-frame"',
  'class="scenario-panel"',
  'class="result-panel"',
  'class="site-footer"',
  'name="color-scheme" content="light"',
]) {
  assert.match(html, new RegExp(designHook));
}
assert.doesNotMatch(html, /id="verify-button"/);

const styles = await readFile(join(site, "styles.css"), "utf8");
for (const designToken of [
  "--canvas: #f6f5f1",
  "--brand: #3157d5",
  "--verified: #167456",
  "--code: #171a18",
  "@media (prefers-reduced-motion: reduce)",
]) {
  assert.ok(
    styles.includes(designToken),
    `missing Auths design-system contract: ${designToken}`,
  );
}

const { loadAuths } = await import(
  pathToFileURL(join(site, "vendor/index.js")).href
);
const auths = await loadAuths({
  moduleUrl: pathToFileURL(join(site, "vendor/wasm/auths_proof_wasm.js")).href,
  wasmInput: await readFile(join(site, "vendor/wasm/auths_proof_wasm_bg.wasm")),
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
