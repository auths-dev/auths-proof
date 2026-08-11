import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { readdir, readFile, stat } from "node:fs/promises";
import { performance } from "node:perf_hooks";

const root = new URL("../", import.meta.url);
const vectorRoot = new URL("../../target/binding-vectors/", root);
const started = performance.now();
const { loadVerifier } = await import(new URL("dist/verify.js", root));
const verifier = await loadVerifier();
const coldStartMs = performance.now() - started;
const input = {
  proofCbor: await readFile(new URL("../../core/fixtures/v1/valid/raw-key-chain.proof.cbor", root)),
  canonicalActionCbor: await readFile(new URL("../../core/fixtures/v1/valid/raw-key-chain.action.cbor", root)),
  trustedContextCbor: await readFile(new URL("authorized.context.cbor", vectorRoot)),
};
const timings = [];
for (let index = 0; index < 100; index += 1) {
  const before = performance.now();
  verifier.verify(input.proofCbor, input.canonicalActionCbor, input.trustedContextCbor);
  timings.push(performance.now() - before);
}
timings.sort((left, right) => left - right);
const { loadPackagedWorkflowEngine } = await import(new URL("dist/internal/wasm.js", root));
const engine = await loadPackagedWorkflowEngine();
const wasmBoundarySerializeSmallP95Ms = boundaryP95(engine, 64);
const wasmBoundarySerializeMediumP95Ms = boundaryP95(engine, 4096);
const wasmBoundarySerializeMaximumP95Ms = boundaryP95(engine, 65536);
const batchStarted = performance.now();
await verifier.verifyMany(Array.from({ length: 64 }, () => input));
const batchMs = performance.now() - batchStarted;
const { defineProfile } = await import(new URL("dist/profile-kit.js", root));
const profile = defineProfile({
  id: "auths.performance/1",
  version: 1,
  canonicalize(value) {
    return {
      mediaType: "application/octet-stream",
      body: Uint8Array.of(value),
      permission: { capability: "benchmark/use", resource: `benchmark://${value}` },
      resourceNamespace: "benchmark://",
      audience: "benchmark://local",
      display: [{ label: "Item", value: String(value) }],
    };
  },
});
const planStarted = performance.now();
await profile.plan(Array.from({ length: 64 }, (_unused, index) => profile.action(index)));
const plan64Ms = performance.now() - planStarted;
const wasm = await readFile(new URL("wasm/auths_proof_wasm_bg.wasm", root));
const distBytes = await directoryBytes(new URL("dist/", root));
const measurement = {
  coldStartMs,
  warmVerificationP95Ms: timings[Math.floor(timings.length * 0.95)],
  wasmBoundarySerializeSmallP95Ms,
  wasmBoundarySerializeMediumP95Ms,
  wasmBoundarySerializeMaximumP95Ms,
  batch64Ms: batchMs,
  plan64Ms,
  residentMemoryBytes: process.memoryUsage().rss,
  wasmBytes: wasm.length,
  compressedWasmBytes: gzipSync(wasm).length,
  distBytes,
};

if (process.argv.includes("--print")) {
  process.stdout.write(`${JSON.stringify(measurement, null, 2)}\n`);
} else {
  const baseline = JSON.parse(await readFile(new URL("performance-baseline.json", root), "utf8"));
  assert.equal(baseline.schema, "auths.performance/1");
  const matchingEnvironment = baseline.environment.platform === process.platform &&
    baseline.environment.architecture === process.arch &&
    baseline.environment.node === process.versions.node;
  if (matchingEnvironment) {
    for (const key of [
      "coldStartMs",
      "warmVerificationP95Ms",
      "wasmBoundarySerializeSmallP95Ms",
      "wasmBoundarySerializeMediumP95Ms",
      "wasmBoundarySerializeMaximumP95Ms",
      "batch64Ms",
      "plan64Ms",
      "residentMemoryBytes",
    ]) {
      assert.ok(measurement[key] <= baseline.measurements[key] * 1.1, `${key} exceeded 10% budget`);
    }
  }
  for (const key of ["wasmBytes", "compressedWasmBytes", "distBytes"]) {
    assert.ok(measurement[key] <= baseline.measurements[key] * 1.15, `${key} exceeded 15% budget`);
  }
  process.stdout.write(`${JSON.stringify({ matchingEnvironment, measurement }, null, 2)}\n`);
}

function boundaryP95(engine, size) {
  const value = new Uint8Array(size);
  const samples = [];
  for (let index = 0; index < 100; index += 1) {
    const before = performance.now();
    engine.commitCanonicalV1("auths.performance-boundary.v1", value);
    samples.push(performance.now() - before);
  }
  samples.sort((left, right) => left - right);
  return samples[Math.floor(samples.length * 0.95)];
}

async function directoryBytes(directory) {
  let total = 0;
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const url = new URL(entry.name, directory);
    total += entry.isDirectory() ? await directoryBytes(new URL(`${entry.name}/`, directory)) : (await stat(url)).size;
  }
  return total;
}
