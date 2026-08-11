import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { ImmutableArtifactCache, loadVerifier } from "../../dist/verify.js";

const root = fileURLToPath(new URL("../../../../target/binding-vectors/", import.meta.url));
const scenarios = JSON.parse(readFileSync(`${root}/scenarios.json`, "utf8"));

test(`packed verifier matches all ${scenarios.length} shared semantic scenarios`, async () => {
  const verifier = await loadVerifier();
  assert.ok(scenarios.length >= 50, "production registry scenario coverage regressed");
  const inputs = scenarios.map(({ id }) => ({
    proofCbor: readFileSync(`${root}/scenarios/${id}.proof.cbor`),
    canonicalActionCbor: readFileSync(`${root}/scenarios/${id}.action.cbor`),
    trustedContextCbor: readFileSync(`${root}/scenarios/${id}.context.cbor`),
  }));
  const results = await verifier.verifyMany(inputs, { chunkSize: 32 });
  assert.equal(results.length, scenarios.length);
  results.forEach((result, index) => {
    const scenario = scenarios[index];
    assert.ok(scenario);
    assert.deepEqual(
      Buffer.from(result.resultCbor),
      readFileSync(`${root}/scenarios/${scenario.id}.result.cbor`),
      scenario.id,
    );
  });
});

test("commitment-cached artifacts preserve every scenario result", async () => {
  const verifier = await loadVerifier();
  const cache = new ImmutableArtifactCache({ maximumEntries: 264, maximumBytes: 16_777_216 });
  const store = (bytes) => {
    const commitment = createHash("sha256").update(bytes).digest();
    cache.put(commitment, bytes);
    return cache.get(commitment);
  };
  for (const { id } of scenarios) {
    const result = verifier.verify(
      store(readFileSync(`${root}/scenarios/${id}.proof.cbor`)),
      store(readFileSync(`${root}/scenarios/${id}.action.cbor`)),
      store(readFileSync(`${root}/scenarios/${id}.context.cbor`)),
    );
    assert.deepEqual(
      Buffer.from(result.resultCbor),
      readFileSync(`${root}/scenarios/${id}.result.cbor`),
      id,
    );
  }
});
