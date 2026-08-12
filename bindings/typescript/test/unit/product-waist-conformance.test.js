import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { productWaistConformance } from "../../dist/testkit/index.js";

const manifest = JSON.parse(
  await readFile(
    new URL("../../../../product/conformance/v1/simplified-product-waist.json", import.meta.url),
    "utf8",
  ),
);

test("product-waist runner executes every Rust-owned invariant in order", async () => {
  const observed = [];
  const cases = manifest.cases.map((candidate) => ({
    id: candidate.id,
    run(expected) {
      assert.deepEqual(expected, {
        boundary: candidate.boundary,
        code: candidate.expected,
      });
      observed.push(candidate.id);
    },
  }));
  const report = await productWaistConformance(manifest, cases);
  assert.deepEqual(observed, manifest.cases.map((candidate) => candidate.id));
  assert.deepEqual(report.passed, observed);
  assert.equal(report.manifestSchema, manifest.schema);
});

test("product-waist runner rejects incomplete and unexpected case sets", async () => {
  const cases = manifest.cases.map((candidate) => ({ id: candidate.id, run() {} }));
  await assert.rejects(
    productWaistConformance(manifest, cases.slice(1)),
    /missing=command\/forged-construction/,
  );
  await assert.rejects(
    productWaistConformance(manifest, [
      ...cases,
      { id: "command/unexpected", run() {} },
    ]),
    /unexpected=command\/unexpected/,
  );
});
