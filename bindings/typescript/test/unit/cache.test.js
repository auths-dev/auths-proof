import assert from "node:assert/strict";
import { test } from "node:test";
import { ImmutableArtifactCache } from "../../dist/verify.js";

const commitment = (value) => new Uint8Array(32).fill(value);

test("immutable artifact cache copies, bounds, evicts, and invalidates", () => {
  const cache = new ImmutableArtifactCache({ maximumEntries: 2, maximumBytes: 5 });
  const source = new Uint8Array([1, 2]);
  cache.put(commitment(1), source);
  source.fill(9);
  assert.deepEqual(cache.get(commitment(1)), new Uint8Array([1, 2]));
  const copy = cache.get(commitment(1));
  copy.fill(8);
  assert.deepEqual(cache.get(commitment(1)), new Uint8Array([1, 2]));

  cache.put(commitment(2), new Uint8Array([3, 4]));
  cache.put(commitment(3), new Uint8Array([5, 6]));
  assert.equal(cache.get(commitment(1)), undefined);
  assert.equal(cache.size, 2);
  assert.equal(cache.byteLength, 4);
  assert.equal(cache.invalidate(commitment(2)), true);
  assert.equal(cache.invalidate(commitment(2)), false);
  cache.clear();
  assert.equal(cache.byteLength, 0);
  assert.throws(() => cache.get(new Uint8Array(31)), /32 bytes/);
  assert.throws(() => cache.put(commitment(4), new Uint8Array(6)), /bounds/);
});
