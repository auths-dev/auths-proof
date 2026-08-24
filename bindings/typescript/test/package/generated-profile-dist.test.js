import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

const roots = ["stripe", "postgresql", "opentofu"].map(
  (domain) => new URL(`../../../generated/${domain}/typescript/`, import.meta.url),
);

function descriptors(source) {
  return [...source.matchAll(/bindProfile\(session, Object\.freeze\((\{[^\n]+\})\), connection\)/gu)]
    .map((match) => match[1]);
}

test("generated profile distributions carry the exact generated descriptors", async () => {
  for (const root of roots) {
    const source = await readFile(new URL("src/index.ts", root), "utf8");
    const distribution = await readFile(new URL("dist/index.js", root), "utf8");
    const expected = descriptors(source);
    assert.ok(expected.length > 0, `${root.pathname} has no generated descriptors`);
    assert.deepEqual(descriptors(distribution), expected, `${root.pathname} dist is stale`);
    assert.doesNotMatch(source, /\bqualifications\s*:/u);
    assert.doesNotMatch(distribution, /\bqualifications\s*:/u);
  }
});
