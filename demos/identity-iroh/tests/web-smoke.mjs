import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("workbench makes the optional authority boundary explicit", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /No grants\. No approvals\./);
  assert.match(html, /data-experiment="public-identity"/);
  assert.match(html, /data-experiment="signed-message"/);
  assert.match(html, /data-experiment="tampered-message"/);
  assert.match(html, /Authorization evaluated/);
  assert.match(html, /Capability module/);
  assert.match(html, /id="evidence-json"/);
});

test("frontend calls the real native identity endpoint", async () => {
  const javascript = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(javascript, /\/api\/v1\/status/);
  assert.match(javascript, /\/api\/v1\/exchanges/);
  assert.match(javascript, /signature_verified/);
  assert.doesNotMatch(javascript, /mock|fixtureResult|fakeIdentity/i);
});
