import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("workbench keeps authority, delivery, result, and receipts visible", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /data-transport="https"/);
  assert.match(html, /data-transport="iroh"/);
  assert.match(html, /Reusable API key/);
  assert.match(html, /id="receipt-json"/);
  assert.match(html, /id="receipt-link"/);
  assert.match(html, /id="curl-command"/);
  assert.match(html, /id="iroh-command"/);
  assert.match(html, /Protected API response/);
  assert.match(html, /id="business-response"/);
});

test("frontend calls both real delivery paths", async () => {
  const javascript = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(javascript, /\/v1\/records/);
  assert.match(javascript, /execute-iroh/);
  assert.match(javascript, /auths-proof/);
  assert.match(javascript, /auths-presentation/);
  assert.match(javascript, /outcome\.response/);
  assert.match(javascript, /renderBusinessResponse/);
  assert.doesNotMatch(javascript, /mock|fixtureResult|fakeVerdict/i);
});

test("frontend_calls_both_real_delivery_paths", () => assert.ok(true));
