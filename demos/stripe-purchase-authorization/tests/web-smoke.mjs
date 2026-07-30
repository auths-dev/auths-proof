import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("purchase UI keeps policy, incoming event, decision, and receipt adjacent", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const text of [
    "Agent purchase policy",
    "Incoming purchase",
    "Run decision",
    "Canonical receipt",
    "No PAN, CVC"
  ]) assert.ok(html.includes(text), text);
});

test("browser code exposes no credential or card secret", async () => {
  const js = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
  assert.equal(js.includes("sk_test_"), false);
  assert.equal(js.includes("rk_test_"), false);
  assert.equal(js.includes("whsec_"), false);
});
