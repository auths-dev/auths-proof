import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("Connect UI keeps the exact command and conservation bounds adjacent", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const text of [
    "Signed transfer",
    "Conservation bounds",
    "Source transaction",
    "Run protected transfer",
    "Canonical receipt"
  ]) assert.ok(html.includes(text), text);
});

test("browser code contains no Stripe credential", async () => {
  const js = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
  assert.equal(js.includes("sk_test_"), false);
  assert.equal(js.includes("rk_test_"), false);
});
