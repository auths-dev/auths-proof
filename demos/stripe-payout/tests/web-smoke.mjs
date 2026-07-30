import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("Payout UI keeps policy, exact payout, approvals, and receipt adjacent", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const text of ["Payout policy", "Exact payout", "Approvers", "Run protected payout", "Canonical receipt", "does not move real bank funds"]) assert.ok(html.includes(text), text);
});

test("browser code contains no credential or bank coordinates", async () => {
  const files = await Promise.all([
    readFile(new URL("../web/app.js", import.meta.url), "utf8"),
    readFile(new URL("../web/index.html", import.meta.url), "utf8")
  ]);
  const text = files.join("\n");
  assert.equal(text.includes("sk_test_"), false);
  assert.equal(text.includes("rk_test_"), false);
  assert.equal(/[0-9]{9,}/.test(text), false);
});
