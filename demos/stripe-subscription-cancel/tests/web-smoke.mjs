import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

test("Cancellation UI keeps policy, exact action, liability, and receipt adjacent", async () => {
  const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
  for (const text of ["Cancellation policy", "Exact cancellation", "Current period", "Future liability", "Run protected cancellation", "Canonical cancellation receipt", "does not mean refunded"]) assert.ok(html.includes(text), text);
});

test("browser code contains no credential or arbitrary deletion controls", async () => {
  const files = await Promise.all([
    readFile(new URL("../web/app.js", import.meta.url), "utf8"),
    readFile(new URL("../web/index.html", import.meta.url), "utf8"),
    readFile(new URL("../web/receipt.html", import.meta.url), "utf8"),
    readFile(new URL("../web/receipt.js", import.meta.url), "utf8")
  ]);
  const text = files.join("\n");
  assert.equal(text.includes("sk_test_"), false);
  assert.equal(text.includes("rk_test_"), false);
  assert.equal(text.includes("invoice_now=true"), false);
  assert.equal(text.includes("prorate=true"), false);
});

test("designed receipt distinguishes cancellation, retained liability, and refund", async () => {
  const html = await readFile(new URL("../web/receipt.html", import.meta.url), "utf8");
  for (const text of ["Provider result", "Liability accounting", "Refund proven", "Downstream service deprovisioning is not proven"]) assert.ok(html.includes(text), text);
});
