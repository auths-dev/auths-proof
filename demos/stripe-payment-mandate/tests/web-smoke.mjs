import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("consent, execution, result, and reconciliation are adjacent", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  for (const id of ["accept", "consent", "execute", "outcome", "reconcile"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.ok(html.indexOf('id="accept"') < html.indexOf('id="execute"'));
});

test("copy distinguishes capability from payment", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /does not charge money/i);
  assert.match(html, /future payments still need separate exact authority/i);
  assert.match(html, /client secret/i);
  assert.match(html, /Human consent/i);
  assert.match(html, /SetupIntent/i);
});

test("browser uses credentialed consent and the required routes", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(script, /credentials: "include"/);
  assert.match(script, /\/consent/);
  assert.match(script, /\/execute/);
  assert.match(script, /\/reconcile/);
  assert.match(script, /displayed_terms_digest/);
});

test("designed receipt and separate machine API are wired", async () => {
  const page = await readFile(new URL("web/receipt.html", root), "utf8");
  const script = await readFile(new URL("web/receipt.js", root), "utf8");
  assert.match(page, /No charge occurred/);
  assert.match(script, /\/api\/v1\/receipts\//);
});

test("frontend sources contain no credential or client-secret values", async () => {
  for (const name of await readdir(new URL("web/", root))) {
    const source = await readFile(new URL(`web/${name}`, root), "utf8");
    assert.doesNotMatch(source, /sk_(?:test|live)_[A-Za-z0-9]{8,}/);
    assert.doesNotMatch(source, /"client_secret"\s*:/);
    assert.doesNotMatch(source, /Authorization\s*:\s*Bearer/i);
  }
});

test("static deployment has restrictive policy and configurable API", async () => {
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "Referrer-Policy"));
  const example = await readFile(new URL("web/config.js.example", root), "utf8");
  assert.match(example, /AUTHS_PAYMENT_MANDATE_API_BASE/);
});
