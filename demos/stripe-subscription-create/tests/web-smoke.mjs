import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("policy action liability and result remain adjacent", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  for (const id of ["policy", "action", "recurring", "immediate", "term", "cycles", "execute", "result", "receipt"]) {
    assert.match(html, new RegExp(`id="${id}"`));
  }
  assert.ok(html.indexOf('id="policy"') < html.indexOf('id="execute"'));
});

test("copy exposes continuing finite liability", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /three provider-clock cycles/i);
  assert.match(html, /whole term and the first invoice/i);
  assert.match(html, /typed mandate/i);
});

test("required routes are wired", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  for (const route of ["/sessions", "/execute", "/reconcile", "/advance-clock"]) {
    assert.match(script, new RegExp(route.replace("/", "\\/")));
  }
});

test("designed receipt and machine API are separate", async () => {
  const page = await readFile(new URL("web/receipt.html", root), "utf8");
  const script = await readFile(new URL("web/receipt.js", root), "utf8");
  assert.match(page, /Finite liability/);
  assert.match(script, /\/api\/v1\/receipts\//);
});

test("frontend is secret free", async () => {
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
  assert.match(await readFile(new URL("web/config.js.example", root), "utf8"), /AUTHS_SUBSCRIPTION_CREATE_API_BASE/);
});
