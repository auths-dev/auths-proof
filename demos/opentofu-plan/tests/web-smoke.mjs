import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("all saved-plan experiments and the result occupy one workbench", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  for (const variant of ["exact", "swapped-plan", "workspace-changed", "stale-state", "destroy-added", "dependency-changed", "configuration-changed"]) {
    assert.match(html, new RegExp(`data-variant="${variant}"`));
  }
  assert.ok(html.indexOf('id="variant-list"') < html.indexOf('id="verdict"'));
  assert.match(html, /No secret names or values cross this interface/);
  assert.match(html, /Complete receipt from the native API/);
});

test("frontend calls readiness, credential probe, execution, and receipt APIs", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(script, /request\("\/readyz"\)/);
  assert.match(script, /request\("\/api\/v1\/credential-probe"\)/);
  assert.match(script, /JSON\.stringify\(\{ variant: state\.active \}\)/);
  assert.match(script, /\/api\/v1\/receipts\//);
  assert.match(script, /result\.opentofu_called/);
});

test("the dedicated receipt route fails closed and reads native JSON", async () => {
  const html = await readFile(new URL("web/receipt.html", root), "utf8");
  const script = await readFile(new URL("web/receipt.js", root), "utf8");
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  assert.match(html, /What Auths allowed/);
  assert.match(html, /Fail-closed receipt page/);
  assert.match(script, /^\s*const match = \/\^\\\/receipts\\\//m);
  assert.match(script, /JSON\.stringify\(receipt, null, 2\)/);
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/receipts/:sessionId"));
});

test("the browser policy and native API proxy are explicit", async () => {
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/api/:path*"));
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "Referrer-Policy"));
});
