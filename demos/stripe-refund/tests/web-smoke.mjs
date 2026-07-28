import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("workbench exposes adjacent selectable controls and live results", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /id="variant-list"/);
  assert.match(html, /data-variant="exact"/);
  assert.match(html, /data-variant="amount-changed"/);
  assert.match(html, /id="verdict"/);
  assert.match(html, /id="execute"/);
  assert.ok(
    html.indexOf('id="variant-list"') < html.indexOf('id="verdict"'),
    "controls should precede the adjacent result in one workbench",
  );
});

test("static deployment proxies API and sets restrictive browser policy", async () => {
  const config = JSON.parse(
    await readFile(new URL("web/vercel.json", root), "utf8"),
  );
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/api/:path*"));
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "Referrer-Policy"));
});

test("copy states test mode and credential isolation concretely", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /Real Stripe test payment/);
  assert.match(html, /NO STRIPE KEY/);
  assert.match(html, /No real money/);
  assert.doesNotMatch(html, /Verification repeats/);
});
