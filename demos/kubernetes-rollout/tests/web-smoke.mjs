import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("controls and live authorization result share one workbench", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  for (const variant of ["exact", "image-changed", "mutable-tag", "replicas-exceed", "forbidden-field", "namespace-changed", "resource-stale", "configuration-changed"]) {
    assert.match(html, new RegExp(`data-variant="${variant}"`));
  }
  assert.ok(html.indexOf('id="variant-list"') < html.indexOf('id="verdict"'));
  assert.match(html, /NO KUBECONFIG · NO TOKEN/);
  assert.doesNotMatch(html, /Verification repeats/);
});

test("static deployment proxies the native API and sets browser policy", async () => {
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/api/:path*"));
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "Referrer-Policy"));
});

test("local Docker deployment serves the frontend and proxies the same API", async () => {
  const compose = await readFile(new URL("compose.local.yaml", root), "utf8");
  const nginx = await readFile(new URL("web/nginx.local.conf", root), "utf8");
  const startup = await readFile(new URL("scripts/local-up.sh", root), "utf8");
  assert.match(compose, /127\.0\.0\.1:\$\{AUTHS_KUBERNETES_LOCAL_PORT:-4173\}:8080/);
  assert.match(compose, /dockerfile: Dockerfile\.local/);
  assert.match(compose, /name: kind/);
  assert.match(nginx, /proxy_pass http:\/\/backend:8080/);
  assert.match(nginx, /Content-Security-Policy/);
  assert.equal((startup.match(/--provenance=false/g) ?? []).length, 2);
  assert.match(startup, /\/readyz/);
});

test("frontend submits selected variants and reads the nested result", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  const receipt = await readFile(new URL("web/receipt.js", root), "utf8");
  assert.match(script, /JSON\.stringify\(\{ variant: state\.active \}\)/);
  assert.match(script, /const result = response\.result/);
  assert.match(script, /result\.kubernetes_called/);
  assert.match(script, /receiptViewer/);
  assert.match(script, /JSON\.stringify\(receipt, null, 2\)/);
  assert.match(receipt, /\/api\/v1\/receipts\//);
});

test("receipt link resolves to a designed page rather than raw API JSON", async () => {
  const html = await readFile(new URL("web/receipt.html", root), "utf8");
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  const nginx = await readFile(new URL("web/nginx.local.conf", root), "utf8");
  assert.match(html, /What Auths decided/);
  assert.match(html, /complete machine-readable JSON/);
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/receipts/:sessionId"));
  assert.match(nginx, /\^\/receipts\/\[0-9a-f\]\{32\}/);
});
