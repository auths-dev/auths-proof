import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);

test("controls and live result are adjacent in the hero", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /class="shell cancel-hero-grid"/);
  assert.match(html, /id="experiments"/);
  assert.match(html, /class="live-result"/);
  assert.match(html, /id="execute"/);
  assert.ok(html.indexOf('id="experiments"') < html.indexOf('id="outcome"'));
});

test("literal copy exposes policy, exact effect, hold, credentials, and receipts", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  for (const phrase of [
    "immutable configured policy",
    "Agent-selected exact effect",
    "Fresh protected evidence",
    "Credential requests",
    "Provider calls",
    "Prior hold",
    "Pre-cancel status",
    "Cancellation claim",
    "Refund created",
    "Capturable",
    "Reason",
    "Inline canonical artifact",
  ]) {
    assert.match(html, new RegExp(phrase, "i"));
  }
  assert.match(html, /does not yet carry a mechanically human-signed/i);
  assert.match(html, /cannot refund a settled payment/i);
  assert.match(html, /manual-capture authorization/i);
  assert.match(html, /without calling it a refund/i);
});

test("designed receipt and separate machine API are wired", async () => {
  const page = await readFile(new URL("web/receipt.html", root), "utf8");
  const script = await readFile(new URL("web/receipt.js", root), "utf8");
  assert.match(page, /Digest-addressed public record/);
  assert.match(page, /id="provider-acceptance"/);
  assert.match(script, /\/api\/v1\/receipts\//);
  assert.match(script, /target_amount_minor/);
  assert.match(script, /capture_conflict/);
  assert.match(script, /reconciled_observation/);
});

test("durable replay remains visible when the in-memory session is gone", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(script, /if \(result\.outcome !== "replay"\) throw error;/);
});

test("cancel status and hold vocabulary are wired", async () => {
  const script = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(script, /linked_authorization/);
  assert.match(script, /authorization-released-by-cancel/);
  assert.match(script, /amount_capturable_minor/);
  assert.match(script, /cancellation_reason/);
  assert.match(script, /capture-conflict/);
});

test("frontend sources contain no credential or client-secret values", async () => {
  const files = await readdir(new URL("web/", root));
  for (const name of files) {
    const source = await readFile(new URL(`web/${name}`, root), "utf8");
    assert.doesNotMatch(source, /sk_(?:test|live)_[A-Za-z0-9]{8,}/);
    assert.doesNotMatch(source, /"client_secret"\s*:/);
    assert.doesNotMatch(source, /Cancellation\s*:\s*Bearer/i);
  }
});

test("static deployment has restrictive policy and configurable API", async () => {
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "Referrer-Policy"));
  assert.ok(config.rewrites.some((rewrite) => rewrite.source === "/receipts/:receiptId"));
  const example = await readFile(new URL("web/config.js.example", root), "utf8");
  assert.match(example, /AUTHS_PAYMENT_CANCEL_API_BASE/);
});
