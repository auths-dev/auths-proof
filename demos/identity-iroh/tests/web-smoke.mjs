import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const root = new URL("../", import.meta.url);

test("workbench makes the optional authority boundary explicit", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /No grants\. No approvals\./);
  assert.match(html, /data-experiment="public-identity"/);
  assert.match(html, /data-experiment="signed-message"/);
  assert.match(html, /data-experiment="tampered-message"/);
  assert.match(html, /Authorization evaluated/);
  assert.match(html, /Capability module/);
  assert.match(html, /id="evidence-json"/);
  assert.match(html, /href="\.\/styles\.css"/);
  assert.match(html, /<script defer src="\.\/app\.js\?v=2"><\/script>/);
});

test("frontend calls the real native identity endpoint", async () => {
  const javascript = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(javascript, /\/api\/v1\/status/);
  assert.match(javascript, /\/api\/v1\/exchanges/);
  assert.match(javascript, /signature_verified/);
  assert.doesNotMatch(javascript, /mock|fixtureResult|fakeIdentity/i);
});

test("frontend starts, enables execution, and changes the selected experiment", async () => {
  const javascript = await readFile(new URL("web/app.js", root), "utf8");
  const makeElement = (properties = {}) => {
    const listeners = new Map();
    return {
      textContent: "",
      dataset: {},
      disabled: true,
      value: "hello",
      classList: {
        add() {},
        toggle() {},
      },
      addEventListener(type, listener) {
        listeners.set(type, listener);
      },
      click() {
        listeners.get("click")?.();
      },
      ...properties,
    };
  };
  const elements = Object.fromEntries([
    "server-principal",
    "server-key",
    "service-state",
    "service-indicator",
    "execute",
    "verdict",
    "verdict-detail",
    "message",
    "operation-title",
    "operation-copy",
  ].map((id) => [id, makeElement()]));
  const variants = ["public-identity", "signed-message", "tampered-message"]
    .map((experiment) => makeElement({ dataset: { experiment } }));
  const context = {
    document: {
      getElementById: (id) => elements[id],
      querySelectorAll: () => variants,
    },
    fetch: async () => ({
      ok: true,
      json: async () => ({
        server_principal: "key:test",
        server_identity_method: "raw-key-identity-v1",
        server_signature_suite: "ed25519-v1",
        server_public_key: "00",
      }),
    }),
  };

  vm.runInNewContext(javascript, context);
  await new Promise((resolve) => setImmediate(resolve));

  assert.equal(elements.execute.disabled, false);
  assert.equal(elements.execute.textContent, "Run identity exchange");
  assert.equal(elements["service-state"].textContent, "ready");
  variants[1].click();
  assert.equal(elements["operation-title"].textContent, "Sign and verify one message");
});

test("static-host configuration preserves the designed frontend", async () => {
  const config = JSON.parse(await readFile(new URL("web/vercel.json", root), "utf8"));
  assert.equal(config.cleanUrls, true);
  const headers = config.headers.flatMap((entry) => entry.headers);
  assert.ok(headers.some((header) => header.key === "Content-Security-Policy"));
  assert.ok(headers.some((header) => header.key === "X-Content-Type-Options"));
});
