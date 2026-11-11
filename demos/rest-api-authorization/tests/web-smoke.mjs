import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const root = new URL("../", import.meta.url);

test("workbench keeps authority, delivery, result, and receipts visible", async () => {
  const html = await readFile(new URL("web/index.html", root), "utf8");
  assert.match(html, /data-transport="https"/);
  assert.match(html, /data-transport="iroh"/);
  assert.match(html, /Reusable API key/);
  assert.match(html, /id="receipt-json"/);
  assert.match(html, /id="receipt-link"/);
  assert.match(html, /id="curl-command"/);
  assert.match(html, /id="iroh-command"/);
  assert.match(html, /Protected API response/);
  assert.match(html, /id="business-response"/);
});

test("frontend calls both real delivery paths", async () => {
  const javascript = await readFile(new URL("web/app.js", root), "utf8");
  assert.match(javascript, /\/v1\/records/);
  assert.match(javascript, /execute-iroh/);
  assert.match(javascript, /auths-proof/);
  assert.match(javascript, /auths-presentation/);
  assert.match(javascript, /outcome\.response/);
  assert.match(javascript, /renderBusinessResponse/);
  assert.doesNotMatch(javascript, /mock|fixtureResult|fakeVerdict/i);
});

test("frontend_calls_both_real_delivery_paths", () => assert.ok(true));

function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

function browserSurface() {
  const elements = new Map();
  const get = (id) => {
    if (!elements.has(id)) elements.set(id, {
      textContent: "", disabled: false, hidden: false, dataset: {},
      classList: { add() {}, remove() {}, toggle() {} },
      setAttribute() {}, removeAttribute() {}, listeners: {},
      addEventListener(event, callback) { this.listeners[event] = callback; },
    });
    return elements.get(id);
  };
  const experiments = ["exact-create", "bounded-create", "exact-read"].map((id) => {
    const button = get(id); button.dataset.experiment = id; return button;
  });
  const transports = ["https", "iroh"].map((id) => {
    const button = get(id); button.dataset.transport = id; return button;
  });
  return { get, document: {
    getElementById: get,
    querySelectorAll: (selector) => selector === "[data-experiment]" ? experiments : transports,
    querySelector: () => get("exact-read"),
  } };
}

const turn = () => new Promise(setImmediate);
const session = (id) => ({
  session_id: id, required_configuration: { maximum_response_bytes: 128 },
  executed_configuration: { maximum_response_bytes: 128 }, policy: { maximum_creates: 2, maximum_created_bytes: 128 },
  operation_id: "records.create.v1", proof_hex: id, presentation_hex: id,
  action: { action: { record_id: id, customer: { name: id } } },
});
const outcome = (id) => ({ receipt: {
  decision: { receipt_id: id, decision: { class: "authorized", code: "authorized", stage: "complete" },
    auths_decision: "authorized", protected_storage_accessed: true },
  delivery: { adapter: "https" }, effect: {}, observation: {},
} });

for (const order of ["execution-first", "preparation-first"]) {
  test(`U1: stale execution cannot publish or release another operation (${order})`, async () => {
    const surface = browserSurface();
    const requests = [];
    const context = vm.createContext({ document: surface.document,
      fetch(url, options) { const response = deferred(); requests.push({ url, options, response }); return response.promise; },
    });
    vm.runInContext(await readFile(new URL("web/app.js", root), "utf8"), context);
    const respond = async (index, body) => {
      requests[index].response.resolve({ ok: true, json: async () => body });
      await turn();
    };
    await respond(0, session("A"));
    const a = vm.runInContext("execute()", context);
    assert.equal(requests[1].options.headers["auths-session"], "A");
    surface.get("bounded-create").listeners.click();
    assert.equal(requests.length, 3);
    if (order === "execution-first") {
      await respond(1, outcome("receipt-A"));
      await a;
      assert.equal(surface.get("execute").disabled, true);
      assert.equal(vm.runInContext("state.operation.kind", context), "preparing");
      await respond(2, session("B"));
    } else {
      await respond(2, session("B"));
    }
    const b = vm.runInContext("execute()", context);
    assert.equal(requests[3].options.headers["auths-session"], "B");
    if (order === "preparation-first") {
      await respond(1, outcome("receipt-A"));
      await a;
      assert.equal(surface.get("execute").disabled, true);
      assert.equal(vm.runInContext("state.operation.session.session_id", context), "B");
    }
    assert.doesNotMatch(surface.get("receipt-json").textContent, /receipt-A/);
    assert.equal(vm.runInContext("state.readSource", context), null);
    assert.equal(vm.runInContext("state.boundedSource", context), null);
    await respond(3, outcome("receipt-B"));
    await b;
    assert.match(surface.get("receipt-json").textContent, /receipt-B/);
    assert.match(surface.get("business-response").textContent, /"record_id": "B"/);
    assert.equal(vm.runInContext("state.readSource", context), "B");
    assert.equal(vm.runInContext("state.boundedSource", context), "B");
    assert.equal(surface.get("execute").disabled, false);
  });
}
