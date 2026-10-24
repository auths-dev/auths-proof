"use strict";

const assert = require("node:assert/strict");
const nodeCrypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const elements = new Map();
function byId(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      value: "", textContent: "", disabled: false, hidden: false,
      options: [],
      addEventListener() {},
      replaceChildren() { this.options = []; this.value = ""; },
      append(option) {
        this.options.push(option);
        if (this.options.length === 1) this.value = option.value;
      },
    });
  }
  return elements.get(id);
}

const posts = [];
let receiptResourceRef = nodeCrypto.createHash("sha256").update("file-A").digest("hex");
async function fetch(url, options = {}) {
  let result;
  if (url === "/api/v1/session") {
    result = { csrf: "synthetic-csrf", subject: null,
      google_status: "not_configured", company_id: null, drive_connected: false };
  } else if (url === "/api/v1/tasks/task-1") {
    result = { task: { task_id: "task-1", company_id: "atlas-studio",
      employee_principal: "employee-A", agent_principal: "agent-A",
      connection_id: "connection-A", connection_generation: 1 },
      task_commitment: "task-digest", approved_calls: [
      { file_id: "file-A", output: "text", max_bytes: 1024 },
      { file_id: "file-B", output: "text", max_bytes: 1024 },
    ] };
  } else if (url === "/api/v1/receipts/receipt-A") {
    result = { verified: true, payload: {
      task_id: "task-1", task_commitment: "task-digest", receipt_id: "receipt-A",
      company_id: "atlas-studio", employee_principal: "employee-A",
      agent_principal: "agent-A", connection_id: "connection-A",
      connection_generation: 1, resource_ref: receiptResourceRef,
      native_code: "authorized", provider_stage: "content_fetched",
      release_stage: "committed", transport_delivery: "unknown",
    } };
  } else if (url === "/api/v1/tasks/activate/prepare") {
    posts.push(JSON.parse(options.body));
    result = { challenge: "synthetic-challenge", signing_preimage: "AA==" };
  } else {
    throw new Error(`unexpected browser request: ${url}`);
  }
  return { ok: true, json: async () => result };
}

async function main() {
  const context = vm.createContext({
    document: { getElementById: byId, createElement: () => ({}) },
    fetch, console, setTimeout, crypto: nodeCrypto.webcrypto,
    TextEncoder, Uint8Array,
  });
  const source = fs.readFileSync(path.join(__dirname, "../src/employee_read_demo/web/workbench.js"), "utf8");
  vm.runInContext(source, context);
  await new Promise(setImmediate);
  byId("task-id").value = "task-1";
  await vm.runInContext("prepareActivation()", context);
  assert.equal(posts[0].task_id, "task-1");
  assert.equal(posts[0].call_index, 0);
  assert.equal(byId("activation-call").options.length, 2);
  byId("activation-call").value = "1";
  await vm.runInContext("prepareActivation()", context);
  assert.equal(posts[1].call_index, 1);
  const agentResult = JSON.stringify({ task_id: "task-1", summary: "Synthetic summary",
    source_ids: ["file-A"], receipt_ids: { "file-A": "receipt-A" } });
  byId("result-file").files = [{ size: agentResult.length, text: async () => agentResult }];
  await vm.runInContext("loadAgentResult()", context);
  assert.equal(byId("result-view").hidden, false);
  assert.equal(byId("result-summary").textContent, "Synthetic summary");
  assert.equal(byId("result-sources").options.length, 1);
  receiptResourceRef = "wrong-resource";
  await assert.rejects(vm.runInContext("loadAgentResult()", context),
    /Cited receipt does not prove/);
  assert.equal(byId("result-view").hidden, true);
  console.log("browser activation selects an exact approved call");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
