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
let sessionOverride = null;
let writePrepareResponse = null;
let writeStatusResponse = null;
let writeAuthorizeResponse = null;
async function fetch(url, options = {}) {
  let result;
  if (url === "/api/v1/session") {
    result = sessionOverride || { csrf: "synthetic-csrf", subject: null,
      google_status: "not_configured", company_id: null, drive_connected: false };
  } else if (url === "/api/v1/write/tasks/prepare" && writePrepareResponse) {
    result = writePrepareResponse;
  } else if (url === "/api/v1/write/tasks/authorize" && writeAuthorizeResponse) {
    posts.push(JSON.parse(options.body));
    result = writeAuthorizeResponse;
  } else if (url === "/api/v1/write/tasks/status" && writeStatusResponse) {
    result = writeStatusResponse;
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
  const agentResult = JSON.stringify({ task_id: "task-1", summary: "Synthetic summary [file-A]",
    source_ids: ["file-A"], receipt_ids: { "file-A": "receipt-A" } });
  byId("result-file").files = [{ size: agentResult.length, text: async () => agentResult }];
  await vm.runInContext("loadAgentResult()", context);
  assert.equal(byId("result-view").hidden, false);
  assert.equal(byId("result-summary").textContent, "Synthetic summary [file-A]");
  assert.equal(byId("result-sources").options.length, 1);
  receiptResourceRef = "wrong-resource";
  await assert.rejects(vm.runInContext("loadAgentResult()", context),
    /Cited receipt does not prove/);
  assert.equal(byId("result-view").hidden, true);
  receiptResourceRef = nodeCrypto.createHash("sha256").update("file-A").digest("hex");
  const wrongCitation = agentResult.replace("[file-A]", "[file-B]");
  byId("result-file").files = [{ size: wrongCitation.length,
    text: async () => wrongCitation }];
  await assert.rejects(vm.runInContext("loadAgentResult()", context),
    /source without a verified read/);
  assert.equal(byId("result-view").hidden, true);
  elements.clear();
  sessionOverride = { csrf: "synthetic-csrf", subject: "jules-subject",
    google_status: "jules_write_only", company_id: "atlas-studio",
    drive_connected: false, task_write_available: true,
    task_write_confirmation_available: true, task_write_execution_available: true,
    task_write_upfront_available: true, task_write_paired_available: false };
  writePrepareResponse = { account_label: "jules@auths.dev",
    resource_label: "Project A working Doc", read_resource_label: null,
    write_tool: "google-docs-delegation-demo/replace_project_a_marker_v2",
    companion_write_tool: null,
    card: { agent_principal: "agent-A", read_scopes: [],
      write_scopes: [{ handle: "working-doc", verb: "edit", recipe_digest: "digest" }],
      purpose: "One listed update", connection_subject: "jules-subject",
      connection_generation: 1, max_provider_calls: 0, max_releases: 0,
      max_release_bytes: 0, max_writes: 1, write_approval_mode: "bounded-upfront",
      upfront_allowed_arguments: [
        { document_id: "working-doc", replacement: "Approved" },
        { document_id: "working-doc", replacement: "Pending" },
      ], expires_at: 123456, task_id: "task-upfront" },
  };
  const upfrontContext = vm.createContext({
    document: { getElementById: byId, createElement: () => ({}) },
    fetch, console, setTimeout, crypto: nodeCrypto.webcrypto,
    TextEncoder, Uint8Array,
  });
  vm.runInContext(source, upfrontContext);
  await new Promise(setImmediate);
  assert.equal(byId("page-title").textContent, "Jules delegates one bounded Project A edit");
  assert.equal(byId("write-confirm-prepare").hidden, true);
  await vm.runInContext("prepareWriteTask()", upfrontContext);
  assert.match(byId("write-card").textContent, /"task_id": "task-upfront"/);
  assert.equal(byId("write-status-label").textContent,
    "Previously signed task (not this review)");
  assert.equal(byId("write-confirm-task-id").value, "");
  assert.equal(byId("write-upfront-review").hidden, false);
  assert.equal(byId("write-upfront-list").options.length, 2);
  assert.match(byId("write-upfront-list").options[0].textContent, /Approved/);
  assert.match(byId("write-card").textContent, /"replacement": "Approved"/);
  assert.match(byId("write-card").textContent, /"replacement": "Pending"/);
  writeStatusResponse = { schema: "auths.gateway-agent-task-status/1",
    task_id: "task-upfront", expires_at: 1792960000, revoked: false,
    provider_calls: 1, max_provider_calls: 1, releases: 1, max_releases: 1,
    released_bytes: 5, max_release_bytes: 64, writes: 1, max_writes: 1,
    reads: [{ operation_id: "read-1", stage: "delivery-unknown", released_bytes: 5 }],
    write_operations: ["write-1"] };
  byId("write-confirm-task-id").value = "task-upfront";
  await vm.runInContext("loadWriteTaskStatus()", upfrontContext);
  assert.match(byId("write-activity-summary").textContent, /writes 1\/1/);
  assert.equal(byId("write-activity-timeline").options.length, 3);
  assert.match(byId("write-activity-timeline").options[1].textContent,
    /acknowledgement is missing/);
  assert.match(byId("write-activity-timeline").options[2].textContent,
    /effect require separate evidence/);
  writeAuthorizeResponse = {
    status: "signed_activation_unconfirmed", task_id: "task-upfront",
    agent_principal: "agent-A", expires_at: 9999999999,
    agent_package: {}, read_agent_package: null,
    companion_agent_package: null,
  };
  vm.runInContext(`
    preparedWriteTask = {
      nonce: "nonce", grant_preimage: "AA==", task_preimage: "AA==",
      expires_at: 9999999999,
      card: { task_id: "task-upfront", agent_principal: "agent-A" },
    };
    signEmployee = async () => "signature";
    download = () => {};
  `, upfrontContext);
  await vm.runInContext("authorizeWriteTask()", upfrontContext);
  assert.equal(byId("write-confirm-task-id").value, "task-upfront");
  assert.equal(byId("write-submit").hidden, true);
  assert.match(byId("message").textContent, /do not sign the task again/);
  elements.clear();
  sessionOverride = { csrf: "synthetic-csrf", subject: "jules-subject",
    google_status: "jules_write_only", company_id: "atlas-studio",
    drive_connected: false, task_write_available: true,
    task_write_confirmation_available: true, task_write_execution_available: false,
    task_write_upfront_available: false, task_write_paired_available: false,
    task_read_only_available: true };
  writePrepareResponse = { account_label: "jules@auths.dev",
    resource_label: "No write destination (read-only task)",
    read_resource_label: "Finance budget document; Google access unverified",
    write_tool: null, companion_write_tool: null,
    card: { agent_principal: "agent-A",
      read_scopes: [{ handle: "finance-doc", recipe_digest: "read-digest" }],
      write_scopes: [], purpose: "Try finance access",
      connection_subject: "jules-subject", connection_generation: 1,
      max_provider_calls: 1, max_releases: 1, max_release_bytes: 16384,
      max_writes: 0, write_approval_mode: "exact", expires_at: 9999999999,
      task_id: "task-finance" },
  };
  writeAuthorizeResponse = { status: "activated_awaiting_agent_proposal",
    task_id: "task-finance", agent_principal: "agent-A",
    expires_at: 9999999999, agent_package: null,
    read_agent_package: {}, companion_agent_package: null };
  const readContext = vm.createContext({
    document: { getElementById: byId, createElement: () => ({}) },
    fetch, console, setTimeout, crypto: nodeCrypto.webcrypto,
    TextEncoder, Uint8Array,
  });
  vm.runInContext(source, readContext);
  await new Promise(setImmediate);
  assert.equal(byId("page-title").textContent, "Jules delegates one finance read attempt");
  assert.equal(byId("write-confirm-prepare").hidden, true);
  assert.equal(byId("write-status-refresh").hidden, false);
  assert.equal(byId("write-revoke").hidden, false);
  await vm.runInContext("prepareWriteTask()", readContext);
  assert.match(byId("write-card").textContent, /"max_writes": 0/);
  assert.match(byId("write-card").textContent, /finance-doc/);
  vm.runInContext(`
    preparedWriteTask = {
      nonce: "read-nonce", grant_preimage: null,
      read_grant_preimage: "AA==", task_preimage: "AA==",
      expires_at: 9999999999,
      card: { task_id: "task-finance", agent_principal: "agent-A" },
    };
    signEmployee = async () => "signature";
    download = () => {};
  `, readContext);
  await vm.runInContext("authorizeWriteTask()", readContext);
  assert.equal(posts.at(-1).grant_signature, undefined);
  assert.equal(posts.at(-1).read_grant_signature, "signature");
  assert.match(byId("message").textContent, /read-only task is active/);
  console.log("browser activation and bounded choice review passed");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
