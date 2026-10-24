"use strict";

const assert = require("node:assert/strict");
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
async function fetch(url, options = {}) {
  let result;
  if (url === "/api/v1/session") {
    result = { csrf: "synthetic-csrf", subject: null,
      google_status: "not_configured", company_id: null, drive_connected: false };
  } else if (url === "/api/v1/tasks/task-1") {
    result = { task: { task_id: "task-1" }, approved_calls: [
      { file_id: "file-A", output: "text", max_bytes: 1024 },
      { file_id: "file-B", output: "text", max_bytes: 1024 },
    ] };
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
    fetch, console, setTimeout,
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
  console.log("browser activation selects an exact approved call");
}

main().catch(error => { console.error(error); process.exitCode = 1; });
