"use strict";

const byId = (id) => document.getElementById(id);
const message = (text) => { byId("message").textContent = text; };
const value = (id) => byId(id).value.trim();
const bytes = (base64) => Uint8Array.from(atob(base64.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
const encoded = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
let session = null;
let preparedAgent = null;
let preparedTask = null;
let preparedActivation = null;
let activationTaskId = null;

async function api(path, body = null) {
  const options = { credentials: "same-origin" };
  if (body !== null) {
    options.method = "POST";
    options.headers = { "Content-Type": "application/json", "X-CSRF-Token": session.csrf };
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || `HTTP ${response.status}`);
  return result;
}

function download(name, content, type) {
  const link = document.createElement("a");
  const url = URL.createObjectURL(new Blob([content], { type }));
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("auths-ap070-employee-key", 1);
    request.onupgradeneeded = () => request.result.createObjectStore("keys", { keyPath: "subject" });
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function employeeKey(create) {
  if (!session.subject) throw new Error("Sign in with Google before using an employee key");
  if (!crypto.subtle) throw new Error("This browser has no WebCrypto support");
  const database = await openKeyDatabase();
  const existing = await new Promise((resolve, reject) => {
    const transaction = database.transaction("keys", "readonly");
    const request = transaction.objectStore("keys").get(session.subject);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  if (existing || !create) {
    database.close();
    if (!existing) throw new Error("No employee key is stored in this browser");
    return existing;
  }
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
  const publicKey = encoded(await crypto.subtle.exportKey("raw", pair.publicKey));
  const record = { subject: session.subject, privateKey: pair.privateKey, publicKey };
  await new Promise((resolve, reject) => {
    const transaction = database.transaction("keys", "readwrite");
    transaction.objectStore("keys").put(record);
    transaction.oncomplete = resolve;
    transaction.onerror = () => reject(transaction.error);
  });
  database.close();
  return record;
}

async function signEmployee(preimage) {
  const record = await employeeKey(false);
  return encoded(await crypto.subtle.sign("Ed25519", record.privateKey, bytes(preimage)));
}

function agentPacket() {
  const raw = value("agent-packet");
  if (raw.startsWith("{")) {
    const parsed = JSON.parse(raw);
    return parsed.identity_packet;
  }
  return raw;
}

function showActivationCalls(taskId, calls) {
  const select = byId("activation-call");
  const previous = activationTaskId === taskId ? select.value : "0";
  select.replaceChildren();
  calls.forEach((call, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = `${index + 1}. ${call.file_id} · ${call.output} · max ${call.max_bytes} bytes`;
    select.append(option);
  });
  if (calls.length) select.value = previous;
  activationTaskId = taskId;
}

async function enrollEmployee() {
  const key = await employeeKey(true);
  const packet = await api("/api/v1/identity/packet", { public_key: key.publicKey });
  const challenge = await api("/api/v1/employees/enroll/prepare", { identity_packet: packet.identity_packet });
  const signature = await signEmployee(challenge.signing_preimage);
  const result = await api("/api/v1/employees/enroll", {
    identity_packet: packet.identity_packet, nonce: challenge.nonce, signature,
  });
  byId("employee-principal").textContent = `Employee principal: ${result.principal}`;
  message("Employee Auths key enrolled for this Google account.");
}

async function prepareAgent() {
  const identity_packet = agentPacket();
  const result = await api("/api/v1/agents/register/prepare", { identity_packet });
  preparedAgent = { ...result, identity_packet };
  byId("agent-principal").textContent = `Pending agent principal: ${result.agent_principal}`;
  byId("agent-preimage").disabled = false;
  byId("agent-complete").disabled = false;
  message("Registration challenge prepared. The separate agent must sign its exact preimage.");
}

async function completeAgent() {
  if (!preparedAgent) throw new Error("Prepare registration first");
  const result = await api("/api/v1/agents/register", {
    identity_packet: preparedAgent.identity_packet, nonce: preparedAgent.nonce,
    signature: value("agent-signature"),
  });
  byId("agent-principal").textContent = `Registered agent: ${result.agent_principal}`;
  byId("task-agent").value = result.agent_principal;
  preparedAgent = null;
  byId("agent-preimage").disabled = true;
  byId("agent-complete").disabled = true;
  message("Distinct agent key registered.");
}

async function prepareTask() {
  const logical_resource_ids = value("task-resources").split(",").map(x => x.trim()).filter(Boolean);
  const result = await api("/api/v1/tasks/prepare", {
    agent_principal: value("task-agent"), logical_resource_ids,
    purpose: value("task-purpose"),
  });
  preparedTask = result;
  byId("task-id").value = result.task.task_id;
  showActivationCalls(result.task.task_id, result.approved_calls);
  byId("review-json").textContent = JSON.stringify({
    employee_principal: result.task.employee_principal,
    agent_principal: result.task.agent_principal,
    purpose: result.task.purpose,
    approved_calls: result.approved_calls,
    not_before: result.task.not_before,
    expires_at: result.task.expires_at,
    max_calls: result.task.max_calls,
    max_total_bytes: result.task.max_total_bytes,
    task_commitment: result.task_commitment,
  }, null, 2);
  byId("review").hidden = false;
  message("Review the exact provider file IDs and limits before signing.");
}

async function authorizeTask() {
  if (!preparedTask) throw new Error("Prepare and review a task first");
  const task_id = preparedTask.task.task_id;
  const result = await api("/api/v1/tasks/authorize/prepare", { task_id });
  if (result.task_commitment !== preparedTask.task_commitment) throw new Error("Task changed after review");
  const signature = await signEmployee(result.signing_preimage);
  const completed = await api("/api/v1/tasks/authorize", { task_id, signature });
  preparedTask = null;
  byId("review").hidden = true;
  message(`Employee grant signed: ${completed.status}. Agent activation is still required.`);
}

async function prepareActivation() {
  const taskId = value("task-id");
  if (!taskId) throw new Error("Enter a task ID first");
  if (activationTaskId !== taskId || !byId("activation-call").options.length) {
    const snapshot = await api(`/api/v1/tasks/${encodeURIComponent(taskId)}`);
    showActivationCalls(taskId, snapshot.approved_calls);
  }
  const call_index = Number(byId("activation-call").value);
  if (!Number.isInteger(call_index) || call_index < 0 ||
      call_index >= byId("activation-call").options.length) {
    throw new Error("Select an approved activation call");
  }
  const result = await api("/api/v1/tasks/activate/prepare", { task_id: taskId, call_index });
  preparedActivation = result;
  byId("activate-preimage").disabled = false;
  byId("activate-complete").disabled = false;
  message("Activation challenge prepared. Have the registered agent sign the downloaded preimage.");
}

async function completeActivation() {
  if (!preparedActivation) throw new Error("Prepare activation first");
  const result = await api("/api/v1/tasks/activate", {
    task_id: value("task-id"), challenge: preparedActivation.challenge,
    signature: value("activate-signature"),
  });
  preparedActivation = null;
  byId("activate-preimage").disabled = true;
  byId("activate-complete").disabled = true;
  message(`Task ${result.task_id} is active. Download its package for the isolated agent.`);
}

async function packageTask() {
  const taskId = value("task-id");
  const result = await api(`/api/v1/tasks/${encodeURIComponent(taskId)}/package`);
  download(`auths-task-${taskId}.json`, JSON.stringify(result, null, 2), "application/json");
  message("Public agent package downloaded. It contains no Google token.");
}

async function loadTask() {
  const result = await api(`/api/v1/tasks/${encodeURIComponent(value("task-id"))}`);
  showActivationCalls(result.task.task_id, result.approved_calls);
  byId("task-status-json").textContent = JSON.stringify(result, null, 2);
  message(`Task status: ${result.status}; ${result.usage.remaining_calls} calls remain.`);
}

async function revokeTask() {
  const taskId = value("task-id");
  const result = await api(`/api/v1/tasks/${encodeURIComponent(taskId)}/revoke`, {});
  message(`Task ${result.task_id} revoked. Future read admissions are closed.`);
}

async function loadReceipt() {
  const result = await api(`/api/v1/receipts/${encodeURIComponent(value("receipt-id"))}`);
  byId("receipt-json").textContent = JSON.stringify(result, null, 2);
  message("Receipt signature verified against the broker receipt key.");
}

function bind(id, action) {
  byId(id).addEventListener("click", async () => {
    byId(id).disabled = true;
    try { await action(); }
    catch (error) { message(error.message || String(error)); }
    finally {
      if (!(id === "agent-complete" && !preparedAgent) &&
          !(id === "activate-complete" && !preparedActivation)) byId(id).disabled = false;
    }
  });
}

async function start() {
  session = await api("/api/v1/session");
  byId("status").textContent = `Google: ${session.google_status}; company: ${session.company_id || "not configured"}`;
  byId("employee").textContent = session.subject ? `Signed in as Google subject ${session.subject}` : "No Google account signed in.";
  byId("drive").textContent = session.drive_connected ? "Drive connected under this employee." : "Drive is not connected.";
  byId("disconnect").hidden = !session.drive_connected;
  if (session.google_status !== "ready") message("Google is not configured. Live task controls remain unavailable.");
  bind("disconnect", async () => { await api("/api/v1/google/disconnect", {}); location.reload(); });
  bind("enroll", enrollEmployee);
  bind("agent-prepare", prepareAgent);
  bind("agent-complete", completeAgent);
  bind("agent-preimage", async () => download("agent-registration.preimage", bytes(preparedAgent.signing_preimage), "application/octet-stream"));
  bind("task-prepare", prepareTask);
  bind("task-authorize", authorizeTask);
  bind("activate-prepare", prepareActivation);
  bind("activate-complete", completeActivation);
  bind("activate-preimage", async () => download("agent-activation.preimage", bytes(preparedActivation.signing_preimage), "application/octet-stream"));
  bind("package", packageTask);
  bind("task-status", loadTask);
  bind("revoke", revokeTask);
  bind("receipt-load", loadReceipt);
}

start().catch(error => message(error.message || String(error)));
