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
let preparedWriteTask = null;
let preparedWriteConfirmation = null;
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

async function prepareWriteTask() {
  const result = await api("/api/v1/write/tasks/prepare", {
    purpose: value("write-purpose"),
  });
  preparedWriteTask = result;
  byId("write-account").textContent = `Operator-pinned Google account: ${result.account_label}`;
  byId("write-source").textContent = result.read_resource_label
    ? `Source: ${result.read_resource_label}` : "No source read in this task";
  byId("write-resource").textContent = `Destination: ${result.resource_label}`;
  byId("write-card").textContent = JSON.stringify({
    agent_principal: result.card.agent_principal,
    source_handles: result.card.read_scopes.map(scope => scope.handle),
    destination_handle: result.card.write_scopes[0].handle,
    verb: result.card.write_scopes[0].verb,
    purpose: result.card.purpose,
    account_subject: result.card.connection_subject,
    connection_generation: result.card.connection_generation,
    max_provider_calls: result.card.max_provider_calls,
    max_releases: result.card.max_releases,
    max_release_bytes: result.card.max_release_bytes,
    max_writes: result.card.max_writes,
    write_approval_mode: result.card.write_approval_mode,
    upfront_allowed_arguments: result.card.upfront_allowed_arguments || null,
    expires_at: result.card.expires_at,
    recipe_digest: result.card.write_scopes[0].recipe_digest,
    write_tool: result.write_tool,
    companion_write_tool: result.companion_write_tool,
    pending_child: result.card.pending_child || null,
  }, null, 2);
  byId("write-review").hidden = false;
  message(result.card.pending_child
    ? "Review the Project A folder, exact child proposal, agent and limits before signing both child grants and the task. The two-effect content plan is still required before provider entry."
    : result.card.write_approval_mode === "bounded-upfront"
      ? "Review every complete allowed edit, the account, destination, agent and one-write limit. One listed choice may be submitted later without another confirmation."
    : "Review the account, destination, agent and limits before signing the task and child grant.");
}

async function authorizeWriteTask() {
  if (!preparedWriteTask) throw new Error("Prepare and review a write task first");
  if (Date.now() / 1000 >= preparedWriteTask.expires_at) {
    throw new Error("This write task review expired; prepare a new one");
  }
  const grantSignature = await signEmployee(preparedWriteTask.grant_preimage);
  const readGrantSignature = preparedWriteTask.read_grant_preimage
    ? await signEmployee(preparedWriteTask.read_grant_preimage) : null;
  const companionGrantSignature = preparedWriteTask.companion_grant_preimage
    ? await signEmployee(preparedWriteTask.companion_grant_preimage) : null;
  const taskSignature = await signEmployee(preparedWriteTask.task_preimage);
  const authorization = {
    nonce: preparedWriteTask.nonce,
    grant_signature: grantSignature,
    task_signature: taskSignature,
  };
  if (readGrantSignature) authorization.read_grant_signature = readGrantSignature;
  if (companionGrantSignature) authorization.companion_grant_signature = companionGrantSignature;
  const result = await api("/api/v1/write/tasks/authorize", authorization);
  if (result.task_id !== preparedWriteTask.card.task_id ||
      result.agent_principal !== preparedWriteTask.card.agent_principal) {
    throw new Error("Signed write task differs from the reviewed task");
  }
  download(`auths-write-agent-${result.task_id}.json`,
    JSON.stringify(result.agent_package, null, 2), "application/json");
  download(`auths-task-card-${result.task_id}.json`,
    JSON.stringify(preparedWriteTask.card, null, 2), "application/json");
  if (result.read_agent_package) {
    download(`auths-read-agent-${result.task_id}.json`,
      JSON.stringify(result.read_agent_package, null, 2), "application/json");
  }
  if (result.companion_agent_package) {
    download(`auths-companion-write-agent-${result.task_id}.json`,
      JSON.stringify(result.companion_agent_package, null, 2), "application/json");
  }
  byId("write-status").textContent = JSON.stringify({
    task_id: result.task_id, status: result.status,
    agent_principal: result.agent_principal, expires_at: result.expires_at,
  }, null, 2);
  byId("write-review").hidden = true;
  byId("write-confirm-task-id").value = result.task_id;
  byId("write-submit").hidden = !session.task_write_upfront_available ||
    !session.task_write_execution_available;
  preparedWriteTask = null;
  message(result.companion_agent_package
    ? "Jules signed the create/populate task and both agent grants. Gateway activation and the exact two-effect content plan are still required before provider entry."
    : session.task_write_upfront_available
      ? "Jules approved the displayed bounded choices. The separate agent must sign one complete choice before the gateway can submit it; no later exact confirmation will be requested."
    : result.status === "activated_awaiting_agent_proposal"
      ? "Jules's task is activated. The separate agent can act within its approved scopes; the edit still needs exact confirmation."
      : "Jules's task is signed. Gateway activation and a separate exact edit confirmation are still required.");
}

async function prepareWriteConfirmation() {
  const paired = session.task_write_paired_available;
  const result = await api(paired
    ? "/api/v1/write/effect-plans/prepare"
    : "/api/v1/write/confirmations/prepare", {
    task_id: value("write-confirm-task-id"),
  });
  preparedWriteConfirmation = result;
  byId("write-confirm-details").textContent = JSON.stringify({
    task_id: result.task_id,
    agent_principal: result.agent_principal,
    account_subject: result.account_subject,
    destination_handle: result.destination_handle,
    method: result.method,
    url: result.url,
    content_type: result.content_type,
    exact_request_body: result.body,
    ...(paired ? {effect_plan: result.plan} : {intent: result.intent}),
    expires_at: result.expires_at,
  }, null, 2);
  byId("write-confirm-review").hidden = false;
  message(paired
    ? "Review the destination, complete initial text and both effects before signing once."
    : "Review the complete destination and proposed request before signing.");
}

async function authorizeWriteConfirmation() {
  if (!preparedWriteConfirmation) throw new Error("Review an agent proposal first");
  if (Date.now() / 1000 >= preparedWriteConfirmation.expires_at) {
    throw new Error("The exact edit review expired; review the proposal again");
  }
  const signature = await signEmployee(preparedWriteConfirmation.signing_preimage);
  const paired = session.task_write_paired_available;
  const result = await api(paired
    ? "/api/v1/write/effect-plans/authorize"
    : "/api/v1/write/confirmations/authorize", {
    nonce: preparedWriteConfirmation.nonce, signature,
  });
  if (result.task_id !== preparedWriteConfirmation.task_id) {
    throw new Error("Confirmed task differs from the reviewed task");
  }
  byId("write-confirm-status").textContent = JSON.stringify(result, null, 2);
  byId("write-confirm-review").hidden = true;
  preparedWriteConfirmation = null;
  byId("write-submit").hidden = paired || !session.task_write_execution_available;
  message(paired
    ? "Jules's exact create-and-populate plan is recorded. Obtain the fresh independent baseline before submitting create; no provider write has been sent."
    : session.task_write_execution_available
      ? "Jules's exact edit is confirmed. Submit it through the gateway when ready."
      : "Jules's exact edit is confirmed. The gateway has not submitted a provider write yet.");
}

async function submitApprovedWrite() {
  const result = await api("/api/v1/write/submissions/execute", {
    task_id: value("write-confirm-task-id"),
  });
  byId("write-confirm-status").textContent = JSON.stringify(result, null, 2);
  byId("write-submit").hidden = true;
  message("Gateway submission recorded. Run the independent demo_co write inspection before claiming an observed edit.");
}

async function revokeWriteTask() {
  const taskId = value("write-confirm-task-id");
  if (!taskId) throw new Error("Enter the signed agent task ID first");
  const result = await api("/api/v1/write/tasks/revoke", {task_id: taskId});
  if (result.task_id !== taskId || result.status !== "revoked") {
    throw new Error("Gateway revocation did not match the selected task");
  }
  byId("write-status").textContent = JSON.stringify(result, null, 2);
  byId("write-submit").hidden = true;
  message("This agent task is revoked. New reads and writes are closed; prior deliveries and entered writes remain.");
}

async function loadWriteTaskStatus() {
  const taskId = value("write-confirm-task-id");
  if (!taskId) throw new Error("Enter the signed agent task ID first");
  const status = await api("/api/v1/write/tasks/status", {task_id: taskId});
  if (status.task_id !== taskId || status.schema !== "auths.gateway-agent-task-status/1") {
    throw new Error("Gateway status did not match the selected task");
  }
  byId("write-activity").textContent = JSON.stringify(status, null, 2);
  message(status.revoked ? "This agent task is revoked." : "Gateway task activity is current.");
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

async function loadAgentResult() {
  byId("result-view").hidden = true;
  byId("result-summary").textContent = "";
  byId("result-sources").replaceChildren();
  const file = byId("result-file").files[0];
  if (!file || file.size > 1_000_000) throw new Error("Choose a bounded agent result JSON file");
  const result = JSON.parse(await file.text());
  if (!result || typeof result !== "object" || Array.isArray(result) ||
      typeof result.task_id !== "string" || result.task_id.length > 256 ||
      typeof result.summary !== "string" || result.summary.length > 100_000 ||
      !Array.isArray(result.source_ids) || !result.source_ids.length ||
      result.source_ids.length > 8 ||
      !result.receipt_ids || typeof result.receipt_ids !== "object" ||
      Array.isArray(result.receipt_ids) ||
      Object.keys(result.receipt_ids).length !== result.source_ids.length) {
    throw new Error("Agent result has an invalid shape");
  }
  const task = await api(`/api/v1/tasks/${encodeURIComponent(result.task_id)}`);
  if (task.task.task_id !== result.task_id ||
      (value("task-id") && value("task-id") !== result.task_id)) {
    throw new Error("Agent result belongs to another task");
  }
  const approved = new Set(task.approved_calls.map(call => call.file_id));
  const seen = new Set();
  const sources = [];
  for (const fileId of result.source_ids) {
    if (typeof fileId !== "string" || !approved.has(fileId) || seen.has(fileId) ||
        !Object.hasOwn(result.receipt_ids, fileId) ||
        typeof result.receipt_ids[fileId] !== "string" ||
        result.receipt_ids[fileId].length > 128) {
      throw new Error("Agent result cites an invalid approved source");
    }
    seen.add(fileId);
    const receipt = await api(`/api/v1/receipts/${encodeURIComponent(result.receipt_ids[fileId])}`);
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(fileId));
    const resourceRef = Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
    const payload = receipt.payload;
    if (receipt.verified !== true || payload.task_id !== result.task_id ||
        payload.task_commitment !== task.task_commitment ||
        payload.company_id !== task.task.company_id ||
        payload.employee_principal !== task.task.employee_principal ||
        payload.agent_principal !== task.task.agent_principal ||
        payload.connection_id !== task.task.connection_id ||
        payload.connection_generation !== task.task.connection_generation ||
        payload.receipt_id !== result.receipt_ids[fileId] ||
        payload.resource_ref !== resourceRef ||
        payload.provider_stage !== "content_fetched" ||
        payload.release_stage !== "committed") {
      throw new Error("Cited receipt does not prove this task's released source");
    }
    sources.push({ fileId, receiptId: payload.receipt_id,
      native: payload.native_code, provider: payload.provider_stage,
      release: payload.release_stage, delivery: payload.transport_delivery });
  }
  const citations = Array.from(result.summary.matchAll(/\[([^\[\]\n]{1,256})\]/g), match => match[1]);
  if (!citations.length || citations.some(fileId => !seen.has(fileId))) {
    throw new Error("Agent summary cites a source without a verified read");
  }
  byId("task-id").value = result.task_id;
  byId("task-status-json").textContent = JSON.stringify(task, null, 2);
  byId("result-summary").textContent = result.summary;
  const list = byId("result-sources");
  list.replaceChildren();
  for (const source of sources) {
    const item = document.createElement("li");
    item.textContent = `${source.fileId}: receipt ${source.receiptId}; native ${source.native}; Google ${source.provider}; release ${source.release}; delivery ${source.delivery}`;
    list.append(item);
  }
  byId("result-view").hidden = false;
  message(`Agent result loaded; ${sources.length} cited broker receipts verified. Transport delivery remains separately observed.`);
}

function bind(id, action) {
  byId(id).addEventListener("click", async () => {
    byId(id).disabled = true;
    let succeeded = false;
    try { await action(); succeeded = true; }
    catch (error) { message(error.message || String(error)); }
    finally {
      if (!(id === "agent-complete" && !preparedAgent) &&
          !(id === "activate-complete" && !preparedActivation) &&
          (id !== "write-submit" || !succeeded)) byId(id).disabled = false;
    }
  });
}

async function start() {
  session = await api("/api/v1/session");
  byId("status").textContent = `Google: ${session.google_status}; company: ${session.company_id || "not configured"}`;
  byId("employee").textContent = session.subject ? `Signed in as Google subject ${session.subject}` : "No Google account signed in.";
  byId("drive").textContent = session.drive_connected ? "Drive connected under this employee." : "Drive is not connected.";
  byId("disconnect").hidden = !session.drive_connected;
  if (session.google_status === "jules_write_only") {
    byId("page-title").textContent = session.task_write_upfront_available
      ? "Jules delegates one bounded Project A edit"
      : "Jules delegates Project A read and write";
    byId("page-description").textContent = session.task_write_upfront_available
      ? "Jules signs one short agent task with the complete permitted edits shown in advance. The gateway accepts only one listed choice."
      : "Jules signs a bounded agent task, then confirms the exact proposed change before the gateway uses her existing Google grant.";
    byId("status").textContent = `Jules-only Project A delegation; company: ${session.company_id}`;
    byId("drive").textContent = "The existing Jules Drive grant is held by the operator.";
    for (const id of ["connect-drive", "general-task", "general-run", "general-evidence"])
      byId(id).hidden = true;
    message("Sign in as Jules, enroll this browser key, then register the separate agent.");
  } else if (session.google_status !== "ready") {
    message("Google is not configured. Live task controls remain unavailable.");
  }
  bind("disconnect", async () => { await api("/api/v1/google/disconnect", {}); location.reload(); });
  bind("enroll", enrollEmployee);
  bind("agent-prepare", prepareAgent);
  bind("agent-complete", completeAgent);
  bind("agent-preimage", async () => download("agent-registration.preimage", bytes(preparedAgent.signing_preimage), "application/octet-stream"));
  bind("task-prepare", prepareTask);
  bind("task-authorize", authorizeTask);
  byId("write-task").hidden = !session.task_write_available;
  if (session.task_write_available) {
    bind("write-prepare", prepareWriteTask);
    bind("write-authorize", authorizeWriteTask);
    if (session.task_write_upfront_available) {
      byId("write-task-description").textContent = "The account, registered agent, destination and complete allowed edits come from the operator's pinned installation. Review both values before signing. This mode permits one listed edit without a later confirmation.";
    }
  }
  byId("write-confirmation").hidden = !session.task_write_confirmation_available;
  if (session.task_write_confirmation_available) {
    if (session.task_write_upfront_available) {
      byId("write-confirmation-heading").textContent = "Submit the agent's bounded choice";
      byId("write-confirmation-description").textContent = "After the separate agent signs one complete listed choice and the operator stages its proof, submit it through the gateway. The gateway checks the signed task, choice and one-write limit before provider entry.";
      byId("write-confirm-prepare").hidden = true;
      byId("write-confirm-authorize").hidden = true;
      byId("write-submit").textContent = "Submit the agent's approved choice";
    } else if (session.task_write_paired_available) {
      byId("write-task-description").textContent = "The account, registered agent, Project A folder and limits come from the operator's pinned installation. After the agent drafts, Jules reviews the exact new file and its content in one separate effect-plan signature.";
      byId("write-confirmation-heading").textContent = "Approve the agent's new Project A file";
      byId("write-confirmation-description").textContent = "After the separate agent signs the create action and stages its draft privately, review the exact folder, title, complete content, create request and populate recipe. This signature is recorded before either provider write.";
      byId("write-confirm-prepare").textContent = "Review agent create and draft";
      byId("write-confirm-authorize").textContent = "Sign this exact two-effect plan";
    }
    if (!session.task_write_upfront_available) {
      bind("write-confirm-prepare", prepareWriteConfirmation);
      bind("write-confirm-authorize", authorizeWriteConfirmation);
    }
    if (session.task_write_execution_available) {
      bind("write-submit", submitApprovedWrite);
      byId("write-status-refresh").hidden = false;
      bind("write-status-refresh", loadWriteTaskStatus);
      byId("write-revoke").hidden = false;
      bind("write-revoke", revokeWriteTask);
    }
  }
  bind("activate-prepare", prepareActivation);
  bind("activate-complete", completeActivation);
  bind("activate-preimage", async () => download("agent-activation.preimage", bytes(preparedActivation.signing_preimage), "application/octet-stream"));
  bind("package", packageTask);
  bind("task-status", loadTask);
  bind("revoke", revokeTask);
  bind("receipt-load", loadReceipt);
  bind("result-load", loadAgentResult);
}

start().catch(error => message(error.message || String(error)));
