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
let preparedRecoveredChild = null;
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
  if (session.employee_principal) {
    if (packet.principal !== session.employee_principal) {
      throw new Error("This browser key differs from the employee key already enrolled for this Google account");
    }
    byId("employee-principal").textContent = `Employee principal: ${packet.principal}`;
    message("Using this browser’s already enrolled employee key.");
    return;
  }
  const challenge = await api("/api/v1/employees/enroll/prepare", { identity_packet: packet.identity_packet });
  const signature = await signEmployee(challenge.signing_preimage);
  const result = await api("/api/v1/employees/enroll", {
    identity_packet: packet.identity_packet, nonce: challenge.nonce, signature,
  });
  byId("employee-principal").textContent = `Employee principal: ${result.principal}`;
  session.employee_principal = result.principal;
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
  const writeScope = result.card.write_scopes[0] || null;
  const choices = result.card.upfront_allowed_arguments || [];
  byId("write-upfront-review").hidden = choices.length === 0;
  const choiceList = byId("write-upfront-list");
  choiceList.replaceChildren();
  for (const [index, choice] of choices.entries()) {
    const item = document.createElement("li");
    item.textContent = `Option ${index + 1}: ` + Object.entries(choice)
      .map(([name, selected]) => `${name}: ${JSON.stringify(selected)}`).join(" · ");
    choiceList.append(item);
  }
  byId("write-card").textContent = JSON.stringify({
    task_id: result.card.task_id,
    agent_principal: result.card.agent_principal,
    source_handles: result.card.read_scopes.map(scope => scope.handle),
    destination_handle: writeScope?.handle || null,
    verb: writeScope?.verb || "read",
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
    recipe_digest: writeScope?.recipe_digest || result.card.read_scopes[0]?.recipe_digest,
    write_tool: result.write_tool,
    companion_write_tool: result.companion_write_tool,
    pending_child: result.card.pending_child || null,
  }, null, 2);
  byId("write-status-label").textContent = "Previously signed task (not this review)";
  byId("write-confirm-task-id").value = "";
  byId("write-activity-summary").textContent = "No gateway task activity loaded for this review.";
  byId("write-activity-timeline").replaceChildren();
  byId("write-review").hidden = false;
  message(!writeScope
    ? session.task_read_only_kind === "project_b_exclusion"
      ? "Review Jules's read-only Google account, permitted Project A source, separate agent and one-read budget. Project B is excluded even though this Google account can read it. This task grants no write."
      : "Review Jules's account, finance source, agent and one-read budget. This task grants no write; Google may still deny the read."
    : result.card.pending_child
    ? "Review the Project A folder, exact child proposal, agent and limits before signing both child grants and the task. The two-effect content plan is still required before provider entry."
    : result.card.write_approval_mode === "bounded-upfront"
      ? "Review each complete marker replacement, the account, destination, agent and one-write limit. Text outside the marker stays in the Doc; one listed choice may run without another confirmation."
    : "Review the account, destination, agent and limits before signing the task and child grant.");
}

async function authorizeWriteTask() {
  if (!preparedWriteTask) throw new Error("Prepare and review a write task first");
  if (Date.now() / 1000 >= preparedWriteTask.expires_at) {
    throw new Error("This write task review expired; prepare a new one");
  }
  const grantSignature = preparedWriteTask.grant_preimage
    ? await signEmployee(preparedWriteTask.grant_preimage) : null;
  const readGrantSignature = preparedWriteTask.read_grant_preimage
    ? await signEmployee(preparedWriteTask.read_grant_preimage) : null;
  const companionGrantSignature = preparedWriteTask.companion_grant_preimage
    ? await signEmployee(preparedWriteTask.companion_grant_preimage) : null;
  const taskSignature = await signEmployee(preparedWriteTask.task_preimage);
  const authorization = {
    nonce: preparedWriteTask.nonce,
    task_signature: taskSignature,
  };
  if (grantSignature) authorization.grant_signature = grantSignature;
  if (readGrantSignature) authorization.read_grant_signature = readGrantSignature;
  if (companionGrantSignature) authorization.companion_grant_signature = companionGrantSignature;
  const result = await api("/api/v1/write/tasks/authorize", authorization);
  if (result.task_id !== preparedWriteTask.card.task_id ||
      result.agent_principal !== preparedWriteTask.card.agent_principal) {
    throw new Error("Signed write task differs from the reviewed task");
  }
  if (result.agent_package) {
    download(`auths-write-agent-${result.task_id}.json`,
      JSON.stringify(result.agent_package, null, 2), "application/json");
  }
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
  byId("write-status-label").textContent = "Newly signed task";
  byId("write-review").hidden = true;
  byId("write-confirm-task-id").value = result.task_id;
  byId("write-submit").hidden = result.status !== "activated_awaiting_agent_proposal" ||
    !session.task_write_upfront_available || !session.task_write_execution_available;
  preparedWriteTask = null;
  if (result.status === "signed_activation_unconfirmed") {
    message(`Jules signed task ${result.task_id}, but gateway activation is unconfirmed. Check its task activity before the agent acts; do not sign the task again.`);
  } else if (result.companion_agent_package) {
    message(result.status === "activated_awaiting_agent_proposal"
      ? "Jules's create/populate task is active. The exact two-effect content plan is still required before provider entry."
      : "Jules signed the create/populate task and both agent grants. Gateway activation and the exact two-effect content plan are still required before provider entry.");
  } else if (!result.agent_package) {
    message(session.task_read_only_kind === "project_b_exclusion"
      ? "Jules's read-only task is active. The separate agent may read only the pinned Project A source; Project B remains excluded despite provider access. No write is permitted."
      : "Jules's read-only task is active. The separate agent may try the pinned finance read once; Google can deny access, and no write is permitted.");
  } else if (session.task_write_upfront_available) {
    message("Jules approved the displayed bounded choices. The separate agent must sign one complete choice before the gateway can submit it; no later exact confirmation will be requested.");
  } else if (result.status === "activated_awaiting_agent_proposal") {
    message("Jules's task is activated. The separate agent can act within its approved scopes; the edit still needs exact confirmation.");
  } else {
    message("Jules's task is signed. Gateway activation and a separate exact edit confirmation are still required.");
  }
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

async function prepareRecoveredChild() {
  const result = await api("/api/v1/write/recovered-child/prepare", {
    task_id: value("write-confirm-task-id"),
  });
  if (result.review.recovery.task_id !== result.task_id ||
      result.review.attempt_stage !== "unknown" ||
      result.review.authority_before_confirmation !== "none") {
    throw new Error("Recovered child review does not match the unknown attempt");
  }
  preparedRecoveredChild = result;
  byId("recovered-child-details").textContent = JSON.stringify(result.review, null, 2);
  byId("recovered-child-review").hidden = false;
  message("Review the original account and create, one candidate, parent, title, marker, content commitment and both independent evidence pins before signing.");
}

async function authorizeRecoveredChild() {
  if (!preparedRecoveredChild) throw new Error("Review one recovered child first");
  if (Date.now() / 1000 >= preparedRecoveredChild.expires_at) {
    throw new Error("Recovered child review expired; inspect the attempt and evidence again");
  }
  const signature = await signEmployee(preparedRecoveredChild.signing_preimage);
  const result = await api("/api/v1/write/recovered-child/authorize", {
    nonce: preparedRecoveredChild.nonce, signature,
  });
  if (result.task_id !== preparedRecoveredChild.task_id ||
      result.status !== "confirmed_pending_child_metadata_check") {
    throw new Error("Confirmed recovered child differs from the reviewed task");
  }
  byId("recovered-child-status").textContent = JSON.stringify(result, null, 2);
  byId("recovered-child-review").hidden = true;
  byId("recovered-child-execute").hidden = false;
  preparedRecoveredChild = null;
  message("Jules signed this exact candidate. The gateway has not bound it; the next step performs one fresh metadata GET and rechecks the original unknown attempt.");
}

async function executeRecoveredChild() {
  const result = await api("/api/v1/write/recovered-child/execute", {
    task_id: value("write-confirm-task-id"),
  });
  byId("recovered-child-status").textContent = JSON.stringify(result, null, 2);
  byId("recovered-child-execute").hidden = true;
  message("The gateway bound the independently checked child. A fresh population preflight is still required before one agent-signed populate action.");
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
  const activity = await api("/api/v1/write/tasks/activity", {task_id: taskId});
  const status = activity.task;
  if (activity.schema !== "auths.gateway-agent-task-activity/1" ||
      status?.task_id !== taskId ||
      status.schema !== "auths.gateway-agent-task-status/1" ||
      !Array.isArray(activity.write_attempts) ||
      activity.write_attempts.length !== status.write_operations.length) {
    throw new Error("Gateway activity did not match the selected task");
  }
  const summary = byId("write-activity-summary");
  summary.textContent = `Provider calls ${status.provider_calls}/${status.max_provider_calls}; ` +
    `releases ${status.releases}/${status.max_releases}; ` +
    `released bytes ${status.released_bytes}/${status.max_release_bytes}; ` +
    `writes ${status.writes}/${status.max_writes}. ` +
    `Expires ${new Date(status.expires_at * 1000).toISOString()}.`;
  const timeline = byId("write-activity-timeline");
  timeline.replaceChildren();
  const addEvent = description => {
    const item = document.createElement("li");
    item.textContent = description;
    timeline.append(item);
  };
  addEvent("Human-signed task activated in the gateway.");
  const readStage = {
    "provider-call-reserved": "provider call reserved; no content delivery recorded",
    "provider-unavailable": "provider unavailable; no content delivered",
    "release-refused": "release refused; no content delivered",
    "delivery-unknown": "delivery may have started; agent acknowledgement is missing",
    "not-delivered": "no private content was sent; the release budget remains charged",
    "agent-acknowledged": "agent acknowledged the delivered bytes",
  };
  for (const read of status.reads) {
    const bytes = read.released_bytes === null ? "" : ` (${read.released_bytes} bytes charged)`;
    addEvent(`Read ${read.operation_id}: ${readStage[read.stage]}${bytes}.`);
  }
  const writeStage = {
    "claimed-no-attempt": "task write claimed; no gateway attempt recorded yet",
    "not-entered": "no provider entry recorded",
    "attempting": "provider entry may be in progress",
    "unknown": "provider entry or effect is uncertain; no automatic retry",
    "response-recorded": "provider response recorded; intended effect needs independent verification",
    "observed": "gateway readback recorded; independent verification is separate",
    "observed-by-provider": "gateway echo readback linked; independent verification is separate",
  };
  for (const write of activity.write_attempts) {
    if (!status.write_operations.includes(write.operation_id) ||
        !Object.hasOwn(writeStage, write.stage)) {
      throw new Error("Gateway write activity did not match the selected task");
    }
    const response = write.response_status === null ? "" : ` (HTTP ${write.response_status})`;
    const comparison = write.stage === "observed" && write.observation_match === false
      ? " Readback did not match." : "";
    addEvent(`Write ${write.operation_id}: ${writeStage[write.stage]}${response}.${comparison}`);
  }
  if (activity.provider_effect !== undefined) {
    const effect = activity.provider_effect;
    if (effect?.schema !== "auths.ap071-populate-task-provider-join/1" ||
        effect.status !== "joined" || effect.task_id !== taskId ||
        effect.provider_state !== "exact_populated" ||
        effect.retry_authorized !== false ||
        !["unknown", "response-recorded", "observed",
          "observed-by-provider"].includes(effect.population_outcome) ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(effect.child_id)) {
      throw new Error("Independent provider effect did not match the task");
    }
    addEvent(`Independent Google inspection found the exact approved content in the bound child. Gateway population outcome: ${effect.population_outcome}. This observation does not by itself attribute the edit to the agent.`);
    const item = document.createElement("li");
    const link = document.createElement("a");
    link.href = `https://docs.google.com/document/d/${encodeURIComponent(effect.child_id)}/edit`;
    link.textContent = "Open the independently checked Doc";
    link.rel = "noopener noreferrer";
    link.target = "_blank";
    item.append(link);
    timeline.append(item);
  }
  if (status.revoked) addEvent("Task revoked; new actions are closed.");
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
  if (session.employee_principal) {
    byId("employee-principal").textContent = `Employee principal: ${session.employee_principal}`;
  }
  byId("drive").textContent = session.drive_connected ? "Drive connected under this employee." : "Drive is not connected.";
  byId("disconnect").hidden = !session.drive_connected;
  if (session.google_status === "jules_write_only") {
    byId("page-title").textContent = session.task_read_only_available
      ? session.task_read_only_kind === "project_b_exclusion"
        ? "Jules delegates one Project A read"
        : "Jules delegates one finance read attempt"
      : session.task_write_upfront_available
      ? "Jules delegates one bounded Project A edit"
      : "Jules delegates Project A read and write";
    byId("page-description").textContent = session.task_read_only_available
      ? session.task_read_only_kind === "project_b_exclusion"
        ? "Jules signs a one-read agent task for Project A. Auths excludes Project B even though the same Google connection can read it."
        : "Jules signs a one-read agent task. The gateway admits it, then Google decides whether Jules may read the finance file."
      : session.task_write_upfront_available
      ? "Jules signs one short agent task with the complete permitted edits shown in advance. The gateway accepts only one listed choice."
      : "Jules signs a bounded agent task, then confirms the exact proposed change before the gateway uses her existing Google grant.";
    byId("status").textContent = `Jules-only delegation; company: ${session.company_id}`;
    byId("drive").textContent = "The existing Jules Drive grant is held by the operator.";
    for (const id of ["connect-drive", "general-task", "general-run", "general-evidence"])
      byId(id).hidden = true;
    message(session.employee_principal
      ? "Jules’s employee key is enrolled; review the pinned task or register a distinct agent."
      : "Sign in as Jules, enroll this browser key, then register the separate agent.");
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
    if (session.task_read_only_available) {
      const projectBExcluded = session.task_read_only_kind === "project_b_exclusion";
      byId("write-heading").textContent = projectBExcluded
        ? "Delegate one Project A read" : "Delegate one finance read attempt";
      byId("write-purpose").value = projectBExcluded
        ? "Test that the agent cannot read task-excluded Project B"
        : "Test Jules's provider-denied finance document access";
      byId("write-prepare").textContent = "Review read-only task";
      byId("write-status").textContent = "No read-only task signed.";
      byId("write-task-description").textContent = projectBExcluded
        ? "The permitted Project A source, Jules's read-only Google account, separate agent and one-read budget are fixed by the operator's installation. Project B is excluded. This grants no write."
        : "The pinned finance file, Jules account, separate agent and one-read budget are fixed by the operator's installation. This grants no write. Google may deny the read after Auths admits it.";
    } else if (session.task_write_upfront_available) {
      byId("write-task-description").textContent = "The account, registered agent, destination and complete allowed marker replacements come from the operator's pinned installation. Surrounding Doc text remains. Review both choices before signing; one listed edit may run without a later confirmation.";
    }
  }
  byId("write-confirmation").hidden = !session.task_write_confirmation_available;
  byId("recovered-child-confirmation").hidden = !session.task_write_paired_available;
  if (session.task_write_paired_available) {
    bind("recovered-child-prepare", prepareRecoveredChild);
    bind("recovered-child-authorize", authorizeRecoveredChild);
    bind("recovered-child-execute", executeRecoveredChild);
  }
  if (session.task_write_confirmation_available) {
    if (session.task_read_only_available) {
      byId("write-confirmation-heading").textContent = "Read attempt activity";
      byId("write-confirmation-description").textContent = "The gateway reports whether the agent's admitted read reached Google and whether any bytes were released.";
      byId("write-confirm-task-label").textContent = "Task ID";
      byId("write-confirm-prepare").hidden = true;
      byId("write-confirm-authorize").hidden = true;
      byId("write-confirm-status").hidden = true;
    } else if (session.task_write_upfront_available) {
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
    }
    if (session.task_write_execution_available || session.task_read_only_available) {
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
