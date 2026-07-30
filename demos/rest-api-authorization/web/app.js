const state = {
  experiment: "exact-create",
  transport: "https",
  session: null,
  busy: false,
  readSource: null,
  boundedSource: null,
};

const $ = (id) => document.getElementById(id);
const experiments = document.querySelectorAll("[data-experiment]");
const transports = document.querySelectorAll("[data-transport]");

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.code || `HTTP ${response.status}`);
  return body;
}

async function prepare() {
  state.busy = true;
  $("execute").disabled = true;
  setVerdict("LOADING", "loading", "Issuing a short-lived proof and presenter-bound request.");
  resetResult();
  try {
    const input = { experiment: state.experiment };
    if (state.experiment === "exact-read") input.source_session_id = state.readSource;
    if (state.experiment === "bounded-create" && state.boundedSource) {
      input.source_session_id = state.boundedSource;
    }
    state.session = await jsonFetch("/api/v1/sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    renderSession();
    $("service-state").textContent = "ready";
    $("service-indicator").classList.add("ready");
    setVerdict("READY", "ready", "The proof and exact request are ready. Call the protected API to see the native verdict.");
    $("execute").disabled = false;
  } catch (error) {
    setVerdict("UNAVAILABLE", "denied", error.message);
    $("service-state").textContent = "unavailable";
  } finally {
    state.busy = false;
  }
}

function renderSession() {
  const session = state.session;
  const required = session.required_configuration.maximum_response_bytes;
  const executed = session.executed_configuration.maximum_response_bytes;
  $("required-config").textContent = `${required} bytes`;
  $("executed-config").textContent = `${executed} bytes`;
  $("config-link").textContent = required === executed ? "exact match" : "mismatch";
  $("config-link").classList.toggle("mismatch", required !== executed);
  $("curl-command").textContent = session.curl_command;
  $("iroh-command").textContent = session.iroh_command;
  $("operation-title").textContent = session.operation_id === "records.create.v1" ? "POST one record" : "GET one record";
  $("response-title").textContent = session.operation_id === "records.create.v1"
    ? "Created customer"
    : "Returned customer";
  $("response-route").textContent = session.operation_id === "records.create.v1"
    ? "POST /v1/records"
    : `GET /v1/records/${session.action.action.record_id}`;
  $("execute").textContent = state.transport === "https" ? "Send through HTTPS" : "Send through native Iroh";
  $("next-action").hidden = state.experiment !== "bounded-create";
  $("next-action").disabled = !state.boundedSource;
  $("delivery").textContent = state.transport.toUpperCase();
  $("transport-copy").textContent = state.transport === "https"
    ? "The browser sends the protected request directly to the HTTPS adapter."
    : "The native service sends the same envelope through the repository Iroh exchange adapter.";
  $("grant-copy").textContent = session.policy.maximum_creates === 1
    ? "Create one exact record under an isolated visitor namespace."
    : `Create up to ${session.policy.maximum_creates} records and ${session.policy.maximum_created_bytes} bytes under one isolated namespace.`;
}

async function execute() {
  if (!state.session || state.busy) return;
  state.busy = true;
  $("execute").disabled = true;
  setVerdict("CHECKING", "loading", "The native service is verifying the exact proof, presentation, action, policy, and configuration.");
  try {
    const outcome = state.transport === "https" ? await executeHttps() : await executeIroh();
    renderOutcome(outcome);
  } catch (error) {
    setVerdict("ERROR", "denied", error.message);
  } finally {
    state.busy = false;
    $("execute").disabled = false;
  }
}

async function executeHttps() {
  const session = state.session;
  const action = session.action;
  const headers = {
    "content-type": "application/json",
    "auths-session": session.session_id,
    "auths-proof": session.proof_hex,
    "auths-presentation": session.presentation_hex,
  };
  if (session.operation_id === "records.create.v1") {
    return jsonFetch("/v1/records", {
      method: "POST",
      headers,
      body: JSON.stringify({ record_id: action.action.record_id, customer: action.action.customer }),
    });
  }
  return jsonFetch(`/v1/records/${encodeURIComponent(action.action.record_id)}`, { headers });
}

async function executeIroh() {
  return jsonFetch(`/api/v1/sessions/${state.session.session_id}/execute-iroh`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  });
}

function renderOutcome(outcome) {
  const receipt = outcome.receipt;
  const decision = receipt.decision.decision;
  const authorized = decision.class === "authorized";
  const replay = decision.code === "replay";
  setVerdict(
    authorized ? "AUTHORIZED" : replay ? "REPLAY" : decision.class.toUpperCase(),
    authorized ? "authorized" : "denied",
    authorized
      ? "The exact action was authorized and the protected effect was observed."
      : stableDetail(decision.code),
  );
  $("decision-code").textContent = decision.code;
  $("decision-stage").textContent = decision.stage;
  $("delivery").textContent = receipt.delivery.adapter.toUpperCase();
  $("proof-status").textContent = receipt.decision.auths_decision.toUpperCase();
  $("storage-status").textContent = receipt.decision.protected_storage_accessed ? "YES" : "NO";
  $("capacity-status").textContent = outcome.replay
    ? "UNCHANGED"
    : receipt.effect
      ? "COMMITTED"
      : "UNCHANGED";
  $("observation-status").textContent = receipt.observation ? "RECORDED" : "NONE";
  renderBusinessResponse(outcome, authorized);
  $("receipt-json").textContent = JSON.stringify(receipt, null, 2);
  const link = $("receipt-link");
  link.href = `/receipts/${receipt.decision.receipt_id}`;
  link.classList.remove("disabled");
  link.removeAttribute("aria-disabled");
  if (authorized && state.session.operation_id === "records.create.v1") {
    state.readSource = state.session.session_id;
    const readButton = document.querySelector('[data-experiment="exact-read"]');
    readButton.disabled = false;
    readButton.title = "";
    if (state.experiment === "bounded-create") {
      state.boundedSource = state.session.session_id;
      $("next-action").disabled = false;
    }
  }
}

function renderBusinessResponse(outcome, authorized) {
  const card = $("api-response");
  if (!authorized) {
    card.dataset.state = "empty";
    $("response-detail").textContent = "No business data was returned because authorization did not complete.";
    $("business-response").textContent = JSON.stringify({ response: null }, null, 2);
    return;
  }
  const action = state.session.action.action;
  const response = outcome.response || {
    record_id: action.record_id,
    customer: action.customer,
    version: 1,
  };
  card.dataset.state = "returned";
  $("response-detail").textContent = state.session.operation_id === "records.read.v1"
    ? "The authorized fields were read from the protected store and returned to the caller."
    : "The fictional customer was written to the protected store.";
  $("business-response").textContent = JSON.stringify({ response }, null, 2);
}

function stableDetail(code) {
  const messages = {
    "proof-invalid": "The proof did not authorize the canonical action. Protected storage was not accessed.",
    "verifier-configuration-mismatch": "The required and executed verifier configurations differ. Execution stopped before protected storage.",
    "executor-audience-mismatch": "The action targets a different semantic executor.",
    "value-limit-exceeded": "The customer payload exceeds the bounded policy.",
    "replay": "This exact action already completed. No second effect was created.",
  };
  return messages[code] || `The request stopped with stable code “${code}”.`;
}

function setVerdict(text, kind, detail) {
  $("verdict").textContent = text;
  $("verdict").dataset.kind = kind;
  $("verdict-detail").textContent = detail;
}

function resetResult() {
  ["decision-code", "decision-stage", "proof-status", "storage-status", "capacity-status", "observation-status"].forEach((id) => $(id).textContent = "—");
  $("receipt-json").textContent = "Run a request to inspect its complete receipt.";
  $("api-response").dataset.state = "waiting";
  $("response-route").textContent = state.experiment === "exact-read"
    ? "GET /v1/records/:id"
    : "POST /v1/records";
  $("response-detail").textContent = "Run the request to see the fictional business data returned by the protected API.";
  $("business-response").textContent = JSON.stringify({ response: null }, null, 2);
  $("receipt-link").classList.add("disabled");
  $("receipt-link").setAttribute("aria-disabled", "true");
}

experiments.forEach((button) => button.addEventListener("click", () => {
  if (button.disabled) return;
  experiments.forEach((item) => item.classList.toggle("active", item === button));
  state.experiment = button.dataset.experiment;
  if (state.experiment !== "bounded-create") state.boundedSource = null;
  prepare();
}));

transports.forEach((button) => button.addEventListener("click", () => {
  transports.forEach((item) => item.classList.toggle("active", item === button));
  state.transport = button.dataset.transport;
  if (state.session) renderSession();
}));

$("execute").addEventListener("click", execute);
$("next-action").addEventListener("click", prepare);
prepare();
