const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const state = { scenario: null, session: null, active: "exact", busy: false };
const $ = (selector) => document.querySelector(selector);
const elements = {
  loading: $("#loading"), workbench: $("#workbench-grid"), service: $("#service-state"),
  list: $("#variant-list"), rows: $("#row-cards"), probe: $("#credential-probe"),
  verdict: $("#verdict"), detail: $("#verdict-detail"), code: $("#decision-code"),
  stage: $("#decision-stage"), credential: $("#credential-called"),
  transaction: $("#transaction-called"), required: $("#required-config"),
  executed: $("#executed-config"), match: $("#config-match"), title: $("#execution-title"),
  copy: $("#execution-copy"), execute: $("#execute"), timeline: $("#timeline"),
  receiptLink: $("#receipt-link"), receiptViewer: $("#receipt-viewer"),
  receiptState: $("#receipt-state"), receiptJson: $("#receipt-json"), release: $("#release"),
};

function api(path) { return `${API}${path}`; }
function short(value, size = 22) {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}
async function request(path, options = {}) {
  const response = await fetch(api(path), { cache: "no-store", ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.code ?? `http-${response.status}`);
    error.code = body.code ?? `http-${response.status}`;
    throw error;
  }
  return body;
}
function selected() {
  return state.session.variants.find((variant) => variant.id === state.active);
}
function typedText(value) {
  if (!value) return "—";
  if (typeof value.value === "object" && value.value !== null) {
    return value.value.value ?? value.value.unscaled ?? JSON.stringify(value.value);
  }
  return String(value.value ?? "null");
}
function renderRows(rows, after = false) {
  elements.rows.innerHTML = rows.map((row, index) => {
    const key = typedText(row.primary_key[0].value);
    const status = typedText(row.before_values[0].value);
    return `<article class="${after ? "changed" : ""}">
      <span>ROW ${String(index + 1).padStart(2, "0")}</span>
      <code>${key.slice(-12)}</code>
      <strong>${status}</strong>
      <small>version ${row.row_version}</small>
    </article>`;
  }).join("");
}
function resetTimeline(kind) {
  elements.timeline.querySelectorAll("li").forEach((row) => {
    row.className = "";
    row.querySelector("b").textContent = "—";
  });
  const verify = elements.timeline.querySelector('[data-stage="verify"]');
  verify.className = kind === "authorized" ? "passed" : "stopped";
  verify.querySelector("b").textContent = kind === "authorized" ? "ready" : "will stop";
}
function renderDecision() {
  const variant = selected();
  const decision = variant.predicted_decision;
  elements.verdict.textContent = decision.class.toUpperCase();
  elements.verdict.dataset.kind = decision.class;
  elements.detail.textContent = variant.description;
  elements.code.textContent = decision.code;
  elements.stage.textContent = decision.stage;
  elements.credential.textContent = "NO";
  elements.transaction.textContent = "NO";
  elements.required.textContent = short(variant.required_configuration_digest);
  elements.required.title = variant.required_configuration_digest;
  elements.executed.textContent = short(variant.executed_configuration_digest);
  elements.executed.title = variant.executed_configuration_digest;
  const same = variant.required_configuration_digest === variant.executed_configuration_digest;
  elements.match.textContent = same ? "exact match" : "mismatch";
  elements.match.classList.toggle("mismatch", !same);
  const authorized = decision.class === "authorized";
  elements.title.textContent = authorized ? "Commit this transition once." : "Prove this transition cannot execute.";
  elements.copy.textContent = authorized
    ? "The native path will claim, acquire the protected credential, recheck exact rows, and atomically commit the update with its ledger."
    : "The native path must stop before claim, credential acquisition, or a database transaction.";
  elements.execute.textContent = authorized ? "Execute exact transition" : "Run denied experiment";
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    const active = button.dataset.variant === state.active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  renderRows(state.session.rows_before);
  resetTimeline(decision.class);
  elements.receiptLink.hidden = true;
  elements.receiptViewer.hidden = true;
}
function renderResult(result) {
  const stateName = result.state;
  const decisionKind = ["committed", "reconciled"].includes(stateName)
    ? "authorized"
    : stateName === "denied" ? "denied" : stateName;
  elements.verdict.textContent = stateName.toUpperCase();
  elements.verdict.dataset.kind = decisionKind;
  elements.detail.textContent = result.database_effect;
  elements.code.textContent = result.stable_code;
  elements.stage.textContent = result.stage;
  elements.credential.textContent = result.credential_acquired ? "YES" : "NO";
  elements.transaction.textContent = result.transaction_started ? "YES" : "NO";
  renderRows(result.rows_after ?? state.session.rows_before, ["committed", "reconciled", "replay"].includes(stateName));
  const completed = stateName === "committed" || stateName === "reconciled";
  const replay = stateName === "replay";
  elements.execute.textContent = completed
    ? "Attempt replay · must be blocked"
    : replay
      ? "Replay blocked · run again"
      : "Run experiment again";
  const order = ["verify", "claim", "credential", "transaction", "lock", "commit", "observe"];
  elements.timeline.querySelectorAll("li").forEach((row) => {
    const stage = row.dataset.stage;
    const passed = completed || replay || (stage === "verify" && stateName === "denied");
    row.className = passed ? "passed" : "stopped";
    row.querySelector("b").textContent = completed
      ? "complete"
      : replay ? (stage === "claim" ? "replay blocked" : "prior run")
        : stage === "verify" ? "stopped" : "not called";
  });
  elements.receiptLink.hidden = false;
}
async function loadReceipt() {
  try {
    const receipt = await request(`/api/v1/receipts/${state.session.session_id}`);
    elements.receiptJson.textContent = JSON.stringify(receipt, null, 2);
    elements.receiptState.textContent = receipt.last_result?.state ?? "recorded";
  } catch (error) {
    elements.receiptJson.textContent = `Receipt unavailable: ${error.message}`;
    elements.receiptState.textContent = "unavailable";
  }
  elements.receiptViewer.hidden = false;
}
async function execute() {
  if (state.busy) return;
  state.busy = true;
  elements.execute.disabled = true;
  elements.execute.textContent = "Running native transaction…";
  try {
    const result = await request(`/api/v1/sessions/${state.session.session_id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ variant: state.active }),
    });
    renderResult(result);
    await loadReceipt();
  } catch (error) {
    elements.verdict.textContent = "INDETERMINATE";
    elements.verdict.dataset.kind = "indeterminate";
    elements.detail.textContent = "The native service failed closed.";
    elements.code.textContent = error.code;
    elements.stage.textContent = "native-service";
    elements.execute.textContent = "Retry fail-closed request";
  } finally {
    state.busy = false;
    elements.execute.disabled = false;
  }
}
async function load() {
  try {
    const [ready, scenario, probe] = await Promise.all([
      request("/readyz"),
      request("/api/v1/scenarios"),
      request("/api/v1/credential-probe"),
    ]);
    state.scenario = scenario;
    state.session = await request("/api/v1/sessions", { method: "POST" });
    elements.service.textContent = `${ready.status} · ${ready.database}`;
    elements.probe.querySelector("strong").textContent = probe.credential_access === "denied"
      ? "DENIED · NO DATABASE CREDENTIAL"
      : "BOUNDARY INDETERMINATE";
    elements.probe.classList.toggle("safe", probe.credential_access === "denied");
    elements.release.textContent = `${scenario.release} · ${scenario.region} · ${scenario.database}`;
    const suffix = API ? `?api=${encodeURIComponent(API)}` : "";
    elements.receiptLink.href = `/receipts/${state.session.session_id}${suffix}`;
    elements.loading.hidden = true;
    elements.workbench.hidden = false;
    renderDecision();
  } catch (error) {
    elements.loading.classList.add("error");
    elements.loading.querySelector("strong").textContent = "The native service is unavailable";
    elements.loading.querySelector("p").textContent = `${error.message}. Nothing is shown as authorized.`;
  }
}

elements.list.addEventListener("click", (event) => {
  const button = event.target.closest("[data-variant]");
  if (!button || state.busy || !state.session) return;
  state.active = button.dataset.variant;
  renderDecision();
});
elements.execute.addEventListener("click", execute);
load();
