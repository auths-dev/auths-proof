const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const state = { scenario: null, session: null, active: "exact", busy: false };
const $ = (selector) => document.querySelector(selector);
const elements = {
  loading: $("#loading"), workbench: $("#workbench-grid"), service: $("#service-state"),
  workspace: $("#workspace"), backend: $("#backend"), lineage: $("#lineage"), serial: $("#serial"),
  changes: $("#changes"), planDigest: $("#plan-digest"), list: $("#variant-list"),
  probe: $("#credential-probe"), verdict: $("#verdict"), detail: $("#verdict-detail"),
  code: $("#decision-code"), stage: $("#decision-stage"), credential: $("#credential-called"),
  tofu: $("#opentofu-called"), required: $("#required-config"), executed: $("#executed-config"),
  match: $("#config-match"), title: $("#execution-title"), copy: $("#execution-copy"),
  execute: $("#execute"), timeline: $("#timeline"), observation: $("#observation"),
  prior: $("#prior-state"), resulting: $("#resulting-state"), committed: $("#committed"),
  converged: $("#converged"), receiptLink: $("#receipt-link"), receiptViewer: $("#receipt-viewer"),
  receiptState: $("#receipt-state"), receiptJson: $("#receipt-json"), release: $("#release"),
};

function api(path) { return `${API}${path}`; }
function short(value, size = 18) {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}
async function request(path, options = {}) {
  const response = await fetch(api(path), { cache: "no-store", ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.error?.message ?? "The native service failed closed.");
    error.code = body.error?.code ?? `http-${response.status}`;
    throw error;
  }
  return body;
}
function selected() { return state.session.variants.find((variant) => variant.id === state.active); }

function renderSession() {
  const target = state.session.target;
  elements.workspace.textContent = target.workspace;
  elements.backend.textContent = target.backend;
  elements.lineage.textContent = short(target.state_lineage, 22);
  elements.lineage.title = target.state_lineage;
  elements.serial.textContent = target.state_serial;
  elements.changes.textContent = target.resource_changes;
  elements.planDigest.textContent = short(target.saved_plan_digest, 30);
  elements.planDigest.title = target.saved_plan_digest;
  elements.release.textContent = `${state.scenario.release} · ${state.scenario.region} · ${state.session.planner_mode}`;
  const suffix = API ? `?api=${encodeURIComponent(API)}` : "";
  elements.receiptLink.href = `/receipts/${state.session.session_id}${suffix}`;
  elements.loading.hidden = true;
  elements.workbench.hidden = false;
  renderDecision();
}

function resetTimeline(kind) {
  elements.timeline.querySelectorAll("li").forEach((row) => {
    row.className = "";
    row.querySelector("b").textContent = "—";
  });
  const first = elements.timeline.querySelector('[data-stage="authorized"]');
  first.className = kind === "authorized" ? "passed" : "stopped";
  first.querySelector("b").textContent = kind === "authorized" ? "ready" : "will stop";
}

function renderDecision() {
  const variant = selected();
  const decision = variant.decision;
  elements.verdict.textContent = decision.class.toUpperCase();
  elements.verdict.dataset.kind = decision.class;
  elements.detail.textContent = decision.detail;
  elements.code.textContent = decision.code;
  elements.stage.textContent = decision.stage;
  elements.credential.textContent = "NO";
  elements.tofu.textContent = "NO";
  const required = variant.required_configuration_digest;
  const executed = variant.executed_configuration_digest;
  elements.required.textContent = short(required, 20);
  elements.required.title = required;
  elements.executed.textContent = short(executed, 20);
  elements.executed.title = executed;
  const matches = required === executed;
  elements.match.textContent = matches ? "exact match" : "mismatch";
  elements.match.classList.toggle("mismatch", !matches);
  const allowed = decision.class === "authorized";
  elements.title.textContent = allowed ? "Apply this saved plan once." : "Prove this plan cannot execute.";
  elements.copy.textContent = allowed
    ? "The native service will verify, claim, resolve the exact artifact, acquire credentials, recheck state, and apply the saved plan."
    : "The native service must stop without acquiring the mutation credential or invoking OpenTofu.";
  elements.execute.textContent = allowed ? "Apply exact saved plan" : "Run the denied experiment";
  elements.execute.disabled = state.busy;
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    const active = button.dataset.variant === state.active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  resetTimeline(decision.class);
  elements.observation.hidden = true;
  elements.receiptLink.hidden = true;
  elements.receiptViewer.hidden = true;
}

function renderExecution(result) {
  elements.verdict.textContent = result.decision.class.toUpperCase();
  elements.verdict.dataset.kind = result.decision.class;
  elements.detail.textContent = result.decision.detail;
  elements.code.textContent = result.decision.code;
  elements.stage.textContent = result.decision.stage;
  elements.credential.textContent = result.credential_called ? "YES" : "NO";
  elements.tofu.textContent = result.opentofu_called ? "YES" : "NO";
  for (const stage of result.stages ?? []) {
    const row = elements.timeline.querySelector(`[data-stage="${stage.name}"]`);
    if (!row) continue;
    row.className = stage.status === "stopped" || stage.status === "replay-blocked" ? "stopped" : "passed";
    row.querySelector("b").textContent = stage.status;
  }
  if (result.resulting_state) {
    elements.prior.textContent = result.resulting_state.prior_state_serial;
    elements.resulting.textContent = result.resulting_state.resulting_state_serial;
    elements.committed.textContent = String(result.resulting_state.state_committed).toUpperCase();
    elements.converged.textContent = String(result.resulting_state.converged).toUpperCase();
    elements.observation.hidden = false;
  }
  elements.receiptLink.hidden = false;
}

async function loadReceipt() {
  try {
    const receipt = await request(`/api/v1/receipts/${state.session.session_id}`);
    elements.receiptJson.textContent = JSON.stringify(receipt, null, 2);
    elements.receiptState.textContent = receipt.result?.decision?.class ?? "recorded";
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
  elements.execute.textContent = "Running native executor…";
  try {
    const response = await request(`/api/v1/sessions/${state.session.session_id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ variant: state.active }),
    });
    renderExecution(response.result);
    await loadReceipt();
    elements.copy.textContent = response.result.opentofu_called
      ? "The exact saved-plan bytes were applied and the protected backend state was read back."
      : "The request stopped before OpenTofu could mutate the configured backend.";
  } catch (error) {
    elements.verdict.textContent = "INDETERMINATE";
    elements.verdict.dataset.kind = "indeterminate";
    elements.detail.textContent = error.message;
    elements.code.textContent = error.code;
    elements.stage.textContent = "native-service";
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
    elements.service.textContent = `${ready.status} · ${ready.planner}`;
    elements.probe.querySelector("strong").textContent = probe.credential_access === "denied"
      ? "DENIED · NO BACKEND OR PROVIDER CREDENTIAL"
      : "BOUNDARY INDETERMINATE";
    elements.probe.classList.toggle("safe", probe.credential_access === "denied");
    renderSession();
  } catch (error) {
    elements.loading.classList.add("error");
    elements.loading.querySelector("strong").textContent = "The native service is unavailable";
    elements.loading.querySelector("p").textContent = `${error.message} Nothing is presented as authorized.`;
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
