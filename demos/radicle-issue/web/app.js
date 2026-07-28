const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");

const state = {
  scenario: null,
  session: null,
  active: "exact",
  busy: false,
  exactExecuted: false,
};

const elements = {
  list: document.querySelector("#variant-list"),
  verdict: document.querySelector("#verdict"),
  detail: document.querySelector("#verdict-detail"),
  code: document.querySelector("#decision-code"),
  stage: document.querySelector("#decision-stage"),
  signer: document.querySelector("#signer-reached"),
  required: document.querySelector("#required-config"),
  executed: document.querySelector("#executed-config"),
  configLink: document.querySelector("#config-link"),
  service: document.querySelector("#service-state"),
  live: document.querySelector(".live-state"),
  execute: document.querySelector("#execute"),
  executionCopy: document.querySelector("#execution-copy"),
  entered: document.querySelector("#entered"),
  executions: document.querySelector("#executions"),
  receipts: document.querySelector("#receipt-count"),
  issue: document.querySelector("#issue-short"),
  release: document.querySelector("#release"),
  timeline: document.querySelector("#receipt-timeline"),
  artifact: document.querySelector("#publication-artifact"),
  patch: document.querySelector("#patch-id"),
  publisher: document.querySelector("#publisher-did"),
  observer: document.querySelector("#observer-id"),
};

function api(path) {
  return `${API}${path}`;
}

async function request(path, options = {}) {
  const response = await fetch(api(path), { ...options, cache: "no-store" });
  const value = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(value.error?.message ?? "The native service failed closed.");
    error.code = value.error?.code ?? `http-${response.status}`;
    throw error;
  }
  return value;
}

function selected() {
  return state.scenario.variants.find((variant) => variant.id === state.active);
}

function short(value, length = 15) {
  if (!value) return "—";
  return `${value.slice(0, length)}…`;
}

function renderDecision() {
  if (!state.scenario) return;
  const variant = selected();
  const decision = variant.decision;
  elements.verdict.textContent = decision.class.toUpperCase();
  elements.verdict.dataset.kind = decision.class;
  elements.detail.textContent = decision.detail;
  elements.code.textContent = decision.code;
  elements.stage.textContent = decision.stage;
  elements.signer.textContent = decision.class === "authorized" ? "YES" : "NO";
  elements.required.textContent = short(variant.required_configuration);
  elements.required.title = variant.required_configuration;
  elements.executed.textContent = short(variant.executed_configuration);
  elements.executed.title = variant.executed_configuration;
  elements.configLink.textContent = variant.configuration_match ? "exact match" : "mismatch";
  elements.configLink.classList.toggle("mismatch", !variant.configuration_match);
  elements.execute.disabled = state.busy || !state.session;
  elements.execute.textContent =
    state.active === "exact" && state.exactExecuted
      ? "Replay the exact workflow"
      : decision.class === "authorized"
        ? "Execute the authorized patch"
        : "Submit denied case to native Rust";
  elements.executionCopy.textContent =
    decision.class === "authorized"
      ? "The Auths kernel authorized the human-to-agent delegation. Native execution still needs a one-time claim."
      : "This case stops at containment. Submit it to confirm the signer and executor remain unreachable.";
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    const active = button.dataset.variant === state.active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  resetRuntime();
  renderDecisionReceipt(decision.class);
}

function resetRuntime() {
  elements.entered.textContent = "—";
  elements.executions.textContent = "—";
  elements.receipts.textContent = "—";
  elements.artifact.hidden = true;
}

function renderDecisionReceipt(kind) {
  elements.timeline.querySelectorAll("li").forEach((item) => {
    item.classList.remove("proven", "denied");
    item.querySelector("strong").textContent = "—";
  });
  const authorized = elements.timeline.querySelector('[data-stage="authorized"]');
  authorized.classList.add(kind === "authorized" ? "proven" : "denied");
  authorized.querySelector("strong").textContent =
    kind === "authorized" ? "proven" : "stopped";
}

function renderExecution(result) {
  if (result.decision) {
    elements.verdict.textContent = result.decision.class.toUpperCase();
    elements.verdict.dataset.kind = result.decision.class;
    elements.code.textContent = result.decision.code;
    elements.stage.textContent = result.decision.stage;
    elements.signer.textContent = result.entered_executor ? "YES" : "NO";
    if (result.decision.detail) elements.detail.textContent = result.decision.detail;
  }
  elements.entered.textContent = result.entered_executor ? "YES" : "NO";
  elements.executions.textContent = String(result.executions);
  elements.receipts.textContent = String(result.receipt_count ?? result.receipts);
  if (result.publication) {
    elements.patch.textContent = short(result.publication.patch_id, 18);
    elements.patch.title = result.publication.patch_id;
    elements.publisher.textContent = short(result.publication.signer_did, 22);
    elements.publisher.title = result.publication.signer_did;
    elements.observer.textContent = short(result.publication.observer_node_id, 18);
    elements.observer.title = result.publication.observer_node_id ?? "";
    elements.artifact.hidden = false;
  }
  for (const stage of result.stages ?? []) {
    const item = elements.timeline.querySelector(`[data-stage="${stage.name}"]`);
    if (!item) continue;
    item.classList.add("proven");
    item.querySelector("strong").textContent = stage.status;
  }
}

async function execute() {
  if (state.busy || !state.session) return;
  state.busy = true;
  elements.execute.disabled = true;
  elements.execute.textContent = "Running native Rust…";
  try {
    const result = await request(
      `/api/v1/sessions/${state.session.session_id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ variant: state.active }),
      },
    );
    if (state.active === "exact") state.exactExecuted = true;
    renderExecution(result);
    elements.executionCopy.textContent = result.entered_executor
      ? "The sealed command crossed the executor boundary exactly once. Try replaying it."
      : "Native Rust confirmed the signer and executor were never reached.";
  } catch (error) {
    elements.entered.textContent = error.code === "execution-lease-consumed" ? "BLOCKED" : "ERROR";
    elements.executions.textContent = state.exactExecuted ? "1" : "0";
    elements.executionCopy.textContent =
      error.code === "execution-lease-consumed"
        ? "Replay blocked: the durable execution lease was already consumed."
        : error.message;
  } finally {
    state.busy = false;
    elements.execute.disabled = false;
    elements.execute.textContent =
      state.active === "exact" && state.exactExecuted
        ? "Replay the exact workflow"
        : "Run selected case in native Rust";
  }
}

async function initialize() {
  bind();
  try {
    const [scenario, session] = await Promise.all([
      request("/api/v1/scenario"),
      request("/api/v1/sessions", { method: "POST" }),
    ]);
    state.scenario = scenario;
    state.session = session;
    elements.service.textContent = `ready · ${scenario.region}`;
    elements.live.classList.add("ready");
    elements.issue.textContent = short(scenario.issue_id, 10);
    elements.issue.title = scenario.issue_id;
    elements.release.textContent = `${scenario.release} · ${scenario.region}`;
    renderDecision();
  } catch (error) {
    elements.service.textContent = "unavailable";
    elements.verdict.textContent = "INDETERMINATE";
    elements.verdict.dataset.kind = "denied";
    elements.detail.textContent = error.message;
    elements.code.textContent = error.code ?? "service-unavailable";
    elements.stage.textContent = "startup";
    elements.execute.disabled = true;
  }
}

function bind() {
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    button.addEventListener("click", () => {
      state.active = button.dataset.variant;
      renderDecision();
    });
  });
  elements.execute.addEventListener("click", execute);
}

initialize();
