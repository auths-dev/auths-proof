const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const state = { scenario: null, session: null, active: "exact", busy: false, exactExecuted: false };

const $ = (selector) => document.querySelector(selector);
const elements = {
  loading: $("#loading-card"), workbench: $("#workbench-grid"), list: $("#variant-list"),
  service: $("#service-state"), verdict: $("#verdict"), detail: $("#verdict-detail"),
  code: $("#decision-code"), stage: $("#decision-stage"), called: $("#kubernetes-called"),
  proposedImage: $("#proposed-image"), required: $("#required-config"), executed: $("#executed-config"),
  configLink: $("#config-link"), execute: $("#execute"), executionTitle: $("#execution-title"),
  executionCopy: $("#execution-copy"), timeline: $("#receipt-timeline"), artifact: $("#rollout-artifact"),
  generation: $("#generation"), observedGeneration: $("#observed-generation"),
  availableReplicas: $("#available-replicas"), auditId: $("#audit-id"),
  deployment: $("#deployment-name"), cluster: $("#cluster-name"), namespace: $("#namespace"),
  replicas: $("#replicas"), mode: $("#cluster-mode"), beforeImage: $("#before-image"),
  afterImage: $("#after-image"), receiptLink: $("#receipt-link"), release: $("#release"),
  receiptViewer: $("#receipt-viewer"), receiptState: $("#receipt-state"),
  receiptJson: $("#receipt-json"),
};

function api(path) { return `${API}${path}`; }
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
function short(value, length = 20) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}
function selected() { return state.session.variants.find((variant) => variant.id === state.active); }

function renderSession() {
  const session = state.session;
  elements.deployment.textContent = session.target.deployment;
  elements.cluster.textContent = short(session.target.cluster, 28);
  elements.cluster.title = session.target.cluster;
  elements.namespace.textContent = session.target.namespace;
  elements.replicas.textContent = `${session.before.replicas} → ${session.after.replicas}`;
  elements.mode.textContent = session.cluster_mode.toUpperCase();
  for (const [element, image] of [[elements.beforeImage, session.before.image], [elements.afterImage, session.after.image]]) {
    element.textContent = short(image, 32); element.title = image;
  }
  const receiptQuery = API ? `?api=${encodeURIComponent(API)}` : "";
  elements.receiptLink.href = `/receipts/${session.session_id}${receiptQuery}`;
  elements.release.textContent = `${state.scenario.release} · ${state.scenario.region}`;
  elements.loading.hidden = true;
  elements.workbench.hidden = false;
  renderDecision();
}

function renderDecision() {
  const variant = selected();
  const decision = variant.decision;
  elements.verdict.textContent = decision.class.toUpperCase();
  elements.verdict.dataset.kind = decision.class;
  elements.detail.textContent = decision.detail;
  elements.code.textContent = decision.code;
  elements.stage.textContent = decision.stage;
  elements.called.textContent = "NOT YET";
  elements.proposedImage.textContent = short(variant.image, 18);
  elements.proposedImage.title = variant.image;
  elements.required.textContent = short(variant.required_configuration);
  elements.required.title = variant.required_configuration ?? "";
  elements.executed.textContent = short(variant.executed_configuration);
  elements.executed.title = variant.executed_configuration ?? "";
  elements.configLink.textContent = variant.configuration_match ? "exact match" : "mismatch";
  elements.configLink.classList.toggle("mismatch", !variant.configuration_match);
  const allowed = decision.class === "authorized";
  elements.executionTitle.textContent = allowed ? "Apply the exact rollout." : "Confirm this patch is blocked.";
  elements.executionCopy.textContent = allowed
    ? "The executor will claim this action, request its restricted Kubernetes token, apply the exact patch, and verify convergence."
    : "The native service should stop at the displayed check without requesting the mutation token or calling Kubernetes.";
  elements.execute.textContent = state.active === "exact" && state.exactExecuted
    ? "Submit the exact rollout again"
    : allowed ? "Apply exact rollout" : "Run this denied patch";
  elements.execute.disabled = state.busy;
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    const active = button.dataset.variant === state.active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  resetTimeline(decision.class);
  elements.artifact.hidden = true;
  elements.receiptLink.hidden = true;
  elements.receiptViewer.hidden = true;
  elements.receiptViewer.open = false;
  elements.receiptState.textContent = "not run";
  elements.receiptJson.textContent = "Run a case to load its receipt.";
}

function resetTimeline(kind) {
  elements.timeline.querySelectorAll("li").forEach((item) => {
    item.classList.remove("proven", "denied");
    item.querySelector("strong").textContent = "—";
  });
  const first = elements.timeline.querySelector('[data-stage="authorized"]');
  first.classList.add(kind === "authorized" ? "proven" : "denied");
  first.querySelector("strong").textContent = kind === "authorized" ? "ready" : "will stop";
}

function renderExecution(result) {
  elements.verdict.textContent = result.decision.class.toUpperCase();
  elements.verdict.dataset.kind = result.decision.class;
  elements.detail.textContent = result.decision.detail;
  elements.code.textContent = result.decision.code;
  elements.stage.textContent = result.decision.stage;
  elements.called.textContent = result.kubernetes_called ? "YES" : "NO";
  for (const stage of result.stages ?? []) {
    const item = elements.timeline.querySelector(`[data-stage="${stage.name}"]`);
    if (!item) continue;
    item.classList.add(stage.status === "stopped" || stage.status === "replay-blocked" ? "denied" : "proven");
    item.querySelector("strong").textContent = stage.status;
  }
  if (result.rollout) {
    elements.generation.textContent = result.rollout.generation;
    elements.observedGeneration.textContent = result.rollout.observed_generation;
    elements.availableReplicas.textContent = result.rollout.available_replicas;
    elements.auditId.textContent = short(result.rollout.api_audit_id, 20);
    elements.auditId.title = result.rollout.api_audit_id;
    elements.artifact.hidden = false;
  }
  elements.receiptLink.hidden = false;
}

async function loadReceipt() {
  try {
    const receipt = await request(`/api/v1/receipts/${state.session.session_id}`);
    elements.receiptJson.textContent = JSON.stringify(receipt, null, 2);
    elements.receiptState.textContent = receipt.result?.decision?.class ?? "recorded";
    elements.receiptViewer.hidden = false;
  } catch (error) {
    elements.receiptJson.textContent = `Receipt unavailable: ${error.message}`;
    elements.receiptState.textContent = "unavailable";
    elements.receiptViewer.hidden = false;
  }
}

async function execute() {
  if (state.busy) return;
  state.busy = true;
  elements.execute.disabled = true;
  elements.execute.textContent = "Running native verifier…";
  try {
    const response = await request(`/api/v1/sessions/${state.session.session_id}/execute`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ variant: state.active }),
    });
    const result = response.result;
    if (state.active === "exact" && result.kubernetes_called) state.exactExecuted = true;
    renderExecution(result);
    await loadReceipt();
    elements.executionCopy.textContent = result.kubernetes_called
      ? "Kubernetes persisted this exact patch and the Deployment converged. Submit it again to see the durable claim block replay."
      : "The request stopped before the protected service requested its mutation token.";
  } catch (error) {
    elements.verdict.textContent = "INDETERMINATE";
    elements.verdict.dataset.kind = "indeterminate";
    elements.detail.textContent = error.message;
    elements.code.textContent = error.code;
    elements.stage.textContent = "native-service";
    elements.executionCopy.textContent = error.message;
  } finally {
    state.busy = false;
    elements.execute.disabled = false;
    const variant = selected();
    elements.execute.textContent = state.active === "exact" && state.exactExecuted
      ? "Submit the exact rollout again"
      : variant.decision.class === "authorized" ? "Apply exact rollout" : "Run this denied patch";
  }
}

function bind() {
  elements.list.querySelectorAll("[data-variant]").forEach((button) => button.addEventListener("click", () => {
    state.active = button.dataset.variant;
    renderDecision();
  }));
  elements.execute.addEventListener("click", execute);
}

async function initialize() {
  bind();
  try {
    state.scenario = await request("/api/v1/scenarios");
    state.session = await request("/api/v1/sessions", { method: "POST" });
    elements.service.textContent = `ready · ${state.scenario.region}`;
    renderSession();
  } catch (error) {
    elements.loading.querySelector("strong").textContent = "Demo unavailable";
    elements.loading.querySelector("p").textContent = `${error.message} (${error.code ?? "startup"})`;
    elements.loading.classList.add("error");
  }
}
initialize();
