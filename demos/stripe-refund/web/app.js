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
  loading: document.querySelector("#loading-card"),
  workbench: document.querySelector("#workbench-grid"),
  list: document.querySelector("#variant-list"),
  service: document.querySelector("#service-state"),
  verdict: document.querySelector("#verdict"),
  detail: document.querySelector("#verdict-detail"),
  code: document.querySelector("#decision-code"),
  stage: document.querySelector("#decision-stage"),
  contacted: document.querySelector("#stripe-contacted"),
  refundAmount: document.querySelector("#refund-amount"),
  required: document.querySelector("#required-config"),
  executed: document.querySelector("#executed-config"),
  configLink: document.querySelector("#config-link"),
  execute: document.querySelector("#execute"),
  executionTitle: document.querySelector("#execution-title"),
  executionCopy: document.querySelector("#execution-copy"),
  timeline: document.querySelector("#receipt-timeline"),
  artifact: document.querySelector("#refund-artifact"),
  refundId: document.querySelector("#refund-id"),
  refundStatus: document.querySelector("#refund-status"),
  requestId: document.querySelector("#request-id"),
  executedAmount: document.querySelector("#executed-amount"),
  paymentAmount: document.querySelector("#payment-amount"),
  paymentId: document.querySelector("#payment-id"),
  alreadyRefunded: document.querySelector("#already-refunded"),
  refundable: document.querySelector("#refundable"),
  receiptLink: document.querySelector("#receipt-link"),
  release: document.querySelector("#release"),
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

function money(amount, currency = "usd") {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency.toUpperCase(),
  }).format(amount / 100);
}

function short(value, length = 17) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function selected() {
  return state.session.variants.find((variant) => variant.id === state.active);
}

function renderSession() {
  const payment = state.session.payment;
  elements.paymentAmount.textContent = money(payment.amount_minor, payment.currency);
  elements.paymentId.textContent = short(payment.charge_id, 24);
  elements.paymentId.title = payment.charge_id;
  elements.alreadyRefunded.textContent = money(payment.amount_refunded_minor, payment.currency);
  elements.refundable.textContent = money(payment.refundable_amount_minor, payment.currency);
  elements.receiptLink.href = api(`/api/v1/receipts/${state.session.session_id}`);
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
  elements.contacted.textContent = "NOT YET";
  elements.refundAmount.textContent = money(variant.amount_minor);
  elements.required.textContent = short(variant.required_configuration);
  elements.required.title = variant.required_configuration;
  elements.executed.textContent = short(variant.executed_configuration);
  elements.executed.title = variant.executed_configuration;
  elements.configLink.textContent = variant.configuration_match ? "exact match" : "mismatch";
  elements.configLink.classList.toggle("mismatch", !variant.configuration_match);
  elements.executionTitle.textContent =
    decision.class === "authorized" ? "Create the exact test refund." : "Confirm this request is blocked.";
  elements.executionCopy.textContent =
    decision.class === "authorized"
      ? "The executor will claim this action, request its restricted Stripe key, and submit these exact parameters."
      : "The native service should stop at the displayed check without requesting the Stripe key or calling Stripe.";
  elements.execute.textContent =
    state.active === "exact" && state.exactExecuted
      ? "Submit the exact refund again"
      : decision.class === "authorized"
        ? `Create exact ${money(variant.amount_minor)} refund`
        : "Run this denied request";
  elements.execute.disabled = state.busy;
  elements.list.querySelectorAll("[data-variant]").forEach((button) => {
    const active = button.dataset.variant === state.active;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  resetTimeline(decision.class);
  elements.artifact.hidden = true;
  elements.receiptLink.hidden = true;
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
  elements.contacted.textContent = result.stripe_called ? "YES" : "NO";
  for (const stage of result.stages ?? []) {
    const item = elements.timeline.querySelector(`[data-stage="${stage.name}"]`);
    if (!item) continue;
    item.classList.add(stage.status === "stopped" ? "denied" : "proven");
    item.querySelector("strong").textContent = stage.status;
  }
  if (result.refund) {
    elements.refundId.textContent = short(result.refund.id, 24);
    elements.refundId.title = result.refund.id;
    elements.refundStatus.textContent = result.refund.status.toUpperCase();
    elements.requestId.textContent = short(result.refund.stripe_request_id, 24);
    elements.requestId.title = result.refund.stripe_request_id;
    elements.executedAmount.textContent = money(result.refund.amount_minor, result.refund.currency);
    elements.artifact.hidden = false;
  }
  elements.receiptLink.hidden = false;
}

async function execute() {
  if (state.busy) return;
  state.busy = true;
  elements.execute.disabled = true;
  elements.execute.textContent = "Running native verifier…";
  try {
    const result = await request(
      `/api/v1/sessions/${state.session.session_id}/execute`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ variant: state.active }),
      },
    );
    if (state.active === "exact" && result.stripe_called) state.exactExecuted = true;
    renderExecution(result);
    elements.executionCopy.textContent = result.stripe_called
      ? "Stripe test mode created this exact refund. Submit it again to see the durable replay claim stop execution."
      : "The request stopped before the protected service requested its Stripe key.";
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
    elements.execute.textContent =
      state.active === "exact" && state.exactExecuted
        ? "Submit the exact refund again"
        : variant.decision.class === "authorized"
          ? `Create exact ${money(variant.amount_minor)} refund`
          : "Run this denied request";
  }
}

async function initialize() {
  bind();
  try {
    state.scenario = await request("/api/v1/scenario");
    state.session = await request("/api/v1/sessions", { method: "POST" });
    elements.service.textContent = `ready · ${state.scenario.region}`;
    renderSession();
  } catch (error) {
    elements.loading.querySelector("strong").textContent = "Demo unavailable";
    elements.loading.querySelector("p").textContent = `${error.message} (${error.code ?? "startup"})`;
    elements.loading.classList.add("error");
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
