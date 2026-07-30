const configuredApi = document.querySelector('meta[name="auths-api-base"]')?.content ?? "";
const API = (window.AUTHS_PAYMENT_CANCEL_API_BASE ?? configuredApi).replace(/\/$/, "");
const $ = (selector) => document.querySelector(selector);
const elements = {
  experiments: $("#experiments"), execute: $("#execute"), reconcile: $("#reconcile"),
  literal: $("#literal-copy"), outcome: $("#outcome"), detail: $("#outcome-detail"),
  credential: $("#credential-requests"), provider: $("#provider-calls"),
  configuration: $("#configuration"), durable: $("#durable-state"),
  receiptLink: $("#receipt-link"), receiptState: $("#receipt-state"), receiptJson: $("#receipt-json"),
  policy: $("#policy-digest"), evaluator: $("#evaluator"), allowedReasons: $("#allowed-reasons"),
  holdRule: $("#hold-rule"), exactAmount: $("#exact-amount"), exactReason: $("#exact-reason"),
  customer: $("#customer"), paymentIntent: $("#payment-intent"), charge: $("#charge"), order: $("#order"),
  observed: $("#observed-at"), testMode: $("#test-mode"), held: $("#budget-held"),
  preStatus: $("#pre-status"), capturable: $("#capturable-amount"), cancelReason: $("#cancel-reason"),
};

const state = { session: null, selected: "success", busy: false };
const money = (minor, currency = "usd") =>
  new Intl.NumberFormat("en-US", { style: "currency", currency: currency.toUpperCase() }).format(minor / 100);
const short = (value, size = 22) => !value ? "—" : value.length > size ? `${value.slice(0, size)}…` : value;

async function request(path, options) {
  const response = await fetch(`${API}${path}`, { cache: "no-store", ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
  return body;
}

function selectExperiment(id) {
  state.selected = id;
  document.querySelectorAll("[data-experiment]").forEach((button) => {
    const active = button.dataset.experiment === id;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
  const experiment = state.session.experiments.find((item) => item.id === id);
  elements.literal.textContent = experiment.detail;
  elements.execute.textContent =
    id === "replay" ? "Submit the exact workflow again" :
    id === "ambiguous" ? "Deliver once and lose the response" :
    `Run ${experiment.label.toLowerCase()}`;
}

function renderSession(session) {
  state.session = session;
  elements.experiments.replaceChildren();
  for (const experiment of session.experiments) {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.experiment = experiment.id;
    button.innerHTML = `<strong>${experiment.label}</strong><span>${experiment.detail}</span>`;
    button.addEventListener("click", () => selectExperiment(experiment.id));
    elements.experiments.append(button);
  }
  const delegation = session.delegation;
  const action = session.agent_selected_exact_cancel;
  const evidence = session.fresh_stripe_and_hold_evidence;
  elements.policy.textContent = short(delegation.policy_digest);
  elements.policy.title = delegation.policy_digest;
  elements.evaluator.textContent = `${delegation.evaluator_semantic_id}/${delegation.evaluator_semantic_version}`;
  elements.allowedReasons.textContent = delegation.allowed_reasons.join(", ");
  elements.holdRule.textContent = delegation.hold_release_rule;
  elements.exactAmount.textContent = money(action.amount_minor, action.currency);
  elements.exactReason.textContent = action.cancellation_reason;
  elements.customer.textContent = short(action.customer_id);
  elements.customer.title = action.customer_id;
  elements.paymentIntent.textContent = short(action.payment_intent_id);
  elements.paymentIntent.title = action.payment_intent_id;
  elements.charge.textContent = short(evidence.latest_charge_id);
  elements.charge.title = evidence.latest_charge_id ?? "";
  elements.order.textContent = short(action.order_scope);
  elements.order.title = action.order_scope;
  elements.observed.textContent = new Date(evidence.observed_at * 1000).toISOString();
  elements.testMode.textContent = evidence.livemode ? "NO — blocked" : "YES";
  elements.configuration.textContent = session.configuration_equal ? "required = executed" : "mismatch";
  elements.held.textContent = money(evidence.amount_capturable_minor, evidence.currency);
  elements.preStatus.textContent = evidence.payment_intent_status;
  elements.cancelReason.textContent = action.cancellation_reason;
  elements.outcome.textContent = "READY";
  elements.outcome.dataset.kind = "idle";
  elements.detail.textContent = "A real manual authorization, exact PaymentIntent and Charge, fresh hold evidence, exact cancel proof, policy, and runtime configuration are loaded.";
  elements.execute.disabled = false;
  selectExperiment("success");
}

function renderResult(result) {
  elements.outcome.textContent = result.outcome.toUpperCase();
  elements.outcome.dataset.kind =
    ["canceled", "reconciled"].includes(result.outcome) ? "canceled" :
    result.outcome === "outcome-unknown" ? "indeterminate" : "denied";
  elements.detail.textContent = {
    canceled: "Stripe and a fresh retrieval proved terminal cancellation. The full prior hold was released atomically.",
    replay: "Durable state returned the original cancellation. No second cancel request was made.",
    rejected: "The request stopped before a claim, credential access, and Stripe provider I/O.",
    "outcome-unknown": "Delivery may have reached Stripe. The cancellation claim and prior hold remain charged until reconciliation.",
    reconciled: "A fresh PaymentIntent retrieval reconciled the effect without another cancel request.",
    "capture-conflict": "Capture won the race. Cancellation will not be retried, the hold was not released, and refund reconciliation is required.",
    "provider-declined": "Stripe definitively declined; the cancellation claim was released and the hold retained.",
    conflict: "The workflow was already bound to another exact action.",
  }[result.outcome] ?? "The service failed closed at a typed cancel lifecycle boundary.";
  elements.credential.textContent = String(result.boundary?.credential_requests ?? 0);
  elements.provider.textContent = String(result.boundary?.provider_calls ?? 0);
  const record = result.record ?? result.transition?.cancel_reservation;
  elements.durable.textContent = record?.state ?? (result.persisted ? "decision-only" : "no state written");
  const provider = record?.cancel_provider;
  elements.capturable.textContent = provider
    ? money(provider.amount_capturable_minor, record.currency)
    : "—";
  elements.cancelReason.textContent = provider?.cancellation_reason ?? state.session.agent_selected_exact_cancel.cancellation_reason;
  elements.reconcile.hidden = result.outcome !== "outcome-unknown";
  if (result.receipt_url) {
    elements.receiptLink.href = `${result.receipt_url}${API ? `?api=${encodeURIComponent(API)}` : ""}`;
    elements.receiptLink.hidden = false;
  }
  if (result.canonical_receipt) {
    elements.receiptState.textContent = result.outcome;
    elements.receiptJson.textContent = JSON.stringify(result.canonical_receipt, null, 2);
  } else if (result.decision) {
    elements.receiptState.textContent = result.outcome;
    elements.receiptJson.textContent = JSON.stringify(result.decision, null, 2);
  }
}

async function execute() {
  if (state.busy) return;
  state.busy = true;
  elements.execute.disabled = true;
  try {
    const result = await request(`/api/v1/sessions/${state.session.session_id}/execute`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ experiment: state.selected }),
    });
    renderResult(result);
    try {
      const status = await request(`/api/v1/sessions/${state.session.session_id}`);
      const hold = status.linked_authorization?.state;
      if (hold === "authorization-released-by-cancel") elements.held.textContent = money(0);
    } catch (error) {
      if (result.outcome !== "replay") throw error;
    }
  } catch (error) {
    elements.outcome.textContent = "FAILED CLOSED";
    elements.outcome.dataset.kind = "indeterminate";
    elements.detail.textContent = error.message;
  } finally {
    state.busy = false;
    elements.execute.disabled = false;
  }
}

async function reconcile() {
  if (state.busy) return;
  state.busy = true;
  elements.reconcile.disabled = true;
  try {
    const result = await request(`/api/v1/sessions/${state.session.session_id}/reconcile`, { method: "POST" });
    renderResult(result);
    const status = await request(`/api/v1/sessions/${state.session.session_id}`);
    if (status.linked_authorization?.state === "authorization-released-by-cancel") {
      elements.held.textContent = money(0);
    }
  } catch (error) {
    elements.detail.textContent = error.message;
  } finally {
    state.busy = false;
    elements.reconcile.disabled = false;
  }
}

async function start() {
  try {
    renderSession(await request("/api/v1/sessions", { method: "POST" }));
  } catch (error) {
    elements.outcome.textContent = "UNAVAILABLE";
    elements.outcome.dataset.kind = "indeterminate";
    elements.detail.textContent = error.message;
    elements.execute.textContent = "Stripe test setup unavailable";
  }
}

elements.execute.addEventListener("click", execute);
elements.reconcile.addEventListener("click", reconcile);
start();
