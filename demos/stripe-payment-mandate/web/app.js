const configuredApi = document.querySelector('meta[name="auths-api-base"]')?.content ?? "";
const API = (window.AUTHS_PAYMENT_MANDATE_API_BASE ?? configuredApi).replace(/\/$/, "");
const $ = (selector) => document.querySelector(selector);
const ui = {
  experiments: $("#experiments"), terms: $("#terms"), accept: $("#accept"),
  consent: $("#consent"), execute: $("#execute"), reconcile: $("#reconcile"),
  outcome: $("#outcome"), detail: $("#detail"), credential: $("#credential"),
  provider: $("#provider"), consentState: $("#consent-state"), capability: $("#capability"),
  policy: $("#policy"), amount: $("#amount"), interval: $("#interval"), usage: $("#usage"),
  termsDigest: $("#terms-digest"), customer: $("#customer"), method: $("#method"),
  receiptLink: $("#receipt-link"), receiptState: $("#receipt-state"), receiptJson: $("#receipt-json"),
};
const state = { session: null, selected: "success", consented: false, busy: false };
const short = (value, size = 22) => !value ? "—" : value.length > size ? `${value.slice(0, size)}…` : value;
const money = (minor, currency) => new Intl.NumberFormat("en-US", {
  style: "currency", currency: currency.toUpperCase(),
}).format(minor / 100);

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, { cache: "no-store", credentials: "include", ...options });
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
  const experiment = state.session.experiments.find((value) => value.id === id);
  ui.detail.textContent = experiment.detail;
  ui.execute.textContent = id === "ambiguous" ? "Create once, lose response" :
    id === "replay" ? "Replay exact workflow" : `Run ${experiment.label.toLowerCase()}`;
}

function renderSession(session) {
  state.session = session;
  ui.terms.textContent = session.terms;
  ui.termsDigest.textContent = short(session.displayed_terms_digest);
  ui.termsDigest.title = session.displayed_terms_digest;
  ui.policy.textContent = short(session.policy_digest);
  ui.policy.title = session.policy_digest;
  ui.amount.textContent = money(session.future_scope.amount_minor, session.future_scope.currency);
  ui.interval.textContent = session.future_scope.interval;
  ui.usage.textContent = session.future_scope.usage;
  ui.customer.textContent = short(session.stripe_evidence.customer_id);
  ui.customer.title = session.stripe_evidence.customer_id;
  ui.method.textContent = short(session.stripe_evidence.payment_method_id);
  ui.method.title = session.stripe_evidence.payment_method_id;
  ui.experiments.replaceChildren();
  session.experiments.forEach((experiment) => {
    const button = document.createElement("button");
    button.type = "button";
    button.dataset.experiment = experiment.id;
    button.innerHTML = `<strong>${experiment.label}</strong><span>${experiment.detail}</span>`;
    button.addEventListener("click", () => selectExperiment(experiment.id));
    ui.experiments.append(button);
  });
  ui.outcome.textContent = "CONSENT REQUIRED";
  ui.outcome.dataset.kind = "idle";
  ui.consent.disabled = !ui.accept.checked;
  selectExperiment("success");
}

function renderResult(result) {
  ui.outcome.textContent = result.outcome.toUpperCase();
  ui.outcome.dataset.kind = result.outcome === "mandate-established" || result.outcome === "replay"
    ? "authorized" : result.outcome === "outcome-unknown" ? "indeterminate" : "denied";
  ui.detail.textContent = {
    "mandate-established": "Stripe confirmed one SetupIntent. No money was charged; future payments still need separate exact authority.",
    replay: "Durable state returned the same capability. No second SetupIntent was created.",
    rejected: "The request stopped before capability reservation, credential access, and Stripe mutation.",
    "outcome-unknown": "Stripe accepted delivery but the response was treated as lost. The capability slot remains held.",
    conflict: "The workflow, consent, or future-use scope is already bound.",
    "provider-failed": "Stripe definitively failed; the capability slot was released.",
    "customer-action-required": "Only the trusted consent UI may continue customer action; no client secret was returned here.",
  }[result.outcome] ?? "The mandate workflow failed closed.";
  ui.credential.textContent = String(result.boundary?.credential_requests ?? 0);
  ui.provider.textContent = String(result.boundary?.provider_calls ?? 0);
  ui.capability.textContent = result.record?.state ?? (result.persisted ? "decision only" : "none");
  ui.reconcile.hidden = result.outcome !== "outcome-unknown";
  if (result.receipt_url) {
    ui.receiptLink.href = `${result.receipt_url}${API ? `?api=${encodeURIComponent(API)}` : ""}`;
    ui.receiptLink.hidden = false;
  }
  const receipt = result.canonical_receipt ?? result.decision;
  if (receipt) {
    ui.receiptState.textContent = result.outcome;
    ui.receiptJson.textContent = JSON.stringify(receipt, null, 2);
  }
}

ui.accept.addEventListener("change", () => {
  ui.consent.disabled = !ui.accept.checked || state.consented || state.busy;
});

ui.consent.addEventListener("click", async () => {
  if (state.busy || !ui.accept.checked) return;
  state.busy = true;
  ui.consent.disabled = true;
  try {
    await request(`/api/v1/sessions/${state.session.session_id}/consent`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ displayed_terms_digest: state.session.displayed_terms_digest }),
    });
    state.consented = true;
    ui.consentState.textContent = "accepted";
    ui.execute.disabled = false;
    ui.outcome.textContent = "READY";
    ui.detail.textContent = "Trusted consent and exact Auths authority are ready.";
  } catch (error) {
    ui.outcome.textContent = "CONSENT FAILED";
    ui.detail.textContent = error.message;
    ui.consent.disabled = false;
  } finally {
    state.busy = false;
  }
});

ui.execute.addEventListener("click", async () => {
  if (state.busy) return;
  state.busy = true;
  ui.execute.disabled = true;
  try {
    renderResult(await request(`/api/v1/sessions/${state.session.session_id}/execute`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ experiment: state.selected }),
    }));
  } catch (error) {
    ui.outcome.textContent = "FAILED CLOSED";
    ui.detail.textContent = error.message;
  } finally {
    state.busy = false;
    ui.execute.disabled = false;
  }
});

ui.reconcile.addEventListener("click", async () => {
  if (state.busy) return;
  state.busy = true;
  ui.reconcile.disabled = true;
  try {
    renderResult(await request(`/api/v1/sessions/${state.session.session_id}/reconcile`, { method: "POST" }));
  } catch (error) {
    ui.detail.textContent = error.message;
  } finally {
    state.busy = false;
    ui.reconcile.disabled = false;
  }
});

request("/api/v1/sessions", { method: "POST" })
  .then(renderSession)
  .catch((error) => {
    ui.outcome.textContent = "UNAVAILABLE";
    ui.outcome.dataset.kind = "indeterminate";
    ui.detail.textContent = error.message;
  });
