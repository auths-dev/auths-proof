const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const match = /^\/receipts\/([0-9a-f]{32})\/?$/.exec(window.location.pathname);

const $ = (selector) => document.querySelector(selector);
const elements = {
  title: $("#receipt-title"), detail: $("#receipt-detail"),
  verification: $("#receipt-verification"), session: $("#session-id"),
  action: $("#action-digest"), evidence: $("#evidence-digest"),
  policy: $("#policy-digest"), provenance: $("#policy-provenance"),
  reservation: $("#reservation-state"),
  configuration: $("#configuration-result"), card: $("#receipt-card"),
  error: $("#receipt-error"), errorDetail: $("#receipt-error-detail"),
  raw: $("#receipt-raw"), json: $("#receipt-json"),
};

function short(value, length = 22) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}

function addFact(list, label, value) {
  const row = document.createElement("div");
  const term = document.createElement("dt");
  const definition = document.createElement("dd");
  const code = document.createElement("code");
  term.textContent = label;
  code.textContent = value ?? "—";
  code.title = value ?? "";
  definition.append(code);
  row.append(term, definition);
  list.append(row);
}

function render(receipt) {
  const result = receipt.result;
  const decision = result?.decision;
  const required = result?.required_configuration;
  const executed = result?.executed_configuration;
  const matches = required && executed ? required === executed : true;
  const authorized = decision?.class === "authorized";
  const replay = decision?.code === "bounded-replay";

  elements.title.textContent = authorized
    ? "The exact refund was authorized."
    : replay
      ? "The replay was blocked without another Stripe call."
      : "The request was denied before an unauthorized refund.";
  elements.detail.textContent = decision?.detail ?? "No execution result has been recorded for this session.";
  elements.verification.dataset.state = authorized ? "verified" : "denied";
  elements.verification.querySelector("strong").textContent = decision?.class?.toUpperCase() ?? "NOT RUN";
  elements.session.textContent = short(receipt.session_id);
  elements.session.title = receipt.session_id;
  elements.action.textContent = short(receipt.action_digest);
  elements.action.title = receipt.action_digest;
  elements.evidence.textContent = short(receipt.evidence_digest);
  elements.evidence.title = receipt.evidence_digest;
  elements.policy.textContent = short(receipt.policy_digest);
  elements.policy.title = receipt.policy_digest;
  elements.provenance.textContent = receipt.policy_provenance ?? "unavailable";
  elements.reservation.textContent = receipt.reservation?.state ?? "not reserved";
  elements.configuration.textContent = matches ? "required = executed" : "mismatch recorded";
  elements.configuration.classList.toggle("safe", matches);

  if (decision) {
    const card = document.createElement("article");
    card.className = "receipt-card";
    const header = document.createElement("header");
    const sequence = document.createElement("span");
    sequence.textContent = "01";
    const heading = document.createElement("div");
    const label = document.createElement("small");
    label.textContent = "Authorization and execution result";
    const title = document.createElement("h3");
    title.textContent = decision.code;
    heading.append(label, title);
    const status = document.createElement("strong");
    status.textContent = decision.class;
    status.dataset.kind = authorized ? "verified" : "denied";
    header.append(sequence, heading, status);
    const facts = document.createElement("dl");
    addFact(facts, "Stopped at", decision.stage);
    addFact(facts, "Stripe called", String(result.stripe_called));
    addFact(facts, "Policy provenance", receipt.policy_provenance);
    addFact(facts, "Evaluator", receipt.evaluator?.evaluator_semantic_id);
    addFact(facts, "Reservation", receipt.reservation?.state);
    addFact(
      facts,
      "Aggregate spent",
      receipt.aggregate_budget?.budgets?.[0]
        ? String(receipt.aggregate_budget.budgets[0].spent_minor)
        : "0",
    );
    addFact(facts, "Required config", required);
    addFact(facts, "Executed config", executed);
    card.append(header, facts);
    elements.card.append(card);
  }
  elements.json.textContent = JSON.stringify(receipt, null, 2);
  elements.raw.hidden = false;
}

function showError(message) {
  elements.title.textContent = "No receipt record is available.";
  elements.detail.textContent = "Nothing is presented as verified when the native record cannot be loaded.";
  elements.verification.dataset.state = "denied";
  elements.verification.querySelector("strong").textContent = "UNAVAILABLE";
  elements.error.hidden = false;
  elements.errorDetail.textContent = message;
}

async function load() {
  if (!match) return showError("The URL does not contain a valid 32-character receipt identifier.");
  try {
    const response = await fetch(`${API}/api/v1/receipts/${match[1]}`, { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
    render(body);
  } catch (error) {
    showError(error.message);
  }
}

load();
