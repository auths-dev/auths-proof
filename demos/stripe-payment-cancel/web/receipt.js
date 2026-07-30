const query = new URLSearchParams(location.search);
const API = (query.get("api") ?? window.AUTHS_PAYMENT_CANCEL_API_BASE ?? "").replace(/\/$/, "");
const match = /^\/receipts\/([0-9a-f]{64})\/?$/.exec(location.pathname);
const $ = (selector) => document.querySelector(selector);
const elements = {
  title: $("#receipt-title"), detail: $("#receipt-detail"), verification: $("#receipt-verification"),
  id: $("#receipt-id"), profile: $("#profile"), operation: $("#operation"), action: $("#action-digest"),
  policy: $("#policy-digest"), configuration: $("#configuration"), cancel: $("#cancel"),
  acceptance: $("#provider-acceptance"), card: $("#receipt-card"), raw: $("#raw"),
  json: $("#receipt-json"), error: $("#error"), errorDetail: $("#error-detail"),
};
const short = (value, length = 24) => !value ? "—" : value.length > length ? `${value.slice(0, length)}…` : value;

function render(envelope) {
  const receipt = envelope.receipt.receipt;
  const kind = envelope.receipt.kind;
  const isDecision = kind === "merchant-cancel-decision";
  const state = receipt.resulting_state ?? receipt.bounded_decision?.decision ?? "recorded";
  elements.title.textContent =
    isDecision ? "Exact authority and bounded eligibility were evaluated." :
    kind === "merchant-cancel-observation" ? "Stripe was freshly observed." :
    "The cancel lifecycle advanced durably.";
  elements.detail.textContent = `This is a ${kind} receipt. Cancellation, attempted execution, provider acceptance, and reconciled observation remain separately stated.`;
  elements.verification.dataset.state = state.includes("canceled") || state === "eligible" ? "verified" : "denied";
  elements.verification.querySelector("strong").textContent = state.toUpperCase();
  elements.id.textContent = short(envelope.receipt_id); elements.id.title = envelope.receipt_id;
  elements.profile.textContent = receipt.exact_action_profile ?? receipt.exact_action?.profile ?? "exact-payment-cancel/1";
  elements.operation.textContent = receipt.operation ?? "cancel";
  elements.action.textContent = short(receipt.action_digest); elements.action.title = receipt.action_digest ?? "";
  elements.policy.textContent = short(receipt.policy_digest); elements.policy.title = receipt.policy_digest ?? "";
  const required = receipt.required_configuration_digest ?? receipt.required_configuration;
  const executed = receipt.executed_configuration_digest ?? receipt.executed_configuration;
  elements.configuration.textContent =
    receipt.configuration_equal === true || JSON.stringify(required) === JSON.stringify(executed)
      ? "required = executed" : "different / not applicable";
  elements.cancel.textContent = String(
    receipt.atomic_hold_release ??
    (receipt.bounded_decision?.code === "payment-cancel-authorized")
  );
  elements.acceptance.textContent = String(receipt.provider_accepted ?? false);
  const pre = document.createElement("pre");
  pre.textContent = JSON.stringify({
    receipt_kind: kind,
    policy_provenance: receipt.policy_provenance,
    auths_decision: receipt.auths_decision,
    bounded_decision: receipt.bounded_decision,
    execution_attempted: receipt.execution_attempted,
    provider_accepted: receipt.provider_accepted,
    reconciled_observation: receipt.reconciled_observation,
    resulting_state: receipt.resulting_state,
    payment_intent_id: receipt.payment_intent_id ?? receipt.provider?.payment_intent_id,
    cancellation_reason: receipt.cancellation_reason ?? receipt.provider?.cancellation_reason,
    pre_cancel_status: receipt.pre_cancel_status,
    target_amount_minor: receipt.target_amount_minor,
    authorization_release_minor: receipt.authorization_release_minor,
    atomic_hold_release: receipt.atomic_hold_release,
    capture_conflict: receipt.capture_conflict,
    latest_charge_id: receipt.provider?.latest_charge_id,
  }, null, 2);
  elements.card.append(pre);
  elements.json.textContent = JSON.stringify(envelope, null, 2);
  elements.raw.hidden = false;
}

async function load() {
  if (!match) return fail("The URL does not contain a canonical 64-character receipt digest.");
  try {
    const response = await fetch(`${API}/api/v1/receipts/${match[1]}`, { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
    render(body);
  } catch (error) { fail(error.message); }
}

function fail(message) {
  elements.title.textContent = "No verified receipt is available.";
  elements.detail.textContent = "Nothing is presented as accepted when the canonical record is unavailable.";
  elements.verification.dataset.state = "denied";
  elements.verification.querySelector("strong").textContent = "UNAVAILABLE";
  elements.error.hidden = false;
  elements.errorDetail.textContent = message;
}
load();
