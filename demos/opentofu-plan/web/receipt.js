const query = new URLSearchParams(window.location.search);
const API = (query.get("api") ?? "").replace(/\/$/, "");
const match = /^\/receipts\/([0-9a-f]{32})\/?$/.exec(window.location.pathname);
const $ = (selector) => document.querySelector(selector);
const elements = {
  title: $("#receipt-title"), detail: $("#receipt-detail"), badge: $("#receipt-badge"),
  session: $("#session-id"), action: $("#action-digest"), evidence: $("#evidence-digest"),
  configuration: $("#configuration"), card: $("#receipt-card"), code: $("#receipt-code"),
  status: $("#receipt-status"), stage: $("#receipt-stage"), credential: $("#receipt-credential"),
  tofu: $("#receipt-tofu"), effect: $("#receipt-effect"), error: $("#receipt-error"),
  errorDetail: $("#receipt-error-detail"), raw: $("#receipt-raw"), json: $("#receipt-json"),
};
function short(value, size = 22) {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}
function fail(message) {
  elements.title.textContent = "No receipt record is available.";
  elements.detail.textContent = "Nothing is presented as verified when the native record cannot be loaded.";
  elements.badge.dataset.kind = "denied";
  elements.badge.querySelector("strong").textContent = "UNAVAILABLE";
  elements.errorDetail.textContent = message;
  elements.error.hidden = false;
}
function render(receipt) {
  const result = receipt.result ?? {};
  const decision = result.decision ?? {};
  const authorized = decision.class === "authorized";
  const required = result.required_configuration;
  const executed = result.executed_configuration;
  elements.title.textContent = authorized ? "The exact saved plan was authorized." : "The plan stopped before an unauthorized effect.";
  elements.detail.textContent = decision.detail ?? "The native service recorded no decision.";
  elements.badge.dataset.kind = authorized ? "authorized" : "denied";
  elements.badge.querySelector("strong").textContent = (decision.class ?? "not-run").toUpperCase();
  for (const [element, value] of [[elements.session, receipt.session_id], [elements.action, receipt.action_digest], [elements.evidence, receipt.evidence_digest]]) {
    element.textContent = short(value);
    element.title = value ?? "";
  }
  elements.configuration.textContent = required && executed && required === executed ? "required = executed" : required || executed ? "mismatch recorded" : "not disclosed";
  elements.code.textContent = decision.code ?? "not-run";
  elements.status.textContent = decision.class ?? "not-run";
  elements.status.dataset.kind = authorized ? "authorized" : "denied";
  elements.stage.textContent = decision.stage ?? "—";
  elements.credential.textContent = String(result.credential_called ?? receipt.credential_boundary?.credential_requested_during_execution ?? false).toUpperCase();
  elements.tofu.textContent = String(result.opentofu_called ?? false).toUpperCase();
  elements.effect.textContent = result.resulting_state?.converged ? `state ${result.resulting_state.resulting_state_serial} converged` : "none committed";
  elements.card.hidden = false;
  elements.json.textContent = JSON.stringify(receipt, null, 2);
  elements.raw.hidden = false;
}
async function load() {
  if (!match) return fail("The URL must contain one 32-character lowercase hexadecimal receipt identifier.");
  try {
    const response = await fetch(`${API}/api/v1/receipts/${match[1]}`, { cache: "no-store" });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error?.message ?? `HTTP ${response.status}`);
    render(body);
  } catch (error) {
    fail(error.message);
  }
}
load();
