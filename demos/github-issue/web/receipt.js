const API_BASE = window.AUTHS_GITHUB_API_BASE || window.location.origin;
const REQUEST_TIMEOUT_MS = 20_000;
const RECEIPT_PATH = /^\/receipts\/(?:demo-)?([0-9a-f]{32})\/?$/;

const elements = {
  dot: document.querySelector("#receipt-dot"),
  state: document.querySelector("#receipt-state"),
  workflowShort: document.querySelector("#workflow-short"),
  total: document.querySelector("#receipt-total"),
  title: document.querySelector("#receipt-title"),
  detail: document.querySelector("#receipt-detail"),
  verification: document.querySelector("#receipt-verification"),
  workflowId: document.querySelector("#workflow-id"),
  schema: document.querySelector("#receipt-schema"),
  signer: document.querySelector("#receipt-signer"),
  configuration: document.querySelector("#configuration-result"),
  cards: document.querySelector("#receipt-cards"),
  error: document.querySelector("#receipt-error"),
  errorDetail: document.querySelector("#receipt-error-detail"),
  raw: document.querySelector("#receipt-raw"),
  rawCount: document.querySelector("#raw-count"),
  json: document.querySelector("#receipt-json"),
};

loadPersistentReceipts();

async function loadPersistentReceipts() {
  const match = RECEIPT_PATH.exec(window.location.pathname);
  if (!match) {
    showError("The URL does not contain a valid 32-character receipt identifier.");
    return;
  }
  const sessionId = match[1];
  elements.workflowShort.textContent = `demo-${sessionId.slice(0, 8)}…`;
  try {
    const response = await request(`/v1/demo/receipts/${sessionId}`);
    renderReceiptLog(response);
  } catch (error) {
    showError(error.message);
  }
}

function renderReceiptLog(response) {
  const envelopes = response.receipts || [];
  const first = envelopes[0];
  const firstReceipt = first?.receipt?.receipt;
  const decisions = envelopes.filter(
    (envelope) => envelope.receipt?.type === "decision",
  );
  const configurationsMatch = decisions.every((envelope) => {
    const receipt = envelope.receipt.receipt;
    return (
      receipt.required_configuration_digest ===
      receipt.executed_configuration_digest
    );
  });

  elements.dot.dataset.state = "ready";
  elements.state.textContent = "verified";
  elements.total.textContent = `${envelopes.length} signed envelopes`;
  elements.title.textContent = "The workflow record is intact.";
  elements.detail.textContent =
    "Each decision precedes its corresponding GitHub effect, and every returned envelope passed signature verification.";
  elements.verification.dataset.state = "verified";
  elements.verification.querySelector("strong").textContent = "VERIFIED";
  elements.workflowId.textContent = response.workflow_id;
  elements.schema.textContent = firstReceipt?.schema || response.schema;
  elements.signer.textContent = short(first?.signer_public_key, 20);
  elements.signer.title = first?.signer_public_key || "";
  elements.configuration.textContent = configurationsMatch
    ? "required = executed"
    : "mismatch recorded";
  elements.configuration.classList.toggle("safe", configurationsMatch);
  elements.raw.hidden = false;
  elements.rawCount.textContent = String(envelopes.length);
  elements.json.textContent = JSON.stringify(envelopes, null, 2);

  envelopes.forEach((envelope, index) => {
    elements.cards.append(createReceiptCard(envelope, index));
  });
}

function createReceiptCard(envelope, index) {
  const kind = envelope.receipt.type;
  const receipt = envelope.receipt.receipt;
  const card = document.createElement("article");
  card.className = "receipt-card";

  const header = document.createElement("header");
  const sequence = document.createElement("span");
  sequence.textContent = String(index + 1).padStart(2, "0");
  const heading = document.createElement("div");
  const label = document.createElement("small");
  label.textContent = kind === "decision" ? "Authorization decision" : "External effect";
  const title = document.createElement("h3");
  title.textContent =
    kind === "decision"
      ? receipt.product_decision?.code || "Decision"
      : receipt.operation || "Execution";
  heading.append(label, title);
  const status = document.createElement("strong");
  const successful =
    kind === "decision"
      ? receipt.product_decision?.class === "authorized"
      : receipt.result === "succeeded";
  status.textContent =
    kind === "decision"
      ? receipt.product_decision?.class || "recorded"
      : receipt.result || "recorded";
  status.dataset.kind = successful ? "verified" : "denied";
  header.append(sequence, heading, status);
  card.append(header);

  const facts = document.createElement("dl");
  const rows =
    kind === "decision"
      ? [
          ["Action", receipt.action_digest],
          ["Evidence", receipt.evidence_digest],
          ["Required config", receipt.required_configuration_digest],
          ["Executed config", receipt.executed_configuration_digest],
        ]
      : [
          ["Action", receipt.action_digest],
          ["Decision", receipt.decision_receipt_digest],
          ["Claim", receipt.claim_id],
          ["Observed", observedSummary(receipt.observed_state)],
        ];
  rows.forEach(([labelText, value]) => {
    const row = document.createElement("div");
    const term = document.createElement("dt");
    term.textContent = labelText;
    const definition = document.createElement("dd");
    const code = document.createElement("code");
    code.textContent = value || "—";
    code.title = value || "";
    definition.append(code);
    row.append(term, definition);
    facts.append(row);
  });
  card.append(facts);

  const signature = document.createElement("p");
  signature.className = "receipt-signature";
  signature.textContent = `Ed25519 signature ${short(envelope.signature, 24)}`;
  signature.title = envelope.signature;
  card.append(signature);

  const pullRequestUrl =
    receipt.observed_state?.kind === "pull-request"
      ? receipt.observed_state.value?.url
      : null;
  if (pullRequestUrl) {
    const link = document.createElement("a");
    link.href = pullRequestUrl;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = "Open the observed draft PR ↗";
    card.append(link);
  }
  return card;
}

function observedSummary(observedState) {
  if (!observedState) return "no postcondition";
  if (observedState.kind === "branch") {
    return `${observedState.value.branch_ref} @ ${short(observedState.value.head_revision, 13)}`;
  }
  if (observedState.kind === "pull-request") {
    return `draft PR #${observedState.value.number}`;
  }
  return observedState.kind;
}

function showError(detail) {
  elements.dot.dataset.state = "failed";
  elements.state.textContent = "unavailable";
  elements.title.textContent = "No verified receipt record.";
  elements.detail.textContent =
    "Nothing is displayed unless the native service can verify the persistent signed log.";
  elements.verification.dataset.state = "failed";
  elements.verification.querySelector("strong").textContent = "NOT VERIFIED";
  elements.error.hidden = false;
  elements.errorDetail.textContent = detail;
}

async function request(path) {
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.detail || `HTTP ${response.status}`);
    }
    return body;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("The native receipt service timed out.");
    }
    throw error;
  } finally {
    window.clearTimeout(timer);
  }
}

function short(value, length = 12) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length)}…` : value;
}
