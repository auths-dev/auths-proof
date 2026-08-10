const state = { experiment: "public-identity", ready: false, busy: false };
const $ = (id) => document.getElementById(id);
const variants = document.querySelectorAll("[data-experiment]");

async function jsonFetch(url, options = {}) {
  const response = await fetch(url, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.detail || body.code || `HTTP ${response.status}`);
  return body;
}

async function connect() {
  try {
    const status = await jsonFetch("/api/v1/status");
    $("server-principal").textContent = status.server_principal;
    $("server-key").textContent = `${status.server_identity_method} · ${status.server_signature_suite} · ${status.server_public_key}`;
    state.ready = true;
    $("service-state").textContent = "ready";
    $("service-indicator").classList.add("ready");
    $("execute").disabled = false;
    $("execute").textContent = "Run identity exchange";
    setVerdict("READY", "ready", "The native Iroh endpoint is ready. No capability or approval service was initialized.");
  } catch (error) {
    setVerdict("UNAVAILABLE", "denied", error.message);
    $("service-state").textContent = "unavailable";
  }
}

async function execute() {
  if (!state.ready || state.busy) return;
  state.busy = true;
  $("execute").disabled = true;
  setVerdict("EXCHANGING", "loading", "Sending one bounded identity packet over a real local Iroh connection.");
  try {
    const outcome = await jsonFetch("/api/v1/exchanges", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ experiment: state.experiment, message: $("message").value }),
    });
    render(outcome);
  } catch (error) {
    setVerdict("ERROR", "denied", error.message);
  } finally {
    state.busy = false;
    $("execute").disabled = false;
  }
}

function render(outcome) {
  const rejected = outcome.code === "signature-invalid";
  const verified = outcome.signature_verified;
  setVerdict(
    rejected ? "REJECTED" : verified ? "VERIFIED" : "EXCHANGED",
    rejected ? "denied" : "verified",
    outcome.detail,
  );
  $("client-principal").textContent = outcome.client.principal;
  $("client-key").textContent = `${outcome.client.method} · ${outcome.client.suite} · ${outcome.client.public_key}`;
  $("server-principal").textContent = outcome.server.principal;
  $("server-key").textContent = `${outcome.server.method} · ${outcome.server.suite} · ${outcome.server.public_key}`;
  $("path").textContent = outcome.transport.path;
  $("code").textContent = outcome.code;
  $("signature-state").textContent = outcome.signature
    ? verified ? "VERIFIED" : "INVALID"
    : "NOT REQUESTED";
  $("evidence-json").textContent = JSON.stringify(outcome, null, 2);
}

function setVerdict(text, kind, detail) {
  $("verdict").textContent = text;
  $("verdict").dataset.kind = kind;
  $("verdict-detail").textContent = detail;
}

function describeExperiment() {
  const copy = {
    "public-identity": ["Send only the public identity", "The method- and suite-labelled identity is ordinary bounded data. No policy object or grant is constructed."],
    "signed-message": ["Sign and verify one message", "The demo-selected Ed25519 adapter verifies the bytes through the algorithm-neutral identity port."],
    "tampered-message": ["Reject changed message bytes", "The client signature covers different bytes. Iroh still delivers the packet, but verification fails closed."],
  }[state.experiment];
  $("operation-title").textContent = copy[0];
  $("operation-copy").textContent = copy[1];
}

variants.forEach((button) => button.addEventListener("click", () => {
  variants.forEach((item) => item.classList.toggle("active", item === button));
  state.experiment = button.dataset.experiment;
  describeExperiment();
}));
$("execute").addEventListener("click", execute);
connect();
