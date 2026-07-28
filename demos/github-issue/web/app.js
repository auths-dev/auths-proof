const API_BASE =
  window.AUTHS_GITHUB_API_BASE ||
  "https://auths-issue-workflow.fly.dev";
const REQUEST_TIMEOUT_MS = 20_000;
const EXECUTION_TIMEOUT_MS = 120_000;

const previews = {
  exact: {
    verdict: "AUTHORIZED",
    kind: "authorized",
    code: "authorized",
    stage: "auths-kernel",
    credential: "after claim",
    detail: "Every bound fact matches. Inspection can proceed, then the executor may publish one branch and one draft PR.",
  },
  "prohibited-path": {
    verdict: "DENIED",
    kind: "denied",
    code: "path-explicitly-denied",
    stage: "candidate-inspection",
    credential: "NO WRITE",
    detail: "The candidate changes .github/**, which the signed workflow grant explicitly denies.",
  },
  "candidate-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "candidate-bundle-malformed",
    stage: "candidate-inspection",
    credential: "NO WRITE",
    detail: "The submitted candidate SHA does not identify the commit in the inspected Git bundle.",
  },
  "repository-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "repository-mismatch",
    stage: "github-evidence",
    credential: "NO WRITE",
    detail: "Fresh GitHub evidence does not identify the immutable repository in the workflow grant.",
  },
  "issue-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "issue-mismatch",
    stage: "github-evidence",
    credential: "NO WRITE",
    detail: "Fresh GitHub evidence does not identify the issue in the workflow grant.",
  },
  "base-advanced": {
    verdict: "DENIED",
    kind: "denied",
    code: "base-revision-mismatch",
    stage: "github-evidence",
    credential: "NO WRITE",
    detail: "The base ref no longer points to the commit named by the workflow grant.",
  },
  "malformed-bundle": {
    verdict: "DENIED",
    kind: "denied",
    code: "candidate-bundle-malformed",
    stage: "candidate-inspection",
    credential: "NO WRITE",
    detail: "The fixed 17-byte regression bundle is rejected as malformed before GitHub evidence or credentials.",
  },
};

const elements = {
  variants: [...document.querySelectorAll(".variant")],
  inspect: document.querySelector("#inspect"),
  execute: document.querySelector("#execute"),
  replay: document.querySelector("#replay"),
  verdict: document.querySelector("#verdict"),
  verdictDetail: document.querySelector("#verdict-detail"),
  decisionCode: document.querySelector("#decision-code"),
  decisionStage: document.querySelector("#decision-stage"),
  credentialRequested: document.querySelector("#credential-requested"),
  mutationCount: document.querySelector("#mutation-count"),
  serviceState: document.querySelector("#service-state"),
  liveState: document.querySelector("#live-state"),
  nativeState: document.querySelector("#native-state"),
  nativeDot: document.querySelector("#native-dot"),
  githubState: document.querySelector("#github-state"),
  githubDot: document.querySelector("#github-dot"),
  release: document.querySelector("#release"),
  repository: document.querySelector("#repository"),
  issue: document.querySelector("#issue"),
  base: document.querySelector("#base"),
  target: document.querySelector("#target"),
  requiredConfig: document.querySelector("#required-config"),
  executedConfig: document.querySelector("#executed-config"),
  configLink: document.querySelector("#config-link"),
  candidateSha: document.querySelector("#candidate-sha"),
  changedPath: document.querySelector("#changed-path"),
  directPush: document.querySelector("#direct-push"),
  actionTitle: document.querySelector("#action-title"),
  actionCopy: document.querySelector("#action-copy"),
  timeline: document.querySelector("#receipt-timeline"),
  githubResult: document.querySelector("#github-result"),
  publishedRef: document.querySelector("#published-ref"),
  publishedSha: document.querySelector("#published-sha"),
  pullRequestLink: document.querySelector("#pull-request-link"),
  receiptCount: document.querySelector("#receipt-count"),
  receiptJson: document.querySelector("#receipt-json"),
};

let selected = "exact";
let sessionId = null;
let sessionReady = false;
let inspected = false;
let completed = false;

elements.variants.forEach((button) => {
  button.addEventListener("click", () => {
    selected = button.dataset.variant;
    inspected = false;
    completed = false;
    elements.variants.forEach((item) => {
      const active = item === button;
      item.classList.toggle("active", active);
      item.setAttribute("aria-pressed", String(active));
    });
    resetExecution();
    applyPreview(selected);
  });
});

elements.inspect.addEventListener("click", inspectCandidate);
elements.execute.addEventListener("click", executeWorkflow);
elements.replay.addEventListener("click", replayWorkflow);

applyPreview(selected);
initialize();

async function initialize() {
  setService("connecting", "checking native service", false);
  try {
    const [health, scenario] = await Promise.all([
      request("/healthz", { timeout: REQUEST_TIMEOUT_MS }),
      request("/v1/demo/scenario", { timeout: REQUEST_TIMEOUT_MS }),
    ]);
    const session = await request("/v1/demo/sessions", {
      method: "POST",
      timeout: REQUEST_TIMEOUT_MS,
    });
    sessionId = session.session_id;
    sessionReady = true;
    elements.repository.textContent = scenario.repository;
    elements.issue.textContent = `#${scenario.issue_number}`;
    elements.base.textContent = short(session.base_revision);
    elements.base.title = session.base_revision;
    elements.target.textContent = session.target_ref;
    elements.requiredConfig.textContent = short(session.required_configuration, 16);
    elements.requiredConfig.title = session.required_configuration;
    elements.executedConfig.textContent = short(session.executed_configuration, 16);
    elements.executedConfig.title = session.executed_configuration;
    const match = session.required_configuration === session.executed_configuration;
    elements.configLink.textContent = match ? "exact match" : "mismatch";
    elements.configLink.classList.toggle("mismatch", !match);
    elements.nativeState.textContent = "ready";
    elements.nativeDot.dataset.state = "ready";
    elements.githubState.textContent = "base confirmed";
    elements.githubDot.dataset.state = "ready";
    elements.release.textContent = `${health.region} · ${health.release}`;
    setService("ready", "native executor ready", true);
    applyPreview(selected);
  } catch (error) {
    sessionReady = false;
    elements.nativeState.textContent = "unavailable";
    elements.nativeDot.dataset.state = "failed";
    elements.githubState.textContent = "not checked";
    setService("failed", "native service unavailable", false);
    elements.verdict.textContent = "UNAVAILABLE";
    elements.verdict.dataset.kind = "denied";
    elements.verdictDetail.textContent =
      `The browser could not create a native session: ${error.message}. Retry by reloading this page.`;
    elements.inspect.disabled = true;
  }
}

async function inspectCandidate() {
  if (!sessionReady || !sessionId) {
    elements.verdictDetail.textContent = "The native session is not ready. Reload the page to retry.";
    return;
  }
  setBusy(elements.inspect, true, "Inspecting Git bundle…");
  elements.execute.disabled = true;
  updateTimeline("candidate", "Inspecting", null);
  try {
    const response = await request(`/v1/demo/sessions/${sessionId}/candidate`, {
      method: "POST",
      body: { experiment: selected },
      timeout: EXECUTION_TIMEOUT_MS,
    });
    const candidate = response.candidate;
    inspected = candidate.status === "inspected";
    elements.candidateSha.textContent = candidate.candidate_revision
      ? short(candidate.candidate_revision, 13)
      : "rejected";
    elements.candidateSha.title = candidate.candidate_revision || "";
    const path = candidate.changed_paths?.[0]?.path || "none accepted";
    elements.changedPath.textContent = path;
    elements.changedPath.title = path;
    elements.directPush.textContent =
      candidate.direct_push?.result === "authentication-rejected"
        ? "REJECTED — no credential"
        : candidate.direct_push?.result || "not attempted";
    updateTimeline(
      "candidate",
      candidate.status === "inspected" ? "Inspected" : "Denied",
      candidate.status === "inspected" ? "done" : "denied",
    );
    elements.githubState.textContent = "evidence current";
    elements.githubDot.dataset.state = "ready";
    elements.execute.disabled = false;
    elements.execute.textContent =
      selected === "exact"
        ? "Publish branch + open draft PR"
        : "Submit denied case";
    elements.actionTitle.textContent =
      selected === "exact"
        ? "Publish the inspected candidate."
        : "Confirm the executor stops.";
    elements.actionCopy.textContent =
      selected === "exact"
        ? "Auths will verify and claim each exact action before a GitHub mutation token is minted."
        : "The native service will return the denial without requesting a GitHub mutation credential.";
  } catch (error) {
    updateTimeline("candidate", "Failed", "denied");
    elements.verdictDetail.textContent = `Candidate inspection failed: ${error.message}`;
  } finally {
    setBusy(elements.inspect, false, "Inspect candidate");
  }
}

async function executeWorkflow() {
  if (!inspected && selected === "exact") {
    elements.verdictDetail.textContent = "Inspect the exact candidate before publishing it.";
    return;
  }
  await runExecution(false);
}

async function replayWorkflow() {
  await runExecution(true);
}

async function runExecution(replay) {
  const button = replay ? elements.replay : elements.execute;
  setBusy(button, true, replay ? "Checking replay…" : "Running native executor…");
  elements.inspect.disabled = true;
  if (!replay) {
    updateTimeline("authorized", "Checking", null);
  }
  try {
    const response = await request(
      `/v1/demo/sessions/${sessionId}/${replay ? "replay" : "execute"}`,
      { method: "POST", timeout: EXECUTION_TIMEOUT_MS },
    );
    renderOutcome(response, replay);
    await loadReceipts();
  } catch (error) {
    elements.verdict.textContent = "FAILED";
    elements.verdict.dataset.kind = "denied";
    elements.verdictDetail.textContent = `The native request terminated: ${error.message}`;
    elements.decisionCode.textContent = "execution-unavailable";
  } finally {
    setBusy(
      button,
      false,
      replay
        ? "Replay the completed action"
        : selected === "exact"
          ? "Publish through Auths"
          : "Submit denied case",
    );
    elements.inspect.disabled = false;
  }
}

function renderOutcome(response, replay) {
  const decision = response.decision || {};
  const authorized = decision.class === "authorized";
  const denied = decision.class === "denied";
  elements.verdict.textContent = replay
    ? "REPLAYED"
    : authorized
      ? "AUTHORIZED"
      : denied
        ? "DENIED"
        : "CHECK REQUIRED";
  elements.verdict.dataset.kind = authorized ? "authorized" : "denied";
  elements.decisionCode.textContent = decision.code || "—";
  elements.decisionStage.textContent = authorized ? "auths-kernel" : previews[selected].stage;
  elements.credentialRequested.textContent = String(response.credential_requests ?? 0);
  elements.mutationCount.textContent = String(response.mutations ?? 0);
  elements.verdictDetail.textContent = replay
    ? "The executor returned the original receipt. It did not push another branch or open another pull request."
    : authorized
      ? "Auths authorized the exact candidate. The executor published the derived branch and opened the deterministic draft PR."
      : "The selected mismatch stopped before a GitHub mutation credential was requested.";

  if (!response.entered_executor) {
    updateTimeline("authorized", "Denied", "denied");
    updateTimeline("branch", "Not attempted", null);
    updateTimeline("pull-request", "Not attempted", null);
    return;
  }
  if (replay || response.execution?.replay === "original-receipt-returned") {
    updateTimeline("replay", "No mutation", "done");
    elements.mutationCount.textContent = "0";
    return;
  }
  updateTimeline("authorized", "Authorized", "done");
  if (response.execution?.branch === "published") {
    updateTimeline("branch", "Published", "done");
  }
  if (response.execution?.pull_request === "opened") {
    updateTimeline("pull-request", "Draft opened", "done");
    completed = true;
    elements.replay.hidden = false;
    elements.githubResult.hidden = false;
    elements.publishedRef.textContent = response.execution.branch_ref;
    elements.publishedSha.textContent = short(response.execution.branch_revision, 13);
    elements.publishedSha.title = response.execution.branch_revision;
    elements.pullRequestLink.href = response.execution.pull_request_url;
    elements.pullRequestLink.textContent =
      `Open draft PR #${response.execution.pull_request_number} ↗`;
    elements.githubState.textContent = "PR confirmed";
  }
}

async function loadReceipts() {
  try {
    const response = await request(`/v1/demo/sessions/${sessionId}/receipts`, {
      timeout: REQUEST_TIMEOUT_MS,
    });
    elements.receiptCount.textContent = String(response.receipts.length);
    elements.receiptJson.textContent = JSON.stringify(response.receipts, null, 2);
  } catch (error) {
    elements.receiptJson.textContent = `Receipts unavailable: ${error.message}`;
  }
}

function applyPreview(variant) {
  const preview = previews[variant];
  elements.verdict.textContent = preview.verdict;
  elements.verdict.dataset.kind = preview.kind;
  elements.verdictDetail.textContent = preview.detail;
  elements.decisionCode.textContent = preview.code;
  elements.decisionStage.textContent = preview.stage;
  elements.credentialRequested.textContent = preview.credential;
  elements.mutationCount.textContent = "0";
  elements.inspect.textContent = "Inspect candidate";
  elements.inspect.disabled = !sessionReady;
  elements.execute.disabled = true;
  elements.execute.textContent =
    variant === "exact" ? "Publish through Auths" : "Submit denied case";
  elements.actionTitle.textContent =
    variant === "exact" ? "Inspect the exact candidate." : "Inspect the changed candidate.";
  elements.actionCopy.textContent =
    "The executor parses the bounded Git bundle without checking out or running candidate code.";
}

function resetExecution() {
  elements.candidateSha.textContent = "not inspected";
  elements.changedPath.textContent = "—";
  elements.directPush.textContent = "not attempted";
  elements.githubResult.hidden = true;
  elements.replay.hidden = true;
  elements.receiptCount.textContent = "0";
  elements.receiptJson.textContent = "Run the workflow to load receipts.";
  [...elements.timeline.children].forEach((item) => {
    item.classList.remove("done", "denied");
    item.querySelector("strong").textContent =
      item.dataset.stage === "candidate" ? "Awaiting inspection" : "—";
  });
}

function updateTimeline(stage, text, state) {
  const item = elements.timeline.querySelector(`[data-stage="${stage}"]`);
  if (!item) return;
  item.classList.remove("done", "denied");
  if (state) item.classList.add(state);
  item.querySelector("strong").textContent = text;
}

function setService(kind, label, ready) {
  elements.serviceState.textContent = label;
  elements.liveState.classList.toggle("ready", ready);
  elements.liveState.classList.toggle("failed", kind === "failed");
}

function setBusy(button, busy, label) {
  button.disabled = busy;
  button.textContent = label;
}

async function request(path, options = {}) {
  const controller = new AbortController();
  const timer = window.setTimeout(
    () => controller.abort(),
    options.timeout || REQUEST_TIMEOUT_MS,
  );
  try {
    const response = await fetch(`${API_BASE}${path}`, {
      method: options.method || "GET",
      headers: options.body ? { "content-type": "application/json" } : undefined,
      body: options.body ? JSON.stringify(options.body) : undefined,
      signal: controller.signal,
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.detail || `HTTP ${response.status}`);
    }
    return body;
  } catch (error) {
    if (error.name === "AbortError") {
      throw new Error("request timed out");
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
