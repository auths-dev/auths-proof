// Production should serve the browser and native API from one origin. A
// deployment that deliberately splits them may set this before loading this
// module and must allow the exact origin in its Content Security Policy.
const API_BASE = window.AUTHS_GITHUB_API_BASE || window.location.origin;
const REQUEST_TIMEOUT_MS = 20_000;
const EXECUTION_TIMEOUT_MS = 120_000;

const previews = {
  exact: {
    verdict: "AUTHORIZED",
    kind: "authorized",
    code: "authorized",
    stage: "auths-kernel",
    detail: "Every bound fact matches. Inspection can proceed, then the executor may publish one branch and one draft PR.",
  },
  "prohibited-path": {
    verdict: "DENIED",
    kind: "denied",
    code: "path-explicitly-denied",
    stage: "candidate-inspection",
    detail: "The candidate changes .github/**, which the signed workflow grant explicitly denies.",
  },
  "candidate-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "candidate-bundle-malformed",
    stage: "candidate-inspection",
    detail: "The submitted candidate SHA does not identify the commit in the inspected Git bundle.",
  },
  "repository-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "repository-mismatch",
    stage: "github-evidence",
    detail: "Fresh GitHub evidence does not identify the immutable repository in the workflow grant.",
  },
  "issue-changed": {
    verdict: "DENIED",
    kind: "denied",
    code: "issue-mismatch",
    stage: "github-evidence",
    detail: "Fresh GitHub evidence does not identify the issue in the workflow grant.",
  },
  "base-advanced": {
    verdict: "DENIED",
    kind: "denied",
    code: "base-revision-mismatch",
    stage: "github-evidence",
    detail: "The base ref no longer points to the commit named by the workflow grant.",
  },
  "malformed-bundle": {
    verdict: "DENIED",
    kind: "denied",
    code: "candidate-bundle-malformed",
    stage: "candidate-inspection",
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
  agentPrincipal: document.querySelector("#agent-principal"),
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
let guidedPreview = false;
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
      body: {
        repository: scenario.repository,
        issueNumber: scenario.issue_number,
        baseRef: scenario.base_ref,
        baseRevision: scenario.base_revision,
        allowedPaths: scenario.allowed_paths,
        protectedPaths: scenario.denied_paths,
        expiresInSeconds: 15 * 60,
        branchBudget: 1,
        draftPullRequestBudget: 1,
        agentLabel: "credential-less-demo-agent",
      },
      timeout: REQUEST_TIMEOUT_MS,
    });
    sessionId = session.session_id;
    sessionReady = true;
    elements.repository.textContent = scenario.repository;
    elements.issue.textContent = `#${scenario.issue_number}`;
    elements.base.textContent = short(session.base_revision);
    elements.base.title = session.base_revision;
    elements.target.textContent = session.target_ref;
    elements.agentPrincipal.textContent = short(session.agent_principal, 16);
    elements.agentPrincipal.title = session.agent_principal;
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
    guidedPreview = true;
    elements.nativeState.textContent = "preview only";
    elements.nativeDot.dataset.state = "failed";
    elements.githubState.textContent = "not checked";
    elements.release.textContent = "guided preview · no live execution";
    setService("preview", "guided preview — service offline", false);
    elements.liveState.title = `Native service unavailable: ${error.message}`;
    applyPreview(selected);
  }
}

async function inspectCandidate() {
  if (guidedPreview) {
    renderGuidedPreview(selected);
    return;
  }
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
      body: { kind: "fixture", experiment: selected },
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
      candidate.direct_push?.result === "refused-without-credential"
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
    const pullRequestUrl = safeExternalUrl(response.execution.pull_request_url);
    if (!pullRequestUrl) {
      elements.verdict.textContent = "CHECK REQUIRED";
      elements.verdict.dataset.kind = "denied";
      elements.verdictDetail.textContent =
        "The executor reported a pull request without a valid HTTPS result URL.";
      updateTimeline("pull-request", "Invalid result URL", "denied");
      return;
    }
    updateTimeline("pull-request", "Draft opened", "done");
    completed = true;
    elements.replay.hidden = false;
    elements.githubResult.hidden = false;
    elements.publishedRef.textContent = response.execution.branch_ref;
    elements.publishedSha.textContent = short(response.execution.branch_revision, 13);
    elements.publishedSha.title = response.execution.branch_revision;
    elements.pullRequestLink.href = pullRequestUrl;
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
  elements.verdict.textContent = `EXPECTED ${preview.verdict}`;
  elements.verdict.dataset.kind = preview.kind;
  elements.verdictDetail.textContent =
    `Expected boundary: ${preview.detail} No Auths decision or GitHub action has run.`;
  elements.decisionCode.textContent = preview.code;
  elements.decisionStage.textContent = preview.stage;
  elements.credentialRequested.textContent = "not requested";
  elements.mutationCount.textContent = "0";
  elements.inspect.textContent = guidedPreview
    ? "Explain selected case"
    : "Inspect candidate";
  elements.inspect.disabled = !(sessionReady || guidedPreview);
  elements.execute.disabled = true;
  elements.execute.textContent =
    variant === "exact" ? "Publish through Auths" : "Submit denied case";
  elements.actionTitle.textContent =
    guidedPreview
      ? "Explore this boundary without pretending it ran."
      : variant === "exact"
        ? "Inspect the exact candidate."
        : "Inspect the changed candidate.";
  elements.actionCopy.textContent =
    guidedPreview
      ? "The live executor is offline. The explanation remains interactive, but execution and receipts stay disabled until a native session exists."
      : "The executor parses the bounded Git bundle without checking out or running candidate code.";
}

function renderGuidedPreview(variant) {
  const preview = previews[variant];
  const changedPath = {
    exact: "demo/runs/** (permitted example)",
    "prohibited-path": ".github/** (denied example)",
    "candidate-changed": "declared SHA ≠ bundle commit",
    "repository-changed": "repository identity mismatch",
    "issue-changed": "issue identity mismatch",
    "base-advanced": "base revision mismatch",
    "malformed-bundle": "17-byte invalid bundle",
  }[variant];

  elements.candidateSha.textContent = "not inspected — preview only";
  elements.changedPath.textContent = changedPath;
  elements.changedPath.title = changedPath;
  elements.directPush.textContent = "not attempted — preview only";
  elements.verdict.textContent = `EXPECTED ${preview.verdict}`;
  elements.verdictDetail.textContent =
    `${preview.detail} This explains the selected boundary; it is not a recorded Auths decision.`;
  elements.credentialRequested.textContent = "not requested";
  updateTimeline("candidate", "Explained only", null);
  updateTimeline("authorized", "Not run", null);
  updateTimeline("branch", "Not attempted", null);
  updateTimeline("pull-request", "Not attempted", null);
  updateTimeline("replay", "Not available", null);
  elements.actionTitle.textContent = "Connect the native service to execute it.";
  elements.actionCopy.textContent =
    "A real run must inspect server-owned evidence, return a native decision, and produce signed receipts. Preview mode never fabricates those facts.";
}

function resetExecution() {
  elements.candidateSha.textContent = "not inspected";
  elements.changedPath.textContent = "—";
  elements.directPush.textContent = "not attempted";
  elements.githubResult.hidden = true;
  elements.pullRequestLink.removeAttribute("href");
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
  elements.liveState.classList.toggle("preview", kind === "preview");
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

function safeExternalUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password
      ? url.href
      : null;
  } catch {
    return null;
  }
}
