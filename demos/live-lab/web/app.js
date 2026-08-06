import { loadPortableAuths } from "./vendor/dist/advanced.js";
import {
  configurationState,
  formatNumber,
  hex,
  runtimeDisplay,
  sha256,
  short,
} from "./lab-core.js";

const state = {
  auths: null,
  scenario: null,
  activeVariant: "valid",
  inputs: new Map(),
  inputLoads: new Map(),
  native: new Map(),
  result: null,
  digest: null,
  session: null,
  apiBase: null,
  runtime: new Map(),
  runtimeMessages: new Map(),
  connectionError: null,
  initializationError: null,
  verificationRun: 0,
  resultVariant: null,
};

const elements = {
  appStatus: document.querySelector("#app-status"),
  nativeStatus: document.querySelector("#native-status"),
  configStatus: document.querySelector("#config-status"),
  connectionStatus: document.querySelector("#connection-status"),
  actionDigest: document.querySelector("#action-digest"),
  proofDigest: document.querySelector("#proof-digest"),
  rootPrincipal: document.querySelector("#root-principal"),
  variants: document.querySelector("#variants"),
  verdict: document.querySelector("#verdict"),
  verdictSummary: document.querySelector("#verdict-summary"),
  verdictCode: document.querySelector("#verdict-code"),
  verdictStage: document.querySelector("#verdict-stage"),
  parity: document.querySelector("#parity"),
  requiredConfig: document.querySelector("#required-config"),
  executedConfig: document.querySelector("#executed-config"),
  metrics: document.querySelector("#metrics"),
  runtimeOutcome: document.querySelector("#runtime-outcome"),
  replayOutcome: document.querySelector("#replay-outcome"),
  executionCount: document.querySelector("#execution-count"),
  receiptCount: document.querySelector("#receipt-count"),
  developerBytes: document.querySelector("#developer-bytes"),
  tourCopy: document.querySelector("#tour-copy"),
  nativeButton: document.querySelector("#native-button"),
  sessionStatus: document.querySelector("#session-status"),
  developerToggle: document.querySelector("#developer-toggle"),
  developerPanel: document.querySelector("#developer-panel"),
};

async function fetchWithRetry(path, options = {}, attempts = 2) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(path, { ...options, cache: "no-store" });
      if (!response.ok) throw new Error(`could not load ${path}`);
      return response;
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    }
  }
  throw lastError;
}

async function fetchBytes(path) {
  const response = await fetchWithRetry(path);
  return new Uint8Array(await response.arrayBuffer());
}

function decodeBase64Url(value) {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(
    normalized.length + ((4 - (normalized.length % 4)) % 4),
    "=",
  );
  const decoded = atob(padded);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function activeVariant() {
  return state.scenario.variants.find(
    (variant) => variant.id === state.activeVariant,
  );
}

function activeNative() {
  return state.native.get(state.activeVariant) ?? activeVariant().native;
}

async function loadVariantInputs(variant) {
  if (state.inputs.has(variant.id)) return;
  const pending = state.inputLoads.get(variant.id);
  if (pending) return pending;
  const load = Promise.all([
    fetchBytes(variant.files.proof),
    fetchBytes(variant.files.action),
    fetchBytes(variant.files.context),
  ])
    .then(([proof, action, context]) => {
      state.inputs.set(variant.id, { proof, action, context });
    })
    .finally(() => {
      state.inputLoads.delete(variant.id);
    });
  state.inputLoads.set(variant.id, load);
  return load;
}

function variantPresentation(variant) {
  const presentations = {
    valid: {
      title: "Exact request",
      detail: "Nothing changed after authorization",
    },
    "tampered-action": {
      title: "Request changed",
      detail: "The MCP request bytes changed",
    },
    "tampered-proof": {
      title: "Permission changed",
      detail: "The signed proof no longer matches",
    },
    "wrong-configuration": {
      title: "Verifier policy changed",
      detail: "The required configuration differs",
    },
  };
  return (
    presentations[variant.id] ?? {
      title: variant.title,
      detail: variant.description,
    }
  );
}

function resultSummary(result) {
  const summaries = {
    authorized: "The proof authorizes this exact request.",
    "malformed-proof":
      "The request no longer matches the evidence that was signed.",
    "action-body-mismatch":
      "The permission and request describe different actions.",
    "verifier-configuration-mismatch":
      "The verifier requirements differ from the signed proof.",
  };
  return (
    summaries[result.code] ??
    (result.kind === "authorized"
      ? "Every required authorization check completed."
      : "The request was denied before execution.")
  );
}

async function verify() {
  const variant = activeVariant();
  const run = ++state.verificationRun;
  elements.appStatus.textContent = "verifying";
  state.result = null;
  state.digest = null;
  state.resultVariant = null;
  updateNativeButton();
  const inputs = state.inputs.get(variant.id);
  if (inputs === undefined) {
    throw new Error(`variant ${variant.id} was not preloaded`);
  }
  const { proof, action, context } = inputs;
  const result = state.auths.verify(proof, action, context);
  const [digest, actionDigest, proofDigest] = await Promise.all([
    sha256(result.resultCbor),
    sha256(action),
    sha256(proof),
  ]);
  if (run !== state.verificationRun) return;
  state.result = result;
  state.digest = digest;
  state.resultVariant = variant.id;
  elements.actionDigest.textContent = short(actionDigest, 16);
  elements.proofDigest.textContent = short(proofDigest, 16);
  renderResult({
    proof,
    action,
    context,
    result,
    digest,
    variant,
    native: activeNative(),
  });
  elements.appStatus.textContent = "ready";
  updateNativeButton();
}

function renderResult({
  proof,
  action,
  context,
  result,
  digest,
  variant,
  native,
}) {
  elements.verdict.textContent = result.kind.toUpperCase();
  elements.verdict.dataset.kind = result.kind;
  elements.verdictSummary.textContent = resultSummary(result);
  elements.verdictCode.textContent = result.code;
  elements.verdictStage.textContent = result.stage;
  elements.parity.textContent =
    digest === native.result_sha256 ? "MATCH" : "MISMATCH";
  elements.parity.dataset.match =
    digest === native.result_sha256 ? "yes" : "no";
  const required = result.requiredConfiguration
    ? hex(result.requiredConfiguration)
    : undefined;
  const executed = hex(result.localConfiguration);
  elements.requiredConfig.textContent = short(required, 18);
  elements.requiredConfig.title = required ?? "unavailable";
  elements.executedConfig.textContent = short(executed, 18);
  elements.executedConfig.title = executed;
  const config = configurationState(required, executed);
  elements.configStatus.textContent = config;
  elements.configStatus.dataset.match = config === "match" ? "yes" : "no";
  elements.tourCopy.textContent = variant.description;
  elements.metrics.innerHTML = Object.entries(result.metrics)
    .map(
      ([name, value]) =>
        `<div><span>${label(name)}</span><strong>${formatNumber(value)}</strong></div>`,
    )
    .join("");
  elements.developerBytes.textContent = JSON.stringify(
    {
      source: state.session
        ? "short-lived native session"
        : "offline release bundle",
      release_id: state.scenario.release.id,
      region: state.session?.region,
      session_expires_at: state.session?.expiresAt,
      variant: variant.id,
      proof_bytes: proof.length,
      action_bytes: action.length,
      context_bytes: context.length,
      browser_result_sha256: digest,
      native_result_sha256: native.result_sha256,
      required_configuration: required,
      executed_configuration: executed,
      result_cbor_prefix: hex(result.resultCbor.slice(0, 48)),
    },
    null,
    2,
  );
}

function label(value) {
  return value
    .replace(/[A-Z]/g, (letter) => ` ${letter}`)
    .replace(/^./, (letter) => letter.toUpperCase());
}

function renderScenario() {
  const scenario = state.scenario;
  elements.rootPrincipal.textContent = short(scenario.proof.root_principal, 22);
  elements.rootPrincipal.title = scenario.proof.root_principal;
  const controls = new Set(
    Array.from(elements.variants.querySelectorAll("[data-variant]")).map(
      (button) => button.dataset.variant,
    ),
  );
  for (const variant of scenario.variants) {
    if (!controls.has(variant.id)) {
      throw new Error(`missing static control for variant ${variant.id}`);
    }
  }
  updateVariantSelection();
}

function updateVariantSelection() {
  elements.variants.querySelectorAll("[data-variant]").forEach((button) => {
    const selected = button.dataset.variant === state.activeVariant;
    button.classList.toggle("active", selected);
    button.setAttribute("aria-pressed", String(selected));
  });
}

async function selectVariant(variantId) {
  state.activeVariant = variantId;
  updateVariantSelection();
  const button = elements.variants.querySelector(
    `[data-variant="${variantId}"]`,
  );
  const title = button?.querySelector("span")?.textContent ?? "Case";
  if (state.initializationError) {
    elements.tourCopy.textContent =
      `${title} selected. The browser verifier is unavailable; reload to try again.`;
    return;
  }
  if (!state.scenario || !state.auths) {
    elements.tourCopy.textContent =
      `${title} selected. Preparing the browser verifier.`;
    elements.verdictSummary.textContent =
      `Loading the ${title.toLowerCase()} evidence.`;
    return;
  }
  const variant = activeVariant();
  if (!state.inputs.has(variant.id)) {
    elements.tourCopy.textContent =
      `${title} selected. Loading its proof evidence.`;
    elements.verdictSummary.textContent =
      `Loading the ${title.toLowerCase()} evidence.`;
    await loadVariantInputs(variant);
    if (state.activeVariant !== variantId) return;
  }
  await verify();
  renderActiveRuntime();
  updateNativeButton();
}

function bindVariantControls() {
  elements.variants.querySelectorAll("[data-variant]").forEach((button) => {
    button.addEventListener("click", () => {
      selectVariant(button.dataset.variant).catch(showVerifierError);
    });
  });
}

function updateNativeButton() {
  if (!state.session) {
    elements.nativeButton.disabled = true;
    elements.nativeButton.textContent = state.connectionError
      ? "Native runtime unavailable"
      : "Run selected case in native Rust";
    return;
  }
  if (!state.result || state.resultVariant !== state.activeVariant) {
    elements.nativeButton.disabled = true;
    elements.nativeButton.textContent = "Verify selected case first";
    return;
  }
  if (state.activeVariant === "valid" && state.session.validSubmissions >= 2) {
    elements.nativeButton.disabled = true;
    elements.nativeButton.textContent = "Replay blocked";
    return;
  }
  elements.nativeButton.disabled = false;
  elements.nativeButton.textContent =
    state.activeVariant === "valid" && state.session.validSubmissions > 0
      ? "Replay exact request"
      : state.activeVariant === "valid"
        ? "Run in native Rust"
        : "Check denial in native Rust";
}

function renderRuntime(display) {
  elements.runtimeOutcome.textContent = display.first;
  elements.replayOutcome.textContent = display.replay;
  elements.executionCount.textContent = display.executorInvocations;
  elements.receiptCount.textContent = display.receiptCount;
}

function defaultSessionStatus() {
  if (state.connectionError) {
    return `${state.connectionError}. Browser verification remains fully available.`;
  }
  if (!state.session) {
    return state.result
      ? "Browser result is ready. Connecting the optional native Rust check."
      : "Browser verification runs first. Native Rust becomes available after it connects.";
  }
  return (
    `Live session ${short(state.session.id, 10)} is owned by ${state.session.region}. ` +
    "Run the selected evidence through the native verifier."
  );
}

function renderActiveRuntime() {
  renderRuntime(
    state.runtime.get(state.activeVariant) ??
      runtimeDisplay(state.activeVariant),
  );
  elements.sessionStatus.textContent =
    state.runtimeMessages.get(state.activeVariant) ?? defaultSessionStatus();
}

function apiBase() {
  if (["127.0.0.1", "localhost"].includes(location.hostname)) {
    return "http://127.0.0.1:8080";
  }
  return document
    .querySelector('meta[name="auths-api"]')
    .content.replace(/\/$/, "");
}

function releaseMatches(meta) {
  const release = state.scenario.release;
  return (
    meta.schema === "auths-live-service/v1" &&
    meta.release_id === release.id &&
    meta.protocol_major === release.protocol_major &&
    meta.portable_abi === release.portable_abi &&
    meta.verifier_configuration === release.verifier_configuration &&
    meta.wasm_sha256 === release.wasm_sha256
  );
}

async function connectNative() {
  state.apiBase = apiBase();
  elements.nativeStatus.textContent = "checking release";
  elements.sessionStatus.textContent =
    "Browser result is ready. Connecting the optional native Rust check.";
  const metaResponse = await fetch(`${state.apiBase}/api/v1/meta`, {
    cache: "no-store",
  });
  if (!metaResponse.ok) throw new Error("native service metadata unavailable");
  const meta = await metaResponse.json();
  if (!releaseMatches(meta)) {
    throw new Error(
      "native service release does not match this browser bundle",
    );
  }
  const response = await fetch(`${state.apiBase}/api/v1/sessions`, {
    method: "POST",
    cache: "no-store",
  });
  if (!response.ok)
    throw new Error("native service could not create a session");
  const session = await response.json();
  if (
    session.release_id !== state.scenario.release.id ||
    !Array.isArray(session.variants) ||
    session.variants.length !== 4
  ) {
    throw new Error("native session contract did not match the browser");
  }
  state.inputs = new Map(
    session.variants.map((variant) => [
      variant.id,
      {
        proof: decodeBase64Url(variant.proof),
        action: decodeBase64Url(variant.action),
        context: decodeBase64Url(variant.context),
      },
    ]),
  );
  state.native = new Map(
    session.variants.map((variant) => [variant.id, variant.native]),
  );
  state.session = {
    id: session.session_id,
    token: session.token,
    region: session.region,
    expiresAt: session.expires_at,
    validSubmissions: 0,
  };
  state.connectionError = null;
  elements.nativeStatus.textContent = "ready";
  elements.nativeStatus.dataset.online = "yes";
  elements.connectionStatus.textContent = session.region;
  renderActiveRuntime();
  updateNativeButton();
  await verify();
}

async function executeNative() {
  if (!state.session) return;
  elements.nativeButton.disabled = true;
  elements.nativeStatus.textContent = "executing";
  const response = await fetch(
    `${state.apiBase}/api/v1/sessions/${state.session.id}/execute`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${state.session.token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ variant: state.activeVariant }),
    },
  );
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(body?.error?.message ?? "native execution failed");
  }
  if (
    body.release_id !== state.scenario.release.id ||
    body.variant !== state.activeVariant ||
    body.native.result_sha256 !== state.digest
  ) {
    throw new Error("browser/native parity failed closed");
  }
  if (state.activeVariant === "valid") {
    state.session.validSubmissions += 1;
    const runtime = body.runtime;
    const display = runtimeDisplay(
      state.activeVariant,
      runtime,
      state.session.validSubmissions,
    );
    state.runtime.set(state.activeVariant, display);
    state.runtimeMessages.set(
      state.activeVariant,
      runtime.response.outcome === "completed"
        ? `Native ${body.region}: authorized and executed once. Replay these exact bytes to test enforcement.`
        : `Native ${body.region}: replay refused; the executor remains at one invocation.`,
    );
  } else {
    state.runtime.set(
      state.activeVariant,
      runtimeDisplay(state.activeVariant, body.runtime),
    );
    state.runtimeMessages.set(
      state.activeVariant,
      `Native ${body.region}: denied before the runtime executor boundary.`,
    );
  }
  renderActiveRuntime();
  elements.nativeStatus.textContent = "ready";
  updateNativeButton();
}

async function boot() {
  bindVariantControls();
  elements.nativeButton.addEventListener("click", () => {
    executeNative().catch((error) => {
      elements.nativeStatus.textContent = "failed closed";
      elements.nativeStatus.dataset.online = "no";
      state.connectionError = error.message;
      state.session = null;
      renderActiveRuntime();
      updateNativeButton();
      console.error(error);
    });
  });
  elements.developerToggle.addEventListener("click", () => {
    const hidden = elements.developerPanel.hidden;
    elements.developerPanel.hidden = !hidden;
    elements.developerToggle.setAttribute("aria-expanded", String(hidden));
  });
  const [scenario, auths] = await Promise.all([
    fetchWithRetry("./assets/scenario.json").then((response) =>
      response.json(),
    ),
    // The verifier resolves only the WASM subject vendored beside it; the SDK
    // accepts no caller-selected module or bytes on this path.
    loadPortableAuths(),
  ]);
  state.scenario = scenario;
  state.auths = auths;
  state.native = new Map(
    scenario.variants.map((variant) => [variant.id, variant.native]),
  );
  renderScenario();
  await loadVariantInputs(activeVariant());
  await verify();
  renderActiveRuntime();
  connectNative().catch((error) => {
    state.connectionError = error.message;
    elements.nativeStatus.textContent = "offline lab";
    elements.nativeStatus.dataset.online = "no";
    elements.connectionStatus.textContent = "offline";
    renderActiveRuntime();
    updateNativeButton();
    console.warn(error.message);
  });
}

boot().catch(showVerifierError);

function showVerifierError(error) {
  state.initializationError = error.message;
  elements.appStatus.textContent = "failed closed";
  elements.verdict.textContent = "UNAVAILABLE";
  elements.verdict.dataset.kind = "indeterminate";
  elements.verdictSummary.textContent =
    "The verifier could not process this case, so the demo failed closed.";
  elements.tourCopy.textContent = error.message;
  updateNativeButton();
  console.error(error);
}
