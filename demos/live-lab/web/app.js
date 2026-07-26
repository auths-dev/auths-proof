import { loadAuths } from "./vendor/index.js";
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
  native: new Map(),
  result: null,
  digest: null,
  session: null,
  apiBase: null,
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
  verifyButton: document.querySelector("#verify-button"),
  nativeButton: document.querySelector("#native-button"),
  sessionStatus: document.querySelector("#session-status"),
  developerToggle: document.querySelector("#developer-toggle"),
  developerPanel: document.querySelector("#developer-panel"),
};

async function fetchBytes(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`could not load ${path}`);
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

async function verify() {
  const variant = activeVariant();
  elements.appStatus.textContent = "verifying";
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
  state.result = result;
  state.digest = digest;
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
}

function renderResult({ proof, action, context, result, digest, variant, native }) {
  elements.verdict.textContent = result.kind.toUpperCase();
  elements.verdict.dataset.kind = result.kind;
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
      source: state.session ? "short-lived native session" : "offline release bundle",
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
  elements.rootPrincipal.textContent = short(
    scenario.proof.root_principal,
    22,
  );
  elements.rootPrincipal.title = scenario.proof.root_principal;
  elements.runtimeOutcome.textContent =
    scenario.runtime.first_execution.outcome.toUpperCase();
  elements.replayOutcome.textContent =
    scenario.runtime.replay.kind.toUpperCase();
  elements.executionCount.textContent =
    scenario.runtime.replay_executor_invocations;
  elements.receiptCount.textContent =
    `${scenario.runtime.decision_receipts} decision · ` +
    `${scenario.runtime.execution_receipts} execution`;
  elements.variants.innerHTML = scenario.variants
    .map(
      (variant) => `
        <button
          class="variant ${variant.id === state.activeVariant ? "active" : ""}"
          data-variant="${variant.id}"
          type="button"
        >
          <span>${variant.title}</span>
          <small>${variant.native.code}</small>
        </button>
      `,
    )
    .join("");
  elements.variants.querySelectorAll("[data-variant]").forEach((button) => {
    button.addEventListener("click", async () => {
      state.activeVariant = button.dataset.variant;
      elements.variants
        .querySelectorAll(".variant")
        .forEach((candidate) => candidate.classList.remove("active"));
      button.classList.add("active");
      await verify();
      updateNativeButton();
    });
  });
}

function updateNativeButton() {
  if (!state.session) {
    elements.nativeButton.disabled = true;
    return;
  }
  if (
    state.activeVariant === "valid" &&
    state.session.validSubmissions >= 2
  ) {
    elements.nativeButton.disabled = true;
    elements.nativeButton.textContent = "Replay blocked";
    return;
  }
  elements.nativeButton.disabled = false;
  elements.nativeButton.textContent =
    state.activeVariant === "valid" &&
    state.session.validSubmissions > 0
      ? "Submit exact replay"
      : "Submit to native runtime";
}

function renderRuntime(display) {
  elements.runtimeOutcome.textContent = display.first;
  elements.replayOutcome.textContent = display.replay;
  elements.executionCount.textContent = display.executorInvocations;
  elements.receiptCount.textContent = display.receiptCount;
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
  const metaResponse = await fetch(`${state.apiBase}/api/v1/meta`, {
    cache: "no-store",
  });
  if (!metaResponse.ok) throw new Error("native service metadata unavailable");
  const meta = await metaResponse.json();
  if (!releaseMatches(meta)) {
    throw new Error("native service release does not match this browser bundle");
  }
  const response = await fetch(`${state.apiBase}/api/v1/sessions`, {
    method: "POST",
    cache: "no-store",
  });
  if (!response.ok) throw new Error("native service could not create a session");
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
  elements.nativeStatus.textContent = "ready";
  elements.nativeStatus.dataset.online = "yes";
  elements.connectionStatus.textContent = session.region;
  elements.sessionStatus.textContent =
    `Live session ${short(session.session_id, 10)} is owned by ${session.region}. ` +
    "Press submit to run the safe executor; the token stays in browser memory and expires in 15 minutes.";
  renderRuntime(runtimeDisplay("valid"));
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
    renderRuntime(
      runtimeDisplay(
        state.activeVariant,
        runtime,
        state.session.validSubmissions,
      ),
    );
    elements.sessionStatus.textContent =
      runtime.response.outcome === "completed"
        ? `Native ${body.region}: proof authorized, safe executor ran once. Submit the exact replay now.`
        : `Native ${body.region}: replay refused by the consumed-challenge ledger; executor remains at one.`;
  } else {
    renderRuntime(runtimeDisplay(state.activeVariant, body.runtime));
    elements.sessionStatus.textContent =
      `Native ${body.region}: ${state.activeVariant} was denied before the runtime executor boundary.`;
  }
  elements.nativeStatus.textContent = "ready";
  updateNativeButton();
}

async function boot() {
  elements.verifyButton.addEventListener("click", verify);
  elements.nativeButton.addEventListener("click", () => {
    executeNative().catch((error) => {
      elements.nativeStatus.textContent = "failed closed";
      elements.nativeStatus.dataset.online = "no";
      elements.sessionStatus.textContent = error.message;
      state.session = null;
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
    fetch("./assets/scenario.json", { cache: "no-store" }).then((response) => {
      if (!response.ok) throw new Error("could not load scenario metadata");
      return response.json();
    }),
    loadAuths({
      moduleUrl: new URL(
        "./vendor/wasm/auths_proof_wasm.js",
        import.meta.url,
      ).href,
    }),
  ]);
  state.scenario = scenario;
  state.auths = auths;
  const inputs = await Promise.all(
    scenario.variants.map(async (variant) => {
      const [proof, action, context] = await Promise.all([
        fetchBytes(variant.files.proof),
        fetchBytes(variant.files.action),
        fetchBytes(variant.files.context),
      ]);
      return [variant.id, { proof, action, context }];
    }),
  );
  state.inputs = new Map(inputs);
  state.native = new Map(
    scenario.variants.map((variant) => [variant.id, variant.native]),
  );
  renderScenario();
  await verify();
  connectNative().catch((error) => {
    elements.nativeStatus.textContent = "offline lab";
    elements.nativeStatus.dataset.online = "no";
    elements.connectionStatus.textContent = "offline";
    elements.sessionStatus.textContent =
      `${error.message}. Browser verification remains fully available.`;
    console.warn(error.message);
  });
}

boot().catch((error) => {
  elements.appStatus.textContent = "failed closed";
  elements.verdict.textContent = "UNAVAILABLE";
  elements.verdict.dataset.kind = "indeterminate";
  elements.tourCopy.textContent = error.message;
  console.error(error);
});
