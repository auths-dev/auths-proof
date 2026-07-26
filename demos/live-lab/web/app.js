import { loadAuths } from "./vendor/index.js";
import {
  configurationState,
  formatNumber,
  hex,
  sha256,
  short,
} from "./lab-core.js";

const state = {
  auths: null,
  scenario: null,
  activeVariant: "valid",
  inputs: new Map(),
  result: null,
  digest: null,
};

const elements = {
  appStatus: document.querySelector("#app-status"),
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
  developerToggle: document.querySelector("#developer-toggle"),
  developerPanel: document.querySelector("#developer-panel"),
};

async function fetchBytes(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`could not load ${path}`);
  return new Uint8Array(await response.arrayBuffer());
}

function activeVariant() {
  return state.scenario.variants.find(
    (variant) => variant.id === state.activeVariant,
  );
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
  const digest = await sha256(result.resultCbor);
  state.result = result;
  state.digest = digest;
  renderResult({ proof, action, context, result, digest, variant });
  elements.appStatus.textContent = "ready";
}

function renderResult({ proof, action, context, result, digest, variant }) {
  elements.verdict.textContent = result.kind.toUpperCase();
  elements.verdict.dataset.kind = result.kind;
  elements.verdictCode.textContent = result.code;
  elements.verdictStage.textContent = result.stage;
  elements.parity.textContent =
    digest === variant.native.result_sha256 ? "MATCH" : "MISMATCH";
  elements.parity.dataset.match =
    digest === variant.native.result_sha256 ? "yes" : "no";
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
      variant: variant.id,
      proof_bytes: proof.length,
      action_bytes: action.length,
      context_bytes: context.length,
      browser_result_sha256: digest,
      native_result_sha256: variant.native.result_sha256,
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
  elements.actionDigest.textContent = short(
    scenario.action.canonical_sha256,
    16,
  );
  elements.proofDigest.textContent = short(scenario.proof.proof_sha256, 16);
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
    });
  });
}

function updateConnection() {
  elements.connectionStatus.textContent = navigator.onLine ? "online" : "offline";
  elements.connectionStatus.dataset.online = navigator.onLine ? "yes" : "no";
}

async function boot() {
  updateConnection();
  window.addEventListener("online", updateConnection);
  window.addEventListener("offline", updateConnection);
  elements.verifyButton.addEventListener("click", verify);
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
  renderScenario();
  await verify();
}

boot().catch((error) => {
  elements.appStatus.textContent = "failed closed";
  elements.verdict.textContent = "UNAVAILABLE";
  elements.verdict.dataset.kind = "indeterminate";
  elements.tourCopy.textContent = error.message;
  console.error(error);
});
