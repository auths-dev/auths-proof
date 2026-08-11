/** Inert diagnostics over an explicitly caller-supplied verifier engine. */
export {
  DiagnosticVerifier,
  createDiagnosticVerifier,
  type DiagnosticResult,
} from "./verifier/diagnostic.js";
export type { PortableWasmEngine } from "./verifier/client.js";

import { SDK_RUNTIME_CONTRACT, evaluateRuntimeContract } from "./runtime-contract.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export interface SdkDiagnosticReport {
  readonly schemaVersion: "auths.diagnostics/1";
  readonly sdkVersion: string;
  readonly runtime: Readonly<{ readonly family: "node" | "browser" | "worker" | "unknown" }>;
  readonly wasm: Readonly<{
    readonly authoringAbi: number;
    readonly identityAbi: number;
    readonly capabilities: readonly string[];
  }>;
  readonly runtimeContract: Readonly<{ readonly satisfied: boolean; readonly missing: readonly string[] }>;
  readonly checks: readonly Readonly<{
    readonly id: "runtime" | "wasm" | "trust" | "profiles" | "adapters";
    readonly status: "pass" | "fail" | "not-configured";
    readonly detail: string;
  }>[];
  readonly adapters: readonly Readonly<{ readonly kind: string; readonly id: string; readonly version: string }>[];
}

export interface DiagnoseSdkOptions {
  readonly expectedVerifierConfiguration?: Uint8Array;
  readonly profiles?: Readonly<Record<string, number>>;
  readonly adapters?: readonly Readonly<{
    readonly kind: string;
    readonly id: string;
    readonly version: string;
  }>[];
}

/** Reports exact package/runtime agreement without accepting authority-bearing data. */
export async function diagnoseSdk(options: DiagnoseSdkOptions = {}): Promise<SdkDiagnosticReport> {
  const engine = await loadPackagedWorkflowEngine() as Awaited<
    ReturnType<typeof loadPackagedWorkflowEngine>
  > & {
    identityAbiVersionV1(): number;
    configurationV1(): Uint8Array;
  };
  const capabilities = SDK_RUNTIME_CONTRACT.capabilities;
  const wasm = Object.freeze({
    authoringAbi: engine.authoringAbiVersionV1(),
    identityAbi: engine.identityAbiVersionV1(),
    capabilities,
  });
  const runtimeContract = evaluateRuntimeContract(wasm);
  const adapters = Object.freeze([...(options.adapters ?? [])]
    .map((adapter) => Object.freeze({ ...adapter }))
    .sort((left, right) => `${left.kind}:${left.id}`.localeCompare(`${right.kind}:${right.id}`)));
  const trust = options.expectedVerifierConfiguration;
  const configuredProfiles = options.profiles;
  const profileMatches = configuredProfiles === undefined
    ? undefined
    : Object.entries(configuredProfiles).every(
      ([id, version]) => (SDK_RUNTIME_CONTRACT.profiles as Readonly<Record<string, number>>)[id] === version,
    );
  const checks: SdkDiagnosticReport["checks"] = Object.freeze([
    Object.freeze({ id: "runtime", status: runtimeFamily() === "unknown" ? "fail" : "pass", detail: runtimeFamily() }),
    Object.freeze({ id: "wasm", status: runtimeContract.satisfied ? "pass" : "fail", detail: runtimeContract.satisfied ? "exact runtime contract" : runtimeContract.missing.join(",") }),
    Object.freeze({
      id: "trust",
      status: trust === undefined ? "not-configured" : equalBytes(trust, engine.configurationV1()) ? "pass" : "fail",
      detail: trust === undefined ? "not supplied" : "exact verifier configuration",
    }),
    Object.freeze({
      id: "profiles",
      status: profileMatches === undefined ? "not-configured" : profileMatches ? "pass" : "fail",
      detail: configuredProfiles === undefined ? "not supplied" : `${Object.keys(configuredProfiles).length} configured`,
    }),
    Object.freeze({ id: "adapters", status: adapters.length === 0 ? "not-configured" : "pass", detail: `${adapters.length} declared` }),
  ]);
  return Object.freeze({
    schemaVersion: "auths.diagnostics/1",
    sdkVersion: SDK_RUNTIME_CONTRACT.sdkVersion,
    runtime: Object.freeze({ family: runtimeFamily() }),
    wasm,
    runtimeContract,
    checks,
    adapters,
  });
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (!(left instanceof Uint8Array) || left.length !== right.length) return false;
  let different = 0;
  for (let index = 0; index < left.length; index += 1) {
    different |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return different === 0;
}

function runtimeFamily(): SdkDiagnosticReport["runtime"]["family"] {
  const globals = globalThis as typeof globalThis & {
    readonly process?: Readonly<{ readonly versions?: Readonly<{ readonly node?: string }> }>;
    readonly importScripts?: unknown;
    readonly document?: unknown;
  };
  if (globals.process?.versions?.node !== undefined) return "node";
  if (typeof globals.importScripts === "function" && globals.document === undefined) return "worker";
  if (globals.document !== undefined) return "browser";
  return "unknown";
}
