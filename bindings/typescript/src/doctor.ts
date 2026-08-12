import { SDK_RUNTIME_CONTRACT } from "./runtime-contract.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export type DoctorMode = "development" | "production" | "unconfigured";
export type DoctorState = "in-memory" | "file-backed" | "durable" | "unconfigured";

export interface DoctorOptions {
  readonly mode?: DoctorMode;
  readonly state?: DoctorState;
}

export interface DoctorReport {
  readonly sdkVersion: string;
  readonly runtime: string;
  readonly portableAbi: Readonly<{
    readonly authoring: number;
    readonly identity: number;
    readonly compatible: boolean;
  }>;
  readonly semanticSubject: "packaged-exact" | "incompatible";
  readonly profiles: readonly string[];
  readonly mode: DoctorMode;
  readonly state: DoctorState;
  readonly status: "ready" | "incompatible";
  readonly warnings: readonly string[];
}

export async function doctor(options: DoctorOptions = {}): Promise<DoctorReport> {
  const engine = await loadPackagedWorkflowEngine() as Awaited<
    ReturnType<typeof loadPackagedWorkflowEngine>
  > & { identityAbiVersionV1(): number };
  const authoring = engine.authoringAbiVersionV1();
  const identity = engine.identityAbiVersionV1();
  const compatible = authoring === SDK_RUNTIME_CONTRACT.authoringAbi &&
    identity === SDK_RUNTIME_CONTRACT.identityAbi;
  const mode = options.mode ?? "unconfigured";
  const state = options.state ?? "unconfigured";
  return Object.freeze({
    sdkVersion: SDK_RUNTIME_CONTRACT.sdkVersion,
    runtime: runtimeLabel(),
    portableAbi: Object.freeze({ authoring, identity, compatible }),
    semanticSubject: compatible ? "packaged-exact" : "incompatible",
    profiles: Object.freeze(Object.entries(SDK_RUNTIME_CONTRACT.profiles)
      .map(([name, version]) => `${name.replace("auths.", "")}/${version}`)),
    mode,
    state,
    status: compatible ? "ready" : "incompatible",
    warnings: doctorWarnings(mode, state),
  });
}

export function renderDoctor(report: DoctorReport): string {
  const abi = report.portableAbi.compatible
    ? `compatible (authoring/${report.portableAbi.authoring}, identity/${report.portableAbi.identity})`
    : `incompatible (authoring/${report.portableAbi.authoring}, identity/${report.portableAbi.identity})`;
  return [
    `Auths SDK        ${report.sdkVersion}`,
    `Runtime          ${report.runtime}`,
    `Portable ABI     ${abi}`,
    `Semantic subject ${report.semanticSubject}`,
    `Profiles         ${report.profiles.join(", ")}`,
    `Mode             ${report.mode}`,
    `State            ${report.state}`,
    `Status           ${report.status} with ${report.warnings.length} warning${report.warnings.length === 1 ? "" : "s"}`,
    ...report.warnings.map((warning) => `Warning          ${warning}`),
  ].join("\n");
}

function doctorWarnings(mode: DoctorMode, state: DoctorState): readonly string[] {
  const warnings: string[] = [];
  if (mode === "development") warnings.push("development custody and trust are not production");
  if (mode === "unconfigured") warnings.push("application composition is not configured");
  if (state === "in-memory") warnings.push("in-memory state is not production durable");
  if (state === "file-backed") warnings.push("file-backed state is single-machine only");
  if (state === "unconfigured") warnings.push("durable state is not configured");
  return Object.freeze(warnings);
}

function runtimeLabel(): string {
  const runtime = globalThis as typeof globalThis & {
    readonly process?: {
      readonly versions?: { readonly node?: string };
      readonly platform?: string;
      readonly arch?: string;
    };
    readonly document?: unknown;
  };
  const node = runtime.process?.versions?.node;
  if (node !== undefined) {
    return `Node ${bounded(node)} / ${bounded(runtime.process?.platform ?? "unknown")} ${bounded(runtime.process?.arch ?? "unknown")}`;
  }
  return runtime.document === undefined ? "Web Worker" : "Browser";
}

function bounded(value: string): string {
  return value.replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 64) || "unknown";
}
