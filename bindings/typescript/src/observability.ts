import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export const AUTHS_EVENT_SCHEMA_VERSION = "auths.telemetry/2";

export type TelemetryStage =
  | "acquisition"
  | "construction"
  | "approval"
  | "signing"
  | "verification"
  | "reservation"
  | "execution"
  | "receipt";

export type TelemetryOutcome = "started" | "succeeded" | "failed" | "denied" | "indeterminate";
export type TelemetryAttribute = string | number | boolean;

export interface AuthsEvent {
  readonly schemaVersion: typeof AUTHS_EVENT_SCHEMA_VERSION;
  readonly name: string;
  readonly timestamp: number;
  readonly correlationId: string;
  readonly operation: string;
  readonly stage: TelemetryStage;
  readonly outcome: TelemetryOutcome;
  readonly durationMs?: number;
  readonly attributes: Readonly<Record<string, TelemetryAttribute>>;
}

export interface TelemetryPort {
  emit(event: AuthsEvent): void | Promise<void>;
}

export interface EventInput {
  readonly name: string;
  readonly timestamp: number;
  readonly correlationId: string;
  readonly operation: string;
  readonly stage: TelemetryStage;
  readonly outcome: TelemetryOutcome;
  readonly durationMs?: number;
  readonly attributes?: Readonly<Record<string, TelemetryAttribute>>;
}

interface NativeEventEngine {
  projectSdkEventV2(input: EventInput): string;
}

/** Parses one bounded event through the Rust-owned operational schema. */
export async function authsEvent(input: EventInput): Promise<AuthsEvent> {
  const engine = await loadPackagedWorkflowEngine() as unknown as NativeEventEngine;
  const parsed: unknown = JSON.parse(engine.projectSdkEventV2(input));
  if (parsed === null || typeof parsed !== "object") {
    throw new TypeError("native telemetry projection is invalid");
  }
  const event = parsed as AuthsEvent;
  return Object.freeze({ ...event, attributes: Object.freeze({ ...event.attributes }) });
}

/** Telemetry is observational: exporter failure can never alter an Auths decision or effect. */
export async function emitAuthsEvent(port: TelemetryPort | undefined, input: EventInput): Promise<void> {
  if (port === undefined) return;
  try {
    await port.emit(await authsEvent(input));
  } catch {
    return;
  }
}

export interface SupportBundleInput {
  readonly sdkVersion: string;
  readonly runtime: string;
  readonly wasm: Readonly<{ readonly authoringAbi: number; readonly identityAbi: number }>;
  readonly capabilities: readonly string[];
  readonly events?: readonly AuthsEvent[];
}

export interface AuthsSupportBundle {
  readonly schemaVersion: "auths.support/1";
  readonly sdkVersion: string;
  readonly runtime: string;
  readonly wasm: Readonly<{ readonly authoringAbi: number; readonly identityAbi: number }>;
  readonly capabilities: readonly string[];
  readonly timeline: readonly AuthsEvent[];
}

/** Builds inert, deterministic operational evidence containing no raw Auths inputs. */
export async function createSupportBundle(input: SupportBundleInput): Promise<AuthsSupportBundle> {
  const capabilities = Object.freeze([...new Set(input.capabilities)].sort());
  const timeline = Object.freeze((await Promise.all(
    [...(input.events ?? [])].map((event) => authsEvent({
      name: event.name,
      timestamp: event.timestamp,
      correlationId: event.correlationId,
      operation: event.operation,
      stage: event.stage,
      outcome: event.outcome,
      ...(event.durationMs === undefined ? {} : { durationMs: event.durationMs }),
      attributes: event.attributes,
    })),
  )).sort((left, right) => left.timestamp - right.timestamp || left.name.localeCompare(right.name)));
  return Object.freeze({
    schemaVersion: "auths.support/1",
    sdkVersion: input.sdkVersion,
    runtime: input.runtime,
    wasm: Object.freeze({ ...input.wasm }),
    capabilities,
    timeline,
  });
}
