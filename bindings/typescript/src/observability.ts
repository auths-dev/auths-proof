export const AUTHS_EVENT_SCHEMA_VERSION = "auths.telemetry/1";

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

const FORBIDDEN_ATTRIBUTE = /(^|[._-])(body|bytes|credential|key|packet|proof|secret|signature|token)($|[._-])/i;
const ALLOWED_ATTRIBUTES = new Set([
  "abi.version",
  "adapter.id",
  "adapter.kind",
  "chunk.size",
  "code",
  "item.count",
  "profile.id",
  "profile.version",
  "runtime.family",
  "stage",
  "work.units",
]);

/** Parses one bounded, low-cardinality, OpenTelemetry-compatible event. */
export function authsEvent(input: EventInput): AuthsEvent {
  if (!Number.isFinite(input.timestamp) || input.timestamp < 0 ||
      input.name.length === 0 || input.name.length > 96 ||
      input.operation.length === 0 || input.operation.length > 96 ||
      input.correlationId.length === 0 || input.correlationId.length > 128) {
    throw new TypeError("Auths telemetry event is outside schema bounds");
  }
  if (input.durationMs !== undefined && (!Number.isFinite(input.durationMs) || input.durationMs < 0)) {
    throw new TypeError("Auths telemetry duration is invalid");
  }
  const attributes: Record<string, TelemetryAttribute> = {};
  const entries = Object.entries(input.attributes ?? {});
  if (entries.length > 32) throw new TypeError("Auths telemetry has too many attributes");
  for (const [key, value] of entries) {
    if (key.length === 0 || key.length > 64 || FORBIDDEN_ATTRIBUTE.test(key) ||
        !ALLOWED_ATTRIBUTES.has(key)) {
      throw new TypeError(`Auths telemetry attribute is not safe: ${key}`);
    }
    if (typeof value === "string" && value.length > 256) {
      throw new TypeError(`Auths telemetry attribute is too large: ${key}`);
    }
    if (typeof value === "number" && !Number.isFinite(value)) {
      throw new TypeError(`Auths telemetry attribute is invalid: ${key}`);
    }
    attributes[key] = value;
  }
  return Object.freeze({
    schemaVersion: AUTHS_EVENT_SCHEMA_VERSION,
    name: input.name,
    timestamp: input.timestamp,
    correlationId: input.correlationId,
    operation: input.operation,
    stage: input.stage,
    outcome: input.outcome,
    ...(input.durationMs === undefined ? {} : { durationMs: input.durationMs }),
    attributes: Object.freeze(attributes),
  });
}

/** Telemetry is observational: exporter failure can never alter an Auths decision or effect. */
export async function emitAuthsEvent(port: TelemetryPort | undefined, input: EventInput): Promise<void> {
  if (port === undefined) return;
  try {
    await port.emit(authsEvent(input));
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
export function createSupportBundle(input: SupportBundleInput): AuthsSupportBundle {
  const capabilities = Object.freeze([...new Set(input.capabilities)].sort());
  const timeline = Object.freeze([...(input.events ?? [])]
    .map((event) => authsEvent(event))
    .sort((left, right) => left.timestamp - right.timestamp || left.name.localeCompare(right.name)));
  return Object.freeze({
    schemaVersion: "auths.support/1",
    sdkVersion: input.sdkVersion,
    runtime: input.runtime,
    wasm: Object.freeze({ ...input.wasm }),
    capabilities,
    timeline,
  });
}
