import { ERROR_REGISTRY } from "./generated/error-registry.js";

type Definition = (typeof ERROR_REGISTRY.definitions)[number];

export type AuthsErrorCode = Definition["code"] | (string & {});
export type ErrorFamily = Definition["family"] | "unknown";
export type RetryClass = Definition["outcomes"][number]["retry"];
export type EffectState = Definition["outcomes"][number]["effect"] | "unknown";
export type RecommendedAction = Definition["recommendedAction"];
export type CauseCategory =
  | "cancelled"
  | "conflict"
  | "corrupt-state"
  | "invalid-response"
  | "limit-exceeded"
  | "timeout"
  | "unavailable"
  | "unknown";

export interface EnteredBoundaries {
  readonly approval: boolean;
  readonly signer: boolean;
  readonly state: boolean;
  readonly credential: boolean;
  readonly provider: boolean;
}

export interface AuthsErrorDetails {
  readonly schema: "auths.error/1";
  readonly family: ErrorFamily;
  readonly code: AuthsErrorCode;
  readonly operation: string;
  readonly stage: string;
  readonly summary: string;
  readonly correlationId: string;
  readonly retry: RetryClass;
  readonly effect: EffectState;
  readonly entered: EnteredBoundaries;
  readonly recommendedAction: RecommendedAction;
  readonly executionReference?: string;
  readonly decisionReference?: string;
  readonly receiptReference?: string;
  readonly causes: readonly CauseCategory[];
}

const definitions = new Map<string, Definition>(
  ERROR_REGISTRY.definitions.map((definition) => [definition.code, definition]),
);
const token = /^[a-z0-9][a-z0-9._:/-]*$/;
const causes = new Set<CauseCategory>([
  "cancelled",
  "conflict",
  "corrupt-state",
  "invalid-response",
  "limit-exceeded",
  "timeout",
  "unavailable",
  "unknown",
]);

export class AuthsError extends Error {
  readonly details: AuthsErrorDetails;

  private constructor(details: AuthsErrorDetails) {
    super(details.summary);
    this.name = "AuthsError";
    this.details = details;
  }

  static parse(input: unknown): AuthsError {
    return new AuthsError(parseDetails(input));
  }

  get code(): AuthsErrorCode { return this.details.code; }
  get family(): ErrorFamily { return this.details.family; }
  get retry(): RetryClass { return this.details.retry; }
  get effect(): EffectState { return this.details.effect; }
  get recommendedAction(): RecommendedAction { return this.details.recommendedAction; }
  get executionReference(): string | undefined { return this.details.executionReference; }

  toJSON(): AuthsErrorDetails {
    return this.details;
  }
}

export function isAuthsError(value: unknown): value is AuthsError {
  return value instanceof AuthsError;
}

export function formatAuthsError(error: AuthsError): string {
  return `${error.code}: ${error.message} [effect=${error.effect}, retry=${error.retry}, action=${error.recommendedAction}]`;
}

export function errorReferenceUrl(code: AuthsErrorCode): string {
  return `https://auths.dev/errors/${encodeURIComponent(code)}`;
}

export function causeCategoryFrom(value: unknown): CauseCategory {
  if (typeof DOMException !== "undefined" && value instanceof DOMException && value.name === "AbortError") {
    return "cancelled";
  }
  if (typeof value !== "object" || value === null) return "unknown";
  const candidate = value as { readonly name?: unknown; readonly code?: unknown };
  if (candidate.name === "TimeoutError" || candidate.code === "ETIMEDOUT") return "timeout";
  if (candidate.code === "ECONFLICT") return "conflict";
  if (candidate.code === "E2BIG") return "limit-exceeded";
  if (candidate.code === "ECONNREFUSED" || candidate.code === "ENETUNREACH") return "unavailable";
  return "unknown";
}

export interface SupportBundleInput {
  readonly sdkVersion: string;
  readonly runtimeFamily: string;
  readonly runtimeVersion: string;
  readonly platform: string;
  readonly abiVersion: string;
  readonly semanticSubject: string;
  readonly profiles: readonly string[];
  readonly capabilities: readonly string[];
  readonly errors?: readonly AuthsError[];
}

export interface AuthsSupportBundle {
  readonly schema: "auths.support/2";
  readonly sdkVersion: string;
  readonly runtime: Readonly<{ readonly family: string; readonly version: string; readonly platform: string }>;
  readonly abiVersion: string;
  readonly semanticSubject: string;
  readonly profiles: readonly string[];
  readonly capabilities: readonly string[];
  readonly errors: readonly AuthsErrorDetails[];
}

export function createSupportBundle(input: SupportBundleInput): AuthsSupportBundle {
  const sdkVersion = parseToken(input.sdkVersion);
  const runtimeFamily = parseToken(input.runtimeFamily);
  const runtimeVersion = parseToken(input.runtimeVersion);
  const platform = parseToken(input.platform);
  const abiVersion = parseToken(input.abiVersion);
  const semanticSubject = parseToken(input.semanticSubject);
  const profiles = sortedTokens(input.profiles);
  const capabilities = sortedTokens(input.capabilities);
  const errors = Object.freeze([...(input.errors ?? [])]
    .map((error) => {
      if (!isAuthsError(error)) throw new TypeError("support bundle errors must be AuthsError values");
      return error.toJSON();
    })
    .sort((left, right) => left.code.localeCompare(right.code) || left.correlationId.localeCompare(right.correlationId)));
  return Object.freeze({
    schema: "auths.support/2",
    sdkVersion,
    runtime: Object.freeze({ family: runtimeFamily, version: runtimeVersion, platform }),
    abiVersion,
    semanticSubject,
    profiles,
    capabilities,
    errors,
  });
}

function parseDetails(input: unknown): AuthsErrorDetails {
  const value = record(input);
  if (value.schema !== "auths.error/1") throw new TypeError("unsupported Auths error schema");
  const code = parseToken(value.code);
  const definition = definitions.get(code);
  if (definition === undefined) return parseUnknownDetails(value, code);
  const operation = parseToken(value.operation);
  const stage = parseToken(value.stage);
  const summary = parseText(value.summary);
  const correlationId = parseToken(value.correlationId);
  if (operation !== definition.operation || !definition.stages.includes(stage as never)) {
    throw new TypeError("Auths error operation or stage does not match its registry entry");
  }
  const retry = parseToken(value.retry) as RetryClass;
  const effect = parseToken(value.effect) as EffectState;
  if (!definition.outcomes.some((outcome) => outcome.retry === retry && outcome.effect === effect)) {
    throw new TypeError("Auths error recovery classification is not registered");
  }
  const recommendedAction = parseToken(value.recommendedAction) as RecommendedAction;
  if (recommendedAction !== definition.recommendedAction) {
    throw new TypeError("Auths error remediation does not match its registry entry");
  }
  const entered = parseEntered(value.entered);
  const executionReference = parseReference(value.executionReference);
  const decisionReference = parseReference(value.decisionReference);
  const receiptReference = parseReference(value.receiptReference);
  if ((executionReference !== undefined) !== definition.allowsExecutionReference ||
      (decisionReference !== undefined && !definition.allowsDecisionReference) ||
      (receiptReference !== undefined && !definition.allowsReceiptReference)) {
    throw new TypeError("Auths error contains an unregistered reference");
  }
  if (retry === "safe" && effect !== "not-applied") {
    throw new TypeError("retry-safe Auths errors must be not-applied");
  }
  if (effect === "possible" &&
      (retry !== "unknown" || recommendedAction !== "resume-and-reconcile" ||
       executionReference === undefined || !entered.provider || receiptReference !== undefined)) {
    throw new TypeError("possible Auths effects require explicit reconciliation");
  }
  const rawCauses = array(value.causes);
  if (rawCauses.length > 8) throw new TypeError("Auths error has too many cause categories");
  const parsedCauses = rawCauses.map((cause) => parseToken(cause) as CauseCategory);
  if (parsedCauses.some((cause) => !causes.has(cause))) {
    throw new TypeError("Auths error contains an unknown cause category");
  }
  const base = {
    schema: "auths.error/1" as const,
    family: definition.family,
    code: definition.code,
    operation,
    stage,
    summary,
    correlationId,
    retry,
    effect,
    entered,
    recommendedAction,
    causes: Object.freeze(parsedCauses),
  };
  return Object.freeze({
    ...base,
    ...(executionReference === undefined ? {} : { executionReference }),
    ...(decisionReference === undefined ? {} : { decisionReference }),
    ...(receiptReference === undefined ? {} : { receiptReference }),
  });
}

function parseUnknownDetails(
  value: Record<string, unknown>,
  code: string,
): AuthsErrorDetails {
  parseToken(value.operation);
  parseToken(value.stage);
  parseText(value.summary);
  const correlationId = parseToken(value.correlationId);
  const rawCauses = array(value.causes);
  if (rawCauses.length > 8) throw new TypeError("Auths error has too many cause categories");
  const unknownCauses: readonly CauseCategory[] = rawCauses.length === 0 ? [] : ["unknown"];
  return Object.freeze({
    schema: "auths.error/1",
    family: "unknown",
    code,
    operation: "unknown",
    stage: "unknown",
    summary: "Unknown Auths error code",
    correlationId,
    retry: "unknown",
    effect: "unknown",
    entered: Object.freeze({ approval: false, signer: false, state: false, credential: false, provider: false }),
    recommendedAction: "contact-support",
    causes: Object.freeze(unknownCauses),
  });
}

function parseEntered(input: unknown): EnteredBoundaries {
  const value = record(input);
  return Object.freeze({
    approval: boolean(value.approval),
    signer: boolean(value.signer),
    state: boolean(value.state),
    credential: boolean(value.credential),
    provider: boolean(value.provider),
  });
}

function parseReference(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : parseToken(value);
}

function parseToken(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 128 || !token.test(value)) {
    throw new TypeError("Auths error token is invalid");
  }
  return value;
}

function parseText(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || new TextEncoder().encode(value).length > 256) {
    throw new TypeError("Auths error text is invalid");
  }
  return value;
}

function sortedTokens(values: readonly string[]): readonly string[] {
  if (values.length > 64) throw new TypeError("support bundle list is too large");
  return Object.freeze([...new Set(values.map(parseToken))].sort());
}

function record(value: unknown): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError("Auths error value must be an object");
  }
  return value as Record<string, unknown>;
}

function array(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError("Auths error causes must be an array");
  return value;
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new TypeError("Auths error boundary state must be boolean");
  return value;
}
