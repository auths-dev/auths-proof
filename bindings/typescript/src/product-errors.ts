import type { ERROR_REGISTRY } from "./generated/error-registry.js";
import {
  ERROR_RUNTIME_DEFINITIONS,
  UNRECOGNIZED_CODE,
} from "./generated/error-registry-runtime.js";

type Definition = (typeof ERROR_REGISTRY.definitions)[number];
type RuntimeDefinition = (typeof ERROR_RUNTIME_DEFINITIONS)[number];

export type KnownAuthsErrorCode = Definition["code"];
/** @internal Historical source spelling retained only for private modules. */
export type AuthsErrorCode = KnownAuthsErrorCode;
export type ErrorFamily = Definition["family"];

/**
 * Answers *may I retry?* — `auths_errors::RetryClass`.
 *
 * This is not the same question as {@link NextCall}, which answers *what should
 * I call next?*. The two shared an identifier once; they never will again.
 */
export type RetryClass = Definition["outcomes"][number]["retry"];

/**
 * Answers *did the real-world effect happen?* — `auths_errors::EffectState`.
 *
 * Exactly three members, owned by Rust. `possible` means WE DO NOT KNOW: a
 * caller who reads it must reconcile before retrying. There is no fourth value
 * and no second spelling; a code this build does not recognize fails closed to
 * `possible`, never to `not-applied`.
 */
export type EffectState = Definition["outcomes"][number]["effect"];
export type RecommendedAction = Definition["recommendedAction"];
export type ProductStage = Definition["stages"][number] | typeof UNRECOGNIZED_CODE.stages[number];

/**
 * Rust's classification of one stable code, projected from the generated
 * registry. TypeScript never recomputes a classification and never mints a
 * code: an unrecognized code takes the generated fail-closed answer.
 */
export interface CodeClassification {
  /** False when this build's registry does not contain the code. */
  readonly known: boolean;
  readonly family: ErrorFamily;
  readonly operation: string;
  readonly stage: string;
  readonly retry: RetryClass;
  readonly effect: EffectState;
  readonly recommendedAction: RecommendedAction;
}

/**
 * Classifies one stable code exactly as `auths_errors::classify` does.
 *
 * When a definition permits several outcomes the dominant one is reported —
 * `possible` over `applied` over `not-applied` — because a caller who must
 * reconcile has strictly more work than one who must not repeat.
 */
export function classifyErrorCode(code: string): CodeClassification {
  const definition = definitions.get(code);
  if (definition === undefined) {
    return Object.freeze({
      known: false,
      family: UNRECOGNIZED_CODE.family,
      operation: UNRECOGNIZED_CODE.operation,
      stage: UNRECOGNIZED_CODE.stages[0],
      retry: UNRECOGNIZED_CODE.retry,
      effect: UNRECOGNIZED_CODE.effect,
      recommendedAction: UNRECOGNIZED_CODE.recommendedAction,
    });
  }
  let dominant: Readonly<{ retry: RetryClass; effect: EffectState }> = definition.outcomes[0]!;
  for (const outcome of definition.outcomes) {
    if (effectRank(outcome.effect) > effectRank(dominant.effect)) dominant = outcome;
  }
  return Object.freeze({
    known: true,
    family: definition.family,
    operation: definition.operation,
    stage: definition.stages[0],
    retry: dominant.retry,
    effect: dominant.effect,
    recommendedAction: definition.recommendedAction,
  });
}

function effectRank(effect: EffectState): number {
  return effect === "possible" ? 2 : effect === "applied" ? 1 : 0;
}
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

export interface AuthsIssue {
  readonly schema: "auths.error/1";
  readonly family: ErrorFamily;
  readonly code: KnownAuthsErrorCode;
  readonly operation: string;
  readonly stage: string;
  readonly summary: string;
  readonly correlationId: string;
  readonly retry: RetryClass;
  readonly effect: EffectState;
  readonly enteredBoundaries: EnteredBoundaries;
  readonly recommendedAction: RecommendedAction;
  readonly executionReference?: string;
  readonly decisionReference?: string;
  readonly receiptReference?: string;
  readonly causes: readonly CauseCategory[];
}

const definitions = new Map<string, RuntimeDefinition>(
  ERROR_RUNTIME_DEFINITIONS.map((definition) => [definition.code, definition]),
);
// Mirrors auths_errors::parse_token exactly. References and correlation IDs
// include base64url operation identifiers, so ASCII uppercase is valid even
// though registered error codes themselves remain lowercase registry values.
const token = /^[A-Za-z0-9][A-Za-z0-9._:/-]*$/;
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

let constructAuthsError: (details: AuthsIssue) => AuthsError;

export class AuthsError extends Error {
  readonly issue: AuthsIssue;

  protected constructor(details: AuthsIssue) {
    super(details.summary);
    this.name = "AuthsError";
    this.issue = details;
  }

  static {
    constructAuthsError = (details) => new AuthsError(details);
  }

  static isKnownCode(code: string): code is KnownAuthsErrorCode {
    return definitions.has(code);
  }

  get code(): KnownAuthsErrorCode { return this.issue.code; }
  get family(): ErrorFamily { return this.issue.family; }
  get retry(): RetryClass { return this.issue.retry; }
  get effect(): EffectState { return this.issue.effect; }
  get recommendedAction(): RecommendedAction { return this.issue.recommendedAction; }
  get executionReference(): string | undefined { return this.issue.executionReference; }

}

/** @internal Rust-envelope decoder used only at trusted SDK boundaries. */
export function parseAuthsErrorEnvelope(input: unknown): AuthsError {
  return constructAuthsError(parseDetails(input));
}

/** @internal Wraps an already registry-derived host issue. */
export function authsErrorFromIssue(details: AuthsIssue): AuthsError {
  return constructAuthsError(details);
}

/** @internal Historical source spelling retained only for private modules. */
export type AuthsErrorDetails = AuthsIssue;

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
  readonly errors: readonly AuthsIssue[];
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
      return error.issue;
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

function parseDetails(input: unknown): AuthsIssue {
  const value = record(input);
  if (value.schema !== "auths.error/1") throw new TypeError("unsupported Auths error schema");
  const code = parseToken(value.code);
  const definition = definitions.get(code);
  if (definition === undefined) throw new TypeError("unknown Auths error code");
  if (parseToken(value.family) !== definition.family) throw new TypeError("Auths error family does not match its registry entry");
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
  const enteredBoundaries = parseEntered(value.entered);
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
  const terminalIntegrityFailure = value.code === "core.terminal-receipt-integrity-failed" &&
    retry === "never" && recommendedAction === "contact-support" &&
    executionReference !== undefined && enteredBoundaries.provider;
  if (effect === "possible" && !terminalIntegrityFailure &&
      (retry !== "unknown" || recommendedAction !== "resume-and-reconcile" ||
       executionReference === undefined || !enteredBoundaries.provider || receiptReference !== undefined)) {
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
    enteredBoundaries,
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

function parseEntered(input: unknown): EnteredBoundaries {
  const value = record(input);
  exactKeys(value, ["approval", "signer", "state", "credential", "provider"]);
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

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): void {
  const keys = Object.keys(value);
  if (keys.length !== expected.length || expected.some((key) => !Object.hasOwn(value, key))) {
    throw new TypeError("Auths error envelope has unknown or missing fields");
  }
}

function array(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) throw new TypeError("Auths error causes must be an array");
  return value;
}

function boolean(value: unknown): boolean {
  if (typeof value !== "boolean") throw new TypeError("Auths error boundary state must be boolean");
  return value;
}
