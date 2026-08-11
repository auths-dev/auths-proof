export type WorkflowErrorCode =
  | "disposed"
  | "invalid-provider"
  | "invalid-principal"
  | "invalid-agent-name"
  | "invalid-profile"
  | "invalid-authority-source"
  | "authority-source-failed"
  | "trusted-context-source-failed"
  | "invalid-trusted-context"
  | "invalid-authority"
  | "authority-mismatch"
  | "invalid-delegation"
  | "delegation-expanded"
  | "configuration-mismatch"
  | "approval-policy-mismatch"
  | "approval-failed"
  | "approval-cancelled"
  | "approval-timeout"
  | "approval-unsupported"
  | "approval-rejected"
  | "approval-response-mismatch"
  | "signer-failed"
  | "signer-rejected"
  | "signer-cancelled"
  | "signer-timeout"
  | "signer-unsupported"
  | "signer-response-mismatch"
  | "transaction-expired"
  | "transaction-consumed";

export type ErrorFamily =
  | "configuration"
  | "authority"
  | "approval"
  | "custody"
  | "provider"
  | "transaction";

export type RetryClass = "never" | "safe" | "conditional" | "unknown";
export type EffectState = "none" | "possible" | "occurred";

export interface ErrorContext {
  readonly operation?: string;
  readonly stage?: string;
  readonly correlationId?: string;
  readonly retry?: RetryClass;
  readonly effect?: EffectState;
  readonly remediation?: Readonly<{ readonly action: string; readonly reference?: string }>;
  readonly causeChain?: readonly string[];
}

export class AuthsWorkflowError extends Error {
  readonly code: WorkflowErrorCode;
  readonly family: ErrorFamily;
  readonly operation: string;
  readonly stage: string;
  readonly correlationId: string | undefined;
  readonly retry: RetryClass;
  readonly effect: EffectState;
  readonly remediation: ErrorContext["remediation"];
  readonly causeChain: readonly string[];

  constructor(code: WorkflowErrorCode, message: string, context: ErrorContext = {}) {
    super(message);
    this.name = "AuthsWorkflowError";
    this.code = code;
    this.family = workflowErrorFamily(code);
    this.operation = safeToken(context.operation, "workflow");
    this.stage = safeToken(context.stage, "unknown");
    this.correlationId = safeOptionalToken(context.correlationId);
    this.retry = context.retry ?? workflowRetry(code);
    this.effect = context.effect ?? "none";
    this.remediation = safeRemediation(context.remediation);
    this.causeChain = safeCauseChain(context.causeChain);
  }
}

export type ProviderFailureKind =
  | "unavailable"
  | "rejected"
  | "cancelled"
  | "timeout"
  | "unsupported";

export class ProviderOperationError extends Error {
  readonly kind: ProviderFailureKind;
  readonly family = "provider" as const;
  readonly operation: string;
  readonly stage: string;
  readonly correlationId: string | undefined;
  readonly retry: RetryClass;
  readonly effect: EffectState;
  readonly remediation: ErrorContext["remediation"];
  readonly causeChain: readonly string[];

  constructor(kind: ProviderFailureKind, context: ErrorContext = {}) {
    super("external provider operation failed");
    this.name = "ProviderOperationError";
    this.kind = kind;
    this.operation = safeToken(context.operation, "provider");
    this.stage = safeToken(context.stage, "call");
    this.correlationId = safeOptionalToken(context.correlationId);
    this.retry = context.retry ?? providerRetry(kind);
    this.effect = context.effect ?? (kind === "timeout" || kind === "cancelled" ? "possible" : "none");
    this.remediation = safeRemediation(context.remediation);
    this.causeChain = safeCauseChain(context.causeChain);
  }
}

function workflowErrorFamily(code: WorkflowErrorCode): ErrorFamily {
  if (code.startsWith("approval-")) return "approval";
  if (code.startsWith("signer-")) return "custody";
  if (code.startsWith("authority-") || code.includes("delegation")) return "authority";
  if (code.startsWith("transaction-")) return "transaction";
  if (code.endsWith("-failed") || code === "invalid-provider") return "provider";
  return "configuration";
}

function workflowRetry(code: WorkflowErrorCode): RetryClass {
  if (code.endsWith("-timeout") || code.endsWith("-cancelled")) return "conditional";
  if (code.endsWith("-failed") || code === "trusted-context-source-failed") return "safe";
  return "never";
}

function providerRetry(kind: ProviderFailureKind): RetryClass {
  if (kind === "unavailable") return "safe";
  if (kind === "timeout" || kind === "cancelled") return "conditional";
  return "never";
}

const SAFE_TOKEN = /^[a-z0-9][a-z0-9._:/-]*$/i;

function safeToken(value: string | undefined, fallback: string): string {
  return value !== undefined && value.length <= 128 && SAFE_TOKEN.test(value) ? value : fallback;
}

function safeOptionalToken(value: string | undefined): string | undefined {
  return value === undefined ? undefined : safeToken(value, "redacted");
}

function safeRemediation(value: ErrorContext["remediation"]): ErrorContext["remediation"] {
  if (value === undefined) return undefined;
  return Object.freeze({
    action: safeToken(value.action, "inspect-error"),
    ...(value.reference === undefined
      ? {}
      : { reference: safeToken(value.reference, "redacted") }),
  });
}

function safeCauseChain(value: readonly string[] | undefined): readonly string[] {
  return Object.freeze((value ?? []).slice(0, 8).map((cause) => safeToken(cause, "redacted")));
}
