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

export class AuthsWorkflowError extends Error {
  readonly code: WorkflowErrorCode;

  constructor(code: WorkflowErrorCode, message: string) {
    super(message);
    this.name = "AuthsWorkflowError";
    this.code = code;
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

  constructor(kind: ProviderFailureKind) {
    super("external provider operation failed");
    this.name = "ProviderOperationError";
    this.kind = kind;
  }
}
