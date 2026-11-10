import type {
  ApprovalOperationContext,
  ApprovalProvider,
  ApprovalRequest,
  ApprovalResponse,
} from "../workflow/contracts.js";
import { ProviderOperationError } from "../workflow/errors.js";

/** Decision bytes must belong to this isolate, never concurrently shared memory. */
export function approvalBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || !(value.buffer instanceof ArrayBuffer) || value.length !== 32) {
    throw new TypeError("approval digest must contain 32 privately owned bytes");
  }
  return value.slice();
}

function text(value: string): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 4096 || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new TypeError("invalid approval text");
  }
  return value;
}

/** Copy all binding and presentation fields before an asynchronous boundary. */
export function snapshotApproval(request: ApprovalRequest): ApprovalRequest {
  if (!["grant", "action", "principal-status", "grant-status"].includes(request.objectKind) ||
      typeof request.expiresAt !== "bigint" || request.expiresAt < 0n ||
      !Array.isArray(request.display) || request.display.length > 64) {
    throw new TypeError("invalid approval request");
  }
  const display = request.display.map(({ label, value }) => Object.freeze({ label: text(label), value: text(value) }));
  if (display.reduce((bytes, field) => bytes + new TextEncoder().encode(field.label + field.value).length, 0) > 65536) {
    throw new TypeError("approval display exceeds its bound");
  }
  return Object.freeze({
    requestId: text(request.requestId),
    objectKind: request.objectKind,
    transactionDigest: approvalBytes(request.transactionDigest),
    policy: Object.freeze({
      policyId: text(request.policy.policyId),
      evaluatorVersion: text(request.policy.evaluatorVersion),
      configurationDigest: approvalBytes(request.policy.configurationDigest),
    }),
    expiresAt: request.expiresAt,
    display: Object.freeze(display),
  });
}

export function approvalResponse(request: ApprovalRequest, decision: "approved" | "rejected"): ApprovalResponse {
  return Object.freeze({
    requestId: request.requestId,
    transactionDigest: request.transactionDigest.slice(),
    policy: Object.freeze({ ...request.policy, configurationDigest: request.policy.configurationDigest.slice() }),
    decision,
  });
}

export function equalApprovalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let i = 0; i < left.length; i += 1) difference |= left[i]! ^ right[i]!;
  return difference === 0;
}

/** Response fields are compared with owner memory, never the provider's input copy. */
function snapshotResponse(response: ApprovalResponse, request: ApprovalRequest): ApprovalResponse {
  if (response.decision !== "approved" && response.decision !== "rejected") throw new TypeError("invalid approval decision");
  const digest = approvalBytes(response.transactionDigest);
  const policyDigest = approvalBytes(response.policy.configurationDigest);
  if (response.requestId !== request.requestId || !equalApprovalBytes(digest, request.transactionDigest) ||
      response.policy.policyId !== request.policy.policyId || response.policy.evaluatorVersion !== request.policy.evaluatorVersion ||
      !equalApprovalBytes(policyDigest, request.policy.configurationDigest)) {
    throw new TypeError("approval response does not match the retained request");
  }
  return approvalResponse(request, response.decision);
}

export function captureApprovalContext(context: ApprovalOperationContext): ApprovalOperationContext {
  const signal = context?.signal;
  if (signal === undefined || typeof signal.addEventListener !== "function" || typeof signal.removeEventListener !== "function") {
    throw new ProviderOperationError("rejected");
  }
  if (signal.aborted) throw new ProviderOperationError("cancelled");
  return Object.freeze({ signal });
}

export function checkApprovalSignal(context: ApprovalOperationContext): void {
  captureApprovalContext(context);
}

/** A provider that ignores abort cannot retain a caller or produce an unhandled late rejection. */
export function callApproval(
  provider: ApprovalProvider,
  input: ApprovalRequest,
  context: ApprovalOperationContext,
): Promise<ApprovalResponse> {
  let owned: ApprovalRequest;
  try {
    context = captureApprovalContext(context);
    owned = snapshotApproval(input);
  } catch (error) {
    return Promise.reject(error instanceof ProviderOperationError ? error : new ProviderOperationError("rejected"));
  }
  return new Promise((resolve, reject) => {
    const abort = () => reject(new ProviderOperationError("cancelled"));
    context.signal.addEventListener("abort", abort, { once: true });
    const finish = () => context.signal.removeEventListener("abort", abort);
    // Install cancellation first, including for a provider that aborts synchronously.
    Promise.resolve().then(() => {
      checkApprovalSignal(context);
      return provider.approve(snapshotApproval(owned), context);
    }).then((response) => {
      finish();
      checkApprovalSignal(context);
      try { resolve(snapshotResponse(response, owned)); }
      catch { reject(new ProviderOperationError("rejected", { causeChain: ["invalid-response"] })); }
    }, (error: unknown) => {
      finish();
      reject(error instanceof ProviderOperationError ? error : new ProviderOperationError("unavailable"));
    }).catch((error: unknown) => {
      finish();
      reject(error instanceof ProviderOperationError ? error : new ProviderOperationError("unavailable"));
    });
  });
}
