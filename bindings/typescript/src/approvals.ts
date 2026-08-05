import {
  type ApprovalPolicyReference,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type ReviewField,
  copyPolicy,
} from "./workflow.js";
import { AuthsWorkflowError, ProviderOperationError } from "./workflow/errors.js";
import { commitCanonical } from "./commitments.js";

export interface ApprovalPolicyOptions {
  readonly policyId?: string;
  readonly evaluatorVersion?: string;
  readonly expiresInSeconds?: number;
  readonly maxUses?: number;
  readonly requirements?: readonly string[];
}

async function buildPolicy(
  mode: string,
  options: ApprovalPolicyOptions = {},
): Promise<ApprovalPolicyReference> {
  const maxUses = options.maxUses ?? 1;
  const expiresInSeconds = options.expiresInSeconds ?? 300;
  if (!Number.isSafeInteger(maxUses) || maxUses < 1 || maxUses > 256) {
    throw new AuthsWorkflowError("invalid-provider", "approval use limit is outside bounds");
  }
  if (
    !Number.isSafeInteger(expiresInSeconds) ||
    expiresInSeconds < 1 ||
    expiresInSeconds > 86_400
  ) {
    throw new AuthsWorkflowError("invalid-provider", "approval expiry is outside bounds");
  }
  const requirements = [...(options.requirements ?? [])].sort();
  if (requirements.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new AuthsWorkflowError("invalid-provider", "approval requirement is invalid");
  }
  const canonical = new TextEncoder().encode(JSON.stringify({
    expiresInSeconds,
    maxUses,
    mode,
    requirements,
  }));
  const commitment = await commitCanonical("auths.approval-policy.v1", canonical);
  return Object.freeze({
    policyId: options.policyId ?? `approval.${mode}`,
    evaluatorVersion: options.evaluatorVersion ?? "1",
    configurationDigest: commitment.digest.slice(),
  });
}

/** Typed, versioned approval-policy builders. */
export const approvalPolicy = Object.freeze({
  grantOnly(options?: ApprovalPolicyOptions) {
    return buildPolicy("grant-only", options);
  },
  everyAction(options?: ApprovalPolicyOptions) {
    return buildPolicy("every-action", options);
  },
  planOnce(options?: ApprovalPolicyOptions) {
    return buildPolicy("plan-once", { ...options, maxUses: options?.maxUses ?? 1 });
  },
  headless(options?: ApprovalPolicyOptions) {
    return buildPolicy("headless", options);
  },
});

export interface BoundedApprovalSessionOptions {
  readonly planCommitment: Uint8Array;
  readonly policy: ApprovalPolicyReference;
  readonly provider: ApprovalProvider;
  readonly expiresAt: bigint;
  readonly maxUses: number;
  readonly display: readonly ReviewField[];
}

/**
 * One finite approval capability bound to one immutable plan commitment.
 * The first transaction is shown to the configured provider; subsequent
 * members are accepted only while the same frozen session remains active.
 */
export class BoundedApprovalSession implements ApprovalProvider, AsyncDisposable {
  readonly #planCommitment: Uint8Array;
  readonly #policy: ApprovalPolicyReference;
  readonly #provider: ApprovalProvider;
  readonly #expiresAt: bigint;
  readonly #maxUses: number;
  readonly #display: readonly ReviewField[];
  #uses = 0;
  #approved = false;
  #disposed = false;

  constructor(options: BoundedApprovalSessionOptions) {
    if (!(options.planCommitment instanceof Uint8Array) || options.planCommitment.length !== 32) {
      throw new AuthsWorkflowError("invalid-provider", "plan commitment must contain 32 bytes");
    }
    if (!Number.isSafeInteger(options.maxUses) || options.maxUses < 1 || options.maxUses > 256) {
      throw new AuthsWorkflowError("invalid-provider", "approval session use limit is outside bounds");
    }
    if (typeof options.provider?.approve !== "function") {
      throw new AuthsWorkflowError("invalid-provider", "approval session provider is missing");
    }
    this.#planCommitment = options.planCommitment.slice();
    this.#policy = copyPolicy(options.policy);
    this.#provider = options.provider;
    this.#expiresAt = options.expiresAt;
    this.#maxUses = options.maxUses;
    this.#display = Object.freeze(options.display.map((field) => Object.freeze({ ...field })));
  }

  get planCommitment(): Uint8Array {
    return this.#planCommitment.slice();
  }

  async approve(request: ApprovalRequest): Promise<ApprovalResponse> {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
    const now = BigInt(Math.floor(Date.now() / 1000));
    if (now > this.#expiresAt || now > request.expiresAt) {
      throw new ProviderOperationError("timeout");
    }
    if (this.#uses >= this.#maxUses) {
      throw new ProviderOperationError("rejected");
    }
    if (
      request.policy.policyId !== this.#policy.policyId ||
      request.policy.evaluatorVersion !== this.#policy.evaluatorVersion ||
      !equalBytes(request.policy.configurationDigest, this.#policy.configurationDigest)
    ) {
      throw new ProviderOperationError("rejected");
    }
    if (!this.#approved) {
      const response = await this.#provider.approve({
        ...request,
        display: Object.freeze([
          ...this.#display,
          Object.freeze({ label: "Plan commitment", value: hex(this.#planCommitment) }),
          ...request.display,
        ]),
      });
      if (response.decision !== "approved") return response;
      if (
        response.requestId !== request.requestId ||
        !equalBytes(response.transactionDigest, request.transactionDigest) ||
        response.policy.policyId !== request.policy.policyId ||
        response.policy.evaluatorVersion !== request.policy.evaluatorVersion ||
        !equalBytes(
          response.policy.configurationDigest,
          request.policy.configurationDigest,
        )
      ) {
        throw new ProviderOperationError("rejected");
      }
      this.#approved = true;
    }
    this.#uses += 1;
    return Object.freeze({
      requestId: request.requestId,
      transactionDigest: request.transactionDigest.slice(),
      policy: copyPolicy(request.policy),
      decision: "approved" as const,
    });
  }

  async dispose(): Promise<void> {
    this.#disposed = true;
    this.#planCommitment.fill(0);
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.dispose();
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
