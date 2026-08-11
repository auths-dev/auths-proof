import {
  type ApprovalPolicy,
  type ApprovalPolicyReference,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type ReviewField,
  copyPolicy,
} from "./workflow.js";
import { AuthsWorkflowError, ProviderOperationError } from "./workflow/errors.js";
import { loadPackagedWorkflowEngine } from "./verifier/wasm.js";

export interface ApprovalPolicyOptions {
  readonly policyId?: string;
  readonly evaluatorVersion?: string;
  readonly expiresInSeconds?: number;
  readonly maxUses?: number;
  readonly requirements?: readonly string[];
}

async function buildPolicy(
  mode: ApprovalPolicy["mode"],
  options: ApprovalPolicyOptions = {},
): Promise<ApprovalPolicy> {
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
  // The commitment decides whether signing proceeds, so its canonical form
  // belongs to auths-author. This binding supplies the fields and nothing else.
  const engine = await loadPackagedWorkflowEngine();
  let configurationDigest: Uint8Array;
  try {
    configurationDigest = engine.commitApprovalPolicyV1(
      mode,
      maxUses,
      expiresInSeconds,
      requirements,
    );
  } catch {
    throw new AuthsWorkflowError(
      "invalid-provider",
      "approval configuration is outside the supported commitment",
    );
  }
  const reference = Object.freeze({
    policyId: options.policyId ?? `approval.${mode}`,
    evaluatorVersion: options.evaluatorVersion ?? "1",
    configurationDigest: configurationDigest.slice(),
  });
  return Object.freeze({
    reference,
    mode,
    maxUses,
    expiresInSeconds,
    requirements: Object.freeze(requirements),
  });
}

/** Typed, versioned approval-policy builders. */
export const approvalPolicy = Object.freeze({
  none(options?: ApprovalPolicyOptions) {
    return buildPolicy("none", { ...options, maxUses: options?.maxUses ?? 1 });
  },
  grantOnly(options?: ApprovalPolicyOptions) {
    return buildPolicy("grant-only", options);
  },
  everyAction(options?: ApprovalPolicyOptions) {
    return buildPolicy("every-action", options);
  },
  riskBased(options?: ApprovalPolicyOptions) {
    return buildPolicy("risk-based", options);
  },
  planOnce(options?: ApprovalPolicyOptions) {
    return buildPolicy("plan-once", { ...options, maxUses: options?.maxUses ?? 1 });
  },
  headless(options?: ApprovalPolicyOptions) {
    return buildPolicy("headless", options);
  },
  custom(options?: ApprovalPolicyOptions) {
    return buildPolicy("custom", options);
  },
});

/** Local no-approval provider. It is valid only with an authority committed to `none`. */
export const noApproval: ApprovalProvider = Object.freeze({
  async approve(request: ApprovalRequest): Promise<ApprovalResponse> {
    return Object.freeze({
      requestId: request.requestId,
      transactionDigest: request.transactionDigest.slice(),
      policy: copyPolicy(request.policy),
      decision: "approved",
    });
  },
});

export interface ThresholdApprovalOptions {
  readonly threshold: number;
  readonly providers: readonly ApprovalProvider[];
}

/** Requires a bounded quorum of independent, exact responses without retrying any provider. */
export function thresholdApproval(options: ThresholdApprovalOptions): ApprovalProvider {
  if (!Number.isSafeInteger(options.threshold) || options.threshold < 1 ||
      options.providers.length < options.threshold || options.providers.length > 16 ||
      options.providers.some((provider) => typeof provider?.approve !== "function") ||
      new Set(options.providers).size !== options.providers.length) {
    throw new AuthsWorkflowError("invalid-provider", "threshold approval configuration is invalid");
  }
  const threshold = options.threshold;
  const providers = Object.freeze([...options.providers]);
  return Object.freeze({
    async approve(request: ApprovalRequest): Promise<ApprovalResponse> {
      const settled = await Promise.allSettled(
        providers.map((provider) => provider.approve(copyApprovalRequest(request))),
      );
      let approved = 0;
      for (const result of settled) {
        if (result.status !== "fulfilled") continue;
        const response = result.value;
        if (response.requestId !== request.requestId ||
            !equalBytes(response.transactionDigest, request.transactionDigest) ||
            response.policy.policyId !== request.policy.policyId ||
            response.policy.evaluatorVersion !== request.policy.evaluatorVersion ||
            !equalBytes(response.policy.configurationDigest, request.policy.configurationDigest)) {
          throw new ProviderOperationError("rejected", { operation: "threshold-approval" });
        }
        if (response.decision === "approved") approved += 1;
      }
      return Object.freeze({
        requestId: request.requestId,
        transactionDigest: request.transactionDigest.slice(),
        policy: copyPolicy(request.policy),
        decision: approved >= threshold ? "approved" as const : "rejected" as const,
      });
    },
  });
}

function copyApprovalRequest(request: ApprovalRequest): ApprovalRequest {
  return Object.freeze({
    ...request,
    transactionDigest: request.transactionDigest.slice(),
    policy: copyPolicy(request.policy),
    display: Object.freeze(request.display.map((field) => Object.freeze({ ...field }))),
  });
}

export interface BoundedApprovalSessionOptions {
  readonly planCommitment: Uint8Array;
  readonly memberCommitments: readonly Uint8Array[];
  readonly policy: ApprovalPolicy;
  readonly provider: ApprovalProvider;
  readonly display: readonly ReviewField[];
  readonly now?: () => bigint;
  readonly startedAt?: bigint;
}

/**
 * One finite approval capability bound to one immutable plan commitment.
 * The first transaction is shown to the configured provider; subsequent
 * members are accepted only while the same frozen session remains active.
 */
export class BoundedApprovalSession implements AsyncDisposable {
  readonly #planCommitment: Uint8Array;
  readonly #memberCommitments: readonly Uint8Array[];
  readonly #policy: ApprovalPolicy;
  readonly #provider: ApprovalProvider;
  readonly #expiresAt: bigint;
  readonly #display: readonly ReviewField[];
  readonly #now: () => bigint;
  #uses = 0;
  #approved = false;
  #disposed = false;

  constructor(options: BoundedApprovalSessionOptions) {
    if (!(options.planCommitment instanceof Uint8Array) || options.planCommitment.length !== 32) {
      throw new AuthsWorkflowError("invalid-provider", "plan commitment must contain 32 bytes");
    }
    if (
      options.policy.mode !== "plan-once" ||
      options.memberCommitments.length === 0 ||
      options.memberCommitments.length !== options.policy.maxUses ||
      options.memberCommitments.some((item) => !(item instanceof Uint8Array) || item.length !== 32)
    ) {
      throw new AuthsWorkflowError("invalid-provider", "approval policy does not match exact plan membership");
    }
    if (typeof options.provider?.approve !== "function") {
      throw new AuthsWorkflowError("invalid-provider", "approval session provider is missing");
    }
    this.#planCommitment = options.planCommitment.slice();
    this.#memberCommitments = Object.freeze(options.memberCommitments.map((item) => item.slice()));
    this.#policy = Object.freeze({
      ...options.policy,
      reference: copyPolicy(options.policy.reference),
      requirements: Object.freeze([...options.policy.requirements]),
    });
    this.#provider = options.provider;
    this.#now = options.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
    const startedAt = options.startedAt ?? this.#now();
    this.#expiresAt = startedAt + BigInt(options.policy.expiresInSeconds);
    this.#display = Object.freeze(options.display.map((field) => Object.freeze({ ...field })));
  }

  get planCommitment(): Uint8Array {
    return this.#planCommitment.slice();
  }

  providerFor(index: number, memberCommitment: Uint8Array): ApprovalProvider {
    if (
      !Number.isSafeInteger(index) ||
      index < 0 ||
      index >= this.#memberCommitments.length ||
      !(memberCommitment instanceof Uint8Array) ||
      memberCommitment.length !== 32
    ) {
      throw new AuthsWorkflowError("invalid-provider", "approval plan member is invalid");
    }
    const expected = this.#memberCommitments[index];
    if (expected === undefined || !equalBytes(expected, memberCommitment)) {
      throw new AuthsWorkflowError("approval-response-mismatch", "approval plan member commitment mismatch");
    }
    return Object.freeze({
      approve: (request: ApprovalRequest) => this.#approveMember(index, memberCommitment, request),
    });
  }

  async #approveMember(
    index: number,
    memberCommitment: Uint8Array,
    request: ApprovalRequest,
  ): Promise<ApprovalResponse> {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
    const now = this.#now();
    if (now > this.#expiresAt || now > request.expiresAt) {
      throw new ProviderOperationError("timeout");
    }
    if (this.#uses >= this.#policy.maxUses || index !== this.#uses) {
      throw new ProviderOperationError("rejected");
    }
    const expectedMember = this.#memberCommitments[index];
    if (expectedMember === undefined || !equalBytes(expectedMember, memberCommitment)) {
      throw new ProviderOperationError("rejected");
    }
    if (
      request.policy.policyId !== this.#policy.reference.policyId ||
      request.policy.evaluatorVersion !== this.#policy.reference.evaluatorVersion ||
      !equalBytes(request.policy.configurationDigest, this.#policy.reference.configurationDigest)
    ) {
      throw new ProviderOperationError("rejected");
    }
    if (!this.#approved) {
      const response = await this.#provider.approve({
        ...request,
        display: Object.freeze([
          ...this.#display,
          Object.freeze({ label: "Plan commitment", value: hex(this.#planCommitment) }),
          Object.freeze({ label: "Plan member", value: `${index + 1}/${this.#memberCommitments.length}` }),
          Object.freeze({ label: "Member commitment", value: hex(memberCommitment) }),
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
    for (const member of this.#memberCommitments) member.fill(0);
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
