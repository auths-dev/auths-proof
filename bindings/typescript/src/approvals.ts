import {
  type ApprovalOperationContext,
  type ApprovalPolicy,
  type ApprovalPolicyReference,
  type ApprovalProvider,
  type ApprovalRequest,
  type ApprovalResponse,
  type ReviewField,
  copyPolicy,
} from "./workflow.js";
import { AuthsWorkflowError, ProviderOperationError } from "./workflow/errors.js";
import { approvalBytes, approvalResponse, callApproval, captureApprovalContext, checkApprovalSignal, equalApprovalBytes, snapshotApproval } from "./internal/approval-operation.js";
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
  async approve(request: ApprovalRequest, context: ApprovalOperationContext): Promise<ApprovalResponse> {
    checkApprovalSignal(context);
    try { return approvalResponse(snapshotApproval(request), "approved"); }
    catch { throw new ProviderOperationError("rejected"); }
  },
});

export interface ThresholdApprovalOptions {
  readonly threshold: number;
  readonly providers: readonly ApprovalProvider[];
}

/** Independent exact approvals; cancellation stops starting children and never retries them. */
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
    async approve(request: ApprovalRequest, context: ApprovalOperationContext): Promise<ApprovalResponse> {
      context = captureApprovalContext(context);
      let owned: ApprovalRequest;
      try { owned = snapshotApproval(request); }
      catch { throw new ProviderOperationError("rejected"); }
      const settled = await Promise.allSettled(providers.map((provider) => callApproval(provider, owned, context)));
      checkApprovalSignal(context);
      let approved = 0;
      for (const result of settled) {
        if (result.status === "rejected") {
          // A malformed exact response is not a quorum abstention.
          if (result.reason instanceof ProviderOperationError && result.reason.causeChain.includes("invalid-response")) throw result.reason;
          continue;
        }
        if (result.value.decision === "approved") approved += 1;
      }
      return approvalResponse(owned, approved >= threshold ? "approved" : "rejected");
    },
  });
}

export const approval = Object.freeze({
  ...approvalPolicy,
  threshold: thresholdApproval,
});

/** Injectable scheduling of deadline observations, paired with the configured clock. */
export interface ApprovalDeadlineScheduler {
  schedule(callback: () => void, delayMs: number): () => void;
}

export interface BoundedApprovalSessionOptions {
  readonly planCommitment: Uint8Array;
  readonly memberCommitments: readonly Uint8Array[];
  readonly policy: ApprovalPolicy;
  readonly provider: ApprovalProvider;
  readonly display: readonly ReviewField[];
  readonly now?: () => bigint;
  readonly startedAt?: bigint;
  readonly scheduler?: ApprovalDeadlineScheduler;
}

type ApprovalState =
  | { readonly kind: "unapproved" }
  | { readonly kind: "approved"; readonly next: number }
  | { readonly kind: "pending"; readonly operation: symbol; readonly stop: (reason: TerminalReason) => void }
  | { readonly kind: "terminal"; readonly reason: TerminalReason };
type TerminalReason = "disposed" | "cancelled" | "session-expired" | "request-expired" | "refused" | "failed" | "exhausted";

const realScheduler: ApprovalDeadlineScheduler = {
  schedule(callback, delayMs) {
    const timer = setTimeout(callback, delayMs);
    return () => clearTimeout(timer);
  },
};

/** One plan's exclusive approval owner. Terminal sessions cannot be revived. */
export class BoundedApprovalSession implements AsyncDisposable {
  readonly #planCommitment: Uint8Array;
  readonly #memberCommitments: readonly Uint8Array[];
  readonly #policy: ApprovalPolicy;
  readonly #provider: ApprovalProvider;
  readonly #expiresAt: bigint;
  readonly #display: readonly ReviewField[];
  readonly #now: () => bigint;
  readonly #scheduler: ApprovalDeadlineScheduler;
  #effectiveTime: bigint;
  #state: ApprovalState = { kind: "unapproved" };

  constructor(options: BoundedApprovalSessionOptions) {
    this.#planCommitment = approvalBytes(options.planCommitment);
    if (options.policy.mode !== "plan-once" || options.memberCommitments.length === 0 ||
        options.memberCommitments.length !== options.policy.maxUses ||
        !Number.isSafeInteger(options.policy.maxUses) || options.policy.maxUses > 256 ||
        !Number.isSafeInteger(options.policy.expiresInSeconds) || options.policy.expiresInSeconds < 1 ||
        options.policy.expiresInSeconds > 86400 || typeof options.provider?.approve !== "function") {
      throw new AuthsWorkflowError("invalid-provider", "approval policy does not match exact plan membership");
    }
    this.#memberCommitments = Object.freeze(options.memberCommitments.map(approvalBytes));
    this.#policy = Object.freeze({ ...options.policy, reference: {
      ...options.policy.reference, configurationDigest: approvalBytes(options.policy.reference.configurationDigest),
    }, requirements: Object.freeze([...options.policy.requirements]) });
    this.#provider = options.provider;
    this.#now = options.now ?? (() => BigInt(Math.floor(Date.now() / 1000)));
    this.#effectiveTime = this.#now();
    if (typeof this.#effectiveTime !== "bigint" || this.#effectiveTime < 0n) throw new TypeError("invalid approval clock");
    const startedAt = options.startedAt ?? this.#effectiveTime;
    if (typeof startedAt !== "bigint" || startedAt < 0n) throw new TypeError("invalid approval start");
    this.#expiresAt = startedAt + BigInt(options.policy.expiresInSeconds);
    // Reuse bounded request validation for presentation as well as policy bytes.
    this.#display = snapshotApproval({ requestId: "session", objectKind: "action", transactionDigest: this.#planCommitment,
      policy: this.#policy.reference, expiresAt: this.#expiresAt, display: options.display }).display;
    this.#scheduler = options.scheduler ?? realScheduler;
    if (typeof this.#scheduler.schedule !== "function") throw new TypeError("invalid approval scheduler");
  }

  get planCommitment(): Uint8Array { return this.#planCommitment.slice(); }

  providerFor(index: number, memberCommitment: Uint8Array): ApprovalProvider {
    if (this.#state.kind === "terminal") throw this.#terminal(this.#state.reason);
    const member = approvalBytes(memberCommitment);
    if (!Number.isSafeInteger(index) || index < 0 || index >= this.#memberCommitments.length) {
      throw new AuthsWorkflowError("invalid-provider", "approval plan member is invalid");
    }
    if (!equalApprovalBytes(this.#memberCommitments[index]!, member)) {
      throw new AuthsWorkflowError("approval-response-mismatch", "approval plan member commitment mismatch");
    }
    return Object.freeze({
      approve: (request: ApprovalRequest, context: ApprovalOperationContext) => this.#approveMember(index, member, request, context),
    });
  }

  #time(): bigint {
    const sampled = this.#now();
    if (typeof sampled !== "bigint" || sampled < 0n) throw new ProviderOperationError("unavailable");
    if (sampled > this.#effectiveTime) this.#effectiveTime = sampled;
    return this.#effectiveTime;
  }

  #terminal(reason: TerminalReason): ProviderOperationError {
    return new ProviderOperationError(reason === "disposed" || reason === "cancelled" ? "cancelled"
      : reason === "session-expired" || reason === "request-expired" ? "timeout" : "rejected");
  }

  #guard(context: ApprovalOperationContext, request: ApprovalRequest): void {
    if (this.#state.kind === "terminal") throw this.#terminal(this.#state.reason);
    checkApprovalSignal(context);
    if (this.#time() > this.#expiresAt) {
      this.#state = { kind: "terminal", reason: "session-expired" };
      throw new ProviderOperationError("timeout");
    }
    if (this.#effectiveTime > request.expiresAt) throw new ProviderOperationError("timeout");
  }

  async #approveMember(index: number, member: Uint8Array, input: ApprovalRequest, context: ApprovalOperationContext): Promise<ApprovalResponse> {
    if (this.#state.kind === "terminal") throw this.#terminal(this.#state.reason);
    context = captureApprovalContext(context);
    let request: ApprovalRequest;
    try { request = snapshotApproval(input); }
    catch { throw new ProviderOperationError("rejected"); }
    // A competing request cannot change or expire the pending owner's request.
    if (this.#state.kind === "pending") throw new ProviderOperationError("rejected");
    this.#guard(context, request);
    const next = this.#state.kind === "approved" ? this.#state.next : 0;
    if (index !== next || !equalApprovalBytes(this.#memberCommitments[index]!, member) ||
        request.policy.policyId !== this.#policy.reference.policyId ||
        request.policy.evaluatorVersion !== this.#policy.reference.evaluatorVersion ||
        !equalApprovalBytes(request.policy.configurationDigest, this.#policy.reference.configurationDigest)) {
      throw new ProviderOperationError("rejected");
    }
    if (this.#state.kind === "approved") {
      this.#accept(index);
      return approvalResponse(request, "approved");
    }
    let visible: ApprovalRequest;
    try {
      visible = snapshotApproval({ ...request, display: [
        ...this.#display,
        { label: "Plan commitment", value: hex(this.#planCommitment) },
        { label: "Plan member", value: `${index + 1}/${this.#memberCommitments.length}` },
        { label: "Member commitment", value: hex(member) }, ...request.display,
      ] });
    } catch { throw new ProviderOperationError("rejected"); }
    return new Promise<ApprovalResponse>((resolve, reject) => {
      const operation = Symbol("approval");
      const controller = new AbortController();
      let cancelTimer: () => void = () => {};
      const current = () => this.#state.kind === "pending" && this.#state.operation === operation;
      const clean = () => { cancelTimer(); context.signal.removeEventListener("abort", aborted); };
      const stop = (reason: TerminalReason) => {
        if (!current()) return;
        this.#state = { kind: "terminal", reason };
        clean();
        controller.abort();
        reject(reason === "failed" ? new ProviderOperationError("unavailable") : this.#terminal(reason));
      };
      const aborted = () => stop("cancelled");
      const deadline = request.expiresAt < this.#expiresAt ? request.expiresAt : this.#expiresAt;
      const watch = () => {
        if (!current()) return;
        try {
          const now = this.#time();
          if (now > this.#expiresAt) { stop("session-expired"); return; }
          if (now > request.expiresAt) { stop("request-expired"); return; }
          const remainingMs = (deadline - now + 1n) * 1000n;
          const delay = Number(remainingMs > 2147483647n ? 2147483647n : remainingMs);
          cancelTimer = this.#scheduler.schedule(watch, delay);
        } catch {
          stop("failed");
        }
      };
      // Publish the pending owner before listeners, timers, or provider callbacks.
      this.#state = { kind: "pending", operation, stop };
      context.signal.addEventListener("abort", aborted, { once: true });
      if (context.signal.aborted) { stop("cancelled"); return; }
      watch();
      if (!current()) return;
      callApproval(this.#provider, visible, { signal: controller.signal }).then((response) => {
        if (!current()) return;
        if (context.signal.aborted) { stop("cancelled"); return; }
        try {
          const now = this.#time();
          if (now > this.#expiresAt) { stop("session-expired"); return; }
          if (now > request.expiresAt) { stop("request-expired"); return; }
          clean();
          if (response.decision === "rejected") this.#state = { kind: "terminal", reason: "refused" };
          else this.#accept(index);
          resolve(approvalResponse(request, response.decision));
        } catch (error) {
          clean();
          this.#state = { kind: "terminal", reason: "failed" };
          reject(error instanceof ProviderOperationError ? error : new ProviderOperationError("unavailable"));
        }
      }, (error: unknown) => {
        if (!current()) return;
        clean();
        this.#state = { kind: "terminal", reason: "failed" };
        reject(error instanceof ProviderOperationError ? error : new ProviderOperationError("unavailable"));
      });
    });
  }

  #accept(index: number): void {
    this.#state = index + 1 === this.#memberCommitments.length
      ? { kind: "terminal", reason: "exhausted" } : { kind: "approved", next: index + 1 };
  }

  async dispose(): Promise<void> {
    if (this.#state.kind === "pending") this.#state.stop("disposed");
    else if (this.#state.kind !== "terminal") this.#state = { kind: "terminal", reason: "disposed" };
    this.#planCommitment.fill(0);
    for (const member of this.#memberCommitments) member.fill(0);
  }

  async [Symbol.asyncDispose](): Promise<void> { await this.dispose(); }
}

function hex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
