import type { Signer } from "./workflow.js";
import type { AttachedAgent, Profile } from "./workflow.js";
import {
  executeMcpClosed,
  executeMcpPlanClosed,
  recoverMcpClosed,
  resumeMcpClosed,
  resourcesForMcpAuthority,
  type McpAction,
  type McpClosedProvider,
  type McpExecutionState,
  type McpExecutionObserver,
  type McpReceiptSink,
  type McpAttestedReceipt,
  type McpToolAuthority,
  type McpPlanClosedResult,
} from "./profiles/mcp/index.js";
import type { ProfilePlan } from "./plans.js";
import type { ApplicationReceiptAttestor } from "./profiles/application/index.js";
import {
  decodeLinkedReceipt,
  encodeLinkedReceipt,
  verifyLinkedReceipt,
} from "./internal/receipt-attestation.js";
import {
  createProductionAuths,
  type ProductionAuths,
  type ProductionAuthsOptions,
} from "./production-client.js";

const configurationResources = new WeakMap<AuthsConfiguration, InternalConfiguration>();
const referenceResources = new WeakMap<ExecutionReference, string>();
type RawMcpExecution = Awaited<ReturnType<typeof executeMcpClosed>>;
type RawMcpPlanExecution = Awaited<ReturnType<typeof executeMcpPlanClosed>>;

export interface Actor {
  readonly principal: string;
}

export type Authority = McpToolAuthority;

export interface AuthsConfiguration {
  readonly mode: "development" | "production";
  readonly diagnostics: readonly string[];
}

export type Receipt = McpAttestedReceipt;

export interface Completed {
  readonly kind: "completed";
  readonly executionId: string;
  readonly result: unknown;
  readonly receipt: Receipt;
}

export interface PlanCompleted {
  readonly kind: "completed";
  readonly results: readonly unknown[];
  readonly receipts: readonly Receipt[];
}

export interface PlanRecoveryResult {
  readonly kind: "recoverable" | "not-applied" | "exact-replay" | "conflict";
  readonly executionId: string;
  readonly completedResults: readonly unknown[];
  readonly completedReceipts: readonly Receipt[];
  readonly reference?: ExecutionReference;
}

export interface Denied {
  readonly kind: "denied";
  readonly code: string;
}

export interface Indeterminate {
  readonly kind: "indeterminate";
  readonly code: string;
}

export class ExecutionReference {
  private constructor(token: symbol, value: string) {
    if (token !== REFERENCE_TOKEN) throw new TypeError("sealed Auths execution reference");
    referenceResources.set(this, value);
    Object.freeze(this);
  }

  static create(token: symbol, value: string): ExecutionReference {
    return new ExecutionReference(token, value);
  }

  static decode(input: Uint8Array): ExecutionReference {
    return decodeExecutionReference(input);
  }

  encode(): Uint8Array {
    return encodeExecutionReference(this);
  }

  toJSON(): never {
    throw new TypeError("Auths execution references are not serializable");
  }
}

export function encodeExecutionReference(reference: ExecutionReference): Uint8Array {
  const value = referenceResources.get(reference);
  if (value === undefined) throw new TypeError("forged Auths execution reference");
  return new TextEncoder().encode(value);
}

export function decodeExecutionReference(input: Uint8Array): ExecutionReference {
  if (!(input instanceof Uint8Array) || input.length !== 134) {
    throw new TypeError("invalid Auths execution reference");
  }
  const value = new TextDecoder("utf-8", { fatal: true }).decode(input);
  if (!/^mcp1\.[0-9a-f]{64}\.[0-9a-f]{64}$/.test(value)) {
    throw new TypeError("invalid Auths execution reference");
  }
  return ExecutionReference.create(REFERENCE_TOKEN, value);
}

const REFERENCE_TOKEN = Symbol("auths-execution-reference");

export interface RecoveryResult {
  readonly kind: "recoverable" | "not-applied" | "exact-replay" | "conflict";
  readonly executionId: string;
  readonly reference?: ExecutionReference;
}

export type ExecutionResult = Completed | PlanCompleted | Denied | Indeterminate | RecoveryResult | PlanRecoveryResult;
export type SingleExecutionResult = Completed | Denied | Indeterminate | RecoveryResult;
export type PlanExecutionResult = PlanCompleted | Denied | Indeterminate | PlanRecoveryResult;

export interface Auths {
  readonly actor: Actor;
  readonly authority: Authority;
  readonly diagnostics: readonly string[];
  execute(input: Readonly<{
    action: McpAction;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<SingleExecutionResult>;
  execute(input: Readonly<{
    plan: ProfilePlan<McpAction>;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<PlanExecutionResult>;
  resume(input: Readonly<{
    reference: ExecutionReference;
    provider: McpClosedProvider;
  }>): Promise<SingleExecutionResult>;
  recover(input: Readonly<{
    action: McpAction;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<SingleExecutionResult>;
  delegate(input: Readonly<{
    authority: McpToolAuthority;
    name?: string;
    expiresInSeconds?: number;
  }>): Promise<Auths>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

interface InternalConfiguration extends AuthsConfiguration {
  open(): Promise<AuthsResources>;
}

export interface AuthsResources {
  readonly agent: AttachedAgent<Profile>;
  readonly authority: McpToolAuthority;
  readonly state: McpExecutionState;
  readonly receipts: McpReceiptSink;
  readonly receiptAttestor: ApplicationReceiptAttestor;
  readonly sessionKey: Uint8Array;
  readonly childSigner: () => Promise<Signer>;
  readonly observer?: McpExecutionObserver;
  readonly dispose: () => Promise<void>;
}

class AuthsFacade implements Auths {
  readonly actor: Actor;
  readonly authority: Authority;
  readonly diagnostics: readonly string[];
  readonly #resources: AuthsResources;
  readonly #children = new Set<AuthsFacade>();
  #closed = false;

  constructor(resources: AuthsResources, diagnostics: readonly string[]) {
    this.#resources = resources;
    this.actor = Object.freeze({ principal: resources.agent.identity.principal.principal });
    this.authority = resources.authority;
    this.diagnostics = Object.freeze([...diagnostics]);
  }

  async execute(input: Readonly<{
    action: McpAction;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<SingleExecutionResult>;
  async execute(input: Readonly<{
    plan: ProfilePlan<McpAction>;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<PlanExecutionResult>;
  async execute(input: Readonly<{
    action?: McpAction;
    plan?: ProfilePlan<McpAction>;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<ExecutionResult> {
    this.#assertActive();
    this.#assertProvider(input.provider);
    const execution = {
      provider: input.provider,
      state: this.#resources.state,
      receipts: this.#resources.receipts,
      attestor: this.#resources.receiptAttestor,
      sessionKey: this.#resources.sessionKey,
      ...(this.#resources.observer === undefined ? {} : { observer: this.#resources.observer }),
      ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
    };
    if (input.action !== undefined && input.plan === undefined) {
      return projectExecution(await executeMcpClosed(this.#resources.agent, input.action, execution));
    }
    if (input.plan !== undefined && input.action === undefined) {
      return projectPlanExecution(await executeMcpPlanClosed(this.#resources.agent, input.plan, execution));
    }
    throw new TypeError("Auths execute requires exactly one action or plan");
  }

  async resume(input: Readonly<{
    reference: ExecutionReference;
    provider: McpClosedProvider;
  }>): Promise<SingleExecutionResult> {
    this.#assertActive();
    this.#assertProvider(input.provider);
    const reference = referenceResources.get(input.reference);
    if (reference === undefined) throw new TypeError("forged Auths execution reference");
    return projectExecution(await resumeMcpClosed(
      this.#resources.agent,
      reference,
      {
        provider: input.provider,
        state: this.#resources.state,
        receipts: this.#resources.receipts,
        attestor: this.#resources.receiptAttestor,
        sessionKey: this.#resources.sessionKey,
        ...(this.#resources.observer === undefined ? {} : { observer: this.#resources.observer }),
      },
    ));
  }

  async recover(input: Readonly<{
    action: McpAction;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<SingleExecutionResult> {
    this.#assertActive();
    this.#assertProvider(input.provider);
    return projectExecution(await recoverMcpClosed(
      this.#resources.agent,
      input.action,
      {
        provider: input.provider,
        state: this.#resources.state,
        receipts: this.#resources.receipts,
        attestor: this.#resources.receiptAttestor,
        sessionKey: this.#resources.sessionKey,
        ...(this.#resources.observer === undefined ? {} : { observer: this.#resources.observer }),
        ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
      },
    ));
  }

  async delegate(input: Readonly<{
    authority: McpToolAuthority;
    name?: string;
    expiresInSeconds?: number;
  }>): Promise<Auths> {
    this.#assertActive();
    const authority = resourcesForMcpAuthority(input.authority);
    const current = resourcesForMcpAuthority(this.authority);
    if (authority.profile.service !== current.profile.service) {
      throw new TypeError("delegated authority belongs to another MCP service");
    }
    const expiresInSeconds = input.expiresInSeconds ?? 300;
    if (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds < 1 || expiresInSeconds > 86_400) {
      throw new TypeError("delegated authority expiry is outside bounds");
    }
    const now = BigInt(Math.floor(Date.now() / 1000));
    const signer = await this.#resources.childSigner();
    const agent = await this.#resources.agent.delegate({
      name: input.name ?? "delegated-agent",
      signer,
      authority: {
        permissions: authority.permissions,
        validity: { notBefore: now, expiresAt: now + BigInt(expiresInSeconds) },
        audiences: authority.audiences,
        remainingDepth: 0,
        actionConstraint: { kind: "inherit" },
        budget: { kind: "inherit" },
        status: { kind: "expiry-only" },
      },
    });
    const child = new AuthsFacade({
      ...this.#resources,
      agent,
      authority: input.authority,
      dispose: () => agent.dispose(),
    }, this.diagnostics);
    this.#children.add(child);
    return child;
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const child of this.#children) await child.close();
    this.#children.clear();
    await this.#resources.dispose();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  #assertActive(): void {
    if (this.#closed) throw new TypeError("Auths is closed");
  }

  #assertProvider(provider: McpClosedProvider): void {
    const authority = resourcesForMcpAuthority(this.authority);
    if (provider?.profile !== "auths.mcp" || provider.service !== authority.profile.service) {
      throw new TypeError("MCP provider does not match this Auths authority");
    }
  }
}

export function createAuthsConfiguration(
  mode: "development" | "production",
  diagnostics: readonly string[],
  open: () => Promise<AuthsResources>,
): AuthsConfiguration {
  if (typeof open !== "function" || diagnostics.some((value) => typeof value !== "string" || value.length === 0 || value.length > 256)) {
    throw new TypeError("invalid Auths composition");
  }
  const configuration = Object.freeze({ mode, diagnostics: Object.freeze([...diagnostics]) });
  configurationResources.set(configuration, { ...configuration, open });
  return configuration;
}

export function createAuths(configuration: AuthsConfiguration): Promise<Auths>;
export function createAuths(configuration: ProductionAuthsOptions): ProductionAuths;
export function createAuths(
  configuration: AuthsConfiguration | ProductionAuthsOptions,
): Promise<Auths> | ProductionAuths {
  if ("endpoint" in configuration) return createProductionAuths(configuration);
  const resources = configurationResources.get(configuration);
  if (resources === undefined) throw new TypeError("Auths configuration was not created by an integration");
  return resources.open().then((opened) => new AuthsFacade(opened, resources.diagnostics));
}

export async function verifyReceipt(receipt: Receipt): Promise<void> {
  await verifyLinkedReceipt(receipt);
}

export function encodeReceipt(receipt: Receipt): Uint8Array {
  return encodeLinkedReceipt(receipt);
}

export function decodeReceipt(input: Uint8Array): Receipt {
  return decodeLinkedReceipt(input);
}

function projectExecution(value: RawMcpExecution): SingleExecutionResult {
  if (value.kind === "completed") {
    return Object.freeze({
      kind: "completed" as const,
      executionId: value.executionId,
      result: value.result,
      receipt: value.receipt,
    });
  }
  if (value.kind === "denied" || value.kind === "indeterminate") {
    return Object.freeze({ kind: value.kind, code: value.code });
  }
  if (value.kind === "recoverable") {
    return Object.freeze({
      kind: "recoverable" as const,
      executionId: value.executionId,
      reference: ExecutionReference.create(REFERENCE_TOKEN, value.executionReference),
    });
  }
  return Object.freeze({ kind: value.kind, executionId: value.executionId });
}

function projectPlanExecution(value: RawMcpPlanExecution): PlanExecutionResult {
  if ("failedIndex" in value) {
    return Object.freeze({ kind: value.kind, code: value.result.code });
  }
  if (value.kind === "completed") {
    return Object.freeze({ kind: "completed", results: value.results, receipts: value.receipts });
  }
  return Object.freeze({
    kind: value.kind,
    executionId: value.executionId,
    completedResults: value.completedResults,
    completedReceipts: value.completedReceipts,
    ...(value.kind === "recoverable"
      ? { reference: ExecutionReference.create(REFERENCE_TOKEN, value.executionReference) }
      : {}),
  });
}
