import type { Signer } from "./workflow.js";
import type { AttachedAgent, Profile } from "./workflow.js";
import {
  executeMcpClosed,
  resumeMcpClosed,
  resourcesForMcpAuthority,
  type McpAction,
  type McpClosedProvider,
  type McpExecutionState,
  type McpReceiptSink,
  type McpToolAuthority,
} from "./profiles/mcp/index.js";

const configurationResources = new WeakMap<AuthsConfiguration, InternalConfiguration>();
const referenceResources = new WeakMap<ExecutionReference, string>();
type RawMcpExecution = Awaited<ReturnType<typeof executeMcpClosed>>;

export interface Actor {
  readonly principal: string;
}

export type Authority = McpToolAuthority;

export interface AuthsConfiguration {
  readonly mode: "development" | "production";
  readonly diagnostics: readonly string[];
}

export interface Receipt {
  readonly bytes: Uint8Array;
}

export interface Completed {
  readonly kind: "completed";
  readonly executionId: string;
  readonly result: unknown;
  readonly receipt: Receipt;
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

  toJSON(): never {
    throw new TypeError("Auths execution references are not serializable");
  }
}

const REFERENCE_TOKEN = Symbol("auths-execution-reference");

export interface RecoveryResult {
  readonly kind: "recoverable" | "not-applied" | "exact-replay" | "conflict";
  readonly executionId: string;
  readonly reference?: ExecutionReference;
}

export type ExecutionResult = Completed | Denied | Indeterminate | RecoveryResult;

export interface Auths {
  readonly actor: Actor;
  readonly authority: Authority;
  readonly diagnostics: readonly string[];
  execute(input: Readonly<{
    action: McpAction;
    provider: McpClosedProvider;
    requestId?: string;
  }>): Promise<ExecutionResult>;
  resume(input: Readonly<{
    reference: ExecutionReference;
    provider: McpClosedProvider;
  }>): Promise<ExecutionResult>;
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
  readonly sessionKey: Uint8Array;
  readonly childSigner: () => Promise<Signer>;
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
  }>): Promise<ExecutionResult> {
    this.#assertActive();
    const result = await executeMcpClosed(
      this.#resources.agent,
      input.action,
      {
        provider: input.provider,
        state: this.#resources.state,
        receipts: this.#resources.receipts,
        sessionKey: this.#resources.sessionKey,
        ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
      },
    );
    return projectExecution(result);
  }

  async resume(input: Readonly<{
    reference: ExecutionReference;
    provider: McpClosedProvider;
  }>): Promise<ExecutionResult> {
    this.#assertActive();
    const reference = referenceResources.get(input.reference);
    if (reference === undefined) throw new TypeError("forged Auths execution reference");
    return projectExecution(await resumeMcpClosed(
      this.#resources.agent,
      reference,
      {
        provider: input.provider,
        state: this.#resources.state,
        receipts: this.#resources.receipts,
        sessionKey: this.#resources.sessionKey,
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

export async function createAuths(configuration: AuthsConfiguration): Promise<Auths> {
  const resources = configurationResources.get(configuration);
  if (resources === undefined) throw new TypeError("Auths configuration was not created by an integration");
  return new AuthsFacade(await resources.open(), resources.diagnostics);
}

function projectExecution(value: RawMcpExecution): ExecutionResult {
  if (value.kind === "completed") {
    return Object.freeze({
      kind: "completed" as const,
      executionId: value.executionId,
      result: value.result,
      receipt: Object.freeze({ bytes: value.receipt.slice() }),
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
