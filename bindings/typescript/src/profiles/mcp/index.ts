import {
  AuthsWorkflowError,
  type AuthorizationResult,
  type ApprovalConfiguration,
  type AttachedAgent,
  type Profile,
  engineForClient,
  registerProfileRuntime,
  resourcesForAttachedAgent,
} from "../../workflow.js";
import {
  authorizePreparedAction,
  type VerifiedArtifactView,
} from "../../internal/authorization.js";
import { causeCategoryFrom } from "../../product-errors.js";
import { MCP_PROFILE } from "../../generated/mcp-profile.js";
import type {
  WorkflowMcpExecutionSession,
  WorkflowMcpSessionTerminal,
} from "../../workflow/contracts.js";
import {
  commandsForGateway,
  createProfilePlan,
  type ProfilePlan,
  type VerifiedPlanCommand,
} from "../../plans.js";
import { loadPackagedWorkflowEngine } from "../../verifier/wasm.js";

const PROFILE_ID = "auths.mcp";
const PROFILE_VERSION = 1;
const MCP_PROFILE_TOKEN: unique symbol = Symbol("auths-mcp-profile");
const MCP_ACTION_TOKEN: unique symbol = Symbol("auths-mcp-action");
const MCP_COMMAND_TOKEN: unique symbol = Symbol("auths-mcp-command");

let mintMcpCommand: (resources: McpCommandResources) => McpCommand;
let mintMcpAction: (
  profile: McpProfile,
  name: string,
  argumentsValue: Readonly<Record<string, unknown>>,
) => McpAction;
let mintMcpProfile: (service: string) => McpProfile;

interface McpActionResources {
  readonly profile: McpProfile;
  readonly name: string;
  readonly argumentsValue: Readonly<Record<string, unknown>>;
}

interface McpCommandResources {
  readonly profile: McpProfile;
  readonly name: string;
  readonly argumentsJson: Uint8Array;
}

const actionResources = new WeakMap<McpAction, McpActionResources>();
const commandResources = new WeakMap<McpCommand, McpCommandResources>();

/** Verifier-minted MCP tool call accepted only by its matching gateway. */
export class McpCommand {
  readonly service: string;
  readonly name: string;

  private constructor(token: typeof MCP_COMMAND_TOKEN, resources: McpCommandResources) {
    if (token !== MCP_COMMAND_TOKEN) throw new TypeError("sealed Auths MCP command");
    this.service = resources.profile.service;
    this.name = resources.name;
    commandResources.set(this, {
      ...resources,
      argumentsJson: resources.argumentsJson.slice(),
    });
    Object.freeze(this);
  }

  private static create(token: typeof MCP_COMMAND_TOKEN, resources: McpCommandResources): McpCommand {
    return new McpCommand(token, resources);
  }

  static {
    mintMcpCommand = (resources) => McpCommand.create(MCP_COMMAND_TOKEN, resources);
  }

  toJSON(): never {
    throw new TypeError("verified Auths commands are not serializable");
  }
}

export interface McpGatewayCall {
  readonly service: string;
  readonly name: string;
  readonly argumentsJson: Uint8Array;
}

export interface McpGateway<Result> {
  parse(command: McpCommand): McpCommand;
  execute(command: McpCommand): Promise<Result>;
  executePlan(command: VerifiedPlanCommand<McpCommand>): Promise<readonly Result[]>;
}

export interface McpAuthority {
  readonly profile: "auths.mcp";
  readonly capability: "tools/call";
  readonly resource: string;
  readonly audience: string;
}

export interface McpReceipt<Result> {
  readonly profile: "auths.mcp";
  readonly idempotencyKey: string;
  readonly outcome: "executed" | "failed" | "outcome-unknown";
  readonly result?: Result;
}

export interface McpGatewayError {
  readonly profile: "auths.mcp";
  readonly code: string;
  readonly retry: "never" | "safe" | "conditional" | "unknown";
  readonly effect: "not-applied" | "applied" | "unknown";
}

export type McpHandlerOutcome<Result> =
  | Readonly<{ readonly effect: "applied"; readonly result: Result }>
  | Readonly<{ readonly effect: "not-applied"; readonly cause?: McpHandlerCause }>
  | Readonly<{ readonly effect: "possible"; readonly cause?: McpHandlerCause }>;

export type McpHandlerCause =
  | "cancelled"
  | "invalid-output"
  | "limit-exceeded"
  | "timeout"
  | "unavailable"
  | "unknown";

export interface McpToolContext {
  readonly executionId: string;
  readonly service: string;
  readonly tool: string;
}

export type McpToolHandler<Result = unknown> = (
  input: Readonly<Record<string, unknown>>,
  context: McpToolContext,
  signal: AbortSignal,
) => Promise<Result | McpHandlerOutcome<Result>>;

export interface McpClosedProvider {
  invoke(
    service: string,
    tool: string,
    argumentsValue: Readonly<Record<string, unknown>>,
    context: McpToolContext,
    signal: AbortSignal,
  ): Promise<unknown | McpHandlerOutcome<unknown>>;
  reconcile(
    executionId: string,
    service: string,
    signal: AbortSignal,
  ): Promise<McpHandlerOutcome<unknown>>;
}

export interface McpExecutionState {
  reserve(executionId: string): Promise<"acquired" | "exact-replay" | "conflict">;
  markProviderEntry(executionId: string): Promise<void>;
  saveRecovery(reference: string, recordJson: Uint8Array): Promise<void>;
  loadRecovery(reference: string): Promise<Uint8Array | undefined>;
}

export interface McpReceiptSink {
  persist(executionId: string, receiptJson: Uint8Array): Promise<void>;
}

export interface McpExecutionResources {
  readonly provider: McpClosedProvider;
  readonly state: McpExecutionState;
  readonly receipts: McpReceiptSink;
  readonly sessionKey: Uint8Array;
  readonly signal?: AbortSignal;
  readonly requestId?: string;
}

export interface McpDevelopmentProviderOptions {
  readonly tools: Readonly<Record<string, McpToolHandler>>;
  readonly timeoutMs?: number;
  readonly reconcile?: (
    executionId: string,
    service: string,
    signal: AbortSignal,
  ) => Promise<McpHandlerOutcome<unknown>>;
}

export type McpClosedResult =
  | Readonly<{ readonly kind: "completed"; readonly executionId: string; readonly result: unknown; readonly receipt: Uint8Array }>
  | Readonly<{ readonly kind: "not-applied" | "exact-replay" | "conflict"; readonly executionId: string }>
  | Readonly<{ readonly kind: "recoverable"; readonly executionId: string; readonly executionReference: string }>;

/** Closed MCP tool-call action constructible only by this profile facade. */
export class McpAction {
  readonly name: string;

  private constructor(
    token: typeof MCP_ACTION_TOKEN,
    profile: McpProfile,
    name: string,
    argumentsValue: Readonly<Record<string, unknown>>,
  ) {
    if (token !== MCP_ACTION_TOKEN) throw new TypeError("sealed Auths MCP action");
    this.name = name;
    actionResources.set(this, {
      profile,
      name,
      argumentsValue,
    });
    Object.freeze(this);
  }

  private static create(
    token: typeof MCP_ACTION_TOKEN,
    profile: McpProfile,
    name: string,
    argumentsValue: Readonly<Record<string, unknown>>,
  ): McpAction {
    if (token !== MCP_ACTION_TOKEN) throw new TypeError("sealed Auths MCP action");
    return new McpAction(token, profile, name, argumentsValue);
  }

  static {
    mintMcpAction = (profile, name, argumentsValue) =>
      McpAction.create(MCP_ACTION_TOKEN, profile, name, argumentsValue);
  }
}

/** Package-owned `auths.mcp/1` profile bound to one logical MCP service. */
export class McpProfile implements Profile<McpAction, McpCommand> {
  readonly id = PROFILE_ID;
  readonly version = PROFILE_VERSION;
  readonly service: string;
  declare readonly __action?: McpAction;
  declare readonly __command?: McpCommand;

  private constructor(token: typeof MCP_PROFILE_TOKEN, service: string) {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    this.service = service;
  }

  private static create(token: typeof MCP_PROFILE_TOKEN, service: string): McpProfile {
    if (token !== MCP_PROFILE_TOKEN) throw new TypeError("sealed Auths MCP profile");
    const profile = new McpProfile(token, service);
    registerProfileRuntime(profile, {
      authorize: (agent, action, approvalOverride) => authorizeMcp(
        agent,
        profile,
        action,
        approvalOverride,
      ),
    });
    return Object.freeze(profile);
  }

  static {
    mintMcpProfile = (service) => McpProfile.create(MCP_PROFILE_TOKEN, service);
  }

  call(name: string, argumentsValue: Readonly<Record<string, unknown>>): McpAction {
    return mintMcpAction(
      this,
      boundedToolName(name),
      copyArguments(argumentsValue),
    );
  }

  async plan(actions: readonly McpAction[]): Promise<ProfilePlan<McpAction>> {
    const resources = actions.map((action) => {
      const item = actionResources.get(action);
      if (item === undefined || item.profile !== this) {
        throw new AuthsWorkflowError("invalid-profile", "MCP plan contains an action from another profile");
      }
      return item;
    });
    const engine = await loadPackagedWorkflowEngine();
    return createProfilePlan(this, actions, (action) => {
      const resources = actionResources.get(action);
      if (resources === undefined || resources.profile !== this) {
        throw new AuthsWorkflowError("invalid-profile", "MCP plan contains an action from another profile");
      }
      try {
        return engine.canonicalizeMcpPlanMemberV1(
          this.service,
          resources.name,
          resources.argumentsValue,
        );
      } catch {
        throw new AuthsWorkflowError(
          "invalid-profile",
          "native MCP profile rejected a plan member",
        );
      }
    }, {
      permissions: resources.map((item) => Object.freeze({
        capability: "tools/call",
        resource: `mcp://${this.service}/tools/${item.name}`,
      })),
      resourceNamespaces: [ `mcp://${this.service}` ],
      audiences: [ `mcp://${this.service}` ],
    });
  }

  gateway<Result>(execute: (call: McpGatewayCall) => Promise<Result>): McpGateway<Result> {
    if (typeof execute !== "function") {
      throw new AuthsWorkflowError("invalid-profile", "MCP gateway executor is missing");
    }
    const profile = this;
    return Object.freeze({
      parse(command: McpCommand): McpCommand {
        const resources = commandResources.get(command);
        if (resources === undefined || resources.profile !== profile) {
          throw new AuthsWorkflowError("invalid-profile", "MCP command is forged or belongs to another profile");
        }
        return command;
      },
      async execute(command: McpCommand): Promise<Result> {
        const resources = commandResources.get(command);
        if (resources === undefined || resources.profile !== profile) {
          throw new AuthsWorkflowError("invalid-profile", "MCP command is forged, consumed, or belongs to another profile");
        }
        commandResources.delete(command);
        return execute(Object.freeze({
          service: profile.service,
          name: resources.name,
          argumentsJson: resources.argumentsJson.slice(),
        }));
      },
      async executePlan(command: VerifiedPlanCommand<McpCommand>): Promise<readonly Result[]> {
        const commands = commandsForGateway(command);
        const results: Result[] = [];
        for (const member of commands) results.push(await this.execute(member));
        return Object.freeze(results);
      },
    });
  }
}

export interface McpProfileOptions {
  readonly service: string;
}

export const mcp = Object.freeze({
  profile(options: McpProfileOptions): McpProfile {
    if (options === null || typeof options !== "object") {
      throw new AuthsWorkflowError("invalid-profile", "MCP profile options are missing");
    }
    return mintMcpProfile(boundedService(options.service));
  },
  developmentProvider(options: McpDevelopmentProviderOptions): McpClosedProvider & AsyncDisposable & { close(): Promise<void> } {
    return new DevelopmentMcpProvider(options);
  },
});

class DevelopmentMcpProvider implements McpClosedProvider, AsyncDisposable {
  readonly #tools: ReadonlyMap<string, McpToolHandler>;
  readonly #timeoutMs: number;
  readonly #reconcile: McpDevelopmentProviderOptions["reconcile"];
  readonly #active = new Set<AbortController>();
  #closed = false;

  constructor(options: McpDevelopmentProviderOptions) {
    if (options === null || typeof options !== "object" || options.tools === null || typeof options.tools !== "object" || Array.isArray(options.tools)) {
      throw new TypeError("MCP development provider requires a bounded tool map");
    }
    const names = Reflect.ownKeys(options.tools);
    if (names.some((name) => typeof name !== "string") || names.length === 0 || names.length > MCP_PROFILE.limits.toolCount) {
      throw new TypeError("MCP tool declarations are outside profile limits");
    }
    const tools = new Map<string, McpToolHandler>();
    for (const name of names as string[]) {
      const handler = options.tools[name];
      if (typeof handler !== "function") throw new TypeError("MCP tool handler is not callable");
      tools.set(boundedToolName(name), handler);
    }
    const timeoutMs = options.timeoutMs ?? MCP_PROFILE.limits.defaultDurationMs;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MCP_PROFILE.limits.maximumDurationMs) {
      throw new TypeError("MCP handler timeout is outside profile limits");
    }
    if (options.reconcile !== undefined && typeof options.reconcile !== "function") {
      throw new TypeError("MCP reconciler is not callable");
    }
    this.#tools = tools;
    this.#timeoutMs = timeoutMs;
    this.#reconcile = options.reconcile;
  }

  async invoke(
    _service: string,
    tool: string,
    argumentsValue: Readonly<Record<string, unknown>>,
    context: McpToolContext,
    signal: AbortSignal,
  ): Promise<unknown | McpHandlerOutcome<unknown>> {
    this.#assertOpen();
    const handler = this.#tools.get(tool);
    if (handler === undefined) return Object.freeze({ effect: "not-applied", cause: "invalid-output" });
    return this.#boundedCall((boundedSignal) => handler(argumentsValue, context, boundedSignal), signal);
  }

  async reconcile(
    executionId: string,
    service: string,
    signal: AbortSignal,
  ): Promise<McpHandlerOutcome<unknown>> {
    this.#assertOpen();
    if (this.#reconcile === undefined) return Object.freeze({ effect: "possible", cause: "unavailable" });
    return this.#boundedCall((boundedSignal) => this.#reconcile!(executionId, service, boundedSignal), signal);
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const controller of this.#active) controller.abort();
    this.#active.clear();
  }

  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  async #boundedCall<Result>(operation: (signal: AbortSignal) => Promise<Result>, outer: AbortSignal): Promise<Result> {
    const controller = new AbortController();
    this.#active.add(controller);
    const onAbort = () => controller.abort();
    outer.addEventListener("abort", onAbort, { once: true });
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      const deadline = new Promise<never>((_, reject) => {
        timeout = setTimeout(() => {
          controller.abort();
          reject(Object.assign(new Error("MCP handler deadline elapsed"), { name: "TimeoutError" }));
        }, this.#timeoutMs);
      });
      return await Promise.race([operation(controller.signal), deadline]);
    } finally {
      if (timeout !== undefined) clearTimeout(timeout);
      outer.removeEventListener("abort", onAbort);
      this.#active.delete(controller);
    }
  }

  #assertOpen(): void {
    if (this.#closed) throw Object.assign(new Error("MCP provider is closed"), { name: "AbortError" });
  }
}

async function authorizeMcp(
  agent: AttachedAgent<Profile>,
  profile: McpProfile,
  candidate: unknown,
  approvalOverride?: ApprovalConfiguration,
  observeArtifacts?: (artifacts: VerifiedArtifactView) => void,
): Promise<AuthorizationResult<McpCommand>> {
  agent.assertActive();
  const action = candidate instanceof McpAction ? actionResources.get(candidate) : undefined;
  if (action === undefined || action.profile !== profile) {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "action was not created by the attached MCP profile",
    );
  }
  const resources = resourcesForAttachedAgent(agent);
  const engine = engineForClient(resources.client);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const evaluationTime = BigInt(Math.floor(Date.now() / 1000));
  let preparation;
  try {
    preparation = engine.prepareMcpActionV1(
      profile.service,
      action.name,
      action.argumentsValue,
      agent.identity.principal.principal,
      resources.signedGrant.slice(),
      challenge,
      evaluationTime,
    );
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "native MCP profile rejected the proposed tool call",
    );
  }
  const argumentsJson = preparation.argumentsJson.slice();
  const result = await authorizePreparedAction(
    agent,
    preparation,
    Object.freeze([
      Object.freeze({ label: "Service", value: profile.service }),
      Object.freeze({ label: "Tool", value: action.name }),
      Object.freeze({ label: "Resource", value: preparation.resource }),
      Object.freeze({ label: "Canonical digest", value: preparation.displayDigestHex }),
    ]),
    approvalOverride,
    observeArtifacts,
  );
  if (result.kind !== "authorized") return result;
  return Object.freeze({
    ...result,
    command: mintMcpCommand({
      profile,
      name: action.name,
      argumentsJson,
    }),
  });
}

export async function executeMcpClosed(
  agent: AttachedAgent<Profile>,
  action: McpAction,
  resources: McpExecutionResources,
): Promise<Exclude<AuthorizationResult<McpCommand>, { readonly kind: "authorized" }> | McpClosedResult> {
  const sessionKey = boundedSessionKey(resources.sessionKey);
  let artifacts: VerifiedArtifactView | undefined;
  const authorization = await authorizeMcp(agent, actionResources.get(action)?.profile ?? invalidProfile(), action, undefined, (value) => {
    artifacts = Object.freeze({
      proofCbor: value.proofCbor.slice(),
      canonicalActionCbor: value.canonicalActionCbor.slice(),
      trustedContextCbor: value.trustedContextCbor.slice(),
    });
  });
  if (authorization.kind !== "authorized") return authorization;
  if (artifacts === undefined) {
    throw new AuthsWorkflowError("gateway-failed", "native MCP authorization omitted execution artifacts");
  }
  const engine = engineForClient(resourcesForAttachedAgent(agent).client);
  const session = engine.beginMcpExecutionV1(
    artifacts.proofCbor,
    artifacts.canonicalActionCbor,
    artifacts.trustedContextCbor,
    resources.requestId,
    sessionKey,
  );
  return driveMcpSession(session, resources);
}

export async function resumeMcpClosed(
  agent: AttachedAgent<Profile>,
  reference: string,
  resources: Omit<McpExecutionResources, "requestId">,
): Promise<McpClosedResult> {
  const record = await resources.state.loadRecovery(reference);
  if (record === undefined) {
    throw new AuthsWorkflowError("gateway-conflict", "MCP execution reference has no matching state");
  }
  const engine = engineForClient(resourcesForAttachedAgent(agent).client);
  const session = engine.resumeMcpExecutionV1(
    boundedSessionKey(resources.sessionKey),
    boundedReference(reference),
    record.slice(),
  );
  return driveMcpSession(session, resources);
}

async function driveMcpSession(
  session: WorkflowMcpExecutionSession,
  resources: Omit<McpExecutionResources, "requestId">,
): Promise<McpClosedResult> {
  const signal = resources.signal ?? new AbortController().signal;
  try {
    for (;;) {
      const terminal = session.terminal();
      if (terminal !== null) return projectTerminal(terminal, resources.state);
      const step = session.nextStep();
      switch (step.kind) {
        case "reserve":
          session.acceptReservation(await resources.state.reserve(step.executionId));
          break;
        case "mark-provider-entry":
          if (signal.aborted) {
            session.cancelBeforeProvider();
            break;
          }
          await resources.state.markProviderEntry(step.executionId);
          session.acceptProviderEntry();
          break;
        case "invoke":
          await invokeMcpHandler(session, step, resources.provider, signal);
          break;
        case "persist-receipt":
          try {
            await resources.receipts.persist(step.executionId, requiredBytes(step.bytes));
            session.acceptReceipt(true);
          } catch {
            try {
              session.acceptReceipt(false);
            } catch {}
          }
          break;
        case "reconcile":
          await reconcileMcpHandler(session, step.executionId, requiredString(step.service), resources.provider, signal);
          break;
      }
    }
  } finally {
    session.free?.();
  }
}

async function invokeMcpHandler(
  session: WorkflowMcpExecutionSession,
  step: Readonly<{ readonly executionId: string; readonly service?: string; readonly tool?: string; readonly bytes?: Uint8Array }>,
  provider: McpClosedProvider,
  signal: AbortSignal,
): Promise<void> {
  const service = requiredString(step.service);
  const tool = requiredString(step.tool);
  let argumentsValue: Readonly<Record<string, unknown>>;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(requiredBytes(step.bytes)));
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError();
    argumentsValue = Object.freeze(parsed as Record<string, unknown>);
  } catch {
    session.acceptHandler("possible", undefined, "invalid-output");
    return;
  }
  try {
    const observed = await provider.invoke(
      service,
      tool,
      argumentsValue,
      Object.freeze({ executionId: step.executionId, service, tool }),
      signal,
    );
    acceptMcpObservation(session, observed);
  } catch (error) {
    session.acceptHandler("possible", undefined, profileCause(error));
  }
}

async function reconcileMcpHandler(
  session: WorkflowMcpExecutionSession,
  executionId: string,
  service: string,
  provider: McpClosedProvider,
  signal: AbortSignal,
): Promise<void> {
  try {
    acceptMcpObservation(session, await provider.reconcile(executionId, service, signal));
  } catch (error) {
    session.acceptHandler("possible", undefined, profileCause(error));
  }
}

function acceptMcpObservation(
  session: WorkflowMcpExecutionSession,
  observed: unknown | McpHandlerOutcome<unknown>,
): void {
  if (isMcpOutcome(observed)) {
    if (observed.effect === "applied") {
      acceptApplied(session, observed.result);
    } else {
      session.acceptHandler(observed.effect, undefined, observed.cause);
    }
    return;
  }
  acceptApplied(session, observed);
}

function acceptApplied(session: WorkflowMcpExecutionSession, result: unknown): void {
  try {
    const encoded = new TextEncoder().encode(JSON.stringify(result ?? null));
    session.acceptHandler("applied", encoded);
  } catch {
    session.acceptHandler("possible", undefined, "invalid-output");
  }
}

function isMcpOutcome(value: unknown): value is McpHandlerOutcome<unknown> {
  if (value === null || typeof value !== "object") return false;
  const effect = (value as { readonly effect?: unknown }).effect;
  return effect === "applied" || effect === "not-applied" || effect === "possible";
}

async function projectTerminal(
  terminal: WorkflowMcpSessionTerminal,
  state: McpExecutionState,
): Promise<McpClosedResult> {
  if (terminal.kind === "completed") {
    return Object.freeze({
      kind: "completed",
      executionId: terminal.executionId,
      result: JSON.parse(new TextDecoder().decode(requiredBytes(terminal.outputJson))),
      receipt: requiredBytes(terminal.receiptJson).slice(),
    });
  }
  if (terminal.kind === "recoverable") {
    const reference = boundedReference(terminal.reference);
    await state.saveRecovery(reference, requiredBytes(terminal.recordJson));
    return Object.freeze({ kind: "recoverable", executionId: terminal.executionId, executionReference: reference });
  }
  return Object.freeze({ kind: terminal.kind, executionId: terminal.executionId });
}

function invalidProfile(): never {
  throw new AuthsWorkflowError("invalid-profile", "action was not created by an MCP profile");
}

function boundedSessionKey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== 32) {
    throw new AuthsWorkflowError("configuration-mismatch", "MCP session key must contain 32 bytes");
  }
  return value.slice();
}

function boundedReference(value: string | undefined): string {
  if (typeof value !== "string" || value.length === 0 || value.length > 256 || !/^mcp1\.[a-f0-9]{64}\.[a-f0-9]{64}$/.test(value)) {
    throw new AuthsWorkflowError("gateway-conflict", "MCP execution reference is invalid");
  }
  return value;
}

function profileCause(value: unknown): McpHandlerCause {
  const cause = causeCategoryFrom(value);
  if (cause === "invalid-response") return "invalid-output";
  return cause === "conflict" || cause === "corrupt-state" ? "unknown" : cause;
}

function requiredString(value: string | undefined): string {
  if (value === undefined) throw new AuthsWorkflowError("gateway-failed", "native MCP step omitted a required field");
  return value;
}

function requiredBytes(value: Uint8Array | undefined): Uint8Array {
  if (!(value instanceof Uint8Array)) throw new AuthsWorkflowError("gateway-failed", "native MCP step omitted bounded bytes");
  return value;
}

function copyArguments(
  value: Readonly<Record<string, unknown>>,
): Readonly<Record<string, unknown>> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new AuthsWorkflowError("invalid-profile", "MCP arguments must be an object");
  }
  try {
    return Object.freeze(structuredClone(value));
  } catch {
    throw new AuthsWorkflowError(
      "invalid-profile",
      "MCP arguments cannot be retained safely",
    );
  }
}

function boundedService(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > 64 ||
    !/^[a-z0-9._-]+$/.test(value)
  ) {
    throw new AuthsWorkflowError("invalid-profile", "MCP service is outside profile limits");
  }
  return value;
}

function boundedToolName(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    new TextEncoder().encode(value).length > 128 ||
    !/^[a-zA-Z0-9._-]+$/.test(value)
  ) {
    throw new AuthsWorkflowError("invalid-profile", "MCP tool name is outside profile limits");
  }
  return value;
}
