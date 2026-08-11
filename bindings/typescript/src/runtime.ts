import type { AuthorizationResult } from "./workflow.js";
import { emitAuthsEvent, type TelemetryPort, type TelemetryStage } from "./observability.js";

const CHALLENGE_TOKEN = Symbol("auths-runtime-challenge");

export class RuntimeChallenge {
  readonly #bytes: Uint8Array;

  private constructor(token: typeof CHALLENGE_TOKEN, bytes: Uint8Array) {
    if (token !== CHALLENGE_TOKEN) throw new TypeError("sealed Auths runtime challenge");
    this.#bytes = bytes;
    Object.freeze(this);
  }

  static parse(token: typeof CHALLENGE_TOKEN, bytes: Uint8Array): RuntimeChallenge {
    if (token !== CHALLENGE_TOKEN || !(bytes instanceof Uint8Array) || bytes.length !== 32) {
      throw new TypeError("runtime challenge must contain 32 bytes");
    }
    return new RuntimeChallenge(token, bytes.slice());
  }

  copy(token: typeof CHALLENGE_TOKEN): Uint8Array {
    if (token !== CHALLENGE_TOKEN) throw new TypeError("sealed Auths runtime challenge");
    return this.#bytes.slice();
  }
}

export function runtimeChallenge(bytes: Uint8Array): RuntimeChallenge {
  return RuntimeChallenge.parse(CHALLENGE_TOKEN, bytes);
}

export interface ChallengePort {
  issue(): Promise<RuntimeChallenge>;
}

export interface ReplayPort {
  claim(challenge: Uint8Array): Promise<"claimed" | "duplicate" | "unavailable">;
}

export interface BudgetClaim {
  readonly account: string;
  readonly algebra: string;
  readonly value: bigint;
}

export interface BudgetPort {
  claim(request: BudgetClaim): Promise<"claimed" | "exhausted" | "unavailable">;
}

export interface RuntimeReceipt {
  readonly challenge: Uint8Array;
  readonly outcome: "executed" | "failed" | "outcome-unknown";
  readonly idempotencyKey?: string;
}

export interface ReceiptPort {
  record(receipt: RuntimeReceipt): Promise<"recorded" | "unavailable">;
}

export interface ClosedExecutorPort<Command, Output> {
  parse(command: Command): Command;
  execute(
    command: Command,
    context?: Readonly<{ readonly idempotencyKey: string; readonly signal?: AbortSignal }>,
  ): Promise<Output>;
}

export class RuntimeExecutionError extends Error {
  readonly effect: "not-applied" | "unknown";

  constructor(effect: "not-applied" | "unknown") {
    super("closed executor failed");
    this.name = "RuntimeExecutionError";
    this.effect = effect;
  }
}

export interface RuntimeExecutionOptions<Command, Output> {
  readonly challenge: RuntimeChallenge | ChallengePort;
  readonly replay: ReplayPort;
  readonly budget?: Readonly<{ port: BudgetPort; claim: BudgetClaim }>;
  readonly receipts: ReceiptPort;
  readonly executor: ClosedExecutorPort<Command, Output>;
}

export type RuntimeClaims = Readonly<{
  replay: "claimed";
  budget: "not-required" | "claimed";
}>;

export type RuntimeExecutionResult<Output> =
  | Readonly<{ kind: "not-authorized"; verdict: "denied" | "indeterminate" }>
  | Readonly<{ kind: "invalid-command" }>
  | Readonly<{ kind: "duplicate" }>
  | Readonly<{ kind: "exhausted"; replay: "claimed" }>
  | Readonly<{
      kind: "unavailable";
      stage: "challenge" | "replay" | "budget" | "state";
      replay: "not-claimed" | "claimed";
    }>
  | Readonly<{ kind: "executed"; output: Output; claims: RuntimeClaims; receipt: "recorded" }>
  | Readonly<{ kind: "failed"; claims: RuntimeClaims; receipt: "recorded" | "unavailable" }>
  | Readonly<{
      kind: "outcome-unknown";
      claims: RuntimeClaims;
      stage: "executor" | "receipt";
    }>;

export async function executeAuthorized<Command, Output>(
  authorization: AuthorizationResult<Command>,
  options: RuntimeExecutionOptions<Command, Output>,
): Promise<RuntimeExecutionResult<Output>> {
  if (authorization.kind !== "authorized") {
    return Object.freeze({ kind: "not-authorized", verdict: authorization.kind });
  }

  let parsed: Command;
  try {
    parsed = options.executor.parse(authorization.command);
  } catch {
    return Object.freeze({ kind: "invalid-command" });
  }
  if (parsed !== authorization.command) {
    return Object.freeze({ kind: "invalid-command" });
  }

  let challenge: RuntimeChallenge;
  try {
    challenge = options.challenge instanceof RuntimeChallenge
      ? options.challenge
      : await options.challenge.issue();
  } catch {
    return Object.freeze({ kind: "unavailable", stage: "challenge", replay: "not-claimed" });
  }
  if (!(challenge instanceof RuntimeChallenge)) {
    return Object.freeze({ kind: "unavailable", stage: "challenge", replay: "not-claimed" });
  }
  const challengeBytes = challenge.copy(CHALLENGE_TOKEN);
  const replay = await claimReplay(options.replay, challengeBytes);
  if (replay === "duplicate") return Object.freeze({ kind: "duplicate" });
  if (replay === "unavailable") {
    return Object.freeze({ kind: "unavailable", stage: "replay", replay: "not-claimed" });
  }

  let budget: RuntimeClaims["budget"] = "not-required";
  if (options.budget !== undefined) {
    const claim = await claimBudget(options.budget.port, options.budget.claim);
    if (claim === "exhausted") return Object.freeze({ kind: "exhausted", replay: "claimed" });
    if (claim === "unavailable") {
      return Object.freeze({ kind: "unavailable", stage: "budget", replay: "claimed" });
    }
    budget = "claimed";
  }
  const claims = Object.freeze({ replay: "claimed" as const, budget });

  let output: Output;
  try {
    output = await options.executor.execute(parsed);
  } catch (error) {
    const outcome = error instanceof RuntimeExecutionError && error.effect === "not-applied"
      ? "failed"
      : "outcome-unknown";
    const receipt = await recordReceipt(options.receipts, challengeBytes, outcome);
    if (outcome === "failed") return Object.freeze({ kind: "failed", claims, receipt });
    return Object.freeze({ kind: "outcome-unknown", claims, stage: "executor" });
  }

  const receipt = await recordReceipt(options.receipts, challengeBytes, "executed");
  if (receipt === "unavailable") {
    return Object.freeze({ kind: "outcome-unknown", claims, stage: "receipt" });
  }
  return Object.freeze({ kind: "executed", output, claims, receipt });
}

async function claimReplay(
  port: ReplayPort,
  challenge: Uint8Array,
): Promise<"claimed" | "duplicate" | "unavailable"> {
  try {
    const result = await port.claim(challenge.slice());
    return result === "claimed" || result === "duplicate" ? result : "unavailable";
  } catch {
    return "unavailable";
  }
}

async function claimBudget(
  port: BudgetPort,
  claim: BudgetClaim,
): Promise<"claimed" | "exhausted" | "unavailable"> {
  try {
    const result = await port.claim(Object.freeze({ ...claim }));
    return result === "claimed" || result === "exhausted" ? result : "unavailable";
  } catch {
    return "unavailable";
  }
}

async function recordReceipt(
  port: ReceiptPort,
  challenge: Uint8Array,
  outcome: RuntimeReceipt["outcome"],
): Promise<"recorded" | "unavailable"> {
  try {
    return await port.record(Object.freeze({ challenge: challenge.slice(), outcome })) === "recorded"
      ? "recorded"
      : "unavailable";
  } catch {
    return "unavailable";
  }
}

export type ExecutionState =
  | "pre-effect"
  | "reserved"
  | "executing"
  | "executed"
  | "failed"
  | "cancelled"
  | "exhausted"
  | "unavailable"
  | "outcome-unknown";

export interface ExecutionRecord {
  readonly idempotencyKey: string;
  readonly challenge: Uint8Array;
  readonly state: ExecutionState;
}

export interface ExecutionStatePort {
  reserve(record: ExecutionRecord): Promise<"reserved" | "duplicate" | "unavailable">;
  transition(
    idempotencyKey: string,
    expected: ExecutionState,
    next: ExecutionState,
  ): Promise<"transitioned" | "conflict" | "unavailable">;
  load(idempotencyKey: string): Promise<ExecutionRecord | undefined>;
}

export interface ReconciliationPort<Output> {
  reconcile(idempotencyKey: string): Promise<
    | Readonly<{ readonly kind: "executed"; readonly output: Output }>
    | Readonly<{ readonly kind: "failed" }>
    | Readonly<{ readonly kind: "pending" | "unknown" }>
  >;
}

export interface ClosedRuntimeOptions<Command, Output> {
  readonly challenges: ChallengePort;
  readonly replay: ReplayPort;
  readonly state: ExecutionStatePort;
  readonly receipts: ReceiptPort;
  readonly executor: ClosedExecutorPort<Command, Output>;
  readonly budget?: Readonly<{ readonly port: BudgetPort; readonly claim: BudgetClaim }>;
  readonly reconciliation?: ReconciliationPort<Output>;
  readonly telemetry?: TelemetryPort;
  readonly correlationId?: () => string;
}

export type ClosedRuntimeResult<Output> =
  | RuntimeExecutionResult<Output>
  | Readonly<{ readonly kind: "cancelled"; readonly state: "pre-effect" | "reserved" }>
  | Readonly<{ readonly kind: "conflict"; readonly state: ExecutionState }>
  | Readonly<{
      readonly kind: "reconciled";
      readonly outcome: "executed" | "failed";
      readonly output?: Output;
    }>;

/** Production-shaped stateful runtime with explicit idempotency and reconciliation. */
export class ClosedRuntime<Command, Output> {
  readonly #options: ClosedRuntimeOptions<Command, Output>;

  constructor(options: ClosedRuntimeOptions<Command, Output>) {
    this.#options = options;
  }

  async execute(
    authorization: AuthorizationResult<Command>,
    input: Readonly<{ readonly idempotencyKey: string; readonly signal?: AbortSignal }>,
  ): Promise<ClosedRuntimeResult<Output>> {
    const correlationId = this.#options.correlationId?.() ?? nextRuntimeCorrelationId();
    if (authorization.kind !== "authorized") {
      return Object.freeze({ kind: "not-authorized", verdict: authorization.kind });
    }
    if (input.idempotencyKey.length === 0 || input.idempotencyKey.length > 256) {
      throw new TypeError("idempotency key is outside bounds");
    }
    let command: Command;
    try {
      command = this.#options.executor.parse(authorization.command);
    } catch {
      return Object.freeze({ kind: "invalid-command" });
    }
    if (command !== authorization.command) return Object.freeze({ kind: "invalid-command" });
    if (isSignalAborted(input.signal)) return Object.freeze({ kind: "cancelled", state: "pre-effect" });

    let challenge: RuntimeChallenge;
    try {
      challenge = await this.#options.challenges.issue();
    } catch {
      return Object.freeze({ kind: "unavailable", stage: "challenge", replay: "not-claimed" });
    }
    if (!(challenge instanceof RuntimeChallenge)) {
      return Object.freeze({ kind: "unavailable", stage: "challenge", replay: "not-claimed" });
    }
    const challengeBytes = challenge.copy(CHALLENGE_TOKEN);
    const replay = await claimReplay(this.#options.replay, challengeBytes);
    if (replay === "duplicate") return this.#reconcile(input.idempotencyKey, "not-claimed");
    if (replay === "unavailable") {
      return Object.freeze({ kind: "unavailable", stage: "replay", replay: "not-claimed" });
    }
    const reserved = await reserveExecutionState(this.#options.state, Object.freeze({
      idempotencyKey: input.idempotencyKey,
      challenge: challengeBytes.slice(),
      state: "pre-effect",
    }));
    emitRuntimeEvent(this.#options.telemetry, correlationId, "reservation", reserved === "reserved" ? "succeeded" : "failed");
    if (reserved === "duplicate") return this.#reconcile(input.idempotencyKey, "claimed");
    if (reserved === "unavailable") {
      return Object.freeze({ kind: "unavailable", stage: "state", replay: "claimed" });
    }

    let budget: RuntimeClaims["budget"] = "not-required";
    if (this.#options.budget !== undefined) {
      const claim = await claimBudget(this.#options.budget.port, this.#options.budget.claim);
      if (claim === "exhausted") {
        const transition = await transitionExecutionState(
          this.#options.state, input.idempotencyKey, "reserved", "exhausted",
        );
        if (transition === "unavailable") {
          return Object.freeze({ kind: "unavailable", stage: "state", replay: "claimed" });
        }
        if (transition === "conflict") return Object.freeze({ kind: "conflict", state: "reserved" });
        return Object.freeze({ kind: "exhausted", replay: "claimed" });
      }
      if (claim === "unavailable") {
        const transition = await transitionExecutionState(
          this.#options.state, input.idempotencyKey, "reserved", "unavailable",
        );
        if (transition === "unavailable") {
          return Object.freeze({ kind: "unavailable", stage: "state", replay: "claimed" });
        }
        if (transition === "conflict") return Object.freeze({ kind: "conflict", state: "reserved" });
        return Object.freeze({ kind: "unavailable", stage: "budget", replay: "claimed" });
      }
      budget = "claimed";
    }
    const claims = Object.freeze({ replay: "claimed" as const, budget });
    if (isSignalAborted(input.signal)) {
      const transition = await transitionExecutionState(
        this.#options.state, input.idempotencyKey, "reserved", "cancelled",
      );
      if (transition === "unavailable") {
        return Object.freeze({ kind: "unavailable", stage: "state", replay: "claimed" });
      }
      if (transition === "conflict") return Object.freeze({ kind: "conflict", state: "reserved" });
      return Object.freeze({ kind: "cancelled", state: "reserved" });
    }
    const executing = await transitionExecutionState(
      this.#options.state, input.idempotencyKey, "reserved", "executing",
    );
    if (executing === "unavailable") {
      return Object.freeze({ kind: "unavailable", stage: "state", replay: "claimed" });
    }
    if (executing === "conflict") return Object.freeze({ kind: "conflict", state: "reserved" });
    emitRuntimeEvent(this.#options.telemetry, correlationId, "execution", "started");

    let output: Output;
    try {
      output = await this.#options.executor.execute(command, {
        idempotencyKey: input.idempotencyKey,
        ...(input.signal === undefined ? {} : { signal: input.signal }),
      });
    } catch (error) {
      const state = error instanceof RuntimeExecutionError && error.effect === "not-applied"
        ? "failed" as const
        : "outcome-unknown" as const;
      const transitioned = await transitionExecutionState(
        this.#options.state, input.idempotencyKey, "executing", state,
      );
      emitRuntimeEvent(this.#options.telemetry, correlationId, "execution", "failed");
      const receipt = await recordRuntimeReceipt(
        this.#options.receipts,
        challengeBytes,
        state,
        input.idempotencyKey,
      );
      emitRuntimeEvent(this.#options.telemetry, correlationId, "receipt", receipt === "recorded" ? "succeeded" : "failed");
      if (state === "failed" && transitioned === "transitioned") {
        return Object.freeze({ kind: "failed", claims, receipt });
      }
      return Object.freeze({ kind: "outcome-unknown", claims, stage: "executor" });
    }
    const transitioned = await transitionExecutionState(
      this.#options.state, input.idempotencyKey, "executing", "executed",
    );
    if (transitioned !== "transitioned") {
      await recordRuntimeReceipt(
        this.#options.receipts,
        challengeBytes,
        "outcome-unknown",
        input.idempotencyKey,
      );
      return Object.freeze({ kind: "outcome-unknown", claims, stage: "receipt" });
    }
    emitRuntimeEvent(this.#options.telemetry, correlationId, "execution", "succeeded");
    const receipt = await recordRuntimeReceipt(
      this.#options.receipts,
      challengeBytes,
      "executed",
      input.idempotencyKey,
    );
    emitRuntimeEvent(this.#options.telemetry, correlationId, "receipt", receipt === "recorded" ? "succeeded" : "failed");
    if (receipt === "unavailable") {
      return Object.freeze({ kind: "outcome-unknown", claims, stage: "receipt" });
    }
    return Object.freeze({ kind: "executed", output, claims, receipt });
  }

  async #reconcile(
    idempotencyKey: string,
    replay: "not-claimed" | "claimed",
  ): Promise<ClosedRuntimeResult<Output>> {
    const loaded = await loadExecutionState(this.#options.state, idempotencyKey);
    if (loaded.kind === "unavailable") {
      return Object.freeze({ kind: "unavailable", stage: "state", replay });
    }
    const record = loaded.record;
    if (record === undefined) return Object.freeze({ kind: "duplicate" });
    if (["executed", "failed", "executing", "outcome-unknown"].includes(record.state)) {
      if (this.#options.reconciliation === undefined) return Object.freeze({ kind: "duplicate" });
      let result;
      try {
        result = await this.#options.reconciliation.reconcile(idempotencyKey);
      } catch {
        return Object.freeze({ kind: "unavailable", stage: "state", replay });
      }
      if (result.kind === "executed") {
        return Object.freeze({
          kind: "reconciled" as const,
          outcome: "executed" as const,
          output: result.output,
        });
      }
      if (result.kind === "failed") return Object.freeze({ kind: "reconciled", outcome: "failed" });
    }
    return Object.freeze({ kind: "conflict", state: record.state });
  }
}

async function reserveExecutionState(
  port: ExecutionStatePort,
  record: ExecutionRecord,
): Promise<"reserved" | "duplicate" | "unavailable"> {
  try {
    const result = await port.reserve(record);
    return result === "reserved" || result === "duplicate" ? result : "unavailable";
  } catch {
    return "unavailable";
  }
}

async function transitionExecutionState(
  port: ExecutionStatePort,
  idempotencyKey: string,
  expected: ExecutionState,
  next: ExecutionState,
): Promise<"transitioned" | "conflict" | "unavailable"> {
  try {
    const result = await port.transition(idempotencyKey, expected, next);
    return result === "transitioned" || result === "conflict" ? result : "unavailable";
  } catch {
    return "unavailable";
  }
}

async function loadExecutionState(
  port: ExecutionStatePort,
  idempotencyKey: string,
): Promise<
  | Readonly<{ readonly kind: "loaded"; readonly record: ExecutionRecord | undefined }>
  | Readonly<{ readonly kind: "unavailable" }>
> {
  try {
    return Object.freeze({ kind: "loaded", record: await port.load(idempotencyKey) });
  } catch {
    return Object.freeze({ kind: "unavailable" });
  }
}

let runtimeCorrelationSequence = 0;

function nextRuntimeCorrelationId(): string {
  runtimeCorrelationSequence = (runtimeCorrelationSequence + 1) % Number.MAX_SAFE_INTEGER;
  return `auths-runtime-${Date.now().toString(36)}-${runtimeCorrelationSequence.toString(36)}`;
}

function emitRuntimeEvent(
  telemetry: TelemetryPort | undefined,
  correlationId: string,
  stage: Extract<TelemetryStage, "reservation" | "execution" | "receipt">,
  outcome: "started" | "succeeded" | "failed",
): void {
  void emitAuthsEvent(telemetry, {
    name: `auths.${stage}.${outcome}`,
    timestamp: Date.now(),
    correlationId,
    operation: "execute-command",
    stage,
    outcome,
  });
}

function isSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true;
}

async function recordRuntimeReceipt(
  port: ReceiptPort,
  challenge: Uint8Array,
  outcome: RuntimeReceipt["outcome"],
  idempotencyKey: string,
): Promise<"recorded" | "unavailable"> {
  try {
    return await port.record(Object.freeze({
      challenge: challenge.slice(),
      outcome,
      idempotencyKey,
    })) === "recorded" ? "recorded" : "unavailable";
  } catch {
    return "unavailable";
  }
}
