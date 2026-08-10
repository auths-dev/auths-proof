import type { AuthorizationResult } from "./workflow.js";

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
}

export interface ReceiptPort {
  record(receipt: RuntimeReceipt): Promise<"recorded" | "unavailable">;
}

export interface ClosedExecutorPort<Command, Output> {
  parse(command: Command): Command;
  execute(command: Command): Promise<Output>;
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
      stage: "challenge" | "replay" | "budget";
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
