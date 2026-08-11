import {
  runtimeChallenge,
  type BudgetClaim,
  type BudgetPort,
  type ChallengePort,
  type ReceiptPort,
  type ReplayPort,
  type RuntimeChallenge,
  type RuntimeReceipt,
  type ExecutionRecord,
  type ExecutionState,
  type ExecutionStatePort,
} from "../runtime.js";

export class InMemoryChallengePort implements ChallengePort {
  #counter = 0;

  async issue(): Promise<RuntimeChallenge> {
    const bytes = new Uint8Array(32);
    const counter = ++this.#counter;
    bytes[28] = counter >>> 24;
    bytes[29] = counter >>> 16;
    bytes[30] = counter >>> 8;
    bytes[31] = counter;
    return runtimeChallenge(bytes);
  }
}

export class InMemoryReplayPort implements ReplayPort {
  readonly #claimed = new Set<string>();

  async claim(challenge: Uint8Array): Promise<"claimed" | "duplicate"> {
    const key = Array.from(challenge, (value) => value.toString(16).padStart(2, "0")).join("");
    if (this.#claimed.has(key)) return "duplicate";
    this.#claimed.add(key);
    return "claimed";
  }

  get size(): number {
    return this.#claimed.size;
  }
}

export class InMemoryBudgetPort implements BudgetPort {
  readonly #remaining = new Map<string, bigint>();

  constructor(initial: Readonly<Record<string, bigint>>) {
    for (const [account, value] of Object.entries(initial)) this.#remaining.set(account, value);
  }

  async claim(request: BudgetClaim): Promise<"claimed" | "exhausted"> {
    const remaining = this.#remaining.get(request.account) ?? 0n;
    if (request.value < 1n || request.value > remaining) return "exhausted";
    this.#remaining.set(request.account, remaining - request.value);
    return "claimed";
  }

  remaining(account: string): bigint {
    return this.#remaining.get(account) ?? 0n;
  }
}

export class InMemoryReceiptPort implements ReceiptPort {
  readonly #receipts: RuntimeReceipt[] = [];

  async record(receipt: RuntimeReceipt): Promise<"recorded"> {
    this.#receipts.push(Object.freeze({ ...receipt, challenge: receipt.challenge.slice() }));
    return "recorded";
  }

  get receipts(): readonly RuntimeReceipt[] {
    return Object.freeze(this.#receipts.map((receipt) => Object.freeze({
      ...receipt,
      challenge: receipt.challenge.slice(),
    })));
  }
}

export class InMemoryExecutionStatePort implements ExecutionStatePort {
  readonly #records = new Map<string, ExecutionRecord>();

  async reserve(record: ExecutionRecord): Promise<"reserved" | "duplicate"> {
    if (this.#records.has(record.idempotencyKey)) return "duplicate";
    this.#records.set(record.idempotencyKey, copyRecord({ ...record, state: "reserved" }));
    return "reserved";
  }

  async transition(
    idempotencyKey: string,
    expected: ExecutionState,
    next: ExecutionState,
  ): Promise<"transitioned" | "conflict"> {
    const current = this.#records.get(idempotencyKey);
    if (current === undefined || current.state !== expected) return "conflict";
    this.#records.set(idempotencyKey, copyRecord({ ...current, state: next }));
    return "transitioned";
  }

  async load(idempotencyKey: string): Promise<ExecutionRecord | undefined> {
    const record = this.#records.get(idempotencyKey);
    return record === undefined ? undefined : copyRecord(record);
  }
}

function copyRecord(record: ExecutionRecord): ExecutionRecord {
  return Object.freeze({ ...record, challenge: record.challenge.slice() });
}
