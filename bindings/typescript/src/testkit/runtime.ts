import {
  runtimeChallenge,
  type BudgetClaim,
  type BudgetPort,
  type ChallengePort,
  type ReceiptPort,
  type ReplayPort,
  type RuntimeChallenge,
  type RuntimeReceipt,
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
