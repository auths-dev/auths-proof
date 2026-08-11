import assert from "node:assert/strict";
import test from "node:test";

import {
  ClosedRuntime,
  RuntimeExecutionError,
  executeAuthorized,
  runtimeChallenge,
} from "../../dist/runtime.js";
import {
  InMemoryBudgetPort,
  InMemoryChallengePort,
  InMemoryExecutionStatePort,
  InMemoryReceiptPort,
  InMemoryReplayPort,
} from "../../dist/testkit/index.js";

function authorized(command) {
  return { kind: "authorized", command };
}

test("runtime touches no state or gateway for non-authorized and invalid commands", async () => {
  const replay = new InMemoryReplayPort();
  const receipts = new InMemoryReceiptPort();
  let gatewayCalls = 0;
  const accepted = {};
  const executor = {
    parse(command) {
      if (command !== accepted) throw new Error("forged");
      return command;
    },
    async execute() {
      gatewayCalls += 1;
    },
  };
  const options = {
    challenge: runtimeChallenge(new Uint8Array(32).fill(1)),
    replay,
    receipts,
    executor,
  };

  assert.deepEqual(await executeAuthorized({ kind: "denied" }, options), {
    kind: "not-authorized",
    verdict: "denied",
  });
  assert.deepEqual(await executeAuthorized({ kind: "indeterminate" }, options), {
    kind: "not-authorized",
    verdict: "indeterminate",
  });
  assert.deepEqual(await executeAuthorized(authorized({}), options), { kind: "invalid-command" });
  assert.equal(replay.size, 0);
  assert.equal(receipts.receipts.length, 0);
  assert.equal(gatewayCalls, 0);
});

test("closed runtime commits idempotent execution states and receipts", async () => {
  const state = new InMemoryExecutionStatePort();
  const receipts = new InMemoryReceiptPort();
  const command = Object.freeze({ command: "publish" });
  let calls = 0;
  const runtime = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state,
    receipts,
    executor: {
      parse(candidate) {
        if (candidate !== command) throw new Error("forged");
        return candidate;
      },
      async execute(candidate, context) {
        assert.equal(candidate, command);
        assert.equal(context.idempotencyKey, "publish-august");
        calls += 1;
        return "published";
      },
    },
  });
  const result = await runtime.execute(authorized(command), { idempotencyKey: "publish-august" });
  assert.equal(result.kind, "executed");
  assert.equal((await state.load("publish-august")).state, "executed");
  assert.equal(receipts.receipts[0].idempotencyKey, "publish-august");
  assert.equal(calls, 1);
  assert.equal((await runtime.execute(authorized(command), {
    idempotencyKey: "publish-august",
  })).kind, "duplicate");
  assert.equal(calls, 1);
});

test("closed runtime emits a redacted reservation-to-receipt timeline", async () => {
  const events = [];
  const command = Object.freeze({ command: "publish" });
  const runtime = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state: new InMemoryExecutionStatePort(),
    receipts: new InMemoryReceiptPort(),
    correlationId: () => "runtime-test",
    telemetry: { emit(event) { events.push(event); } },
    executor: {
      parse(candidate) { return candidate === command ? candidate : undefined; },
      async execute() { return "published"; },
    },
  });
  assert.equal((await runtime.execute(authorized(command), { idempotencyKey: "publish" })).kind, "executed");
  await Promise.resolve();
  assert.deepEqual(events.map(({ stage, outcome }) => [stage, outcome]), [
    ["reservation", "succeeded"],
    ["execution", "started"],
    ["execution", "succeeded"],
    ["receipt", "succeeded"],
  ]);
  assert.equal(events.every((event) => event.correlationId === "runtime-test"), true);
  assert.equal(events.every((event) => Object.keys(event.attributes).length === 0), true);
});

test("closed runtime records known failures separately from unknown outcomes", async () => {
  const state = new InMemoryExecutionStatePort();
  const runtime = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state,
    receipts: new InMemoryReceiptPort(),
    executor: {
      parse(command) { return command; },
      async execute() { throw new RuntimeExecutionError("not-applied"); },
    },
  });
  const result = await runtime.execute(authorized(Object.freeze({})), { idempotencyKey: "known-failure" });
  assert.equal(result.kind, "failed");
  assert.equal((await state.load("known-failure")).state, "failed");
});

test("closed runtime maps state failures and reconciles ambiguous completed effects", async () => {
  const command = Object.freeze({ command: "publish" });
  let gatewayCalls = 0;
  const unavailable = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state: {
      async reserve() { throw new Error("database offline"); },
      async transition() { return "unavailable"; },
      async load() { return undefined; },
    },
    receipts: new InMemoryReceiptPort(),
    executor: {
      parse(candidate) { return candidate; },
      async execute() { gatewayCalls += 1; },
    },
  });
  assert.deepEqual(await unavailable.execute(authorized(command), { idempotencyKey: "state-down" }), {
    kind: "unavailable",
    stage: "state",
    replay: "claimed",
  });
  assert.equal(gatewayCalls, 0);

  const inner = new InMemoryExecutionStatePort();
  const ambiguous = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state: {
      reserve: (record) => inner.reserve(record),
      load: (idempotencyKey) => inner.load(idempotencyKey),
      async transition(idempotencyKey, expected, next) {
        if (next === "executed") return "unavailable";
        return inner.transition(idempotencyKey, expected, next);
      },
    },
    receipts: new InMemoryReceiptPort(),
    reconciliation: { async reconcile() { return { kind: "executed", output: "published" }; } },
    executor: {
      parse(candidate) { return candidate; },
      async execute() { gatewayCalls += 1; return "published"; },
    },
  });
  assert.equal((await ambiguous.execute(authorized(command), { idempotencyKey: "ambiguous" })).kind, "outcome-unknown");
  assert.deepEqual(await ambiguous.execute(authorized(command), { idempotencyKey: "ambiguous" }), {
    kind: "reconciled",
    outcome: "executed",
    output: "published",
  });
  assert.equal(gatewayCalls, 1);
});

test("closed runtime records exhausted budget state before returning", async () => {
  const state = new InMemoryExecutionStatePort();
  let gatewayCalls = 0;
  const runtime = new ClosedRuntime({
    challenges: new InMemoryChallengePort(),
    replay: new InMemoryReplayPort(),
    state,
    receipts: new InMemoryReceiptPort(),
    budget: {
      port: new InMemoryBudgetPort({ production: 0n }),
      claim: { account: "production", algebra: "numeric-ceiling-v1", value: 1n },
    },
    executor: {
      parse(candidate) { return candidate; },
      async execute() { gatewayCalls += 1; },
    },
  });
  assert.equal((await runtime.execute(authorized(Object.freeze({})), {
    idempotencyKey: "exhausted",
  })).kind, "exhausted");
  assert.equal((await state.load("exhausted")).state, "exhausted");
  assert.equal(gatewayCalls, 0);
});

test("runtime claims replay and budget before one closed execution", async () => {
  const replay = new InMemoryReplayPort();
  const budget = new InMemoryBudgetPort({ production: 5n });
  const receipts = new InMemoryReceiptPort();
  const command = Object.freeze({ command: "deploy" });
  let gatewayCalls = 0;
  const options = {
    challenge: runtimeChallenge(new Uint8Array(32).fill(2)),
    replay,
    budget: {
      port: budget,
      claim: { account: "production", algebra: "numeric-ceiling-v1", value: 2n },
    },
    receipts,
    executor: {
      parse(candidate) {
        if (candidate !== command) throw new Error("mismatch");
        return candidate;
      },
      async execute() {
        gatewayCalls += 1;
        return "deployed";
      },
    },
  };

  const result = await executeAuthorized(authorized(command), options);
  assert.equal(result.kind, "executed");
  assert.equal(result.output, "deployed");
  assert.deepEqual(result.claims, { replay: "claimed", budget: "claimed" });
  assert.equal(budget.remaining("production"), 3n);
  assert.equal(gatewayCalls, 1);
  assert.equal(receipts.receipts.length, 1);

  assert.deepEqual(await executeAuthorized(authorized(command), options), { kind: "duplicate" });
  assert.equal(budget.remaining("production"), 3n);
  assert.equal(gatewayCalls, 1);
});

test("runtime fails closed when a parser substitutes a different command", async () => {
  const replay = new InMemoryReplayPort();
  let gatewayCalls = 0;
  const result = await executeAuthorized(authorized({}), {
    challenge: runtimeChallenge(new Uint8Array(32).fill(3)),
    replay,
    receipts: new InMemoryReceiptPort(),
    executor: {
      parse() {
        return {};
      },
      async execute() {
        gatewayCalls += 1;
      },
    },
  });
  assert.deepEqual(result, { kind: "invalid-command" });
  assert.equal(replay.size, 0);
  assert.equal(gatewayCalls, 0);
});
