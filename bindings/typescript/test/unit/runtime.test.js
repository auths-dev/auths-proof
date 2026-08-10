import assert from "node:assert/strict";
import test from "node:test";

import { executeAuthorized, runtimeChallenge } from "../../dist/runtime.js";
import {
  InMemoryBudgetPort,
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
