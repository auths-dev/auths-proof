import assert from "node:assert/strict";
import { test } from "node:test";
import { BoundedApprovalSession, approvalPolicy } from "../../dist/index.js";
import { defineProfile } from "../../dist/profile-kit.js";

const profile = defineProfile({
  id: "example.plan/1",
  version: 1,
  canonicalize(input) {
    return {
      mediaType: "application/json",
      body: new TextEncoder().encode(JSON.stringify({ ...input, cost: input.cost.toString() })),
      permission: { capability: input.capability, resource: `repo://demo/${input.path}` },
      resourceNamespace: "repo://demo",
      audience: "repo://demo",
      budget: { algebra: "numeric-ceiling-v1", value: input.cost },
      display: [{ label: "Path", value: input.path }],
    };
  },
});

test("profile plans aggregate exact authority and commit ordered actions", async () => {
  const first = profile.action({ capability: "file/modify", path: "a", cost: 2n });
  const second = profile.action({ capability: "pr/open", path: "b", cost: 3n });
  const plan = await profile.plan([first, second]);
  assert.equal(plan.length, 2);
  assert.equal(plan.authority.permissions.length, 2);
  assert.equal(plan.authority.budget.value, 5n);
  const reversed = await profile.plan([second, first]);
  assert.notDeepEqual(plan.commitment.digest, reversed.commitment.digest);
});

test("bounded approval sessions prompt once and cannot outlive their plan", async () => {
  const policy = await approvalPolicy.planOnce({ maxUses: 2 });
  let prompts = 0;
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(4),
    policy,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    maxUses: 2,
    display: [{ label: "Plan", value: "two actions" }],
    provider: {
      async approve(request) {
        prompts += 1;
        return {
          requestId: request.requestId,
          transactionDigest: request.transactionDigest,
          policy: request.policy,
          decision: "approved",
        };
      },
    },
  });
  const request = (index) => ({
    requestId: `action:${index}`,
    objectKind: "action",
    transactionDigest: new Uint8Array(32).fill(index),
    policy,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    display: [],
  });
  assert.equal((await session.approve(request(1))).decision, "approved");
  assert.equal((await session.approve(request(2))).decision, "approved");
  assert.equal(prompts, 1);
  await assert.rejects(() => session.approve(request(3)));
  await session.dispose();
  await assert.rejects(() => session.approve(request(1)));
});

test("bounded approval sessions reject a substituted provider response", async () => {
  const policy = await approvalPolicy.planOnce();
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(5),
    policy,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    maxUses: 1,
    display: [],
    provider: {
      async approve(request) {
        return {
          requestId: `${request.requestId}:substituted`,
          transactionDigest: request.transactionDigest,
          policy: request.policy,
          decision: "approved",
        };
      },
    },
  });
  await assert.rejects(() => session.approve({
    requestId: "action:1",
    objectKind: "action",
    transactionDigest: new Uint8Array(32).fill(1),
    policy,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    display: [],
  }));
});
