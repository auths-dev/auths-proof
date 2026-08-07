import assert from "node:assert/strict";
import { test } from "node:test";
import { approvalPolicy } from "../../dist/index.js";
import { BoundedApprovalSession } from "../../dist/approvals.js";
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
  assert.notDeepEqual(plan.commitment, reversed.commitment);
});

test("bounded approval sessions prompt once and cannot outlive their plan", async () => {
  const policy = await approvalPolicy.planOnce({ maxUses: 2 });
  let prompts = 0;
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(4),
    memberCommitments: [new Uint8Array(32).fill(11), new Uint8Array(32).fill(12)],
    policy,
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
    policy: policy.reference,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    display: [],
  });
  assert.equal((await session.providerFor(0, new Uint8Array(32).fill(11)).approve(request(1))).decision, "approved");
  assert.equal((await session.providerFor(1, new Uint8Array(32).fill(12)).approve(request(2))).decision, "approved");
  assert.equal(prompts, 1);
  await assert.rejects(() => session.providerFor(1, new Uint8Array(32).fill(12)).approve(request(3)));
  await session.dispose();
  assert.throws(() => session.providerFor(0, new Uint8Array(32).fill(11)));
});

test("bounded approval sessions reject a substituted provider response", async () => {
  const policy = await approvalPolicy.planOnce({ maxUses: 1 });
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(5),
    memberCommitments: [new Uint8Array(32).fill(21)],
    policy,
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
  await assert.rejects(() => session.providerFor(0, new Uint8Array(32).fill(21)).approve({
    requestId: "action:1",
    objectKind: "action",
    transactionDigest: new Uint8Array(32).fill(1),
    policy: policy.reference,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    display: [],
  }));
});

test("bounded approval sessions reject reordered and substituted plan members", async () => {
  const policy = await approvalPolicy.planOnce({ maxUses: 2 });
  const members = [new Uint8Array(32).fill(31), new Uint8Array(32).fill(32)];
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(6),
    memberCommitments: members,
    policy,
    display: [],
    provider: { async approve(request) { return { ...request, decision: "approved" }; } },
  });
  assert.throws(
    () => session.providerFor(0, members[1]),
    /member commitment mismatch/,
  );
  const request = {
    requestId: "action:second",
    objectKind: "action",
    transactionDigest: new Uint8Array(32).fill(2),
    policy: policy.reference,
    expiresAt: BigInt(Math.floor(Date.now() / 1000)) + 60n,
    display: [],
  };
  await assert.rejects(() => session.providerFor(1, members[1]).approve(request));
});

test("bounded approval sessions reject duplicates, appended members, and expired reuse", async () => {
  const policy = await approvalPolicy.planOnce({ maxUses: 2, expiresInSeconds: 10 });
  const members = [new Uint8Array(32).fill(41), new Uint8Array(32).fill(42)];
  let now = 100n;
  const session = new BoundedApprovalSession({
    planCommitment: new Uint8Array(32).fill(7),
    memberCommitments: members,
    policy,
    display: [],
    now: () => now,
    startedAt: now,
    provider: { async approve(request) { return { ...request, decision: "approved" }; } },
  });
  assert.throws(() => session.providerFor(1, members[0]), /member commitment mismatch/);
  assert.throws(() => session.providerFor(2, new Uint8Array(32).fill(43)), /member is invalid/);
  now = 111n;
  await assert.rejects(
    () => session.providerFor(0, members[0]).approve({
      requestId: "action:expired",
      objectKind: "action",
      transactionDigest: new Uint8Array(32).fill(1),
      policy: policy.reference,
      expiresAt: 200n,
      display: [],
    }),
    (error) => error?.kind === "timeout",
  );
});
