import assert from "node:assert/strict";
import test from "node:test";
import { approvalPolicy, noApproval, thresholdApproval } from "../../dist/approvals.js";

const request = {
  requestId: "request-1",
  objectKind: "action",
  transactionDigest: new Uint8Array(32).fill(1),
  policy: {
    policyId: "approval.none",
    evaluatorVersion: "1",
    configurationDigest: new Uint8Array(32).fill(2),
  },
  expiresAt: 100n,
  display: [],
};

test("approval policies cover optional, risk, and threshold compositions", async () => {
  assert.equal((await approvalPolicy.none()).mode, "none");
  assert.equal((await approvalPolicy.riskBased()).mode, "risk-based");
  assert.equal((await noApproval.approve(request)).decision, "approved");
  const provider = (decision) => ({
    async approve(candidate) { return { ...candidate, policy: candidate.policy, decision }; },
  });
  assert.equal((await thresholdApproval({
    threshold: 2,
    providers: [provider("approved"), provider("approved"), provider("rejected")],
  }).approve(request)).decision, "approved");
  assert.equal((await thresholdApproval({
    threshold: 3,
    providers: [provider("approved"), provider("approved"), provider("rejected")],
  }).approve(request)).decision, "rejected");
  const duplicate = provider("approved");
  assert.throws(() => thresholdApproval({ threshold: 2, providers: [duplicate, duplicate] }), /invalid/);
  const isolated = thresholdApproval({
    threshold: 1,
    providers: [
      { async approve(candidate) {
        const transactionDigest = candidate.transactionDigest.slice();
        candidate.transactionDigest.fill(9);
        return { ...candidate, transactionDigest, decision: "rejected" };
      } },
      { async approve(candidate) {
        assert.deepEqual(candidate.transactionDigest, request.transactionDigest);
        return { ...candidate, decision: "approved" };
      } },
    ],
  });
  assert.equal((await isolated.approve(request)).decision, "approved");
});
