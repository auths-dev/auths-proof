import assert from "node:assert/strict";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  ApprovalRefused, approvalRequests, approve, collectApprovals, decline, exactMcpTool,
  integerField, openApprovalRequest, proposeMcpApproval, stringField,
} from "../../dist/self-hosted.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../fixtures/approval/remote-approval.json", import.meta.url), "utf8",
));
const members = new Map(fixture.members.map((member) => [member.name, member]));
const responses = new Map(fixture.responses.map((response) => [response.name, response]));
const nameOf = new Map(fixture.members.map((member) => [member.principal, member.name]));

const contract = exactMcpTool({
  service: fixture.service,
  name: fixture.tool,
  fields: {
    amount: integerField({ minimum: 1, maximum: 10_000_000 }),
    payment_intent: stringField({ minBytes: 1, maxBytes: 64 }),
  },
});

function b64(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

function seededSigner(name) {
  const member = members.get(name);
  const seed = Buffer.alloc(32, member.seed_byte);
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der", type: "pkcs8",
  });
  const principal = member.principal;
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "test.seeded-approver", principal,
    signature: { principalMethod: "raw-key-v1", verificationMethod: principal, suite: "ed25519-v1" },
    keyVersion: "test-key-1", keyState: "active-current", lifecycle: "ephemeral",
  };
  const requests = [];
  return {
    requests,
    descriptor,
    async sign(request) {
      requests.push(request);
      return {
        kind: "signed",
        response: {
          requestId: request.requestId, objectId: request.objectId, principal,
          descriptor: descriptor.signature, providerKeyVersion: descriptor.keyVersion,
          transactionDigest: request.transactionDigest,
          signature: new Uint8Array(signBytes(null, request.signingPreimage, key)),
          evidence: [{
            type: member.evidence_type, mediaType: member.evidence_media_type,
            bytes: b64(member.evidence_b64),
          }],
        },
      };
    },
    async close() {},
    async [Symbol.asyncDispose]() {},
  };
}

async function proposal() {
  return proposeMcpApproval({
    contract,
    command: fixture.arguments,
    required: fixture.required,
    approvers: fixture.approvers.map((name) => ({ principal: members.get(name).principal })),
    requester: members.get(fixture.requester).principal,
    challenge: Uint8Array.from(Buffer.from(fixture.challenge_hex, "hex")),
    evaluationTime: BigInt(fixture.evaluation_time),
  });
}

const agentGrants = [{
  signedGrant: b64(fixture.agent_grant.signed_grant_b64),
  evidence: fixture.agent_grant.evidence.map((item) => ({
    type: item.evidence_type, mediaType: item.evidence_media_type, bytes: b64(item.evidence_b64),
  })),
}];

async function reviewed(approver) {
  const request = fixture.requests.find((item) => item.approver === approver);
  return openApprovalRequest(request.request_text, { now: BigInt(fixture.opened_at) });
}

test("TypeScript issues the native requests", async () => {
  const issued = await approvalRequests(await proposal());
  assert.equal(issued.length, fixture.requests.length);
  issued.forEach((request, index) => {
    const expected = fixture.requests[index];
    assert.equal(request.approver, members.get(expected.approver).principal);
    assert.deepEqual(request.data, b64(expected.request_b64));
    assert.equal(request.text, expected.request_text);
    assert.equal(Buffer.from(request.requestId).toString("hex"), expected.request_id_hex);
  });
});

test("TypeScript opens every request vector with the native code", async () => {
  for (const vector of fixture.open) {
    if (vector.profiles !== "mcp") continue;
    const data = vector.input_text ?? b64(vector.input_b64);
    if (vector.expect === null) {
      const review = await openApprovalRequest(data, { now: BigInt(vector.now) });
      assert.equal(review.title, vector.review.title, vector.name);
      assert.deepEqual(review.fields.map((pair) => [...pair]), vector.review.fields, vector.name);
      assert.equal(review.displayDigestHex, vector.review.display_digest_hex);
      assert.equal(review.requester, vector.review.requester);
      assert.deepEqual([...review.approvers], vector.review.approvers);
      assert.equal(review.required, vector.review.required);
      assert.equal(review.approver, vector.review.approver);
      assert.deepEqual([review.validFrom, review.validUntil], vector.review.window.map(BigInt));
      assert.equal(Buffer.from(review.requestId).toString("hex"), vector.review.request_id_hex);
    } else {
      await assert.rejects(
        openApprovalRequest(data, { now: BigInt(vector.now) }),
        (error) => error instanceof ApprovalRefused && error.code === vector.expect,
        vector.name,
      );
    }
  }
});

test("TypeScript approves and declines to the native bytes", async () => {
  for (const [name, approver, grants] of [
    ["approve-agent-with-grant", "agent", agentGrants],
    ["approve-manager-a", "manager-a", []],
    ["approve-manager-b", "manager-b", []],
  ]) {
    const review = await reviewed(approver);
    const signer = seededSigner(approver);
    const response = await approve(review, signer, { grants });
    assert.equal(response.decision, "approve");
    assert.deepEqual(response.data, b64(responses.get(name).response_b64), name);
    const [request] = signer.requests;
    assert.equal(request.objectKind, "action");
    assert.deepEqual(request.display.map(({ label, value }) => [label, value]),
      review.fields.map((pair) => [...pair]));
    assert.equal(request.expiresAtUnixSeconds, review.validUntil);
  }
  const review = await reviewed("manager-b");
  const signer = seededSigner("manager-b");
  const response = await decline(review, signer, { now: BigInt(fixture.decided_at) });
  assert.equal(response.decision, "decline");
  assert.deepEqual(response.data, b64(responses.get("decline-manager-b").response_b64));
  const [request] = signer.requests;
  assert.equal(request.objectKind, "approval-decline");
  assert.match(request.requestId, /^approval-decline:/u);
  assert.equal(request.expiresAtUnixSeconds, review.validUntil);
});

test("only the addressed approver can answer", async () => {
  const review = await reviewed("manager-a");
  await assert.rejects(approve(review, seededSigner("outsider")),
    (error) => error instanceof ApprovalRefused && error.code === "approval.not-addressed");
  await assert.rejects(decline(review, seededSigner("manager-b"), { now: BigInt(fixture.decided_at) }),
    (error) => error instanceof ApprovalRefused && error.code === "approval.not-addressed");
});

test("TypeScript collects every vector with the native statuses and proof", async () => {
  const built = await proposal();
  for (const vector of fixture.collect) {
    const collection = await collectApprovals(built, vector.responses_b64.map(b64));
    assert.deepEqual(collection.statuses.map((status) => ({
      approver: nameOf.get(status.approver),
      status: status.status,
      ...(status.code === undefined ? {} : { code: status.code }),
      ...(status.decidedAt === undefined ? {} : { decided_at: Number(status.decidedAt) }),
    })), vector.statuses, vector.name);
    assert.deepEqual(collection.unattributed.map((pair) => [...pair]), vector.unattributed);
    if (vector.proof_b64 !== undefined) {
      assert.deepEqual(collection.assemble(), b64(vector.proof_b64), vector.name);
    } else {
      assert.throws(() => collection.assemble(),
        (error) => error instanceof ApprovalRefused && error.code === vector.assemble_code);
    }
  }
});
