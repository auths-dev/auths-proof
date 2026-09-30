import assert from "node:assert/strict";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  ApprovalRefused, approvalRequests, approve, collectApprovals, decline, exactMcpTool,
  integerField, openApprovalRequest, proposeMcpApproval, signApprovalAction, stringField,
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

function evidenceOf(items) {
  return items.map((item) => ({
    type: item.evidence_type, mediaType: item.evidence_media_type, bytes: b64(item.evidence_b64),
  }));
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
    contract: "signer-custody/2", kind: "workload", adapterId: "test.seeded-member", principal,
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
          evidence: evidenceOf([member]),
        },
      };
    },
    async close() {},
    async [Symbol.asyncDispose]() {},
  };
}

const agentGrants = [{
  signedGrant: b64(fixture.agent_grant.signed_grant_b64),
  evidence: evidenceOf(fixture.agent_grant.evidence),
}];

function fixtureAction(which) {
  const action = fixture[which];
  return {
    signedAction: b64(action.signed_action_b64),
    grants: agentGrants,
    evidence: evidenceOf(action.evidence),
  };
}

async function proposal(argumentsValue = fixture.arguments) {
  return proposeMcpApproval({
    contract,
    command: argumentsValue,
    required: fixture.required,
    approvers: fixture.approvers.map((name) => members.get(name).principal),
    actor: members.get(fixture.requester).principal,
    actorGrant: agentGrants[0].signedGrant,
    challenge: Uint8Array.from(Buffer.from(fixture.challenge_hex, "hex")),
    evaluationTime: BigInt(fixture.evaluation_time),
  });
}

async function reviewed(approver) {
  const request = fixture.requests.find((item) => item.approver === approver);
  return openApprovalRequest(request.request_text, { now: BigInt(fixture.opened_at) });
}

test("TypeScript issues the native requests for the native requirement", async () => {
  const built = await proposal();
  assert.equal(built.actor, members.get(fixture.requester).principal);
  assert.equal(built.requirement.required, fixture.required);
  assert.deepEqual(built.requirement.approvers, fixture.approvers.map((name) => members.get(name).principal));
  assert.equal(Buffer.from(built.requirement.requirementId).toString("hex"), fixture.requirement_id_hex);
  assert.deepEqual([built.requirement.validFrom, built.requirement.validUntil],
    [BigInt(fixture.evaluation_time), BigInt(fixture.evaluation_time + fixture.validity_seconds)]);
  const issued = await approvalRequests(built);
  assert.equal(issued.length, fixture.requests.length);
  issued.forEach((request, index) => {
    const expected = fixture.requests[index];
    assert.equal(request.approver, members.get(expected.approver).principal);
    assert.deepEqual(request.data, b64(expected.request_b64));
    assert.equal(request.text, expected.request_text);
    assert.equal(Buffer.from(request.requestId).toString("hex"), expected.request_id_hex);
  });
});

test("the actor may not approve its own action", async () => {
  await assert.rejects(proposeMcpApproval({
    contract, command: fixture.arguments, required: 1,
    approvers: [members.get("manager-a").principal, members.get(fixture.requester).principal],
    actor: members.get(fixture.requester).principal, actorGrant: agentGrants[0].signedGrant,
    challenge: Uint8Array.from(Buffer.from(fixture.challenge_hex, "hex")),
    evaluationTime: BigInt(fixture.evaluation_time),
  }));
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
  for (const approver of fixture.approvers) {
    const name = `approve-${approver}`;
    const review = await reviewed(approver);
    const signer = seededSigner(approver);
    const response = await approve(review, signer);
    assert.equal(response.decision, "approve");
    assert.deepEqual(response.data, b64(responses.get(name).response_b64), name);
    assert.match(response.text, /^auths-as2-/u);
    const [request] = signer.requests;
    assert.equal(request.objectKind, "approval");
    assert.match(request.requestId, /^approval:[0-9a-f]{64}:[0-9a-f]{64}$/u);
    assert.deepEqual(request.display.map(({ label, value }) => [label, value]),
      review.fields.map((pair) => [...pair]));
    assert.equal(request.expiresAtUnixSeconds, review.validUntil);
  }
  for (const approver of ["manager-b", "manager-c"]) {
    const review = await reviewed(approver);
    const signer = seededSigner(approver);
    const response = await decline(review, signer, { now: BigInt(fixture.decided_at) });
    assert.equal(response.decision, "decline");
    assert.deepEqual(response.data, b64(responses.get(`decline-${approver}`).response_b64));
    const [request] = signer.requests;
    assert.equal(request.objectKind, "approval-decline");
    assert.match(request.requestId, /^approval-decline:/u);
    assert.equal(request.expiresAtUnixSeconds, review.validUntil);
  }
});

test("only the addressed approver can answer", async () => {
  const review = await reviewed("manager-a");
  await assert.rejects(approve(review, seededSigner("outsider")),
    (error) => error instanceof ApprovalRefused && error.code === "approval.not-addressed");
  await assert.rejects(approve(review, seededSigner(fixture.requester)),
    (error) => error instanceof ApprovalRefused && error.code === "approval.not-addressed");
  await assert.rejects(decline(review, seededSigner("manager-b"), { now: BigInt(fixture.decided_at) }),
    (error) => error instanceof ApprovalRefused && error.code === "approval.not-addressed");
});

test("the actor signs the native action with its grant chain", async () => {
  const built = await proposal();
  const signer = seededSigner(fixture.requester);
  const action = await signApprovalAction(built, signer, { grants: agentGrants });
  const expected = fixtureAction("agent_action");
  assert.deepEqual(action.signedAction, expected.signedAction);
  assert.deepEqual(action.evidence, expected.evidence);
  assert.deepEqual(action.grants, agentGrants);
  const [request] = signer.requests;
  assert.equal(request.objectKind, "action");
  assert.equal(request.expiresAtUnixSeconds, built.requirement.validUntil);
  const fields = Object.fromEntries(request.display.map(({ label, value }) => [label, value]));
  assert.equal(fields["approvals required"], "any 2 of 3");
  await assert.rejects(signApprovalAction(built, seededSigner("manager-a"), { grants: agentGrants }), TypeError);
  await assert.rejects(signApprovalAction(built, seededSigner(fixture.requester)), TypeError);
});

test("TypeScript collects every vector with the native statuses and proof, counting approvals", async () => {
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
    assert.equal(collection.approved, vector.approved, vector.name);
    assert.equal(collection.required, fixture.required);
    assert.equal(collection.isComplete, vector.approved >= fixture.required, vector.name);
    const action = fixtureAction(vector.action === "attacker" ? "attacker_action" : "agent_action");
    if (vector.proof_b64 !== undefined) {
      assert.deepEqual(collection.assemble(action), b64(vector.proof_b64), vector.name);
    } else {
      assert.throws(() => collection.assemble(action),
        (error) => error instanceof ApprovalRefused && error.code === vector.assemble_code, vector.name);
    }
  }
});

