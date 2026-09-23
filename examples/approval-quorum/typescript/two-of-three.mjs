// Two of three managers approve one exact action before the agent submits it.
//
//   node examples/approval-quorum/typescript/two-of-three.mjs [fixture.json]
//
// The managers' keys are the public test vectors of
// bindings/fixtures/gateway/approval-quorum.json; production approvers sign
// through their own custody adapters. The operator's trust template anchors
// the three managers and requires two authorized approvals from two distinct
// actors.

import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  AuthoringUnsuccessful, authorMcpQuorumProof, enumField, exactMcpTool, stringField,
} from "@auths-dev/sdk/self-hosted";

const fixturePath = process.argv[2] ??
  new URL("../../../bindings/fixtures/gateway/approval-quorum.json", import.meta.url);
const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
const bytes = (value) => new Uint8Array(Buffer.from(value, "base64url"));

const tool = exactMcpTool({
  service: "airtable-gateway-demo",
  name: "set_demo_status_v1",
  fields: {
    operation_id: stringField({ minBytes: 1, maxBytes: 128 }),
    operator_namespace: enumField(["airtable-demo"]),
    recipe_digest: stringField({ minBytes: 64, maxBytes: 64 }),
    record_id: stringField({ minBytes: 17, maxBytes: 43 }),
    replacement: enumField(["Approved", "Pending"]),
  },
});

// A manager's signer. The seed is a public test vector, never a secret.
function manager(member) {
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, member.seed_byte),
    ]),
    format: "der", type: "pkcs8",
  });
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "example.manager",
    principal: member.principal,
    signature: { principalMethod: "raw-key-v1", verificationMethod: member.principal, suite: "ed25519-v1" },
    keyVersion: "example-key-1", keyState: "active-current", lifecycle: "ephemeral",
  };
  return {
    descriptor,
    async sign(request) {
      return {
        kind: "signed",
        response: {
          requestId: request.requestId, objectId: request.objectId, principal: member.principal,
          descriptor: descriptor.signature, providerKeyVersion: descriptor.keyVersion,
          transactionDigest: request.transactionDigest,
          signature: new Uint8Array(sign(null, request.signingPreimage, key)),
          evidence: [{
            type: "raw-key-v1", mediaType: "application/vnd.auths.raw-key.v1",
            bytes: bytes(member.evidence_b64),
          }],
        },
      };
    },
    async close() {},
  };
}

const managers = new Map(fixture.members.map((member) => [member.name, manager(member)]));
const vector = fixture.cases.find((item) => item.id === "two-of-three-managers");
const author = (names, required) => authorMcpQuorumProof({
  contract: tool,
  command: tool.decode(JSON.parse(vector.arguments_json)),
  required,
  approvers: names.map((name) => ({ signer: managers.get(name) })),
  trustedContextTemplate: bytes(fixture.sdk_trusted_context_b64),
  challenge: new Uint8Array(Buffer.from(fixture.challenge_hex, "hex")),
  evaluationTime: BigInt(fixture.not_before),
  expiresAt: BigInt(fixture.expires_at),
});

const authored = await author(["manager-a", "manager-b"], 2);
let single = "authorized";
try {
  await author(["manager-a"], 1);
} catch (error) {
  if (!(error instanceof AuthoringUnsuccessful)) throw error;
  single = error.code;
}
console.log(JSON.stringify({
  example: "approval-quorum",
  outcome: "authorized",
  approvals: authored.plan.approvers.length,
  members: fixture.members.filter((member) => member.member).length,
  plan_id: Buffer.from(authored.plan.planId).toString("hex"),
  matches_gateway_vector: Buffer.from(authored.proof).equals(Buffer.from(bytes(vector.proof_b64))),
  single_approval: single,
}));
