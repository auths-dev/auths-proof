// Any two of three managers approve one exact action before the agent submits it.
//
//   node examples/approval-quorum/typescript/two-of-three.mjs [fixture.json]
//
// The agent and managers' keys are the public test vectors of
// bindings/fixtures/gateway/approval-quorum.json; production signers use their
// own custody adapters. The operator's trust template anchors the agent for
// one MCP tool, names the three managers as approvers, and requires approvals
// from any two of them. The agent signs the action; each approving manager
// signs an approval of that exact action. Which two approve does not matter.

import { createPrivateKey, sign } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  authorMcpQuorumProof, enumField, exactMcpTool, stringField, verifyCommand,
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

// A member's signer. The seed is a public test vector, never a secret.
function signer(member) {
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"),
      Buffer.alloc(32, member.seed_byte),
    ]),
    format: "der", type: "pkcs8",
  });
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "example.member",
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

const signers = new Map(fixture.members.map((member) => [member.name, signer(member)]));
const approvers = fixture.approvers.map((name) => signers.get(name).descriptor.principal);
const template = bytes(fixture.sdk_trusted_context_b64);
const challenge = new Uint8Array(Buffer.from(fixture.challenge_hex, "hex"));
const vector = fixture.cases.find((item) => item.id === "managers-a-and-b");
const author = (names) => authorMcpQuorumProof({
  contract: tool,
  command: tool.decode(JSON.parse(vector.arguments_json)),
  actor: signers.get(fixture.actor),
  required: fixture.required,
  approvers,
  signers: names.map((name) => signers.get(name)),
  trustedContextTemplate: template,
  challenge,
  evaluationTime: BigInt(fixture.authored_at),
});

const authored = await author(["manager-a", "manager-b"]);
// A different pair authorizes the same action: any two of the three suffice.
const otherPair = await author(["manager-b", "manager-c"]);

// One approval is not enough: the verifier denies the gateway's own vector.
const single = fixture.cases.find((item) => item.id === "one-of-three-managers");
const denied = await verifyCommand({
  contract: tool,
  proof: bytes(single.proof_b64),
  action: bytes(single.action_b64),
  trustedContext: authored.trustedContext,
});

console.log(JSON.stringify({
  example: "approval-quorum",
  outcome: "authorized",
  approvals: 2,
  approvers: authored.requirement.approvers.length,
  required: authored.requirement.required,
  requirement_id: Buffer.from(authored.requirement.requirementId).toString("hex"),
  matches_gateway_vector: Buffer.from(authored.proof).equals(Buffer.from(bytes(vector.proof_b64))),
  any_two_authorize: otherPair.proof.length > 0,
  single_approval: denied.kind === "authorized" ? "authorized" : denied.code,
}));
