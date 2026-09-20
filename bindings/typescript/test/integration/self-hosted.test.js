import assert from "node:assert/strict";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { authorMcpProof, exactMcpTool, stringField, verifyCommand } from "../../dist/self-hosted.js";

const ACTOR = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
const RAW_EVIDENCE = {
  evidenceType: "raw-key-v1",
  mediaType: "application/vnd.auths.raw-key.v1",
};
const vector = (name) => new Uint8Array(readFileSync(
  new URL(`../../../../target/binding-vectors/${name}`, import.meta.url),
));
let wasmPromise;
function packagedWasm() {
  wasmPromise ??= (async () => {
    const wasm = await import("../../wasm/auths_proof_wasm.js");
    await wasm.default({ module_or_path: readFileSync(
      new URL("../../wasm/auths_proof_wasm_bg.wasm", import.meta.url),
    ) });
    return wasm;
  })();
  return wasmPromise;
}

const contract = exactMcpTool({
  service: "reports",
  name: "update_demo_record",
  fields: { value: stringField({ minBytes: 1, maxBytes: 32 }) },
});

async function proofFixture() {
  const wasm = await packagedWasm();
  const grant = vector("mcp.signed-root-grant.cbor");
  const challenge = new Uint8Array(32).fill(0x22);
  const prepared = await contract.prepare(
    { value: "reviewed" },
    { actor: ACTOR, terminalGrant: grant, challenge, evaluationTime: 50n },
  );
  const signedAction = wasm.completeActionSigningV1(
    prepared.actionEnvelope, "raw-key-v1", ACTOR, "ed25519-v1",
    vector("mcp.action-signature.bin"),
  );
  const builder = new wasm.WorkflowProofBuilderV1();
  const index = builder.pushGrant(grant);
  builder.bindGrantEvidence(index, RAW_EVIDENCE.evidenceType, RAW_EVIDENCE.mediaType,
    vector("mcp.root-evidence.bin"));
  builder.bindActionEvidence(RAW_EVIDENCE.evidenceType, RAW_EVIDENCE.mediaType,
    vector("mcp.actor-evidence.bin"));
  const artifacts = builder.finish(signedAction, prepared.action, vector("mcp.context.cbor"));
  return { ...prepared, artifacts };
}

test("TypeScript projects an exact typed command only from native-authorized bytes", async () => {
  const { action, artifacts } = await proofFixture();
  const result = await verifyCommand({
    contract, proof: artifacts.proofCbor, action,
    trustedContext: artifacts.trustedContextCbor,
  });
  assert.equal(result.kind, "authorized");
  assert.deepEqual(result.command, { value: "reviewed" });
  const wrongTool = exactMcpTool({
    service: "reports", name: "delete_demo_record",
    fields: { value: stringField({ minBytes: 1, maxBytes: 32 }) },
  });
  const mismatch = await verifyCommand({
    contract: wrongTool, proof: artifacts.proofCbor, action,
    trustedContext: artifacts.trustedContextCbor,
  });
  assert.equal(mismatch.kind, "denied");
  assert.equal(mismatch.code, "self-hosted.contract-mismatch");
  const mutated = action.slice();
  mutated[mutated.length - 1] ^= 1;
  const altered = await verifyCommand({
    contract, proof: artifacts.proofCbor, action: mutated,
    trustedContext: artifacts.trustedContextCbor,
  });
  assert.notEqual(altered.kind, "authorized");
});

test("external custody signer authors a portable exact proof without minted trust", async () => {
  const seed = vector("mcp.actor-seed.bin");
  const key = createPrivateKey({
    key: Buffer.concat([
      Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed),
    ]),
    format: "der", type: "pkcs8",
  });
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "test.external",
    principal: ACTOR,
    signature: {
      principalMethod: "raw-key-v1", verificationMethod: ACTOR, suite: "ed25519-v1",
    },
    keyVersion: "test-key-1", keyState: "active-current", lifecycle: "durable",
  };
  let signings = 0;
  const signer = {
    descriptor,
    async sign(request) {
      signings += 1;
      return {
        kind: "signed",
        response: {
          requestId: request.requestId, objectId: request.objectId,
          principal: ACTOR, descriptor: descriptor.signature,
          providerKeyVersion: descriptor.keyVersion,
          transactionDigest: request.transactionDigest,
          signature: new Uint8Array(signBytes(null, request.signingPreimage, key)),
          evidence: [{
            type: RAW_EVIDENCE.evidenceType, mediaType: RAW_EVIDENCE.mediaType,
            bytes: vector("mcp.actor-evidence.bin"),
          }],
        },
      };
    },
  };
  const authored = await authorMcpProof({
    contract, command: { value: "reviewed" }, signer,
    grants: [{
      signedGrant: vector("mcp.signed-root-grant.cbor"),
      evidence: [{
        type: RAW_EVIDENCE.evidenceType, mediaType: RAW_EVIDENCE.mediaType,
        bytes: vector("mcp.root-evidence.bin"),
      }],
    }],
    trustedContextTemplate: vector("mcp.context.cbor"),
    challenge: new Uint8Array(32).fill(0x22), evaluationTime: 50n,
  });
  assert.equal(signings, 1);
  const result = await verifyCommand({
    contract, proof: authored.proof, action: authored.action,
    trustedContext: authored.trustedContext,
  });
  assert.equal(result.kind, "authorized");
  assert.deepEqual(result.command, { value: "reviewed" });
});

test("an exact contract cannot be widened by mutating its source schema", () => {
  const mutable = { kind: "string", minBytes: 1, maxBytes: 3 };
  const tool = exactMcpTool({ service: "reports", name: "update", fields: { value: mutable } });
  mutable.maxBytes = 4096;
  assert.throws(() => tool.decode({ value: "unbounded" }), /byte bounds/);
  assert.throws(() => exactMcpTool({
    service: "reports", name: "update",
    fields: { __proto__: stringField({ maxBytes: 3 }) },
  }), /closed command schema/);
});
