import assert from "node:assert/strict";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  arrayField, authorMcpProof, booleanField, enumField, exactMcpTool, integerField, optionalField, stringField,
  runOnce, verifyCommand,
} from "../../dist/self-hosted.js";
import { runSelfHostedAdapterConformance } from "../../dist/testkit/index.js";

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
  const expectedMismatch = await runOnce({
    contract, proof: artifacts.proofCbor, action,
    trustedContext: artifacts.trustedContextCbor, expectedCommand: { value: "different" },
    operationKey: "expect-review", attempts: {
      async claimOnce() { throw new Error("mismatch reached claim"); },
      async read() { return undefined; },
      async finish() { throw new Error("mismatch reached finish"); },
    },
    adapter: {
      credential() { throw new Error("mismatch reached credential"); },
      async invoke() { throw new Error("mismatch reached provider"); },
      async observe() { throw new Error("mismatch reached observation"); },
    },
  });
  assert.equal(expectedMismatch.kind, "denied");
  assert.equal(expectedMismatch.code, "self-hosted.expected-command-mismatch");
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
      assert.equal(request.display.find((item) => item.label === "arguments")?.value,
        '{"value":"reviewed"}');
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
  }), /command fields must be a closed object/);
  assert.throws(() => tool.decode({ value: "\ud800" }), /Unicode/);
});

test("checked integer and boolean fields reject coercion and unsafe numbers", async () => {
  const tool = exactMcpTool({
    service: "reports", name: "set_limit",
    fields: {
      count: integerField({ minimum: -5, maximum: 10 }),
      enabled: booleanField(),
      retryCount: optionalField(integerField({ minimum: 0, maximum: 3 })),
    },
  });
  assert.deepEqual(tool.decode({ count: 3, enabled: true, retryCount: null }),
    { count: 3, enabled: true, retryCount: null });
  const prepared = await tool.prepare(
    { count: 3, enabled: true, retryCount: null },
    {
      actor: ACTOR, terminalGrant: vector("mcp.signed-root-grant.cbor"),
      challenge: new Uint8Array(32).fill(0x22), evaluationTime: 50n,
    },
  );
  assert.deepEqual(JSON.parse(new TextDecoder().decode(prepared.argumentsJson)),
    { count: 3, enabled: true, retryCount: null });
  for (const command of [
    { count: true, enabled: true, retryCount: null },
    { count: 11, enabled: true, retryCount: null },
    { count: 3.5, enabled: true, retryCount: null },
    { count: -0, enabled: true, retryCount: null },
    { count: Number.MAX_SAFE_INTEGER + 1, enabled: true, retryCount: null },
    { count: 3, enabled: 1, retryCount: null },
    { count: 3, enabled: true, retryCount: "2" },
  ]) {
    assert.throws(() => tool.decode(command));
  }
});

test("public adapter conformance covers denial, replay, uncertainty and observation", async () => {
  const prepared = await proofFixture();
  const report = await runSelfHostedAdapterConformance({
    contract, command: { value: "reviewed" },
    artifacts: {
      proof: prepared.artifacts.proofCbor,
      action: prepared.action,
      trustedContext: prepared.artifacts.trustedContextCbor,
    },
    adapterFactory: (provider) => ({
      credential: () => "synthetic-token",
      invoke: (command, credential) => provider.write(command, credential),
      observe: (command) => provider.read(command),
    }),
  });
  assert.equal(report.passed, true, JSON.stringify(report.cases));
  assert.equal(report.cases.length, 10);
});

test("closed enum variants stay exact through typed preparation and projection", async () => {
  const tool = exactMcpTool({ service: "reports", name: "update_demo_record",
    fields: { status: enumField(["open", "in_progress", "closed"]),
      maybe: optionalField(enumField(["open", "closed"])),
      history: arrayField(enumField(["open", "closed"]), { minItems: 2, maxItems: 3 }) } });
  const command = { status: "in_progress", maybe: null, history: ["open", "open"] };
  assert.deepEqual(tool.decode(command), command);
  const hostile = JSON.parse(readFileSync(new URL("../../../fixtures/self-hosted-profile/enum-hostile-cases.json", import.meta.url), "utf8"));
  const fieldNames = { status: "status", maybe: "maybe", history: "history" };
  for (const item of hostile.cases) {
    const candidate = { ...command, [fieldNames[item.field]]: item.value };
    if (item.valid) assert.deepEqual(tool.decode(candidate), candidate);
    else assert.throws(() => tool.decode(candidate), /enum variant/);
  }
  for (const variants of [[], ["open", "open"], ["open", "Open!"], Array.from({ length: 33 }, (_, i) => String(i))]) {
    assert.throws(() => enumField(variants));
  }
  const options = { actor: ACTOR, terminalGrant: vector("mcp.signed-root-grant.cbor"),
    challenge: new Uint8Array(32).fill(0x22), evaluationTime: 50n };
  const first = await tool.prepare(command, options);
  const second = await tool.prepare({ ...command, status: "closed" }, options);
  assert.notDeepEqual(first.actionCommitment, second.actionCommitment);
  assert.equal(JSON.parse(new TextDecoder().decode(first.argumentsJson)).status, "in_progress");
});

test("enum action and commitment match the shared Python/native corpus", async () => {
  const corpus = JSON.parse(readFileSync(new URL("../../../fixtures/self-hosted-profile/enum-action-vectors.json", import.meta.url), "utf8"));
  const tool = exactMcpTool({ service: corpus.service, name: corpus.tool,
    fields: { status: enumField(["open", "in_progress", "closed"]) } });
  const options = { actor: ACTOR, terminalGrant: vector("mcp.signed-root-grant.cbor"),
    challenge: new Uint8Array(32).fill(0x22), evaluationTime: 50n };
  for (const item of corpus.cases) {
    const prepared = await tool.prepare({ status: item.status }, options);
    assert.equal(new TextDecoder().decode(prepared.argumentsJson), item.arguments_json);
    assert.equal(Buffer.from(prepared.action).toString("hex"), item.action_hex);
    assert.equal(Buffer.from(prepared.actionCommitment).toString("hex"), item.commitment_hex);
  }
});
