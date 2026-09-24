import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { installPackedSdk } from "../package/helpers/packed-install.mjs";

const harness = process.env.AUTHS_GATEWAY_HARNESS;
const vectors = fileURLToPath(new URL("../../../../target/binding-vectors/", import.meta.url));

// Expected before replacement through the packed package against the gateway's
// counting-provider harness: request a read-back, attach it, submit and write;
// then change the record and show the stale expectation refused by the SDK and,
// for an agent that skips that check, by the gateway before any credential lease.
const consumer = String.raw`
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { createConnection } from "node:net";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuthoringUnsuccessful, attachObservations, authorMcpProof, enumField, exactMcpTool, stringField,
} from "@auths-dev/sdk/self-hosted";
import { GatewayClient, GatewayEndpoint } from "@auths-dev/sdk/gateway";

const [harnessPath, vectorDirectory] = process.argv.slice(2);
const vector = (name) => readFile(join(vectorDirectory, name));
const NOW = 1790000000n;
const ACTOR = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
const RAW = { type: "raw-key-v1", mediaType: "application/vnd.auths.raw-key.v1" };
const signature = { principalMethod: "raw-key-v1", verificationMethod: ACTOR, suite: "ed25519-v1" };
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"),
    await vector("mcp.actor-seed.bin")]),
  format: "der", type: "pkcs8",
});
const actorEvidence = { ...RAW, bytes: await vector("mcp.actor-evidence.bin") };
const signer = {
  descriptor: { contract: "signer-custody/2", kind: "workload", adapterId: "test.gateway-journey",
    principal: ACTOR, signature, keyVersion: "journey-key-1", keyState: "active-current",
    lifecycle: "ephemeral" },
  async sign(request) {
    return { kind: "signed", response: {
      requestId: request.requestId, objectId: request.objectId, principal: ACTOR,
      descriptor: signature, providerKeyVersion: "journey-key-1",
      transactionDigest: request.transactionDigest,
      signature: new Uint8Array(signBytes(null, request.signingPreimage, privateKey)),
      evidence: [actorEvidence],
    } };
  },
};
const status = enumField(["Approved", "Pending"]);
const contract = exactMcpTool({ service: "gateway-observer-test", name: "set_status_v1", fields: {
  operation_id: stringField({ minBytes: 1, maxBytes: 128 }),
  operator_namespace: enumField(["observer-demo"]),
  recipe_digest: stringField({ minBytes: 64, maxBytes: 64 }),
  record_id: stringField({ minBytes: 17, maxBytes: 43 }),
  replacement: status, expected: status,
  record_uri: stringField({ minBytes: 1, maxBytes: 256 }),
} });
const bytes = (text) => new Uint8Array(Buffer.from(text, "base64url"));
const frame = (socket, request) => new Promise((resolve, reject) => {
  const payload = Buffer.from(JSON.stringify(request));
  const length = Buffer.alloc(4); length.writeUInt32BE(payload.length);
  const connection = createConnection(socket);
  const chunks = [];
  connection.on("error", reject);
  connection.on("data", (chunk) => chunks.push(chunk));
  connection.on("end", () => {
    const all = Buffer.concat(chunks);
    resolve(JSON.parse(all.subarray(4, 4 + all.readUInt32BE(0)).toString()));
  });
  connection.write(Buffer.concat([length, payload]));
});

const state = await mkdtemp(join(tmpdir(), "agh"));
const child = spawn(harnessPath, ["--state-dir", state, "--agent", ACTOR, "--now", String(NOW)],
  { stdio: ["ignore", "pipe", "inherit"] });
try {
  const setup = JSON.parse(await new Promise((resolve) =>
    createInterface({ input: child.stdout }).once("line", resolve)));
  if (setup.schema !== "auths.gateway-harness/1") throw new Error("unexpected harness");
  const control = async (request) => {
    const response = await frame(setup.control_socket, request);
    if (response.ok !== true) throw new Error("harness refused " + JSON.stringify(request));
    return response;
  };
  const counts = async () => { const value = await control({ command: "counts" });
    return [value.writes, value.leases]; };
  const client = new GatewayClient(new GatewayEndpoint(setup.app_socket));
  const record = setup.records[0];
  const rootEvidence = { type: setup.root_evidence.evidence_type,
    mediaType: setup.root_evidence.media_type, bytes: bytes(setup.root_evidence.bytes_b64) };
  const grants = [{ signedGrant: bytes(setup.signed_grant_b64), evidence: [rootEvidence] }];
  const template = bytes(setup.trusted_context_b64);
  const challenge = bytes(setup.challenge_b64);
  const command = (operation, expected, replacement) => ({
    operation_id: operation, operator_namespace: "observer-demo",
    recipe_digest: setup.recipe_digest, record_id: record.record_id, replacement, expected,
    record_uri: record.read_back_subject,
  });
  const readBack = async () => {
    const observed = await client.observeReadBack({ record_id: record.record_id });
    if (observed.outcome !== "signed" || observed.subject !== record.read_back_subject) {
      throw new Error("read-back refused: " + JSON.stringify(observed));
    }
    return observed;
  };
  const author = (value, observation, now) => authorMcpProof({
    contract, command: value, grants, trustedContextTemplate: template, signer, challenge,
    evaluationTime: now, observations: [observation],
  });
  const engine = await import(new URL("./node_modules/@auths-dev/sdk/wasm/auths_proof_wasm.js",
    import.meta.url).href);
  await engine.default({ module_or_path: await readFile(new URL(
    "./node_modules/@auths-dev/sdk/wasm/auths_proof_wasm_bg.wasm", import.meta.url)) });
  // What an agent that skips its SDK's final verification would send.
  const authorUnchecked = async (value, observation, now) => {
    const prepared = await attachObservations(await contract.prepare(value, {
      actor: ACTOR, terminalGrant: grants[0].signedGrant, challenge, evaluationTime: now,
    }), [observation]);
    const context = engine.bindTrustedContextRequestV1(template, prepared.audience, challenge, now);
    const request = engine.prepareActionSigningV1(prepared.actionEnvelope,
      signature.principalMethod, signature.verificationMethod, signature.suite);
    const signed = engine.completeActionSigningV1(prepared.actionEnvelope,
      signature.principalMethod, signature.verificationMethod, signature.suite,
      new Uint8Array(signBytes(null, request.signingPreimage, privateKey)));
    const builder = new engine.WorkflowProofBuilderV1();
    const index = builder.pushGrant(grants[0].signedGrant);
    builder.bindGrantEvidence(index, rootEvidence.type, rootEvidence.mediaType, rootEvidence.bytes);
    builder.bindActionEvidence(actorEvidence.type, actorEvidence.mediaType, actorEvidence.bytes);
    return { proof: builder.finish(signed, prepared.action, context).proofCbor, action: prepared.action };
  };
  const refusedBeforeLease = async (value, observation, now, expected) => {
    try {
      await author(value, observation, now);
      throw new Error("the SDK authored a refused replacement");
    } catch (error) {
      if (!(error instanceof AuthoringUnsuccessful) || error.code !== expected.code) throw error;
    }
    const before = await counts();
    const result = await client.submit(await authorUnchecked(value, observation, now));
    if (JSON.stringify(result) !== JSON.stringify(expected)) {
      throw new Error("gateway result " + JSON.stringify(result));
    }
    if (JSON.stringify(await counts()) !== JSON.stringify(before)) {
      throw new Error("a refused replacement reached a lease or write");
    }
    return result;
  };

  const observed = await readBack();
  const first = await author(command("journey-1", "Pending", "Approved"), observed, NOW);
  const written = await client.submit({ proof: first.proof, action: first.action });
  const afterWrite = await counts();
  await control({ command: "set-record", record_id: record.record_id, status: "Pending" });
  const changed = await readBack();
  const conditionFalse = await refusedBeforeLease(command("journey-2", "Approved", "Pending"),
    changed, NOW, { outcome: "denied", code: "observation-condition-false" });
  const aged = BigInt((await control({ command: "advance-clock", seconds: 61 })).now);
  const stale = await refusedBeforeLease(command("journey-3", "Pending", "Approved"),
    changed, aged, { outcome: "indeterminate", code: "observation-missing" });
  process.stdout.write(JSON.stringify({
    written: { outcome: written.outcome, status: written.status }, afterWrite,
    conditionFalse, stale, final: await counts(),
  }));
} finally {
  child.kill();
}
`;

test("packed npm consumer attaches a gateway read-back and is refused once it is stale", {
  skip: process.platform === "win32" ? "the gateway harness requires Unix sockets" : false,
}, async () => {
  assert.ok(harness, "AUTHS_GATEWAY_HARNESS must name the built auths-gateway-harness binary");
  await readFile(join(vectors, "mcp.actor-seed.bin"));
  const { directory } = await installPackedSdk("auths-typescript-gateway-consumer-");
  try {
    await writeFile(join(directory, "consumer.mjs"), consumer);
    const output = execFileSync(process.execPath, ["consumer.mjs", harness, vectors],
      { cwd: directory, encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] });
    assert.deepEqual(JSON.parse(output), {
      written: { outcome: "observed-by-provider", status: 200 },
      afterWrite: [1, 2],
      conditionFalse: { outcome: "denied", code: "observation-condition-false" },
      stale: { outcome: "indeterminate", code: "observation-missing" },
      final: [1, 3],
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
