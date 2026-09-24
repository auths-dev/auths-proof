import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  AuthoringUnsuccessful, authorMcpQuorumProof, enumField, exactMcpTool, stringField, verifyCommand,
} from "../../dist/self-hosted.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../fixtures/gateway/approval-quorum.json", import.meta.url), "utf8",
));
const members = new Map(fixture.members.map((member) => [member.name, member]));
const cases = new Map(fixture.cases.map((item) => [item.id, item]));
const challenge = Uint8Array.from(Buffer.from(fixture.challenge_hex, "hex"));
const template = b64(fixture.sdk_trusted_context_b64);

const contract = exactMcpTool({
  service: fixture.service,
  name: fixture.tool,
  fields: {
    operation_id: stringField({ minBytes: 1, maxBytes: 128 }),
    operator_namespace: enumField(["airtable-demo"]),
    recipe_digest: stringField({ minBytes: 64, maxBytes: 64 }),
    record_id: stringField({ minBytes: 17, maxBytes: 43 }),
    replacement: enumField(["Approved", "Pending"]),
  },
});

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

function b64(value) {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

async function seededSigner(name, { reject = false } = {}) {
  const wasm = await packagedWasm();
  const seed = new Uint8Array(32).fill(members.get(name).seed_byte);
  const identity = wasm.deriveEd25519RawKeyIdentityV1(wasm.developmentEd25519PublicKeyV1(seed));
  const principal = identity.principal;
  assert.equal(principal, members.get(name).principal);
  const key = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(seed)]),
    format: "der", type: "pkcs8",
  });
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "test.seeded-manager", principal,
    signature: { principalMethod: "raw-key-v1", verificationMethod: principal, suite: "ed25519-v1" },
    keyVersion: "test-key-1", keyState: "active-current", lifecycle: "ephemeral",
  };
  const requests = [];
  return {
    requests,
    descriptor,
    async sign(request) {
      requests.push(request);
      if (reject) return { kind: "rejected", failure: "denied" };
      return {
        kind: "signed",
        response: {
          requestId: request.requestId, objectId: request.objectId, principal,
          descriptor: descriptor.signature, providerKeyVersion: descriptor.keyVersion,
          transactionDigest: request.transactionDigest,
          signature: new Uint8Array(signBytes(null, request.signingPreimage, key)),
          evidence: [{ type: "raw-key-v1", mediaType: identity.mediaType, bytes: identity.evidence }],
        },
      };
    },
    async close() {},
  };
}

async function author(caseId, names, required, signers, validitySeconds) {
  return authorMcpQuorumProof({
    contract,
    command: contract.decode(JSON.parse(cases.get(caseId).arguments_json)),
    required,
    approvers: (signers ?? await Promise.all(names.map((name) => seededSigner(name))))
      .map((signer) => ({ signer })),
    trustedContextTemplate: template,
    challenge,
    evaluationTime: BigInt(fixture.authored_at),
    ...(validitySeconds === undefined ? {} : { validitySeconds }),
  });
}

for (const item of fixture.cases.filter((candidate) => candidate.decision === "authorized")) {
  test(`TypeScript authors the exact gateway quorum bytes: ${item.id}`, async () => {
    const authored = await author(item.id, item.approvers, item.required);
    assert.deepEqual(authored.proof, b64(item.proof_b64));
    assert.deepEqual(authored.action, b64(item.action_b64));
    assert.deepEqual(authored.command, JSON.parse(item.arguments_json));
    assert.equal(authored.plan.required, item.required);
    assert.deepEqual(authored.plan.approvers, item.approvers.map((name) => members.get(name).principal));
    assert.equal(new Set(authored.plan.proofReferences.map((value) => Buffer.from(value).toString("hex"))).size,
      item.approvers.length);
    assert.deepEqual([authored.plan.validFrom, authored.plan.validUntil],
      [BigInt(fixture.authored_at), BigInt(fixture.authored_at + fixture.validity_seconds)]);
  });
}

test("validitySeconds matches single-signer authoring", async () => {
  const item = cases.get("two-of-three-managers");
  const explicit = await author(item.id, item.approvers, 2, undefined, fixture.validity_seconds);
  assert.deepEqual(explicit.proof, b64(item.proof_b64));
  const longer = await author(item.id, item.approvers, 2, undefined, 300);
  assert.equal(longer.plan.validUntil, BigInt(fixture.authored_at + 300));
  assert.notDeepEqual(longer.proof, explicit.proof);
  for (const invalid of [0, 301]) {
    await assert.rejects(author(item.id, item.approvers, 2, undefined, invalid));
  }
});

test("every approver reviews the same action and quorum", async () => {
  const signers = await Promise.all(["manager-a", "manager-b", "manager-c"].map((name) => seededSigner(name)));
  await author("three-of-three-managers", undefined, 2, signers);
  const displays = new Set(signers.map((signer) => JSON.stringify(signer.requests[0].display)));
  assert.equal(displays.size, 1);
  const fields = Object.fromEntries(signers[0].requests[0].display.map((field) => [field.label, field.value]));
  assert.equal(fields["approval quorum"], "2 of 3");
  assert.equal(new Set(signers.map((signer) => Buffer.from(signer.requests[0].objectId).toString("hex"))).size, 3);
  assert.ok(signers.every((signer) => signer.requests[0].expiresAtUnixSeconds === BigInt(fixture.authored_at) + 300n));
});

test("the TypeScript verifier decides every gateway vector identically", async () => {
  const wasm = await packagedWasm();
  const context = wasm.bindTrustedContextRequestV1(
    template, `mcp://${fixture.service}`, challenge, BigInt(fixture.evaluation_time),
  );
  for (const item of fixture.cases) {
    const decision = await verifyCommand({
      contract, proof: b64(item.proof_b64), action: b64(item.action_b64), trustedContext: context,
    });
    assert.equal(decision.kind, item.decision, item.id);
    if (item.decision !== "authorized") assert.equal(decision.code, item.code, item.id);
  }
});

test("one approval or an outsider never authors a quorum", async () => {
  await assert.rejects(author("one-of-three-managers", ["manager-a"], 1), (error) =>
    error instanceof AuthoringUnsuccessful && error.kind === "rejected" &&
    error.code === cases.get("one-of-three-managers").code);
  await assert.rejects(author("outsider-does-not-count", ["manager-a", "outsider"], 2), (error) =>
    error instanceof AuthoringUnsuccessful && error.kind === "rejected" &&
    error.code === cases.get("outsider-does-not-count").code);
});

test("a duplicate approver or impossible threshold is refused before signing", async () => {
  for (const [names, required] of [[["manager-a", "manager-a"], 2], [["manager-a", "manager-b"], 3],
    [["manager-a", "manager-b"], 0]]) {
    const signers = await Promise.all(names.map((name) => seededSigner(name)));
    await assert.rejects(author("two-of-three-managers", undefined, required, signers));
    assert.ok(signers.every((signer) => signer.requests.length === 0));
  }
});

test("a declining approver stops the quorum", async () => {
  const signers = [await seededSigner("manager-a"), await seededSigner("manager-b", { reject: true })];
  await assert.rejects(author("two-of-three-managers", undefined, 2, signers), (error) =>
    error instanceof AuthoringUnsuccessful && error.kind === "rejected");
});

test("the runnable example authors the gateway quorum through the package exports", () => {
  const directory = mkdtempSync(join(tmpdir(), "auths-approval-quorum-"));
  try {
    mkdirSync(join(directory, "node_modules/@auths-dev"), { recursive: true });
    symlinkSync(fileURLToPath(new URL("../..", import.meta.url)),
      join(directory, "node_modules/@auths-dev/sdk"), "dir");
    copyFileSync(fileURLToPath(new URL(
      "../../../../examples/approval-quorum/typescript/two-of-three.mjs", import.meta.url,
    )), join(directory, "two-of-three.mjs"));
    const output = execFileSync(process.execPath, [
      join(directory, "two-of-three.mjs"),
      fileURLToPath(new URL("../../../fixtures/gateway/approval-quorum.json", import.meta.url)),
    ], { encoding: "utf8" });
    const report = JSON.parse(output.trim().split("\n").at(-1));
    assert.equal(report.outcome, "authorized");
    assert.deepEqual([report.approvals, report.members], [2, 3]);
    assert.equal(report.matches_gateway_vector, true);
    assert.equal(report.single_approval, cases.get("one-of-three-managers").code);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
