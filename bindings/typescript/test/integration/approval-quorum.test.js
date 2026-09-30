import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createPrivateKey, sign as signBytes } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import {
  AuthoringUnsuccessful, approvalRequests, approve, authorMcpQuorumProof, collectApprovals,
  enumField, exactMcpTool, openApprovalRequest, proposeMcpApproval, signApprovalAction,
  stringField, verifyCommand,
} from "../../dist/self-hosted.js";

const fixture = JSON.parse(readFileSync(
  new URL("../../../fixtures/gateway/approval-quorum.json", import.meta.url), "utf8",
));
const members = new Map(fixture.members.map((member) => [member.name, member]));
const cases = new Map(fixture.cases.map((item) => [item.id, item]));
const challenge = Uint8Array.from(Buffer.from(fixture.challenge_hex, "hex"));
const template = b64(fixture.sdk_trusted_context_b64);
const approvers = fixture.approvers.map((name) => members.get(name).principal);
const authoredAt = BigInt(fixture.authored_at);

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

function command(caseId) {
  return contract.decode(JSON.parse(cases.get(caseId).arguments_json));
}

async function author(caseId, names, { required = fixture.required, signers, actor, validitySeconds } = {}) {
  return authorMcpQuorumProof({
    contract,
    command: command(caseId),
    actor: actor ?? await seededSigner(fixture.actor),
    required,
    approvers,
    signers: signers ?? await Promise.all(names.map((name) => seededSigner(name))),
    trustedContextTemplate: template,
    challenge,
    evaluationTime: authoredAt,
    ...(validitySeconds === undefined ? {} : { validitySeconds }),
  });
}

for (const item of fixture.cases.filter((candidate) =>
  candidate.authoring === "sdk" && candidate.decision === "authorized")) {
  test(`TypeScript authors the exact gateway quorum bytes in process: ${item.id}`, async () => {
    const authored = await author(item.id, item.approvers, { required: item.required });
    assert.deepEqual(authored.proof, b64(item.proof_b64));
    assert.deepEqual(authored.action, b64(item.action_b64));
    assert.deepEqual(authored.command, JSON.parse(item.arguments_json));
    assert.equal(authored.requirement.required, item.required);
    assert.deepEqual(authored.requirement.approvers, [...approvers].sort());
    assert.equal(authored.requirement.requirementId.length, 32);
    assert.deepEqual([authored.requirement.validFrom, authored.requirement.validUntil],
      [authoredAt, authoredAt + BigInt(fixture.validity_seconds)]);
  });
}

for (const item of fixture.cases.filter((candidate) => candidate.authoring === "sdk")) {
  test(`TypeScript authors the exact gateway quorum bytes remotely: ${item.id}`, async () => {
    const proposal = await proposeMcpApproval({
      contract, command: command(item.id), required: item.required, approvers,
      actor: members.get(fixture.actor).principal, challenge, evaluationTime: authoredAt,
    });
    assert.deepEqual(proposal.action, b64(item.action_b64));
    const issued = await approvalRequests(proposal);
    const responses = [];
    for (const name of item.approvers) {
      const request = issued.find((candidate) => candidate.approver === members.get(name).principal);
      const review = await openApprovalRequest(request.text, { now: authoredAt });
      responses.push((await approve(review, await seededSigner(name))).data);
    }
    const action = await signApprovalAction(proposal, await seededSigner(fixture.actor));
    const collection = await collectApprovals(proposal, responses);
    assert.equal(collection.approved, item.approvers.length);
    assert.equal(collection.required, item.required);
    assert.equal(collection.isComplete, true);
    assert.deepEqual(collection.assemble(action), b64(item.proof_b64));
  });
}

test("the quorum window defaults to a day and is configurable", async () => {
  const item = cases.get("managers-a-and-b");
  assert.equal(fixture.validity_seconds, 86_400);
  const explicit = await author(item.id, item.approvers, { validitySeconds: fixture.validity_seconds });
  assert.deepEqual(explicit.proof, b64(item.proof_b64));
  const shorter = await author(item.id, item.approvers, { validitySeconds: 3_600 });
  assert.equal(shorter.requirement.validUntil, authoredAt + 3_600n);
  assert.notDeepEqual(shorter.proof, explicit.proof);
  // A week passes the native bound; the one-day anchors then refuse it.
  await assert.rejects(author(item.id, item.approvers, { validitySeconds: 604_800 }), (error) =>
    error instanceof AuthoringUnsuccessful && error.code === "action-outside-validity");
  for (const invalid of [0, 604_801]) {
    await assert.rejects(author(item.id, item.approvers, { validitySeconds: invalid }), (error) =>
      !(error instanceof AuthoringUnsuccessful));
  }
});

test("the actor and every approver review the same action and requirement", async () => {
  const actor = await seededSigner(fixture.actor);
  const signers = await Promise.all(fixture.approvers.map((name) => seededSigner(name)));
  await author("three-of-three-managers", undefined, { actor, signers });
  const everyone = [actor, ...signers];
  assert.ok(everyone.every((signer) => signer.requests.length === 1));
  const displays = new Set(everyone.map((signer) => JSON.stringify(signer.requests[0].display)));
  assert.equal(displays.size, 1);
  const fields = Object.fromEntries(actor.requests[0].display.map((field) => [field.label, field.value]));
  assert.equal(fields["approvals required"], "any 2 of 3");
  assert.equal(fields.actor, members.get(fixture.actor).principal);
  assert.equal(actor.requests[0].objectKind, "action");
  assert.ok(signers.every((signer) => signer.requests[0].objectKind === "approval" &&
    signer.requests[0].requestId.startsWith("approval:")));
  assert.equal(new Set(everyone.map((signer) => Buffer.from(signer.requests[0].objectId).toString("hex"))).size, 4);
  assert.ok(everyone.every((signer) => signer.requests[0].expiresAtUnixSeconds ===
    authoredAt + BigInt(fixture.validity_seconds)));
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

test("too few, unlisted, repeated, or self approvals are refused before anything is signed", async () => {
  const attempts = [
    { names: ["manager-a"] },
    { names: ["manager-a", "outsider"] },
    { names: ["manager-a", "manager-a"] },
    { names: ["manager-a", "manager-b"], required: 0 },
    { names: ["manager-a", "manager-b"], required: 4 },
    { names: ["manager-a", fixture.actor] },
  ];
  for (const attempt of attempts) {
    const actor = await seededSigner(fixture.actor);
    const signers = await Promise.all(attempt.names.map((name) => seededSigner(name)));
    await assert.rejects(author("managers-a-and-b", undefined, {
      actor, signers, ...(attempt.required === undefined ? {} : { required: attempt.required }),
    }), (error) => !(error instanceof AuthoringUnsuccessful), JSON.stringify(attempt));
    assert.ok([actor, ...signers].every((signer) => signer.requests.length === 0), JSON.stringify(attempt));
  }
  // The actor is never an approver: listing it is refused natively.
  const actor = await seededSigner(fixture.actor);
  await assert.rejects(authorMcpQuorumProof({
    contract, command: command("managers-a-and-b"), actor, required: 2,
    approvers: [...approvers.slice(0, 2), members.get(fixture.actor).principal],
    signers: await Promise.all(["manager-a", "manager-b"].map((name) => seededSigner(name))),
    trustedContextTemplate: template, challenge, evaluationTime: authoredAt,
  }), (error) => !(error instanceof AuthoringUnsuccessful));
  assert.equal(actor.requests.length, 0);
});

test("a declining approver or actor stops the in-process quorum", async () => {
  const declining = [await seededSigner("manager-a"), await seededSigner("manager-b", { reject: true })];
  await assert.rejects(author("managers-a-and-b", undefined, { signers: declining }), (error) =>
    error instanceof AuthoringUnsuccessful && error.kind === "rejected" && error.code === "denied");
  await assert.rejects(author("managers-a-and-b", ["manager-a", "manager-b"], {
    actor: await seededSigner(fixture.actor, { reject: true }),
  }), (error) => error instanceof AuthoringUnsuccessful && error.kind === "rejected");
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
    assert.deepEqual([report.approvals, report.approvers, report.required], [2, 3, 2]);
    assert.equal(report.matches_gateway_vector, true);
    assert.equal(report.any_two_authorize, true);
    assert.equal(report.single_approval, cases.get("one-of-three-managers").code);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
