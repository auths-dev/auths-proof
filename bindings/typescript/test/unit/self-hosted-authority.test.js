import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  AuthoringUnsuccessful, authorMcpProof, authorRootGrant, compileTrustedContext,
  exactMcpTool, stringField,
} from "../../dist/self-hosted.js";
import { developmentEd25519Key } from "../../dist/testkit/index.js";
import { loadPackagedWorkflowEngine } from "../../dist/internal/wasm.js";

const quorum = JSON.parse(readFileSync(
  new URL("../../../fixtures/gateway/approval-quorum.json", import.meta.url), "utf8",
));
const b64 = (value) => new Uint8Array(Buffer.from(value, "base64url"));

const NOW = 1_790_000_000n;
const AUDIENCE = "mcp://refunds";
const PERMISSION = { capability: "tools/call", resource: `${AUDIENCE}/tools/create_refund_v1` };
const MCP = { id: "auths.mcp", version: 2 };
const CHALLENGE = new Uint8Array(32).fill(0x33);
const ASSURANCE = {
  id: "raw-key-baseline",
  requirements: [
    { role: "root", quantifier: "every", claim: "self-certifying-identifier" },
    { role: "actor", quantifier: "every", claim: "self-certifying-identifier" },
    { role: "actor", quantifier: "every", claim: "offline-verifiable" },
  ],
};
const contract = exactMcpTool({
  service: "refunds",
  name: "create_refund_v1",
  fields: { operation_id: stringField({ minBytes: 1, maxBytes: 64 }) },
});

function custody(key, { decline = false, unbound = false } = {}) {
  const descriptor = {
    contract: "signer-custody/2", kind: "workload", adapterId: "test.development-key",
    principal: key.principal, signature: key.signature, keyVersion: "development-1",
    keyState: "active-current", lifecycle: "ephemeral",
  };
  const requests = [];
  return {
    descriptor,
    requests,
    async sign(request) {
      requests.push(request);
      if (decline) return { kind: "rejected", failure: "denied" };
      return {
        kind: "signed",
        response: {
          requestId: unbound ? `${request.requestId}-other` : request.requestId,
          objectId: request.objectId, principal: key.principal, descriptor: key.signature,
          providerKeyVersion: "development-1", transactionDigest: request.transactionDigest,
          signature: await key.sign(request.signingPreimage), evidence: [key.evidence],
        },
      };
    },
    async close() {},
    async [Symbol.asyncDispose]() {},
  };
}

function rootAnchor(principal) {
  return {
    id: "root", principal, acceptedMethods: ["raw-key-v1"], profiles: [MCP],
    permissions: [PERMISSION], resourceNamespaces: [AUDIENCE], audiences: [AUDIENCE],
    notBefore: NOW - 3_600n, expiresAt: NOW + 86_400n, maxDelegationDepth: 1,
    assurancePolicy: ASSURANCE.id,
  };
}

function grantRequest(signer, subject, extensions) {
  return {
    signer, subject, profile: MCP, permissions: [PERMISSION], audiences: [AUDIENCE],
    notBefore: NOW - 300n, expiresAt: NOW + 3_600n, remainingDepth: 0,
    assuranceFloor: ASSURANCE.id, criticalExtensions: extensions, requestedAt: NOW,
  };
}

async function parties() {
  const root = await developmentEd25519Key(new Uint8Array(32).fill(0x11));
  const agent = await developmentEd25519Key(new Uint8Array(32).fill(0x22));
  return { root, agent };
}

function authorAs(agent, grant, template) {
  return authorMcpProof({
    contract, command: { operation_id: "refund-1" }, grants: [grant],
    trustedContextTemplate: template, signer: custody(agent), challenge: CHALLENGE,
    evaluationTime: NOW,
  });
}

test("compileTrustedContext reproduces the Rust SDK builder's quorum template byte for byte", async () => {
  const audience = `mcp://${quorum.service}`;
  const anchors = quorum.members.filter((member) => member.member).map((member) => ({
    id: member.name, principal: member.principal, acceptedMethods: ["raw-key-v1"], profiles: [MCP],
    permissions: [{ capability: "tools/call", resource: `${audience}/tools/${quorum.tool}` }],
    resourceNamespaces: [audience], audiences: [audience],
    notBefore: BigInt(quorum.evaluation_time - 86_400), expiresAt: BigInt(quorum.evaluation_time + 86_400),
    maxDelegationDepth: 0, assurancePolicy: "approval-quorum-test-v1",
  }));
  const compiled = await compileTrustedContext({
    anchors,
    assurance: { ...ASSURANCE, id: "approval-quorum-test-v1" },
    minimumAuthorizedBranches: quorum.required,
    minimumDistinctActors: quorum.required,
    minimumDistinctRoots: 1,
    evidenceTypes: ["raw-key-v1"],
  });
  assert.deepEqual(compiled, b64(quorum.sdk_trusted_context_b64));
});

test("developmentEd25519Key derives the fixture principals and evidence natively", async () => {
  for (const member of quorum.members) {
    const key = await developmentEd25519Key(new Uint8Array(32).fill(member.seed_byte));
    assert.equal(key.principal, member.principal);
    assert.deepEqual(key.evidence.bytes, b64(member.evidence_b64));
    assert.deepEqual(key.signature, {
      principalMethod: "raw-key-v1", verificationMethod: member.principal, suite: "ed25519-v1",
    });
    assert.equal(key.publicKey.length, 32);
  }
  const fresh = [await developmentEd25519Key(), await developmentEd25519Key()];
  assert.notEqual(fresh[0].principal, fresh[1].principal);
  await assert.rejects(developmentEd25519Key(new Uint8Array(31)), TypeError);
});

test("a root grant's critical extension reaches the verifier, which enforces it", async () => {
  const { root, agent } = await parties();
  const rootSigner = custody(root);
  const grant = await authorRootGrant(grantRequest(
    rootSigner, agent.principal, [{ id: "exact-marker-v1", bytes: new Uint8Array([1]) }],
  ));
  assert.deepEqual(grant.evidence, [root.evidence]);
  assert.equal(rootSigner.requests.length, 1);
  assert.equal(rootSigner.requests[0].objectKind, "grant");
  assert.equal(rootSigner.requests[0].expiresAtUnixSeconds, NOW + 300n);
  const shown = Object.fromEntries(rootSigner.requests[0].display.map((field) => [field.label, field.value]));
  assert.equal(shown["grant subject"], agent.principal);
  assert.equal(shown["critical extensions"], "exact-marker-v1 (1 bytes)");

  const engine = await loadPackagedWorkflowEngine();
  const inspected = engine.inspectSignedGrantV1(grant.signedGrant);
  try {
    assert.equal(inspected.issuer, root.principal);
    assert.equal(inspected.subject, agent.principal);
    assert.equal(inspected.hasParent, false);
    assert.deepEqual([...inspected.criticalExtensions], ["exact-marker-v1"]);
  } finally {
    inspected.free?.();
  }

  const accepting = await compileTrustedContext({
    anchors: [rootAnchor(root.principal)], assurance: ASSURANCE,
    evidenceTypes: ["raw-key-v1"], criticalExtensions: ["exact-marker-v1"],
  });
  const authored = await authorAs(agent, grant, accepting);
  assert.deepEqual(authored.command, { operation_id: "refund-1" });

  const ignorant = await compileTrustedContext({
    anchors: [rootAnchor(root.principal)], assurance: ASSURANCE, evidenceTypes: ["raw-key-v1"],
  });
  await assert.rejects(authorAs(agent, grant, ignorant), (error) =>
    error instanceof AuthoringUnsuccessful && error.kind === "rejected" &&
    error.code === "critical-extension-unknown");

  const wrongMarker = await authorRootGrant(grantRequest(
    custody(root), agent.principal, [{ id: "exact-marker-v1", bytes: new Uint8Array([2]) }],
  ));
  await assert.rejects(authorAs(agent, wrongMarker, accepting), (error) =>
    error instanceof AuthoringUnsuccessful && error.code === "local-policy-denied");
});

test("a context pinned to another verifier is not this package's, and binding equals the native binding", async () => {
  const { root, agent } = await parties();
  const grant = await authorRootGrant(grantRequest(custody(root), agent.principal, []));
  const elsewhere = new Uint8Array(32).fill(7);
  const pinned = await compileTrustedContext({
    anchors: [rootAnchor(root.principal)], assurance: ASSURANCE, configuration: elsewhere,
  });
  const engine = await loadPackagedWorkflowEngine();
  assert.deepEqual(engine.validateTrustedContextV1(pinned, root.principal, elsewhere), pinned);
  assert.throws(() => engine.validateTrustedContextV1(pinned, root.principal, engine.configurationV1()));
  await assert.rejects(authorAs(agent, grant, pinned), (error) =>
    error instanceof AuthoringUnsuccessful && error.code === "verifier-configuration-mismatch");

  const template = await compileTrustedContext({ anchors: [rootAnchor(root.principal)], assurance: ASSURANCE });
  const request = { audience: AUDIENCE, challenge: CHALLENGE, evaluationTime: NOW };
  const bound = await compileTrustedContext({
    anchors: [rootAnchor(root.principal)], assurance: ASSURANCE, request,
  });
  assert.deepEqual(bound, engine.bindTrustedContextRequestV1(template, AUDIENCE, CHALLENGE, NOW));
  assert.notDeepEqual(bound, template);
  assert.deepEqual((await authorAs(agent, grant, bound)).command, { operation_id: "refund-1" });
});

test("malformed trust or grant input is refused before native code or custody", async () => {
  const { root, agent } = await parties();
  const anchors = [rootAnchor(root.principal)];
  for (const [input, kind] of [
    [{ anchors: [], assurance: ASSURANCE }, RangeError],
    [{ anchors, assurance: ASSURANCE, configuration: new Uint8Array(31) }, TypeError],
    [{ anchors, assurance: ASSURANCE, minimumAuthorizedBranches: -1 }, RangeError],
    [{ anchors: [{ ...anchors[0], notBefore: 1 }], assurance: ASSURANCE }, RangeError],
    [{ anchors: [{ ...anchors[0], principal: "" }], assurance: ASSURANCE }, TypeError],
    [{ anchors, assurance: ASSURANCE, request: { audience: AUDIENCE, challenge: new Uint8Array(3), evaluationTime: NOW } }, TypeError],
  ]) {
    await assert.rejects(compileTrustedContext(input), kind);
  }
  await assert.rejects(compileTrustedContext({ anchors, assurance: ASSURANCE, criticalExtensions: ["exact-marker-v1", "exact-marker-v1"] }));

  const signer = custody(root);
  for (const [change, kind] of [
    [{ requestedAt: Number(NOW) }, RangeError],
    [{ subject: "" }, TypeError],
    [{ profile: { id: "auths.mcp", version: 70_000 } }, RangeError],
    [{ criticalExtensions: [{ id: "exact-marker-v1", bytes: new Uint8Array(16_385) }] }, RangeError],
    [{ signer: { descriptor: { ...signer.descriptor, contract: "signer-custody/1" } } }, TypeError],
  ]) {
    await assert.rejects(authorRootGrant({ ...grantRequest(signer, agent.principal, []), ...change }), kind);
  }
  await assert.rejects(authorRootGrant({ ...grantRequest(signer, agent.principal, []), expiresAt: NOW - 400n }));
  assert.equal(signer.requests.length, 0);
});

test("a declining or unbound root custody response issues no grant", async () => {
  const { root, agent } = await parties();
  await assert.rejects(authorRootGrant(grantRequest(custody(root, { decline: true }), agent.principal, [])),
    (error) => error instanceof AuthoringUnsuccessful && error.kind === "rejected" && error.code === "denied");
  await assert.rejects(authorRootGrant(grantRequest(custody(root, { unbound: true }), agent.principal, [])),
    (error) => error instanceof TypeError && /does not bind/.test(error.message));
});
