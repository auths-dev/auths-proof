import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuthsWorkflowError,
  loadAuths,
  signedGrantSource,
  trustedContextSource,
} from "../dist/index.js";

const ROOT = "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs";
const PARENT = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
const CHILD = "did:web:child.workflow.auths.example";
const PROFILE = Object.freeze({ id: "auths.mcp", version: 1 });

const vector = (name) =>
  new Uint8Array(
    readFileSync(
      new URL(`../../../target/binding-vectors/${name}`, import.meta.url),
    ),
  );
const contextSource = () =>
  trustedContextSource({
    sourceId: "fixture.context",
    provider: {
      async loadTrustedContext() { return vector("authorized.context.cbor"); },
    },
  });

let wasmPromise;

async function packagedWasm() {
  if (wasmPromise !== undefined) return wasmPromise;
  wasmPromise = (async () => {
    const wasm = await import("../wasm/auths_proof_wasm.js");
    await wasm.default({
      module_or_path: readFileSync(
        new URL("../wasm/auths_proof_wasm_bg.wasm", import.meta.url),
      ),
    });
    return wasm;
  })();
  return wasmPromise;
}

const policy = () => ({
  policyId: "approval.default",
  evaluatorVersion: "1",
  configurationDigest: new Uint8Array(32).fill(7),
});

const baseAuthority = () => ({
  permissions: [{ capability: "tools/call", resource: "mcp://reports/read" }],
  validity: { notBefore: 20n, expiresAt: 80n },
  audiences: ["mcp://reports"],
  actionConstraint: { kind: "inherit" },
  budget: {
    kind: "ceiling",
    algebra: "numeric-ceiling-v1",
    value: 10n,
  },
  remainingDepth: 1,
  status: {
    kind: "snapshot-required",
    method: "status.test-v1",
    maxAge: 30n,
  },
});

async function fixture(
  rootVector = "authoring.delegation-root-grant.cbor",
  approvalDecision = "approved",
) {
  const wasm = await packagedWasm();
  const counters = {
    approvals: 0,
    parentSignatures: 0,
    childSignatures: 0,
    childDisposals: 0,
  };
  const requiredApproval = policy();
  const approval = {
    mode: "grant-only",
    policy: requiredApproval,
    provider: {
      async approve(request) {
        counters.approvals += 1;
        return {
          requestId: request.requestId,
          transactionDigest: request.transactionDigest.slice(),
          policy: request.policy,
          decision: approvalDecision,
        };
      },
    },
  };
  const parentSigner = {
    kind: "test-parent",
    lifecycle: "durable",
    async publicIdentity() {
      return {
        principal: PARENT,
        principalMethod: "raw-key-v1",
        verificationMethod: "key:test-parent",
        suite: "ed25519-v1",
      };
    },
    async sign(request) {
      counters.parentSignatures += 1;
      return {
        requestId: request.requestId,
        principal: request.principal,
        transactionDigest: request.transactionDigest.slice(),
        signature: new Uint8Array(64).fill(9),
      };
    },
  };
  const childSigner = {
    kind: "test-child",
    lifecycle: "ephemeral",
    async publicIdentity() {
      return {
        principal: CHILD,
        principalMethod: "did-web-v1",
        verificationMethod: `${CHILD}#key-1`,
        suite: "ed25519-v1",
      };
    },
    async sign() {
      counters.childSignatures += 1;
      throw new Error("child signer must not sign its incoming grant");
    },
    async dispose() {
      counters.childDisposals += 1;
    },
  };
  const client = await loadAuths({
    signer: parentSigner,
    trustedAuthority: {
      authorityId: "local.test-root",
      rootPrincipal: ROOT,
      verifierConfiguration: wasm.configurationV1(),
      context: contextSource(),
      requiredApproval,
    },
  });
  const parent = await client.attachAgent({
    name: "research-agent",
    profile: PROFILE,
    authority: signedGrantSource({
      sourceId: rootVector,
      provider: {
        async loadSignedGrant() {
          return { signedGrant: vector(rootVector), evidence: [] };
        },
      },
    }),
    approval,
  });
  return { client, parent, childSigner, counters };
}

test("delegate plans reviews approves and signs one attenuated child", async () => {
  const { client, parent, childSigner, counters } = await fixture();
  const child = await parent.delegate({
    name: "records-child",
    authority: baseAuthority(),
    signer: childSigner,
  });

  assert.equal(counters.approvals, 1);
  assert.equal(counters.parentSignatures, 1);
  assert.equal(counters.childSignatures, 0);
  assert.equal(child.identity.principal.principal, CHILD);
  assert.equal(child.authority.issuer, PARENT);
  assert.equal(child.authority.subject, CHILD);
  assert.deepEqual(child.authority.validity, {
    notBefore: 20n,
    expiresAt: 80n,
  });
  assert.deepEqual(child.authority.budget, {
    algebra: "numeric-ceiling-v1",
    value: 10n,
  });
  assert.deepEqual(child.authority.status, {
    policy: "snapshot-required",
    method: "status.test-v1",
    maxAge: 30n,
  });
  assert.deepEqual(child.authority.criticalExtensions, ["extension.test-v1"]);
  assert.equal(
    child.authority.explanation.code,
    "delegated-authority-structurally-bound",
  );
  assert.deepEqual(child.delegation.diff, {
    removedPermissions: 0,
    removedAudiences: 0,
    validityShortened: true,
    actionNarrowed: false,
    budgetNarrowed: true,
    statusNarrowed: true,
    parentDepth: 2,
    childDepth: 1,
  });
  assert.deepEqual(child.delegation.warnings, [
    "any-body",
    "delegation-allowed",
  ]);

  await child.dispose();
  await child.dispose();
  assert.equal(counters.childDisposals, 1);
  await parent.dispose();
  await client.dispose();
});

test("every caller-selectable authority dimension fails before approval when widened", async (t) => {
  const cases = [
    ["permissions", () => ({ ...baseAuthority(), permissions: [
      ...baseAuthority().permissions,
      { capability: "tools/admin", resource: "mcp://reports/admin" },
    ] })],
    ["validity", () => ({ ...baseAuthority(), validity: { notBefore: 0n, expiresAt: 101n } })],
    ["audiences", () => ({ ...baseAuthority(), audiences: ["mcp://other"] })],
    ["budget", () => ({ ...baseAuthority(), budget: {
      kind: "ceiling", algebra: "numeric-ceiling-v1", value: 21n,
    } })],
    ["delegation depth", () => ({ ...baseAuthority(), remainingDepth: 2 })],
    ["status", () => ({ ...baseAuthority(), status: { kind: "expiry-only" } })],
    ["assurance", () => ({ ...baseAuthority(), assuranceFloor: "weaker-policy" })],
  ];

  for (const [name, authority] of cases) {
    await t.test(name, async () => {
      const { client, parent, childSigner, counters } = await fixture();
      await assert.rejects(
        parent.delegate({ name: "records-child", authority: authority(), signer: childSigner }),
        (error) =>
          error instanceof AuthsWorkflowError && error.code === "delegation-expanded",
      );
      assert.equal(counters.approvals, 0);
      assert.equal(counters.parentSignatures, 0);
      assert.equal(counters.childDisposals, 1);
      await parent.dispose();
      await client.dispose();
    });
  }
});

test("profile action and critical-extension substitution are closed before approval", async () => {
  const profile = await fixture();
  await assert.rejects(
    profile.parent.delegate({
      name: "records-child",
      authority: baseAuthority(),
      signer: profile.childSigner,
      profile: { id: "auths.http", version: 1 },
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "delegation-expanded",
  );
  assert.equal(profile.counters.approvals, 0);
  await profile.parent.dispose();
  await profile.client.dispose();

  const action = await fixture("authoring.signed-root-grant.cbor");
  await assert.rejects(
    action.parent.delegate({
      name: "records-child",
      authority: {
        ...baseAuthority(),
        actionConstraint: { kind: "any-body" },
        remainingDepth: 0,
      },
      signer: action.childSigner,
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "delegation-expanded",
  );
  assert.equal(action.counters.approvals, 0);
  await action.parent.dispose();
  await action.client.dispose();

  const extensions = await fixture();
  await assert.rejects(
    extensions.parent.delegate({
      name: "records-child",
      authority: {
        ...baseAuthority(),
        criticalExtensions: [],
      },
      signer: extensions.childSigner,
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "invalid-delegation",
  );
  assert.equal(extensions.counters.approvals, 0);
  await extensions.parent.dispose();
  await extensions.client.dispose();
});

test("client disposal cleans up attached ephemeral child signers", async () => {
  const { client, parent, childSigner, counters } = await fixture();
  const child = await parent.delegate({
    name: "records-child",
    authority: baseAuthority(),
    signer: childSigner,
  });
  await client.dispose();
  assert.equal(child.disposed, true);
  assert.equal(parent.disposed, true);
  assert.equal(counters.childDisposals, 1);
  await child.dispose();
  assert.equal(counters.childDisposals, 1);
});

test("approval rejection signs nothing and cleans up the acquired child signer", async () => {
  const { client, parent, childSigner, counters } = await fixture(
    "authoring.delegation-root-grant.cbor",
    "rejected",
  );
  await assert.rejects(
    parent.delegate({
      name: "records-child",
      authority: baseAuthority(),
      signer: childSigner,
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "approval-rejected",
  );
  assert.equal(counters.approvals, 1);
  assert.equal(counters.parentSignatures, 0);
  assert.equal(counters.childDisposals, 1);
  await parent.dispose();
  await client.dispose();
});
