import assert from "node:assert/strict";
import test from "node:test";

import { approvalPolicy } from "../../dist/approvals.js";
import {
  grantId,
  loadLifecycleAuthor,
  statusSnapshotId,
} from "../../dist/lifecycle.js";
import { development } from "../../dist/testkit/index.js";
import { compileTrustedContext } from "../../dist/trust.js";

const MAX_U64 = 18_446_744_073_709_551_615n;

async function lifecycleFixture() {
  const author = await loadLifecycleAuthor();
  const signer = await development.ephemeralSigner();
  const principal = await signer.publicIdentity();
  const policy = await approvalPolicy.everyAction();
  const approval = development.approval(policy);
  return { author, signer, principal, policy, approval };
}

test("lifecycle author binds typed status to signer and Rust-parsed snapshots", async () => {
  const { author, signer, principal, policy, approval } = await lifecycleFixture();
  const observedAt = BigInt(Math.floor(Date.now() / 1000));
  const validUntil = observedAt + 300n;
  const signed = await author.authorPrincipalStatus({
    method: "signed-status-v1",
    principal: principal.principal,
    purpose: "control",
    state: "active",
    sequence: 1n,
    observedAt,
    validUntil,
    issuer: principal.principal,
  }, { signer, approval, requiredApproval: policy.reference, expiresAt: validUntil });
  const second = await author.authorPrincipalStatus({
    method: "signed-status-v1",
    principal: principal.principal,
    purpose: "authentication",
    state: "active",
    sequence: 2n,
    observedAt,
    validUntil,
    issuer: principal.principal,
  }, { signer, approval, requiredApproval: policy.reference, expiresAt: validUntil });
  const snapshot = author.principalSnapshot({
    id: statusSnapshotId("11".repeat(32)),
    observedAt,
    validUntil,
    statements: [signed],
    trust: [{ method: "signed-status-v1", issuer: principal.principal, sequenceFloor: 1n }],
  });

  assert.equal(snapshot.statementCount, 1);
  assert.equal(author.principalSnapshot({
    id: statusSnapshotId("15".repeat(32)),
    observedAt,
    validUntil,
    statements: [second, signed],
  }).statementCount, 2);
  assert.throws(() => author.principalSnapshot({
    id: statusSnapshotId("12".repeat(32)),
    observedAt,
    validUntil,
    statements: [signed, signed],
  }));
  assert.throws(() => author.principalSnapshot({
    id: statusSnapshotId("14".repeat(32)),
    observedAt: observedAt - 1n,
    validUntil,
    statements: [signed],
  }));
  author.dispose();
  assert.throws(() => author.principalSnapshot({
    id: statusSnapshotId("13".repeat(32)),
    observedAt,
    validUntil,
    statements: [],
  }), /disposed/);
  await signer.dispose?.();
});

test("lifecycle author rejects issuer and signer mismatch before signing", async () => {
  const { author, signer, policy, approval } = await lifecycleFixture();
  let signCalls = 0;
  const mismatched = {
    ...signer,
    kind: signer.kind,
    lifecycle: signer.lifecycle,
    publicIdentity: async () => ({
      principal: "did:key:zMismatch",
      principalMethod: "did-key-v1",
      verificationMethod: "did:key:zMismatch#key",
      suite: "ed25519-v1",
    }),
    sign: async (request) => {
      signCalls += 1;
      return signer.sign(request);
    },
  };
  await assert.rejects(author.authorGrantStatus({
    method: "signed-status-v1",
    grantId: grantId("22".repeat(32)),
    state: "revoked",
    sequence: 2n,
    observedAt: 10n,
    validUntil: 100n,
    issuer: "did:key:zExpected",
  }, { signer: mismatched, approval, requiredApproval: policy.reference, expiresAt: 100n }), /does not match/);
  assert.equal(signCalls, 0);
  const descriptor = await signer.publicIdentity();
  await assert.rejects(author.authorGrantStatus({
    method: "signed-status-v1",
    grantId: grantId("23".repeat(32)),
    state: "active",
    sequence: 18_446_744_073_709_551_616n,
    observedAt: 1n,
    validUntil: 2n,
    issuer: descriptor.principal,
  }, { signer, approval, requiredApproval: policy.reference, expiresAt: 2n }));
  await signer.dispose?.();
});

test("typed trust configuration compiles through Rust and rejects unsupported adapters", async () => {
  const { author, signer, principal } = await lifecycleFixture();
  const principalStatus = author.principalSnapshot({
    id: statusSnapshotId("33".repeat(32)),
    observedAt: 0n,
    validUntil: MAX_U64,
    statements: [],
  });
  const grantStatus = author.grantSnapshot({
    id: statusSnapshotId("44".repeat(32)),
    observedAt: 0n,
    validUntil: MAX_U64,
    statements: [],
  });
  const profile = { id: "auths.mcp", version: 1 };
  const configuration = {
    sourceId: "integration.trust",
    composition: {
      minimumAuthorizedBranches: 1,
      minimumDistinctActors: 1,
      minimumDistinctRoots: 1,
    },
    trustAnchors: [{
      id: "integration-root",
      principal: principal.principal,
      acceptedMethods: ["raw-key-v1"],
      profiles: [profile],
      permissions: [{ capability: "mcp.tool.invoke", resource: "mcp://service/tool" }],
      resourceNamespaces: ["mcp://service"],
      audiences: ["auths://integration"],
      notBefore: 0n,
      expiresAt: MAX_U64,
      maxDelegationDepth: 4,
      assurancePolicy: "integration-assurance",
      statusPolicy: { mode: "expiry-only" },
    }],
    registries: {
      principalMethods: ["raw-key-v1"],
      signatureSuites: ["ed25519-v1"],
      evidenceTypes: ["raw-key-v1"],
      principalStatusMethods: [],
      grantStatusMethods: [],
      assuranceClaims: ["self-certifying-identifier"],
      resourceMatchers: ["uri-namespace-v1"],
      profiles: [profile],
      profilePolicies: ["exact-v1"],
    },
    expectedAudience: "auths://integration",
    evaluationTime: 0n,
    assurance: {
      id: "integration-assurance",
      requirements: [{
        role: "root",
        quantifier: "every",
        claimKind: "self-certifying-identifier",
      }],
    },
    principalStatus,
    grantStatus,
    resourceMatcher: "uri-namespace-v1",
    profilePolicy: "exact-v1",
    channelPolicy: "none-v1",
  };

  const compiling = compileTrustedContext(configuration);
  configuration.registries.principalMethods.push("mutated-after-call");
  const compiled = await compiling;
  assert.equal(compiled.verifierConfiguration.length, 32);
  assert.deepEqual(compiled.roots, [principal.principal]);
  configuration.registries.principalMethods.pop();

  await assert.rejects(compileTrustedContext({
    ...configuration,
    registries: { ...configuration.registries, principalMethods: ["uninstalled-method-v1"] },
  }), /Rust rejected/);
  await assert.rejects(compileTrustedContext({
    ...configuration,
    trustAnchors: [],
  }), /Rust rejected/);
  await assert.rejects(compileTrustedContext({
    ...configuration,
    registries: { ...configuration.registries, principalMethods: ["raw-key-v1", "raw-key-v1"] },
  }), /Rust rejected/);
  await assert.rejects(compileTrustedContext({
    ...configuration,
    limits: { "bundle-bytes": 1_000_000_000 },
  }), /Rust rejected/);
  await signer.dispose?.();
});
