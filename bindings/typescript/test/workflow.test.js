import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuthsClient,
  AuthsWorkflowError,
  ProviderOperationError,
  loadAuths,
  trustedContextSource,
} from "../dist/index.js";
import {
  SigningCoordinator,
  WasmSigningAdapter,
} from "../dist/internal/signing.js";

const descriptor = () => ({
  principal: "did:web:workflow.auths.example",
  principalMethod: "did-web-v1",
  verificationMethod: "did:web:workflow.auths.example#key-1",
  suite: "ed25519-v1",
});

const policy = (fill = 7) => ({
  policyId: "approval.default",
  evaluatorVersion: "1",
  configurationDigest: new Uint8Array(32).fill(fill),
});
const ROOT = "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs";
const contextSource = () =>
  trustedContextSource({
    sourceId: "fixture.context",
    provider: {
      async loadTrustedContext() {
        return new Uint8Array(
          readFileSync(
            new URL("../../../target/binding-vectors/authorized.context.cbor", import.meta.url),
          ),
        );
      },
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

async function packagedConfiguration() {
  return (await packagedWasm()).configurationV1();
}

test("workflow loader binds an immutable principal to package-owned WASM", async () => {
  const mutableDescriptor = descriptor();
  const verifierConfiguration = await packagedConfiguration();
  const requiredApproval = policy();
  let disposed = 0;
  const signer = {
    kind: "test-external",
    lifecycle: "durable",
    async publicIdentity() {
      return mutableDescriptor;
    },
    async sign() {
      throw new Error("not used while loading");
    },
    async dispose() {
      disposed += 1;
    },
  };

  const client = await loadAuths({
    signer,
    trustedAuthority: {
      authorityId: "local.test-root",
      rootPrincipal: ROOT,
      verifierConfiguration,
      context: contextSource(),
      requiredApproval,
    },
  });
  mutableDescriptor.principal = "did:web:substituted.example";
  verifierConfiguration.fill(0);
  requiredApproval.configurationDigest.fill(0);

  assert.equal(
    client.identity.principal.principal,
    "did:web:workflow.auths.example",
  );
  assert.equal(client.identity.signerKind, "test-external");
  assert.notDeepEqual(
    client.trustedAuthority.verifierConfiguration,
    verifierConfiguration,
  );
  assert.notDeepEqual(
    client.trustedAuthority.requiredApproval.configurationDigest,
    requiredApproval.configurationDigest,
  );
  const exposedAuthority = client.trustedAuthority;
  exposedAuthority.verifierConfiguration.fill(0);
  exposedAuthority.requiredApproval.configurationDigest.fill(0);
  assert.notDeepEqual(
    client.trustedAuthority.verifierConfiguration,
    exposedAuthority.verifierConfiguration,
  );
  assert.notDeepEqual(
    client.trustedAuthority.requiredApproval.configurationDigest,
    exposedAuthority.requiredApproval.configurationDigest,
  );

  await client.dispose();
  await client.dispose();
  assert.equal(disposed, 1);
  assert.throws(
    () => client.assertActive(),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "disposed",
  );
});

test("application code cannot construct a workflow client", () => {
  assert.throws(
    () => new AuthsClient(Symbol("hostile"), {}, {}, {}, {}),
    /sealed Auths workflow client/,
  );
  assert.throws(
    () => AuthsClient.create(Symbol("hostile"), {}, {}, {}, {}),
    /sealed Auths workflow client/,
  );
});

test("workflow load fails closed and cleans up on trust mismatch", async () => {
  let identityCalls = 0;
  let disposed = 0;
  const signer = {
    kind: "test-external",
    lifecycle: "ephemeral",
    async publicIdentity() {
      identityCalls += 1;
      return descriptor();
    },
    async sign() {
      throw new Error("must not sign");
    },
    async dispose() {
      disposed += 1;
    },
  };
  await assert.rejects(
    loadAuths({
      signer,
      trustedAuthority: {
        authorityId: "wrong.test-root",
        rootPrincipal: "did:web:root.auths.example",
        verifierConfiguration: new Uint8Array(32),
        context: contextSource(),
        requiredApproval: policy(),
      },
    }),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "configuration-mismatch",
  );
  assert.equal(identityCalls, 0);
  assert.equal(disposed, 1);
});

function signingFixture(overrides = {}) {
  const counters = { approvals: 0, signatures: 0, completions: 0 };
  const requiredApproval = policy();
  const principal = descriptor();
  const adapter = {
    prepare(objectKind) {
      return {
        objectKind,
        objectId: new Uint8Array(32).fill(3),
        signingPreimage: new Uint8Array([4, 5, 6]),
      };
    },
    complete(_kind, _unsigned, _principal, signature) {
      counters.completions += 1;
      return new Uint8Array([0xa1, ...signature]);
    },
  };
  const approvalProvider = {
    async approve(request) {
      counters.approvals += 1;
      return {
        requestId: request.requestId,
        transactionDigest: request.transactionDigest.slice(),
        policy: request.policy,
        decision: "approved",
      };
    },
  };
  const signer = {
    kind: "test-external",
    lifecycle: "ephemeral",
    async publicIdentity() {
      return principal;
    },
    async sign(request) {
      counters.signatures += 1;
      return {
        requestId: request.requestId,
        principal: request.principal,
        transactionDigest: request.transactionDigest.slice(),
        signature: new Uint8Array(64).fill(9),
        evidence: [{
          evidenceType: "raw-key-v1",
          mediaType: "application/vnd.auths.raw-key.v1",
          bytes: new Uint8Array([8]),
        }],
      };
    },
  };
  return {
    counters,
    adapter,
    options: {
      objectKind: "grant",
      unsignedObject: new Uint8Array([0xa0]),
      principal,
      signer,
      approval: {
        mode: "grant-only",
        policy: requiredApproval,
        provider: approvalProvider,
      },
      requiredApproval,
      expiresAt: 200n,
      display: [{ label: "Agent", value: "records-child" }],
      ...overrides,
    },
  };
}

test("exact approval and signer responses complete one transaction", async () => {
  const fixture = signingFixture();
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  const result = await coordinator.execute(fixture.options);
  assert.equal(result.transactionDigest.length, 32);
  assert.deepEqual(result.evidence, [{
    evidenceType: "raw-key-v1",
    mediaType: "application/vnd.auths.raw-key.v1",
    bytes: new Uint8Array([8]),
  }]);
  assert.equal(fixture.counters.approvals, 1);
  assert.equal(fixture.counters.signatures, 1);
  assert.equal(fixture.counters.completions, 1);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "transaction-consumed",
  );
});

test("transaction binding drives the real Rust WASM authoring ABI", async () => {
  const wasm = await packagedWasm();
  const fixture = signingFixture({
    unsignedObject: readFileSync(
      new URL(
        "../../../target/binding-vectors/authoring.proposed-grant.cbor",
        import.meta.url,
      ),
    ),
  });
  const coordinator = new SigningCoordinator(
    new WasmSigningAdapter(wasm),
    () => 100n,
  );
  const result = await coordinator.execute(fixture.options);
  assert.ok(result.signedObject.length > fixture.options.unsignedObject.length);
  assert.equal(fixture.counters.approvals, 1);
  assert.equal(fixture.counters.signatures, 1);
});

test("approval commitment mismatch invokes no provider", async () => {
  const fixture = signingFixture({ requiredApproval: policy(99) });
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "approval-policy-mismatch",
  );
  assert.deepEqual(fixture.counters, {
    approvals: 0,
    signatures: 0,
    completions: 0,
  });
});

test("hostile approval substitution invokes no signer", async () => {
  const fixture = signingFixture();
  fixture.options.approval.provider.approve = async (request) => {
    fixture.counters.approvals += 1;
    return {
      requestId: request.requestId,
      transactionDigest: new Uint8Array(32),
      policy: request.policy,
      decision: "approved",
    };
  };
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "approval-response-mismatch",
  );
  assert.equal(fixture.counters.approvals, 1);
  assert.equal(fixture.counters.signatures, 0);
  assert.equal(fixture.counters.completions, 0);
});

test("runtime-invalid approval modes fail before any callback", async () => {
  const fixture = signingFixture();
  fixture.options.approval.mode = "trust-me";
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "invalid-provider",
  );
  assert.deepEqual(fixture.counters, {
    approvals: 0,
    signatures: 0,
    completions: 0,
  });
});

test("hostile signer substitution cannot reach native completion", async () => {
  const fixture = signingFixture();
  fixture.options.signer.sign = async (request) => {
    fixture.counters.signatures += 1;
    return {
      requestId: request.requestId,
      principal: request.principal,
      transactionDigest: new Uint8Array(32),
      signature: new Uint8Array(64).fill(9),
    };
  };
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "signer-response-mismatch",
  );
  assert.equal(fixture.counters.approvals, 1);
  assert.equal(fixture.counters.signatures, 1);
  assert.equal(fixture.counters.completions, 0);
});

test("provider exceptions are sanitized before they cross the SDK", async () => {
  const fixture = signingFixture();
  fixture.options.approval.provider.approve = async () => {
    throw new Error("secret signing preimage: 040506");
  };
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) => {
      assert.equal(error.code, "approval-failed");
      assert.doesNotMatch(error.message, /040506|secret/);
      return true;
    },
  );
  assert.equal(fixture.counters.signatures, 0);
});

test("provider cancellation remains a distinct typed workflow error", async () => {
  const fixture = signingFixture();
  fixture.options.signer.sign = async () => {
    throw new ProviderOperationError("cancelled");
  };
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "signer-cancelled",
  );
  assert.equal(fixture.counters.completions, 0);
});

test("throwing hostile response accessors are sanitized", async () => {
  const fixture = signingFixture();
  fixture.options.signer.sign = async (request) => ({
    requestId: request.requestId,
    principal: request.principal,
    transactionDigest: request.transactionDigest,
    get signature() {
      throw new Error("private provider state");
    },
  });
  const coordinator = new SigningCoordinator(fixture.adapter, () => 100n);
  await assert.rejects(
    coordinator.execute(fixture.options),
    (error) => {
      assert.equal(error.code, "signer-response-mismatch");
      assert.doesNotMatch(error.message, /private provider state/);
      return true;
    },
  );
  assert.equal(fixture.counters.completions, 0);
});
