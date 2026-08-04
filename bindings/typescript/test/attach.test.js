import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AttachedAgent,
  AuthsWorkflowError,
  SignedGrantSource,
  loadAuths,
  signedGrantSource,
} from "../dist/index.js";

const ROOT = "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs";
const SUBJECT = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
const PROFILE = Object.freeze({ id: "auths.mcp", version: 1 });
const signedRootGrant = () =>
  new Uint8Array(
    readFileSync(
      new URL(
        "../../../target/binding-vectors/authoring.signed-root-grant.cbor",
        import.meta.url,
      ),
    ),
  );

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

const policy = (fill = 7) => ({
  policyId: "approval.default",
  evaluatorVersion: "1",
  configurationDigest: new Uint8Array(32).fill(fill),
});

const approval = (required = policy()) => ({
  mode: "grant-only",
  policy: required,
  provider: {
    async approve() {
      throw new Error("attach must not request approval");
    },
  },
});

async function fixture(overrides = {}) {
  const wasm = await packagedWasm();
  const requiredApproval = overrides.requiredApproval ?? policy();
  const counters = { loads: 0, disposals: 0 };
  const provider =
    overrides.provider ??
    {
      async loadSignedGrant(request) {
        counters.loads += 1;
        assert.equal(request.sourceId, "fixture.root");
        assert.equal(request.authorityId, "local.test-root");
        assert.equal(request.subject, overrides.subject ?? SUBJECT);
        assert.deepEqual(request.profile, overrides.profile ?? PROFILE);
        return signedRootGrant();
      },
    };
  const signer = {
    kind: "test-external",
    lifecycle: "durable",
    async publicIdentity() {
      return {
        principal: overrides.subject ?? SUBJECT,
        principalMethod: "raw-key-v1",
        verificationMethod: "key:test-attached-agent",
        suite: "ed25519-v1",
      };
    },
    async sign() {
      throw new Error("attach must not sign");
    },
    async dispose() {
      counters.disposals += 1;
    },
  };
  const client = await loadAuths({
    signer,
    trustedAuthority: {
      authorityId: "local.test-root",
      rootPrincipal: overrides.rootPrincipal ?? ROOT,
      verifierConfiguration: wasm.configurationV1(),
      requiredApproval,
    },
  });
  const source = signedGrantSource({
    sourceId: "fixture.root",
    provider,
  });
  return { client, source, counters, requiredApproval };
}

test("attachAgent binds one canonical root authority through native Rust", async () => {
  const { client, source, counters, requiredApproval } = await fixture();
  const attached = await client.attachAgent({
    name: "research-agent",
    profile: PROFILE,
    authority: source,
    approval: approval(requiredApproval),
  });

  assert.equal(counters.loads, 1);
  assert.equal(attached.name, "research-agent");
  assert.equal(attached.identity.principal.principal, SUBJECT);
  assert.deepEqual(attached.profile, PROFILE);
  assert.equal(attached.authority.issuer, ROOT);
  assert.equal(attached.authority.subject, SUBJECT);
  assert.deepEqual(attached.authority.profile, PROFILE);
  assert.deepEqual(attached.authority.permissions, [
    { capability: "tools/call", resource: "mcp://reports/read" },
  ]);
  assert.deepEqual(attached.authority.validity, {
    notBefore: 20n,
    expiresAt: 80n,
  });
  assert.equal(attached.authority.actionConstraint.kind, "exact-body");
  assert.deepEqual(attached.authority.budget, {
    algebra: "numeric-ceiling-v1",
    value: 10n,
  });
  assert.equal(
    attached.authority.explanation.verification,
    "pending-authorization",
  );
  assert.match(attached.authority.explanation.message, /remain pending/);

  const exposed = attached.authority;
  exposed.grantId.fill(0);
  assert.notDeepEqual(attached.authority.grantId, exposed.grantId);
  await attached.dispose();
  assert.throws(
    () => attached.authority,
    (error) => error instanceof AuthsWorkflowError && error.code === "disposed",
  );
  client.assertActive();
  await client.dispose();
  assert.equal(counters.disposals, 1);
});

test("normal attach rejects caller-shaped sources and sealed object construction", async () => {
  const { client, requiredApproval } = await fixture();
  await assert.rejects(
    client.attachAgent({
      name: "research-agent",
      profile: PROFILE,
      authority: {
        sourceId: "hostile",
        bytes: signedRootGrant(),
      },
      approval: approval(requiredApproval),
    }),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "invalid-authority-source",
  );
  assert.throws(
    () => new SignedGrantSource(Symbol("hostile"), "hostile", {}),
    /sealed Auths signed-grant source/,
  );
  assert.throws(
    () => new AttachedAgent(Symbol("hostile"), {}, "hostile", {}, {}, {}),
    /sealed Auths attached agent/,
  );
  await client.dispose();
});

test("attach differentiates malformed authority from structural mismatch", async () => {
  const malformed = await fixture({
    provider: {
      async loadSignedGrant() {
        return new Uint8Array([0xa0]);
      },
    },
  });
  await assert.rejects(
    malformed.client.attachAgent({
      name: "research-agent",
      profile: PROFILE,
      authority: malformed.source,
      approval: approval(malformed.requiredApproval),
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "invalid-authority",
  );
  await malformed.client.dispose();

  const mismatch = await fixture({ rootPrincipal: SUBJECT });
  await assert.rejects(
    mismatch.client.attachAgent({
      name: "research-agent",
      profile: PROFILE,
      authority: mismatch.source,
      approval: approval(mismatch.requiredApproval),
    }),
    (error) =>
      error instanceof AuthsWorkflowError && error.code === "authority-mismatch",
  );
  await mismatch.client.dispose();
});

test("configuration failures happen before authority I/O and provider failures are sanitized", async () => {
  const beforeIo = await fixture();
  await assert.rejects(
    beforeIo.client.attachAgent({
      name: "research-agent",
      profile: PROFILE,
      authority: beforeIo.source,
      approval: approval(policy(9)),
    }),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "approval-policy-mismatch",
  );
  assert.equal(beforeIo.counters.loads, 0);
  await beforeIo.client.dispose();

  const providerFailure = await fixture({
    provider: {
      async loadSignedGrant() {
        throw new Error("secret provider endpoint and credential");
      },
    },
  });
  await assert.rejects(
    providerFailure.client.attachAgent({
      name: "research-agent",
      profile: PROFILE,
      authority: providerFailure.source,
      approval: approval(providerFailure.requiredApproval),
    }),
    (error) =>
      error instanceof AuthsWorkflowError &&
      error.code === "authority-source-failed" &&
      !error.message.includes("credential"),
  );
  await providerFailure.client.dispose();
});

test("disposing the parent client invalidates attached agents", async () => {
  const { client, source, requiredApproval } = await fixture();
  const attached = await client.attachAgent({
    name: "research-agent",
    profile: PROFILE,
    authority: source,
    approval: approval(requiredApproval),
  });
  await client.dispose();
  assert.throws(
    () => attached.identity,
    (error) => error instanceof AuthsWorkflowError && error.code === "disposed",
  );
  await attached.dispose();
});
