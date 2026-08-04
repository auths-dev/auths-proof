import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuthsWorkflowError,
  loadAuths,
  prepareRawKeyAuthority,
  signedGrantSource,
  trustedContextSource,
} from "../dist/index.js";
import { McpAction, mcp } from "../dist/mcp.js";
import { ApplicationAction, defineProfile } from "../dist/profile-kit.js";

const ROOT = "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs";
const ACTOR = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
const RAW_EVIDENCE = Object.freeze({
  evidenceType: "raw-key-v1",
  mediaType: "application/vnd.auths.raw-key.v1",
});
const vector = (name) =>
  new Uint8Array(
    readFileSync(
      new URL(`../../../target/binding-vectors/${name}`, import.meta.url),
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

const policy = () => ({
  policyId: "approval.default",
  evaluatorVersion: "1",
  configurationDigest: new Uint8Array(32).fill(7),
});

async function fixture(evidence = {
  ...RAW_EVIDENCE,
  bytes: vector("mcp.actor-evidence.bin"),
}, invalidSignature = false, profileOverride) {
  const wasm = await packagedWasm();
  const seed = vector("mcp.actor-seed.bin");
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const privateKey = createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" });
  const requiredApproval = policy();
  const counters = { approvals: 0, signatures: 0 };
  const signer = {
    kind: "test-raw-key",
    lifecycle: "durable",
    async publicIdentity() {
      return {
        principal: ACTOR,
        principalMethod: "raw-key-v1",
        verificationMethod: ACTOR,
        suite: "ed25519-v1",
      };
    },
    async sign(request) {
      counters.signatures += 1;
      return {
        requestId: request.requestId,
        principal: request.principal,
        transactionDigest: request.transactionDigest.slice(),
        signature: invalidSignature
          ? new Uint8Array(64)
          : new Uint8Array(signBytes(null, request.signingPreimage, privateKey)),
        evidence: [evidence],
      };
    },
  };
  const client = await loadAuths({
    signer,
    trustedAuthority: {
      authorityId: "local.test-root",
      rootPrincipal: ROOT,
      verifierConfiguration: wasm.configurationV1(),
      context: trustedContextSource({
        sourceId: "fixture.context",
        provider: {
          async loadTrustedContext() { return vector("mcp.context.cbor"); },
        },
      }),
      requiredApproval,
    },
  });
  const profile = profileOverride ?? mcp.profile({ service: "reports" });
  const agent = await client.attachAgent({
    name: "reports-agent",
    profile,
    authority: signedGrantSource({
      sourceId: "fixture.mcp-root",
      provider: {
        async loadSignedGrant() {
          return {
            signedGrant: vector("mcp.signed-root-grant.cbor"),
            evidence: [{ ...RAW_EVIDENCE, bytes: vector("mcp.root-evidence.bin") }],
          };
        },
      },
    }),
    approval: {
      mode: "every-action",
      policy: requiredApproval,
      provider: {
        async approve(request) {
          counters.approvals += 1;
          return {
            requestId: request.requestId,
            transactionDigest: request.transactionDigest.slice(),
            policy: request.policy,
            decision: "approved",
          };
        },
      },
    },
  });
  return { client, agent, profile, counters };
}

test("application profile kit uses the native authoring and verification path", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const profile = defineProfile({
      id: "auths.mcp",
      version: 1,
      canonicalize(input) {
        return {
          mediaType: "application/vnd.auths.mcp-call.v1+json",
          body: new TextEncoder().encode(
            `{"arguments":{"value":"${input.value}"},"name":"update_demo_record","profile":"auths.mcp","profile_version":1,"service":"reports"}`,
          ),
          permission: {
            capability: "tools/call",
            resource: "mcp://reports/tools/update_demo_record",
          },
          resourceNamespace: "mcp://reports",
          audience: "mcp://reports",
          display: [
            { label: "Service", value: "reports" },
            { label: "Tool", value: "update_demo_record" },
          ],
        };
      },
    });
    const { client, agent } = await fixture(undefined, false, profile);
    const action = profile.action({ value: "reviewed" });
    assert.equal(action instanceof ApplicationAction, true);
    const result = await agent.authorize(action);
    assert.equal(result.kind, "authorized", `${result.stage}:${result.code}`);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("raw-key bootstrap creates the root grant and trusted context locally", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const requiredApproval = policy();
    const approval = {
      mode: "every-action",
      policy: requiredApproval,
      provider: {
        async approve(request) {
          return {
            requestId: request.requestId,
            transactionDigest: request.transactionDigest.slice(),
            policy: request.policy,
            decision: "approved",
          };
        },
      },
    };
    const signer = (principal, seedName, evidenceName) => {
      const seed = vector(seedName);
      const privateKey = createPrivateKey({
        key: Buffer.concat([
          Buffer.from("302e020100300506032b657004220420", "hex"),
          Buffer.from(seed),
        ]),
        format: "der",
        type: "pkcs8",
      });
      return {
        kind: "test-raw-key",
        lifecycle: "durable",
        async publicIdentity() {
          return {
            principal,
            principalMethod: "raw-key-v1",
            verificationMethod: principal,
            suite: "ed25519-v1",
          };
        },
        async sign(request) {
          return {
            requestId: request.requestId,
            principal: request.principal,
            transactionDigest: request.transactionDigest.slice(),
            signature: new Uint8Array(signBytes(null, request.signingPreimage, privateKey)),
            evidence: [{
              ...RAW_EVIDENCE,
              bytes: vector(evidenceName),
            }],
          };
        },
      };
    };
    const rootSigner = signer(ROOT, "mcp.root-seed.bin", "mcp.root-evidence.bin");
    const actorSigner = signer(ACTOR, "mcp.actor-seed.bin", "mcp.actor-evidence.bin");
    const profile = mcp.profile({ service: "reports" });
    const prepared = await prepareRawKeyAuthority({
      authorityId: "local.bootstrap",
      rootSigner,
      subjectPrincipal: ACTOR,
      profile,
      permissions: [{
        capability: "tools/call",
        resource: "mcp://reports/tools/update_demo_record",
      }],
      resourceNamespaces: ["mcp://reports"],
      validity: { notBefore: 20n, expiresAt: 80n },
      audiences: ["mcp://reports"],
      budget: { algebra: "numeric-ceiling-v1", value: 20n },
      remainingDepth: 0,
      approval,
    });
    const client = await loadAuths({
      signer: actorSigner,
      trustedAuthority: prepared.trustedAuthority,
    });
    const agent = await client.attachAgent({
      name: "bootstrap-agent",
      profile,
      authority: prepared.authority,
      approval,
    });
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "authorized", `${result.stage}:${result.code}`);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP facade canonicalizes signs assembles and authorizes locally", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile, counters } = await fixture();
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "authorized");
    assert.equal(result.stage, "complete");
    assert.equal(counters.approvals, 1);
    assert.equal(counters.signatures, 1);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP authorization preserves indeterminate as a value", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile } = await fixture({
      evidenceType: "unavailable-control-v1",
      mediaType: "application/octet-stream",
      bytes: new Uint8Array([1]),
    });
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "indeterminate");
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP authorization preserves denial as a value", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const evidence = {
      ...RAW_EVIDENCE,
      bytes: vector("mcp.actor-evidence.bin"),
    };
    const { client, agent, profile } = await fixture(evidence, true);
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "denied");
    assert.equal(result.code, "invalid-signature");
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP actions are profile-bound and sealed", async () => {
  const first = mcp.profile({ service: "reports" });
  const second = mcp.profile({ service: "records" });
  assert.throws(
    () => new McpAction(Symbol("hostile"), first, "read", new Uint8Array([1])),
    /sealed Auths MCP action/,
  );
  const { client, agent } = await fixture();
  await assert.rejects(
    agent.authorize(second.call("update_demo_record", { value: "reviewed" })),
    (error) => error instanceof AuthsWorkflowError && error.code === "invalid-profile",
  );
  await client.dispose();
});
