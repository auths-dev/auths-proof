import { createPrivateKey, sign as signBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  loadAuths,
  signedGrantSource,
  trustedContextSource,
} from "../../../dist/index.js";
import { mcp } from "../../../dist/mcp.js";

export const ROOT = "key:sha256:qogx823wE-Cfoq_WXwDS1D6S8jMOhJssOpaNRZOJCKs";
export const ACTOR = "key:sha256:MPL4hHxgoCRRtbEjYAedm50CmSM11XgLojSwwYeRi1E";
export const RAW_EVIDENCE = Object.freeze({
  evidenceType: "raw-key-v1",
  mediaType: "application/vnd.auths.raw-key.v1",
});

export const vector = (name) =>
  new Uint8Array(
    readFileSync(
      new URL(`../../../../../target/binding-vectors/${name}`, import.meta.url),
    ),
  );

let wasmPromise;
export async function packagedWasm() {
  if (wasmPromise !== undefined) return wasmPromise;
  wasmPromise = (async () => {
    const wasm = await import("../../../wasm/auths_proof_wasm.js");
    await wasm.default({
      module_or_path: readFileSync(
        new URL("../../../wasm/auths_proof_wasm_bg.wasm", import.meta.url),
      ),
    });
    return wasm;
  })();
  return wasmPromise;
}

export const policy = () => ({
  policyId: "approval.default",
  evaluatorVersion: "1",
  configurationDigest: new Uint8Array(32).fill(7),
});

export const executablePolicy = (reference, mode = "every-action", maxUses = 1) => ({
  reference,
  mode,
  maxUses,
  expiresInSeconds: 300,
  requirements: [],
});

/** Builds the shared MCP client, agent, and profile over canonical vectors. */
export async function mcpFixture(evidence = {
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
      policy: executablePolicy(requiredApproval, "plan-once", 2),
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
