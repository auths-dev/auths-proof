import { createPrivateKey, sign as signBytes } from "node:crypto";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  AuthsWorkflowError,
  commandsForGateway,
  loadAuths,
  prepareRawKeyAuthority,
  signedGrantSource,
  trustedContextSource,
} from "../../../dist/index.js";
import { inspectDecision } from "../../../dist/inspection.js";
import { McpAction, McpCommand, mcp } from "../../../dist/mcp.js";
import { ApplicationAction, ApplicationCommand, defineProfile } from "../../../dist/profile-kit.js";
import {
  ACTOR,
  RAW_EVIDENCE,
  ROOT,
  executablePolicy,
  mcpFixture as fixture,
  packagedWasm,
  policy,
  vector,
} from "../helpers/mcp-fixture.js";

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
    assert.equal(result.command instanceof ApplicationCommand, true);
    const gateway = profile.gateway(async (command) => command.permission.resource);
    assert.equal(
      await gateway.execute(result.command),
      "mcp://reports/tools/update_demo_record",
    );
    assert.throws(() => new ApplicationCommand(Symbol(), {}, {}), /sealed/);
    assert.equal(profile.createVerifiedCommand, undefined);
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
      policy: executablePolicy(requiredApproval),
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
    assert.equal(result.command instanceof McpCommand, true);
    const inspection = await inspectDecision(result);
    assert.deepEqual(
      inspection.approval.requiredConfiguration,
      inspection.approval.executedConfiguration,
    );
    const calls = [];
    const gateway = profile.gateway(async (call) => {
      calls.push(call);
      return "executed";
    });
    assert.equal(await gateway.execute(result.command), "executed");
    assert.equal(calls[0].name, "update_demo_record");
    assert.equal(counters.approvals, 1);
    assert.equal(counters.signatures, 1);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP canonical JSON is independent of JavaScript object insertion order", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile } = await fixture();
    const first = profile.call("update_demo_record", {
      z: 2,
      nested: { second: true, first: "é" },
      value: "reviewed",
    });
    const second = profile.call("update_demo_record", {
      value: "reviewed",
      nested: { first: "é", second: true },
      z: 2,
    });
    assert.deepEqual(
      (await profile.plan([first])).commitment,
      (await profile.plan([second])).commitment,
    );

    const result = await agent.authorize(first);
    assert.equal(result.kind, "authorized");
    const gateway = profile.gateway(async (call) =>
      new TextDecoder().decode(call.argumentsJson));
    assert.equal(
      await gateway.execute(result.command),
      '{"nested":{"first":"é","second":true},"value":"reviewed","z":2}',
    );
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("MCP plan approval prompts once and releases only a sealed plan command", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile, counters } = await fixture();
    const plan = await profile.plan([
      profile.call("update_demo_record", { value: "first" }),
      profile.call("update_demo_record", { value: "second" }),
    ]);
    const result = await agent.authorizePlan(plan);
    assert.equal(result.kind, "authorized");
    assert.equal(result.command.count, 2);
    assert.equal(counters.approvals, 1);
    assert.equal(counters.signatures, 2);
    const commands = commandsForGateway(result.command);
    assert.equal(commands.length, 2);
    const values = [];
    const gateway = profile.gateway(async (call) => {
      values.push(JSON.parse(new TextDecoder().decode(call.argumentsJson)).value);
    });
    for (const command of commands) await gateway.execute(command);
    assert.deepEqual(values, ["first", "second"]);
    assert.throws(() => new McpCommand(Symbol(), {}), /sealed/);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("a failed MCP plan exposes no earlier command capability", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile, counters } = await fixture();
    const plan = await profile.plan([
      profile.call("update_demo_record", { value: "allowed" }),
      profile.call("delete_everything", {}),
    ]);
    const result = await agent.authorizePlan(plan);
    assert.equal(result.kind, "denied");
    assert.equal(result.failedIndex, 1);
    assert.equal("command" in result, false);
    assert.equal("command" in result.results[0], false);
    assert.equal(counters.approvals, 1);
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
