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
} from "../../../dist/index.js";
import { inspectDecision } from "../../../dist/inspection.js";
import { loadVerifier } from "../../../dist/verify.js";
import { McpAction, McpCommand, mcp } from "../../../dist/mcp.js";
import {
  ApplicationAction,
  ApplicationCommand,
  defineProfile,
  verifyApplicationReceipt,
} from "../../../dist/profile-kit.js";
import { development, InMemoryApplicationExecutionStore } from "../../../dist/testkit/index.js";
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

const workflowProjection = () => JSON.parse(readFileSync(
  new URL("../../../../../target/binding-vectors/workflow.projection.json", import.meta.url),
  "utf8",
));
const hex = (value) => Buffer.from(value).toString("hex");

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
    const gateway = profile.gateway({
      state: new InMemoryApplicationExecutionStore(),
      credentials: { async acquire() { return undefined; } },
      receipts: await development.receiptAttestor(),
      canonicalizeResult: (value) => new TextEncoder().encode(value),
      execute: async (command) => command.permission.resource,
    });
    assert.equal(
      (await gateway.execute(result.command, { idempotencyKey: "application-profile" })).output,
      "mcp://reports/tools/update_demo_record",
    );
    assert.throws(() => new ApplicationCommand(Symbol(), {}, {}), /sealed/);
    assert.equal(profile.createVerifiedCommand, undefined);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("application plan gateway keeps exact bytes opaque and stores native signed receipts", async () => {
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
          permission: { capability: "tools/call", resource: "mcp://reports/tools/update_demo_record" },
          resourceNamespace: "mcp://reports",
          audience: "mcp://reports",
          display: [{ label: "Value", value: input.value }],
        };
      },
      decodeVerified(canonical) {
        return JSON.parse(new TextDecoder().decode(canonical.body)).arguments.value;
      },
    });
    const { client, agent } = await fixture(undefined, false, profile);
    const plan = await profile.plan([
      profile.action({ value: "first" }),
      profile.action({ value: "second" }),
    ]);
    const authorization = await agent.authorizePlan(plan);
    assert.equal(authorization.kind, "authorized");
    const stages = [];
    const gateway = profile.gateway({
      state: new InMemoryApplicationExecutionStore(),
      credentials: {
        async acquire(command, context) {
          stages.push(`credential:${command}`);
          assert.ok(context.canonicalCommand.length > 0);
          return undefined;
        },
      },
      receipts: await development.receiptAttestor(),
      canonicalizeResult: (value) => new TextEncoder().encode(value),
      async execute(command, _credential, context) {
        stages.push(`provider:${command}`);
        assert.ok(context.canonicalCommand.length > 0);
        return command;
      },
    });
    const execution = await gateway.executePlan(authorization.command, {
      idempotencyKey: "application-plan",
    });
    assert.deepEqual(execution.outputs, ["first", "second"]);
    assert.deepEqual(stages, [
      "credential:first",
      "provider:first",
      "credential:second",
      "provider:second",
    ]);
    for (const receipt of execution.receipts) {
      await verifyApplicationReceipt(receipt.decisionReceipt);
      await verifyApplicationReceipt(receipt.executionReceipt);
      assert.equal(receipt.stateClaim, "committed");
    }
    await assert.rejects(
      () => gateway.executePlan(authorization.command, { idempotencyKey: "application-plan" }),
      /consumed|forged/,
    );
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

test("MCP development provider is bounded and disposable", async () => {
  const calls = [];
  const provider = mcp.developmentProvider({
    service: "reports",
    timeoutMs: 50,
    tools: {
      async publish_report(argumentsValue, context) {
        calls.push(context.tool);
        return { published: argumentsValue.name };
      },
    },
  });
  const signal = new AbortController().signal;
  assert.deepEqual(
    await provider.invoke(
      "reports",
      "publish_report",
      { name: "weekly" },
      { executionId: "execution", service: "reports", tool: "publish_report" },
      signal,
    ),
    { published: "weekly" },
  );
  assert.deepEqual(
    await provider.invoke(
      "reports",
      "missing",
      {},
      { executionId: "execution", service: "reports", tool: "missing" },
      signal,
    ),
    { effect: "not-applied", cause: "invalid-output" },
  );
  await provider.close();
  await assert.rejects(
    () => provider.invoke(
      "reports",
      "publish_report",
      {},
      { executionId: "execution", service: "reports", tool: "publish_report" },
      signal,
    ),
    { name: "AbortError" },
  );
  assert.deepEqual(calls, ["publish_report"]);
});

test("shared Rust workflow projection matches TypeScript", async () => {
  const projection = workflowProjection();
  const verifier = await loadVerifier();
  const result = verifier.verify(
    vector("workflow.proof.cbor"),
    vector("workflow.action.cbor"),
    vector("workflow.context.cbor"),
  );
  const inspection = await inspectDecision(result);

  assert.equal(projection.schema, "auths.full-workflow-projection/2");
  assert.equal(result.kind, projection.verdict);
  assert.equal(result.stage, projection.stage);
  assert.equal(result.code, projection.code);
  assert.deepEqual(
    Object.fromEntries(Object.entries(result.metrics).map(([key, value]) => [key, Number(value)])),
    projection.metrics,
  );
  assert.equal(hex(result.resultCbor), hex(vector("workflow.result.cbor")));
  assert.equal(hex(inspection.commitments.action), projection.commitments.action);
  assert.equal(hex(inspection.commitments.result), projection.commitments.result);
  assert.equal(
    hex(inspection.commitments.localConfiguration),
    projection.commitments.localConfiguration,
  );

  const profile = mcp.profile({ service: projection.command.service });
  const action = profile.call(
    projection.command.name,
    JSON.parse(projection.command.argumentsJson),
  );
  const plan = await profile.plan([action, action]);
  assert.equal(hex(plan.commitment), projection.commitments.plan);
  const wasm = await packagedWasm();
  assert.equal(
    hex(wasm.commitPlanApprovalV1(plan.commitment, new Uint8Array(32).fill(7), 2, 350n)),
    projection.commitments.planApproval,
  );
  const receiptSigner = projection.receipts.signer;
  const decisionReceipt = wasm.prepareAuthorizedDecisionReceiptV1(
    vector("workflow.proof.cbor"),
    vector("workflow.action.cbor"),
    vector("workflow.context.cbor"),
    60n,
    receiptSigner.principal,
    receiptSigner.verificationMethod,
    receiptSigner.suite,
  );
  assert.equal(hex(decisionReceipt.receiptId), projection.receipts.decision.id);
  assert.equal(hex(decisionReceipt.canonical), projection.receipts.decision.canonical);
  assert.equal(
    hex(decisionReceipt.signingPreimage),
    projection.receipts.decision.signingPreimage,
  );
  const expectedExecution = projection.receipts.execution;
  const executionReceipt = wasm.prepareApplicationExecutionReceiptV1(
    decisionReceipt.receiptId,
    expectedExecution.idempotencyKey,
    true,
    plan.commitment,
    expectedExecution.memberIndex,
    expectedExecution.memberCount,
    vector("workflow.action.cbor"),
    "succeeded",
    true,
    Uint8Array.from(Buffer.from(expectedExecution.result, "hex")),
    BigInt(expectedExecution.completedAt),
    receiptSigner.principal,
    receiptSigner.verificationMethod,
    receiptSigner.suite,
  );
  assert.equal(hex(executionReceipt.receiptId), expectedExecution.id);
  assert.equal(hex(executionReceipt.canonical), expectedExecution.canonical);
  assert.equal(hex(executionReceipt.signingPreimage), expectedExecution.signingPreimage);

  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile: attachedProfile } = await fixture();
    const authorized = await agent.authorize(
      attachedProfile.call(projection.command.name, JSON.parse(projection.command.argumentsJson)),
    );
    assert.equal(authorized.kind, "authorized");
    const calls = [];
    await attachedProfile.gateway(async (call) => calls.push(call)).execute(authorized.command);
    assert.equal(calls[0].service, projection.command.service);
    assert.equal(calls[0].name, projection.command.name);
    assert.equal(new TextDecoder().decode(calls[0].argumentsJson), projection.command.argumentsJson);
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
    const values = [];
    const gateway = profile.gateway(async (call) => {
      values.push(JSON.parse(new TextDecoder().decode(call.argumentsJson)).value);
    });
    await gateway.executePlan(result.command);
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
