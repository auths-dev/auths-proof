import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Auths,
  VerifiedAction,
  commitCanonical,
  createDiagnosticVerifier,
  inspectDecision,
} from "../../dist/advanced.js";
import { McpAction, McpCommand, mcp } from "../../dist/mcp.js";
import { ApplicationCommand, defineProfile } from "../../dist/profile-kit.js";
import { ProfilePlan, VerifiedPlanCommand, commandsForGateway } from "../../dist/index.js";
import { mcpFixture } from "./helpers/mcp-fixture.js";

const authorizedFixture = async () => {
  const { client, agent, profile } = await mcpFixture();
  const result = await agent.authorize(
    profile.call("update_demo_record", { value: "reviewed" }),
  );
  assert.equal(result.kind, "authorized");
  return { client, profile, result };
};

const withFrozenClock = async (body) => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    return await body();
  } finally {
    Date.now = originalNow;
  }
};

test("inspection exposes copied bounded evidence and no capability", async () => {
  await withFrozenClock(async () => {
    const { client, result } = await authorizedFixture();
    const inspection = await inspectDecision(result);

    assert.equal(Object.isFrozen(inspection), true);
    assert.equal(Object.isFrozen(inspection.commitments), true);
    assert.equal(Object.isFrozen(inspection.decision), true);
    assert.equal(Object.isFrozen(inspection.kernel), true);
    assert.equal(Object.isFrozen(inspection.safeToLog), true);

    assert.equal("action" in inspection, false);
    assert.equal("command" in inspection, false);
    assert.equal("proof" in inspection, false);
    assert.equal("resultCbor" in inspection, false);
    assert.equal(inspection.commitments.result.length, 32);
    assert.equal(inspection.commitments.action.length, 32);

    for (const value of Object.values(inspection.safeToLog)) {
      assert.equal(["string", "boolean"].includes(typeof value), true);
    }

    const again = await inspectDecision(result);
    inspection.commitments.result[0] ^= 0xff;
    assert.notDeepEqual(inspection.commitments.result, again.commitments.result);

    await client.dispose();
  });
});

test("inspection evidence cannot be promoted into any command", async () => {
  await withFrozenClock(async () => {
    const { client, profile, result } = await authorizedFixture();
    const inspection = await inspectDecision(result);
    const gateway = profile.gateway(async () => "executed");

    for (const candidate of [
      inspection,
      inspection.commitments,
      { ...inspection, service: result.command.service, name: result.command.name },
      Object.assign(Object.create(McpCommand.prototype), inspection),
      Object.assign(Object.create(McpCommand.prototype), inspection.commitments),
    ]) {
      await assert.rejects(() => gateway.execute(candidate), /forged/);
    }

    assert.throws(
      () => new VerifiedAction(Symbol(), inspection.commitments.action),
      /sealed/,
    );
    assert.throws(() => new McpCommand(Symbol(), inspection), /sealed/);
    assert.throws(() => new ApplicationCommand(Symbol(), inspection, inspection), /sealed/);
    assert.throws(() => new VerifiedPlanCommand(Symbol(), [inspection]), /sealed/);
    assert.throws(() => new ProfilePlan(Symbol(), profile, [], {}), /sealed/);
    assert.throws(() => commandsForGateway(inspection), /sealed|plan/);

    await client.dispose();
  });
});

test("canonical bytes recovered from inspection stay inert", async () => {
  await withFrozenClock(async () => {
    const { client, profile, result } = await authorizedFixture();
    const canonical = result.action.canonicalBytes();
    const commitment = await commitCanonical("auths.canonical-action.v1", canonical);
    const inspection = await inspectDecision(result);
    assert.deepEqual(commitment.digest, inspection.commitments.action);

    // Replaying the canonical bytes through an engine the caller controls
    // reproduces the verdict as evidence and nothing more.
    const replay = createDiagnosticVerifier({ verifyV1: () => result.resultCbor }).verify(
      new Uint8Array([1]),
      canonical,
      new Uint8Array([2]),
    );
    assert.equal(replay.kind, "authorized");
    assert.equal(replay.effectCapable, false);
    assert.equal("action" in replay, false);

    const gateway = profile.gateway(async () => "executed");
    await assert.rejects(() => gateway.execute(replay), /forged/);
    assert.throws(() => new Auths({ verifyV1: () => result.resultCbor }), /sealed/);

    await client.dispose();
  });
});

test("application profile inspection cannot mint its own command", async () => {
  await withFrozenClock(async () => {
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
          display: [{ label: "Tool", value: "update_demo_record" }],
        };
      },
    });
    const { client, agent } = await mcpFixture(undefined, false, profile);
    const result = await agent.authorize(profile.action({ value: "reviewed" }));
    assert.equal(result.kind, "authorized", `${result.stage}:${result.code}`);

    const inspection = await inspectDecision(result);
    const gateway = profile.gateway(async (command) => command.permission.resource);
    await assert.rejects(() => gateway.execute(inspection), /forged/);
    assert.equal(profile.createVerifiedCommand, undefined);

    const inspected = profile.inspectAction(profile.action({ value: "reviewed" }));
    await assert.rejects(() => gateway.execute(inspected), /forged/);

    await client.dispose();
  });
});

test("advanced inspection never reaches profile action construction", async () => {
  await withFrozenClock(async () => {
    const { client, result } = await authorizedFixture();
    const inspection = await inspectDecision(result);
    const other = mcp.profile({ service: "reports" });
    assert.throws(
      () => new McpAction(Symbol(), other, "update_demo_record", inspection.commitments.action),
      /sealed/,
    );
    await client.dispose();
  });
});
