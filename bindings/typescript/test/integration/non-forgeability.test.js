import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Auths,
  DiagnosticVerifier,
  VerifiedAction,
  createDiagnosticVerifier,
  loadPortableAuths,
} from "../../dist/advanced.js";
import { mintPackagedVerifierEngine } from "../../dist/verifier/result.js";
import { McpAction, McpCommand, McpProfile, mcp } from "../../dist/mcp.js";
import { mcpFixture, packagedWasm } from "./helpers/mcp-fixture.js";

const fixture = (name) =>
  readFileSync(
    new URL(`../../../../core/fixtures/v1/valid/${name}`, import.meta.url),
  );

const authorizedResultBytes = () => fixture("raw-key-chain.result.cbor");
const actionBytes = () => fixture("raw-key-chain.action.cbor");
const hostileEngine = () => ({ verifyV1: () => authorizedResultBytes() });

test("a hostile engine cannot reach the capability-minting constructor", () => {
  assert.throws(() => new Auths(hostileEngine()), /sealed/);
  assert.throws(() => Reflect.construct(Auths, [hostileEngine()]), /sealed/);
  assert.throws(() => Reflect.construct(Auths, [Symbol(), hostileEngine()]), /sealed/);
});

test("subclassing cannot smuggle a hostile engine into the verifier", () => {
  class ForgedAuths extends Auths {
    constructor() {
      super(hostileEngine());
    }
  }
  assert.throws(() => new ForgedAuths(), /sealed/);

  class ForgedAction extends VerifiedAction {
    constructor() {
      super(Symbol(), actionBytes());
    }
  }
  assert.throws(() => new ForgedAction(), /sealed/);

  class ForgedCommand extends McpCommand {
    constructor() {
      super(Symbol(), {});
    }
  }
  assert.throws(() => new ForgedCommand(), /sealed/);
});

test("prototype grafting cannot produce a working verifier or action", () => {
  const grafted = Object.create(Auths.prototype);
  assert.throws(
    () => grafted.verify(new Uint8Array([1]), actionBytes(), new Uint8Array([2])),
    TypeError,
  );
  const graftedAction = Object.create(VerifiedAction.prototype);
  assert.throws(() => graftedAction.canonicalBytes(), TypeError);
});

test("the packaged mint refuses every engine the loader did not produce", async () => {
  const packaged = await packagedWasm();
  assert.throws(() => mintPackagedVerifierEngine(hostileEngine()), /packaged WASM engine/);
  assert.throws(() => mintPackagedVerifierEngine({ ...packaged }), /packaged WASM engine/);
  assert.throws(() => mintPackagedVerifierEngine(Object.create(packaged)), /packaged WASM engine/);
  assert.throws(
    () => mintPackagedVerifierEngine(new Proxy(packaged, {})),
    /packaged WASM engine/,
  );
  assert.throws(
    () => mintPackagedVerifierEngine({ verifyV1: packaged.verifyV1 }),
    /packaged WASM engine/,
  );
});

test("the packaged module namespace cannot be monkey-patched", async () => {
  const packaged = await packagedWasm();
  assert.throws(() => {
    packaged.verifyV1 = () => authorizedResultBytes();
  }, TypeError);
  assert.equal(Object.isExtensible(packaged), false);
});

test("a forged authorized result never becomes a verified action", () => {
  const diagnostic = createDiagnosticVerifier(hostileEngine()).verify(
    new Uint8Array([1]),
    actionBytes(),
    new Uint8Array([2]),
  );
  assert.equal(diagnostic.kind, "authorized");
  assert.equal("action" in diagnostic, false);
  assert.equal(diagnostic.effectCapable, false);
  assert.equal(diagnostic.submittedActionCbor instanceof VerifiedAction, false);
  assert.throws(() => new DiagnosticVerifier(Symbol(), hostileEngine()), /sealed/);
});

test("a real verified action cannot be copied or serialized into a command", async () => {
  const auths = await loadPortableAuths();
  const result = auths.verify(
    fixture("raw-key-chain.proof.cbor"),
    actionBytes(),
    new Uint8Array(
      readFileSync(
        new URL("../../../../target/binding-vectors/authorized.context.cbor", import.meta.url),
      ),
    ),
  );
  assert.equal(result.kind, "authorized");
  const cloned = structuredClone(result.action);
  assert.equal(cloned instanceof VerifiedAction, false);
  assert.equal(typeof cloned.canonicalBytes, "undefined");
  const copied = { ...result.action };
  assert.equal(copied instanceof VerifiedAction, false);
  assert.equal(typeof copied.canonicalBytes, "undefined");
  assert.equal(JSON.stringify(result.action), "{}");
  const grafted = Object.assign(Object.create(VerifiedAction.prototype), cloned);
  assert.throws(() => grafted.canonicalBytes(), TypeError);
});

test("MCP commands reject copies clones and serialization at the gateway", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile } = await mcpFixture();
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "authorized");
    const gateway = profile.gateway(async () => "executed");
    assert.equal(await gateway.execute(result.command), "executed");

    assert.throws(() => JSON.stringify(result.command), /not serializable/);
    const cloned = structuredClone(result.command);
    assert.equal(cloned instanceof McpCommand, false);
    await assert.rejects(() => gateway.execute(cloned), /forged/);

    const copied = { service: result.command.service, name: result.command.name };
    await assert.rejects(() => gateway.execute(copied), /forged/);
    const grafted = Object.assign(Object.create(McpCommand.prototype), copied);
    await assert.rejects(() => gateway.execute(grafted), /forged/);

    const otherProfile = mcp.profile({ service: "reports" });
    const otherGateway = otherProfile.gateway(async () => "executed");
    await assert.rejects(() => otherGateway.execute(result.command), /forged/);

    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("denied decisions expose no command on any surface", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent, profile } = await mcpFixture(undefined, true);
    const result = await agent.authorize(
      profile.call("update_demo_record", { value: "reviewed" }),
    );
    assert.equal(result.kind, "denied");
    assert.equal("command" in result, false);
    assert.equal("action" in result, false);
    assert.equal(Object.keys(result).includes("command"), false);
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("sealed MCP profile and action constructors stay unavailable", () => {
  assert.throws(() => new McpProfile(Symbol(), "reports"), /sealed/);
  assert.throws(() => new McpAction(Symbol(), {}, "tool", new Uint8Array()), /sealed/);
  // TypeScript's `private static` is compile-time only, so the runtime factories
  // remain reachable. Each one must still reject every forgeable token.
  assert.throws(() => McpCommand.create(Symbol(), {}), /sealed/);
  assert.throws(() => McpProfile.create(Symbol(), "reports"), /sealed/);
  assert.throws(() => McpAction.create(Symbol(), {}, "tool", new Uint8Array()), /sealed/);
  assert.throws(() => VerifiedAction.fromEngine(Symbol(), actionBytes()), /sealed/);
  assert.throws(() => Auths.create(Symbol(), hostileEngine()), /sealed/);
  assert.throws(() => DiagnosticVerifier.create(Symbol(), hostileEngine()), /sealed/);
  for (const token of [undefined, null, "auths-authorized", Symbol.for("auths-authorized")]) {
    assert.throws(() => VerifiedAction.fromEngine(token, actionBytes()), /sealed/);
    assert.throws(() => Auths.create(token, hostileEngine()), /sealed/);
  }
});

test("a hostile action cannot enter the MCP authorization path", async () => {
  const originalNow = Date.now;
  Date.now = () => 50_000;
  try {
    const { client, agent } = await mcpFixture();
    const forged = Object.assign(Object.create(McpAction.prototype), {
      name: "update_demo_record",
    });
    await assert.rejects(() => agent.authorize(forged), /attached MCP profile/);
    await assert.rejects(
      () => agent.authorize({ name: "update_demo_record" }),
      /attached MCP profile/,
    );
    await client.dispose();
  } finally {
    Date.now = originalNow;
  }
});

test("indeterminate engine bytes stay inert", () => {
  const indeterminate = readFileSync(
    new URL(
      "../../../../core/fixtures/v1/indeterminate/unsupported-budget-algebra.result.cbor",
      import.meta.url,
    ),
  );
  const result = createDiagnosticVerifier({ verifyV1: () => indeterminate }).verify(
    new Uint8Array([1]),
    actionBytes(),
    new Uint8Array([2]),
  );
  assert.equal(result.kind, "indeterminate");
  assert.equal("action" in result, false);
  assert.equal(result.effectCapable, false);
});
