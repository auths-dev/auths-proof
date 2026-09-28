import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { GatewayClient, GatewayEndpoint, GatewayProtocolError } from "../../dist/gateway.js";
import { createVerifier } from "../../dist/verify.js";

// Signed outcome `/2` conformance: the TypeScript SDK accepts every vector the
// gateway signs, refuses the retired schema, and its WASM verifier reaches the
// gateway's decision on a grant that requires the outcome's stage.
const fixture = JSON.parse(readFileSync(
  new URL("../../../fixtures/gateway/outcome-v2.json", import.meta.url), "utf8",
));
const MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor";
const observation = (entry) => new Uint8Array(Buffer.from(entry.observation_b64, "base64"));
const b64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));
const operation = (entry) => entry.subject.slice(entry.subject.lastIndexOf("/") + 1);

async function observeOutcome(entry, schema) {
  const directory = await mkdtemp(join(tmpdir(), "auths-outcome-"));
  const path = join(directory, "app.sock");
  const reply = Buffer.from(JSON.stringify({
    outcome: "signed",
    schema,
    subject: entry.subject,
    observed_at: fixture.observed_at,
    media_type: MEDIA_TYPE,
    observation_b64: Buffer.from(observation(entry)).toString("base64url"),
  }));
  const server = createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 4 || bytes.length < bytes.readUInt32BE(0) + 4) return;
      const frame = Buffer.alloc(4 + reply.length);
      frame.writeUInt32BE(reply.length, 0);
      reply.copy(frame, 4);
      socket.end(frame);
    });
  });
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    return await new GatewayClient(new GatewayEndpoint(path)).observeOutcome(operation(entry));
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

test("the fixture names outcome /2", () => {
  assert.equal(fixture.outcome_schema, "auths.gateway-outcome/2");
  assert.ok(fixture.accepted.length > 0 && fixture.refused.length > 0 && fixture.verdicts.length > 0);
});

test("the TypeScript client accepts every signed outcome /2", { skip: process.platform === "win32" }, async () => {
  for (const entry of fixture.accepted) {
    const result = await observeOutcome(entry, "auths.gateway-outcome/2");
    assert.deepEqual(result, {
      outcome: "signed",
      schema: "auths.gateway-outcome/2",
      subject: entry.subject,
      observedAt: fixture.observed_at,
      mediaType: MEDIA_TYPE,
      observation: observation(entry),
    }, entry.id);
  }
});

test("the TypeScript client refuses the retired outcome schema", { skip: process.platform === "win32" }, async () => {
  const retired = fixture.refused.find((entry) => entry.id === "outcome-v1-schema");
  await assert.rejects(observeOutcome(retired, "auths.gateway-outcome/1"), GatewayProtocolError);
});

test("the TypeScript verifier reaches the gateway verdict on every outcome /2 case", async () => {
  const verifier = await createVerifier();
  const trustedContext = b64url(fixture.verdict_trusted_context_b64);
  for (const item of fixture.verdicts) {
    const verdict = verifier.verify({
      proof: b64url(item.proof_b64), action: b64url(item.action_b64), trustedContext,
    });
    assert.equal(verdict.kind, item.decision, item.id);
    assert.equal(verdict.code, item.code, item.id);
  }
});
