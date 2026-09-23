import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { GatewayClient, GatewayEndpoint, GatewayProtocolError } from "../../dist/gateway.js";

test("gateway client submits proof/action only and separates observed from effect", { skip: process.platform === "win32" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "auths-gateway-"));
  const path = join(directory, "app.sock");
  const seen = [];
  const server = createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 4 || bytes.length < bytes.readUInt32BE(0) + 4) return;
      seen.push(JSON.parse(bytes.subarray(4, bytes.readUInt32BE(0) + 4).toString("utf8")));
      const reply = Buffer.from('{"outcome":"observed","status":200,"matched":true}');
      const frame = Buffer.alloc(4 + reply.length);
      frame.writeUInt32BE(reply.length, 0);
      reply.copy(frame, 4);
      socket.end(frame);
    });
  });
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    const result = await new GatewayClient(new GatewayEndpoint(path)).submit({
      proof: new Uint8Array([1, 2]),
      action: new Uint8Array([3, 4]),
    });
    assert.deepEqual(result, { outcome: "observed", status: 200, matched: true });
    assert.deepEqual(seen, [{
      schema: "auths.gateway-submit/1",
      proof_b64: "AQI",
      action_b64: "AwQ",
    }]);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
});

test("gateway endpoint refuses provider URLs and client refuses empty actions", async () => {
  assert.throws(() => new GatewayEndpoint("https://api.example.com"), TypeError);
  const client = new GatewayClient(new GatewayEndpoint("/tmp/auths-test.sock"));
  await assert.rejects(
    client.submit({ proof: new Uint8Array([1]), action: new Uint8Array() }),
    TypeError,
  );
});

async function replyOnce(reply) {
  const directory = await mkdtemp(join(tmpdir(), "auths-gateway-"));
  const path = join(directory, "app.sock");
  const server = createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 4 || bytes.length < bytes.readUInt32BE(0) + 4) return;
      const body = Buffer.from(reply);
      const frame = Buffer.alloc(4 + body.length);
      frame.writeUInt32BE(body.length, 0);
      body.copy(frame, 4);
      socket.end(frame);
    });
  });
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    return await new GatewayClient(new GatewayEndpoint(path)).submit({
      proof: new Uint8Array([1]),
      action: new Uint8Array([2]),
    });
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

const ECHO = `auths-e1-${"ab".repeat(32)}`;
const DIGEST = "cd".repeat(32);

function providerResult(status = 200, evidence = {}) {
  return JSON.stringify({
    outcome: "observed-by-provider",
    status,
    evidence: { channel: "read-back", echo: ECHO, evidence_digest: DIGEST, observed_at: 1790000000, ...evidence },
  });
}

test("gateway client exposes observed-by-provider without evidence bytes", { skip: process.platform === "win32" }, async () => {
  const evidence = { channel: "read-back", echo: ECHO, evidenceDigest: DIGEST, observedAt: 1790000000 };
  assert.deepEqual(await replyOnce(providerResult()), { outcome: "observed-by-provider", status: 200, evidence });
  assert.deepEqual(await replyOnce(providerResult(null)), { outcome: "observed-by-provider", status: null, evidence });
  for (const hostile of [
    providerResult(99),
    providerResult("200"),
    providerResult(200, { channel: "webhook" }),
    providerResult(200, { echo: "auths-e1-app-supplied" }),
    providerResult(200, { echo: ECHO.toUpperCase() }),
    providerResult(200, { evidence_digest: "00" }),
    providerResult(200, { observed_at: -1 }),
    providerResult(200, { evidence_b64: "e30" }),
    '{"outcome":"observed-by-provider","status":200}',
    '{"outcome":"observed-by-provider","status":200,"evidence":[]}',
  ]) {
    await assert.rejects(replyOnce(hostile), GatewayProtocolError);
  }
});

const MEDIA_TYPE = "application/vnd.auths.observation.v1+cbor";
const OBSERVATION = new Uint8Array(512).map((_, index) => index % 256);
const SUBJECT = "https://api.airtable.com/v0/app/tbl/rec#/fields/DemoStatus";

function signed(overrides = {}) {
  return JSON.stringify({
    outcome: "signed",
    schema: "auths.gateway-readback/1",
    subject: SUBJECT,
    observed_at: 1790000000,
    media_type: MEDIA_TYPE,
    observation_b64: Buffer.from(OBSERVATION).toString("base64url"),
    ...overrides,
  });
}

async function observeOnce(reply, request) {
  const directory = await mkdtemp(join(tmpdir(), "auths-gateway-"));
  const path = join(directory, "app.sock");
  const seen = [];
  const server = createServer((socket) => {
    let bytes = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      if (bytes.length < 4 || bytes.length < bytes.readUInt32BE(0) + 4) return;
      seen.push(JSON.parse(bytes.subarray(4, bytes.readUInt32BE(0) + 4).toString("utf8")));
      const body = Buffer.from(reply);
      const frame = Buffer.alloc(4 + body.length);
      frame.writeUInt32BE(body.length, 0);
      body.copy(frame, 4);
      socket.end(frame);
    });
  });
  try {
    await new Promise((resolve) => server.listen(path, resolve));
    const result = await request(new GatewayClient(new GatewayEndpoint(path)));
    return { result, seen };
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

const readBack = (client) => client.observeReadBack({ record_id: "recTEST0000000001" });
const outcome = (client) => client.observeOutcome("step-1");

test("gateway client requests a read-back and returns the signed observation bytes", { skip: process.platform === "win32" }, async () => {
  const { result, seen } = await observeOnce(signed(), readBack);
  assert.deepEqual(result, {
    outcome: "signed",
    schema: "auths.gateway-readback/1",
    subject: SUBJECT,
    observedAt: 1790000000,
    mediaType: MEDIA_TYPE,
    observation: OBSERVATION,
  });
  assert.deepEqual(seen, [{
    schema: "auths.gateway-observe/1",
    request: { kind: "read-back", arguments: { record_id: "recTEST0000000001" } },
  }]);
});

test("gateway client requests an outcome and surfaces a refusal as a result", { skip: process.platform === "win32" }, async () => {
  const subject = "auths-gateway://ns/operations/step-1";
  const signedOutcome = await observeOnce(signed({ schema: "auths.gateway-outcome/1", subject }), outcome);
  assert.equal(signedOutcome.result.outcome, "signed");
  assert.equal(signedOutcome.result.schema, "auths.gateway-outcome/1");
  assert.equal(signedOutcome.result.subject, subject);
  assert.deepEqual(signedOutcome.result.observation, OBSERVATION);
  assert.deepEqual(signedOutcome.seen, [{
    schema: "auths.gateway-observe/1",
    request: { kind: "outcome", operation_id: "step-1" },
  }]);
  const refused = await observeOnce('{"outcome":"refused","code":"gateway.observer.not-provisioned"}', outcome);
  assert.deepEqual(refused.result, { outcome: "refused", code: "gateway.observer.not-provisioned" });
});

test("gateway client rejects malformed observation frames", { skip: process.platform === "win32" }, async () => {
  // A signed read-back is not accepted as the answer to an outcome request.
  await assert.rejects(observeOnce(signed(), outcome), GatewayProtocolError);
  for (const hostile of [
    signed({ schema: "auths.gateway-outcome/1" }),
    signed({ media_type: "application/cbor" }),
    signed({ subject: "" }),
    signed({ subject: "s".repeat(1025) }),
    signed({ observed_at: -1 }),
    signed({ observed_at: 1.5 }),
    signed({ observed_at: "1790000000" }),
    signed({ observation_b64: "" }),
    signed({ observation_b64: `${Buffer.from(OBSERVATION).toString("base64url")}=` }),
    signed({ observation_b64: "+/8=" }),
    signed({ observation_b64: "AB" }),
    signed({ observation_b64: "A" }),
    signed({ observation_b64: "QUJD RA" }),
    signed({ observation_b64: Buffer.alloc(4097, 1).toString("base64url") }),
    signed({ confirmed: true }),
    signed({ observation: "AAAA" }),
    '{"outcome":"refused"}',
    '{"outcome":"refused","code":""}',
    '{"outcome":"refused","code":"x","reason":"y"}',
    '{"outcome":"observed","status":200,"matched":true}',
    '{"outcome":"signed"}',
    "[]",
    "not json",
  ]) {
    await assert.rejects(observeOnce(hostile, readBack), GatewayProtocolError, hostile.slice(0, 80));
  }
});

test("gateway client refuses unbounded observation requests before connecting", async () => {
  const client = new GatewayClient(new GatewayEndpoint("/tmp/auths-test.sock"));
  for (const argumentsMap of [
    {},
    [],
    null,
    { record_id: "" },
    { record_id: "x".repeat(129) },
    { record_id: "a\0b" },
    { record_id: 7 },
    { "-record": "rec1" },
    Object.fromEntries(Array.from({ length: 17 }, (_, index) => [`field${index}`, "v"])),
  ]) {
    await assert.rejects(client.observeReadBack(argumentsMap), TypeError);
  }
  for (const operation of ["", "-step", "step 1", "s".repeat(129), "stép", 7]) {
    await assert.rejects(client.observeOutcome(operation), TypeError);
  }
});
