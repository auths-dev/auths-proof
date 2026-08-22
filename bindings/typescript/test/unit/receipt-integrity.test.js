import assert from "node:assert/strict";
import { test } from "node:test";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { ReceiptIntegrityError, connect } from "../../dist/index.js";
import { encodeDeterministic, decodeDeterministic } from "../../dist/internal/cbor.js";
import { PROFILE_CLIENT_RUNTIME, bindProfile } from "../../dist/profile-runtime.js";

const operation = "op_AAAAAAAAAAAAAAAAAAAAAA";
const digest = new Uint8Array(32).fill(9);
const descriptor = {
  profileClientRuntime: PROFILE_CLIENT_RUNTIME,
  profileId: "auths.example.double",
  version: 1,
  collectionRoute: "/v1/profiles/example/double/1/operations",
  runtimeContractDigest: Buffer.from(digest).toString("hex"),
  errorProjectionDigest: Buffer.from(digest).toString("hex"),
  preparationEvidence: null,
  requestBytes: 4096,
  responseBytes: 4096,
  executionMilliseconds: 30_000,
  receiptCount: 4,
  receiptBytes: 1024,
  profileApi: {
    schema: "auths.profile-api/1",
    types: {
      Input: {
        kind: "record",
        fields: [{ name: "value", value: { kind: "uint", minimum: "0", maximum: "100" }, sensitive: false }],
      },
      Result: {
        kind: "record",
        fields: [{ name: "doubled", value: { kind: "uint", minimum: "0", maximum: "200" }, sensitive: false }],
      },
    },
  },
  inputType: "Input",
  successType: "Result",
};

function issue(effect, provider, correlation = operation) {
  return encodeDeterministic(new Map([
    ["schema", "auths.error/1"], ["family", "internal"],
    ["code", "core.terminal-receipt-integrity-failed"], ["operation", "resume"],
    ["stage", "receipt"], ["summary", "the retained receipt failed integrity verification"],
    ["correlationId", correlation], ["retry", "never"], ["effect", effect],
    ["entered", new Map([["approval", true], ["signer", true], ["state", true], ["credential", provider], ["provider", provider]])],
    ["recommendedAction", "contact-support"], ["executionReference", operation],
    ["decisionReference", null], ["receiptReference", null], ["causes", ["corrupt-state"]],
  ]));
}

function integrityWire(state, effect, terminal, options = {}) {
  const provider = options.provider ?? (effect === "possible" || effect === "applied");
  return new Map([
    [1, 1], [2, "receipt-integrity-failed"], [3, new Uint8Array(16)], [4, operation],
    [5, issue(effect, provider, options.correlation)], [6, state], [7, effect],
    [8, terminal], [9, "primary"],
  ]);
}

async function withProfile(wire, action) {
  const directory = await mkdtemp(join(tmpdir(), "auths-integrity-"));
  const socketPath = join(directory, "agent.sock");
  const server = createServer((socket) => {
    let buffered = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffered = Buffer.concat([buffered, chunk]);
      const marker = buffered.indexOf("\r\n\r\n");
      if (marker < 0) return;
      const header = buffered.subarray(0, marker).toString("ascii");
      const contentLength = Number(/^Content-Length: (\d+)$/mi.exec(header)?.[1]);
      if (!Number.isSafeInteger(contentLength) || buffered.length !== marker + 4 + contentLength) return;
      const [method, path] = header.split("\r\n", 1)[0].split(" ");
      const request = contentLength === 0 ? null : decodeDeterministic(buffered.subarray(marker + 4));
      let response;
      if (method === "POST" && path === "/v1/session") {
        assert.ok(request instanceof Map);
        response = new Map([
          [1, 1], [2, request.get(2)], [3, "ses_AQEBAQEBAQEBAQEBAQEBAQ"], [4, "raw:test-agent"],
          [5, request.get(5)],
          [6, [new Map([[1, descriptor.profileId], [2, descriptor.version], [3, digest], [4, "auths.profile-operation/1"], [5, digest], [6, null], [7, new Map([[1, `qlf_${"A".repeat(43)}`], [2, "linux-x86_64"], [3, new Uint8Array(32).fill(4)]])]])]],
          [7, 16], [8, "full"],
        ]);
      } else if (method === "DELETE") {
        response = new Map([[1, 1]]);
      } else {
        assert.ok(request instanceof Map);
        response = new Map(wire);
        response.set(3, request.get(2));
      }
      const body = Buffer.from(encodeDeterministic(response));
      const responseHeader = Buffer.from(`HTTP/1.1 200 OK\r\nContent-Type: application/auths+cbor;version=1\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`, "ascii");
      socket.end(Buffer.concat([responseHeader, body]));
    });
  });
  try {
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, resolve);
    });
    await chmod(socketPath, 0o600);
    const client = await connect({ agentSocket: socketPath });
    try {
      await action(bindProfile(client, descriptor, "primary"));
    } finally {
      await client.close();
    }
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(directory, { recursive: true, force: true });
  }
}

test("receipt integrity outcomes preserve durable truth and mint sealed errors", async () => {
  for (const [state, effect, terminal] of [
    ["ready", "not-applied", false],
    ["recovery-required", "possible", false],
    ["completed", "applied", true],
    ["not-applied", "not-applied", true],
  ]) {
    await withProfile(integrityWire(state, effect, terminal), async (profile) => {
      const outcome = await profile.invokeOutcome({ value: 7 });
      assert.equal(outcome.kind, "receipt-integrity-failed");
      assert.equal(outcome.state, state);
      assert.equal(outcome.effect, effect);
      assert.equal(outcome.terminal, terminal);
      assert.deepEqual(outcome.receiptIds, []);
      await assert.rejects(
        profile.invoke({ value: 7 }),
        (error) => error instanceof ReceiptIntegrityError &&
          error.state === state && error.effect === effect &&
          error.terminal === terminal && error.receiptIds.length === 0,
      );
    });
  }
});

test("receipt integrity outcomes reject identity, boundary, and truth substitutions", async () => {
  for (const wire of [
    integrityWire("ready", "not-applied", true),
    integrityWire("completed", "applied", true, { correlation: "op_BBBBBBBBBBBBBBBBBBBBBB" }),
    integrityWire("recovery-required", "possible", false, { provider: false }),
  ]) {
    await withProfile(wire, async (profile) => {
      await assert.rejects(profile.invokeOutcome({ value: 7 }), TypeError);
    });
  }
});
