import assert from "node:assert/strict";
import test from "node:test";

import { ProviderOperationError } from "../../dist/custody.js";
import { mcp } from "../../dist/mcp.js";
import {
  certifyAtomicStore,
  certifyByteTransport,
  certifyMcpProvider,
  certifySigner,
} from "../../dist/testkit/index.js";

const metadata = Object.freeze({ implementation: "test.candidate", version: "1" });

class ConformantSigner {
  kind = "conformance";
  lifecycle = "ephemeral";
  #closed = false;
  #requests = new Set();
  #principal = Object.freeze({
    principal: "did:key:zConformance",
    principalMethod: "did-key-v1",
    verificationMethod: "did:key:zConformance#key",
    suite: "ed25519-v1",
  });

  async publicIdentity() {
    if (this.#closed) throw new ProviderOperationError("cancelled");
    return this.#principal;
  }

  async sign(request) {
    if (this.#closed || request.signal?.aborted) throw new ProviderOperationError("cancelled");
    if (request.expiresAt < BigInt(Math.floor(Date.now() / 1000))) throw new ProviderOperationError("rejected");
    if (this.#requests.has(request.requestId)) throw new ProviderOperationError("rejected");
    this.#requests.add(request.requestId);
    return Object.freeze({
      requestId: request.requestId,
      principal: request.principal,
      transactionDigest: request.transactionDigest.slice(),
      signature: new Uint8Array([1]),
    });
  }

  async dispose() {
    this.#closed = true;
  }
}

class AtomicStore {
  #records = new Map();

  async reserve(record) {
    if (record.value.length > 262_144) throw new TypeError("bounded record");
    const current = this.#records.get(record.key);
    if (current === undefined) {
      this.#records.set(record.key, record.commitment.slice());
      return "acquired";
    }
    return equal(current, record.commitment) ? "exact-replay" : "conflict";
  }
}

class ByteTransport {
  #deliver;
  #closed = false;

  constructor(deliver) {
    this.#deliver = deliver;
  }

  async exchange(packet, { maximumBytes, signal }) {
    if (this.#closed || signal.aborted) throw new Error("closed");
    if (packet.length === 0 || packet.length > maximumBytes) throw new TypeError("bounded input");
    const result = new Uint8Array(await this.#deliver(packet.slice()));
    if (result.length === 0 || result.length > maximumBytes) throw new TypeError("bounded output");
    return result;
  }

  async close() {
    this.#closed = true;
  }
}

test("Auths-owned mechanism and MCP suites execute every catalog case", async () => {
  const signer = await certifySigner(() => new ConformantSigner(), metadata);
  const atomic = await certifyAtomicStore(() => new AtomicStore(), metadata);
  const transport = await certifyByteTransport((deliver) => new ByteTransport(deliver), metadata);
  const provider = await certifyMcpProvider((options) => mcp.developmentProvider(options), metadata);
  for (const report of [signer, atomic, transport, provider]) {
    assert.equal(report.passed, true, JSON.stringify(report.results));
    assert.equal(report.claim, "test-results-only-not-security-certification");
    assert.ok(report.results.every((result) => result.classification === "deterministic"));
  }
});

test("Auths-owned atomic cases detect a false reservation implementation", async () => {
  const report = await certifyAtomicStore(
    () => ({ async reserve() { return "acquired"; } }),
    metadata,
  );
  assert.equal(report.passed, false);
  assert.equal(report.results.find((result) => result.id === "atomic-store/exact-replay")?.passed, false);
  assert.equal(report.results.find((result) => result.id === "atomic-store/concurrent-single-winner")?.passed, false);
  const durability = await certifyAtomicStore(
    () => new AtomicStore(),
    { ...metadata, capabilities: ["durable-reopen"] },
  );
  assert.equal(
    durability.results.find((result) => result.id === "atomic-store/reopen-durability-claim")?.passed,
    false,
  );
});

test("Auths-owned cases detect binding, substitution, retry, and redaction faults", async () => {
  const binding = await certifySigner(
    () => ({
      kind: "broken",
      lifecycle: "ephemeral",
      async publicIdentity() {
        return {
          principal: "did:key:zBroken",
          principalMethod: "did-key-v1",
          verificationMethod: "did:key:zBroken#key",
          suite: "ed25519-v1",
        };
      },
      async sign(request) {
        return {
          requestId: "substituted",
          principal: request.principal,
          transactionDigest: request.transactionDigest,
          signature: new Uint8Array([1]),
        };
      },
      async dispose() {},
    }),
    metadata,
  );
  assert.equal(binding.results.find((result) => result.id === "signer/request-binding")?.passed, false);

  const substitution = await certifyByteTransport(
    () => new ByteTransport(async () => new Uint8Array([9])),
    metadata,
  );
  assert.equal(substitution.results.find((result) => result.id === "byte-transport/exact-bytes")?.passed, false);

  const retry = await certifyMcpProvider((options) => mcp.developmentProvider({
    ...options,
    tools: Object.fromEntries(Object.entries(options.tools).map(([name, handler]) => [name, async (...args) => {
      await handler(...args);
      return handler(...args);
    }])),
  }), metadata);
  assert.equal(retry.results.find((result) => result.id === "mcp/exact-call")?.passed, false);

  await assert.rejects(certifyAtomicStore(
    () => new AtomicStore(),
    { implementation: "secret\nmaterial", version: "1" },
  ));
});

function equal(left, right) {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
