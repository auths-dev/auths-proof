import assert from "node:assert/strict";
import test from "node:test";

import { ProviderOperationError } from "../../dist/custody.js";
import { custodyConformance } from "../../dist/testkit/index.js";

class ConformantSigner {
  kind = "conformance";
  lifecycle = "ephemeral";
  #disposed = false;
  #requests = new Set();
  #now;
  #principal = Object.freeze({
    principal: "did:key:zConformance",
    principalMethod: "did-key-v1",
    verificationMethod: "did:key:zConformance#key",
    suite: "ed25519-v1",
  });

  constructor(now) {
    this.#now = now;
  }

  async publicIdentity() {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
    return { ...this.#principal };
  }

  async sign(request) {
    if (this.#disposed) throw new ProviderOperationError("cancelled");
    if (request.signal?.aborted) throw new ProviderOperationError("cancelled");
    if (request.expiresAt < this.#now()) throw new ProviderOperationError("rejected");
    if (this.#requests.has(request.requestId)) throw new ProviderOperationError("rejected");
    if (
      request.principal.principal !== this.#principal.principal ||
      request.principal.principalMethod !== this.#principal.principalMethod ||
      request.principal.verificationMethod !== this.#principal.verificationMethod ||
      request.principal.suite !== this.#principal.suite
    ) throw new ProviderOperationError("rejected");
    this.#requests.add(request.requestId);
    return Object.freeze({
      requestId: request.requestId,
      principal: { ...request.principal },
      transactionDigest: request.transactionDigest.slice(),
      signature: new Uint8Array([1]),
    });
  }

  async dispose() {
    this.#disposed = true;
  }
}

test("custody conformance covers binding, expiry, duplicate, cancellation, and disposal", async () => {
  const now = () => 1_000n;
  const report = await custodyConformance({
    now,
    create: async () => new ConformantSigner(now),
  });
  assert.equal(report.passed, true);
  assert.equal(report.results.length, 8);
  assert.equal(report.results.every((result) => result.passed), true);
});
