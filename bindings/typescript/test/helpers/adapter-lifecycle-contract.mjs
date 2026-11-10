import assert from "node:assert/strict";
import { deferred } from "./resource-lifecycle-contract.mjs";

export async function adapterLifecycleContract(t, { connectRemoteVerifier, createIdentityClient }) {
  const factories = {
    remote: async (adapters, owned) => connectRemoteVerifier({ endpoint: "https://verification.auths.example", transport: adapters[0], transportOwnership: owned ? "owned" : "borrowed" }),
    identity: async (adapters, owned) => createIdentityClient({ methods: [adapters[0]], authenticators: [adapters[1]], adapterOwnership: owned ? "owned" : "borrowed" }),
  };
  for (const [name, create] of Object.entries(factories)) {
    for (const owned of [true, false]) await t.test(`C4/C7: ${name} ${owned ? "owned" : "borrowed"} adapters obey cleanup ownership`, async () => {
      const counts = [0, 0]; const adapters = counts.map((_, index) => ({
        contract: "bounded-byte-transport/2", id: "test-method", suiteId: "test-suite", version: 1,
        cleanupRetry: "idempotent", async send() { throw new Error("unused"); },
        async resolve() { throw new Error("unused"); }, async validate() { throw new Error("unused"); }, async verify() { throw new Error("unused"); },
        async close() { counts[index]++; if (index === 0 && counts[index] === 1) throw new Error("private provider failure"); },
        async [Symbol.asyncDispose]() { await this.close(); },
      }));
      const client = await create(adapters, owned);
      if (owned) {
        await assert.rejects(client.close(), (error) => error.code === "signer-failed");
        await assert.rejects(client.close(), (error) => error.code === "signer-failed");
        assert.equal(counts[0], 1);
        if (name === "identity") assert.equal(counts[1], 1);
        await client.retryCleanup(); await client.close();
        assert.equal(counts[0], 2);
        if (name === "identity") assert.equal(counts[1], 1);
      } else {
        await client.close(); await client.retryCleanup(); assert.deepEqual(counts, [0, 0]);
      }
    });
  }
  await t.test("C2/C7: remote close retains an owned transport until its send settles", async () => {
    const entered = deferred(), returned = deferred(); let closes = 0;
    const client = await connectRemoteVerifier({ endpoint: "https://verification.auths.example", transportOwnership: "owned", transport: {
      contract: "bounded-byte-transport/2", async send() { entered.resolve(); return returned.promise; },
      async close() { closes++; }, async [Symbol.asyncDispose]() { await this.close(); },
    } });
    const pending = client.verify({ proof: new Uint8Array([1]), action: new Uint8Array([2]), trustedContext: new Uint8Array([3]) });
    await entered.promise;
    const failed = assert.rejects(pending); const closing = client.close();
    assert.equal(closes, 0);
    returned.resolve({ status: 500, mediaType: "application/cbor", body: new Uint8Array() });
    await failed; await closing; assert.equal(closes, 1);
  });
}
