import assert from "node:assert/strict";

function deferred() {
  let resolve;
  const promise = new Promise((yes) => { resolve = yes; });
  return { promise, resolve };
}

/** Shared by source and installed-package tests; no WASM fixture is required. */
export async function signingDeadlineContract(t, { SigningCoordinator }) {
  for (const completionTime of [200n, 201n]) {
    await t.test(`T1: signer completion at ${completionTime} owns deadline acceptance`, async () => {
      let now = 100n;
      let completions = 0;
      let freed = 0;
      const entered = deferred();
      const signed = deferred();
      const principal = { principal: "did:web:signing.example", principalMethod: "did-web-v1",
        verificationMethod: "did:web:signing.example#key", suite: "ed25519-v1" };
      const policy = { policyId: "deadline", evaluatorVersion: "1", configurationDigest: new Uint8Array(32).fill(1) };
      const options = {
        objectKind: "grant", unsignedObject: new Uint8Array([0xa0]), principal,
        expiresAt: 200n, display: [{ label: "Grant", value: "bounded" }],
        requiredApproval: policy,
        approval: {
          policy: { reference: policy, mode: "grant-only", maxUses: 1, expiresInSeconds: 100, requirements: [] },
          provider: { async approve(request) { return { ...request, decision: "approved" }; } },
        },
        signer: {
          async sign(request) { entered.resolve(request); return signed.promise; },
        },
      };
      const owner = new SigningCoordinator({
        prepare(objectKind) { return { objectKind, requestId: "owned-grant", objectId: new Uint8Array(32).fill(2),
          transactionDigest: new Uint8Array(32).fill(3), signingPreimage: new Uint8Array([4]),
          free() { freed++; } }; },
        complete() { completions++; return new Uint8Array([5]); },
      }, () => now);
      const pending = owner.execute(options);
      const request = await entered.promise;
      now = completionTime;
      // Roll the clock back from the first observed expiry before retrying.
      const outcome = completionTime > 200n
        ? assert.rejects(pending, (error) => error.code === "transaction-expired")
        : pending;
      signed.resolve({ requestId: request.requestId, principal: request.principal,
        transactionDigest: request.transactionDigest, signature: new Uint8Array(64).fill(6) });
      await outcome;
      assert.equal(completions, completionTime === 200n ? 1 : 0);
      assert.equal(freed, 1);
      now = 1n;
      await assert.rejects(owner.execute(options), (error) => error.code === "transaction-consumed");
      assert.equal(completions, completionTime === 200n ? 1 : 0);
    });
  }

  await t.test("T1: rollback during approval cannot lower the signer's retained clock", async () => {
    const samples = [100n, 199n, 50n, 201n];
    let completed = false;
    const principal = { principal: "did:web:clock.example", principalMethod: "did-web-v1",
      verificationMethod: "did:web:clock.example#key", suite: "ed25519-v1" };
    const policy = { policyId: "clock", evaluatorVersion: "1", configurationDigest: new Uint8Array(32) };
    const owner = new SigningCoordinator({
      prepare(objectKind) { return { objectKind, requestId: "clock-grant", objectId: new Uint8Array(32),
        transactionDigest: new Uint8Array(32), signingPreimage: new Uint8Array([1]) }; },
      complete() { completed = true; return new Uint8Array([2]); },
    }, () => { assert.ok(samples.length); return samples.shift(); });
    await assert.rejects(owner.execute({
      objectKind: "grant", unsignedObject: new Uint8Array([0xa0]), principal, expiresAt: 200n,
      requiredApproval: policy, display: [],
      approval: { policy: { reference: policy, mode: "grant-only", maxUses: 1, expiresInSeconds: 100, requirements: [] },
        provider: { async approve(request) { return { ...request, decision: "approved" }; } } },
      signer: { async sign(request) { return { ...request, signature: new Uint8Array(64) }; } },
    }), (error) => error.code === "transaction-expired");
    assert.equal(samples.length, 0);
    assert.equal(completed, false);
  });
}
