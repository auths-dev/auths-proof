import assert from "node:assert/strict";
import { test } from "node:test";
import { fixtures } from "../../dist/testkit/index.js";

test("development signer owns raw-key descriptor and signing details", async () => {
  const signer = await fixtures.ephemeralSigner();
  const principal = await signer.publicIdentity();
  assert.match(principal.principal, /^key:sha256:/);
  assert.equal(principal.principalMethod, "raw-key-v1");
  const response = await signer.sign({
    requestId: "action:test",
    objectKind: "action",
    objectId: new Uint8Array(32),
    principal,
    transactionDigest: new Uint8Array(32),
    signingPreimage: new Uint8Array([1, 2, 3]),
    expiresAt: 100n,
    display: [],
  });
  assert.equal(response.signature.length, 64);
  assert.equal(response.evidence?.[0]?.evidenceType, "raw-key-v1");
  await signer.dispose();
  await assert.rejects(() => signer.publicIdentity());
});
