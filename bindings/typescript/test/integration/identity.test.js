import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { test } from "node:test";
import {
  loadEd25519RawKeyAuthentication,
  loadIdentity,
  loadRawKeyIdentityAdapter,
} from "../../dist/identity.js";

test("neutral identity surface keeps decode, validation, and authentication distinct", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const subjectPublicKey = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  const identity = await loadIdentity();
  const rawKey = await loadRawKeyIdentityAdapter();
  const ed25519 = await loadEd25519RawKeyAuthentication();

  const validated = rawKey.create("ed25519-v1", subjectPublicKey);
  assert.equal(validated.validation, "validated");
  const decoded = identity.decodePublicIdentity(validated.packet);
  assert.equal(decoded.validation, "decoded");
  assert.equal(decoded.identityId, validated.identityId);

  const message = new TextEncoder().encode("identity without authority");
  const preimage = identity.signingPreimage(validated, message);
  const signature = new Uint8Array(sign(null, preimage, privateKey));
  const signedPacket = identity.encodeSignedMessage(validated, message, signature);
  const authenticated = ed25519.verify(signedPacket);
  assert.deepEqual(authenticated.message, message);
  assert.equal(authenticated.identity.validation, "validated");

  const changed = signedPacket.slice();
  changed[changed.length - 1] ^= 1;
  assert.throws(() => ed25519.verify(changed));

  const mismatched = identity.encodePublicIdentity(
    validated.methodId,
    validated.identityId,
    validated.suiteId,
    Uint8Array.from({ length: 32 }, () => 9),
  );
  assert.throws(() => rawKey.validate(mismatched));
});
