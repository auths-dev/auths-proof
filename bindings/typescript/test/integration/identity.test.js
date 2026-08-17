import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
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
  const parsed = identity.parseIdentity(decoded, rawKey);
  assert.equal(decoded.validation, "decoded");
  assert.equal(parsed.identityId, validated.identityId);

  const message = new TextEncoder().encode("identity without authority");
  const preimage = identity.signingPreimage(validated, message);
  const signature = new Uint8Array(sign(null, preimage, privateKey));
  const signedPacket = identity.encodeSignedMessage(validated, message, signature);
  const decodedMessage = identity.decodeSignedMessage(signedPacket);
  const authenticated = identity.authenticate(decodedMessage, validated, ed25519);
  assert.deepEqual(authenticated.message, message);
  assert.equal(authenticated.identity.validation, "validated");

  const changed = signedPacket.slice();
  changed[changed.length - 1] ^= 1;
  const changedMessage = identity.decodeSignedMessage(changed);
  assert.throws(() => identity.authenticate(changedMessage, validated, ed25519));

  const mismatched = identity.encodePublicIdentity(
    validated.methodId,
    validated.identityId,
    validated.suiteId,
    Uint8Array.from({ length: 32 }, () => 9),
  );
  assert.throws(() => identity.parseIdentity(identity.decodePublicIdentity(mismatched), rawKey));
  assert.throws(() => identity.encodePublicIdentity(
    "method-v1",
    `example:${"x".repeat(600)}`,
    "suite-v1",
    subjectPublicKey,
  ));
  assert.throws(() => identity.signingPreimage(validated, new Uint8Array(65_537)));
});

test("caller-owned identity and signature adapters compose through typed parse ports", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const subjectPublicKey = new Uint8Array(
    publicKey.export({ type: "spki", format: "der" }).subarray(-32),
  );
  const identity = await loadIdentity();
  const packet = identity.encodePublicIdentity(
    "example-key-v1",
    "example:alice",
    "example-ed25519-v1",
    subjectPublicKey,
  );
  const decoded = identity.decodePublicIdentity(packet);
  const method = {
    methodId: "example-key-v1",
    parse(candidate) {
      if (candidate.identityId !== "example:alice" || candidate.publicKey.length !== 32) {
        throw new TypeError("invalid example identity");
      }
      return candidate;
    },
  };
  const validated = identity.parseIdentity(decoded, method);
  const message = new TextEncoder().encode("adapter-owned semantics");
  const preimage = identity.signingPreimage(validated, message);
  const signed = identity.encodeSignedMessage(
    validated,
    message,
    new Uint8Array(sign(null, preimage, privateKey)),
  );
  const suite = {
    suiteId: "example-ed25519-v1",
    parse(candidate) {
      const candidatePreimage = identity.signingPreimage(candidate.identity, candidate.message);
      if (!verify(null, candidatePreimage, publicKey, candidate.signature)) {
        throw new TypeError("invalid example signature");
      }
      return { identityId: candidate.identity.identityId, message: candidate.message };
    },
  };
  const authenticated = identity.authenticate(
    identity.decodeSignedMessage(signed),
    validated,
    suite,
  );
  assert.deepEqual(authenticated.message, message);
  assert.throws(() => identity.parseIdentity(decoded, { ...method, methodId: "other-v1" }));
  assert.throws(() => identity.authenticate(
    identity.decodeSignedMessage(signed),
    validated,
    { ...suite, suiteId: "other-v1" },
  ));
  assert.throws(() => identity.authenticate(
    identity.decodeSignedMessage(signed),
    validated,
    {
      ...suite,
      parse(candidate) {
        return { identityId: candidate.identity.identityId, message: new Uint8Array([0]) };
      },
    },
  ));
});


// CAPABILITY REMOVED (contract 6.2 / 11.6, ruling 10A): the identity DESCRIPTOR
// tier is deleted. Two tests lived here -- "resolver-backed general identities
// preserve state, purpose, and exact adapter selection" and "general descriptors
// encode rotating, threshold, and hybrid credential shapes" -- and both drove
// `client.encodeDescriptor` / `resolveDescriptor` / `validateDescriptor` /
// `authenticateDescriptor` with `IdentityMethodRegistry` and
// `SignatureSuiteRegistry`. That was a second, complete identity API alongside
// the packet tier above, with no counterpart in Python, so the "semantic parity
// across T3 languages" claim never covered it. The tests come back with the
// tier, in the same change that gives Python one.
test("the identity entry point publishes exactly one tier", async () => {
  const client = await loadIdentity();
  for (const removed of [
    "encodeDescriptor",
    "decodeDescriptor",
    "resolveDescriptor",
    "validateDescriptor",
    "descriptorSigningPreimage",
    "authenticateDescriptor",
  ]) {
    assert.equal(typeof client[removed], "undefined",
      `IdentityClient still publishes ${removed}, a second identity tier`);
  }
  const module = await import("../../dist/identity.js");
  for (const removed of ["IdentityMethodRegistry", "SignatureSuiteRegistry"]) {
    assert.equal(module[removed], undefined,
      `${removed} is still exported; it exists only to serve the deleted descriptor tier`);
  }
  // The packet tier is intact.
  assert.equal(typeof client.encodePublicIdentity, "function");
  assert.equal(typeof client.decodePublicIdentity, "function");
  assert.equal(typeof client.decodeSignedMessage, "function");
  assert.equal(typeof client.authenticate, "function");
});
