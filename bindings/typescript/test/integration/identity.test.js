import assert from "node:assert/strict";
import { generateKeyPairSync, sign, verify } from "node:crypto";
import { test } from "node:test";
import {
  loadEd25519RawKeyAuthentication,
  loadIdentity,
  loadRawKeyIdentityAdapter,
  IdentityMethodRegistry,
  SignatureSuiteRegistry,
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

test("resolver-backed general identities preserve state, purpose, and exact adapter selection", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const key = new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  const client = await loadIdentity();
  const unresolvedPacket = client.encodeDescriptor({
    methodId: "example-resolver-v1",
    identityId: "example:alice",
    methodMaterial: new TextEncoder().encode("https://identity.example/alice"),
    relationships: [],
  });
  const decoded = client.decodeDescriptor(unresolvedPacket);
  const method = {
    metadata: {
      methodId: "example-resolver-v1",
      version: "1",
      purposes: ["authentication"],
      lifecycle: "active",
    },
    async resolve(request) {
      assert.equal(request.maximumRedirects, 0);
      return {
        descriptor: {
          methodId: request.descriptor.methodId,
          identityId: request.descriptor.identityId,
          methodMaterial: request.descriptor.methodMaterial,
          relationships: [{
            relationshipId: "current-signing",
            purpose: "authentication",
            suiteId: "example-ed25519-v1",
            verificationMaterial: [{ materialId: "key-2026-08", bytes: key }],
          }],
        },
        evidence: {
          source: "https://identity.example/alice",
          fetchedAt: 100n,
          expiresAt: 200n,
          version: "etag-1",
        },
      };
    },
    parse(candidate) {
      assert.equal(candidate.resolution.source, "https://identity.example/alice");
      return candidate;
    },
  };
  const methods = new IdentityMethodRegistry([method]);
  const resolved = await client.resolveDescriptor(decoded, methods);
  const validated = client.validateDescriptor(resolved, methods);
  const message = new TextEncoder().encode("credential shape is adapter-owned");
  const preimage = client.descriptorSigningPreimage(validated, "current-signing", message);
  const signature = new Uint8Array(sign(null, preimage, privateKey));
  const suites = new SignatureSuiteRegistry([{
    metadata: {
      suiteId: "example-ed25519-v1",
      version: "1",
      purposes: ["authentication"],
      lifecycle: "active",
    },
    async authenticate(request) {
      assert.equal(request.relationship.verificationMaterial.length, 1);
      assert.equal(verify(null, request.signingPreimage, publicKey, request.signature), true);
      return {
        identityId: request.identity.identityId,
        relationshipId: request.relationship.relationshipId,
        message: request.message,
      };
    },
  }]);
  const authenticated = await client.authenticateDescriptor(validated, {
    relationshipId: "current-signing",
    message,
    signature,
    suites,
  });
  assert.equal(decoded.state, "decoded");
  assert.equal(resolved.state, "resolved");
  assert.equal(validated.state, "validated");
  assert.equal(authenticated.purpose, "authentication");
  assert.deepEqual(client.principal(validated), {
    method: "example-resolver-v1",
    principal: "example:alice",
    evidence: validated.packet,
  });

  assert.throws(() => new IdentityMethodRegistry([method, method]), /duplicate/);
  assert.throws(() => new SignatureSuiteRegistry([]).select("example-ed25519-v1"), /unsupported/);
  assert.throws(() => new IdentityMethodRegistry([{ ...method, metadata: {
    ...method.metadata,
    lifecycle: "deprecated",
  }}]).select("example-resolver-v1"), /deprecated/);
});

test("general descriptors encode rotating, threshold, and hybrid credential shapes", async () => {
  const client = await loadIdentity();
  const descriptor = {
    methodId: "example-composite-v1",
    identityId: "example:team",
    methodMaterial: new Uint8Array([2, 3]),
    relationships: [{
      relationshipId: "threshold-signing",
      purpose: "authentication",
      suiteId: "example-threshold-hybrid-v1",
      verificationMaterial: [
        { materialId: "ed25519-current", bytes: new Uint8Array(32).fill(1) },
        { materialId: "p256-current", bytes: new Uint8Array(65).fill(2) },
        { materialId: "pq-current", bytes: new Uint8Array(1_184).fill(3) },
      ],
    }],
  };
  const packet = client.encodeDescriptor(descriptor);
  const decoded = client.decodeDescriptor(packet);
  assert.deepEqual(decoded.relationships, descriptor.relationships);
  assert.throws(() => client.descriptorSigningPreimage(decoded, "old-signing", new Uint8Array([1])));
  const rotated = client.decodeDescriptor(client.encodeDescriptor({
    ...descriptor,
    relationships: [{
      ...descriptor.relationships[0],
      verificationMaterial: [{ materialId: "pq-next", bytes: new Uint8Array(1_184).fill(4) }],
    }],
  }));
  assert.equal(rotated.identityId, decoded.identityId);
  assert.notDeepEqual(rotated.packet, decoded.packet);
});
