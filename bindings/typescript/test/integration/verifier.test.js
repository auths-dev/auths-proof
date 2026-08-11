import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  Verifier,
  VerifiedAction,
  loadVerifier,
} from "../../dist/verify.js";
import { createDiagnosticVerifier } from "../../dist/diagnostics.js";

const fixture = (name) =>
  readFileSync(
    new URL(`../../../../core/fixtures/v1/valid/${name}`, import.meta.url),
  );
const bindingVector = (name) =>
  readFileSync(
    new URL(`../../../../target/binding-vectors/${name}`, import.meta.url),
  );

test("authorized results expose only a sealed verified action", async () => {
  const auths = await loadVerifier();
  const action = fixture("raw-key-chain.action.cbor");
  const result = auths.verify(
    fixture("raw-key-chain.proof.cbor"),
    action,
    bindingVector("authorized.context.cbor"),
  );
  assert.equal(result.kind, "authorized");
  assert.equal(result.code, "authorized");
  assert.equal(result.requiredConfiguration.length, 32);
  assert.equal(result.localConfiguration.length, 32);
  assert.deepEqual(result.requiredConfiguration, result.localConfiguration);
  assert.deepEqual(Buffer.from(result.action.canonicalBytes()), action);
});

test("application code cannot construct a verified action", () => {
  assert.throws(() => new VerifiedAction(Symbol(), new Uint8Array()), /sealed/);
});

test("application code cannot construct a capability-minting verifier", () => {
  assert.throws(() => new Verifier({ verifyV1: () => new Uint8Array() }), /sealed/);
  assert.throws(() => new Verifier(Symbol(), { verifyV1: () => new Uint8Array() }), /sealed/);
});

test("precompiled WASM matches the canonical Rust result", async () => {
  const auths = await loadVerifier();
  const result = auths.verify(
    fixture("raw-key-chain.proof.cbor"),
    fixture("raw-key-chain.action.cbor"),
    bindingVector("authorized.context.cbor"),
  );
  assert.equal(result.kind, "authorized");
  assert.deepEqual(result.requiredConfiguration, result.localConfiguration);
  assert.deepEqual(
    Buffer.from(result.resultCbor),
    bindingVector("authorized.result.cbor"),
  );
});

test("native batches are identical to independent verification and honor cancellation", async () => {
  const auths = await loadVerifier();
  const input = {
    proofCbor: fixture("raw-key-chain.proof.cbor"),
    canonicalActionCbor: fixture("raw-key-chain.action.cbor"),
    trustedContextCbor: bindingVector("authorized.context.cbor"),
  };
  const singles = [auths.verify(input.proofCbor, input.canonicalActionCbor, input.trustedContextCbor),
    auths.verify(input.proofCbor, input.canonicalActionCbor, input.trustedContextCbor)];
  const batch = await auths.verifyMany([input, input], { chunkSize: 1 });
  assert.deepEqual(batch.map((result) => result.resultCbor), singles.map((result) => result.resultCbor));
  assert.deepEqual(
    batch.map((result) => result.kind === "authorized" && result.action.canonicalBytes()),
    singles.map((result) => result.kind === "authorized" && result.action.canonicalBytes()),
  );
  await assert.rejects(() => auths.verifyMany([], {}), /between 1 and 256/);
  const cancelled = new AbortController();
  cancelled.abort();
  await assert.rejects(() => auths.verifyMany([input], { signal: cancelled.signal }), /aborted/i);
  await assert.rejects(() => auths.verifyMany([{
    proofCbor: new Uint8Array(16_777_217),
    canonicalActionCbor: new Uint8Array(),
    trustedContextCbor: new Uint8Array(),
  }]), /aggregate byte bound/);
});

test("package-owned portable loader accepts no injected module", async () => {
  assert.equal(loadVerifier.length, 0);
  const auths = await loadVerifier();
  const result = auths.verify(
    fixture("raw-key-chain.proof.cbor"),
    fixture("raw-key-chain.action.cbor"),
    bindingVector("authorized.context.cbor"),
  );
  assert.equal(result.kind, "authorized");
});

test("configuration mismatch reports required and executed commitments", async () => {
  const auths = await loadVerifier();
  const result = auths.verify(
    fixture("raw-key-chain.proof.cbor"),
    fixture("raw-key-chain.action.cbor"),
    fixture("raw-key-chain.context.cbor"),
  );
  assert.equal(result.kind, "denied");
  assert.equal(result.code, "verifier-configuration-mismatch");
  assert.equal(result.requiredConfiguration.length, 32);
  assert.equal(result.localConfiguration.length, 32);
  assert.notDeepEqual(result.requiredConfiguration, result.localConfiguration);
  assert.equal("action" in result, false);
});

test("portable decoder rejects shape version and trailing data", () => {
  const canonical = fixture("raw-key-chain.result.cbor");
  assert.equal(canonical[0], 0xb0);
  assert.deepEqual(canonical.subarray(-2), Buffer.from([0x0f, 0x02]));
  const action = fixture("raw-key-chain.action.cbor");
  const verifying = (bytes) => () =>
    createDiagnosticVerifier({ verifyV1: () => bytes }).verify(
      new Uint8Array([1]),
      action,
      new Uint8Array([2]),
    );

  assert.throws(verifying(Buffer.concat([canonical, Buffer.from([0x00])])), /trailing/);

  assert.throws(
    verifying(Buffer.concat([
      Buffer.from([0xb0, 0x01, 0x04, 0x00, 0x00]),
      canonical.subarray(5),
    ])),
    /canonical/,
  );

  assert.throws(
    verifying(Buffer.concat([
      Buffer.from([0xb1]),
      canonical.subarray(1),
      Buffer.from([0x10, 0xf6]),
    ])),
    /shape/,
  );

  assert.throws(
    verifying(Buffer.concat([canonical.subarray(0, -1), Buffer.from([0x03])])),
    /ABI version/,
  );
});
