import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { Auths, VerifiedAction, loadAuths } from "../dist/index.js";

const fixture = (name) =>
  readFileSync(
    new URL(`../../../core/fixtures/v1/valid/${name}`, import.meta.url),
  );
const bindingVector = (name) =>
  readFileSync(
    new URL(`../../../target/binding-vectors/${name}`, import.meta.url),
  );

test("authorized results expose only a sealed verified action", () => {
  const expected = fixture("raw-key-chain.result.cbor");
  const engine = new Auths({ verifyV1: () => expected });
  const action = fixture("raw-key-chain.action.cbor");
  const result = engine.verify(new Uint8Array([1]), action, new Uint8Array([2]));
  assert.equal(result.kind, "authorized");
  assert.equal(result.code, "authorized");
  assert.equal(result.requiredConfiguration.length, 32);
  assert.equal(result.localConfiguration.length, 32);
  assert.deepEqual(result.requiredConfiguration, result.localConfiguration);
  assert.deepEqual(result.action.canonicalBytes(), action);
});

test("application code cannot construct a verified action", () => {
  assert.throws(() => new VerifiedAction(Symbol(), new Uint8Array()), /sealed/);
});

test("precompiled WASM matches the canonical Rust result", async () => {
  const auths = await loadAuths({
    moduleUrl: new URL("../wasm/auths_proof_wasm.js", import.meta.url).href,
    wasmInput: readFileSync(
      new URL("../wasm/auths_proof_wasm_bg.wasm", import.meta.url),
    ),
  });
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

test("configuration mismatch reports required and executed commitments", async () => {
  const auths = await loadAuths({
    moduleUrl: new URL("../wasm/auths_proof_wasm.js", import.meta.url).href,
    wasmInput: readFileSync(
      new URL("../wasm/auths_proof_wasm_bg.wasm", import.meta.url),
    ),
  });
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
});

test("portable decoder rejects shape version and trailing data", () => {
  const canonical = fixture("raw-key-chain.result.cbor");
  assert.equal(canonical[0], 0xb0);
  assert.deepEqual(canonical.subarray(-2), Buffer.from([0x0f, 0x02]));
  const action = fixture("raw-key-chain.action.cbor");

  const trailing = new Auths({
    verifyV1: () => Buffer.concat([canonical, Buffer.from([0x00])]),
  });
  assert.throws(
    () => trailing.verify(new Uint8Array([1]), action, new Uint8Array([2])),
    /trailing/,
  );

  const reorderedKeys = Buffer.concat([
    Buffer.from([0xb0, 0x01, 0x04, 0x00, 0x00]),
    canonical.subarray(5),
  ]);
  const reordered = new Auths({ verifyV1: () => reorderedKeys });
  assert.throws(
    () => reordered.verify(new Uint8Array([1]), action, new Uint8Array([2])),
    /canonical/,
  );

  const unknownField = Buffer.concat([
    Buffer.from([0xb1]),
    canonical.subarray(1),
    Buffer.from([0x10, 0xf6]),
  ]);
  const unknown = new Auths({ verifyV1: () => unknownField });
  assert.throws(
    () => unknown.verify(new Uint8Array([1]), action, new Uint8Array([2])),
    /shape/,
  );

  const unsupportedAbi = Buffer.concat([
    canonical.subarray(0, -1),
    Buffer.from([0x03]),
  ]);
  const unsupported = new Auths({ verifyV1: () => unsupportedAbi });
  assert.throws(
    () => unsupported.verify(new Uint8Array([1]), action, new Uint8Array([2])),
    /ABI version/,
  );
});
