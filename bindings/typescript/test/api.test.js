import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import { Auths, VerifiedAction, loadAuths } from "../dist/index.js";

const fixture = (name) =>
  readFileSync(
    new URL(`../../../core/fixtures/v1/valid/${name}`, import.meta.url),
  );

test("authorized results expose only a sealed verified action", () => {
  const expected = fixture("raw-key-chain.result.cbor");
  const engine = new Auths({ verifyV1: () => expected });
  const action = fixture("raw-key-chain.action.cbor");
  const result = engine.verify(new Uint8Array([1]), action, new Uint8Array([2]));
  assert.equal(result.kind, "authorized");
  assert.equal(result.code, "authorized");
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
    fixture("raw-key-chain.context.cbor"),
  );
  assert.equal(result.kind, "authorized");
  assert.deepEqual(
    Buffer.from(result.resultCbor),
    fixture("raw-key-chain.result.cbor"),
  );
});
