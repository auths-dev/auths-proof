"use strict";

const fs = require("node:fs");
const path = require("node:path");

const packageDirectory = process.argv[2];
if (!packageDirectory) {
  throw new Error("expected generated wasm package directory");
}
const wasm = require(path.join(packageDirectory, "auths_proof_wasm.js"));
const root = path.resolve(packageDirectory, "../..");
const proof = fs.readFileSync(
  path.join(root, "fixtures/v1/valid/raw-key-chain.proof.cbor"),
);
const action = fs.readFileSync(
  path.join(root, "fixtures/v1/valid/raw-key-chain.action.cbor"),
);
const context = fs.readFileSync(
  path.join(packageDirectory, "authorized.context.cbor"),
);
const expected = fs.readFileSync(
  path.join(packageDirectory, "authorized.result.cbor"),
);

const first = wasm.verifyV1(
  new Uint8Array(proof),
  new Uint8Array(action),
  new Uint8Array(context),
);
const second = wasm.verifyV1(
  new Uint8Array(proof),
  new Uint8Array(action),
  new Uint8Array(context),
);
if (!(first instanceof Uint8Array) || !Buffer.from(first).equals(expected)) {
  throw new Error("WASM result differs from native canonical result bytes");
}
if (!Buffer.from(first).equals(Buffer.from(second))) {
  throw new Error("WASM verification is not byte deterministic");
}
if (wasm.configurationV1().length !== 32) {
  throw new Error("WASM configuration commitment must be 32 bytes");
}
const malformed = wasm.verifyV1(
  new Uint8Array([0xff]),
  new Uint8Array([0xff]),
  new Uint8Array([0xff]),
);
if (!(malformed instanceof Uint8Array) || malformed.length === 0) {
  throw new Error("protocol failures must be result bytes, not exceptions");
}
const declarations = fs.readFileSync(
  path.join(packageDirectory, "auths_proof_wasm.d.ts"),
  "utf8",
);
for (const exported of ["verifyV1", "configurationV1"]) {
  if (!declarations.includes(exported)) {
    throw new Error(`generated TypeScript declarations omit ${exported}`);
  }
}
