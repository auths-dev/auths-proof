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
  path.join(root, "core/fixtures/v1/valid/raw-key-chain.proof.cbor"),
);
const action = fs.readFileSync(
  path.join(root, "core/fixtures/v1/valid/raw-key-chain.action.cbor"),
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

// ---------------------------------------------------------------------------
// The declared ABI is the whole ABI.
//
// Every symbol this module publishes to JavaScript is declared by exactly one
// manifest, and every declaration is published. Without this, a symbol can be
// added or a manifest can rot and nothing notices.
// ---------------------------------------------------------------------------

const manifestDirectory = path.resolve(__dirname, "..");
const manifests = [
  "identity-abi-v1.json",
  "authoring-abi-v1.json",
  "product-abi-v1.json",
].map((name) => ({
  name,
  value: JSON.parse(fs.readFileSync(path.join(manifestDirectory, name), "utf8")),
}));

const declaredBy = new Map();
for (const { name, value } of manifests) {
  for (const symbol of [...value.exports, ...value.types]) {
    const previous = declaredBy.get(symbol);
    if (previous !== undefined) {
      throw new Error(`${symbol} is declared by both ${previous} and ${name}`);
    }
    declaredBy.set(symbol, name);
  }
}

const published = new Set(Object.keys(wasm));
const undeclared = [...published].filter((symbol) => !declaredBy.has(symbol)).sort();
const unpublished = [...declaredBy.keys()].filter((symbol) => !published.has(symbol)).sort();
if (undeclared.length > 0 || unpublished.length > 0) {
  throw new Error(
    "the WASM ABI manifests and the published module disagree\n" +
      `  exported but undeclared: ${JSON.stringify(undeclared)}\n` +
      `  declared but not exported: ${JSON.stringify(unpublished)}`,
  );
}

// Generic reference machinery must not come back through a later edit.
const removed = manifests
  .flatMap(({ value }) => value.removedInV1?.exports ?? []);
if (removed.length === 0) {
  throw new Error("no manifest records the removed generic reference exports");
}
for (const symbol of removed) {
  if (published.has(symbol) || declarations.includes(symbol)) {
    throw new Error(
      `${symbol} is generic reference machinery removed from the consumer package; ` +
        "it must not be re-exported. See docs/target-state/PRELAUNCH_CODEBASE_CONSOLIDATION_SPEC.md.",
    );
  }
}

// ---------------------------------------------------------------------------
// The boundary carries meaning.
//
// A failure crossing the WASM boundary must arrive as a structured Auths error
// carrying a stable registry code, the effect state, the retry class, and the
// recommended action. A bare string destroys all four.
// ---------------------------------------------------------------------------

const registry = JSON.parse(
  fs.readFileSync(path.join(root, "product/errors/v1/registry.json"), "utf8"),
);
const registered = new Set(registry.definitions.map((definition) => definition.code));
const EFFECT_STATES = ["not-applied", "possible", "applied"];

const probes = [
  ["decodePublicIdentityV2", () => wasm.decodePublicIdentityV2(new Uint8Array([0xff, 0xff, 0xff]))],
  ["decodeSignedIdentityMessageV2", () => wasm.decodeSignedIdentityMessageV2(new Uint8Array([1, 2, 3]))],
  ["canonicalPrincipalV1", () => wasm.canonicalPrincipalV1("!!!")],
  ["decodeProductionResponseV1", () => wasm.decodeProductionResponseV1(new Uint8Array([0xff]))],
  ["parsePrincipalStatusSnapshotV1", () => wasm.parsePrincipalStatusSnapshotV1(null)],
];
for (const [name, probe] of probes) {
  let thrown;
  try {
    probe();
    throw new Error(`${name}: adversarial input did not fail; the probe proves nothing`);
  } catch (error) {
    thrown = error;
  }
  if (typeof thrown === "string") {
    throw new Error(`${name} threw the bare string ${JSON.stringify(thrown)}`);
  }
  if (!(thrown instanceof Error)) {
    throw new Error(`${name} threw a ${typeof thrown}, not an Error`);
  }
  if (thrown.schema !== "auths.error/1") {
    throw new Error(`${name} threw schema ${JSON.stringify(thrown.schema)}`);
  }
  if (!registered.has(thrown.code)) {
    throw new Error(
      `${name} reported code ${JSON.stringify(thrown.code)}, which is in no registry. ` +
        "Bindings mint no error codes.",
    );
  }
  if (!EFFECT_STATES.includes(thrown.effect)) {
    throw new Error(`${name} reported effect ${JSON.stringify(thrown.effect)}`);
  }
  for (const field of ["retry", "recommendedAction", "operation", "stage", "family", "summary"]) {
    if (typeof thrown[field] !== "string" || thrown[field].length === 0) {
      throw new Error(`${name} lost ${field} at the WASM boundary`);
    }
  }
  const owner = registry.definitions.find((definition) => definition.code === thrown.code);
  if (thrown.recommendedAction !== owner.recommendedAction) {
    throw new Error(
      `${name} reported recommendedAction ${JSON.stringify(thrown.recommendedAction)}; ` +
        `the registry says ${JSON.stringify(owner.recommendedAction)}`,
    );
  }
  if (!owner.outcomes.some((outcome) =>
    outcome.effect === thrown.effect && outcome.retry === thrown.retry)) {
    throw new Error(
      `${name} reported an outcome ${thrown.code} does not declare: ` +
        `${thrown.effect}/${thrown.retry}`,
    );
  }
}

// Rust owns the classification; this module projects it for all 48 codes.
for (const definition of registry.definitions) {
  const classification = wasm.classifyErrorCodeV1(definition.code);
  if (classification.known !== true) {
    throw new Error(`${definition.code} is in the registry but classified as unknown`);
  }
  if (classification.recommendedAction !== definition.recommendedAction) {
    throw new Error(`${definition.code} projected the wrong recommended action`);
  }
  if (!definition.outcomes.some((outcome) =>
    outcome.effect === classification.effect && outcome.retry === classification.retry)) {
    throw new Error(`${definition.code} projected an outcome it does not declare`);
  }
}

// The fail-closed rule: a code minted by a newer build is never swallowed and
// never downgraded to not-applied.
for (const unknownCode of ["future.not-yet-invented", "", "core.", "mcp.handler-failed-v2"]) {
  const classification = wasm.classifyErrorCodeV1(unknownCode);
  if (classification.known !== false) {
    throw new Error(`${JSON.stringify(unknownCode)} was reported as a known code`);
  }
  if (classification.effect !== "possible") {
    throw new Error(
      `an unrecognized code mapped to effect ${JSON.stringify(classification.effect)}; ` +
        "contract 4.1 requires 'possible'",
    );
  }
  if (classification.retry !== "unknown" ||
    classification.recommendedAction !== "resume-and-reconcile") {
    throw new Error("an unrecognized code must ask the caller to resume and reconcile");
  }
}
