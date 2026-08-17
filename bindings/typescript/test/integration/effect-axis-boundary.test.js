/**
 * WAVE ACCEPTANCE TEST — the effect axis must survive every boundary.
 *
 * This file is the specification for the Transport and Surface lanes. It is
 * EXPECTED TO BE RED until they land. Every failure here is a finding, not a
 * flake, and none of these assertions may be weakened to make the suite green.
 *
 * Property under test (contract 4.1, 5.1, 5.2, 5.4, 5.5, 5.6):
 *
 *   Rust classifies each of the 48 registry codes with an effect —
 *   not-applied | possible | applied. `possible` means WE DO NOT KNOW whether
 *   the real-world effect happened. A caller who reads `not-applied` when the
 *   truth is `possible` will blindly retry and may repeat a payment or a
 *   database write. That distinction must arrive intact at the public
 *   TypeScript API, together with the stable code identity, the retry class,
 *   and the recommended action.
 *
 * Every value read here is read the way a REAL CALLER reads it: through a
 * subpath declared in bindings/public-topology-v1.json and published in
 * package.json "exports". No test in this file may import an internal module.
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const RED = "EFFECT-AXIS ACCEPTANCE (expected red until the Transport and Surface lanes land)";

const repoRoot = new URL("../../../../", import.meta.url);
const packageRoot = new URL("../../", import.meta.url);

const readJson = async (url) => JSON.parse(await readFile(url, "utf8"));

/** The Rust-owned registry. Nothing in this file hardcodes a count or a code. */
const registry = await readJson(new URL("product/errors/v1/registry.json", repoRoot));
/** Rust-minted `auths.error/1` envelopes, one per code, produced by `ErrorEnvelope::parse`. */
const fixtures = await readJson(new URL("product/fixtures/v1/errors/manifest.json", repoRoot));
const topology = await readJson(new URL("bindings/public-topology-v1.json", repoRoot));
const manifest = await readJson(new URL("package.json", packageRoot));

const definitions = registry.definitions;
const byCode = new Map(definitions.map((definition) => [definition.code, definition]));
const envelopeFor = new Map(fixtures.fixtures.map((fixture) => [fixture.code, fixture]));

/** Derived, never assumed. */
const RUST_EFFECT_STATES = Object.freeze(["not-applied", "possible", "applied"]);
const codesWithEffect = (effect) =>
  definitions
    .filter((definition) => definition.outcomes.some((outcome) => outcome.effect === effect))
    .map((definition) => definition.code)
    .sort();
const POSSIBLE_CODES = codesWithEffect("possible");
const APPLIED_CODES = codesWithEffect("applied");

/**
 * Resolves a published subpath to its built module, proving the import is one
 * a real consumer can write. A subpath that is not in "exports" is not public.
 */
const exportKey = (subpath) =>
  subpath === manifest.name ? "." : `.${subpath.slice(manifest.name.length)}`;

const importPublic = async (subpath) => {
  const entry = manifest.exports[exportKey(subpath)];
  assert.ok(entry, `${subpath} is not a published entry point of ${manifest.name}`);
  return import(new URL(entry.import, packageRoot).href);
};

// ---------------------------------------------------------------------------
// Anti-vacuity guards. A check that iterates an empty set cannot fail.
// ---------------------------------------------------------------------------

test("EA-0 the registry, its fixtures, and the declared topology are all non-empty and aligned", () => {
  assert.equal(registry.schema, "auths.error-registry/1");
  assert.ok(definitions.length > 0, "registry has no definitions; every per-code test below would be vacuous");
  assert.equal(envelopeFor.size, definitions.length,
    "the Rust-minted fixture corpus does not cover every registry code");
  assert.ok(POSSIBLE_CODES.length > 0,
    "no code carries effect 'possible'; the safety-critical case would be untested");
  assert.ok(APPLIED_CODES.length > 0,
    "no code carries effect 'applied'; that arm of the axis would be untested");
  for (const definition of definitions) {
    for (const outcome of definition.outcomes) {
      assert.ok(RUST_EFFECT_STATES.includes(outcome.effect),
        `${definition.code} declares effect '${outcome.effect}', outside the Rust-owned set`);
    }
  }
  const declared = topology.layers.flatMap((layer) => layer.typescript);
  assert.ok(declared.length > 0, "public topology declares no TypeScript entry points");
  for (const subpath of declared) {
    assert.ok(manifest.exports[exportKey(subpath)],
      `${subpath} is declared in public-topology-v1.json but is not published in package.json exports`);
  }
});

// ---------------------------------------------------------------------------
// EA-1  Surface: every registry code reaches a public caller with all four
//       fields of its recovery contract.
// ---------------------------------------------------------------------------

test("EA-1 every registry code reaches a public TypeScript caller with code, effect, retry, and action", async () => {
  const sdk = await importPublic("@auths-dev/sdk");
  assert.ok(sdk.AuthsError, `${RED}: the product root publishes no AuthsError`);
  const lost = [];
  for (const definition of definitions) {
    const envelope = envelopeFor.get(definition.code);
    const outcome = definition.outcomes[0];
    let error;
    try {
      error = sdk.AuthsError.parse(envelope);
    } catch (cause) {
      lost.push(`${definition.code}: public root refused the Rust-minted envelope (${cause})`);
      continue;
    }
    if (error.code !== definition.code) lost.push(`${definition.code}: code identity became ${error.code}`);
    if (error.effect !== outcome.effect) lost.push(`${definition.code}: effect became ${error.effect}, Rust says ${outcome.effect}`);
    if (error.retry !== outcome.retry) lost.push(`${definition.code}: retry became ${error.retry}, Rust says ${outcome.retry}`);
    if (error.recommendedAction !== definition.recommendedAction) {
      lost.push(`${definition.code}: recommendedAction became ${error.recommendedAction}, Rust says ${definition.recommendedAction}`);
    }
    if (!RUST_EFFECT_STATES.includes(error.effect)) {
      lost.push(`${definition.code}: effect '${error.effect}' is outside the three Rust-owned states`);
    }
  }
  assert.deepEqual(lost, [], `${RED}\n${lost.join("\n")}`);
});

// ---------------------------------------------------------------------------
// EA-2  Fail-closed: an unrecognized code must become `possible`, never a
//       fourth value and never `not-applied` (contract 4.1).
// ---------------------------------------------------------------------------

test("EA-2 an unregistered code fails closed to effect 'possible' at the public TypeScript surface", async () => {
  const sdk = await importPublic("@auths-dev/sdk");
  const template = envelopeFor.get(POSSIBLE_CODES[0]);
  const future = "mcp.code-minted-by-a-newer-rust";
  assert.equal(byCode.has(future), false, "the unknown-code probe accidentally uses a registered code");
  const error = sdk.AuthsError.parse({ ...template, code: future });
  assert.equal(error.code, future, `${RED}: an unknown code lost its identity at the public surface`);
  assert.equal(error.effect, "possible",
    `${RED}: an unknown code mapped to effect '${error.effect}'. Contract 4.1 requires 'possible'. ` +
    `A newer Rust code must never be silently swallowed or downgraded by an older binding.`);
  assert.ok(RUST_EFFECT_STATES.includes(error.effect),
    `${RED}: '${error.effect}' is a fourth effect state. There are exactly three.`);
});

test("EA-2b the public TypeScript surface admits no effect value outside the three Rust-owned states", async () => {
  const sdk = await importPublic("@auths-dev/sdk");
  const observed = new Set();
  for (const definition of definitions) {
    observed.add(sdk.AuthsError.parse(envelopeFor.get(definition.code)).effect);
  }
  observed.add(sdk.AuthsError.parse({
    ...envelopeFor.get(POSSIBLE_CODES[0]),
    code: "plan.code-minted-by-a-newer-rust",
  }).effect);
  const extra = [...observed].filter((value) => !RUST_EFFECT_STATES.includes(value)).sort();
  assert.deepEqual(extra, [],
    `${RED}: the public surface produced effect value(s) ${JSON.stringify(extra)} outside ` +
    `${JSON.stringify(RUST_EFFECT_STATES)}. EffectState has exactly three members.`);
});

// ---------------------------------------------------------------------------
// EA-3  Transport: Rust -> WASM -> TypeScript. An error crossing the WASM
//       boundary must arrive as a structured envelope, not a flattened string
//       (contract 5.2; bindings/wasm/auths-proof-wasm/src/lib.rs:4928).
// ---------------------------------------------------------------------------

test("EA-3 an error crossing the WASM boundary arrives structured, not flattened to a string", async () => {
  const identity = await importPublic("@auths-dev/sdk/identity");
  const sdk = await importPublic("@auths-dev/sdk");
  const client = await identity.loadIdentity();
  let thrown;
  let threw = false;
  try {
    client.decodePublicIdentity(new Uint8Array([0xff, 0xff, 0xff]));
  } catch (error) {
    threw = true;
    thrown = error;
  }
  assert.ok(threw, "the WASM boundary probe did not fail; pick adversarial input that does");
  assert.notEqual(typeof thrown, "string",
    `${RED}: the WASM boundary threw a bare JavaScript string ${JSON.stringify(String(thrown))}. ` +
    `js_error at bindings/wasm/auths-proof-wasm/src/lib.rs:4928 flattens every error to ` +
    `JsValue::from_str, destroying code identity, effect state, retry class, and recommended action.`);
  assert.ok(thrown instanceof Error, `${RED}: the WASM boundary threw a non-Error value`);
  assert.ok(sdk.AuthsError && thrown instanceof sdk.AuthsError,
    `${RED}: the WASM boundary threw ${thrown?.constructor?.name}, not the public AuthsError`);
  assert.ok(byCode.has(thrown.code),
    `${RED}: the WASM boundary reported code ${JSON.stringify(thrown.code)}, which is not in the registry`);
  assert.ok(RUST_EFFECT_STATES.includes(thrown.effect),
    `${RED}: the WASM boundary reported effect ${JSON.stringify(thrown.effect)}`);
  assert.ok(typeof thrown.retry === "string", `${RED}: the WASM boundary reported no retry class`);
  assert.ok(typeof thrown.recommendedAction === "string",
    `${RED}: the WASM boundary reported no recommended action`);
});

test("EA-3b every WASM-boundary failure on a published entry point is a structured Auths error", async () => {
  const identity = await importPublic("@auths-dev/sdk/identity");
  const client = await identity.loadIdentity();
  const probes = [
    ["identity.decodePublicIdentity", () => client.decodePublicIdentity(new Uint8Array([0xff, 0xff, 0xff]))],
    ["identity.decodeSignedMessage", () => client.decodeSignedMessage(new Uint8Array([0x01, 0x02, 0x03]))],
  ];
  const flattened = [];
  for (const [name, probe] of probes) {
    try {
      probe();
      flattened.push(`${name}: adversarial input did not fail; the probe proves nothing`);
    } catch (error) {
      if (typeof error === "string") {
        flattened.push(`${name}: threw the bare string ${JSON.stringify(error)}`);
      } else if (!(error instanceof Error)) {
        flattened.push(`${name}: threw a ${typeof error}, not an Error`);
      } else if (typeof error.code !== "string" || typeof error.effect !== "string") {
        flattened.push(`${name}: threw ${error.constructor.name} with code=${error.code} effect=${error.effect}`);
      }
    }
  }
  assert.deepEqual(flattened, [],
    `${RED}: the following published entry points lose the effect axis at the WASM boundary\n` +
    flattened.join("\n"));
});

// ---------------------------------------------------------------------------
// EA-4  The execution path. This is the safety-critical one: a real failed
//       execution, driven through published entry points, must tell the caller
//       whether the effect may have happened (contract 5.1).
// ---------------------------------------------------------------------------

const driveExecution = async (toolName, tools) => {
  const { development } = await importPublic("@auths-dev/sdk/integrations");
  const { mcp } = await importPublic("@auths-dev/sdk/profiles");
  const provider = mcp.developmentProvider({ tools });
  const auths = await development.createAuths({ authority: mcp.allowTools([toolName]) });
  try {
    return await auths.execute({
      action: mcp.callTool({ name: toolName, arguments: {} }),
      provider,
      requestId: `effect-axis-${toolName}-000001`,
    });
  } finally {
    await auths.close();
    await provider.close();
  }
};

test("EA-4 a provider failure tells the public caller the effect is 'possible'", async () => {
  const result = await driveExecution("boom", {
    async boom() { throw new Error("provider exploded after entry"); },
  });
  const shape = `${result.kind} { ${Object.keys(result).join(", ")} }`;
  assert.ok(typeof result.code === "string",
    `${RED}: a provider failure surfaced as ${shape} with no stable code identity. ` +
    `Rust classifies this as mcp.handler-failed, effect 'possible'.`);
  assert.ok(byCode.has(result.code),
    `${RED}: a provider failure surfaced code ${JSON.stringify(result.code)}, not in the registry`);
  assert.equal(result.effect, "possible",
    `${RED}: a provider failure surfaced as ${shape} with effect ${JSON.stringify(result.effect)}. ` +
    `The caller cannot tell that the real-world effect may have been applied, and may blindly retry.`);
  assert.equal(result.retry, "unknown", `${RED}: a possible-effect failure did not report retry 'unknown'`);
  assert.equal(result.recommendedAction, "resume-and-reconcile",
    `${RED}: a possible-effect failure did not recommend reconciliation`);
});

test("EA-4b two distinct registry codes do not collapse to one caller-visible shape", async () => {
  const failed = await driveExecution("boom", {
    async boom() { throw new Error("provider exploded after entry"); },
  });
  const invalidOutput = await driveExecution("oversized", {
    async oversized() { return { blob: "x".repeat(2 * 1024 * 1024) }; },
  });
  assert.notDeepEqual(
    { kind: failed.kind, code: failed.code },
    { kind: invalidOutput.kind, code: invalidOutput.code },
    `${RED}: a handler that threw and a handler that produced invalid output both surfaced as ` +
    `${failed.kind} with code ${JSON.stringify(failed.code)}. Rust distinguishes mcp.handler-failed ` +
    `from mcp.invalid-handler-output; the public path destroys that identity.`);
});

const driveDenial = async (requestId) => {
  const { development } = await importPublic("@auths-dev/sdk/integrations");
  const { mcp } = await importPublic("@auths-dev/sdk/profiles");
  const provider = mcp.developmentProvider({ tools: { async allowed() { return { ok: true }; } } });
  const auths = await development.createAuths({ authority: mcp.allowTools(["allowed"]) });
  try {
    return await auths.execute({
      action: mcp.callTool({ name: "forbidden", arguments: {} }),
      provider,
      requestId,
    });
  } finally {
    await auths.close();
    await provider.close();
  }
};

test("EA-4c a denial tells the public caller the effect is 'not-applied'", async () => {
  const denied = await driveDenial("effect-axis-denied-000001");
  assert.equal(denied.kind, "denied");
  assert.equal(denied.effect, "not-applied",
    `${RED}: a denial surfaced as ${denied.kind} { ${Object.keys(denied).join(", ")} } with effect ` +
    `${JSON.stringify(denied.effect)}. A caller cannot prove from the public result that nothing happened.`);
});

// ---------------------------------------------------------------------------
// EA-5  Inventory gate: bindings mint no error codes (contract 5.4). Rather
//       than listing the codes to check, fail when a code appears OUTSIDE the
//       registry, so the whole class cannot return.
// ---------------------------------------------------------------------------

test("EA-5 every code the public execution path emits originates in the Rust registry", async () => {
  const emitted = new Set();
  const record = (result) => {
    if (typeof result?.code === "string") emitted.add(result.code);
  };
  record(await driveExecution("boom", { async boom() { throw new Error("provider exploded"); } }));
  record(await driveDenial("effect-axis-inventory-000001"));
  assert.ok(emitted.size > 0, "no code was observed; this inventory gate would be vacuous");
  const unregistered = [...emitted].filter((code) => !byCode.has(code)).sort();
  assert.deepEqual(unregistered, [],
    `${RED}: the public execution path emitted code(s) ${JSON.stringify(unregistered)} that exist in no ` +
    `registry. All codes originate in product/errors/v1/registry.json (${definitions.length} today).`);
});

// ---------------------------------------------------------------------------
// EA-6  The reported inventory. Not an assertion about behaviour: this prints
//       the derived possible/applied sets so the transcript carries them.
// ---------------------------------------------------------------------------

test("EA-6 the derived effect inventory is reported", () => {
  const lines = [
    `registry: ${definitions.length} stable codes`,
    `effect 'possible' (${POSSIBLE_CODES.length}): ${POSSIBLE_CODES.join(", ")}`,
    `effect 'applied' (${APPLIED_CODES.length}): ${APPLIED_CODES.join(", ")}`,
  ];
  for (const line of lines) console.log(`# ${line}`);
  assert.equal(POSSIBLE_CODES.length + APPLIED_CODES.length +
    definitions.filter((d) => d.outcomes.every((o) => o.effect === "not-applied")).length,
    definitions.length, "the three effect partitions do not sum to the registry size");
});
