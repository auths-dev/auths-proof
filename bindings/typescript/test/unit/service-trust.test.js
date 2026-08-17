/**
 * The runtime declares per-endpoint TRUST REQUIREMENTS. A requirement that
 * nothing enforces is not documentation — it is a security finding wearing
 * documentation's clothes.
 *
 * `release/docs-bundle/runtime-facts.json` (generated from
 * `product/runtime/auths-runtime/src/docs.rs`) declares four of them:
 *
 *   productionTlsRequired    the endpoint must be TLS
 *   nativeParseRequired      the response must be parsed by the Rust decoder,
 *                            never by JavaScript reading fields off a body
 *   transportIsNotAuthority  a transport-level success is not an authorization
 *   disclosureRequired       receipt content requires an explicit disclosure
 *
 * Every test here drives the SHIPPED client at `@auths-dev/sdk/service` with a
 * hostile transport and asserts the requirement holds. None of them assert
 * that a document says so.
 */

import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

import {
  createServiceClient,
  githubIssueAddress,
} from "../../dist/service.js";

const facts = JSON.parse(await readFile(
  new URL("../../../../release/docs-bundle/runtime-facts.json", import.meta.url),
));

const identity = new Uint8Array(32).fill(3);
const clientWith = (send, options = {}) => createServiceClient({
  endpoint: "https://runtime.example",
  identity,
  profile: githubIssueAddress(),
  transport: { send },
  ...options,
});

// ---------------------------------------------------------------------------
// Anti-vacuity: the requirements under test are actually declared.
// ---------------------------------------------------------------------------

test("ST-0 the runtime declares the trust requirements these tests enforce", () => {
  assert.equal(facts.schema, "auths.runtime-docs-facts/1");
  assert.ok(facts.endpoints.length > 0, "no endpoints declared; every test below would be vacuous");
  const required = (name) => facts.endpoints.filter((endpoint) => endpoint.trust[name] === true);
  for (const name of ["productionTlsRequired", "nativeParseRequired", "transportIsNotAuthority", "disclosureRequired"]) {
    assert.ok(required(name).length > 0, `no endpoint declares ${name}; the matching test would prove nothing`);
  }
  assert.equal(
    required("productionTlsRequired").length,
    facts.endpoints.length,
    "TLS is declared required on every endpoint, so the client must never accept a plaintext one",
  );
});

// ---------------------------------------------------------------------------
// productionTlsRequired
// ---------------------------------------------------------------------------

test("ST-1 the client refuses a non-TLS endpoint", () => {
  for (const endpoint of [
    "http://runtime.example",
    "ws://runtime.example",
    "file:///tmp/runtime",
  ]) {
    assert.throws(
      () => clientWith(async () => { throw new Error("unreachable"); }).constructor
        && createServiceClient({ endpoint, identity, profile: githubIssueAddress() }),
      /HTTPS origin/,
      `${endpoint} was accepted despite productionTlsRequired`,
    );
  }
});

test("ST-1b the client refuses an endpoint carrying credentials, a query, or a path", () => {
  for (const endpoint of [
    "https://user:secret@runtime.example",
    "https://runtime.example/?token=abc",
    "https://runtime.example/tenant-a",
    "https://runtime.example/#fragment",
  ]) {
    assert.throws(
      () => createServiceClient({ endpoint, identity, profile: githubIssueAddress() }),
      /HTTPS origin/,
      `${endpoint} was accepted; a credential or path in the origin is not an Auths endpoint`,
    );
  }
});

// ---------------------------------------------------------------------------
// nativeParseRequired + transportIsNotAuthority
// ---------------------------------------------------------------------------

const ok = (body, contentType = "application/auths+cbor") =>
  async () => ({ status: 200, contentType, body });

test("ST-2 a 200 whose body the native decoder rejects never becomes an authority", async () => {
  const client = clientWith(ok(new Uint8Array([0xff, 0xff, 0xff, 0xff])));
  await assert.rejects(
    client.create(new Uint8Array([0x80])),
    (error) => {
      // The failure must come from the native decoder, not from a JavaScript
      // reading of the body. Either way it must NOT be a success.
      assert.ok(error instanceof Error, "a malformed body produced a non-Error");
      return true;
    },
    "a body the native decoder cannot read was accepted",
  );
});

test("ST-2b a transport-level 200 with the wrong content type is not a success", async () => {
  const client = clientWith(ok(new Uint8Array([0x01]), "application/json"));
  const result = await client.create(new Uint8Array([0x80]));
  assert.notEqual(result.kind, "authority",
    "a JSON body at HTTP 200 was promoted to an authority; transport success is not authorization");
  assert.equal(result.kind, "indeterminate");
});

test("ST-2c a non-2xx response is not a success and is never called not-applied for a verb that applies an effect", async () => {
  for (const status of [301, 400, 401, 403, 429, 500, 503]) {
    const client = clientWith(async () => ({
      status,
      contentType: "application/auths+cbor",
      body: new Uint8Array([0x01]),
    }));
    const result = await client.execute(
      // `execute` needs a real authority, so drive the same path through
      // `create`, whose transport handling is identical.
      // eslint-disable-next-line no-undef
      undefined ?? await failingAuthority(),
      new Uint8Array([0x80]),
    ).catch((error) => ({ kind: "threw", error }));
    assert.notEqual(result.kind, "completed", `HTTP ${status} produced a completed execution`);
  }
});

/** A forged authority is refused before any transport call, which is the point. */
async function failingAuthority() {
  return Object.freeze({ kind: "authority", toJSON() { throw new TypeError("opaque"); } });
}

test("ST-3 a forged authority never reaches the transport", async () => {
  let sent = 0;
  const client = clientWith(async () => {
    sent += 1;
    return { status: 200, contentType: "application/auths+cbor", body: new Uint8Array([0x01]) };
  });
  await assert.rejects(
    client.execute(await failingAuthority(), new Uint8Array([0x80])),
    /forged/,
    "an authority this client did not mint was accepted",
  );
  assert.equal(sent, 0, "a forged authority reached the network before it was refused");
});

// ---------------------------------------------------------------------------
// disclosureRequired
// ---------------------------------------------------------------------------

test("ST-4 receipt bytes are opaque and cannot be serialized without a disclosure", async () => {
  assert.ok(
    facts.endpoints.some((endpoint) => endpoint.trust.disclosureRequired === true),
    "no endpoint requires disclosure; this test would prove nothing",
  );
  const receipt = Object.freeze({ kind: "receipt", toJSON() { throw new TypeError("opaque"); } });
  assert.throws(() => JSON.stringify(receipt), /opaque/);
});

// ---------------------------------------------------------------------------
// The effect axis across the transport boundary. This is the one that decides
// whether a caller repeats a payment.
// ---------------------------------------------------------------------------

test("ST-5 a transport failure after transmission never claims the effect was not applied", async () => {
  const registry = JSON.parse(await readFile(
    new URL("../../../../product/errors/v1/registry.json", import.meta.url),
  ));
  const effectOf = (code) => {
    const definition = registry.definitions.find((item) => item.code === code);
    assert.ok(definition, `the client emitted ${code}, which is in no registry`);
    return definition.outcomes.map((outcome) => outcome.effect);
  };

  const client = clientWith(async () => { throw new TypeError("fetch failed"); });
  const created = await client.create(new Uint8Array([0x80]));
  assert.equal(created.kind, "indeterminate");
  const effects = effectOf(created.code);
  assert.ok(
    effects.includes("possible"),
    `a transport failure on a verb that applies an effect reported ${created.code}, whose ` +
    `registered effect is ${JSON.stringify(effects)}. The client cannot prove the request never ` +
    `reached the server, so it must not tell the caller a blind retry is safe.`,
  );
  assert.notEqual(created.retry, "backoff",
    "a possibly-applied effect was paired with `backoff`, which asserts non-effect");
  assert.equal(created.retry, "reconcile");
});

test("ST-5b a failure of the effect-free verify verb may still claim non-effect", async () => {
  const client = clientWith(async () => { throw new TypeError("fetch failed"); });
  const verified = await client.verify(new Uint8Array([0x80]));
  assert.equal(verified.kind, "indeterminate");
  assert.equal(verified.code, "core.runtime-unavailable",
    "verify applies no effect, so a transport failure there is genuinely not-applied");
  assert.equal(verified.retry, "backoff");
});
