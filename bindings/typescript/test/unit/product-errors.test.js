import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  AuthsError,
  causeCategoryFrom,
  createSupportBundle,
  formatAuthsError,
  isAuthsError,
} from "../../dist/product-errors.js";
import { mcp } from "../../dist/profiles.js";
import { decodeReceipt } from "../../dist/verify.js";

const fixtures = JSON.parse(await readFile(
  new URL("../../../../product/fixtures/v1/errors/manifest.json", import.meta.url),
));

test("every Rust-owned error fixture parses to the same recovery contract", () => {
  for (const fixture of fixtures.fixtures) {
    const error = AuthsError.parse(fixture);
    assert.equal(isAuthsError(error), true);
    assert.equal(error.code, fixture.code);
    assert.match(formatAuthsError(error), new RegExp(fixture.code.replace(".", "\\.")));
    if (error.effect === "possible") {
      assert.equal(error.retry, "unknown");
      assert.equal(error.recommendedAction, "resume-and-reconcile");
      assert.ok(error.executionReference);
    }
  }
});

test("unsafe retry and unbounded causes fail closed", () => {
  const possible = fixtures.fixtures.find((fixture) => fixture.effect === "possible");
  assert.throws(() => AuthsError.parse({ ...possible, retry: "safe" }), /not registered/);
  assert.throws(() => AuthsError.parse({ ...possible, causes: Array(9).fill("unknown") }), /too many/);
  assert.doesNotMatch(JSON.stringify(AuthsError.parse(possible)), /providerBody|credentialValue|signatureBytes|proofBytes/);
});

test("support bundles are deterministic and bounded", () => {
  const error = AuthsError.parse(fixtures.fixtures[0]);
  const input = {
    sdkVersion: "1.0.0-rc.1",
    runtimeFamily: "node",
    runtimeVersion: "22.23.1",
    platform: "linux-x64",
    abiVersion: "authoring-1",
    semanticSubject: "auths-v1",
    profiles: ["mcp/1"],
    capabilities: ["verify", "execute", "verify"],
    errors: [error],
  };
  assert.deepEqual(createSupportBundle(input), createSupportBundle(input));
});

test("provider failures collapse to bounded cause categories", () => {
  const failure = Object.assign(new Error("credential=never-cross-this-boundary"), { code: "ETIMEDOUT" });
  assert.equal(causeCategoryFrom(failure), "timeout");
  assert.doesNotMatch(causeCategoryFrom(failure), /credential|boundary/);
});

test("future error codes remain bounded without inferring retry or effect", () => {
  const future = {
    ...fixtures.fixtures[0],
    code: "future.new-code",
    retry: "safe",
    effect: "applied",
    executionReference: "secret-reference",
    causes: ["future-cause"],
  };
  const error = AuthsError.parse(future);
  assert.equal(error.code, "future.new-code");
  assert.equal(error.family, "unknown");
  assert.equal(error.retry, "unknown");
  assert.equal(error.effect, "unknown");
  assert.equal(error.executionReference, undefined);
  assert.equal(error.recommendedAction, "contact-support");
});

test("future profile and receipt versions fail before interpretation", () => {
  assert.throws(
    () => mcp.profile({ service: "future", version: 2 }),
    /unsupported MCP profile version/,
  );
  assert.throws(
    () => decodeReceipt(new TextEncoder().encode('{"schema":"auths.portable-receipt/2"}')),
    /unsupported portable Auths receipt/,
  );
});
