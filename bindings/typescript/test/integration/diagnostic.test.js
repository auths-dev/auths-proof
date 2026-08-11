import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  DiagnosticVerifier,
  createDiagnosticVerifier,
  diagnoseSdk,
} from "../../dist/diagnostics.js";

const fixture = (name) =>
  readFileSync(
    new URL(`../../../../core/fixtures/v1/valid/${name}`, import.meta.url),
  );

const authorizedBytes = () => fixture("raw-key-chain.result.cbor");
const actionBytes = () => fixture("raw-key-chain.action.cbor");

const verifyWith = (bytes) =>
  createDiagnosticVerifier({ verifyV1: () => bytes }).verify(
    new Uint8Array([1]),
    actionBytes(),
    new Uint8Array([2]),
  );

test("a hostile authorized result stays non-effect-capable", () => {
  const result = verifyWith(authorizedBytes());
  assert.equal(result.kind, "authorized");
  assert.equal(result.effectCapable, false);
  assert.equal("action" in result, false);
  assert.equal(result.submittedActionCbor instanceof Uint8Array, true);
  assert.equal(typeof result.submittedActionCbor.canonicalBytes, "undefined");
});

test("diagnostic results are frozen and copy their bytes", () => {
  const result = verifyWith(authorizedBytes());
  assert.equal(Object.isFrozen(result), true);
  assert.throws(() => {
    result.effectCapable = true;
  }, TypeError);
  result.submittedActionCbor[0] = 0xff;
  assert.deepEqual(verifyWith(authorizedBytes()).submittedActionCbor, actionBytes());
});

test("application code cannot construct a diagnostic verifier", () => {
  assert.throws(() => new DiagnosticVerifier(Symbol(), { verifyV1: () => new Uint8Array() }), /sealed/);
});

test("diagnostic verifiers reject engines without verifyV1", () => {
  assert.throws(() => createDiagnosticVerifier({}), /verifyV1/);
  assert.throws(() => createDiagnosticVerifier(null), /verifyV1/);
});

test("diagnostic verifiers reject non-byte engine output", () => {
  const verifier = createDiagnosticVerifier({ verifyV1: () => "authorized" });
  assert.throws(
    () => verifier.verify(new Uint8Array([1]), actionBytes(), new Uint8Array([2])),
    /non-byte/,
  );
});

test("SDK diagnostics report exact ABI, runtime, capabilities, and adapters", async () => {
  const report = await diagnoseSdk({
    expectedVerifierConfiguration: new Uint8Array(32),
    profiles: { "auths.mcp": 1 },
    adapters: [{ kind: "signer", id: "example.kms", version: "1" }],
  });
  assert.equal(report.schemaVersion, "auths.diagnostics/1");
  assert.equal(report.runtime.family, "node");
  assert.equal(report.wasm.authoringAbi, 1);
  assert.equal(report.wasm.identityAbi, 1);
  assert.equal(report.runtimeContract.satisfied, true);
  assert.deepEqual(report.checks.map(({ id, status }) => [id, status]), [
    ["runtime", "pass"],
    ["wasm", "pass"],
    ["trust", "fail"],
    ["profiles", "pass"],
    ["adapters", "pass"],
  ]);
  assert.deepEqual(report.adapters, [{ kind: "signer", id: "example.kms", version: "1" }]);
});
