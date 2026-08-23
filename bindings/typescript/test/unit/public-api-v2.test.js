import assert from "node:assert/strict";
import { test } from "node:test";

import * as root from "../../dist/index.js";
import * as verify from "../../dist/verify.js";
import * as identity from "../../dist/identity.js";
import * as protocol from "../../dist/protocol.js";
import * as profileRuntime from "../../dist/profile-runtime.js";
import * as adapters from "../../dist/adapters.js";
import { conformance, ephemeralEd25519Signer } from "../../dist/testkit/index.js";

test("clean-cut modules expose the intended domain-neutral surface", () => {
  assert.deepEqual(Object.keys(root).sort(), [
    "AuthsError", "AuthsOperationError", "ClientStateError", "ConflictError",
    "DeniedError", "NotAppliedError", "PartialError", "ReceiptIntegrityError", "RecoveryRequiredError",
    "UnavailableError", "connect", "isAuthsError", "recoveryHandleFromBytes", "runtimeInfo",
  ]);
  assert.equal(typeof verify.createVerifier, "function");
  assert.equal(typeof identity.createRawKeyEd25519IdentityClient, "function");
  assert.equal(typeof protocol.connectRemoteVerifier, "function");
  assert.deepEqual(Object.keys(profileRuntime).sort(), [
    "PROFILE_CLIENT_RUNTIME", "bindProfile",
  ]);
  assert.equal(typeof adapters, "object");
});

test("operation errors cannot be forged by application code", () => {
  for (const name of [
    "DeniedError", "UnavailableError", "ConflictError", "NotAppliedError",
    "PartialError", "ReceiptIntegrityError", "RecoveryRequiredError",
  ]) {
    assert.throws(
      () => Reflect.construct(root[name], [{}, "op_AAAAAAAAAAAAAAAAAAAAAA", []]),
      /SDK-constructible only/,
    );
  }
});

test("the ephemeral custody signer satisfies the selected v2 suite", async () => {
  const signer = await ephemeralEd25519Signer();
  assert.equal(signer.descriptor.contract, "signer-custody/2");
  assert.equal(signer.descriptor.lifecycle, "ephemeral");
  await signer.close();
  await signer.close();

  const report = await conformance.custodySigner(ephemeralEd25519Signer);
  assert.equal(report.metadata.suite, "signer-custody/2");
  assert.equal(report.passed, true);
});
