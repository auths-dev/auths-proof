import assert from "node:assert/strict";
import test from "node:test";
import { parseAuthsErrorEnvelope } from "../../dist/product-errors.js";
import { AuthsWorkflowError, ProviderOperationError } from "../../dist/workflow/errors.js";

test("workflow and provider errors expose bounded recovery metadata", () => {
  const workflow = new AuthsWorkflowError("approval-timeout", "approval timed out", {
    operation: "authorize",
    stage: "approval",
    correlationId: "request-1",
    effect: "possible",
    remediation: { action: "reconcile-approval" },
    causeChain: ["provider-timeout"],
  });
  assert.equal(workflow.family, "approval");
  assert.equal(workflow.retry, "conditional");
  assert.equal(workflow.effect, "possible");
  assert.deepEqual(workflow.causeChain, ["provider-timeout"]);
  assert.doesNotMatch(JSON.stringify(workflow), /credential|signature|proof/i);

  const redacted = new AuthsWorkflowError("invalid-provider", "provider failed", {
    operation: "kms\nsecret",
    correlationId: "private key material",
    remediation: { action: "paste credential", reference: "https://example.test/?token=secret" },
    causeChain: ["signature bytes are secret"],
  });
  assert.equal(redacted.operation, "workflow");
  assert.equal(redacted.correlationId, "redacted");
  assert.deepEqual(redacted.remediation, { action: "inspect-error", reference: "redacted" });
  assert.deepEqual(redacted.causeChain, ["redacted"]);

  const provider = new ProviderOperationError("unavailable", { operation: "kms-sign" });
  assert.equal(provider.family, "provider");
  assert.equal(provider.retry, "safe");
  // BEHAVIOUR CHANGE (contract 4.1): the workflow layer's private effect axis
  // (none|possible|occurred) is deleted. `none` was a second spelling of
  // `not-applied`; the value is the same, the word is now the Rust-owned one.
  assert.equal(provider.effect, "not-applied");
});

test("Rust error tokens accept base64url operation references", () => {
  const operation = "op_Gf0wzqCl4vdf_IjnYcNMzA";
  const error = parseAuthsErrorEnvelope({
    schema: "auths.error/1",
    family: "state",
    code: "operation.idempotency-conflict",
    operation: "execute",
    stage: "reservation",
    summary: "The idempotency key is bound to another commitment.",
    correlationId: operation,
    retry: "unknown",
    effect: "possible",
    entered: {
      approval: true,
      signer: true,
      state: true,
      credential: true,
      provider: true,
    },
    recommendedAction: "resume-and-reconcile",
    executionReference: operation,
    decisionReference: null,
    receiptReference: null,
    causes: ["conflict"],
  });
  assert.equal(error.executionReference, operation);
  assert.equal(error.effect, "possible");
});
