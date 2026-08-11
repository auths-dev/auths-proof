import assert from "node:assert/strict";
import test from "node:test";
import { AuthsWorkflowError, ProviderOperationError } from "../../dist/index.js";

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
  assert.equal(provider.effect, "none");
});
