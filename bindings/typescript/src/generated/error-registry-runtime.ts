/** Minimal generated validation projection used by the root SDK. */
export const ERROR_RUNTIME_DEFINITIONS = [
  {
    "code": "core.invalid-configuration",
    "family": "configuration",
    "operation": "create",
    "stages": [
      "configuration"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.unsupported-abi",
    "family": "runtime",
    "operation": "create",
    "stages": [
      "runtime"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.unsupported-semantic-subject",
    "family": "runtime",
    "operation": "create",
    "stages": [
      "runtime"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.malformed-input",
    "family": "input",
    "operation": "verify",
    "stages": [
      "parse"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.native-runtime-unavailable",
    "family": "runtime",
    "operation": "create",
    "stages": [
      "runtime"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.forged-execution-reference",
    "family": "state",
    "operation": "resume",
    "stages": [
      "reference"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.runtime-conflict",
    "family": "state",
    "operation": "execute",
    "stages": [
      "lifecycle-store"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.runtime-unavailable",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "lifecycle-store"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.runtime-cancelled",
    "family": "state",
    "operation": "execute",
    "stages": [
      "cancellation"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-result"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.observation-pending",
    "family": "provider",
    "operation": "resume",
    "stages": [
      "reconciliation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.observation-inconclusive",
    "family": "provider",
    "operation": "resume",
    "stages": [
      "reconciliation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.workflow-terminal",
    "family": "state",
    "operation": "resume",
    "stages": [
      "lifecycle"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.internal-invariant",
    "family": "internal",
    "operation": "execute",
    "stages": [
      "internal"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.terminal-receipt-integrity-failed",
    "family": "internal",
    "operation": "resume",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      },
      {
        "retry": "never",
        "effect": "possible"
      },
      {
        "retry": "never",
        "effect": "applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "core.authorization-denied",
    "family": "input",
    "operation": "verify",
    "stages": [
      "authorization"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.authorization-indeterminate",
    "family": "state",
    "operation": "verify",
    "stages": [
      "authorization"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.unauthenticated-principal",
    "family": "input",
    "operation": "create",
    "stages": [
      "authentication"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "client.agent-unavailable",
    "family": "runtime",
    "operation": "connect",
    "stages": [
      "local-agent"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "client.profile-unavailable",
    "family": "configuration",
    "operation": "connect",
    "stages": [
      "negotiation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "client.profile-contract-mismatch",
    "family": "configuration",
    "operation": "connect",
    "stages": [
      "negotiation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "connection.contract-mismatch",
    "family": "configuration",
    "operation": "execute",
    "stages": [
      "connection-resolution"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "install-compatible-runtime",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "connection.credential-unavailable",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "credential"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "connection.unavailable",
    "family": "configuration",
    "operation": "execute",
    "stages": [
      "connection-resolution"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "operation.admission-exhausted",
    "family": "state",
    "operation": "execute",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "operation.idempotency-conflict",
    "family": "state",
    "operation": "execute",
    "stages": [
      "reservation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "operation.outcome-unknown",
    "family": "state",
    "operation": "execute",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "operation.recovery-unavailable",
    "family": "state",
    "operation": "recover",
    "stages": [
      "reconciliation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "operation.timed-out",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "pre-provider"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "opentofu.plan-preflight-denied",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "profile-evaluation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "opentofu.plan-preflight-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "opentofu.saved-plan-denied",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "profile-evaluation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "opentofu.apply-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "postgresql.preflight-denied",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "profile-evaluation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "postgresql.preflight-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "postgresql.update-denied",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "profile-evaluation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "postgresql.update-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "stripe.refund-denied",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "profile-evaluation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "stripe.refund-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "provider-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-malformed",
    "family": "input",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-signature-invalid",
    "family": "input",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-signer-untrusted",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-profile-denied",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-expired",
    "family": "state",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.receipt-trust-indeterminate",
    "family": "runtime",
    "operation": "verify",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "core.verification-capacity",
    "family": "runtime",
    "operation": "verify",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "remote.authentication-failed",
    "family": "configuration",
    "operation": "verify",
    "stages": [
      "channel-authentication"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "remote.response-malformed",
    "family": "runtime",
    "operation": "verify",
    "stages": [
      "remote-response"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "remote.transport-unavailable",
    "family": "runtime",
    "operation": "verify",
    "stages": [
      "transport"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "remote.timeout",
    "family": "runtime",
    "operation": "verify",
    "stages": [
      "transport"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.receipt-invalid",
    "family": "input",
    "operation": "verify",
    "stages": [
      "receipt-profile-payload"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.admission-capacity",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.delegation-capacity",
    "family": "runtime",
    "operation": "delegate",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.recovery-not-found",
    "family": "input",
    "operation": "resume",
    "stages": [
      "lifecycle-store"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.recovery-kind-mismatch",
    "family": "input",
    "operation": "resume",
    "stages": [
      "lifecycle-store"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.packet-malformed",
    "family": "input",
    "operation": "decode",
    "stages": [
      "identity-packet"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.method-unsupported",
    "family": "configuration",
    "operation": "decode",
    "stages": [
      "identity-method"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.not-found",
    "family": "profile",
    "operation": "resolve",
    "stages": [
      "identity-resolution"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.resolution-rejected",
    "family": "profile",
    "operation": "resolve",
    "stages": [
      "identity-resolution"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.resolution-indeterminate",
    "family": "runtime",
    "operation": "resolve",
    "stages": [
      "identity-resolution"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.evidence-expired",
    "family": "state",
    "operation": "validate",
    "stages": [
      "identity-evidence"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.validation-rejected",
    "family": "profile",
    "operation": "validate",
    "stages": [
      "identity-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.validation-indeterminate",
    "family": "runtime",
    "operation": "validate",
    "stages": [
      "identity-validation"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.relationship-denied",
    "family": "profile",
    "operation": "authenticate",
    "stages": [
      "identity-relationship"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.signature-invalid",
    "family": "input",
    "operation": "authenticate",
    "stages": [
      "identity-signature"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "identity.authentication-indeterminate",
    "family": "runtime",
    "operation": "authenticate",
    "stages": [
      "identity-authenticator"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.boundary-invalid",
    "family": "configuration",
    "operation": "create",
    "stages": [
      "boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.attenuation-denied",
    "family": "profile",
    "operation": "delegate",
    "stages": [
      "delegation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.delegation-outcome-unknown",
    "family": "state",
    "operation": "delegate",
    "stages": [
      "delegation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.workflow-proof-invalid",
    "family": "input",
    "operation": "execute",
    "stages": [
      "workflow-proof"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.workflow-expired",
    "family": "state",
    "operation": "execute",
    "stages": [
      "expiry"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.workflow-cancelled",
    "family": "state",
    "operation": "execute",
    "stages": [
      "cancellation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.executor-audience-mismatch",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "audience"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.repository-mismatch",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "repository-boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.repository-renamed-or-transferred",
    "family": "state",
    "operation": "execute",
    "stages": [
      "repository-boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.issue-mismatch",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "issue-boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.issue-not-open",
    "family": "state",
    "operation": "execute",
    "stages": [
      "issue-boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.base-revision-mismatch",
    "family": "state",
    "operation": "execute",
    "stages": [
      "base-revision"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.branch-already-exists",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "branch-precondition"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.pull-request-already-exists",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "pull-request-precondition"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.candidate-bundle-malformed",
    "family": "input",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.candidate-limit-exceeded",
    "family": "input",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.candidate-not-descendant",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.merge-commit-denied",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.unsupported-git-object",
    "family": "input",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.path-not-allowed",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.path-explicitly-denied",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.file-mode-denied",
    "family": "profile",
    "operation": "verify",
    "stages": [
      "candidate-inspection"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.repository-automation-policy-mismatch",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "repository-evidence"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.branch-budget-exhausted",
    "family": "state",
    "operation": "execute",
    "stages": [
      "branch-reservation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.pull-request-budget-exhausted",
    "family": "state",
    "operation": "execute",
    "stages": [
      "pull-request-reservation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.evidence-missing",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "provider-evidence"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.evidence-stale",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "provider-evidence"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.verifier-configuration-mismatch",
    "family": "configuration",
    "operation": "execute",
    "stages": [
      "required-executed"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.exact-action-mismatch",
    "family": "input",
    "operation": "execute",
    "stages": [
      "exact-action"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.candidate-substituted",
    "family": "input",
    "operation": "execute",
    "stages": [
      "exact-candidate-claim"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.credential-boundary-failed",
    "family": "internal",
    "operation": "execute",
    "stages": [
      "credential-boundary"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.branch-rejected",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "branch-result"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "github.pull-request-rejected",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "pull-request-result"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "github.delegation-capacity",
    "family": "runtime",
    "operation": "delegate",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.execution-capacity",
    "family": "runtime",
    "operation": "execute",
    "stages": [
      "admission"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "github.branch-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "branch-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.pull-request-outcome-unknown",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "pull-request-observation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": false
  },
  {
    "code": "github.workflow-terminal-applied",
    "family": "state",
    "operation": "resume",
    "stages": [
      "recovery"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "github.workflow-terminal-not-applied",
    "family": "state",
    "operation": "resume",
    "stages": [
      "recovery"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": true,
    "allowsDecisionReference": true,
    "allowsReceiptReference": true
  },
  {
    "code": "github.receipt-invalid",
    "family": "input",
    "operation": "verify",
    "stages": [
      "receipt-profile-payload"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.invalid-handler-output",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "handler-result"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.handler-failed",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "handler"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.handler-timeout",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "handler"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.cancelled-before-entry",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "reservation"
    ],
    "outcomes": [
      {
        "retry": "safe",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "retry-execution",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.reservation-conflict",
    "family": "state",
    "operation": "execute",
    "stages": [
      "reservation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.replay",
    "family": "state",
    "operation": "execute",
    "stages": [
      "reservation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "inspect-receipt",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.receipt-persist-failed",
    "family": "state",
    "operation": "execute",
    "stages": [
      "receipt"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "mcp.reconciliation-pending",
    "family": "provider",
    "operation": "resume",
    "stages": [
      "reconciliation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "plan.member-interrupted",
    "family": "provider",
    "operation": "execute",
    "stages": [
      "plan-member"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "plan.member-failed-before-entry",
    "family": "profile",
    "operation": "execute",
    "stages": [
      "plan-member"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "plan.resume-reference-invalid",
    "family": "state",
    "operation": "resume",
    "stages": [
      "reference"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "plan.reconciliation-pending",
    "family": "provider",
    "operation": "resume",
    "stages": [
      "reconciliation"
    ],
    "outcomes": [
      {
        "retry": "unknown",
        "effect": "possible"
      }
    ],
    "recommendedAction": "resume-and-reconcile",
    "allowsExecutionReference": true,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "plan.action-substituted",
    "family": "input",
    "operation": "execute",
    "stages": [
      "plan-commitment"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-input",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.denied",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.cancelled",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.throttled",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.unavailable",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.revoked-key",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "key-lifecycle"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "correct-configuration",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.disabled-key",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "key-lifecycle"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.provider-unknown",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider"
    ],
    "outcomes": [
      {
        "retry": "conditional",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.invalid-provider-response",
    "family": "provider",
    "operation": "sign",
    "stages": [
      "provider-response"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.request-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.principal-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.descriptor-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.key-version-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.transaction-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.malformed-signature",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.non-canonical-signature",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.signature-verification-failed",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.evidence-mismatch",
    "family": "input",
    "operation": "sign",
    "stages": [
      "central-validation"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "contact-support",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  },
  {
    "code": "custody.lifecycle-not-permitted",
    "family": "state",
    "operation": "sign",
    "stages": [
      "key-lifecycle"
    ],
    "outcomes": [
      {
        "retry": "never",
        "effect": "not-applied"
      }
    ],
    "recommendedAction": "satisfy-condition",
    "allowsExecutionReference": false,
    "allowsDecisionReference": false,
    "allowsReceiptReference": false
  }
] as const;

/** Rust-owned fail-closed classification for an unknown code. */
export const UNRECOGNIZED_CODE = {
  "known": false,
  "family": "runtime",
  "operation": "execute",
  "stages": [
    "unrecognized-code"
  ],
  "retry": "unknown",
  "effect": "possible",
  "recommendedAction": "resume-and-reconcile"
} as const;
