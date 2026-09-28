export const ERROR_REGISTRY = {
  "schema": "auths.error-registry/1",
  "definitions": [
    {
      "code": "core.invalid-configuration",
      "family": "configuration",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Invalid configuration",
      "explanation": "A bounded configuration value is invalid.",
      "fixtureId": "core-invalid-configuration"
    },
    {
      "code": "core.unsupported-abi",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Unsupported ABI",
      "explanation": "The installed language package and native runtime do not share an ABI.",
      "fixtureId": "core-unsupported-abi"
    },
    {
      "code": "core.unsupported-semantic-subject",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Unsupported semantic subject",
      "explanation": "The installed artifacts do not implement the same Auths meaning.",
      "fixtureId": "core-unsupported-semantic-subject"
    },
    {
      "code": "core.malformed-input",
      "family": "input",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Malformed bounded input",
      "explanation": "The supplied bounded value could not be parsed.",
      "fixtureId": "core-malformed-input"
    },
    {
      "code": "core.native-runtime-unavailable",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Native runtime unavailable",
      "explanation": "The packaged Auths runtime could not be initialized.",
      "fixtureId": "core-native-runtime-unavailable"
    },
    {
      "code": "core.forged-execution-reference",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Invalid execution reference",
      "explanation": "The execution reference is malformed, unauthenticated, or bound to different state.",
      "fixtureId": "core-forged-execution-reference"
    },
    {
      "code": "core.runtime-conflict",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Runtime state conflict",
      "explanation": "A concurrent operation changed the exact workflow state.",
      "fixtureId": "core-runtime-conflict"
    },
    {
      "code": "core.runtime-unavailable",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Runtime unavailable",
      "explanation": "The durable runtime could not complete an operation before provider entry.",
      "fixtureId": "core-runtime-unavailable"
    },
    {
      "code": "core.runtime-cancelled",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Workflow cancelled",
      "explanation": "The workflow was cancelled with definite non-effect evidence.",
      "fixtureId": "core-runtime-cancelled"
    },
    {
      "code": "core.outcome-unknown",
      "family": "provider",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Provider outcome unknown",
      "explanation": "The exact effect may have occurred and must be observed before retry.",
      "fixtureId": "core-outcome-unknown"
    },
    {
      "code": "core.observation-pending",
      "family": "provider",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Observation pending",
      "explanation": "The provider has not exposed conclusive evidence for the exact effect.",
      "fixtureId": "core-observation-pending"
    },
    {
      "code": "core.observation-inconclusive",
      "family": "provider",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Observation inconclusive",
      "explanation": "Available evidence cannot prove effect or non-effect for the exact request.",
      "fixtureId": "core-observation-inconclusive"
    },
    {
      "code": "core.workflow-terminal",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Workflow already terminal",
      "explanation": "The workflow has already reached an immutable terminal state.",
      "fixtureId": "core-workflow-terminal"
    },
    {
      "code": "core.internal-invariant",
      "family": "internal",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Internal invariant failure",
      "explanation": "Auths rejected an impossible internal state before an effect.",
      "fixtureId": "core-internal-invariant"
    },
    {
      "code": "core.terminal-receipt-integrity-failed",
      "family": "internal",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": true,
      "title": "core.terminal-receipt-integrity-failed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.terminal-receipt-integrity-failed"
    },
    {
      "code": "core.authorization-denied",
      "family": "input",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Authorization denied",
      "explanation": "Available facts prove the supplied proof does not authorize the exact action.",
      "fixtureId": "core-authorization-denied"
    },
    {
      "code": "core.authorization-indeterminate",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Authorization indeterminate",
      "explanation": "A required authorization fact was unavailable, so no decision was reached before any effect.",
      "fixtureId": "core-authorization-indeterminate"
    },
    {
      "code": "core.unauthenticated-principal",
      "family": "input",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Unauthenticated principal",
      "explanation": "The request asserts a principal the runtime cannot authenticate, so no authority is issued.",
      "fixtureId": "core-unauthenticated-principal"
    },
    {
      "code": "core.receipt-malformed",
      "family": "input",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-malformed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-malformed"
    },
    {
      "code": "core.receipt-signature-invalid",
      "family": "input",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-signature-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-signature-invalid"
    },
    {
      "code": "core.receipt-signer-untrusted",
      "family": "profile",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-signer-untrusted",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-signer-untrusted"
    },
    {
      "code": "core.receipt-profile-denied",
      "family": "profile",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-profile-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-profile-denied"
    },
    {
      "code": "core.receipt-expired",
      "family": "state",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-expired",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-expired"
    },
    {
      "code": "core.receipt-trust-indeterminate",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.receipt-trust-indeterminate",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.receipt-trust-indeterminate"
    },
    {
      "code": "core.verification-capacity",
      "family": "runtime",
      "owner": "core",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "core.verification-capacity",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "core.verification-capacity"
    },
    {
      "code": "remote.authentication-failed",
      "family": "configuration",
      "owner": "remote",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "remote.authentication-failed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "remote.authentication-failed"
    },
    {
      "code": "remote.response-malformed",
      "family": "runtime",
      "owner": "remote",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "remote.response-malformed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "remote.response-malformed"
    },
    {
      "code": "remote.transport-unavailable",
      "family": "runtime",
      "owner": "remote",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "remote.transport-unavailable",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "remote.transport-unavailable"
    },
    {
      "code": "remote.timeout",
      "family": "runtime",
      "owner": "remote",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "remote.timeout",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "remote.timeout"
    },
    {
      "code": "mcp.receipt-invalid",
      "family": "input",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "mcp.receipt-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "mcp.receipt-invalid"
    },
    {
      "code": "mcp.admission-capacity",
      "family": "runtime",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "mcp.admission-capacity",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "mcp.admission-capacity"
    },
    {
      "code": "mcp.delegation-capacity",
      "family": "runtime",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "mcp.delegation-capacity",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "mcp.delegation-capacity"
    },
    {
      "code": "mcp.recovery-not-found",
      "family": "input",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "mcp.recovery-not-found",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "mcp.recovery-not-found"
    },
    {
      "code": "mcp.recovery-kind-mismatch",
      "family": "input",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "mcp.recovery-kind-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "mcp.recovery-kind-mismatch"
    },
    {
      "code": "identity.packet-malformed",
      "family": "input",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.packet-malformed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.packet-malformed"
    },
    {
      "code": "identity.method-unsupported",
      "family": "configuration",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.method-unsupported",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.method-unsupported"
    },
    {
      "code": "identity.not-found",
      "family": "profile",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.not-found",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.not-found"
    },
    {
      "code": "identity.resolution-rejected",
      "family": "profile",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.resolution-rejected",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.resolution-rejected"
    },
    {
      "code": "identity.resolution-indeterminate",
      "family": "runtime",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.resolution-indeterminate",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.resolution-indeterminate"
    },
    {
      "code": "identity.evidence-expired",
      "family": "state",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.evidence-expired",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.evidence-expired"
    },
    {
      "code": "identity.validation-rejected",
      "family": "profile",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.validation-rejected",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.validation-rejected"
    },
    {
      "code": "identity.validation-indeterminate",
      "family": "runtime",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.validation-indeterminate",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.validation-indeterminate"
    },
    {
      "code": "identity.relationship-denied",
      "family": "profile",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.relationship-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.relationship-denied"
    },
    {
      "code": "identity.signature-invalid",
      "family": "input",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.signature-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.signature-invalid"
    },
    {
      "code": "identity.authentication-indeterminate",
      "family": "runtime",
      "owner": "identity",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "identity.authentication-indeterminate",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "identity.authentication-indeterminate"
    },
    {
      "code": "github.boundary-invalid",
      "family": "configuration",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.boundary-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.boundary-invalid"
    },
    {
      "code": "github.attenuation-denied",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.attenuation-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.attenuation-denied"
    },
    {
      "code": "github.delegation-outcome-unknown",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.delegation-outcome-unknown",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.delegation-outcome-unknown"
    },
    {
      "code": "github.workflow-proof-invalid",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.workflow-proof-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.workflow-proof-invalid"
    },
    {
      "code": "github.workflow-expired",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.workflow-expired",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.workflow-expired"
    },
    {
      "code": "github.workflow-cancelled",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.workflow-cancelled",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.workflow-cancelled"
    },
    {
      "code": "github.executor-audience-mismatch",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.executor-audience-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.executor-audience-mismatch"
    },
    {
      "code": "github.repository-mismatch",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.repository-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.repository-mismatch"
    },
    {
      "code": "github.repository-renamed-or-transferred",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.repository-renamed-or-transferred",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.repository-renamed-or-transferred"
    },
    {
      "code": "github.issue-mismatch",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.issue-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.issue-mismatch"
    },
    {
      "code": "github.issue-not-open",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.issue-not-open",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.issue-not-open"
    },
    {
      "code": "github.base-revision-mismatch",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.base-revision-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.base-revision-mismatch"
    },
    {
      "code": "github.branch-already-exists",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.branch-already-exists",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.branch-already-exists"
    },
    {
      "code": "github.pull-request-already-exists",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.pull-request-already-exists",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.pull-request-already-exists"
    },
    {
      "code": "github.candidate-bundle-malformed",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.candidate-bundle-malformed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.candidate-bundle-malformed"
    },
    {
      "code": "github.candidate-limit-exceeded",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.candidate-limit-exceeded",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.candidate-limit-exceeded"
    },
    {
      "code": "github.candidate-not-descendant",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.candidate-not-descendant",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.candidate-not-descendant"
    },
    {
      "code": "github.merge-commit-denied",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.merge-commit-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.merge-commit-denied"
    },
    {
      "code": "github.unsupported-git-object",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.unsupported-git-object",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.unsupported-git-object"
    },
    {
      "code": "github.path-not-allowed",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.path-not-allowed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.path-not-allowed"
    },
    {
      "code": "github.path-explicitly-denied",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.path-explicitly-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.path-explicitly-denied"
    },
    {
      "code": "github.file-mode-denied",
      "family": "profile",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.file-mode-denied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.file-mode-denied"
    },
    {
      "code": "github.repository-automation-policy-mismatch",
      "family": "runtime",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.repository-automation-policy-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.repository-automation-policy-mismatch"
    },
    {
      "code": "github.branch-budget-exhausted",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.branch-budget-exhausted",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.branch-budget-exhausted"
    },
    {
      "code": "github.pull-request-budget-exhausted",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.pull-request-budget-exhausted",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.pull-request-budget-exhausted"
    },
    {
      "code": "github.evidence-missing",
      "family": "runtime",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.evidence-missing",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.evidence-missing"
    },
    {
      "code": "github.evidence-stale",
      "family": "runtime",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.evidence-stale",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.evidence-stale"
    },
    {
      "code": "github.verifier-configuration-mismatch",
      "family": "configuration",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.verifier-configuration-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.verifier-configuration-mismatch"
    },
    {
      "code": "github.exact-action-mismatch",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.exact-action-mismatch",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.exact-action-mismatch"
    },
    {
      "code": "github.candidate-substituted",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.candidate-substituted",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.candidate-substituted"
    },
    {
      "code": "github.credential-boundary-failed",
      "family": "internal",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.credential-boundary-failed",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.credential-boundary-failed"
    },
    {
      "code": "github.branch-rejected",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": true,
      "title": "github.branch-rejected",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.branch-rejected"
    },
    {
      "code": "github.pull-request-rejected",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": true,
      "title": "github.pull-request-rejected",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.pull-request-rejected"
    },
    {
      "code": "github.delegation-capacity",
      "family": "runtime",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.delegation-capacity",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.delegation-capacity"
    },
    {
      "code": "github.execution-capacity",
      "family": "runtime",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.execution-capacity",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.execution-capacity"
    },
    {
      "code": "github.branch-outcome-unknown",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.branch-outcome-unknown",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.branch-outcome-unknown"
    },
    {
      "code": "github.pull-request-outcome-unknown",
      "family": "provider",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.pull-request-outcome-unknown",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.pull-request-outcome-unknown"
    },
    {
      "code": "github.workflow-terminal-applied",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": true,
      "title": "github.workflow-terminal-applied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.workflow-terminal-applied"
    },
    {
      "code": "github.workflow-terminal-not-applied",
      "family": "state",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": true,
      "title": "github.workflow-terminal-not-applied",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.workflow-terminal-not-applied"
    },
    {
      "code": "github.receipt-invalid",
      "family": "input",
      "owner": "github",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "github.receipt-invalid",
      "explanation": "The registered Auths contract rejected or classified this bounded operation.",
      "fixtureId": "github.receipt-invalid"
    },
    {
      "code": "mcp.invalid-handler-output",
      "family": "profile",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Invalid MCP handler output",
      "explanation": "The invoked handler returned an invalid or oversized bounded result.",
      "fixtureId": "mcp-invalid-handler-output"
    },
    {
      "code": "mcp.handler-failed",
      "family": "provider",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP handler failed",
      "explanation": "The invoked handler failed without conclusive no-effect evidence.",
      "fixtureId": "mcp-handler-failed"
    },
    {
      "code": "mcp.handler-timeout",
      "family": "provider",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP handler timed out",
      "explanation": "The invoked handler did not produce conclusive effect evidence before its deadline.",
      "fixtureId": "mcp-handler-timeout"
    },
    {
      "code": "mcp.cancelled-before-entry",
      "family": "profile",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP execution cancelled",
      "explanation": "Execution was cancelled before the handler was entered.",
      "fixtureId": "mcp-cancelled-before-entry"
    },
    {
      "code": "mcp.reservation-conflict",
      "family": "state",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP reservation conflict",
      "explanation": "A different committed request already owns the execution record.",
      "fixtureId": "mcp-reservation-conflict"
    },
    {
      "code": "mcp.replay",
      "family": "state",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP replay blocked",
      "explanation": "The committed MCP execution has already reached a terminal state.",
      "fixtureId": "mcp-replay"
    },
    {
      "code": "mcp.receipt-persist-failed",
      "family": "state",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP receipt persistence failed",
      "explanation": "The effect was observed but its execution receipt was not durably persisted.",
      "fixtureId": "mcp-receipt-persist-failed"
    },
    {
      "code": "mcp.reconciliation-pending",
      "family": "provider",
      "owner": "mcp",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "MCP reconciliation pending",
      "explanation": "The profile still lacks conclusive effect evidence.",
      "fixtureId": "mcp-reconciliation-pending"
    },
    {
      "code": "plan.member-interrupted",
      "family": "provider",
      "owner": "plan",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Plan member interrupted",
      "explanation": "The current ordered member may have applied and later members remain blocked.",
      "fixtureId": "plan-member-interrupted"
    },
    {
      "code": "plan.member-failed-before-entry",
      "family": "profile",
      "owner": "plan",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Plan member blocked",
      "explanation": "The current ordered member failed before provider entry.",
      "fixtureId": "plan-member-failed-before-entry"
    },
    {
      "code": "plan.resume-reference-invalid",
      "family": "state",
      "owner": "plan",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Plan reference invalid",
      "explanation": "The supplied reference is not bound to this ordered plan execution.",
      "fixtureId": "plan-resume-reference-invalid"
    },
    {
      "code": "plan.reconciliation-pending",
      "family": "provider",
      "owner": "plan",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Plan reconciliation pending",
      "explanation": "The current member remains outcome-unknown and later members remain blocked.",
      "fixtureId": "plan-reconciliation-pending"
    },
    {
      "code": "plan.action-substituted",
      "family": "input",
      "owner": "plan",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Plan action substituted",
      "explanation": "The current ordered member does not match the approved plan commitment.",
      "fixtureId": "plan-action-substituted"
    },
    {
      "code": "custody.denied",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody request denied",
      "explanation": "The configured custody provider denied the exact signing request.",
      "fixtureId": "custody-denied"
    },
    {
      "code": "custody.cancelled",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody request cancelled",
      "explanation": "The exact signing request was cancelled before Auths accepted a signature.",
      "fixtureId": "custody-cancelled"
    },
    {
      "code": "custody.throttled",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody provider throttled",
      "explanation": "The custody provider refused the request under its current rate policy.",
      "fixtureId": "custody-throttled"
    },
    {
      "code": "custody.unavailable",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody provider unavailable",
      "explanation": "The custody provider could not conclusively service the exact signing request.",
      "fixtureId": "custody-unavailable"
    },
    {
      "code": "custody.revoked-key",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody key revoked",
      "explanation": "The configured key version is permanently barred from new signing.",
      "fixtureId": "custody-revoked-key"
    },
    {
      "code": "custody.disabled-key",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody key disabled",
      "explanation": "The configured key version is not permitted to create new signatures.",
      "fixtureId": "custody-disabled-key"
    },
    {
      "code": "custody.provider-unknown",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody outcome unknown",
      "explanation": "The provider did not prove whether it produced a signature for the exact request.",
      "fixtureId": "custody-provider-unknown"
    },
    {
      "code": "custody.invalid-provider-response",
      "family": "provider",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Invalid custody response",
      "explanation": "The provider response could not be parsed as a bounded signing response.",
      "fixtureId": "custody-invalid-provider-response"
    },
    {
      "code": "custody.request-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Signing request mismatch",
      "explanation": "The provider response names a different signing request.",
      "fixtureId": "custody-request-mismatch"
    },
    {
      "code": "custody.principal-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Signing principal mismatch",
      "explanation": "The provider response names a different signing principal.",
      "fixtureId": "custody-principal-mismatch"
    },
    {
      "code": "custody.descriptor-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Signing descriptor mismatch",
      "explanation": "The response signature method or suite differs from the frozen descriptor.",
      "fixtureId": "custody-descriptor-mismatch"
    },
    {
      "code": "custody.key-version-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Signing key version mismatch",
      "explanation": "The provider response names a different key version.",
      "fixtureId": "custody-key-version-mismatch"
    },
    {
      "code": "custody.transaction-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Signing transaction mismatch",
      "explanation": "The provider response is bound to a different Auths transaction.",
      "fixtureId": "custody-transaction-mismatch"
    },
    {
      "code": "custody.malformed-signature",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Malformed provider signature",
      "explanation": "The returned signature is not a bounded encoding accepted by its suite.",
      "fixtureId": "custody-malformed-signature"
    },
    {
      "code": "custody.non-canonical-signature",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Non-canonical provider signature",
      "explanation": "The returned signature has a different canonical representation.",
      "fixtureId": "custody-non-canonical-signature"
    },
    {
      "code": "custody.signature-verification-failed",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Provider signature invalid",
      "explanation": "The returned signature does not verify over the exact Auths preimage.",
      "fixtureId": "custody-signature-verification-failed"
    },
    {
      "code": "custody.evidence-mismatch",
      "family": "input",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody evidence mismatch",
      "explanation": "The returned evidence does not match the frozen custody descriptor.",
      "fixtureId": "custody-evidence-mismatch"
    },
    {
      "code": "custody.lifecycle-not-permitted",
      "family": "state",
      "owner": "custody",
      "ownerVersion": 1,
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
      "allowsReceiptReference": false,
      "title": "Custody lifecycle blocks signing",
      "explanation": "The exact key lifecycle state does not permit new signatures.",
      "fixtureId": "custody-lifecycle-not-permitted"
    }
  ]
} as const;

/** SHA-256 of canonical compact JSON for this generated registry. */
export const ERROR_REGISTRY_SHA256 = "92e6dc23f76b27641318f64228f7f94e8db7bdd006e75e6d479521ec463fee17" as const;

/**
 * `auths_errors::classify` applied to a code this build's registry does not
 * contain. A binding projects this; it never recomputes it and never invents a
 * fourth effect state.
 */
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

/**
 * `auths_errors::outcome_codes` -- the registry code an authorization verdict
 * carries. A verdict names itself with a kernel diagnostic, not a registry
 * code; this is the Rust-owned translation.
 */
export const OUTCOME_CODES = {
  "denied": "core.authorization-denied",
  "indeterminate": "core.authorization-indeterminate"
} as const;
