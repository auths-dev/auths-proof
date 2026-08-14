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
    }
  ]
} as const;
