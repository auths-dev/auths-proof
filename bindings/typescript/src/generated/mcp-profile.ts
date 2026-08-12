export const MCP_PROFILE = {
  "schema": "auths.mcp-session-contract/1",
  "profile": "auths.mcp",
  "profileVersion": 1,
  "semanticSubject": "auths.mcp-session/1",
  "limits": {
    "toolCount": 128,
    "toolNameBytes": 128,
    "inputBytes": 262144,
    "inputDepth": 32,
    "outputBytes": 1048576,
    "outputDepth": 32,
    "safeErrorBytes": 256,
    "maximumDurationMs": 300000,
    "defaultDurationMs": 30000
  },
  "steps": [
    "reserve",
    "mark-provider-entry",
    "invoke",
    "persist-receipt",
    "reconcile"
  ],
  "handlerEffects": [
    "not-applied",
    "applied",
    "possible"
  ],
  "errorCodes": [
    "mcp.invalid-handler-output",
    "mcp.handler-failed",
    "mcp.handler-timeout",
    "mcp.cancelled-before-entry",
    "mcp.reservation-conflict",
    "mcp.replay",
    "mcp.receipt-persist-failed",
    "mcp.reconciliation-pending"
  ]
} as const;
