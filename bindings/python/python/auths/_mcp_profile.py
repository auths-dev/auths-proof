from __future__ import annotations

import json
from typing import Any, Final

MCP_PROFILE: Final[dict[str, Any]] = json.loads(r"""{
  "schema": "auths.mcp-session-contract/2",
  "profile": "auths.mcp",
  "profileVersion": 2,
  "semanticSubject": "auths.mcp-session/2",
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
    "persist-provider-result",
    "persist-receipt",
    "reconcile"
  ],
  "handlerEffects": [
    "applied",
    "possible"
  ],
  "errorCodes": [
    "mcp.receipt-invalid",
    "mcp.admission-capacity",
    "mcp.delegation-capacity",
    "mcp.recovery-not-found",
    "mcp.recovery-kind-mismatch",
    "mcp.invalid-handler-output",
    "mcp.handler-failed",
    "mcp.handler-timeout",
    "mcp.cancelled-before-entry",
    "mcp.reservation-conflict",
    "mcp.replay",
    "mcp.receipt-persist-failed",
    "mcp.reconciliation-pending"
  ]
}
""")
