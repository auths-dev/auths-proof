# Auths MCP Tools Call Profile V1

**Status:** Pre-audit application profile  
**MCP operation:** immediate `tools/call`  
**Profile:** `auths.mcp/1`

## Canonical action body

The Auths action body is RFC 8785 canonical JSON containing:

- the fixed profile identifier;
- a lowercase service identifier;
- the exact case-sensitive MCP tool name;
- the complete MCP arguments object;

MCP `_meta` and task-augmented calls are rejected in V1. JSON-RPC request IDs
are transport correlation and are not part of the signed application action.

## Permission mapping

```text
capability = tools/call
resource   = mcp://<service>/tools/<tool-name>
audience   = mcp://<service>
```

Before execution, the application checks that the permission inside the
verified Auths action exactly equals the permission derived from the canonical
MCP call. An `Authorized` proof for one tool can never authorize another tool
whose bytes happen to be signed.

## Execution gate

The service executes only when all are true:

```text
canonical MCP call parsed
AND Auths verdict == Authorized
AND signed permission == derived MCP permission
AND channel policy satisfied
AND challenge atomically claimed
AND budget atomically claimed
AND application tool policy accepts
```

An authenticated Iroh endpoint is only a transport observation. It cannot
replace any Auths condition.

V1 supports one immediate tool call. MCP tasks, `_meta`, prompts, sampling,
OAuth, and generic proxy behavior are outside this exact profile. Transport
selection is independent and belongs to `auths-proof-exchange`.
