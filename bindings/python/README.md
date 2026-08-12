# `auths`

Auths proves what software may do, executes the exact protected action through
a closed profile, and leaves a verifiable receipt.

## Install

```bash
pip install auths
```

Published wheels include the native implementation. Consumers do not need a
Rust toolchain.

## Protect one MCP action

```python
from auths.integrations import development
from auths.profiles import mcp


async def publish_report(arguments: dict[str, object]) -> object:
    return {"published": True, "arguments": arguments}


provider = mcp.development_provider(tools={"publish_report": publish_report})
async with development.create_auths(
    authority=mcp.allow_tools(("publish_report",)),
) as auths:
    result = await auths.execute(
        action=mcp.call_tool(
            name="publish_report",
            arguments={"period": "weekly"},
        ),
        provider=provider,
    )
    print(result)
```

## Public modules

One wheel provides the same progressive topology as TypeScript:

| Import | Purpose |
| --- | --- |
| `auths` | create, delegate, execute, resume, product results and errors |
| `auths.identity` | standalone identity decoding and authentication |
| `auths.verify` | effect-free proof, decision and receipt verification |
| `auths.profiles` | qualified effect domains; initially MCP |
| `auths.integrations` | maintained compositions and mechanism adapters |
| `auths.framework` | proven signer and atomic-reservation contracts |
| `auths.testkit` | deterministic fixtures and conformance suites |

All public modules have explicit `__all__` and typed installed-wheel coverage.
The root does not re-export the other modules. Internal security machinery
remains private.

## Identity without capabilities

`auths.identity` is independent of grants, approvals and execution. It carries
method- and suite-labelled identity data without forcing an application into
the protected workflow.

## Verification without effects

`auths.verify` is deterministic and effect-free. Verification never becomes
authorization and returns no executable handle. Differential tools belong to
`auths.testkit`.

## Resource ownership

Use `async with` for the normal path. Explicit `await auths.aclose()` is also
supported for applications that cannot use a context manager. Both forms are
idempotent and close owned signers and native sessions.

## Production boundary

The development composition uses ephemeral keys and in-memory state. It is not
production durable. Production applications provide qualified profile
integrations plus the narrowly proven framework mechanisms they need. Provider
credentials remain behind the profile gateway and are acquired only after
Auths has authorized and durably reserved the exact action.

Supported Python, platform, ABI and semantic-subject claims are recorded in
`sdk-runtime-contract.json`. Public API and wheel-content snapshots reject
undeclared or obsolete prelaunch modules.
