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

## Use a production runtime

```python
from auths import create_auths
from auths.profiles import github_issue_address

auths = create_auths(
    endpoint="https://auths.example.com",
    identity=public_identity_bytes,
    profile=github_issue_address(),
)
authority = await auths.create(authority_request_bytes)
if authority.kind != "authority":
    raise RuntimeError(authority.code)
result = await auths.execute(authority, action_bytes)
if result.kind == "recoverable":
    await auths.resume(result.reference)
```

## Public modules

One wheel provides the same progressive topology as TypeScript:

| Import | Purpose |
| --- | --- |
| `auths` | create, delegate, execute, resume, product results and errors |
| `auths.identity` | standalone identity decoding and authentication |
| `auths.verify` | effect-free proof, decision and receipt verification |
| `auths.profiles` | qualified MCP, OpenTofu, PostgreSQL and GitHub effect domains |
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

The development composition uses ephemeral keys and in-memory state. The root
production client talks to an HTTPS operator runtime through a bounded,
Rust-owned binary contract. Provider credentials remain behind the profile
gateway and are acquired only after Auths has authorized and durably reserved
the exact action.

Supported Python, platform, ABI and semantic-subject claims are recorded in
`sdk-runtime-contract.json`. Public API and wheel-content snapshots reject
undeclared or obsolete prelaunch modules.

Run `python -m auths doctor` to inspect bounded installed runtime, ABI and
profile facts. The report never reads application secrets or prints protocol
payloads.
