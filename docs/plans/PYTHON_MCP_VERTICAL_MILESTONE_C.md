# Python MCP Vertical — Milestone C

Status: complete

## Outcome

The installed Python SDK can attach an MCP agent, construct and approve an exact tool call, authorize it through the embedded Rust verifier, and execute it through a profile-bound gateway. Python never assembles proof CBOR, request-bound verifier context, protocol identifiers, permission mappings, or executable authorization capabilities.

## UX

The normal API has one linear path:

```python
profile = mcp.profile(service="reports")
agent = await client.attach_agent(
    name="reports-agent",
    profile=profile,
    authority=root_grant,
    approval=approval,
)
result = await agent.authorize(
    profile.call("update_demo_record", {"value": "reviewed"})
)

if result.kind == "authorized":
    value = await profile.gateway(execute).execute(result.command)
```

Denied and indeterminate results do not contain a command. Normal results expose stable codes, bounded metrics, safe explanations, and an approval summary. Canonical bytes and raw verification artifacts remain in the advanced inspection API.

## Architecture

```text
untrusted Python Mapping
        |
        v
native MCP parser + profile canonicalizer
        |
        v
Rust action-envelope authoring --> external approval + signer callbacks
        |                                      |
        +--------------- signed action --------+
        |
        v
Rust proof + request-context assembly
        |
        v
embedded Rust three-way verifier
        |
        +-- denied / indeterminate --> data only
        |
        +-- authorized --> native-sealed, one-use McpCommand
                                      |
                                      v
                           service-bound MCP gateway
```

`auths-author` owns the deterministic action envelope and bounded proof/context assembly used by both the WebAssembly and Python bindings. `auths-profile-mcp` remains the sole owner of MCP canonicalization, permission derivation, review display, and decoding from `VerifiedAction`. The Python layer coordinates application callbacks and converts native verdicts into typed results.

## APIs

- `mcp.profile(service=...) -> McpProfile`
- `McpProfile.call(name, arguments) -> McpAction`
- `AttachedAgent.authorize(action, request=...) -> McpAuthorizationResult`
- `McpProfile.gateway(executor) -> McpGateway[T]`
- `McpGateway.execute(command) -> T`

`AuthorizationRequest` supplies a cryptographically random challenge and current evaluation time by default. Explicit values exist for deterministic replay and differential testing.

## Security properties

- `McpCommand` has no public constructor and cannot be copied, pickled, subclassed, or restored from state.
- Only an authorized native verifier result can be decoded into `McpCommand`.
- A command is bound to one MCP service and consumed before its executor runs.
- A wrong gateway performs no effect and does not consume the command.
- Denied and indeterminate branches have no command field.
- Provider and gateway failures cross the normal API as stable, non-sensitive errors.
- Public evidence collections and proof material are bounded before verification.

## Milestone checklist

- [x] MCP profile facade and exact action construction
- [x] Native proof and trusted-context assembly
- [x] Local three-way authorization
- [x] Native profile-command decoding
- [x] Closed gateway accepting only native-sealed commands
- [x] Safe explanations and normal/advanced separation
- [x] Installed-wheel authorization and execution test
- [x] Denied path proves zero gateway effect
- [x] Command provenance, one-use, profile-binding, and serialization tests
- [x] Static result narrowing fixture

## Deferred to Milestone D

Multi-action plan ergonomics, complete inspection coverage, the full cross-language workflow fixture suite, release-wheel operating-system coverage, and final packaging qualification remain outside this milestone.
