# Auths for Python

The `auths` package embeds Auths Proof Protocol V1 semantics in Rust.
Verification is deterministic, performs no I/O, and accepts exactly three byte
strings:

```python
from auths import verify

result = verify(proof_cbor, canonical_action_cbor, trusted_context_cbor)
if result.kind == "authorized":
    pass_to_a_closed_profile(result.action)
else:
    log(result.explanation.code, result.explanation.message)
```

Release wheels include the native verifier; consumers do not need Rust or a C
compiler.

`result.action` is a non-constructible native capability from the same Rust
verification run as the decision record. Python code cannot create, subclass,
copy, pickle, mutate, or recover it from canonical bytes. Bounded byte
inspection is deliberately separated into `auths.advanced`.

## Native authoring waist

`auths.native` exposes the typed Rust operations required by later workflow
facades: principals, root and child grants, attenuation diffs, lifecycle status,
authorization plans, MCP action canonicalization, trusted-context compilation,
request binding, and exact external signing requests.

```python
from auths import native

actor = native.Principal(actor_id)
request = native.GrantRequest(
    actor,
    "auths.mcp",
    1,
    [("tools/call", "mcp://reports/read")],
    20,
    80,
    ["mcp://reports"],
    None,
    ("numeric-ceiling-v1", 10),
    0,
    None,
    "raw-key-baseline",
    [],
)
plan = native.plan_child(parent_grant, request)
signing = native.prepare_signing(
    plan.unsigned, "raw-key-v1", issuer_id, "ed25519-v1"
)
signed = signing.complete(external_signer(signing.signing_preimage))
```

The native waist does not retain private keys or expose a general
`sign(bytes)` operation.

## Attach and delegate

Milestone B adds provider-neutral async protocols and a typed workflow without
moving Auths semantics into Python:

```python
from auths import (
    Approval,
    AuthsClient,
    BudgetCeiling,
    DelegatedAuthority,
    Permission,
    Profile,
    SnapshotRequired,
    TrustedAuthority,
    Validity,
)

approval = Approval.grant_only("approval.default", approval_provider)
trusted = TrustedAuthority(
    "local.root",
    root_principal,
    native_trusted_context,
    approval.policy.reference,
)

async with AuthsClient(signer=parent_signer, trusted_authority=trusted) as client:
    parent = await client.attach_agent(
        name="research-agent",
        profile=Profile("auths.mcp", 1),
        authority=native_signed_root_grant,
        approval=approval,
    )
    async with await parent.delegate(
        name="records-child",
        authority=DelegatedAuthority(
            permissions=(Permission("tools/call", "mcp://records/tools/update"),),
            validity=Validity(20, 80),
            audiences=("mcp://records",),
            remaining_depth=0,
            budget=BudgetCeiling("numeric-ceiling-v1", 1),
            status=SnapshotRequired("status.local-v1", 30),
        ),
        signer=child_signer,
    ) as child:
        review(child.authority, child.delegation)
```

Rust binds the trusted root, plans every attenuation dimension, derives issuer
and parent linkage, commits approval configuration, prepares the exact signing
request, and validates the echoed request, principal, descriptor, and
transaction through `auths-custody`. Python schedules callbacks and owns their
lifetime. Cancellation and every partial failure close the child signer and
leave no reusable signing transaction.

No production signer or approval adapter is bundled. Proof assembly,
profile-action authorization, and command decoding remain native Rust
operations.

## Authorize and execute MCP

The MCP facade closes the path from an untrusted application mapping to one
profile-bound executor call:

```python
from auths import AuthorizationRequest, mcp

profile = mcp.profile(service="reports")
agent = await client.attach_agent(
    name="reports-agent",
    profile=profile,
    authority=root_grant,
    approval=approval,
)
result = await agent.authorize(
    profile.call("update_demo_record", {"value": "reviewed"}),
    request=AuthorizationRequest(),
)

if result.kind == "authorized":
    response = await profile.gateway(execute).execute(result.command)
```

Rust parses and canonicalizes the call, constructs its action envelope,
assembles the bounded proof and exact request context, runs the local
three-input verifier, and decodes an executor command only from the sealed
authorized action. The native command has no public constructor, is bound to
the configured service, cannot be copied or serialized, and is consumed by the
gateway before the application callback runs. Denied and indeterminate results
contain no command.

## Adoption layer

The promoted claim remains the deterministic delegated-authority verifier
(Level 3 of the repository's adoption ladder). The Python SDK now has the
minimum attach, delegate, authorize, and MCP gateway vertical, but this does
not promote it to a Full Workflow SDK. Importing `auths` performs no identity
exchange, approval, gateway effect, receipt, or provider setup.

Supported wheels use the CPython 3.9 abi3 floor. PyPy, free-threaded CPython,
alternative interpreters, production readiness, stable-v1 compatibility, and
independent review of the new surface are not claimed.
