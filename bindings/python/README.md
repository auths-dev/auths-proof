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

The signer integration, approval protocol, async lifecycle, attach/delegate
facade, proof assembly, and sealed profile-command gateway are later Python
milestones. The native waist does not retain private keys or expose a general
`sign(bytes)` operation.

## Adoption layer

The promoted claim remains the deterministic delegated-authority verifier
(Level 3 of the repository's adoption ladder). Milestone A adds a
repository-local native authoring foundation but does not promote Python to a
Full Workflow SDK. Importing `auths` performs no identity exchange, approval,
gateway effect, receipt, or provider setup.

Supported wheels use the CPython 3.9 abi3 floor. PyPy, free-threaded CPython,
alternative interpreters, production readiness, stable-v1 compatibility, and
independent review of the new surface are not claimed.
