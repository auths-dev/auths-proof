# Auths for Python

`auths` is the Python SDK for identity exchange, authentication, delegated
authority, protected actions, and reliable effect execution. Protocol meaning
is implemented by the embedded Rust core; Python coordinates typed application
values and replaceable async providers.

Release wheels include the native core. Applications do not need Rust, Node,
a hosted Auths service, or private-key export.

## Identity without permissions

`auths.identity` is credential-shape agnostic. An identity method owns its
method material, while a relationship names its purpose, suite, and one or
more opaque verification-material objects. A suite may therefore consume one
Ed25519 key, a P-256 credential, a threshold set, a classical/post-quantum
hybrid, or resolver-provided material without changing the identity API.

```python
from auths.identity import IdentityRegistry, decode_identity

registry = IdentityRegistry(methods=[method], suites=[suite])
decoded = decode_identity(packet)
resolved = await decoded.resolve(registry)
validated = await resolved.validate(registry)
authenticated = await validated.authenticate(
    message,
    signature,
    registry,
    relationship_id="signing-2026",
)
```

Decoded, resolved, validated, and authenticated identities are distinct types.
Authentication grants no permission. The explicit `authority_input` bridge
preserves method, relationship, suite, purpose, provenance, and assurance when
an application later chooses to introduce authority.

The runnable [identity quickstart](examples/identity_quickstart.py) uses
clearly named development adapters. Production applications replace them with
method, resolver, and suite adapters; Auths does not own that ecosystem.

Importing `auths.identity` does not load workflow, approvals, trust, lifecycle,
profiles, or runtime modules.

`auths.integrations.exchange_identity` is a bounded async byte-transport port.
It carries public identity packets without importing or creating authority.

## Verification without workflow

Teams that already possess proof, action, and trusted-context bytes use the
effect-free verifier directly:

```python
from auths.verify import Authorized, Denied, Indeterminate, verify

decision = verify(proof_cbor, action_cbor, trusted_context_cbor)

match decision:
    case Authorized():
        record(decision)
    case Denied() | Indeterminate():
        record(decision)
```

The public result is inert evidence and cannot become a gateway command.
`auths.inspection` provides bounded projections. `auths.diagnostics` accepts
caller-supplied or differential engines, and its output is always inert.
`verify_many` is bounded, order-preserving, releases the GIL during pure native
work, and has the same result meaning as independent `verify` calls.

## Protected actions

The integrated workflow loads trust, binds a signed root grant, delegates only
narrower authority, obtains approval, signs the exact transaction, verifies it
locally, and returns a profile-specific one-use command only for an authorized
result.

```python
from auths import Approval, AuthsClient
from auths.profiles.mcp import McpAuthorized, mcp

profile = mcp.profile(service="reports")
approval = Approval.every_action("approval.reports", approval_provider)

async with AuthsClient(
    signer=signer,
    trusted_authority=trusted_authority,
    telemetry=telemetry,
) as client:
    async with await client.attach_agent(
        name="reports-agent",
        profile=profile,
        authority=root_grant,
        approval=approval,
    ) as agent:
        decision = await agent.authorize(
            profile.call("publish_report", {"month": "august"})
        )
        if isinstance(decision, McpAuthorized):
            response, receipt = await profile.gateway(execute).execute(
                decision.command,
                idempotency_key=request_id,
            )
```

MCP plans commit exact order and membership. Plan-once approval is finite,
bound to that commitment, and cannot leak commands from a partial plan. The
installed-wheel [full workflow consumer](external/full_workflow_consumer.py)
is executed in CI on Linux, macOS, and Windows with the Rust toolchain removed.

## Profiles

Two maintained profiles prove the closed-command boundary:

- `auths.profiles.mcp` protects canonical MCP tool calls;
- `auths.profiles.http` protects canonical origin-bound HTTP requests and
  returns profile receipts.

`auths.profile_kit` lets applications define another typed profile. Its
canonicalizer and decoder remain profile-owned, while Rust constructs the
canonical action, commits plans, verifies proofs, and brands matching one-use
commands. The kit deliberately has no generic executor.

All effectful gateways require an idempotency key. They consume the native
command before calling application code and report `outcome-unknown` when a
provider may have been entered without a trustworthy outcome. Receipts bind
the exact action, proof authority, trusted context, native lifecycle state,
observed provider outcome, and ordered plan membership when applicable.

## Trust, lifecycle, approvals, and runtime

- `auths.trust` compiles typed anchors, assurance requirements, proof plans,
  status snapshots, evidence limits, and offline evidence into a native
  trusted context.
- `auths.lifecycle` authors signed principal and grant status, builds typed
  snapshots, and supplies withdrawal, rotation, and compromise recipes;
  `auths.trust.replace_policy` performs a clean current-policy replacement.
- `auths.authority` exposes attenuation and Rust-owned all-of, any-of, and
  threshold proof plans.
- `auths.approvals` supports committed no-approval, grant-only, every-action,
  risk-gated, custom, exact plan-once, and bounded threshold-provider paths.
- `auths.runtime` exposes Rust-owned transition, replay, additive budget, and
  exclusive-capacity decisions behind challenge, budget, command, receipt,
  clock, executor, and reconciliation protocols. Its in-memory implementation
  is for deterministic development and conformance tests.

Provider orchestration is async-native. The SDK has no second blocking facade,
hidden event loop, hidden retry, or claim of remote atomicity or exactly-once
execution.

## Errors and operations

`AuthsError` exposes bounded family, code, operation, stage, correlation,
retry, effect-state, remediation, and cause-code fields. SDK representations,
events, timelines, and support bundles reject secret-bearing or unbounded
attributes. Raw proof, signature, credential, private material, and provider
payloads are not placed in operational messages.

`auths.testkit` contains explicit development adapters and executable port
checks. Production signers, approval systems, resolvers, stores, telemetry
exporters, transports, and frameworks remain replaceable integrations.
Maintained boundary recipes are in
[Python integration recipes](docs/INTEGRATION_RECIPES.md); durable state is
demonstrated by the separately packaged `auths-sqlite` adapter.

## Release boundary

This package is prelaunch. There are no compatibility shims, deprecated
aliases, legacy readers, migration helpers, dual execution paths, or old/new
ABI windows. `auths.advanced`, `auths.native`, and `auths.mcp` do not exist.

The current package/native pair uses ABI 2 and fails closed on disagreement.
Repository qualification covers abi3 wheels for CPython 3.9–3.14 on Linux,
macOS, and Windows, strict mypy and Pyright, exact public API and wheel-content
snapshots, differential fixtures, hostile-handle checks, and installed-wheel
consumers. Publication, production readiness, and independent-review claims
remain blocked until their separate evidence gates pass.
