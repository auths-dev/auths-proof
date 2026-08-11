# Auths for Python

Auths lets software prove exactly what it may do, execute through a closed
action family, and leave a signed receipt. Rust owns the security meaning;
Python provides typed, asynchronous application I/O.

The beginner journey introduces five security nouns progressively:

| Term | Meaning |
| --- | --- |
| Identity | Who or what is presenting a credential. |
| Authority | The bounded things that identity may do. |
| Action | The exact inert operation being proposed. |
| Approval | Optional confirmation of one exact transaction. |
| Receipt | Signed evidence of a decision or observed effect. |

Authentication proves control of identity material. It grants no permission.
Approval confirms a transaction. It does not create authority.

```python
from auths.integrations import development
from auths.profiles import mcp

provider = mcp.development_provider(tools={"publish_report": publish_report})
async with development.create_auths(
    authority=mcp.allow_tools(["publish_report"]),
) as auths:
    result = await auths.execute(
        action=mcp.call_tool(name="publish_report", arguments=report),
        provider=provider,
    )
```

Identity and effect-free verification remain independently usable. Installed
wheels include the Rust core, so consumers do not need a Rust toolchain. The
[product glossary](../../docs/product/GLOSSARY.md) defines the progressive
language used by the SDK and recipes.

<!-- auths-beginner-end -->

Publication, promotion, production readiness, and independent review remain
separate evidence gates recorded in `sdk-capability.json`.

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
