# Python Full Workflow SDK — Milestone D

**Status:** repository-local implementation complete
**Baseline:** `940382a`
**Governing specification:** AP-SPEC-035, AP35-PR8 through AP35-PR9
**Capability tier:** repository-local Full Workflow SDK

## UX

The normal MCP path adds an ordered plan without exposing protocol bytes:

```python
approval = Approval.plan_once(
    "approval.mcp-plan",
    approval_provider,
    max_uses=2,
)
plan = profile.plan((
    profile.call("prepare_report", {"month": "august"}),
    profile.call("publish_report", {"month": "august"}),
))
result = await agent.authorize_plan(plan)

if result.kind == "authorized":
    responses = await profile.gateway(execute).execute_plan(result.command)
```

The approval provider is called once for the exact ordered plan. Every member
is still signed and verified independently. A denied or indeterminate member
stops the plan and exposes no command, including commands from earlier
authorized members. Execution remains ordered and is not presented as an
atomic remote transaction.

Advanced consumers can inspect copied commitments and run a caller-supplied
diagnostic verifier. Neither path can mint a verified action or profile
command.

```text
+----------------------+       +-------------------------------+
| normal workflow      |       | advanced evidence             |
| plan -> authorize    |       | raw verify -> inert result    |
|      -> sealed plan  |       | inspect -> copied commitments |
+----------+-----------+       +---------------+---------------+
           |                                   |
           v                                   v
  closed MCP gateway                    never effect-capable
```

## Architecture

```text
Python MCP facade
  -> native MCP canonicalization and ordered plan commitment
  -> bounded plan-once approval session
  -> existing native proof assembly and verification per member
  -> native sealed MCP plan command
  -> profile-owned MCP gateway

Rust fixture generator
  -> one shared Full Workflow projection
  -> TypeScript fixture assertion
  -> Python fixture assertion

wheel build
  -> content allowlist
  -> isolated consumer install
  -> mypy and Pyright contracts
  -> CPython 3.9/current on Linux, macOS, and Windows
```

Rust continues to own canonical action, plan, approval, proof, verifier, and
command meaning. Python owns callback scheduling, immutable product results,
and deterministic disposal. The package does not add a generic executor.

An application profile kit is deliberately deferred. MCP remains a complete
profile-local vertical, and a Python profile abstraction will be considered
only after a second independently implemented Python profile supplies the
comparison evidence required by the profile/domain abstraction boundary plan.

## APIs

- `Approval.plan_once(...)` builds the exact committed approval mode.
- `McpProfile.plan(actions)` returns an immutable ordered `McpPlan`.
- `AttachedAgent.authorize_plan(plan)` returns `McpPlanAuthorized`,
  `McpPlanDenied`, or `McpPlanIndeterminate`.
- Only `McpPlanAuthorized` carries a native `McpPlanCommand`.
- `McpGateway.execute_plan(command, idempotency_key=...)` consumes the command
  before invoking the application callback for each ordered member and returns
  command-bound receipts.
- `inspect_decision(result)` returns safe commitments, metrics, and log fields.
- `create_diagnostic_verifier(engine)` returns inert diagnostic results from
  a caller-supplied byte engine.

## Security and release gates

- [x] Exact ordered membership and native plan commitments
- [x] One bounded approval prompt and exact member sequencing
- [x] No partial command exposure on denied or indeterminate plans
- [x] Forgery, copying, pickling, reflection, mutation, substitution, expiry,
      cancellation, and duplicate-use failures
- [x] Complete result inspection and inert raw-verifier coverage
- [x] Shared Rust/TypeScript/Python workflow projection
- [x] Strict mypy and Pyright installed-consumer contracts
- [x] Installed-wheel workflow and package-content qualification
- [x] CPython 3.9 and current-version coverage on Linux, macOS, and Windows
- [x] Architecture, compliance, SBOM, provenance, API, docs, and semantic
      identity evidence
- [x] Capability metadata promoted to repository-local Full Workflow only
      after the preceding evidence exists

## Claim boundary

Milestone D supports the repository-local pre-review Full Workflow label. It
does not claim independent review, production readiness, stable-v1
compatibility, production custody adapters, provider-effect atomicity, or
publication authorization.
