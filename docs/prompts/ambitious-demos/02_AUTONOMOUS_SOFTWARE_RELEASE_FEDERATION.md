# Prompt: Build an Autonomous Software Release Federation

You are working in the `auths-dev/auths-proof` repository with no assumed prior context. Build a complete demo in which an open-source infrastructure vendor and a regulated enterprise customer use humans and agents to patch, publish, approve, deploy, and roll back software without sharing accounts or confusing code review with authority to act.

Work autonomously. Read `AGENTS.md`, all referenced repository instructions, the target-state architecture, both elite SDK specifications, the public SDKs, semantic fixtures, and existing demos before implementation.

Rust must continue to own Auths meaning. Do not reimplement authorization, approval, lifecycle, plan, verification, or receipt semantics in TypeScript or Python. Extend shared surfaces only when the demo exposes a genuine product gap.

## Organizations and identity systems

- **ForgeWorks**, the software vendor, authenticates maintainers with GitHub OAuth/OIDC and gives maintainers Ed25519 Auths identities.
- **Meridian Bank**, the customer, authenticates employees with a separate enterprise mechanism such as local SAML and gives approvers P-256 Auths identities.
- CI, review, release, deployment, and rollback agents each have distinct workload identities and narrowly defined authority.

Treat provider authentication and Auths signing identity as separate layers. Keep all provider, key, registry, CI, and deployment integrations behind explicit adapters.

## Required workflow

1. Generate a vulnerable package and a deterministic security advisory.
2. Let a coding agent propose a patch but grant it no review or publication authority.
3. Let an independent security agent inspect the patch and attach test, dependency, and provenance evidence.
4. Produce a package artifact and bind the exact digest, version, provenance, and release channel into an Auths plan.
5. Require two ForgeWorks maintainers to approve publication.
6. Execute a one-use publication command against a local registry adapter.
7. Let Meridian verify the vendor identity, authority chain, artifact, approvals, and receipt without trusting ForgeWorks' database.
8. Require separate Meridian approval for staging and production deployment.
9. Execute deployment through a Python agent while a TypeScript control plane inspects the same portable plan and receipts.
10. Trigger a bounded rollback that cannot authorize an unrelated deployment.

## Attack lab

Provide runnable cases for:

- Replacing a dependency after security review.
- Publishing a different package digest under the approved version.
- Asking the review agent to publish.
- Asking the coding agent to approve its own patch.
- Reusing the publication command.
- Expanding staging authority into production authority.
- Revoking a maintainer between release approval and publication.
- Rotating a release-agent key without invalidating the identity relationship.
- Cancelling deployment before the remote call, after the remote call, and when the outcome is unknown.
- Delivering the correct artifact over a different transport while presenting invalid authority.

Each failure must come from the real Auths path and expose structured diagnostics rather than a demo-specific Boolean.

## Experience

Build a release console that shows:

- The patch and evidence chain.
- Human and agent identities.
- Review, approval, publication, and deployment as visibly separate stages.
- Exact artifact digests and plan contents.
- Authority narrowing from vendor release to customer deployment.
- Live execution states and receipts.
- A side-by-side Python/TypeScript verification view.
- A one-click attack lab.

## Architecture and quality constraints

- Use separate vendor and customer services and stores.
- Use a local registry and deployment target so the complete demo is deterministic and credential-free.
- Keep GitHub OAuth/OIDC and SAML development providers outside Auths core.
- Use the maintained SDK profile surfaces or implement a clean application profile through the profile kit.
- Model uncertain remote outcomes honestly.
- Preserve opaque verified authority across FFI boundaries.
- Use type-driven design, parse-don't-validate boundaries, DRY domain components, and minimal comments.
- Do not add prelaunch compatibility aliases, shims, deprecated entry points, or speculative abstractions.

## Deliverables

Place the result under `demos/autonomous-release-federation/` and include:

- A one-command launcher and deterministic scenario reset.
- TypeScript control plane and Python agent service.
- Separate organization configurations and persistence.
- Local OAuth/OIDC, SAML, registry, CI-evidence, and deployment adapters.
- Architecture, threat model, and authority-flow diagrams.
- A feature-to-proof matrix.
- Unit, integration, browser, cross-SDK, lifecycle, replay, and partial-outcome tests.
- CI integration following repository policies.

The demo is done when a new developer can patch, review, publish, verify, deploy, attack, and roll back the package while seeing that identities, authority, approvals, artifact bytes, transport, and execution remain independent concerns.
