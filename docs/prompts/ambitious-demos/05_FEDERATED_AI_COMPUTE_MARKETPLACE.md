# Prompt: Build a Federated AI Compute and Data Marketplace

You are working in the `auths-dev/auths-proof` repository without prior knowledge of its architecture. Build an ambitious demo in which a research laboratory, a private dataset owner, and a GPU provider let independent humans and agents compose a model-training workflow without surrendering control of data, compute, budgets, or publication.

Start by reading `AGENTS.md` and all referenced instructions, the target-state architecture documents, TypeScript and Python elite SDK specifications, the Rust semantic core, fixtures, adapters, and existing demos. Work autonomously and make bounded decisions when product details are unspecified.

Use Auths rather than recreating it. Rust must own verification, identity relationships, authority, attenuation, approval, lifecycle, plan, and receipt semantics. Extend shared surfaces only when a real reusable gap is demonstrated.

## Organizations and identities

- **Lumen Research** authenticates researchers through university OAuth/OIDC and uses P-256 Auths identities.
- **Atlas Data Cooperative** authenticates data stewards through WebAuthn-style login and uses Ed25519 Auths identities.
- **Orbit Compute** authenticates employees separately and gives scheduler and worker agents independently managed workload identities.
- Privacy, scheduling, training, evaluation, and release agents must never share one omnipotent identity.

Keep human authentication, Auths identity, signing suite, storage, transport, and compute-provider integration as separate choices.

## Required workflow

1. Seed a synthetic private dataset, a fixed compute catalog, a training budget, and a candidate model definition.
2. Let Atlas authorize one bounded computation over one dataset version without granting raw-data export.
3. Let Orbit delegate a fixed GPU type, duration, region, and cost ceiling to a scheduler agent.
4. Have Lumen construct an exact training plan binding dataset digest, code digest, parameters, budget, output destination, and permitted follow-up actions.
5. Require independent approvals from the researcher, data steward, and compute-budget owner.
6. Let a privacy agent review inputs without gaining training or publication authority.
7. Execute training through a Python service and inspect the same plan through a TypeScript control plane.
8. Have evaluation agents attach bounded evidence to the exact output model digest.
9. Authorize publication only when the required evidence and approvals apply to that exact model.
10. Give each organization independently verifiable receipts without exposing another organization's private data or keys.
11. Demonstrate HTTPS and Iroh delivery while keeping the same authorization outcome.

## Attack lab

Build repeatable cases for:

- Increasing the GPU budget or duration after approval.
- Changing the dataset version or training parameters.
- Asking a child agent for raw-data export authority.
- Substituting a different model after evaluation.
- Letting the training agent approve publication.
- Replaying a completed training or release command.
- Expiring dataset permission during a queued run.
- Compromising or rotating a scheduler key.
- Withdrawing one organization's approval during a multi-step plan.
- Reporting remote success, remote failure, and outcome unknown.
- Delivering a valid message through Iroh with invalid or insufficient authority.

Every case must exercise real SDK behavior and provide inspectable errors, lifecycle observations, receipts, telemetry, and support diagnostics.

## Experience

Build a polished marketplace and operations console showing:

- The three independent organizations and their identity systems.
- Dataset, compute, budget, model, and evidence ownership.
- Human and agent identity/lifecycle state.
- Proposed plans and authority narrowing.
- Separate review, approval, execution, evaluation, and publication stages.
- Live execution, partial outcomes, cancellation, and receipts.
- Side-by-side Python and TypeScript verification.
- A one-click attack lab explaining every rejection.

## Engineering constraints

- Use separate organization services, stores, and signing material.
- Use deterministic local dataset, GPU-scheduler, training, and model-registry adapters; require no paid cloud credentials.
- Keep IdP, signing suite, transport, persistence, profile, and executor adapters swappable.
- Implement domain actions through maintained profiles or the application profile kit.
- Treat exact bytes, digests, budgets, time bounds, and lifecycle observations as first-class inputs.
- Preserve native-owned opaque verification and one-use command boundaries.
- Use strong types, parse-don't-validate construction, separation of concerns, DRY code, and minimal comments.
- Do not introduce compatibility shims or deprecated surfaces.

## Deliverables and completion

Place the demo under `demos/federated-ai-marketplace/`. Include a one-command launcher, deterministic reset, README, architecture and trust-boundary diagram, threat model, feature-to-proof matrix, synthetic fixtures, and comprehensive unit, integration, browser, parity, lifecycle, replay, transport, and partial-outcome tests.

The demo is complete when a new developer can train and publish one model through independently owned data and compute, verify the result from both SDKs, rotate a key, switch transport, withdraw authority, replay attacks, and understand from the UI and receipts why every successful or failed action received its outcome.
