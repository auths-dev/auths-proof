# Prompt: Build a Cross-Company Incident Response System

You are working in the `auths-dev/auths-proof` repository. You have no assumed prior knowledge of the project. Build an ambitious, production-shaped demo that proves two independent companies can let humans and agents resolve a shared infrastructure incident without sharing an identity system or accidentally granting broad authority.

Work autonomously. Make reasonable product and engineering decisions instead of waiting for routine clarification.

## First: understand the repository

Before changing code:

1. Read `AGENTS.md` and every instruction it references.
2. Read the repository README, the target-state architecture documents, and the TypeScript and Python elite SDK specifications.
3. Inspect the Rust core, both SDK public surfaces, existing demos, test fixtures, architecture constraints, and semantic-freeze machinery.
4. Identify the intended seams between identity providers, signing suites, transports, profiles, approvals, runtime adapters, and Rust-owned semantics.
5. Write a short implementation plan and then execute it fully.

Do not hand-code Auths verification, capability, approval, lifecycle, or receipt semantics in the demo. If an SDK surface is genuinely missing, implement the smallest reusable Rust-owned capability and bind it cleanly into the required SDKs.

## Product story

Build two separately deployed companies:

- **Northstar Commerce**, an online retailer experiencing a regional outage.
- **EdgeShield**, Northstar's CDN and security provider.

Northstar authenticates employees through a local, standards-compliant OAuth/OIDC provider and uses P-256-backed Auths identities. EdgeShield authenticates employees through a distinct non-OAuth mechanism such as client-certificate/mTLS authentication and uses Ed25519 Auths identities. Agent identities must be distinct from employee identities.

The identity-provider adapters belong at the application boundary. OAuth, mTLS, P-256, and Ed25519 must not become coupled inside Auths abstractions.

## Required actors

- Northstar incident commander.
- Northstar security engineer.
- EdgeShield on-call engineer.
- Northstar diagnostic agent.
- EdgeShield remediation agent.
- An untrusted or compromised agent used by the attack lab.

Give each actor a visible identity, current lifecycle state, organization, signing suite, and authority summary.

## Required workflow

1. Generate an outage affecting one Northstar tenant in one region.
2. Give the diagnostic agent read-only authority over bounded metrics and logs.
3. Have the diagnostic agent produce evidence and propose remediation without receiving execution authority.
4. Let EdgeShield delegate authority to purge Northstar's cache in exactly one region for ten minutes.
5. Have the remediation agent construct an exact firewall-and-cache plan through the appropriate Auths profile APIs.
6. Require threshold approval from one authorized person at each company.
7. Review, approve, sign, and execute the plan using one-use commands.
8. Execute one operation over HTTPS and another over Iroh without changing authorization semantics.
9. Show both companies the plan, authority chain, status decisions, execution outcomes, and independently verifiable receipts.
10. Verify at least one portable artifact in both Python and TypeScript and prove they reach the same result.

## Attack lab

The UI must let a user run each case and see exactly where it fails:

- Expand one-region authority to all regions in a child delegation.
- Change a firewall-rule byte after approval.
- Replay an already executed command.
- Use an expired grant.
- Revoke or compromise an approver before execution.
- Rotate EdgeShield from one Ed25519 key to another during the incident.
- Deliver an unauthorized request successfully over Iroh.
- Make the remote API fail before execution, after execution, and with an unknown outcome.
- Withdraw approval while a multi-step plan is in progress.

Do not merely assert that the cases fail. Exercise the real SDK paths and display typed errors, receipts, completed steps, unresolved outcomes, and telemetry.

## Experience

Build a polished web control room with:

- Separate Northstar and EdgeShield views.
- A live incident timeline.
- Actor and identity inspectors.
- A readable authority graph.
- Plan review and approval screens.
- Transport selection and delivery state.
- Receipt inspection and cross-language verification.
- An attack-lab panel with one control per failure case.

Use the TypeScript SDK for the web application and a Python service for orchestration or agent execution. Both must call real Auths APIs. Follow the visual and structural house style of existing demos without copying a demo that no longer represents the target architecture.

## Architecture constraints

- Run each company as a separate service with separate persistence and configuration.
- Do not use a shared user table, shared signing key, or hidden omnipotent backend identity.
- Keep IdP adapters, key adapters, transports, stores, and application profiles swappable.
- Keep review distinct from approval and approval distinct from execution.
- Never turn a successful network response into proof of authorization.
- Never expose a constructible effect-capable verified object in TypeScript or Python.
- Prefer parse-don't-validate APIs, type-driven design, DRY components, and explicit ownership boundaries.
- Keep comments rare and useful; do not put workflow notes or self-referential implementation commentary in code or docstrings.

## Deliverables

Place the demo under `demos/cross-company-incident-response/` and provide:

- A one-command local launcher with deterministic seed data.
- All application, adapter, and test code.
- A concise README explaining the product story and how to run it.
- An architecture and trust-boundary diagram.
- A threat model tied to the attack-lab cases.
- A table mapping every Auths feature to the screen and test that proves it.
- Unit, integration, browser, and adversarial tests.
- Cross-SDK fixtures that are produced by one SDK and consumed by the other.
- CI coverage using the repository's existing policies and pinned toolchains.

## Definition of done

The demo is complete only when a new developer can launch it, resolve the incident through the UI, run every attack case, inspect the receipts, switch transports without changing authority, rotate a key, and see Python and TypeScript agree on the same artifacts.

Run targeted validation locally. Update generated repository artifacts only through their owning commands. Leave the branch ready for authoritative hosted CI and document any genuinely external promotion gate without pretending it passed.
