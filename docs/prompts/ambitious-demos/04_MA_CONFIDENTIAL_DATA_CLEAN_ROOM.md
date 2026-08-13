# Prompt: Build an M&A Confidential Data Clean Room

You are working in the `auths-dev/auths-proof` repository with no assumed project context. Build a complete enterprise demo in which an acquiring company, an acquisition target, and an outside auditor collaborate through agents on confidential diligence without sharing identity systems, raw accounts, or unrestricted data access.

Read `AGENTS.md`, all referenced instructions, the target-state architecture, elite SDK specifications, Rust core, public SDKs, fixtures, and existing demos before implementation. Work autonomously and preserve the repository's prelaunch clean-break policy.

Rust owns Auths semantics. Python and TypeScript may provide product workflows and adapters but must not reproduce verification, authority, approval, lifecycle, or execution meaning.

## Organizations and identity systems

- **Aster Group**, the buyer, authenticates employees through enterprise OAuth/OIDC and uses P-256 Auths identities.
- **Birch Systems**, the target, authenticates employees through a local SAML provider and uses Ed25519 Auths identities.
- **ClearLedger**, the auditor, uses client-certificate authentication and independently managed Ed25519 identities.
- PII-classification, financial-analysis, legal-review, and summarization agents have separate workload identities and authority.

No organization may read another organization's account database or private keys. Authentication adapters and signing-key adapters must remain application-level, replaceable components.

## Required workflow

1. Seed realistic but synthetic contracts, employee records, revenue data, liabilities, and intellectual-property documents.
2. Let Birch expose explicitly selected datasets into a clean room without authorizing raw export.
3. Give a PII agent authority only to classify fields.
4. Give a financial agent authority only to execute approved aggregate calculations.
5. Give a summarization agent authority to summarize specifically approved documents without accessing excluded datasets.
6. Keep agent review findings separate from human approval.
7. Require one authorized lawyer from each company to approve sensitive cross-dataset analyses.
8. Let ClearLedger verify the identity, authority, plan, evidence, and outcome without receiving the underlying documents.
9. Expire all diligence authority at deal close and support early withdrawal.
10. Persist workflow state and receipts through the separately packaged Python SQLite runtime adapter.
11. Verify selected artifacts in both TypeScript and Python.

## Attack lab

Provide real, visible cases for:

- Asking the summarization agent to export raw documents.
- Expanding a financial query to employee-level records.
- Changing query bytes after approval.
- Combining two individually allowed datasets into a prohibited analysis.
- Letting an agent approve its own work.
- Replaying a completed export or calculation command.
- Withdrawing approval during a multi-step plan.
- Expiring the clean room while an agent is queued.
- Compromising an auditor or lawyer identity.
- Restarting a service midway through execution.
- Returning success, failure, and unknown outcomes from the data executor.

Display typed failures, completed plan members, unresolved outcomes, receipts, and support diagnostics. Do not replace Auths decisions with application-specific flags.

## Experience

Build three distinct consoles plus a shared clean-room view:

- Dataset and document inventory with bounded exposure controls.
- Human and agent identity inspectors.
- A readable authority and lifecycle graph.
- Proposed analysis plans with exact inputs and permitted outputs.
- Separate review and approval experiences.
- Execution timeline, result attestations, and receipts.
- Auditor verification that reveals proofs but not confidential source data.
- Attack-lab controls and an explanation of the invariant that rejected each action.

Use TypeScript for the primary web application and Python for at least one agent/execution service. Exercise real SDK surfaces throughout.

## Engineering constraints

- Deploy organizations as separate services and persistence domains.
- Keep IdP, signing, storage, transport, profile, and executor adapters independent.
- Implement application-specific clean-room actions through maintained profile-kit abstractions.
- Never let transport delivery or database possession imply authority.
- Never expose constructible verified authority through an SDK.
- Use type-driven design, parse-don't-validate boundaries, DRY components, explicit ownership, and minimal comments.
- Add no prelaunch shims, aliases, or deprecation machinery.

## Deliverables and completion

Place the result under `demos/ma-confidential-clean-room/`. Supply a deterministic one-command launcher, scenario reset, synthetic fixtures, README, architecture/trust diagram, threat model, feature-to-proof matrix, and unit, integration, browser, persistence, cross-SDK, lifecycle, and adversarial tests.

The demo is complete when a new developer can conduct diligence, authorize a narrowly bounded analysis, obtain an auditor-verifiable receipt, restart the system safely, close the deal, and demonstrate that every attempted authority expansion or data substitution fails for the correct reason.
