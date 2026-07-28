# About the GitHub Issue Workflow Demo

## Goal

The demo answers one product question:

> Can an AI agent propose code for a GitHub issue without possessing a GitHub credential, while a separate executor proves that the exact proposed change is authorized before publishing it?

The demonstration makes that answer visible:

- an agent boundary creates a Git candidate with no GitHub credential;
- a human workflow grant names the exact repository, issue, base, allowed changes, audience, and effect budget;
- the native service inspects the candidate as hostile Git data;
- current GitHub facts are read independently;
- the Auths kernel verifies a signed authority chain for the exact action;
- a GitHub mutation credential is requested only after authorization and a durable effect claim;
- one deterministic branch and one draft pull request are published;
- authorization and execution are recorded as separate signed receipts;
- replay returns the original result without another mutation.

The negative cases change one fact at a time and show where the workflow stops. This is important because the product is not merely “an agent that can open pull requests.” The product is a cryptographically and operationally constrained boundary between an uncredentialed proposer and a credentialed executor.

## What the demo proves

The live path uses:

- the real Auths verifier and core proof model;
- a real human → workflow → agent authority chain;
- canonical, exact GitHub action bytes;
- a real bounded Git bundle;
- real current GitHub evidence;
- a real repository-scoped GitHub App installation;
- real branch publication and draft-PR creation;
- durable replay claims;
- signed decision and execution receipts;
- persistent public receipt links.

The frontend does not decide whether an action is authorized. It previews expected outcomes for usability, but the displayed final result comes from the native service.

The agent does not receive a GitHub App key or installation token. Read-only evidence and mutation credentials are owned by the native executor. Mutation tokens are requested only after the exact effect has been authorized and claimed.

## What is intentionally demo-specific

The current deployment is deliberately narrow:

- one configured GitHub organization, repository, issue, and base ref;
- server-owned candidate fixtures instead of arbitrary user uploads;
- ephemeral per-session demo identities;
- a fixed 15-minute interactive grant;
- one Fly machine and one local persistent volume;
- JSON/JSONL persistence rather than a shared database;
- a small daily public mutation quota;
- no end-user authentication or organization administration;
- no webhook-driven workflow lifecycle;
- no general policy authoring interface;
- no multi-tenant installation management;
- no background reconciliation worker;
- no automatic cleanup of old demonstration branches and pull requests.

These constraints make a public live demo safe and understandable. They are not the intended limits of a production product.

## Product thesis

A fully fledged product would be an authorization and execution gateway for code-writing agents.

Agents would submit proposals and evidence, not platform credentials. Humans and organizations would define reusable workflow grants. Auths would verify the exact proposed action against those grants and fresh platform facts. A credential broker would mint the narrowest available credential only for a claimed, authorized effect. Every decision and effect would produce an independently inspectable receipt.

For GitHub issue work, that means a team could safely say:

> An agent may address this issue, from this base revision, within these paths and limits, and may create at most one draft pull request. It may not change automation, bypass review, push arbitrary refs, or reuse the permission for another action.

The same pattern can later cover review comments, issue triage, release preparation, dependency updates, or other platforms, but each product integration should retain a cohesive vertical package with its own exact vocabulary and containment rules.

## Future Work

### Multi-tenant GitHub App product

A production service needs an installation and onboarding model:

- organization administrator installs the GitHub App;
- installation and repository IDs are stored as immutable identifiers;
- repositories opt into explicit automation policies;
- users and agents authenticate to a tenant;
- every workflow is scoped to a tenant, installation, repository, and actor;
- GitHub App installation lifecycle events update or revoke access;
- permissions are continuously checked against the expected minimum set.

The product should never ask users to paste long-lived personal access tokens.

### Real workflow initiation

Replace the fixed public issue with supported initiation paths:

- a GitHub issue command or label;
- an authenticated dashboard;
- a CLI or agent SDK request;
- a webhook from an approved workflow;
- an API call from an existing orchestration system.

Initiation should produce a human-readable grant preview before signature or approval. The user must be able to see the repository, issue, base, allowed paths, denied paths, limits, audience, expiry, and effect budget.

### External candidate submission

The demo builds server-owned bundles. A product needs a secure upload protocol for agent-produced candidates:

- authenticated, content-addressed uploads;
- strict request and bundle size limits before buffering;
- streaming storage rather than keeping large artifacts in process memory;
- malware and archive-bomb protections where applicable;
- isolated Git inspection workers;
- no checkout or execution during authorization;
- support for SHA-1 and SHA-256 Git object formats;
- immutable retention sufficient for audit and reconciliation;
- deletion and retention policies that do not invalidate required receipts.

Candidate construction and candidate inspection should be separate services or sandboxes with no shared credentials.

### Policy authoring and review

Build a policy experience that can express and explain:

- allowed and denied path patterns;
- maximum files, bytes, commits, and objects;
- file modes, symlinks, submodules, merge commits, and non-UTF-8 paths;
- automation-sensitive files such as workflows, `CODEOWNERS`, attributes, and submodules;
- permitted base branches and repository identities;
- approval thresholds and authority delegation;
- effect budgets and expiry;
- executor audiences and verifier versions.

Every policy change should be versioned, signed or administratively attested, reviewable, and bound by digest into subsequent actions.

### Durable control plane

Replace local JSON files with transactional shared storage:

- relational workflow and claim records with unique constraints;
- append-only receipt storage or a transparency log;
- encrypted object storage for candidate bundles;
- schema migrations and backwards-compatible readers;
- idempotency keys on every external effect;
- outbox/inbox patterns for reliable event delivery;
- a durable job queue for execution and reconciliation;
- explicit terminal and retryable states;
- backup, restore, and disaster-recovery exercises.

The claim transaction must commit before credential issuance. Multi-region execution must have a single logical owner for each effect.

### Credential broker hardening

Move credential minting behind a dedicated security boundary:

- GitHub App private keys held in KMS, HSM, or an equivalent managed signer;
- no raw private key material in application environment variables where avoidable;
- short-lived installation tokens with repository and permission narrowing;
- separate read-only evidence and mutation credential requests;
- complete audit events for issuance without logging tokens;
- token zeroization and bounded in-memory lifetime;
- key rotation and emergency revocation procedures;
- policy that prevents the agent-facing service from calling the broker directly.

Where GitHub cannot issue a token narrow enough for one exact operation, the executor must remain the enforcement point and expose only sealed commands.

### Background reconciliation

Ambiguous external outcomes are normal in distributed systems. Productize reconciliation as a first-class worker:

- automatically inspect pending or ambiguous claims;
- use exact deterministic postconditions;
- never retry a mutation until absence is proven;
- record every observation in append-only reconciliation history;
- alert operators when resolution exceeds a service-level objective;
- provide a safe operator action that cannot bypass the original grant;
- resume downstream effects only after the preceding effect is proven.

Chaos tests should interrupt the service before and after every claim, credential request, write, postcondition read, receipt append, and state commit.

### Receipt product

Turn receipts into durable customer-facing evidence:

- stable public or access-controlled receipt URLs;
- independent client-side signature verification;
- downloadable canonical JSON and verification tooling;
- published signer keys, key history, and rotation proofs;
- links from decisions to execution receipts and vice versa;
- repository, issue, action, proof, configuration, and evidence commitments;
- retention guarantees;
- export to SIEM, audit, and compliance systems;
- optional anchoring in an external transparency service.

The current receipt page trusts the native service to verify the persistent log. A mature product should also let the browser or an offline CLI verify canonical bytes and signatures independently.

### User experience

A production UI should organize work around proposals, not low-level sessions:

- inbox of proposed issue fixes;
- clear diff and policy-impact review;
- explicit explanation of why an action is allowed, denied, or indeterminate;
- side-by-side required and executed configuration;
- current GitHub evidence and freshness;
- execution progress and reconciliation state;
- receipt timeline in the same viewport as the approval;
- links to the exact branch and pull request;
- safe cancellation before an effect is claimed;
- accessible responsive behavior and tested failure states.

Avoid vague security slogans. Every label should state what was checked, what credential was requested, and what external effect occurred.

### Observability and operations

Add production-grade:

- structured logs with workflow and claim identifiers but no secrets;
- metrics for decisions, denials by code, token issuance, mutations, reconciliation, and latency;
- distributed traces across API, verifier, credential broker, workers, and GitHub;
- alerts for claim stalls, receipt failures, signature errors, quota pressure, and permission drift;
- rate limits by tenant, user, repository, installation, and IP;
- abuse detection and public-demo isolation;
- runbooks and operator tooling;
- service-level objectives for verification and execution.

Security-relevant outcomes should use closed stable codes, not free-form log parsing.

### GitHub lifecycle integration

Support and verify:

- installation suspension and deletion;
- repository transfer or rename;
- issue closure, locking, or deletion;
- force-pushed or advanced base refs;
- branch protection and rulesets;
- pull-request merge, close, or conversion from draft;
- App permission changes;
- webhook delivery replay and deduplication;
- GitHub API version upgrades.

Fresh evidence must use immutable identifiers wherever GitHub provides them.

### Cleanup and repository hygiene

As the demo evolves:

- keep reusable GitHub workflow logic in `product/integrations/auths-github`;
- keep deployment and public-fixture concerns in `demos/github-issue`;
- split `app.rs` only along real boundaries such as configuration, HTTP projection, and service assembly;
- replace repeated JSON construction with typed response DTOs;
- publish an OpenAPI contract for the product surface;
- add browser tests for every experiment and literal receipt deep links;
- add deployment smoke tests for Vercel rewrites, CORS, CSP, Fly health, and persistent receipts;
- add a cleanup job for demo-created branches and pull requests;
- keep test repositories and GitHub App installations isolated from production tenants;
- pin and audit container, Rust, Git, and frontend toolchain versions;
- keep architecture and deployment documentation synchronized with executable checks.

Do not move GitHub-specific claims, credentials, or receipts into generic folders merely to make individual files smaller. The vertical package is a deliberate cohesion boundary.

### Production readiness bar

The product is fully robust only when it can demonstrate:

1. arbitrary agent input cannot reach a credential or mutation before exact authorization;
2. every action-affecting value is canonicalized, signed, claimed, executed, observed, and receipted consistently;
3. crashes and retries cannot duplicate effects;
4. stale, missing, conflicting, or unverifiable evidence cannot authorize;
5. configuration drift is visible and denies before credential issuance;
6. tenant and installation isolation is enforced at storage, queue, credential, and execution boundaries;
7. receipts remain verifiable across restarts, migrations, key rotation, and long retention periods;
8. operators can reconcile ambiguous outcomes without bypassing the grant;
9. deployment, browser, integration, chaos, and security tests continuously prove these properties;
10. users can understand the proposed action and observed result without reading raw protocol structures.

