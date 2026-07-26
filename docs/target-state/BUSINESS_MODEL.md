# Auths Platform Business Model

> Historical planning document. It is nonnormative and does not define kernel
> protocol or security guarantees.

**Status:** Proposed

**Date:** 25 July 2026

**Technical foundation:** Auths Proof Protocol V1

**Initial commercial verticals:** MCP security and internal deployment

## Executive thesis

The recommended business model is:

> Make proof verification an open, portable standard. Sell the operating
> system that organizations use to issue, govern, observe, and operate
> authority at scale.

Auths should not monetize by forcing authorization decisions through a hosted
service. Its core architectural advantage is that a service can verify
authority locally, deterministically, and without a network dependency.

The commercial platform should monetize the valuable organizational work
around that verification:

- authority issuance and approval;
- trust and registry management;
- safe distribution of signed configuration;
- fleet-wide visibility;
- replay coordination;
- receipts, investigations, and audit retention;
- enterprise integrations;
- managed, private-cloud, on-premises, and air-gapped operation;
- support, security response, and contractual guarantees.

The concise product thesis is:

> **Auths Proof is the open standard. Auths Platform is how organizations
> operate that standard at scale. Auths MCP and Auths Deploy make its value
> immediately tangible.**

## Strategic principles

### 1. Verification remains open and local

Organizations must be able to:

- verify proofs without an Auths account;
- run the verifier without network access;
- perform unlimited local verification;
- retain control of their trust configuration;
- use the protocol and canonical corpus independently;
- leave the commercial platform without replacing the enforcement primitive.

This is both a product guarantee and a competitive advantage. Auths should be
adoptable as infrastructure rather than rented as a synchronous API.

### 2. Organizational coordination is commercial

The difficult work at organizational scale is not executing a deterministic
verification function. It is:

- deciding who may issue authority;
- collecting and recording approvals;
- detecting dangerous widening;
- distributing trusted configuration safely;
- understanding reachable authority;
- coordinating replay and revocation state;
- investigating why an operation was permitted;
- producing evidence for security and compliance teams;
- integrating existing identity, signing, deployment, and observability
  systems.

The paid platform should make those activities dramatically safer and easier.

### 3. The business model must reinforce the architecture

Commercial incentives must not undermine the protocol:

- no per-verification fee;
- no required call to Auths Cloud during enforcement;
- no secret cloud-only verdict semantics;
- no proprietary extension required to interpret an otherwise standard proof;
- no dependence on telemetry to preserve correctness;
- no privileged identity implementation;
- no application business logic inside the proof kernel or CLI.

Paid functionality may create and distribute standard Auths artifacts, operate
downstream runtime state, and analyze standard receipts. The artifacts remain
independently verifiable.

### 4. Auths sells authority infrastructure, not identity

Auths should integrate with existing principal-control and signing systems
rather than require organizations to replace them.

Commercial integrations may support:

- enterprise identity providers;
- workload identity systems;
- cloud KMS products;
- hardware security modules;
- internal certificate authorities;
- device identity;
- principal methods such as DIDs or KERI;
- future identity technologies.

None receives privileged authority semantics. The business remains valuable
regardless of which identity technologies win.

## Product portfolio

| Product | Primary customer | Core value | Model |
|---|---|---|---|
| **Auths Proof** | Developers and implementers | Standard proof creation and local verification | Free and open source |
| **Auths Authority** | Platform and security teams | Issuance, delegation, approval, and authority governance | Paid platform |
| **Auths Trust** | Platform and security teams | Trusted-context, registry, and adapter configuration | Paid platform |
| **Auths Observe** | Security, audit, and compliance | Receipts, authority graphs, investigations, and retention | Subscription plus storage |
| **Auths MCP** | AI platform and security teams | Exact delegated authority for agents and tool calls | Team and enterprise product |
| **Auths Deploy** | Platform and infrastructure teams | Artifact-bound deployment authorization | Enterprise product |
| **Auths Enterprise** | Regulated and large organizations | Private operation, integrations, SLA, and support | Annual license |

## Auths Proof

Auths Proof is the open foundation and developer-acquisition surface.

It should include:

- the protocol specification and CDDL;
- registries and domain-separation rules;
- the Rust reference verifier;
- the portable verification boundary;
- supported Rust, TypeScript/WASM, Python, and Go packages;
- the canonical conformance corpus;
- stable results and explanations;
- local trusted-context construction;
- local proof authoring;
- basic MCP and deployment profiles and examples;
- profile and adapter development kits;
- fuzz and conformance runners.

The recommended license for the specification, corpus, verifier, and supported
SDKs is a permissive license such as Apache-2.0.

The free product must be genuinely useful. A developer should be able to
protect a production service using only the open implementation. The commercial
platform wins by eliminating organizational toil, not by deliberately crippling
the verifier.

## Auths Authority

Auths Authority is the commercial center of the platform.

It manages the lifecycle around standard Auths grants and proofs while keeping
the verification path independent.

### Capabilities

- safe grant planning;
- exact-action approval requests;
- visual authority-chain exploration;
- authority diff and widening detection;
- delegation and attenuation builders;
- separation-of-duties workflows;
- threshold and multi-party approval;
- scheduled expiry and revocation workflows;
- proof and evidence minimization;
- reusable organizational approval templates;
- break-glass and emergency authority workflows;
- signing requests for external KMS, HSM, custody, and identity systems;
- private profile and adapter catalogs;
- review, staging, and promotion of authority configuration;
- policy-as-code and API-driven workflows.

### Questions the product should answer

- Who granted this authority?
- Which chain of grants makes an operation possible?
- What exact action was approved?
- What can this principal delegate?
- Is this proposed grant wider than its parent?
- What new authority becomes reachable if this change is approved?
- Which agents or workloads can currently affect production?
- Which grants are unused, unusually broad, or about to expire?
- Which approval or assurance requirement is currently missing?

Auths Authority can be centralized without becoming a centralized enforcement
dependency. It creates and governs portable artifacts; services still verify
those artifacts locally.

## Auths Trust

Auths Trust manages the deterministic inputs that organizations intentionally
provide to local verifiers.

### Capabilities

- trusted-root management;
- immutable registry-manifest construction;
- signed trusted-context bundles;
- application-profile registration;
- principal, status, assurance, budget, and extension adapter registration;
- staged configuration promotion;
- environment-specific trust views;
- key and certificate rollover workflows;
- explicit revocation and status checkpoints;
- compatibility and conformance validation;
- fleet distribution and version visibility;
- rollback-safe signed releases.

The paid service may compile, sign, distribute, and observe trusted
configuration. It must not hide policy fetches inside the verifier.

Every verifier must continue to operate against an explicitly supplied,
locally available trusted context.

## Auths Observe

Auths Observe converts decision receipts into an operational security product.

### Capabilities

- searchable authorization history;
- proof, action, context, plan, and result digest tracking;
- authority-chain and delegation-graph visualization;
- replay and duplicate-operation detection;
- grant-usage and blast-radius analysis;
- denied and indeterminate trend analysis;
- investigation timelines;
- anomaly and widening alerts;
- expiring-authority dashboards;
- cross-service principal activity;
- tamper-evident receipt archives;
- configurable retention;
- SIEM, data-warehouse, and audit export;
- compliance evidence packages.

Local enforcement does not depend on receipt upload. Receipt collection is an
optional downstream operation and may be delayed, filtered, self-hosted, or
disabled.

### Commercial model

Auths Observe can include a receipt allowance in each subscription and charge
for:

- additional ingestion blocks;
- additional retention;
- archival tiers;
- SIEM destinations;
- compliance exports;
- cryptographic long-term archival;
- advanced investigations and detections.

This aligns price with real storage and operational cost without taxing the
security decision itself.

## Auths MCP

Auths MCP is the recommended initial commercial wedge.

### Product promise

> Stop handing agents broad bearer credentials. Give them bounded,
> explainable, cryptographically verifiable authority that each MCP server
> enforces locally.

### Capabilities

- in-process MCP server middleware;
- agent, server, and tool inventory;
- exact tool-call and canonical-argument binding;
- short-lived delegated authority;
- bounded reusable tool authority;
- human approval for high-consequence actions;
- threshold approval;
- challenge and replay protection;
- agent-authority visualization;
- service and tool risk classification;
- permission receipts;
- incident investigation;
- integrations with existing SSO, workload identity, KMS, HSM, and signing
  systems.

The primary architecture is embedded verification, not a mandatory proxy.
Optional exchange services and gateways may simplify deployment without
becoming the only way to use the protocol.

### Free and paid boundary

Open:

- core MCP profile;
- verification middleware;
- local examples;
- local proof creation;
- conformance tests.

Paid:

- organization-wide approval workflows;
- agent and MCP fleet inventory;
- managed challenges and replay state;
- private profiles;
- trust-bundle distribution;
- authority graph;
- receipt retention and investigations;
- enterprise identity and signing integrations;
- private deployment and support.

## Auths Deploy

Auths Deploy extends the same authority model into high-consequence internal
deployment and infrastructure operations.

### Capabilities

- artifact-bound approval;
- source-revision binding;
- configuration-digest binding;
- target-environment binding;
- deployment-strategy binding;
- multi-party approval;
- short-lived deployment-agent grants;
- replay-safe execution;
- deployment receipts;
- break-glass workflows;
- authority-diff analysis;
- integrations with source control, CI/CD, artifact registries, Kubernetes,
  infrastructure-as-code systems, KMS products, HSMs, and change-management
  systems.

Auths Deploy is not a replacement deployment platform. It adds
cryptographically exact authority to the systems an organization already uses.

This product naturally supports higher-value enterprise contracts because it
protects production changes, infrastructure mutation, secrets, administrative
operations, and incident response.

## Auths Enterprise

Auths Enterprise packages the platform for organizations with strict
operational, regulatory, security, or procurement requirements.

### Capabilities

- private-cloud and customer-VPC deployment;
- self-hosted and on-premises deployment;
- fully air-gapped operation;
- high availability and disaster recovery;
- configurable data residency;
- HSM and KMS integrations;
- internal directory and identity integrations;
- custom receipt retention;
- customer-managed encryption;
- enterprise SSO and lifecycle management for platform operators;
- audit and compliance integrations;
- security embargo and coordinated vulnerability response;
- contractual uptime and support SLAs;
- dedicated architecture and onboarding support;
- custom profiles, adapters, and integration certification.

Self-hosted commercial functionality should be licensed annually. Local proof
verification remains unlimited.

## Packaging and illustrative pricing

Prices below are directional starting points, not a commitment. They should be
validated against actual product cost and buyer value.

### Community: free

- unlimited local verification;
- open protocol, verifier, SDKs, and corpus;
- public profiles and adapters;
- local authoring;
- basic MCP and deployment integrations;
- community support.

### Team: approximately $500–$1,000 per month

- managed authority workspace;
- private profiles and trusted configurations;
- MCP agent and server inventory;
- approval workflows;
- signed registry distribution;
- basic authority graph;
- receipt search with modest retention;
- a limited number of production environments;
- team support.

### Business: approximately $2,500–$7,500 per month

- multiple teams and environments;
- advanced delegation and approval workflows;
- authority-diff and widening analysis;
- deployment integrations;
- managed replay services;
- SIEM streaming;
- longer receipt retention;
- custom approval rules;
- enterprise identity integration;
- stronger availability and support SLA.

### Enterprise: approximately $75,000–$300,000 or more annually

- private-cloud, VPC, on-premises, or air-gapped deployment;
- high availability and disaster recovery;
- HSM, KMS, and internal signing integrations;
- custom data residency and retention;
- custom profiles and adapters;
- security embargo program;
- dedicated support and architecture reviews;
- professional onboarding;
- contractual SLA;
- unlimited local verification.

### Expansion units

Commercial tiers may scale through a combination of:

- protected production services;
- managed authority domains;
- active managed agents;
- production environments;
- authority administrators and approvers;
- receipt ingestion and retention;
- premium integrations;
- private deployment requirements.

Pricing must remain predictable. Avoid charging for every proof or every
verification invocation.

## What remains free and what becomes paid

The durable dividing line is:

> Verification is open. Organizational coordination is commercial.

### Free

- verify a proof;
- author a proof locally;
- implement a profile;
- implement a principal or evidence adapter;
- run the canonical corpus;
- integrate an individual service;
- operate without Auths Cloud;
- use the protocol in another conforming implementation.

### Paid

- coordinate approvals across people, workloads, and agents;
- distribute signed trust configuration across a fleet;
- manage grants across teams and environments;
- visualize reachable authority;
- detect dangerous delegation changes;
- operate managed replay infrastructure;
- store, analyze, and investigate receipts;
- integrate enterprise identity and signing systems;
- run the management platform privately;
- receive contractual support and security guarantees.

## Buyer map

### AI platform and security teams

Buy Auths MCP to constrain agents and provide defensible tool-call approval,
enforcement, and audit.

### Platform engineering

Buys Auths Authority and Auths Deploy to replace fragmented approval logic and
bind authorization to exact production operations.

### Infrastructure security

Buys trust management, authority analysis, replay protection, incident
investigation, and private deployment.

### Compliance and audit

Buys receipt retention, search, lineage, SIEM integration, and evidence
packages.

### Engineering leadership

Buys a consistent authorization primitive that prevents every service team
from rebuilding delegation, approval, and audit logic independently.

## Go-to-market sequence

### Stage 1: establish the open standard

- publish the protocol, verifier, SDKs, and corpus;
- make local integration excellent;
- demonstrate independent implementation parity;
- ship clear MCP and deployment examples;
- make the one-hour integration objective real.

### Stage 2: sell Auths MCP

Lead with one concrete problem:

> Secure MCP tool use without giving agents broad bearer credentials.

Offer open middleware and a hosted authority, approval, replay, and receipt
console. Land with an AI platform or security engineering team.

### Stage 3: expand into authority operations

Once multiple MCP servers or services use Auths, sell:

- fleet inventory;
- private trust and profile management;
- approval workflows;
- authority graph;
- widening detection;
- receipt investigations;
- enterprise integrations.

At this stage, Auths moves from a library to organizational infrastructure.

### Stage 4: sell Auths Deploy

Extend the same authority model into:

- production deployment;
- infrastructure mutation;
- administrative operations;
- secrets and data operations;
- incident response.

The buyer expands to platform engineering, infrastructure security, and
compliance.

### Stage 5: become the enterprise authority fabric

The long-term platform unifies exact authority across:

- agents;
- workloads;
- deployments;
- service-to-service operations;
- administrative actions;
- data operations;
- human approvals;
- machine delegation.

Auths then becomes the common proof-of-permission layer between principal
control and application execution.

## Revenue streams

The platform can support several complementary revenue streams:

1. **Managed-platform subscriptions**
   for Auths Authority, Auths Trust, Auths Observe, MCP, and deployment.

2. **Annual enterprise licenses**
   for VPC, private-cloud, on-premises, and air-gapped operation.

3. **Receipt ingestion and retention**
   for audit, investigations, and compliance.

4. **Premium integrations**
   for identity providers, KMS/HSM systems, CI/CD platforms, SIEM products,
   and internal enterprise systems.

5. **Support and security programs**
   including SLAs, security embargoes, architecture reviews, and incident
   response.

6. **Professional services**
   for initial authority modeling, profile development, integration, and
   deployment. Services should accelerate product adoption rather than become
   the core business.

7. **Certified ecosystem**
   for reviewed profiles, adapters, integrations, and eventual marketplace
   distribution.

## Economic advantages

Auths has an unusually attractive platform cost structure:

- customer services perform the high-volume verification work;
- the commercial platform is not on the synchronous decision path;
- paid operations are lower volume and higher value;
- receipt storage and analysis can be priced according to actual cost;
- offline and private deployments are natural rather than exceptional;
- one protocol supports several commercial verticals;
- the same authority graph expands across teams and services.

This permits strong software margins while providing customers with better
availability, privacy, latency, and vendor independence than a mandatory
hosted authorization API.

## Defensibility

The moat should not be a closed wire format. It should be the quality and
breadth of the operational system around an open standard:

- the most trusted reference implementation;
- the strongest canonical corpus and conformance program;
- the safest authority authoring and widening analysis;
- a large catalog of profiles and integrations;
- excellent cross-language developer experience;
- organizational authority and receipt graphs;
- deployment and MCP expertise;
- enterprise-grade private operation;
- accumulated operational knowledge about delegation and agent authority.

An open standard increases the value of this moat. Customers can trust the
primitive while choosing the best platform for operating it.

## Repository and product boundaries

This business model does not alter the three-repository architecture.

### `auths-proof`

Owns the open protocol kernel:

- specification and CDDL;
- canonical model and codec;
- pure verifier and ports;
- corpus and conformance;
- portable engine boundary;
- reference Rust API and WASM core;
- fuzz and architecture checks.

### `auths-proof-exchange`

Owns transport-neutral exchange:

- challenge and submission exchange;
- framing;
- typed channel observations;
- transport integrations;
- transport-invariance tests.

### `auths-proof-apps`

Owns downstream product and operational behavior:

- language wrappers and application integrations;
- profiles;
- MCP and deployment products;
- authority and trust management applications;
- runtime replay;
- receipts and observability;
- managed and private deployment;
- enterprise connectors.

Commercial packaging must not cause transport, runtime, application-profile,
or management logic to move into the proof kernel.

## External market references

Current authorization vendors demonstrate several parts of this commercial
pattern:

- [Cerbos Hub](https://docs.cerbos.dev/cerbos-hub/index.html) pairs an
  open-source local decision engine with a paid control plane for management,
  distribution, CI/CD, and audit.
- [Permit.io](https://www.permit.io/pricing) pairs local authorization
  components with paid operational, audit, enterprise, and private-deployment
  capabilities.
- [Permit MCP Gateway](https://www.permit.io/mcp-gateway/pricing) demonstrates
  an emerging paid category around agent authorization, approval, audit, and
  enterprise MCP security.
- [AuthZed SpiceDB Enterprise](https://authzed.com/products/spicedb-enterprise)
  demonstrates annual enterprise licensing for self-hosted authorization
  infrastructure and support.
- [WorkOS](https://workos.com/pricing) demonstrates independent monetization
  of enterprise connections, audit streaming, retention, and support.

Auths should use these as validation of the commercial shape, not as a product
ceiling. Its differentiation is portable cryptographic authority, exact-action
binding, offline verification, identity-method agnosticism, and execution from
sealed verified output.

## Success condition

The business model is working when:

- developers can adopt Auths Proof without permission or payment;
- one protected MCP server or deployment service provides immediate standalone
  value;
- teams pay to coordinate authority and approvals across several services;
- security teams rely on the authority graph and receipt history;
- enterprises pay for private operation, integrations, and guarantees;
- increasing enforcement volume makes Auths more valuable without increasing
  per-decision platform dependency;
- the open protocol becomes more trusted as the commercial platform becomes
  more capable.

The end state is not merely a successful authorization SDK. It is an enterprise
authority platform built on an open proof-of-permission standard.
