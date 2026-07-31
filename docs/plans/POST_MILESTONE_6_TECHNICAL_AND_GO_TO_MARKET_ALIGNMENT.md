# Post-Milestone-6 Technical and Go-to-Market Alignment

## Status and scope

Research and decision brief, current as of 2026-07-31.

This document maps the technical sequence in
`docs/target-state/POST_MILESTONE_6_PRODUCTIZATION_AND_RELEASE_PLAN.md` to the
working strategy in `docs/plans/GO_TO_MARKET_STRATEGY.md`. It does not authorize
or implement any post-Milestone-6 productization, release, hosted service,
commercial packaging, or go-to-market work.

The source strategy is a working-tree draft rather than a tracked release
artifact at the time of this review. Statements attributed to it are therefore
inputs to reconcile, not shipped-product facts or approved public claims.

The labels in this document are deliberate:

- **Repository fact**: evidenced by the repository at the reviewed revision.
- **External fact**: supported by a linked primary or authoritative source.
- **Recommendation**: a proposed decision, sequence, or target; it is not a
  statement of present capability.
- **Owner decision**: a choice that cannot be resolved from technical evidence
  alone.

## Executive conclusion

**Repository fact.** Milestones 0 through 6 are complete on `main`. The result
is a strong research and bounded-authorization base, but it is not yet a public
v1, audited production service, certified ecosystem, supported SDK product, or
commercial offering.

**Recommendation.** Preserve the post-Milestone-6 plan's assurance-first
sequence. The go-to-market strategy should begin design-partner recruitment and
developer discovery in parallel with review, but it must not place a production
TypeScript SDK, MCP flagship, certification claim, hosted product, compliance
claim, or SLA ahead of the release-candidate, assurance, audit, and runtime
gates that make those claims defensible.

The resulting order is:

```text
freeze semantics and produce an attestable RC
  -> publish one exact assurance and threat-model boundary
  -> independent formal, protocol, and stateful-execution review
  -> stabilize the thin waist and developer-preview TypeScript SDK
  -> productionize the enforcement runtime
  -> run profile conformance and restricted design-partner integrations
  -> operate the GitHub flagship
  -> unify the workbench and publish v1
  -> validate paid operational products
  -> expand domains only through the established profile process
```

Commercial discovery may run alongside the technical gates. Commercial
promises may not get ahead of them.

## Baseline: what is fact and what remains a hypothesis

| Statement | Classification | Correction or implication |
| --- | --- | --- |
| The bounded-authorization research program through Milestone 6 is complete. | Repository fact | This is the starting point, not the public-v1 finish line. |
| The repository currently declares `MIT OR Apache-2.0` and includes both license texts. | Repository fact | Any licensing change needs an ownership and contribution-rights review; the current dual license is already a genuine open-source boundary. |
| The verifier, formal evidence, seven domain verticals, conformance fixtures, and benchmark work exist. | Repository fact | Claims must stay scoped to the exact reviewed artifacts and assumptions. |
| A product-grade TypeScript SDK, MCP delegation application, platform custody providers, design-partner integrations, and commercial product are available. | Not a repository fact | These are proposed work in the strategy and local specifications, not shipped capabilities. |
| Fully local verification is a durable architecture constraint. | Repository fact and product constraint | Hosted coordination must remain optional and outside the local decision dependency. |
| Hosted and on-premises offerings are supported today. | Unsupported if phrased as present capability | The strategy chooses these as desired deployment forms; Phase 11 must prove them before they can be marketed as supported. |
| Auths is formally verified end to end. | Unsupported | The exact claim must separate Lean semantics, generated/refined Rust, bounded representations, trusted runtime components, and nondeterministic providers. |
| Auths is compliant, certified, audited, production-ready, or covered by an SLA. | Unsupported | Each term requires its own completed evidence and scope. None follows from Milestone 6 alone. |
| AI-agent framework builders and internal-agent teams are the first market. | Strategy hypothesis | Validate with design partners before treating this as customer fact or fixing packaging around it. |
| The first paid product and economic buyer are known. | False; intentionally unresolved | Do not invent pricing tiers or revenue commitments before commercial discovery. |

## Sequencing reconciliation

| Technical phase | Go-to-market work allowed at this gate | Work that must wait | Exit evidence used by the next gate |
| --- | --- | --- | --- |
| Phase 7: close and freeze | Recruit research reviewers; interview prospective design partners; publish no production claim. | SDK GA, hosted service, certification, SLA, consequential customer workflow. | Clean tag; reproducible source and evidence; SBOM; signed or attestable artifacts; immutable semantic IDs. |
| Phase 8: exact assurance claim | Test positioning against the exact claim; prepare security FAQ and threat-model language. | “Formally verified system,” provider-correctness claims, production assurance packages. | Every public claim maps to a theorem, test, audit artifact, or explicit assumption. |
| Phase 9: independent review | Offer a restricted developer preview against non-production or reversible effects; collect usability evidence. | Production readiness, unqualified security claims, paid assurance, public v1. | Independent findings, remediation evidence, retest, and no unresolved critical findings. |
| Phase 10: stable thin waist | Build the TypeScript developer preview and MCP reference vertically; start measured integrations. | Broad adapter catalogue, universal operation dispatcher, general CLI, stable-v1 compatibility promise. | Versioned SDK contract, cross-language fixtures, denial semantics, clean-checkout examples, external-user integration evidence. |
| Phase 11: production runtime | Pilot customer-operated deployments; validate operator workflows, tenant/data boundaries, and recovery. | Multi-tenant managed execution, external SLA, regulated production claims. | Contention, crash, interruption, credential-broker, backup/restore, reconciliation, and chaos evidence. |
| Phase 12: profile conformance | Publish conformance tools and results; qualify maintained profiles. | A trademarked certification program before governance and independent implementations exist. | Versioned suite, profile inventory, reproducible results, exact live evidence. |
| Phase 13: flagship workflow | Operate the GitHub draft-PR workflow with a restricted design partner after review and runtime gates. | Financial or infrastructure flagship before its separate risk controls and review. | Continuous operation, recovery, rotation, replay, and no-agent-credential evidence. |
| Phases 14-15: workbench and v1 | Public launch, stable documentation, reproducible packages, evidence-led enterprise evaluation. | Claims beyond the published assurance scope; mandatory hosted verification. | Reproducible public v1, operator guide, benchmark method, conformance and audit evidence. |
| Phase 16: domain expansion | Add domains only when buyer evidence and a new semantic shape justify them. | Provider-logo expansion or shared-core changes for convenience. | A new vertical passes the established profile and release gates without weakening core. |

### Corrections to the current strategy sequence

1. **Recommendation.** Replace “publish the flagship MCP delegation demo” as
   the first external distribution step with “publish an explicitly labeled
   developer preview after the RC and exact-claim gates.” A polished demo can
   precede completion of all organization-level compliance work, but it cannot
   precede the semantic freeze it claims to demonstrate.
2. **Recommendation.** Treat the TypeScript SDK as the first developer product,
   not the first technical phase. It belongs after the thin-waist contract is
   reviewable and must remain a binding over the Rust semantics rather than a
   second policy implementation.
3. **Recommendation.** Recruit design partners during independent review, but
   limit early effects to sandboxes, reads, test modes, or reversible draft
   operations. Consequential production effects begin only after the relevant
   review and Phase 11 recovery gates.
4. **Recommendation.** Rename Phase 12's initial output from “certification” to
   “profile conformance qualification.” A public certification mark and
   governance program comes later, after stable profiles and independent
   implementations exist.
5. **Recommendation.** Decide the license and package boundary before the first
   external package publication. Do not defer it until commercial discovery.
6. **Recommendation.** Produce provenance, SBOMs, checksums, and verification
   instructions at the RC gate. They are release inputs, not enterprise
   add-ons.
7. **Recommendation.** Do not publish hosted-service SLOs, RPO/RTO promises, or
   support tiers until the deployment model, data boundary, operating history,
   and staffing model are known.

## Open-core and commercial licensing boundary

### External facts

- The [Open Source Definition](https://opensource.org/osd) requires free
  redistribution, derived works, and no discrimination against fields of
  endeavor. A source-visible license that restricts commercial use or a field
  of use must not be represented as open source.
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0.html) grants
  broad copyright rights and an express contributor patent license. The
  repository's current `MIT OR Apache-2.0` expression allows recipients to
  choose either license.
- The European Commission explains that the Cyber Resilience Act has a
  specific regime for free and open-source software, but commercially supplied
  software and qualifying open-source stewards can still have obligations.
  Open source is not a blanket exclusion from product regulation. See the
  Commission's [CRA open-source guidance](https://digital-strategy.ec.europa.eu/en/policies/cra-open-source).

### Recommended boundary

Keep the following under the repository's existing open-source license unless
an IP lawyer and the owner approve a prospective change before outside
contributions begin:

- protocol, canonical formats, verifier, proof kernel, and formal artifacts;
- local Rust runtime required to decide and enforce exact actions safely;
- the TypeScript SDK path required to author, delegate, verify, and inspect
  locally;
- profile SDK, conformance kit, adversarial fixtures, and release evidence;
- MCP reference profile and at least one complete open reference deployment;
- local receipt inspection, recovery, and operator tooling necessary to avoid
  a hosted dependency.

Commercial code may contain:

- hosted organization, trust, policy-distribution, and fleet operations;
- enterprise control-plane deployment and lifecycle automation;
- organization workflows, enterprise RBAC, SSO administration, retention,
  search, legal hold, and export;
- managed KMS/HSM/SIEM/workflow integrations and deployment assistance;
- support contracts, training, review facilitation, and customer-specific
  assurance mappings.

The boundary must be architectural as well as contractual:

```text
commercial control plane
       |
       | versioned open protocol and packages only
       v
open local verifier/runtime ----> profile-owned provider gateway
```

Commercial modules may depend on public interfaces. Open packages must not
import commercial modules, require a license check for safe local operation, or
withhold security fixes. Artifact signatures, SBOMs, vulnerability notices,
and conformance evidence for open releases are part of release integrity and
must not be paywalled.

**Owner decision.** Keep `MIT OR Apache-2.0` or move future releases to
Apache-2.0 only. The recommended default is to keep the current dual license
through v1 because it is already declared and avoids a needless relicensing
event. Before accepting material external contributions, adopt an explicit
inbound policy, DCO or CLA choice, trademark policy, and contributor ownership
record with counsel.

## Artifact distribution and provenance

### External facts

- [SLSA 1.2](https://slsa.dev/spec/v1.2/) defines source and build tracks with
  increasing security guarantees. Build L1 requires provenance, L2 requires
  signed provenance from a hosted build platform, and L3 adds a hardened build
  platform; SLSA does not assert that the artifact is defect-free.
- GitHub artifact attestations can bind an artifact digest to its repository,
  workflow, commit, and build identity, and can attach an SBOM. GitHub warns
  that attestations must be verified and are not a guarantee that software is
  secure. See [GitHub artifact attestations](https://docs.github.com/en/actions/concepts/security/artifact-attestations).
- [SPDX 3.0](https://spdx.dev/use/specifications/) is the current SPDX document
  version, while SPDX is also published as ISO/IEC 5962:2021.
- The [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)
  supports content-addressed distribution of container images and other
  content; OCI 1.1 referrers can associate signatures, SBOMs, and other
  artifacts with a subject digest.
- npm trusted publishing uses short-lived OIDC credentials and automatically
  publishes provenance for eligible public packages from supported hosted CI.
  See [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/).
- crates.io supports OIDC-based trusted publishing from GitHub Actions, avoiding
  a long-lived release token. See the [Rust project's announcement](https://blog.rust-lang.org/2025/07/11/crates-io-development-update-2025-07/).
- [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) is a secure
  development practice framework and common acquisition vocabulary. It
  complements, rather than replaces, provenance and product-security review.

### Recommended release matrix

| Artifact | Distribution | Required evidence |
| --- | --- | --- |
| Source and formal evidence | Git tag plus release archive | Commit-bound release manifest, checksums, exact toolchain/lockfiles, clean-checkout reproduction instructions. |
| Rust crates | crates.io | Package dry-run, locked release workflow, OIDC trusted publishing, source link, license metadata, digest in release manifest. |
| TypeScript SDK | npm | OIDC trusted publishing, npm provenance, exact Rust/WASM binding digest, canonical cross-language fixtures. |
| Enforcement runtime image | GHCR or another OCI registry | Immutable digest, multi-platform manifest if supported, SBOM, build provenance, signature/attestation, rollback version. |
| Native binaries and WASM | GitHub release | Checksums, SBOM, provenance attestation, signature or Sigstore bundle, platform/toolchain record. |
| Conformance and assurance bundle | GitHub release and OCI artifact | Profile/evaluator versions, fixture digests, theorem/test manifest, reviewer report references, verification command. |

**Recommendation.** Target SLSA Build L2 for the first RC and assess the build
platform against Build L3 before public v1. Generate the SPDX SBOM inside the
release build, attach it to the exact artifact digest, and make verification a
documented consumer command. Use reproducibility as an additional check, not as
a substitute for signed provenance. Separate the release workflow from ordinary
CI, protect its environment and tags, require human approval, and remove
long-lived registry publication tokens where trusted publishing is available.

## Independent review and audit strategy

### External facts

- [OWASP ASVS 5.0](https://owasp.org/www-project-application-security-verification-standard/)
  provides testable requirements and a basis for specifying application
  security verification. It does not review Lean refinements, provider
  semantics, or distributed reservation correctness by itself.
- AICPA's [Trust Services Criteria](https://www.aicpa-cima.com/resources/download/2017-trust-services-criteria-with-revised-points-of-focus-2022)
  cover controls relevant to security, availability, processing integrity,
  confidentiality, and privacy. A SOC 2 examination concerns a service
  organization's system and controls; it is not a certification of protocol
  correctness.
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001) specifies
  requirements for an organizational information security management system.
  It is not a proof that an individual product has no security defects.

### Recommended tracks and gates

1. **Assurance-boundary review.** An independent formal-methods reviewer checks
   theorem statements, Aeneas qualification, Rust closure, axioms, and the
   public assurance manifest after Phase 8.
2. **Protocol and implementation review.** A Rust/cryptography reviewer checks
   canonicalization, parsing bounds, attenuation, configuration binding,
   replay, unsafe code, dependency use, and receipt commitments.
3. **Stateful execution review.** A distributed-systems reviewer checks
   reservations, claims, credential ordering, crash points, ambiguous outcomes,
   reconciliation, storage isolation, and recovery.
4. **Deployment security assessment.** After Phase 11 exposes deployable
   surfaces, perform architecture review, ASVS-scoped application testing,
   dependency/supply-chain review, and penetration testing of the actual
   operator and hosted surfaces.
5. **Operational assurance.** Begin SOC 2 readiness only when a service scope,
   controls, owners, evidence collection, vendors, and incident process exist.
   Pursue a report or ISO/IEC 27001 certification only when design-partner
   procurement evidence justifies it.

Every finding must have an owner, severity, affected claim, regression
evidence, remediation commit, and independent retest. Critical findings block
release. High findings block the affected production claim until resolved or
formally accepted by the owner with a bounded exposure and deadline. Audit
reports should state exact revision and scope; “audited” must never float across
later unreviewed releases.

## Deployment and tenant threat models

### External facts

- [NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final) rejects
  implicit trust based only on network location or ownership and focuses
  protection on resources. [NIST SP 800-207A](https://csrc.nist.gov/pubs/sp/800/207/a/final)
  further applies granular application/service identity policies to
  cloud-native systems.
- The [OWASP multi-tenant security guidance](https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html)
  identifies cross-tenant leakage, impersonation, broken isolation, noisy
  neighbors, shared-resource poisoning, and audit gaps, and recommends binding
  verified tenant context across storage, cache, queues, logs, and rate limits.
- [SPIFFE](https://spiffe.io/docs/latest/spiffe/concepts/) provides workload
  identity, but explicitly assumes sufficient workload isolation to prevent
  credential theft. Identity is an input to Auths; it is not the exact-action
  authority decision or the isolation boundary by itself.

### Recommended deployment classes

| Class | Trust and data boundary | Recommendation |
| --- | --- | --- |
| Embedded verifier | Runs in the customer's process; no Auths service dependency. | v1 baseline. Define compatibility and security-update commitments, not an availability SLA. |
| Customer-operated enforcement runtime | Credentials, reservation state, and effects remain in the customer's environment. | First production deployment. Provide hardened defaults, recovery guides, and explicit operator responsibilities. |
| Hosted control plane plus customer-near executor | Auths hosts organization/configuration metadata; credentials and consequential execution remain near the provider boundary. | Preferred first commercial architecture after Phase 11. Hosted outage must not silently widen authority. |
| Multi-tenant hosted executor | Auths holds or brokers multiple tenants' consequential credentials and state. | Defer. It has the largest blast radius and requires a separate threat model, isolation tests, compliance scope, incident response, and staffing. |

The threat model must explicitly cover:

- malicious or compromised agent, SDK caller, executor, operator, tenant admin,
  control-plane employee, CI workflow, and dependency;
- tenant-context forgery and confusion across API, database, cache, queue,
  object store, logs, metrics, support tooling, and backups;
- replay, rollback, stale policy/evaluator distribution, downgrade, and split
  brain;
- credential theft before request, leakage through diagnostics, and provider
  token scope wider than the verified command;
- denial-of-service and capacity exhaustion without converting failure into an
  allow;
- receipts and evidence as sensitive data, including retention, residency,
  deletion, export, and legal hold;
- compromised build or update channel and malicious-but-valid artifacts;
- fail-closed, last-known-good, and recovery behavior for every dependency;
- customer/operator responsibility for host, network, identity, provider, and
  backup controls.

No hosted plane may be a mandatory verifier phone-home path. A cached policy may
be used only under an explicit version, validity window, revocation model, and
required/executed configuration contract; absence or ambiguity cannot widen
authority.

## SLO, RPO, RTO, and support commitments

### External facts

- Google's [SRE guidance](https://sre.google/sre-book/service-level-objectives/)
  distinguishes an SLI (measurement), SLO (target), and SLA (agreement with
  consequences). It recommends choosing a small set of user-relevant
  indicators and avoiding 100% targets.
- Google's [disaster-recovery planning guide](https://docs.cloud.google.com/architecture/dr-scenarios-planning-guide)
  notes that lower RTO and RPO targets generally cost more and must be chosen
  from business impact, not copied from another service.

### Recommended commitment ladder

1. **Before hosted pilots:** define SLIs only: correct allow/deny/indeterminate
   outcomes, decision latency percentiles, policy propagation, reservation
   contention, reconciliation age, receipt durability, backup success, and
   restore time.
2. **During design-partner pilots:** operate internal SLOs and error budgets;
   exercise restore and incident procedures. Keep these explicitly
   non-contractual.
3. **Before general availability:** set external SLOs from measured user needs
   and sustained operating data. Use a stricter internal target as a safety
   margin.
4. **Only with legal and staffing approval:** offer an SLA with service-credit
   or other consequences and support response commitments.

**Recommended provisional design objectives, not promises:** design the first
hosted control plane for 99.9% monthly availability, policy propagation p95 no
worse than 60 seconds, metadata/receipt RPO no worse than 5 minutes, and tested
RTO no worse than 4 hours. Recalculate all four after partner impact analysis
and restore exercises. The local verifier and an already-authorized
customer-near executor must not fail merely because the optional hosted plane
is unavailable, subject to explicit freshness and revocation rules.

Do not sell 24x7 P1 support until an actual rotation, escalation authority,
observability, and incident process exist. The recommended first support offer
is business-hours engineering support for pilots, followed by separately
priced 24x7 coverage only when staffing and design-partner demand justify it.

## Profile conformance and certification

### External facts

- The [OpenID Foundation certification program](https://openid.net/certification/)
  separates free conformance testing from certification and supports published
  self-certification; independent certification services are a further layer.
- The [CNCF Kubernetes conformance program](https://www.cncf.io/training/certification/software-conformance/)
  uses a common open-source test application, submitted results, review,
  version currency, and a certification mark to make interoperability claims
  confirmable.

### Recommended three levels

1. **Conformance tested:** anyone can run the versioned open suite and publish
   results bound to an artifact digest.
2. **Maintained profile:** the Auths project maintains the profile inventory,
   implementation, live evidence, security contact, compatibility window, and
   passing results for the current version.
3. **Certified implementation:** a governed program reviews submitted evidence,
   controls mark usage, publishes a registry, defines renewal and revocation,
   and discloses whether the review is self-attested or independent.

Phase 12 should deliver levels 1 and 2. Launch level 3 only after at least two
independently maintained implementations or design-partner deployments pass the
same stable suite. The owner must approve governance, fees, liability language,
trademark rules, reviewer independence, renewal cadence, and revocation. A
profile can be conformant without its provider being correct, available, or
covered by Auths' formal proof; the public mark must preserve that boundary.

## Design-partner validation

There is no external technical standard that determines the correct number of
design partners or proves product-market fit. The following are recommendations
and must be treated as product experiments, not market facts.

Recruit three to five partners across the two proposed user types, with at
least two capable of maintaining their integration without the core author.
Use a written charter that defines the permitted environment, effect risk,
data handling, support window, feedback rights, and explicit absence of
production or compliance claims.

Measure:

- time from clean install to first locally verified action;
- time and concepts required for parent-to-child delegation;
- percentage who correctly diagnose a deliberate denied call;
- adapter code and provider-specific code that could not remain vertical;
- forbidden-side-effect tests, restart behavior, and receipt comprehension;
- operator time for deploy, upgrade, backup, restore, rotation, and incident
  diagnosis;
- repeated requests for hosted coordination, on-premises control, retention,
  integrations, and support;
- named buyer, procurement trigger, budget source, and willingness to pay for a
  specific operational outcome.

The design-partner gate is met when one external maintainer can upgrade and
operate an integration, multiple partners use actual delegation rather than
identity-only verification, at least one reviewed flagship workflow runs under
real operational conditions, and repeated needs identify one paid product.
Interviews, stars, downloads, demos, and letters of intent do not substitute for
those behaviors.

## Enterprise compliance positioning

### External facts

- The EU [Cyber Resilience Act](https://eur-lex.europa.eu/eli/reg/2024/2847/2024-11-20/eng)
  applies cybersecurity and vulnerability-handling obligations to products with
  digital elements placed on the EU market. The Commission states that Article
  14 reporting obligations apply from 2026-09-11 and the main obligations from
  2027-12-11. See the current [implementation timeline](https://digital-strategy.ec.europa.eu/en/factpages/cyber-resilience-act-implementation).
- SOC 2 evaluates scoped service-organization controls against selected Trust
  Services Criteria. ISO/IEC 27001 evaluates an organization's ISMS. Neither
  inherits automatically from a cloud provider, dependency, formal proof, or
  penetration test.
- NIST SSDF, SLSA, SPDX, ASVS, independent security review, and the Auths
  assurance manifest provide different evidence. None should be collapsed into
  the word “compliant.”

### Recommended positioning

Use “evidence-ready bounded authorization” and describe the exact evidence
available. Do not say “SOC 2 compliant,” “ISO compliant,” “CRA certified,”
“formally verified platform,” or “zero-trust compliant.” Say instead that the
product can support named customer controls, and publish a scoped mapping only
after counsel or the relevant assessor reviews it.

Begin CRA applicability analysis now, before EU commercial distribution and
before the 2026-09-11 reporting date. The owner must determine with EU counsel
whether each open package, commercial artifact, hosted service, and steward
role is in scope; who is the manufacturer or steward; the support period; the
vulnerability coordinator; and the reporting process. This document is not
legal advice.

The recommended assurance order is product security and CRA readiness first,
SOC 2 readiness when a hosted service and buyer requirement exist, and
ISO/IEC 27001 only when the business needs a broader ISMS credential. Public
sector, financial-sector, healthcare, FedRAMP, DORA, HIPAA, or similar packages
should remain out of scope until a qualified buyer and jurisdiction require
them.

## Incumbent and adjacent product categories

Auths should not claim that identity, fine-grained authorization, workload
identity, secrets management, gateways, or agent-security products are
obsolete. They provide inputs and adjacent controls. The differentiation is the
combination of delegable bounded authority, exact-action commitments,
credential ordering, replay/recovery, and receipts at the effect boundary.

| Category | Representative current products or standards | What they establish | Auths relationship |
| --- | --- | --- | --- |
| Fine-grained authorization and policy decision points | [Amazon Verified Permissions](https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/what-is-avp.html), [Cedar](https://docs.cedarpolicy.com/), [Authzed/SpiceDB](https://authzed.com/pricing), [Cerbos](https://www.cerbos.dev/pricing) | Whether a principal may take an action on a resource under policy; managed and self-hosted forms exist. | Adjacent and sometimes composable. Auths must prove its additional delegation, exact-effect, credential, state, and receipt boundary rather than compete on “authorization” as a generic word. |
| Workload identity | [SPIFFE](https://spiffe.io/docs/latest/spiffe-specs/) and SPIRE | Portable workload identity and short-lived identity documents. | Identity may anchor a principal or executor; it does not replace bounded action authority. |
| Secrets and privileged credential management | [HashiCorp Vault](https://developer.hashicorp.com/vault/docs) and cloud KMS/HSM systems | Store, issue, rotate, lease, or protect credentials and keys. | Credential broker input. Auths should request credentials only after the exact action is authorized and should narrow provider scope where possible. |
| API gateways, service mesh, and policy engines | NIST SP 800-207A deployment components and existing gateway/mesh products | Network/application enforcement, service identity, routing, and policy hooks. | Potential enforcement location; network position alone is not authority proof. |
| Agent/MCP security and observability | [Oso for Agents](https://www.osohq.com/pricing) and emerging platform controls | Session audit, risky-tool detection, inventory, alerts, and governance. | Strongest adjacent category for the proposed wedge. Auths should lead with deterministic pre-effect authority and receipted execution, not generic agent monitoring. |

## Pricing and packaging implications

### External market facts

- AWS Verified Permissions meters authorization and policy-management API
  requests; its [current pricing](https://aws.amazon.com/verified-permissions/pricing/)
  includes per-request charges.
- [Cerbos](https://www.cerbos.dev/pricing) keeps its policy decision point open
  source and charges its hosted control plane primarily by monthly active
  principals, with enterprise self-hosting, support, and retention options.
- [Authzed](https://authzed.com/pricing) offers open-source SpiceDB plus
  usage/capacity-priced cloud, self-hosted enterprise, dedicated
  infrastructure, support, signed releases, SBOMs, and compliance evidence.
- [Oso for Agents](https://www.osohq.com/pricing) currently publishes
  per-human-user pricing for developer and growth plans and custom enterprise
  packaging.

These facts show several accepted metrics; they do not prove which one fits
Auths.

### Recommended packaging hypothesis

| Package | Included | Recommended metric |
| --- | --- | --- |
| Community | Open protocol, verifier/runtime, SDKs, conformance, reference profiles, local receipts and recovery. | Free under the open-source license; no toll on local verification or security updates. |
| Managed operations | Optional hosted organization/configuration plane, fleet inventory, policy lifecycle, receipt retention/search, integrations, and business-hours support. | Base organization fee plus managed environments/executors and retention; include generous event volume. |
| Enterprise self-managed | Commercial control plane, deployment automation, SSO/admin governance, enterprise integrations, retention/residency options, and support. | Annual platform subscription plus deployment capacity and support level. |
| Assurance and services | Architecture review, deployment assistance, training, customer control mapping, and facilitated independent review. | Fixed-scope services or annual support; never sell access to release evidence required to trust open artifacts. |

Avoid per-local-verification pricing: it conflicts with offline verification,
creates a toll at the safety boundary, and makes cost scale with correct use.
Avoid choosing per-agent, per-principal, per-human-seat, per-action, or
per-receipt pricing until design partners reveal which unit tracks customer
value without discouraging safe enforcement. Do not publish price points before
commercial discovery; competitor prices are anchors, not evidence of
willingness to pay for Auths.

## Open Questions

The following decisions remain with the owner. Each row includes the best
evidence-backed default, but the recommendation is not an approval.

| Owner decision | Recommended default | Decision deadline or gate |
| --- | --- | --- |
| Open-source license for v1 | Keep `MIT OR Apache-2.0`; do not introduce field-of-use restrictions into the open core. | Before Phase 7 RC metadata is frozen. |
| Inbound contribution policy | Choose DCO or CLA with counsel; record copyright and patent authority before material external contributions. | Before public contributor recruitment. |
| Exact commercial package/repository boundary | Keep all safety-critical local operation and release evidence open; isolate optional organizational operations behind versioned public interfaces. | Before first commercial implementation or external SDK publication. |
| Trademark and certification marks | Reserve Auths marks separately from code rights and publish neutral usage rules. | Before public certification or partner co-marketing. |
| Artifact catalogue and registries | crates.io, npm, GHCR/OCI, GitHub release, and one digest-bound assurance bundle. | Phase 7 planning. |
| Supply-chain target | SLSA Build L2 for RC; assess and target L3 for public v1; SPDX SBOM and consumer verification for every executable artifact. | Phase 7 exit gate. |
| CRA role and scope | Obtain EU counsel opinion for manufacturer, steward, hosted service, and package roles; establish reporting ownership immediately. | Before EU commercial distribution and before 2026-09-11 reporting obligations could apply. |
| First production deployment | Customer-operated executor with optional hosted coordination; defer multi-tenant hosted credentials/execution. | Phase 11 architecture freeze. |
| Hosted data boundary | Keep provider credentials and consequential execution customer-near; minimize hosted receipts and define retention/residency/deletion. | Before hosted design-partner data is accepted. |
| External SLO/SLA | Run internal SLOs first; no SLA until measured operation, recovery exercises, legal terms, and staffing exist. | Before hosted GA contract. |
| RPO/RTO | Use 5-minute RPO and 4-hour RTO only as provisional design objectives; revise from customer impact and tested restores. | Phase 11 exit gate and every material architecture change. |
| Support coverage | Business-hours pilot support first; 24x7 only with funded rotation and enterprise demand. | Before paid support contract. |
| Independent audit firms and budget | Separate formal, Rust/protocol, stateful execution, and deployed-application scopes; require independent retest. | Engage during Phases 7-8; complete affected reviews before production claims. |
| SOC 2 or ISO/IEC 27001 | SOC 2 readiness only after hosted scope and buyer evidence; ISO/IEC 27001 only if broader procurement demand justifies it. | Commercial discovery, before claiming either. |
| Profile program governance | Ship open conformance first; defer certification mark until stable versioned suite plus two independent implementations. | Phase 12. |
| Design-partner cohort | Three to five partners, at least two external maintainers, restricted effects until review/runtime gates. | Recruit during Phase 9; production flagship after Phase 11. |
| First economic buyer and paid product | Keep unresolved until repeated operational needs identify both buyer and budget. | Stage 5 commercial discovery. |
| Pricing metric and price points | Test managed environment/executor and retention/support packaging; avoid per-local-verification tolls. | After at least three real integrations and willingness-to-pay interviews. |
| Public claim language | Use the Phase 8 assurance manifest as the only source of security claims and date every audit scope. | Before any public developer preview, website, or sales collateral. |

## Program gate

No post-Milestone-6 implementation should begin merely because this document
recommends it. The owner must first approve the relevant open questions, create
the required implementation plan and PR boundaries, and preserve the existing
rule that provider/domain behavior stays outside shared/core code.

The go-to-market strategy becomes execution-ready only when its “decided” list
distinguishes architecture commitments from shipped capabilities, its first
external demo is subordinated to the RC and exact-claim gates, and its
commercial, compliance, certification, availability, and pricing language is
conditioned on the evidence above.
