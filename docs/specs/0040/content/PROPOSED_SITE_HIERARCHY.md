# Proposed Auths Documentation Hierarchy

## Routing rule

Every public page has one primary owner among the six top-level sections. Its
canonical route begins with that section's prefix. Cross-topic links are
allowed only inside an explicitly labelled **Related topics** block; they are
never used as a substitute for the current section's missing content.

Reference and Assurance are cross-cutting utilities. They keep their own
namespaces and navigation, but every primary section links to the exact utility
page it needs—not to a generic utility landing.

## 1. Get started

```text
/get-started                                  landing and path chooser
├── /prerequisites                            supported runtimes and inputs
├── /choose                                   deterministic integration chooser
├── /quickstarts                              tested-project index
│   ├── /local-rest-effect                    first in-process effect
│   ├── /runtime-effect                       first HTTPS runtime effect
│   ├── /agent-delegation                     first delegated tool
│   ├── /approved-plan                        first exact approved plan
│   ├── /offline-verification                 first effect-free verification
│   ├── /recovery                             first recoverable execution
│   └── /identity-swap                        first cryptographic-suite swap
├── /paths                                    outcome-path index
│   ├── /application                          protect an application effect
│   ├── /agent                                delegate to an agent
│   ├── /runtime                              deploy the runtime boundary
│   ├── /verification                         verify without executing
│   └── /cross-company                        independent organizations
├── /evaluate                                 deterministic evaluation plan
└── /adoption                                 incremental-adoption index
    ├── /plan                                 privacy-safe inventory
    ├── /signed-requests                      compose existing signatures
    ├── /oauth-oidc                           retain login/session identity
    ├── /api-keys                             close ambient credentials
    ├── /cloud-iam                            compose workload IAM
    ├── /policy-engines                       compose Cedar/OPA/ReBAC
    ├── /capabilities                         bridge UCAN/Biscuit/macaroons
    ├── /approvals                            bind existing approval systems
    ├── /shadow-mode                          compare without effects
    └── /cutover                              enforce and roll back one effect
```

Left-nav groups: **Choose a path**, **Quickstarts**, **Adopt incrementally**,
**Next steps**.

## 2. Identity & trust

```text
/identity-trust                               landing
├── /how-it-works                             identity versus authority tour
├── /identity-sources                         source chooser
│   ├── /raw-public-keys                      standalone labelled key evidence
│   ├── /oauth-oidc                           user/session identity
│   ├── /spiffe                               workload identity
│   └── /application-resolvers                application-owned resolution
├── /cryptographic-suites                     suite chooser
│   ├── /ed25519                              maintained adapter
│   ├── /p256                                 maintained proof of agility
│   └── /custom-and-post-quantum               application adapters and limits
├── /trust-policy                             roots, issuers, and assurance
├── /exchange-public-identity                 transport-neutral exchange
├── /key-and-root-rotation                    overlap, rollback, recovery
├── /verification-context                     exact trusted-context inputs
└── /testing                                   unknown suite, wrong root, mismatch
```

Left-nav groups: **Understand**, **Identity sources**, **Cryptography**,
**Operate trust**, **Test**.

## 3. Authority

```text
/authority                                    landing
├── /model                                    actor/action/authority/outcome/receipt
├── /create                                   author exact authority
├── /constraints                              action, resource, time, use, budget
├── /delegate                                 attenuation and critical extensions
│   ├── /depth-and-chain                      multi-hop boundaries
│   └── /widening-failures                    adversarial cases
├── /lifecycle                                lifecycle index
│   ├── /validity-and-expiry                  temporal bounds
│   ├── /revocation-and-status                lifecycle evidence
│   ├── /uses-and-replay                      exact-use accounting
│   └── /budgets                              budget algebra and state
├── /plans                                    ordered plan semantics
│   └── /approvals                            transaction-bound approvals
├── /execute                                  sealed command and closed gateway
├── /resume                                   recovery without fresh retry
├── /verify                                   effect-free verification
├── /receipts                                 evidence model
│   └── /disclosure                           opaque, summary, authorized full
└── /profiles                                 domain semantics and profile kit
```

Left-nav groups: **Model**, **Author and narrow**, **Lifecycle**, **Execute and
recover**, **Verify and inspect**, **Profiles**.

## 4. Agents

```text
/agents                                       landing and use-case chooser
├── /how-auths-works                          agent-specific architecture
├── /quickstart                               executable one-tool delegation
├── /delegation                               exact scope and prohibited action
├── /approved-plans                           multi-party exact plan
├── /multi-agent                              attenuated handoffs
├── /mcp                                      MCP index
│   ├── /client                               use Auths from an agent harness
│   ├── /protect-server                       closed execution for MCP tools
│   ├── /tool-profiles                        canonical tool actions
│   └── /transport-boundary                   MCP success is not authority
├── /identity                                 agent/workload identity composition
├── /skills-and-plugins                       maintained tooling and provenance
├── /production-patterns                      state, custody, gateway ownership
└── /testing                                  widening, substitution, uncertainty
```

Left-nav groups: **Start**, **Delegate**, **MCP**, **Compose**, **Operate and
test**.

## 5. Production operations

```text
/operations                                   landing and deployment chooser
├── /evaluate-locally                         production-shaped local exercise
├── /deploy-runtime                           deployment topology and readiness
├── /configure                                configuration index
│   ├── /durable-state                        replay/use/budget/recovery store
│   ├── /custody                              KMS/HSM/application signer
│   ├── /trust-and-profiles                   roots, suites, profiles
│   └── /provider-gateways                    closed credential boundary
├── /observability                            metrics, logs, traces, redaction
├── /execution-lifecycle                      state-machine tour
├── /recovery-and-reconciliation              retry/resume/reconcile decision tree
├── /backup-and-restore                       semantic restore exercise
├── /upgrade-and-rollback                     exact release promotion
├── /receipt-retention                        retention and bounded disclosure
├── /security-checklist                       deployment hardening
└── /incidents                                runbook index
    ├── /state-loss                           fence, restore, reconcile
    ├── /signer-outage                        preserve verification-only paths
    ├── /trust-root-error                     rollback and re-evaluate
    ├── /provider-unknown                     stop fresh retry, reconcile
    ├── /receipt-disclosure                   contain without deleting evidence
    └── /compromised-credential               revoke, rotate, reconcile
```

Left-nav groups: **Deploy**, **Configure**, **Observe**, **Recover**, **Maintain**,
**Incident response**.

## 6. Developers

```text
/developers                                   landing
├── /quickstarts                              developer-oriented catalog/index
├── /sdks                                     SDK chooser
│   ├── /rust                                 native SDK orientation
│   ├── /typescript                           product SDK orientation
│   ├── /python                               product SDK orientation
│   └── /parity                               shared operation/outcome mapping
├── /runtime-api                              Runtime API orientation
├── /cli                                      CLI orientation and installation
├── /testing                                  fixture and outcome catalog
├── /errors                                   closed-outcome and error hub
├── /versioning                               prelaunch and release contracts
├── /integrations                             composition index
│   ├── /identity-and-trust                   OIDC, SPIFFE, keys, resolvers
│   ├── /policy                               Cedar, OPA, ReBAC
│   ├── /cloud-iam                            provider identity and credentials
│   ├── /transport                            HTTPS, Iroh, queues
│   ├── /capabilities                         UCAN, Biscuit, macaroons
│   └── /profile-kit                          application-owned profiles
├── /extension-kits                           ports, adapters, conformance
├── /examples                                 source-at-release catalog
└── /releases                                 changelog and support matrix
```

Left-nav groups: **Start building**, **SDKs**, **Runtime and CLI**, **Test and
debug**, **Integrate and extend**, **Releases**.

## Cross-cutting utility hierarchies

These do not compete with the six product sections. They are exact lookup and
evidence destinations.

```text
/reference
├── /sdk
│   ├── /rust
│   ├── /typescript
│   └── /python
├── /runtime-api
├── /cli
├── /profiles
├── /errors
├── /schemas
├── /evidence
└── /manifest.json

/assurance
├── /semantics
├── /authority
├── /execution
├── /disclosure
├── /cross-language
├── /formal
├── /adversarial
├── /supply-chain
└── /limitations
```

## Required page relationships

Every non-landing page renders:

1. global top navigation;
2. the complete left navigation for its owning section;
3. breadcrumbs from section landing to current page;
4. previous and next pages within its local sequence;
5. page and section Markdown actions;
6. related topics, explicitly labelled as cross-topic;
7. source/release/scenario provenance where applicable; and
8. a next action that remains in the owning section unless the journey is
   complete.

