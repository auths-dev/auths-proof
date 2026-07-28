# Auths domain priority ranking

Status: Product research  
Date: 2026-07-28  
Scope: Candidate demonstrations and vertical product packages after the GitHub and Radicle issue-workflow demos

## Decision

The next four Auths domains should be:

1. Kubernetes workload rollouts.
2. OpenTofu saved-plan application.
3. PostgreSQL bounded data changes.
4. Stripe refunds.

This document ranks ten future domains. GitHub and Radicle are excluded because their specifications and demonstrations already exist.

The first four are intentionally diverse. Together, they show that the same Auths core can protect:

- a production workload;
- an infrastructure plan;
- a database mutation; and
- a movement of money.

That is a stronger product argument than building four more source-control integrations.

## What is being ranked

A “domain” here is not an entire vendor API. It is one narrow, consequential operation with:

- a canonical action that can be committed to before execution;
- fresh evidence that can be checked immediately before execution;
- a protected credential that the proposing agent never receives;
- an observable postcondition;
- a useful denial story when any material byte or condition changes; and
- enough real-world consequence that proof-bound execution is visibly better than ordinary bearer-token delegation.

Each resulting implementation should remain one vertical product package. Core proof, policy, claims, receipts, and verification primitives stay in their existing core packages; vendor vocabulary, evidence acquisition, execution, and workflow state stay together in the product package.

## Method

Scores are product-priority judgments, not market-share measurements. Each candidate was scored out of 100:

| Criterion | Weight | Question |
|---|---:|---|
| Consequence and credential risk | 20 | Is accidental or adversarial execution materially harmful? |
| Exact-action fit | 20 | Can the requested effect be represented and committed to precisely? |
| Agent demand | 15 | Is this an operation autonomous agents are likely to perform? |
| Evidence and postconditions | 15 | Can freshness, preconditions, and the resulting effect be checked? |
| Demonstration quality | 15 | Can a visitor understand the value in a short, real end-to-end demo? |
| Differentiation | 10 | Does Auths add more than scopes, RBAC, or ordinary approval gates? |
| Reusable learning | 5 | Does the adapter exercise a new class of core behavior? |

The research used primary product and protocol documentation. The ranking favors narrow demonstrations that can be made truthful and robust over broad integrations with impressive names.

## Ranked portfolio

| Rank | Domain and first operation | Score | Why it belongs here | Specification |
|---:|---|---:|---|---|
| 1 | Kubernetes: exact workload rollout | 94 | High consequence, strong preconditions, excellent live visualization, and a familiar agent use case | `0007-kubernetes-workload-rollouts.md` |
| 2 | OpenTofu: apply one saved plan | 92 | The plan artifact is a natural action commitment; state freshness and credentials make the Auths boundary obvious | `0008-opentofu-saved-plan-apply.md` |
| 3 | PostgreSQL: bounded production data change | 88 | Demonstrates transactional enforcement, row-level preconditions, privacy-aware receipts, and exact cardinality | `0009-postgresql-bounded-data-changes.md` |
| 4 | Stripe: exact refund | 86 | A small, irreversible financial action that is immediately understandable and safely demonstrable in test mode | `0010-stripe-exact-refunds.md` |
| 5 | AWS: execute one CloudFormation change set | 83 | A named change set provides a strong execution handle and AWS credentials are valuable, but the demo is operationally heavier | Future |
| 6 | Package registry: publish one immutable release | 80 | Supply-chain consequences and artifact digests are a strong fit; trusted publishing already removes some token pain | Future |
| 7 | Cloudflare DNS: exact record change | 78 | A precise, visible operation with outage risk; propagation makes the postcondition more nuanced | Future |
| 8 | HashiCorp Vault: issue or rotate one secret | 75 | Excellent credential-boundary story, but a public demo must avoid turning secret material into theater | Future |
| 9 | Salesforce: exact CRM mutation | 71 | Strong enterprise value and record preconditions, but less universally legible and harder to demo without synthetic setup | Future |
| 10 | MCP: exact high-impact tool call | 68 | Strategically aligned with agents, but too abstract as the next showcase and at risk of looking self-referential | Future |

## 1. Kubernetes workload rollout

### Recommended first slice

Authorize exactly one server-side-apply update to a named `Deployment` in a dedicated namespace. The MVP permits only:

- an image change to an immutable image digest;
- a bounded replica-count change; and
- a small allowlist of rollout annotations.

It explicitly excludes Secrets, RBAC, admission configuration, arbitrary Pods, `exec`, host access, and changes to security context.

### Why it ranks first

Kubernetes authorization answers whether an identity may perform a class of API operations. Auths can additionally bind authority to the exact object, namespace, current resource version, patch bytes, dry-run result, verifier configuration, and expiry. The proposing agent does not need a kubeconfig or bearer token.

The demonstration is unusually visual: a visitor can see the proposed manifest, authorization verdict, API receipt, rollout state, and the application’s visible version in one screen.

Kubernetes officially recommends least privilege and short-lived ServiceAccount tokens. Server-side dry-run runs admission, defaulting, validation, and merge logic without persistence, while server-side apply exposes field ownership and conflict behavior. Those primitives make Kubernetes a strong integration point, although dry-run is not by itself an execution guarantee.

Primary references:

- [Service accounts and short-lived TokenRequest credentials](https://kubernetes.io/docs/concepts/security/service-accounts/)
- [Role-based access control](https://kubernetes.io/docs/reference/access-authn-authz/rbac/)
- [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/)
- [API concepts, including dry-run](https://kubernetes.io/docs/reference/using-api/api-concepts/)
- [Admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/)
- [`kubectl apply` server-side options](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_apply/)

### Key research risk

Admission webhooks and controllers can be dynamic. The implementation must not imply that a dry-run response guarantees identical persisted or converged state. It must bind the request and dry-run evidence, then verify the persisted object and rollout postcondition. Unexpected divergence is an indeterminate or failed execution, never an authorization success.

## 2. OpenTofu saved-plan application

### Recommended first slice

Authorize application of one saved OpenTofu plan to one named workspace and state lineage. The protected system plans and applies; the agent may propose configuration but receives neither backend nor provider credentials.

### Why it ranks second

A saved plan is almost the ideal Auths action body: OpenTofu documents that applying a saved plan performs the changes described by that plan without another planning prompt. The action can bind the opaque plan digest, a sanitized JSON projection, configuration and provider-lock digests, state lineage and serial, workspace, backend identity, and allowed resource changes.

It also exposes a valuable non-obvious security property: plan and backend artifacts can contain sensitive values. Public receipts must therefore commit to them without publishing them.

Primary references:

- [OpenTofu `plan`, saved plans, and sensitive-data warning](https://opentofu.org/docs/v1.11/cli/commands/plan/)
- [OpenTofu saved-plan apply behavior](https://opentofu.org/docs/v1.11/cli/commands/apply/)
- [OpenTofu backend configuration and credential handling](https://opentofu.org/docs/language/settings/backends/configuration/)
- [Terraform saved-plan behavior](https://developer.hashicorp.com/terraform/tutorials/cli/plan)
- [Terraform core workflow](https://developer.hashicorp.com/terraform/cli/run)

### Key research risk

A plan is exact at the orchestration layer, not a proof that every provider-side effect will succeed or remain unchanged by a remote API. The demo must distinguish plan authorization, apply acceptance, and observed postconditions.

## 3. PostgreSQL bounded data changes

### Recommended first slice

Authorize one typed `UPDATE` over an already resolved, bounded set of rows in one tenant and table. Do not begin with arbitrary SQL.

### Why it ranks third

This domain forces Auths to handle concerns that source-control and infrastructure demos do not:

- transactional preconditions;
- exact affected-row cardinality;
- row-level security;
- schema and session configuration;
- privacy-preserving commitments to before and after values; and
- an execution ledger committed atomically with the data change.

The visual demo can show the selected rows, the permitted column transition, the transaction receipt, and rejected cases such as an extra row, changed tenant, stale value, or forbidden column.

PostgreSQL supplies the right substrate: transactions, serializable isolation, privileges, row security, and policies whose default behavior is deny when row security is enabled without an applicable policy.

Primary references:

- [PostgreSQL privileges](https://www.postgresql.org/docs/current/ddl-priv.html)
- [Row security policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [`CREATE POLICY`](https://www.postgresql.org/docs/current/sql-createpolicy.html)
- [`SET TRANSACTION`](https://www.postgresql.org/docs/current/sql-set-transaction.html)
- [Transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
- [Transactions](https://www.postgresql.org/docs/current/transactions.html)

### Key research risk

Raw SQL is too broad and too difficult to canonicalize safely. The first profile must be a typed mutation language compiled to parameterized SQL by the trusted executor. Database triggers and functions also create hidden effects and must be forbidden or explicitly fingerprinted.

## 4. Stripe exact refund

### Recommended first slice

Authorize one partial or full refund for a named test-mode Charge or PaymentIntent, for an exact amount, currency, reason, account, and API version.

### Why it ranks fourth

“The agent cannot refund $10.01 when the user authorized $10.00” is an immediate explanation of exact-action authorization. Stripe test mode makes the demonstration real without moving real money. The adapter also exercises idempotency, external reconciliation, webhook observations, and a durable claim store.

Stripe supports partial refunds up to the remaining unrefunded amount. Stripe also supports idempotency keys on POST requests, but its documented pruning behavior means provider idempotency cannot replace Auths’ durable replay claim.

Primary references:

- [Create a refund](https://docs.stripe.com/api/refunds/create)
- [Idempotent requests](https://docs.stripe.com/api/idempotent_requests)
- [API keys, restricted keys, and test mode](https://docs.stripe.com/keys)
- [Stripe API test mode](https://docs.stripe.com/api)

### Key research risk

An API response and a settled refund are different events. The receipt model must separately represent request acceptance, refund state, and later webhook confirmation. The public demo must be test-mode-only by construction.

## 5. AWS CloudFormation change-set execution

### Recommended first slice

Execute one already-created CloudFormation change set for one stack, with destructive replacements, IAM resources, custom resources, macros, and nested stacks denied in the first profile.

### Why it is not in the first four

CloudFormation’s explicit preview-then-execute model is a strong match. AWS documents, however, that a change set does not guarantee a successful update because runtime conditions may still fail. AWS role and cross-service policy behavior also make a robust public environment costlier to operate and explain than OpenTofu.

Primary references:

- [Updating stacks with change sets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-updating-stacks-changesets.html)
- [`CreateChangeSet` and execution roles](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_CreateChangeSet.html)
- [CloudFormation IAM access and temporary credentials](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/control-access-with-iam.html)
- [Drift-aware change sets](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/drift-aware-change-sets.html)

## 6. Package-registry release

### Recommended first slice

Publish one immutable npm package version whose name, version, tarball digest, provenance subject, registry, dist-tag, and workflow identity are fixed.

### Why it ranks below AWS

Supply-chain compromise is highly consequential and artifact digests fit Auths well. npm trusted publishing already uses OIDC to avoid long-lived tokens and can automatically generate provenance, so the Auths story must focus on proof-bound release intent and one-time execution rather than claiming to invent credentialless publishing.

Primary references:

- [npm trusted publishing](https://docs.npmjs.com/trusted-publishers/)
- [Viewing package provenance](https://docs.npmjs.com/viewing-package-provenance/)
- [`npm trust`](https://docs.npmjs.com/cli/v11/commands/npm-trust/)

## 7. Cloudflare DNS record change

### Recommended first slice

Change one named A, AAAA, CNAME, or TXT record in one zone, binding its current record ID and value, exact replacement, TTL, proxy setting, and zone.

### Why it ranks seventh

DNS changes are precise and visibly consequential, and Cloudflare supports scoped API tokens. The complication is distributed propagation: Cloudflare documents that even batch operations use a database transaction while propagation through its distributed store is not atomic. Receipts therefore need separate provider acceptance and observed DNS states.

Primary references:

- [Cloudflare API token permissions](https://developers.cloudflare.com/fundamentals/api/reference/permissions/)
- [DNS record management](https://developers.cloudflare.com/dns/manage-dns-records/)
- [Batch DNS record changes and propagation semantics](https://developers.cloudflare.com/dns/manage-dns-records/how-to/batch-record-changes/)

## 8. Vault secret issuance or rotation

### Recommended first slice

Authorize issuance of one dynamic credential for one Vault role, audience, TTL ceiling, and recipient, or rotation of one named static secret without exposing the value in Auths receipts.

### Why it ranks eighth

Vault is a natural protected credential broker and its response-wrapping model is complementary. The challenge is presentation: the most important output must remain secret, so a public demo can easily become an animation rather than compelling evidence.

Primary references:

- [Vault secrets engines](https://developer.hashicorp.com/vault/docs/secrets)
- [Static and dynamic secrets](https://developer.hashicorp.com/vault/tutorials/get-started/understand-static-dynamic-secrets)
- [Response wrapping](https://developer.hashicorp.com/vault/docs/concepts/response-wrapping)

## 9. Salesforce CRM mutation

### Recommended first slice

Update one Opportunity stage or one Case status with exact record identity, version precondition, allowed transition, and field allowlist.

### Why it ranks ninth

This is commercially valuable and tests enterprise records rather than developer infrastructure. It ranks lower because the product value is less obvious without domain context, and a convincing public demo needs a maintained synthetic Salesforce organization.

Primary reference:

- [Salesforce REST API OAuth usage](https://developer.salesforce.com/docs/platform/connect-rest-api/guide/intro_using_oauth.html)

Further design research should verify the chosen object API’s conditional-update and composite-operation semantics before a specification is accepted.

## 10. MCP high-impact tool execution

### Recommended first slice

Authorize one exact MCP tool invocation whose server identity, tool schema digest, canonical arguments, resource audience, verifier configuration, and result commitments are fixed.

### Why it ranks tenth

MCP is strategically important for agent tools, and its authorization model explicitly uses OAuth concepts. But “Auths authorizes an authorization tool call” is less legible than changing a workload or refunding a payment. It should follow several concrete adapters so it can extract a credible common profile from real experience.

Primary references:

- [MCP authorization](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)

## Why not build a universal adapter first

The common layer should standardize:

- canonical action commitments;
- required and executed verifier configuration;
- evidence commitments and freshness;
- claims and replay outcomes;
- decision, execution, and observation receipts; and
- credential-after-claim execution ordering.

It should not pretend that Kubernetes admission, PostgreSQL transactions, Stripe idempotency, and DNS propagation have the same semantics. Those belong in vertical packages with domain-specific profiles and conformance suites. A universal executor would either be unsafe or push the important behavior into undocumented callbacks.

## Sequencing decision

The next specifications are therefore:

1. `0007-kubernetes-workload-rollouts.md`
2. `0008-opentofu-saved-plan-apply.md`
3. `0009-postgresql-bounded-data-changes.md`
4. `0010-stripe-exact-refunds.md`

The implementation order should remain the same unless deployment constraints make the PostgreSQL demo available before the OpenTofu sandbox. Specification order is based on product value, not a promise that all four will ship concurrently.

## Research limitations

- The ranking deliberately does not use unsourced market-size or adoption claims.
- Vendor behavior can change; every implementation must pin and test the API or CLI versions on which its profile depends.
- A product specification is still required before ranks 5–10 are implemented.
- Public demos are not conformance evidence. Each adapter needs deterministic fixtures, negative vectors, failure injection, and live-provider contract tests.
- The ranking should be revisited after the first two new demos produce usability data. Comprehension and operational burden should outweigh attachment to this ordering.
