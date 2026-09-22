# Auths Proof: go-to-market research and top 10 product opportunities

**Date:** 2026-09-18

**Status:** Research brief and product recommendation

**Scope:** Auths Proof, with an explicit review of `proofbound-runtime` and
`proof-bound`

**Decision horizon:** First commercial wedge, followed by a two-year product
portfolio

## Executive recommendation

Auths should enter the market as the **exact-action control layer for AI agents
that perform consequential writes**.

The customer-facing promise should be:

> Let agents propose real changes without giving them standing authority to do
> anything else. Auths checks the exact action, obtains approval when required,
> executes through a closed gateway, and produces a receipt that can be verified
> independently.

The first sellable product should be an **Auths Exact-Action Gateway** with two
opinionated launch packs:

1. **Financial Operations for Stripe**: refunds, payment capture/cancel,
   subscription changes, transfers, and payouts.
2. **Production Change Control**: Kubernetes rollouts and OpenTofu saved-plan
   application.

This is a sharper wedge than a generic “MCP security gateway.” Horizontal MCP
authorization is already crowded. Okta/Auth0, Microsoft Entra, Descope, Permit,
Arcade, Composio, and the model platforms themselves now cover substantial
parts of agent identity, OAuth, token custody, tool-level policy, approvals, and
audit. Auths has a more defensible claim when it goes below “may call this tool”
to “may perform this exact provider action, against this exact resource and
state, once, with this evidence and outcome.”

The existing repository makes this credible. It already contains provider
verticals for Stripe, Kubernetes, OpenTofu, PostgreSQL, GitHub, and Radicle;
stateful replay and reservation machinery; approval and custody designs;
receipts; Rust, TypeScript, Python, and WASM surfaces; and extensive negative
fixtures. That is a substantial head start. The missing work is mostly product
selection, packaging, deployment, onboarding, external proof, and customer
evidence—not invention of the core security model.

The recommended business model is open core:

- Keep the protocol, verifier, SDKs, canonical fixtures, and at least one useful
  local gateway open.
- Charge for the operational layer: managed or customer-hosted gateways,
  provider packs, policy and approval administration, receipt retention and
  export, enterprise identity and KMS/HSM integration, recovery operations,
  support, and assurance packages.
- Start with paid design partnerships rather than a broad self-serve launch.

`proofbound-runtime` and `proof-bound` both contain useful ideas, but neither is
needed in the critical path for the first product:

- `proofbound-runtime` should later become an optional execution adapter for
  local commands and coding agents. It adds kernel-enforced Linux containment
  and independently verified execution receipts. It should not be merged into
  Auths or presented as protection for remote SaaS effects.
- `proof-bound` should be used to strengthen Auths release claims and can later
  power a paid assurance export. It should not sit in the authorization runtime,
  and formal methods should not lead the initial marketing message.

## 1. What Auths can credibly sell

Auths is not merely a policy engine. Its useful commercial unit is a complete
effect boundary:

```text
human or organization
        |
        | bounded, signed delegation
        v
agent proposes exact action
        |
        v
Auths verifies proof + policy + freshness + state
        |
        +---- deny with stable reason
        |
        +---- require exact-action approval
        |
        v
closed provider gateway receives credentials only after authorization
        |
        v
provider effect + reconciliation + independently inspectable receipt
```

The repository already contains the raw material for this position:

- an offline, deterministic verification kernel;
- authority attenuation and delegation;
- exact-action commitments;
- replay, budgets, reservations, and exactly-once execution state;
- human approval and external key-custody designs;
- closed provider gateways and typed provider outcomes;
- decision, execution, and observation receipts;
- provider-specific implementations for Stripe, Kubernetes, OpenTofu,
  PostgreSQL, GitHub, and Radicle;
- Rust, TypeScript, Python, and WASM surfaces; and
- adversarial fixtures and conformance machinery.

The most important product distinction is **effect-level exactness**. Existing
identity and authorization products commonly answer questions such as:

- Is this user or agent authenticated?
- May this principal call this API, server, or tool?
- Does this subject have a role or relationship to this resource?
- Should this call require human consent?

Auths can additionally answer:

- Is this the exact resource and exact mutation the principal delegated?
- Did every child delegation become no broader than its parent?
- Is the approval bound to the bytes that will actually execute?
- Has this one-use action already been claimed or consumed?
- Did the provider accept the request, reject it, or leave an ambiguous outcome?
- Can a third party verify the decision and receipt without trusting an Auths
  service?

That is the part worth turning into a product.

## 2. Research method and confidence

This brief combines four evidence classes:

1. **Repository evidence.** The Auths source, specifications, demos, compliance
   inventory, existing GTM plans, and domain research were reviewed. The sibling
   `proofbound-runtime` and `proof-bound` repositories were also reviewed.
2. **Primary market sources.** Standards bodies, official product
   documentation, vendor product pages, public research, and public financial
   or market forecasts were preferred.
3. **Community pain signals.** Reddit discussions were sampled to find recurring
   language and operational complaints. These are qualitative signals, not a
   representative survey. Several threads contain vendor promotion or
   engagement farming, so no market-size conclusion relies on Reddit.
4. **Explicit scenarios.** Bottom-up revenue figures below are planning
   scenarios, not forecasts.

The market and competitor review is current as of 2026-09-18. Agent security
and MCP are changing quickly, so the competitor matrix should be refreshed
quarterly.

## 3. Market thesis

### 3.1 The problem is moving from hypothetical to budgeted

Agent adoption is no longer confined to demos. McKinsey's 2025 survey found
23% of respondents scaling an agentic system somewhere in the enterprise and
another 39% experimenting. Its August 2026 survey reports that 40% of large
organizations are scaling agents, compared with 22% of smaller organizations.
The same research says adoption is concentrated in IT, knowledge management,
and software engineering—the functions closest to Auths' initial technical
buyers. See [McKinsey's 2025 survey](https://www.mckinsey.com/~/media/mckinsey/business%20functions/quantumblack/our%20insights/the%20state%20of%20ai/november%202025/the-state-of-ai-2025-agents-innovation_cmyk-v1.pdf?u%2F=)
and [the 2026 survey](https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai).

Security guidance is converging on the exact failure Auths addresses. OWASP's
“Excessive Agency” guidance identifies excessive functionality, excessive
permissions, and excessive autonomy as root causes; it recommends granular
tools, minimum downstream privileges, user-context execution, human approval,
and complete mediation in downstream systems. See
[OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/).

NIST has also begun a dedicated software and AI agent identity and
authorization initiative covering identification, authorization, auditing,
non-repudiation, prompt-injection controls, and the binding of accountable
people to agent actions. See the
[NIST concept-paper announcement](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
and [AI Agent Standards Initiative](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure).

### 3.2 MCP validates the need but does not remove the product opportunity

MCP's 2026-07-28 release substantially improves OAuth interoperability and
enterprise-managed authorization. Its maintainers explicitly report that
authorization is where implementers spend most integration time. The stable
Enterprise-Managed Authorization extension addresses centralized identity and
repeated consent, while current proposals separately explore per-call passkey
approval, action-security metadata, signed execution records, and tamper-evident
audit records. See the
[MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/),
[Enterprise-Managed Authorization](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/),
and [SEP tracker](https://plan.modelcontextprotocol.io/seps).

This creates both validation and pressure:

- OAuth setup and enterprise identity are becoming standard infrastructure.
  Auths should integrate with them, not compete with them.
- The open gap is increasingly the semantic boundary around a particular
  action: exact parameters, state preconditions, delegation, approval binding,
  one-time execution, ambiguous outcomes, and portable evidence.
- Standards may eventually absorb pieces of this gap. Auths therefore needs
  real provider integrations and operating evidence, not only a protocol claim.

### 3.3 Market-size anchors

There is not yet a credible, standalone market category called “exact-action
authorization for agents.” Treating a broad IAM or AI-security number as the
Auths TAM would be misleading. The following adjacent-spend anchors are useful:

| Market signal | 2026 | 2027 | Relevance |
| --- | ---: | ---: | --- |
| Global information-security spending | $244B | — | Very broad ceiling, not an Auths TAM |
| Securing AI, total | $2.835B | $4.783B | Broad adjacent category |
| AI usage control | $433M | $749M | Closest named segment |
| AI gateways | $251M | $429M | Adjacent deployment budget |
| Usage control + gateways | **$684M** | **$1.178B** | Useful near-market envelope, still broader than Auths |

Sources: [Gartner's 2026 information-security forecast](https://www.gartner.com/en/documents/7408930)
and [Gartner's August 2026 AI-security forecast](https://www.gartner.com/en/newsroom/press-releases/2026-08-26-gartner-forecasts-the-market-for-securing-ai-will-reach-almost-5-billion-in-2027).

The Gartner data supports a growing budget, not an obtainable share. A more
honest bottom-up planning model is:

| Scenario | Qualified organizations | Average annual contract | Implied annual revenue pool |
| --- | ---: | ---: | ---: |
| Beachhead | 250 | $30,000 | $7.5M |
| Focused category | 2,000 | $60,000 | $120M |
| Platform outcome | 10,000 | $100,000 | $1.0B |

These are sensitivity scenarios. They assume Auths can prove value to platform,
security, fintech, or infrastructure teams with consequential agent workflows.
They are not claims about the number of buyers currently in market.

### 3.4 Payments and high-impact automation are especially timely

Agentic payments are becoming infrastructure rather than a laboratory topic.
Stripe has an Agentic Commerce Suite, Visa binds agent identity and contextual
authority to tokenized transactions, and Mastercard supports programmatically
enforced rules and spend limits for machine payments. See
[Stripe's Agentic Commerce Suite](https://stripe.com/blog/agentic-commerce-suite),
[Visa Intelligent Commerce](https://corporate.visa.com/en/solutions/intelligent-commerce/vcs-agentic-ai.html),
and [Mastercard Agent Pay for Machines](https://www.mastercard.com/us/en/news-and-trends/press/2026/june/mastercard-launches-agent-pay-for-machines.html).

Auths should not try to replace these networks. The better opening is the
merchant and enterprise operations surrounding payments: an agent refunding a
charge, capturing or cancelling a payment, changing a subscription, initiating
a transfer, or approving a payout. Those are high-consequence internal effects
where the Auths repository is unusually mature and where network-level checkout
products do not remove the need for enterprise policy, approval, and evidence.

## 4. Recurring pain points

### 4.1 Production teams do not know what agents can do

The most common concern is not model identity in isolation. It is the inability
to enumerate and constrain reachable effects. A representative Reddit thread
describes an enterprise agent receiving API access while nobody could explain
what it could write; replies repeatedly focus on broad tokens, tool lists, and
the fact that a model's understanding is not a security boundary. See
[“new AI agent just got API access to our stack”](https://www.reddit.com/r/LocalLLaMA/comments/1sadvqq/new_ai_agent_just_got_api_access_to_our_stack_and/).

**Product implication:** lead with an inventory of protected writes and exact
allowed effects, not abstract agent identity.

### 4.2 Prototype credentials become permanent

Builders report that broad keys issued “just for now” survive into production,
after which teams cannot tell what an agent may touch or what it actually did.
Common workarounds are per-agent service accounts, short-lived credentials,
approval for writes, and hand-built audit logs. See
[“Those of you running AI agents in prod”](https://www.reddit.com/r/aiagents/comments/1urhxpw/those_of_you_running_ai_agents_in_prod_how_are/)
and [“How are teams handling auth/IAM for production agents?”](https://www.reddit.com/r/AI_Agents/comments/1u01q5d/how_are_teams_handling_authiam_for_production/).

**Product implication:** the provider credential should remain behind the
gateway; the agent should carry authority to propose a specific action, not a
general bearer credential.

### 4.3 MCP OAuth is expensive and inconsistent

Recent MCP implementers describe differences among clients, incomplete
registration metadata, token-storage uncertainty, refresh problems, and
difficulty supporting OAuth 2.1 consistently. See
[one implementation cost report](https://www.reddit.com/r/mcp/comments/1vbmi0u/what_implementing_oauth_21_for_a_remote_mcp/),
[cross-client authentication differences](https://www.reddit.com/r/mcp/comments/1uosmck/mcp_authentication_across_the_big_agents/),
and [remote OAuth pain](https://www.reddit.com/r/mcp/comments/1mw09b5/how_are_you_handling_oauth_when_running_mcp/).

**Product implication:** do not require customers to replace their identity
provider. Provide tested integrations with Auth0, Okta, Entra, Descope, and
self-hosted OIDC; keep Auths focused on the action layer.

### 4.4 Tool-level allowlists are too coarse

Community discussions repeatedly distinguish “may call this tool” from “may
use this tool on these fields, resources, and values.” Operators also note that
per-call approval creates fatigue and eventually trains people to click through.
See [“How are people handling permissions for MCP tools?”](https://www.reddit.com/r/AI_Agents/comments/1w9op5p/how_are_people_handling_permissions_for_mcp_tools/).

**Product implication:** automate low-risk actions inside a bounded grant;
approve only a high-risk exact mutation. Policies must constrain arguments and
provider state, not only tool names.

### 4.5 Approval often is not bound to execution

Several builders identify a time-of-check/time-of-use gap: the UI shows one
summary, but the eventual call is reconstructed or mutated later. Retries and
re-plans can also create duplicate effects even without an attacker. See
[“Most human-approval steps in agent systems are not actually controls”](https://www.reddit.com/r/AI_Agents/comments/1v08f4x/most_humanapproval_steps_in_agent_systems_are_not/).

**Product implication:** approval must sign or commit to the exact canonical
action, policy version, audience, expiry, and one-use claim. Execution must be
derived from the approved object rather than from a fresh model-generated
request.

### 4.6 Audit logs are not enough

Teams want to answer who delegated authority, which agent acted, what exact
parameters were authorized, whether the action executed, and what outcome is
known. Ordinary logs are producer-controlled and often omit policy or
uncertainty. A recurring community recommendation is to make the audit ledger a
first-class platform output rather than a runner log. See
[the production-permissions discussion](https://www.reddit.com/r/aiagents/comments/1urhxpw/those_of_you_running_ai_agents_in_prod_how_are/).

**Product implication:** sell independently verifiable decision and execution
receipts, with explicit “unknown” and reconciliation states, rather than only a
dashboard of green events.

### 4.7 Sandboxing and authorization solve different problems

Builders trust unattended coding agents more when file, process, network, and
tool boundaries exist outside the model. They also recognize that sandboxing
does not decide whether an allowed external business action is authorized. See
[“What actually makes you trust a local coding agent?”](https://www.reddit.com/r/LocalLLaMA/comments/1wg1jea/what_actually_makes_you_trust_a_local_coding/).

**Product implication:** Auths should compose with execution sandboxes. This is
where `proofbound-runtime` is useful. Do not blur OS containment with provider
authorization.

## 5. Competitive landscape

### 5.1 The market is converging from six directions

| Category | Representative products | What they do well | Opening for Auths |
| --- | --- | --- | --- |
| Enterprise identity | Okta/Auth0, Microsoft Entra Agent ID, Descope | Agent identity, OAuth/OIDC, token exchange, enterprise policy, lifecycle, governance | Treat them as identity and token issuers; add portable exact-action authority and provider-specific execution semantics |
| Agent runtimes and MCP gateways | Permit MCP Gateway, Arcade, Composio | Tool connectivity, credential custody, per-tool checks, delegated user auth, consent, broad integration catalogs | Differentiate below tool name: exact arguments, state preconditions, one-use execution, reconciliation, independently verifiable receipts |
| General authorization | OPA/Styra, Cedar/AWS Verified Permissions, Oso, Cerbos, relationship authorization | Mature policy languages and local or hosted decision engines | Compose as policy inputs; Auths should own proof-carrying delegation and the effect lifecycle, not invent a universal policy language |
| Model/platform controls | OpenAI Agents SDK, Anthropic managed-agent permissions | Native approval pauses and per-tool allow/ask configuration | Offer model- and framework-independent enforcement at the actual effect boundary |
| Provider and payment controls | Cloud IAM, restricted API keys, Stripe, Visa, Mastercard | Native scopes, tokenization, fraud controls, spend limits, settlement | Use them as lower-layer controls; bind the enterprise's exact intent and operational workflow above them |
| Approval/credential proxies | TAP, ActionDock, emerging exact-action gateways | Fast onboarding, hidden credentials, human approval, HTTP/MCP proxying | Win on cryptographic delegation, offline verification, provider lifecycle semantics, and rigorous negative evidence—not merely another approval screen |

Primary examples:

- [Auth0 for AI Agents](https://auth0.com/ai) covers agent identity, token vault,
  MCP authentication, fine-grained RAG authorization, and human approval.
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/security-for-ai-overview)
  provides agent identities, delegated permissions, and central governance.
- [Descope Agentic Identity Hub](https://docs.descope.com/agentic-identity-hub)
  combines OAuth, per-tool scopes, token vaulting, policy, audit, and
  enterprise-managed authorization.
- [Permit MCP Gateway](https://docs.permit.io/permit-mcp-gateway/overview/)
  provides identity-aware per-tool authorization, consent, policy, and audit.
- [Arcade](https://docs.arcade.dev/en/get-started/about-arcade) combines tool
  authentication, authorization, secrets, and a hosted action runtime.
- [Composio](https://docs.composio.dev/) offers managed authentication and more
  than 1,000 application toolkits.
- [OpenAI Agents SDK](https://openai.github.io/openai-agents-js/guides/mcp/)
  and [Anthropic permission policies](https://platform.claude.com/docs/en/managed-agents/permission-policies)
  both include native per-tool approval controls.
- [Tool Authorization Protocol](https://docs.tap.human.tech/) and
  [ActionDock](https://actiondock.app/) demonstrate how quickly credential
  isolation plus approval can become a product.

### 5.2 Positioning that will not work

Auths should not lead with any of the following:

- “OAuth for MCP”—standards and identity vendors are absorbing it.
- “Fine-grained authorization”—a mature, crowded category with well-funded
  incumbents.
- “Human approval for agents”—already a feature in model platforms, gateways,
  and small startups.
- “Agent identity”—Okta, Microsoft, Descope, workload-identity vendors, and MCP
  enterprise authorization have stronger distribution.
- “A formally verified authorization system”—the current evidence does not
  justify that full-system claim, and buyers search for operational outcomes.
- “One gateway for every action”—the repository's own architecture correctly
  rejects generic semantics for unrelated provider effects.

### 5.3 Positioning that can work

The differentiated message is:

> Identity products decide who connected. Policy engines decide whether a
> category of request is allowed. Auths proves that the exact action being
> executed is inside the authority that was delegated—and produces a receipt
> another system can verify.

The practical buyer translation is:

- stop giving agents broad production credentials;
- let agents propose changes while a gateway holds the real credential;
- automate safe actions within explicit bounds;
- require approval only for the exact high-risk mutation;
- prevent retries from duplicating irreversible effects; and
- answer “who authorized exactly what, what happened, and what remains
  unknown?” during an incident or audit.

## 6. Product-selection rubric

Each product was scored out of 100:

| Dimension | Weight | Question |
| --- | ---: | --- |
| Pain and urgency | 25 | Is the problem consequential, repeated, and moving into production? |
| Repository readiness | 25 | How much of the hard security behavior already exists? |
| Differentiation | 20 | Does Auths have a credible advantage over existing products? |
| Distribution | 15 | Can the product reach users through developers, ecosystems, or a clear buyer? |
| Willingness to pay | 15 | Is there a budget owner with loss, audit, or operating cost? |

Scores are comparative planning judgments, not market measurements. A high
score authorizes discovery and a bounded pilot—not a large build.

## 7. Top 10 products Auths could build

| Rank | Product | Score | Primary buyer | Recommended role |
| ---: | --- | ---: | --- | --- |
| 1 | Auths Exact-Action Gateway | 89 | AI platform and security engineering | Core product and category wedge |
| 2 | Auths Financial Operations Guard | 87 | Fintech/payments platform, risk, support automation | First paid vertical pack |
| 3 | Auths Production Change Gate | 84 | Platform engineering, SRE, cloud security | Second paid vertical pack |
| 4 | Auths Database Mutation Guard | 80 | Data platform, security, regulated operations | High-value design-partner vertical |
| 5 | Auths Authority SDK | 78 | Agent-framework and MCP developers | Open-source distribution engine |
| 6 | Auths Approval and Credential Broker | 75 | Security/platform teams | Feature bundle; sell standalone only if demand proves it |
| 7 | Auths Receipt Ledger and Evidence Explorer | 73 | Security operations, audit, compliance | Commercial control-plane module |
| 8 | Auths Cross-Organization Delegation Exchange | 69 | B2B platforms and multi-company workflows | Long-term network product |
| 9 | Auths Bounded Agent Runner | 66 | Coding-agent and internal-tool platform teams | Optional product using `proofbound-runtime` |
| 10 | Auths Authorization Assurance Pack | 61 | Security-product vendors and regulated buyers | Later assurance product using `proof-bound` |

### 7.1 Product 1 — Auths Exact-Action Gateway

**Job to be done:** Put one non-bypassable boundary between an agent and a
consequential MCP or HTTP write, without handing the agent the provider
credential.

**MVP**

- TypeScript SDK and deployable sidecar/gateway.
- OIDC integration rather than a new identity provider.
- Canonical exact-action object covering tool/server identity, resource,
  arguments, audience, expiry, and policy commitment.
- `allow`, `deny`, and `require_approval` decisions.
- One-use claim, replay protection, and closed credential-after-claim ordering.
- Signed decision and execution receipts with an offline verifier.
- Two real provider packs, not a universal arbitrary-HTTP executor.

**Why it can win:** Permit, Arcade, Descope, Auth0, and other products validate
the category, but most buyer-facing descriptions center on identity, scopes,
tool-level policy, or audit. Auths can make exact provider effects and portable
verification the product boundary.

**Critical constraint:** The first page, demo, and sales conversation must show
a refund, rollout, or database update—not an abstract policy diagram.

**Commercial shape:** open local gateway; paid managed gateway, on-premises
operations, provider packs, policy distribution, receipt retention, and support.

**90-day validation:** three external teams protect one real write workflow;
at least one pays for a pilot; zero integration requires the agent to retain
the provider's write credential.

### 7.2 Product 2 — Auths Financial Operations Guard

**Job to be done:** Let support, finance, and operations agents perform narrowly
authorized money-related actions without receiving broad Stripe authority.

**MVP**

- Start with exact refund, payment capture/cancel, and subscription modification.
- Bind customer/account, payment object, amount/currency, allowed transition,
  reason, API version, current provider state, expiry, and one-use budget.
- Risk-based approval thresholds and approver separation.
- Provider-held idempotency plus Auths' durable replay/claim state.
- Separate request acceptance, provider state, later observation, and unknown
  outcome in receipts.
- Stripe test-mode sandbox, then a customer-controlled restricted key in pilot.

**Why it can win:** The repository already implements a deep Stripe profile
family rather than a slideware integration. The use case is legible: “The agent
was allowed to refund $10.00 on this charge once; it could not refund $10.01,
change another customer, or retry into a duplicate.” The product addresses
enterprise back-office operations rather than competing with card networks on
consumer checkout.

**Buyer:** head of payments/platform, support-automation owner, fintech risk,
or finance operations.

**Commercial shape:** paid provider pack plus gateway; price by protected
account/environment and support tier, not by authorization decision.

**Kill signal:** target teams are unwilling to let agents execute any financial
write even with a closed boundary, or Stripe-native controls fully satisfy the
workflow with no material custom approval/audit cost.

### 7.3 Product 3 — Auths Production Change Gate

**Job to be done:** Allow agents to propose and execute bounded infrastructure
changes without inheriting a developer's kubeconfig or cloud credentials.

**MVP**

- Kubernetes: one named Deployment, immutable image digest, bounded replicas,
  explicit resource version, dry-run evidence, and observed rollout result.
- OpenTofu: one saved-plan digest, workspace/state identity and serial,
  provider-lock/config commitments, denylisted destructive resource classes,
  and post-apply observation.
- Approval bindings that survive queueing and cannot authorize a different
  deployment or plan.
- Incident-friendly receipts and reconciliation after timeouts.

**Why it can win:** Infrastructure teams already understand plans, diffs,
approvals, and drift. Auths adds exact delegated authority and removes the
agent's standing production credential. The existing Kubernetes and OpenTofu
verticals reduce implementation risk.

**Competition:** GitOps, admission control, OPA, Terraform/OpenTofu automation
platforms, and cloud IAM are strong substitutes. Auths must integrate with
them and prove that agent-specific delegation and exact receipts close a gap;
it should not rebuild CI/CD.

**Commercial shape:** enterprise gateway deployed in the customer's network,
with per-cluster/workspace pricing and an annual support contract.

### 7.4 Product 4 — Auths Database Mutation Guard

**Job to be done:** Let an agent perform one bounded production data correction
without receiving general SQL write access.

**MVP**

- Typed mutations only; no arbitrary SQL.
- One tenant, table, key set, allowed columns, before-value preconditions, and
  exact cardinality ceiling.
- Parameterized SQL created by the trusted gateway.
- Row-level security and transaction isolation checks.
- Atomic execution ledger plus privacy-preserving before/after commitments.
- Deny or indeterminate on triggers, functions, schema drift, or cardinality
  mismatch unless explicitly profiled.

**Why it can win:** Database access is a high-consequence boundary with an
obvious failure mode. Auths' existing PostgreSQL vertical already reflects
transaction, cardinality, tenant, and privacy semantics that generic MCP
gateways usually do not own.

**Buyer:** data platform, regulated operations, trust and safety, or enterprise
support automation.

**Commercial shape:** customer-hosted gateway and database pack; sell first as
a paid integration, not a self-serve database proxy.

### 7.5 Product 5 — Auths Authority SDK

**Job to be done:** Give framework authors a small, local API for bounded grants,
attenuated child delegation, exact actions, verification, and receipts.

**MVP**

- Polished TypeScript API backed by the Rust/WASM kernel.
- Python workflow parity for the agent ecosystem.
- Framework adapters for only two externally validated runtimes.
- Local examples that work without an Auths account.
- Canonical fixtures, negative cases, and an integration conformance suite.
- Clear distinction between identity, OAuth token acquisition, authority, human
  approval, and provider execution.

**Why it matters:** This is the distribution product. Framework maintainers and
developers are unlikely to adopt a commercial control plane before they can
understand and exercise the model locally.

**Why it is not the first paid product:** SDK adoption can validate the model
but often does not identify an economic buyer. The commercial product should
solve gateway operations, provider semantics, governance, and evidence
retention.

**Metric:** time from install to the first allowed exact action and first
intentional denial, both under 15 minutes for a new developer.

### 7.6 Product 6 — Auths Approval and Credential Broker

**Job to be done:** Keep write credentials away from agents and require a human
or automated approver to authorize the exact request that will execute.

**MVP**

- Approval inbox for Slack/Teams/web plus WebAuthn or passkey signing.
- Risk tiers that avoid approving every read.
- Immutable action preview generated from canonical bytes.
- Expiry, revocation, approver separation, cancellation, and stale-state
  revalidation.
- AWS KMS, PKCS#11/HSM, and customer-managed secret-store integrations.
- Credential release only after claim and immediately before execution.

**Why it is ranked sixth:** The need is real, but approval and credential
brokering are rapidly becoming features of Auth0, Descope, Permit, Arcade,
Composio, model platforms, and smaller proxies. It is essential inside the
gateway but weak as the entire category unless external demand proves otherwise.

**Commercial shape:** enterprise module or provider pack, with premium custody
and regulated-workflow support.

### 7.7 Product 7 — Auths Receipt Ledger and Evidence Explorer

**Job to be done:** Answer, after the fact, who authorized what exact action,
which policy and configuration applied, whether it executed, and which facts
remain unresolved.

**MVP**

- Append-only receipt ingestion and independent verification.
- Search by human, agent, delegation chain, provider, resource, policy, action,
  denial code, and outcome.
- Clear separation of decision, claim, provider request, acceptance,
  observation, reconciliation, and unknown outcome.
- Retention policy, legal hold, SIEM export, and privacy-aware redaction.
- “Verify outside Auths” bundle export.

**Why it can win:** Ordinary audit logs are useful but producer-controlled.
Auths' portable receipt and offline-verification model can support cross-team,
cross-company, and auditor use without making the hosted ledger the root of
trust.

**Risk:** A dashboard without protected production workflows is an empty GRC
product. Build it only after products 1–4 generate receipts customers repeatedly
need to inspect.

### 7.8 Product 8 — Auths Cross-Organization Delegation Exchange

**Job to be done:** Let one organization delegate a narrowly defined action to
another organization's agent without sharing a general credential or requiring
one central authorization service.

**Example:** A customer delegates permission for a vendor's incident-response
agent to change one Cloudflare rule or open one pull request for a specific
incident, with expiry, approval, and a receipt both parties can verify.

**MVP**

- Cross-tenant trust roots and audience binding.
- Multi-party delegation with monotonic narrowing.
- Organization-owned identity and custody adapters.
- Exchange transport that cannot upgrade authority.
- Dual-party receipt verification and explicit dispute evidence.
- One domain only—incident response is more credible than a generic federation.

**Why it can win:** Most current offerings are strongest inside one identity or
gateway control plane. Auths' portable proof model is naturally suited to an
organizational boundary.

**Why it is later:** Trust bootstrap, procurement, legal meaning, interoperability,
and network effects make this a long sales and standards problem. The ambitious
cross-company demo is useful research, not evidence of a market.

### 7.9 Product 9 — Auths Bounded Agent Runner

**Job to be done:** Combine business-action authorization with an OS-enforced
boundary for local tools and coding agents.

**MVP using `proofbound-runtime`**

- Auths verifies who delegated a task and its exact business/tool authority.
- Proofbound Runtime launches the local command on supported Linux hosts with
  explicit filesystem, process, environment, network, and resource authority.
- The two receipts are joined without claiming that either proves the other's
  domain.
- A customer can verify both the authorization and the execution boundary.

**Why it can win:** Most gateways govern API calls but do not control the local
process that prepares them. Most sandboxes constrain processes but do not
establish business authority for remote effects. The combination is more
complete while preserving separate trust claims.

**Why it is ninth:** It is Linux-first, operationally demanding, and competes
with fast-moving coding-agent sandboxes and container/microVM platforms. It is
not required to prove the initial remote-effect product.

**Boundary:** Never claim that a runtime receipt proves the absence of all
exfiltration or that an Auths decision proves OS containment.

### 7.10 Product 10 — Auths Authorization Assurance Pack

**Job to be done:** Give security-sensitive customers evidence that a particular
Auths release, policy adapter, provider pack, and deployment artifact satisfy
specific registered claims—without collapsing tests, bounded checks, formal
models, assumptions, and artifact linkage into one score.

**MVP using `proof-bound`**

- A public claim board for the Auths verifier and one provider pack.
- Exact source and release-artifact identities.
- Typed evidence from tests, conformance, fuzzing, bounded checks, and formal
  work, with assumptions and exclusions visible.
- An independently verifiable release bundle.
- Customer export suitable for security review or audit evidence.

**Why it can win:** Buyers of authorization infrastructure care about the
integrity of the enforcement layer. Proofbound's independent verifier,
three-facet status, explicit assumption accounting, and refusal to emit a vague
score are meaningfully differentiated.

**Why it is tenth:** The sibling repository's own product analysis identifies
onboarding and external-validation gaps. This is valuable assurance for Auths,
but it is not the first user job and should not delay product adoption.

## 8. Recommended portfolio architecture

The ten ideas are not ten unrelated startups. They form a product ladder:

```text
Open distribution
  Auths Authority SDK
        |
        v
Core enforcement
  Auths Exact-Action Gateway
        |
        +--> Financial Operations pack
        +--> Production Change pack
        +--> Database Mutation pack
        |
        v
Enterprise operations
  Approval + Credential Broker
  Receipt Ledger + Evidence Explorer
        |
        v
Expansion
  Cross-Organization Delegation Exchange
  Bounded Agent Runner
  Authorization Assurance Pack
```

This preserves the repository's vertical-first architecture. Shared mechanisms
can be reused, but Stripe, Kubernetes, OpenTofu, and PostgreSQL must keep their
own action, state, provider, reconciliation, and receipt semantics.

## 9. Go-to-market plan

### 9.1 Ideal customer profile

Prioritize teams with all of the following:

- at least one agent or agentic workflow moving beyond a prototype;
- a real write path into payments, infrastructure, or production data;
- broad credentials, home-grown approval logic, or a manual operator currently
  blocking deployment;
- an identifiable platform, security, risk, or operations owner;
- a reason to retain and explain action history; and
- willingness to deploy an enforcement component in their environment.

Best initial targets:

1. fintech or SaaS teams automating support and financial operations;
2. AI platform teams enabling internal agents to change production systems;
3. agent-framework or MCP-server vendors whose customers demand safer writes;
4. regulated enterprises experimenting with agents but blocked by security
   review.

Avoid spending early cycles on hobby agents, read-only RAG, generic chatbots,
or teams seeking only OAuth setup. They may adopt the SDK but are weak paid
design partners.

### 9.2 Buyer, champion, and user

| Role | Likely person | Message |
| --- | --- | --- |
| Economic buyer | VP/Head of Platform, CISO delegate, payments/platform leader | Ship agent writes without accepting broad standing authority and unauditable risk |
| Champion | Staff security/platform engineer | One enforcement pattern, typed provider behavior, customer-hosted option, usable evidence |
| Developer user | Agent or integration engineer | SDK and gateway that remove custom auth, replay, approval, and receipt plumbing |
| Reviewer | Security, audit, risk, compliance | Exact delegation chain, policy/config identity, action binding, outcome and uncertainty |

### 9.3 Sales motion

Start with a paid, bounded design engagement:

- 6–8 weeks;
- one provider and one action family;
- one non-production environment followed by one controlled production path;
- fixed success criteria and a security boundary document;
- customer-operated credentials and deployment;
- $15,000–$40,000 pilot fee, credited toward an annual contract if converted.

The fee is a hypothesis. Its job is to distinguish interest from budget. Do not
offer a large free integration program that converts engineering velocity into
custom consulting without commercial evidence.

After repeated pilots, test packaging such as:

- Open-source SDK and local verifier: free.
- Team gateway: $500–$2,000 per month for a small number of environments and
  one provider pack.
- Enterprise/on-premises: $50,000–$250,000 annual contract value depending on
  environments, provider packs, custody, SSO, retention, support, and assurance.

Do not finalize pricing until at least five qualified buyer conversations and
two paid pilots establish the unit of value. Authorization-decision volume is
unlikely to be the right primary meter because it taxes safe automation and is
hard for buyers to forecast.

### 9.4 Distribution

Use a two-track motion:

**Developer distribution**

- publish a 15-minute local demo with one allowed action and four visible
  denials;
- ship TypeScript and Python examples for one mainstream agent framework each;
- publish the offline verifier and adversarial fixture suite;
- contribute precise findings to MCP, OWASP, and agent-security discussions;
- show composition with OAuth, OIDC, OPA/Cedar, and provider IAM rather than
  attacking established layers.

**Buyer distribution**

- founder-led outreach to platform/security/payments leaders with an active
  agent-write project;
- integration partnerships with agent runtimes and MCP-server vendors;
- security architecture workshops centered on one blocked workflow;
- case studies measured in credentials removed, writes protected, approval
  latency, duplicate effects prevented, and audit preparation time.

### 9.5 Demonstration

The flagship demo should show a real, understandable consequence:

1. An agent proposes a $10 refund for one Stripe charge.
2. Auths shows the human, agent, exact charge, amount, reason, policy, expiry,
   and current provider state.
3. A risk policy requires passkey approval.
4. The gateway claims the one-use authority, obtains the restricted provider
   credential, and executes the exact request.
5. The receipt distinguishes provider acceptance from later state observation.
6. A $10.01 mutation, another charge, expired approval, child-authority
   expansion, configuration substitution, and replay all fail before provider
   I/O.
7. A standalone verifier checks the exported receipt without contacting Auths.

The second demo should apply the same product surface to a Kubernetes rollout.
That proves the platform is not payment-specific without claiming that the two
domains share execution semantics.

## 10. First 90 days

### Days 0–30: prove comprehension and demand

- Freeze the positioning sentence and two launch packs.
- Create a one-page architecture and five-minute video around the refund demo.
- Conduct 20 problem interviews: 8 platform/security, 6 payments/fintech, 6
  framework/MCP vendors.
- Ask for the last real blocked or risky agent write, current credential path,
  approval logic, retry behavior, audit requirement, and budget owner.
- Recruit three design candidates; require access to a real workflow diagram
  and a named buyer.
- Benchmark the install-to-denial and install-to-success journeys with external
  developers.

### Days 31–60: productize one vertical

- Package the gateway and Stripe refund/capture/cancel profiles behind a small
  TypeScript API.
- Integrate one enterprise OIDC provider and one customer-managed secret/KMS
  path.
- Build the exact-action approval UI and portable receipt export.
- Add production-shaped deployment, health, recovery, and upgrade guidance.
- Complete an independent security architecture review of the shipping slice.
- Sign one paid pilot or treat the financial-operations hypothesis as weakened.

### Days 61–90: run and compare

- Run the first pilot in a customer-controlled non-production environment.
- Measure integration time, denied unsafe variants, approval latency, operator
  interventions, reconciliation cases, and receipt usefulness.
- In parallel, prototype the Kubernetes pack with a second design partner.
- Publish the open SDK, verifier, exact limitations, and one third-party-run
  conformance result.
- Decide with evidence whether the first vertical remains financial operations
  or moves to production change control.

## 11. Metrics and decision gates

### Activation

- Median time to first verified allow: under 15 minutes locally.
- Median time to first intentional denial: under 15 minutes.
- Production-shaped provider integration: under two engineer-days after the
  gateway is deployed.
- No provider write credential exposed to the agent process.

### Product value

- Number of high-impact writes protected per week.
- Percentage automated inside a bounded grant versus sent for approval.
- Approval latency at p50 and p95.
- Duplicate or replayed provider effects prevented.
- Number of unknown outcomes reconciled without a second write.
- Time to answer an incident-review question from receipts.

### Commercial evidence

- 20 qualified interviews yield at least 5 active projects with the problem.
- At least 3 teams provide a concrete workflow and integration owner.
- At least 2 accept a paid pilot proposal.
- At least 1 converts to an annual contract or a credible procurement process.

### Kill or redirect criteria

Redirect the initial wedge if, after 20 qualified interviews:

- fewer than five teams have an agent write blocked by authorization or
  credential risk;
- no buyer will pay for a bounded pilot;
- every target can solve the problem with existing IdP, provider IAM, and a
  small approval callback;
- the exact-action model requires so much provider-specific work that customers
  prefer bespoke code; or
- operational integration cost exceeds the loss or audit cost being removed.

## 12. Review of `proofbound-runtime`

### What is worth incorporating

The repository implements a strong complementary concept: a Linux-first
execution-assurance gateway that declares filesystem, executable, environment,
network, process, memory, time, and output authority before starting an
untrusted child process. It uses Landlock, seccomp, cgroup v2, an explicit
environment allowlist, exact executable/loader closure, canonical receipts,
and an independently implemented verifier.

The valuable ideas for Auths are:

- **Enforcement precedes execution.** This matches Auths' requirement that
  denial occurs before credentials and provider I/O.
- **Unsupported means unavailable.** There is no best-effort unconfined
  fallback.
- **Producer and verifier separation.** The executor cannot grade its own
  receipt.
- **Explicit authority plans.** Local execution authority is typed and bounded
  instead of left in prompts.
- **Receipt composition with preserved assumptions.** An Auths action receipt
  and runtime execution receipt can be joined without pretending to prove the
  same thing.

These ideas justify product 9, Auths Bounded Agent Runner, and could strengthen
local provider adapters, coding-agent workflows, policy compilers, or risky
helper processes.

### What is not needed for the initial product

- The first Stripe, Kubernetes, OpenTofu, or PostgreSQL gateway does not require
  a child-process sandbox to establish its provider authorization boundary.
- Runtime is Linux-first and therefore cannot be the universal desktop or SaaS
  story.
- Landlock/seccomp/cgroup evidence says nothing by itself about whether a refund,
  rollout, or database mutation was authorized.
- Folding Runtime into the Auths monorepo would mix separately valuable domains
  and violate the clearer product boundary already documented by both projects.

**Decision:** keep it separate; build an optional typed adapter only after the
Exact-Action Gateway has external users or a design partner specifically needs
local execution containment.

## 13. Review of `proof-bound`

### What is worth incorporating

Proofbound is an assurance compiler. Its best ideas for Auths are:

- claims are registered against exact subjects and evidence;
- formal status, implementation linkage, and assumptions remain separate;
- tests, bounded checks, model theorems, and source/artifact linkage cannot be
  silently upgraded into one score;
- the evidence producer does not control the final verdict;
- every report preserves what is not proved or is out of scope;
- release receipts can be checked independently.

Auths should use these ideas internally for release assurance, especially for
the verifier, canonical codecs, authority attenuation, provider profile
evaluators, and release artifacts. They also support product 10, the
Authorization Assurance Pack.

There is a longer-term commercial fit: regulated customers repeatedly ask
security vendors to substantiate claims about their enforcement layer. A
portable Auths claim board and independently verifiable release bundle could
reduce that burden and strengthen procurement trust.

### What is not needed for the initial product

- Proofbound should not execute in the authorization or provider-effect path.
- Customers do not need to learn its tier vocabulary to protect their first
  agent action.
- Its own product analysis identifies first-hour, packaging, and external-trust
  gaps. It is not yet a ready-made customer-facing assurance portal.
- “Formally verified” must not become GTM shorthand. The current projects have
  mixed evidence types and explicit assumptions; the marketing must preserve
  that honesty.

**Decision:** use Proofbound as an internal release discipline now; expose a
small, plain-language assurance bundle later; do not make it a runtime
dependency or delay the first paid vertical for it.

## 14. What not to build now

- A universal arbitrary-HTTP executor. It erases the provider semantics that
  make Auths safe and differentiated.
- A new identity provider or OAuth server. Integrate with established systems.
- A broad agent inventory/posture product. Okta, Microsoft, Descope, WitnessAI,
  and others have stronger distribution and existing enterprise surfaces.
- A generic policy language. Compose with OPA, Cedar, and customer policy;
  retain Auths' closed exact-action profiles.
- A marketplace of hundreds of shallow integrations. Composio and Arcade have
  catalog advantages; Auths should go deep on consequential effects.
- A receipt dashboard before real workflows generate receipts.
- A blockchain or token network. Offline verification and content identity do
  not require one.
- A general cross-company federation before one bilateral workflow succeeds.
- A combined Auths/Proofbound/Runtime mega-product. The separation of identity,
  authority, effect execution, OS containment, and assurance is a strength.

## 15. Final decision

Auths has enough implemented surface to support many plausible products, but
the market does not reward breadth by itself. The horizontal agent-security
control plane is filling quickly. Auths should exploit the part of the stack it
has built unusually deeply:

> exact, attenuated, locally verifiable authority carried to a provider-specific
> effect boundary, with one-use execution state and independently verifiable
> evidence.

Build one product surface—the Exact-Action Gateway—and prove it through one
financial-operations pack and one production-change pack. Keep the SDK and
verifier open for distribution. Sell provider depth, operations, governance,
custody, evidence retention, deployment, and assurance. Use
`proofbound-runtime` and `proof-bound` as later, composable advantages without
putting either in the first customer's critical path.

The immediate objective is not another impressive internal demo. It is one
external team protecting one real write, one buyer paying for the outcome, and
one receipt a third party can verify without trusting Auths.

## Source register

### Market and standards

- [Gartner: securing AI market forecast, August 2026](https://www.gartner.com/en/newsroom/press-releases/2026-08-26-gartner-forecasts-the-market-for-securing-ai-will-reach-almost-5-billion-in-2027)
- [Gartner: worldwide information-security forecast, 2026](https://www.gartner.com/en/documents/7408930)
- [McKinsey: State of AI 2025](https://www.mckinsey.com/~/media/mckinsey/business%20functions/quantumblack/our%20insights/the%20state%20of%20ai/november%202025/the-state-of-ai-2025-agents-innovation_cmyk-v1.pdf?u%2F=)
- [McKinsey: State of AI 2026](https://www.mckinsey.com/capabilities/quantumblack/our-insights/the-state-of-ai)
- [OWASP LLM06:2025 Excessive Agency](https://genai.owasp.org/llmrisk/llm062025-excessive-agency/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/)
- [NIST: identity and authority of software agents](https://www.nist.gov/news-events/news/2026/02/new-concept-paper-identity-and-authority-software-agents)
- [NIST AI Agent Standards Initiative](https://www.nist.gov/news-events/news/2026/02/announcing-ai-agent-standards-initiative-interoperable-and-secure)
- [MCP 2026-07-28 release](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [MCP Enterprise-Managed Authorization](https://blog.modelcontextprotocol.io/posts/enterprise-managed-auth/)
- [MCP SEP tracker](https://plan.modelcontextprotocol.io/seps)

### Competitors and substitutes

- [Auth0 for AI Agents](https://auth0.com/ai)
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/security-for-ai-overview)
- [Descope Agentic Identity Hub](https://docs.descope.com/agentic-identity-hub)
- [Permit MCP Gateway](https://docs.permit.io/permit-mcp-gateway/overview/)
- [Arcade](https://docs.arcade.dev/en/get-started/about-arcade)
- [Composio](https://docs.composio.dev/)
- [OpenAI Agents SDK MCP approvals](https://openai.github.io/openai-agents-js/guides/mcp/)
- [Anthropic managed-agent permission policies](https://platform.claude.com/docs/en/managed-agents/permission-policies)
- [Tool Authorization Protocol](https://docs.tap.human.tech/)
- [ActionDock](https://actiondock.app/)
- [Stripe Agentic Commerce Suite](https://stripe.com/blog/agentic-commerce-suite)
- [Visa Intelligent Commerce](https://corporate.visa.com/en/solutions/intelligent-commerce/vcs-agentic-ai.html)
- [Mastercard Agent Pay for Machines](https://www.mastercard.com/us/en/news-and-trends/press/2026/june/mastercard-launches-agent-pay-for-machines.html)

### Qualitative community signals

- [MCP OAuth implementation cost](https://www.reddit.com/r/mcp/comments/1vbmi0u/what_implementing_oauth_21_for_a_remote_mcp/)
- [MCP authentication differences across major agents](https://www.reddit.com/r/mcp/comments/1uosmck/mcp_authentication_across_the_big_agents/)
- [Remote MCP OAuth pain](https://www.reddit.com/r/mcp/comments/1mw09b5/how_are_you_handling_oauth_when_running_mcp/)
- [Unclear production-agent permissions](https://www.reddit.com/r/LocalLLaMA/comments/1sadvqq/new_ai_agent_just_got_api_access_to_our_stack_and/)
- [Production agent permission practices](https://www.reddit.com/r/aiagents/comments/1urhxpw/those_of_you_running_ai_agents_in_prod_how_are/)
- [Production agent IAM questions](https://www.reddit.com/r/AI_Agents/comments/1u01q5d/how_are_teams_handling_authiam_for_production/)
- [MCP tool-permission practices and approval fatigue](https://www.reddit.com/r/AI_Agents/comments/1w9op5p/how_are_people_handling_permissions_for_mcp_tools/)
- [Approval-to-execution binding gap](https://www.reddit.com/r/AI_Agents/comments/1v08f4x/most_humanapproval_steps_in_agent_systems_are_not/)
- [Trust requirements for unattended coding agents](https://www.reddit.com/r/LocalLLaMA/comments/1wg1jea/what_actually_makes_you_trust_a_local_coding/)

### Internal repository sources

- `README.md`
- `docs/plans/GO_TO_MARKET_STRATEGY.md`
- `docs/plans/AUTHS_BUSINESS_LAUNCH_ROADMAP.md`
- `docs/research/competition/AUTHS_COMPETITIVE_AND_ALTERNATIVE_SOLUTIONS.md`
- `docs/research/domains/0001-domain-priority-ranking.md`
- `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`
- `compliance.toml`
- `proofbound-runtime/README.md`
- `proofbound-runtime/docs/specs/0001_initial_spec.md`
- `proof-bound/README.md`
- `proof-bound/docs/product-analysis.md`
- `proof-bound/docs/notes/assurance-platform-verticals.md`
