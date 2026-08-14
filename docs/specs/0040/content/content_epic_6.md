# Content Epic 6 — Agents, MCP, and Integrations

> **Status revoked by rendered-site audit.** Requalify through Content Epics
> 10–19; existing checked tasks record prior implementation, not completion.

**Depends on:** [Content Epic 0](./epic_0.md), Content Epics 3–5, and Platform
Epic P9.

**Ownership:** This epic owns composition guidance, recommendations, and
integration narratives. P9 owns typed ownership matrices and fact-backed
components; adapter inventories and supported capabilities remain generated.

## Outcome

Agent builders and integration owners can understand which Auths components are
independent, choose a composition, and implement bounded agent authority without
assuming that identity, transport, capability, approval, or provider adapters
are mandatory bundles.

## Current problem

Auths' flexibility is a major advantage but can look like a single complex
system when content introduces all components together. Existing demos prove
composition, yet the docs lack distinct paths for using an MCP client, building
a protected MCP server, delegating to an agent, importing policy/identity
context, and authoring adapters.

Stripe's agent pages separate developer tools, MCP, agent skills, billing, and
commerce, then explain independent combinations.
[Research evidence](./STRIPE_CONTENT_RESEARCH.md#batch-5--sdks-cli-agents-failures-and-assurance)

## Required landings and guides

| Route | Purpose |
|---|---|
| `/agents` | Choose an agent use case |
| `/agents/how-auths-works` | Architecture and independent composition |
| `/agents/delegate-one-tool` | First bounded delegation |
| `/agents/approved-plan` | Exact multi-step plan with approvals |
| `/agents/multi-agent` | Attenuated handoff across agents |
| `/agents/mcp-client` | Use Auths tooling from an agent harness |
| `/agents/protect-mcp-server` | Build an MCP server with closed execution |
| `/agents/skills` | Maintained skills/plugins and installation |
| `/integrations` | Composition chooser and ownership matrix |
| `/integrations/identity-trust` | OIDC, SPIFFE, raw keys, application resolvers |
| `/integrations/policy` | Cedar, OPA, ReBAC evidence/context composition |
| `/integrations/cloud` | Provider IAM and closed credential gateways |
| `/integrations/transport` | HTTPS, Iroh, queues, and application transport |
| `/integrations/capabilities` | UCAN, Biscuit, macaroons, imported authority |
| `/integrations/profile-kit` | Application-owned profile construction |

## Composition model

```text
identity/trust evidence ----+
policy/context evidence -----+--> Auths verification and authority
imported capability ---------+             |
                                             v
transport ------------------------> sealed command delivery
                                             |
state/custody --------------------> closed runtime gateway
                                             |
provider adapter -----------------> application effect
```

Each guide includes a table with rows `Auths supplies`, `application supplies`,
`external system supplies`, `state required`, `secrets involved`, `offline
verification`, and `failure ownership`.

## Agent skills policy

- Maintained plugins/skills are the recommended path.
- Installation instructions are generated from versioned manifests.
- Manual prompt copying is a fallback with explicit update and provenance risk.
- Skills may explain and invoke public Auths tools but never contain credentials
  or bypass runtime authorization.
- Agent documentation distinguishes proposing, approving, authorizing,
  executing, observing, and verifying.

## Implementation steps

- [x] Declare page identities against P9's integration ownership schema.
- [x] Author the agent landing and architecture page before individual guides.
- [x] Build the seven agent/MCP guides over Content Epic 4 scenarios.
- [x] Build the integration chooser and six composition guides.
- [x] Curate generated adapter/profile inventories from release topology.
- [x] Add “Auths with” links to interoperability fixtures rather than unsupported
  competitive claims.
- [x] Author install explanations and safety boundaries around P4's versioned
  skill/plugin manifests.
- [x] Add adversarial content examples for widening, prompt substitution,
  approval substitution, transport success, ambient credential access, and
  unknown provider outcomes.

## Acceptance criteria

- No page implies that Iroh requires Auths authority, that identity requires
  capabilities, or that approval alone authorizes an effect.
- A reader can select and implement identity, policy, transport, custody, state,
  and provider components independently.
- MCP client use and protected MCP server construction are separate journeys.
- Every agent guide shows the exact delegated scope and one prohibited action.
- Maintained skills resolve to a release and pass secret/content scans.
- TypeScript and Python workflows remain semantically identical.

## Validation

```text
npm run test:content
npm run test:integration-matrix
npm run test:agent-scenarios
npm run test:skills
npm run test:security-copy
npm run test:markdown
npm run build
```
