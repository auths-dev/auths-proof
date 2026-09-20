# Auths Proof: unseating incumbents by changing the unit of authorization

- **Date:** 2026-09-21
- **Builds on:** [2026-09-18 go-to-market research](2026-09-18-go-to-market-and-product-opportunities.md)
  and [2026-09-19 product directions](2026-09-19-auths-proof-product-directions.md)
- **Assumes:** the self-hosted stack (AP-SPEC-051–052) is complete, and the
  declared-recipe gateway (053), enum node (055), and OpenAPI derivation
  (056) ship on the sequence in those specs
- **Confidence:** competitive claims are planning judgments from public
  product behavior as of this date, not measured market data; repository
  readiness claims cite spec numbers and should be checked against each
  spec's `Status` line before any customer promise

## Decision

Pick incumbents by one rule and attack them in one order.

**The rule.** Every incumbent worth displacing authorizes a *container*
around a consequential action: a run, a budget, a scope, a session, a token,
a role. Auths authorizes the *action itself*: this exact request, on this
exact resource, once, inside a bounded and revocable grant, with a proof a
third party can verify offline. The products to build are the ones where the
incumbent's container is widest relative to the blast radius of what sits
inside it.

**The order.**

1. Agent commit and release signing (fills a gap; ships in weeks; creates
   the identity root everything else uses).
2. Agent spend authority on Stripe (deepest repository vertical; clearest
   budget owner; strongest "why now").
3. Production change gate for OpenTofu, Kubernetes, and PostgreSQL (second
   deepest vertical; ride inside the incumbent as a required check).
4. Per-system-of-record write gateway from OpenAPI (largest market; most
   competition; needs 053/056 and a reference customer from 2–3).
5. Embedded verification for API owners (strongest technical position;
   slowest adoption; needs a marquee logo from 2).

This differs from the two prior documents in three places. The 09-18 paper's
"Exact-Action Gateway" is plumbing, not a product; its two launch packs are
the products, and they are #2 and #3 here. The 09-19 paper's embedded kit is
#5: right mechanism, early timing. Neither lists #1, which is the only
product already working end to end and the one that makes delegated agent
identity concrete for every later sale.

## 1. Why the unit of authorization is the wedge

The market is converging on agent authorization from identity (Okta, Entra,
Descope), token custody (Arcade, Composio, Nango), policy (Permit, OpenFGA,
Cerbos, OPA), and the model platforms' own tool permissions. Each of these
answers "may this agent call this tool or hold this token?" None answers
"was this specific write, with these specific arguments, allowed, and did
it happen once?" That second question is the one a controller, a platform
lead, or an auditor asks after an agent does something expensive.

Auths already has the primitives for the second question, and the 053–056
sequence makes them usable without an Auths-authored profile per provider:

| Primitive | Where it exists | What it changes for a buyer |
| --- | --- | --- |
| Exact canonical action commitment | core, `auths.mcp/v2`, 051 | authorization names the write, not the tool |
| Offline-verifiable proof under a delegated, revocable identity | core, KERI-style identity, `auths id agent` | an auditor verifies without trusting the operator's logs |
| One-use atomic claim with `unknown` as a first-class outcome | 051–052 attempt store and runner | no blind retries; "we do not know" is recorded, not hidden |
| Credential isolated from the agent | 053 gateway | the agent cannot use the token outside an authorized action |
| Bounded schema with closed enumerations | 054 §5, 055 | intent bounds live in the contract, so an agent can self-authorize inside them |
| Contracts and recipes derived from the vendor's OpenAPI | 056 | a new operation costs an hour of bounding decisions, not a spec |
| Formally translated verifier | `formal/` | the verifier is an assurance artifact, not a promise |

The last row is unusual enough to lead with in regulated conversations and
irrelevant everywhere else. Do not put it on the front page.

## 2. The five products

Each entry uses the same template so they can be compared. "Repository
readiness" names specs, not implementation status; check each spec before
quoting it.

### 2.1 Product 1 — Agent commit and release signing

**Incumbent and its unit.** Sigstore and `gitsign` bind a keyless signature
to an OIDC identity; GitHub enforces "signed commits required". Both
authorize a *session identity*. An agent has no OIDC identity of its own, so
today it signs as its operator or not at all, and a reviewer cannot tell a
human commit from an agent commit made under the human's key.

**Auths' unit.** A delegated key with separate `sign_commit` and
`sign_release` scopes, an expiry, and one-line revocation, anchored under
the maintainer's root. Verification resolves the delegation chain, not the
operator's session.

**Repository readiness.** Working now: the `claude-release` delegated agent,
agent-signed PR auths#381, `auths verify` through a pinned root, and CI
bundle verification. The gaps are packaging: a GitHub Action, a
`git config` recipe, and a README that a maintainer can follow in ten
minutes.

**Buyer and champion.** Engineering leads adopting coding agents; security
teams asking "which commits did an agent make, and under whose authority?"
Champion is whoever owns branch protection.

**Why the incumbent cannot copy quickly.** Sigstore's trust model is OIDC
issuer plus transparency log. Adding delegated, scoped, revocable agent
identities under a human root is a different trust model, not a feature.

**What it needs from the spec stack.** Nothing new. It uses core identity
and delegation only.

**Commercial shape.** Free and open. This product exists to create the
identity root and the habit; it is the distribution channel for 2–4, not a
revenue line.

**90-day validation.** Twenty external repositories with agent-signed
commits verified in CI; one organization enforcing "agent commits must
verify" in branch protection; zero support tickets that require reading
Auths source.

### 2.2 Product 2 — Agent spend authority on Stripe

**Incumbent and its unit.** Ramp, Brex, and Stripe Issuing spend controls
authorize a *budget* on a card. Google's AP2 authorizes a signed *mandate*
for an agent purchase, which is the closest conceptual neighbor but is a
payments-network protocol, not an operator-side control over an existing
Stripe account.

**Auths' unit.** This refund, capture, cancel, transfer, or payout, on this
exact PaymentIntent or account, once, inside a grant such as "refunds up to
$500 on orders under 30 days old, until Friday", with a proof the finance
team or auditor can verify without the engineering team's logs.

**Repository readiness.** The deepest vertical in the repository:
AP-SPEC-010 through 023 cover refunds, capture, cancel, authorization,
Connect transfers, payouts, mandates, and subscription changes; 041 covers
the connection; `product/integrations/auths-stripe` exists. Verify which
of these are implemented versus specified before choosing the first three
operations.

**Buyer and champion.** Controller or CFO with a written "agents do not
touch money" policy that is currently blocking a finance-automation project.
Champion is the finance-systems or RevOps engineer who owns the Stripe
integration. Sell the unblocked workflow; the control is the enabler.

**Why the incumbent cannot copy quickly.** Card-level controls have no
primitive for "this object and no other". AP2 binds a mandate to a purchase
on the buyer side; it does not govern refunds, payouts, or subscription
changes on the merchant side, and it does not produce an operator-held
proof that a specific back-office action was authorized.

**What it needs from the spec stack.** 053 for credential isolation from
the agent (the Stripe secret key must live in the gateway), 055 for enum
arguments such as refund reason, and the bounded-policy layer in
AP-SPEC-025 for per-principal limits once more than one agent shares an
account. The first pilot can run with schema-level bounds alone.

**Commercial shape.** Paid managed gateway plus a Stripe operation pack.
Price against the automation it unblocks, not against the incumbent
control.

**90-day validation.** One design partner runs agent-initiated refunds or
subscription changes in production through the gateway, with finance
approving grants and reading proofs; the Stripe secret never leaves the
gateway process; every `unknown` outcome is reconciled by read-back and
none is retried automatically.

### 2.3 Product 3 — Production change gate

**Incumbent and its unit.** Terraform Cloud and Spacelift approve a *run*.
Argo CD gates a *sync*. OPA Gatekeeper and Kyverno evaluate a *policy*
against a manifest. Bytebase and similar tools review *SQL text*. All are
containers: the approved thing and the applied thing are not
cryptographically the same object.

**Auths' unit.** The saved-plan hash (OpenTofu), the exact rollout
specification (Kubernetes), or the bounded DML statement with row and value
limits (PostgreSQL), applied exactly once, with an approval that is bound to
the bytes that execute.

**Repository readiness.** AP-SPEC-007 Kubernetes rollouts, 008 OpenTofu
saved-plan apply, 009 PostgreSQL bounded data changes, and connections
042–043; `product/integrations/auths-kubernetes`, `auths-opentofu`,
`auths-postgresql` exist. Same caveat: confirm implementation status per
spec.

**Buyer and champion.** Platform or SRE lead who has been asked to let an
agent perform operational changes and has said no. Champion is the person
who owns the CI/CD or GitOps pipeline.

**Why the incumbent cannot copy quickly.** Their approval object is the run
or the policy decision, recorded in their own database. Binding approval to
the exact applied bytes with an externally verifiable proof requires a
signing and verification model they do not have and a canonical action
format they would have to standardize.

**How to enter.** Do not replace the incumbent. Ship as a Terraform Cloud
run task, an Argo CD pre-sync hook, or a Kubernetes admission webhook that
requires an Auths proof for the exact object. "Required check" is a
one-line change in the buyer's pipeline; "replacement" is a migration.

**What it needs from the spec stack.** Core and the existing verticals.
053 is optional here because the incumbent's runner, not the agent, holds
the cloud credential; the gate is non-bypassable by construction if the
runner enforces it.

**Commercial shape.** Open verifier and hooks; paid operations, retention,
and the managed control plane for grants and proofs.

**90-day validation.** One team runs agent-proposed OpenTofu applies or
Kubernetes rollouts in a real environment where the runner refuses any
apply without a proof for that exact plan hash; a deliberately modified
plan is rejected in front of the buyer.

### 2.4 Product 4 — Per-system-of-record write gateway from OpenAPI

**Incumbent and its unit.** Composio, Arcade, and Nango hold the token and
authorize by OAuth *scope*. Salesforce Agentforce, Workday, and ServiceNow
agent platforms authorize by *role* inside their own product. Model
platforms authorize by *tool allowlist*.

**Auths' unit.** A bounded, signed, one-use write to Salesforce, Workday,
NetSuite, or Jira through the 053 gateway, with the contract and recipe
derived from the vendor's own OpenAPI document by 056, reviewed, and
approved by digest.

**Repository readiness.** This is the product the 051–056 sequence is
building. Nothing is sellable until 053 ships and 056 has a corpus of
real vendor documents that shows the rejection rate.

**Buyer and champion.** Security or compliance lead at a company deploying
agents against systems of record, who needs to answer "what can the agent
change, and prove it". Champion is the platform engineer building the
agent. Sell to security; the developer is the user, not the buyer. The
09-18 paper is right that this category is crowded when sold to
developers as "another integration layer".

**Why the incumbent cannot copy quickly.** Token vaults are optimized for
breadth of connectors and OAuth flows; per-operation bounded contracts
with signed proofs are orthogonal to their architecture and would slow
their connector velocity. The SaaS vendors' own agent platforms cannot
offer a cross-vendor proof, and buyers do not want per-vendor audit
formats.

**How to enter.** One launch pack per system of record, starting with the
one a design partner already has agents writing to. Never "any API"; that
positioning is what the incumbents own and what the specs refuse.

**What it needs from the spec stack.** All of 053, 055, and 056, plus a
typed query-parameter segment in 053's recipe language, which many SaaS
write operations need and 056 currently rejects. Add reads through the
same gateway before a security reviewer asks, because data exfiltration is
a read.

**Commercial shape.** Paid managed gateway, per-system packs, and
compliance evidence retention.

**90-day validation.** Only after 053 ships: one pack, one design partner,
the vendor's real OpenAPI document deriving at least five write operations
with a documented rejection list, and one security reviewer signing off on
the proof format.

### 2.5 Product 5 — Embedded verification for API owners

**Incumbent and its unit.** OAuth scopes, API keys, and relationship or
policy engines (OpenFGA, Cerbos) authorize a *scope* or *relationship*
for a client.

**Auths' unit.** The API owner embeds the verifier, and each consequential
request from a customer, integration, or agent carries a proof for that
exact request. The gate is non-bypassable by construction because the
server checks before it executes; no 053 gateway is needed on the client
side.

**Repository readiness.** AP-SPEC-024, status Implemented, is this model
for one records API; the 09-19 paper's pilot package describes it.

**Buyer and champion.** The team that owns a customer-facing API and is
currently refusing or delaying a customer's automation request because
the only alternative is a broad long-lived credential.

**Why it is last despite the strongest technical position.** It asks API
owners to expose a new authorization model to their customers, which is
the slowest adoption curve on this list. The 09-19 paper's 30-day
falsifier still applies. Run it after product 2 or 3 produces a logo that
makes the model familiar.

**Commercial shape.** SDK plus verifier as open core; paid grant
management, receipt retention, and support.

**90-day validation.** As in the 09-19 paper: one design partner with a
blocked write workflow and a budget owner, validated within 30 days, or
deprioritize.

## 3. What not to build

- **An agent identity platform.** Okta, Entra, SPIFFE, and several startups
  own that narrative. Auths' identity layer is a substrate for products 1–5,
  not a product.
- **A universal MCP or HTTP gateway.** Both prior papers say this; the
  052/024 amendments and 053 §3.2 encode it. "Support any API" is the
  incumbents' claim and the specs' non-goal.
- **A unified API.** Breadth of connectors is Composio's and Nango's game and
  their moat.
- **A standalone receipt or audit product.** Proofs are a feature of every
  product above. Sold alone, they compete with SIEM and GRC tools that
  already have the buyer.

## 4. Sequencing and dependencies

```text
 now         weeks         ~2 months          ~4 months          later
  |            |               |                  |                 |
  1 signing ---+-- 2 Stripe ---+-- 3 change gate -+-- 4 SoR gateway +-- 5 API owner
  (core only)     (053 opt.)      (core + verticals)  (053+055+056)    (024 model)
                                                        |
                                            053 Epic 1 ADR -> recipe AST -> 056 corpus
```

Product 1 depends on nothing and should ship first. Product 2 can pilot on
schema-level bounds before 053 lands, but the production claim needs 053
so the Stripe secret is isolated from the agent. Product 3 needs only core
and the verticals. Product 4 is gated on 053 and 056 and should not be
promised to a customer before 053 Epic 1's ADR is committed. Product 5 is a
timing decision, not a technical one.

Cross-cutting dependency: AP-SPEC-025 bounded policy is needed as soon as
two agents share one contract with different limits. Until then, contract
bounds from 054/055 carry the intent.

## 5. Risks and falsifiers

| Risk | How it would show up | What to do |
| --- | --- | --- |
| Buyers accept container-level authorization as good enough | Design partners for 2 and 3 say "run approval is fine" | Lead with a demonstrated failure: an approved run applying a modified plan, or an agent refund outside policy. If the demo does not change minds, the wedge is wrong. |
| Rejection rate on real OpenAPI documents makes 056 feel broken | First derivation of a vendor document yields more rejections than fields | Publish the rejection list as a feature; add typed query segments and omit-when-null to 053 if they dominate the list. |
| AP2 or a payments-network mandate standard absorbs product 2 | Stripe ships operator-side mandate controls for back-office actions | Position Auths as the verifier and proof format for mandates rather than a competitor; the exact-action commitment is compatible. |
| Signing product creates support load without revenue | Repositories adopt product 1 but nothing converts | Acceptable for one quarter; it exists to seed identity roots. Measure conversion to 2–3 conversations, not revenue. |
| Reads outside the gate undermine the "agents can't" claim | A security reviewer asks how data exfiltration is prevented | Say "writes" everywhere until reads go through 053. Do not let marketing say "actions". |

## 6. Thirty-day plan

1. Ship product 1: a GitHub Action that verifies agent-signed commits
   through a pinned root, a ten-minute README, and the `claude-release`
   recipe as the worked example. Target twenty repositories.
2. Pick the first three Stripe operations for product 2 from the 010–023
   specs by implementation status, and book one finance-side design partner
   conversation using the demo script "refund inside policy passes; refund
   outside policy is denied before the key is touched".
3. Build the product 3 demo as a Terraform Cloud run task or Argo pre-sync
   hook that rejects a modified plan hash in front of the buyer.
4. Commit 053 Epic 1's ADR so product 4 has a start date that can be quoted.
5. Re-run the 09-19 paper's interview prompts with the framing "which
   approval in your pipeline is not bound to what actually executed?" and
   record the answers by product.
