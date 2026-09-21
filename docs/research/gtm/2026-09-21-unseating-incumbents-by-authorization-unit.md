# Auths Proof: a portable authority format incumbents can emit and accept

- **Date:** 2026-09-21
- **Builds on:** [2026-09-18 go-to-market research](2026-09-18-go-to-market-and-product-opportunities.md)
  and [2026-09-19 product directions](2026-09-19-auths-proof-product-directions.md)
- **Assumes:** the self-hosted stack (AP-SPEC-051–052) is still being frozen;
  the declared-recipe gateway (053) and OpenAPI derivation (056) are not built;
  the enum node (055) is implemented but does not restrict grants by variant
- **Confidence:** competitive claims are planning judgments from public
  product behavior as of this date, not measured market data; repository
  readiness claims cite spec numbers and should be checked against each
  spec's `Status` line before any customer promise

## Decision

Pick incumbent credential owners by one rule and integrate in one order.

**The rule.** Several incumbents already inspect exact arguments, bind saved
plans, or mediate credentials. Auths' proposed distinction is a *portable*
proof of delegated authority for one canonical action that another party can
verify offline. A one-use claim controls admission within its configured
store; it does not establish exactly one external effect. Prioritize workflows
where this independent artifact and an enforced credential boundary matter
enough to justify integration with the existing owner.

**The order.**

1. Agent commit and release signing (tests a distribution path; still needs
   AP-SPEC-058 and external adoption evidence).
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
#5: right mechanism, early timing. Neither lists #1. A KERI-coupled sibling
project has a reported working signing path, but auths-proof has not yet
shipped the method-agnostic path or demonstrated adoption.

## 1. Why the unit of authorization is the wedge

The market is converging on agent authorization from identity (Okta, Entra,
Descope), token custody (Arcade, Composio, Nango), policy (Permit, OpenFGA,
Cerbos, OPA), and model-platform tool permissions. Existing products can
already inspect structured arguments or bind an exact saved artifact. The
question Auths may answer differently is whether a party outside that
product can verify the *delegated authority* for the exact action. Provider
entry, ambiguous delivery, and observed effect remain separate questions.

Auths has some primitives for that question; 053/056 remain proposed work
needed to extend the boundary without an Auths-authored provider profile:

| Primitive | Where it exists | What it changes for a buyer |
| --- | --- | --- |
| Exact canonical action commitment | core, `auths.mcp/v2`, 051 | authorization names the write, not the tool |
| Offline-verifiable proof under a delegated, revocable identity | core method registry and verifier; convenient git signing on auths-proof is Epic 3 work | an auditor can verify under supplied, sufficiently fresh trust; not independent discovery of later revocation |
| One-use atomic claim with `unknown` as a first-class outcome | 051–052 local attempt store and runner | no blind automatic retry in that voluntarily used runner; no external exactly-once claim |
| Credential isolated from the application | 053 gateway, specified but not built | would constrain the gateway-held credential only under tested deployment isolation |
| Bounded schema with closed enumerations | 054 §5, 055 | command values can be restricted by contract; grant-level variant restriction is still 025 work |
| Contracts and recipes derived from vendor OpenAPI | 056, specified but not built | could reduce authoring for operations that pass a measured rejection wall |
| Selected translated authority predicates | `formal/` | authority, attenuation, lifecycle, and bounded-policy predicates are translated to Lean and refined under stated assumptions; decoding, cryptography, and storage remain outside that surface |

The last row is unusual enough to lead with in regulated conversations and
irrelevant everywhere else. Do not put it on the front page.

## 2. The five products

Each entry uses the same template so they can be compared. "Repository
readiness" names specs, not implementation status; check each spec before
quoting it.

### 2.1 Product 1 — Agent commit and release signing

**Incumbent and its unit.** Sigstore and `gitsign` bind a keyless signature
to an OIDC identity; GitHub can enforce signed commits. CI agents obtain
workload identity through OIDC today; local and offline agents do not have
the same convenient issuance path. Auths treats Sigstore keyless and OIDC
workload identity as principal methods, not as incompatible competitors.

**Auths' unit.** A delegated key with separate `sign_commit` and
`sign_release` scopes, an expiry, and one-line revocation, anchored under
the maintainer's root. Verification resolves the delegation chain, not the
operator's session.

**Repository readiness.** The reported `claude-release` and auths#381
signing path is in a KERI-coupled sibling project and was not independently
checked in the review. Auths-proof still needs AP-SPEC-058, a method-agnostic
signer/verifier path, and adoption evidence. It is not just packaging work.

**Buyer and champion.** Engineering leads adopting coding agents; security
teams asking "which commits did an agent make, and under whose authority?"
Champion is whoever owns branch protection.

**What remains distinctive after the incumbent's cheapest response.** A
focused team could add a signed, scoped approval envelope at merge/release
in roughly **6–12 weeks**; polished cross-host portability may take **2–3
quarters** (independent review §H, estimates, not a roadmap). Auths could
offer one delegated-authority artifact across hosts and local/offline agents.
That value still needs a working auths-proof signer and external adoption.

**What it needs from the spec stack.** AP-SPEC-058 and Epic 3 evidence on
auths-proof; core identity and delegation alone are not a user-ready git path.

**Commercial shape.** Free and open. This product exists to create the
identity root and the habit; it is the distribution channel for 2–4, not a
revenue line.

**90-day validation.** Twenty external repositories with agent-signed
commits verified in CI; one organization enforcing "agent commits must
verify" in branch protection; zero support tickets that require reading
Auths source.

### 2.2 Product 2 — Agent spend authority on Stripe

**Incumbent and its unit.** Ramp, Brex, and Stripe Issuing have spend
controls; Google's AP2 already specifies signed, constrained purchase
authorization. Auths should not imply they only authorize an undifferentiated
budget or that AP2 merely signs intent. The merchant-side refund/payout
workflow and portable delegation are the proposed distinction.

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

**What remains distinctive after the incumbent's cheapest response.** An
incumbent could add an agent identifier, action hash, approval, and durable
consumption record in about **one quarter** for a narrow workflow; wider
interoperability might take **2–4 quarters** (review §H estimates). Auths
could carry the same offline-verifiable delegation across payments and
non-payment provider effects, but still needs integration, liability, and
settlement evidence that incumbents already partly own.

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

**Incumbent and its unit.** Terraform and related platforms can bind an
approval to a saved plan; admission controllers can inspect a manifest or
policy decision. They are not uniformly limited to coarse runs or roles.
Auths' possible increment is one portable proof of delegated authority
across those otherwise separate workflows.

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

**What remains distinctive after the incumbent's cheapest response.** A
focused incumbent could bind a digest and require approval for one workflow
in **6–12 weeks**; a common multi-tool product may take **2–4 quarters**
(review §H estimates). Auths could standardize independently verifiable
delegation across tools, but the same stale-state and side-effect recovery
problems remain for Auths too.

**How to enter.** Do not replace the incumbent. Integrate a proof check at
the executor or admission boundary for the exact object, then test that no
alternate apply path bypasses it. A required check is a deployment change,
not automatically a one-line security guarantee.

**What it needs from the spec stack.** Core and the existing verticals.
053 is optional here if a separately controlled incumbent runner alone holds
the cloud credential and every relevant execution path enforces the proof;
that isolation and coverage must be tested, not inferred from placement.

**Commercial shape.** Open verifier and hooks; paid operations, retention,
and the managed control plane for grants and proofs.

**90-day validation.** One team runs agent-proposed OpenTofu applies or
Kubernetes rollouts in a real environment where the runner refuses any
apply without a proof for that exact plan hash; a deliberately modified
plan is rejected in front of the buyer.

### 2.4 Product 4 — Per-system-of-record write gateway from OpenAPI

**Incumbent and its unit.** Composio, Arcade, and Nango mediate credentials;
Arcade and Composio already expose pre-execution argument inspection, and
Nango offers a credential proxy. Salesforce Agentforce, Workday, and
ServiceNow agent platforms also govern actions within their own products.
Enterprise-suite equivalents were not checked individually in the review.

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

**What remains distinctive after the incumbent's cheapest response.** An
existing gateway could add a fail-closed check over normalized arguments
and durable execution ID in **4–12 weeks** for one feature, or **1–2
quarters** for a hardened managed policy product (review §H estimates).
The proposed Auths distinction is independently verifiable delegation plus
an operator-approved, digest-bound, data-only recipe—not merely inspecting
arguments. The 053 gateway has not yet demonstrated that boundary.

**How to enter.** One launch pack per system of record, starting with the
one a design partner already has agents writing to. Never "any API"; that
positioning is what the incumbents own and what the specs refuse.

**What it needs from the spec stack.** 053 and 056 are unbuilt; 055 is
implemented. A typed query-parameter segment remains an explicit 053/056
extension candidate, not an existing capability. The self-hosted and proposed
gateway paths govern writes; AP-SPEC-024 §10's records API governs exact
reads. An application with an independent read credential is not constrained
by a write gate. General read authorization and confidentiality require
separate coverage and egress assumptions.

**Commercial shape.** Paid managed gateway, per-system packs, and
compliance evidence retention.

**90-day validation.** Only after 053 ships: one pack, one design partner,
the vendor's real OpenAPI document deriving at least five write operations
with a documented rejection list, and one security reviewer signing off on
the proof format.

### 2.5 Product 5 — Embedded verification for API owners

**Incumbent and its unit.** OAuth scopes and API keys can be coarse, but
OpenFGA conditions and Cerbos request attributes already support structured
policy decisions. The comparison is not exact requests versus static roles.

**Auths' unit.** The API owner embeds a verifier, and each consequential
request from a customer, integration, or agent carries a proof for that
exact request. Enforcement depends on the owner routing every relevant
path through the check and withholding alternate credentials; placement
inside the server alone is not a non-bypassability proof. No 053 gateway is
needed on the client side when the owner controls that boundary.

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

**What remains distinctive after the incumbent's cheapest response.** An
API owner could put exact request attributes, a request ID, and durable
consumption behind an existing policy engine in about **one quarter**;
a polished multi-language offering may take **2–3 quarters** (review §H
estimates). Auths' possible increment is portable offline delegation chains
without an online central policy decision, if buyers value that portability
enough to adopt a new format.

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
 proposed sequencing; dates depend on the gates and buyer evidence
  |            |               |                  |                 |
  1 signing ---+-- 2 Stripe ---+-- 3 change gate -+-- 4 SoR gateway +-- 5 API owner
  (058 + trial)    (053 for       (vertical-specific   (053+056;       (024 model)
                   isolation)     boundary testing)    055 built)
                                                        |
                                            053 Epic 1 ADR -> recipe AST -> 056 corpus
```

Product 1 needs AP-SPEC-058 and external adoption evidence before shipping.
Product 2 can pilot on
schema-level bounds before 053 lands, but the production claim needs 053
so the Stripe secret is isolated from the agent. Product 3 needs only core
and the verticals plus deployment coverage tests. Product 4 is gated on 053
and 056 and should not be
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

1. Specify AP-SPEC-058 and prototype product 1 in auths-proof: a GitHub
   Action verifying agent-signed commits through pinned trust, a ten-minute
   README, and three principal methods. The sibling project's
   `claude-release` recipe is prior art to port, not proof this ships today.
   Target twenty genuinely external repositories; do not simulate adoption.
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
