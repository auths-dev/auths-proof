# Product surface evolution strategy

## Decision

Auths ships the smallest complete product surface that preserves its security
model. Protocol machinery remains implemented and tested, but it is not public
merely because it exists.

The initial SDK experience is organized around five verbs:

```text
create -> delegate -> execute -> resume -> verify
```

Users progressively disclose more control through qualified profiles,
integrations, framework contracts, and testkit conformance. They do not begin
by assembling trust compilation, authority authoring, lifecycle transitions,
approval transactions, runtime stores, provider sessions, and receipts.

This is a product boundary, not a reduction in the Rust semantic model.

## Why the surface is smaller than the implementation

The implementation must understand more than an application developer should
have to understand. Auths still needs exact authority, attenuation, trust,
status, signing, approval, replay, reservation, recovery, reconciliation, and
receipt semantics. Exposing each subsystem as a peer SDK module makes those
mechanisms look like separate products and invites applications to coordinate
security transitions themselves.

The public surface therefore describes customer purposes:

| Purpose | Public owner |
| --- | --- |
| Protected workflow | root SDK |
| Independent identity and authentication | `identity` |
| Effect-free proof, decision, and receipt verification | `verify` |
| Qualified effect-domain semantics | `profiles` |
| Maintained compositions and mechanism adapters | `integrations` |
| Proven extension contracts | `framework` |
| Deterministic fixtures and conformance | `testkit` |

Everything else is private unless evidence establishes a durable public use.

## Three dispositions

### Private semantic machinery

Authority construction, trust compilation, lifecycle transitions, command
minting, approval-transaction coordination, recovery state, and receipt
attestation remain private by default. They are security-critical parts of the
product waist, not an advanced menu that should automatically return after
launch.

Private does not mean unimportant or untested. These components retain Rust
ownership, cross-language fixtures, adversarial tests, and formal or
conformance evidence where applicable.

### Evidence-gated extension contracts

A lower-level contract may become public when at least two materially
independent completed verticals require the same semantics. The extraction
must preserve one meaning across those verticals rather than generalize their
differences away.

Signer custody and atomic reservation satisfy that rule today. A clock,
telemetry port, distributed store, or profile-authoring primitive may qualify
later. A universal provider result or reconciler does not qualify merely
because several integrations perform I/O.

Promotion requires:

1. two independent production-shaped consumers;
2. one precise semantic owner;
3. TypeScript and Python parity;
4. an Auths-owned conformance suite;
5. bounded failure and resource-lifecycle behavior; and
6. evidence that public control cannot bypass Rust-owned transitions.

### Concrete product verticals

Effect semantics return as concrete, qualified profiles rather than generic
categories. Stripe, Kubernetes, Cloudflare, GitHub, PostgreSQL, and Records may
each own actions, authority projection, provider entry, outcomes,
reconciliation, receipts, and domain failures.

Generic HTTP, Git, deployment, supply-chain, and edge profiles are not useful
substitutes. They describe transport or broad categories while erasing the
domain facts needed to decide whether an effect occurred or can be retried.

## How traction changes the roadmap

Product-market fit supplies evidence about where users need control. It does
not justify exposing all internals.

| Observed demand | Likely response |
| --- | --- |
| Enterprises require HSM or KMS custody | expand the proven custody contract and maintained integrations |
| Operators require durable distributed recovery | qualify atomic storage implementations and production compositions |
| Multiple teams successfully build distinct verticals | extract only their shared profile-authoring contracts |
| Customers repeatedly protect Cloudflare changes | qualify a concrete Cloudflare profile |
| Support teams need richer explanations | add bounded inert projections to root or `verify` |
| A customer requests raw command/session handles | improve the closed workflow unless a safe independent purpose is proven |

The governing question is:

> Does this request reveal a reusable customer purpose, or does it ask the
> application to coordinate Auths' security internals?

The first can justify a public surface. The second usually means the product
waist needs to become more capable.

## Promotion and rejection gates

A proposed public API must identify:

- the customer journey it shortens;
- why the root, a profile, or an integration cannot own it;
- its semantic owner;
- whether it is effect-capable;
- its failure, cancellation, and disposal behavior;
- its TypeScript and Python shape;
- installed-artifact tests and conformance evidence; and
- the narrower alternative considered.

Reject the proposal when it:

- exposes native commands or session steps;
- lets bindings decide authorization or transition meaning;
- invents a generic provider, result, or reconciler;
- duplicates an existing purpose under a mechanism name;
- has only one real consumer;
- exists only to mirror a Rust crate; or
- creates language-specific power without SDK parity.

## Prelaunch and stable evolution

Before 1.0, obsolete public paths are deleted without aliases, warnings,
forwarders, or migration layers. Git history records prelaunch changes.

After 1.0, public promotion is a compatibility commitment. Package API,
portable ABI, semantic subject, profile version, error identity, receipt/state
schema, and conformance suite evolve under the versioning policy. Private
implementation may continue to change freely when those public meanings remain
coherent.

## Desired outcome

Auths should feel small at first contact and deep under pressure:

```text
ordinary application       concrete domain       infrastructure author
        |                         |                         |
      root SDK                profiles                  framework
        |                         |                         |
        +---------------- integrations -------------------+
                                  |
                        private Rust semantic waist
```

The product succeeds when beginners can protect an effect without learning
the architecture, while advanced teams can replace infrastructure or add a
qualified vertical without weakening Auths meaning.
