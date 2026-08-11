# Architecture

Product-facing terms are defined in the [Auths product glossary](product/GLOSSARY.md).
This document uses exact framework and protocol terminology.

## Rule

> Auths owns authority. Adapters prove principal control.

```text
external signer -> authoring requests -> ProofBundle
                                         |
bundled evidence -> allowlisted adapters |
                         |               |
                         v               v
                  VerifiedPrincipal -> verifier -> TrustVerdict
                         ^
local trust anchors -----+
```

The verifier is the product kernel. It is deterministic and receives all
ambient facts explicitly. It does not resolve identities or evidence.

## Layers

| Layer | Crates | Responsibility |
|---|---|---|
| Model | `auths-model` | Validated protocol vocabulary, context, and verdict reasons |
| Encoding | `auths-codec` | Deterministic CBOR, signing preimages, and typed identifiers |
| Ports and registries | `auths-ports`, `auths-registries` | Principal, suite, resource, profile, budget, extension, status, assurance, and immutable manifest-bound executable registries |
| Kernel | `auths-verifier`, `auths-authority`, `auths-composition`, `auths-assurance`, `auths-registries` | Sealed verification, attenuation, plans, assurance, and exact configured status handling |
| Authoring | `auths-author` | Safe authority planning, diffs, warnings, and keyless signing requests |
| Shared pure primitive | `auths-multikey` | Closed Ed25519/P-256 Multikey parsing |
| Adapters | `auths-raw-key`, `auths-did-key`, `auths-did-keri`, `auths-did-web`, `auths-spiffe-x509`, `auths-webauthn`, `auths-hsm-attested` | Exact principal-control and evidence verification |
| Native resolution | downstream `auths-proof-apps/integrations/auths-resolver-did-web` | Policy-constrained retrieval and trust-record production |
| Signature suites | `auths-signature` | Mandatory Ed25519 and low-S P-256 verification |
| Conformance | `auths-testkit`, `xtask`, `fuzz` | Corpus, architecture, native/WASM, property, and parser checks |

Core crates contain no network, filesystem, process, environment, system
clock, randomness, private keys, databases, Git, or async runtime.

Concrete pure adapters also contain no network. The native HTTP resolver is a
leaf integration crate: adapters and the verifier cannot depend on it.

`cargo xtask arch` reads `cargo metadata`, rejects forbidden dependency
edges, and fails closed on an unclassified workspace package.

## Verification data flow

```text
untrusted bytes
   |
   v
bounded strict CBOR decoder
   |
   v
evidence/reference graph validation
   |
   v
branch-local control results
   |
   v
all plan leaves + local trust anchors
   |
   v
grant[0] -> grant[1] -> ... -> terminal principal
   |           |
   +--> exact adapter principal-control verification
   |
   v
action body/audience/challenge/time/signature
   |
   v
signed attachment integrity + exact pure policies
   |
   v
Authorized | Denied | Indeterminate
```

## Extending identity support

A new principal method:

1. defines an exact adapter ID and evidence media type;
2. implements `PrincipalMethod`;
3. verifies principal-to-method binding, purpose, algorithm, signature, and
   method-specific evidence;
4. reports only assurance actually established;
5. passes the shared conformance suite;
6. is instantiated explicitly by the host application.

The verifier never depends on the concrete adapter and never tries adapters
until one happens to accept.

The corpus enforces that separation with mixed chains in every supported
root/actor direction, including:

```text
did:keri root -> raw-key agent -> exact action
raw-key root  -> did:keri agent -> exact action
```

The same authority path verifies both. Only the exact adapter lookup and its
principal-control result differ.

Live evidence acquisition adds a second boundary:

```text
native HTTP resolver -> document + local trust record
                                  |
                                  v
                         pure did:web adapter
                                  |
                                  v
                       unchanged authority kernel
```

## Scope stop

Key custody, live resolution, witness networks, directories, policy engines,
gateways, budgets, storage, dashboards, and execution are downstream
application concerns. Exchange/framing belongs to `auths-proof-exchange`;
profiles and effects belong to `auths-proof-apps`.
