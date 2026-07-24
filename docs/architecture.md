# Architecture

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
| Model | `auths-proof-model` | Validated protocol vocabulary and verdicts |
| Encoding | `auths-proof-codec` | Deterministic CBOR, signing bytes, identifiers |
| Ports | `auths-proof-adapter-api` | Principal-control and grant-status traits |
| Kernel | `auths-proof-verifier` | Authority attenuation and action verification |
| Authoring | `auths-proof-author` | Keyless draft/signature attachment workflow |
| Shared pure primitive | `auths-proof-multikey` | Closed Ed25519/P-256 Multikey parsing and verification |
| Adapters | `auths-proof-raw-key`, `auths-proof-did-key`, `auths-proof-did-keri`, `auths-proof-did-web` | Concrete principal-control proofs |
| Native resolution | `auths-proof-did-web-http` | Policy-constrained retrieval and trust-record production |
| Composition | `auths-proof-cli` | Files, flags, output, explicit adapter registry |
| Assurance | `auths-proof-testkit`, `xtask` | Fixtures, conformance, architecture checks |

Core crates contain no network, filesystem, process, environment, system
clock, randomness, private keys, databases, Git, or async runtime.

Concrete pure adapters also contain no network. The native HTTP resolver is a
leaf integration crate: adapters and the verifier cannot depend on it.

`cargo xtask arch` reads `cargo metadata` and rejects forbidden dependency
edges.

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
local trust anchor
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
Authorized | Denied | Indeterminate
```

## Extending identity support

A new principal method:

1. defines an exact adapter ID and evidence media type;
2. implements `PrincipalControlVerifier`;
3. verifies principal-to-method binding, purpose, algorithm, signature, and
   method-specific evidence;
4. reports only assurance actually established;
5. passes the shared conformance suite;
6. is instantiated explicitly by the host application.

The verifier never depends on the concrete adapter and never tries adapters
until one happens to accept.

Milestone 2 enforces that separation with mixed chains in both directions:

```text
did:keri root -> raw-key agent -> exact action
raw-key root  -> did:keri agent -> exact action
```

The same authority path verifies both. Only the exact adapter lookup and its
principal-control result differ.

Milestone 3 adds a second boundary:

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
gateways, budgets, storage, dashboards, and execution are application-layer
concerns. See the strict-boundary section of
`AUTHS_PROOF_GREENFIELD_FOUNDATION.md`.
