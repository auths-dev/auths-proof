# auths-proof

> Bring any cryptographic principal. Auths proves whether its action was
> authorized.

`auths-proof` is a small protocol and offline verification kernel for
proof-carrying authorization:

> Every action carries proof that it was authorized.

The architectural rule is:

> Auths owns authority. Adapters prove principal control.

## Status

Milestones 0 through 3 are implemented:

- frozen pre-audit V1 specification and CDDL;
- deterministic, bounded CBOR codec;
- exact permission and delegation attenuation;
- explicit trust anchors and three-way verdicts;
- raw Ed25519 and P-256 principals;
- pure, bounded, offline `did:keri` principal verification;
- self-contained Ed25519/P-256 `did:key` principals;
- pure bundled `did:web` verification with explicit current and historical
  trust records;
- a separate policy-constrained native `did:web` HTTPS resolver;
- KERI rotation, threshold, pre-rotation commitment, and CESR verification;
- independent keripy interoperability fixtures;
- keyless authoring requests;
- offline verifier and CLI;
- mixed-algorithm and mixed-principal golden fixtures;
- property, conformance, architecture, and WASM checks.

This is version `0.1.0`, pre-audit software. It is not yet production-ready.
All identity methods remain explicit adapters, not hidden dependencies or
special cases in the kernel.

Milestone 4 is implemented in two independently versioned companion
repositories: `auths-proof-exchange` owns the transport-neutral exchange
protocol and Iroh adapter, while `auths-proof-mcp` owns the first exact MCP
`tools/call` application profile. Neither networking nor MCP enters this
kernel's dependency graph.

## Verify the walkthrough fixture

```sh
cargo run -p auths-proof-cli -- inspect \
  --proof fixtures/v1/valid/mixed-ed25519-p256.cbor
```

```sh
cargo run -p auths-proof-cli -- verify \
  --proof fixtures/v1/valid/mixed-ed25519-p256.cbor \
  --body fixtures/v1/valid/action.json \
  --now 1725000125 \
  --audience mcp://filesystem \
  --challenge-hex a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5 \
  --anchor-principal key:sha256:dn9ZYzD5Wup7QPTK36C8xM2uAKmJNAYXt4-vO9mFkYg \
  --anchor-capability mcp.tools.call \
  --anchor-resource mcp://filesystem/read_file \
  --anchor-valid-from 1725000000 \
  --anchor-valid-until 1725000300 \
  --anchor-depth 1
```

Expected result:

```text
Authorized
reason  AuthorizedByGrantChain
```

The root is Ed25519 and the terminal actor is P-256. The verdict also reports
that raw-key principals and the expiry-only grant are irrevocable until their
configured expiry.

## CLI

```text
auths-proof verify          verify a bundle against explicit local context
auths-proof inspect         inspect a canonical bundle without trusting it
auths-proof raw-evidence    package an existing public key as raw-key evidence
auths-proof grant-request   emit grant request CBOR and exact signing bytes
auths-proof grant-attach    attach an externally produced grant signature
auths-proof action-request  emit action request CBOR and exact signing bytes
auths-proof action-attach   attach an externally produced action signature
auths-proof bundle          assemble signed objects and evidence
auths-proof did-web-resolve fetch trusted current did:web evidence explicitly
```

The CLI never creates or stores private keys. A KMS, HSM, passkey flow, SSH
agent, CI signer, or other external signer receives the emitted signing bytes.

`verify` performs no network requests. A `did:web` proof requires one or more
explicit `--did-web-trust` files. Create a current evidence/trust pair
separately:

```sh
auths-proof did-web-resolve \
  --did did:web:identity.example.com \
  --allow-host identity.example.com \
  --observed-at 1725000125 \
  --valid-until 1725000425 \
  --evidence-out did-web.evidence.cbor \
  --trust-out did-web.current.trust
```

Trust files are verifier configuration and must not be accepted from an
untrusted prover.

Verification exit codes:

| Code | Meaning |
|---:|---|
| 0 | `Authorized` |
| 1 | CLI/input failure |
| 2 | `Denied` |
| 3 | `Indeterminate` |

## Workspace

```text
model <- codec -----+----> author
  |                 |
  +-> adapter-api --+----> verifier
         ^                    ^
         |                    |
 raw / DID adapters        CLI composition
                               ^
                               |
                         HTTP resolver leaf
```

- `auths-proof-model`: validated protocol types;
- `auths-proof-codec`: deterministic CBOR and domain-separated identifiers;
- `auths-proof-multikey`: shared closed Ed25519/P-256 Multikey primitive;
- `auths-proof-adapter-api`: pure principal/status ports;
- `auths-proof-verifier`: authority and action verification;
- `auths-proof-author`: keyless signing requests and bundle assembly;
- `auths-proof-raw-key`: Ed25519/P-256 reference adapter;
- `auths-proof-did-keri`: pure embedded-KEL principal adapter;
- `auths-proof-did-key`: pure self-contained DID adapter;
- `auths-proof-did-web`: pure bundled-document adapter;
- `auths-proof-did-web-http`: native retrieval and trust-record production;
- `auths-proof-testkit`: deterministic fixtures and conformance;
- `xtask`: architecture, vector, WASM, and release checks.

See:

- [Greenfield foundation](AUTHS_PROOF_GREENFIELD_FOUNDATION.md)
- [V1 protocol](spec/v1/protocol.md)
- [`did:keri` adapter profile](spec/v1/did-keri.md)
- [`did:key` adapter profile](spec/v1/did-key.md)
- [`did:web` evidence and trust profile](spec/v1/did-web.md)
- [Verification algorithm](spec/v1/verification-algorithm.md)
- [Threat model](docs/threat-model.md)
- [Architecture](docs/architecture.md)

## Development

```sh
cargo xtask ci
```

Golden vectors are checked byte-for-byte:

```sh
cargo xtask wire
```

Only after reviewing an intentional protocol change:

```sh
cargo xtask wire --update
```

## Strict boundary

The proof kernel does not own key custody, live DID resolution, witness
networks, identity directories, OAuth, gateways, policy languages, budgets,
databases, Git registries, dashboards, or action execution. The reference
`did:web` resolver is an explicit native leaf: it produces evidence and local
trust records but cannot verify authority.

If a feature cannot be evaluated deterministically from the proof and explicit
context, it belongs above the kernel.
