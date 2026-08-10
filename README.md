# Auths

Auths is an open protocol and SDK for proof-carrying, bounded machine
authority. The `auths-proof` component is its strictly offline reference
kernel for Auths Proof Protocol V1.

> Auths owns authority. Adapters establish bounded facts.

The workspace contains only the target V1 model, deterministic codec,
effect-free ports and registries, mandatory Ed25519 and P-256/SHA-256 suites,
authority attenuation, authorization-plan composition, assurance, status,
staged verification, keyless authoring, raw-key, `did:key`, `did:keri`,
bundled `did:web`, SPIFFE/X.509, WebAuthn, and HSM-attested methods, and the
canonical language-neutral corpus.

The sealed verification pipeline is:

```text
untrusted bytes
  -> DecodedProof
  -> ResolvedProof
  -> ControlVerifiedProof
  -> VerifiedAuthority
  -> VerifiedAction
```

The language-neutral boundary is
`verify_v1(proof_cbor, canonical_action_cbor, trusted_context_cbor) ->
verification_result_cbor`. The result includes stable stage/code values,
self-binding digests, authorized branches, assurance satisfactions, and
resource/work totals.
The trusted context also binds the verifier-required composition obligation
and the exact executable adapter/registry configuration commitment.

`VerifiedAction` has no public constructor. The kernel reads no clock,
environment variable, network connection, filesystem, database, replay store,
budget store, profile implementation, receipt sink, or private key. Every
trust anchor, accepted executable registry and manifest, evaluation time,
expected audience/challenge, status snapshot and issuer/floor trust,
assurance policy, resource matcher, profile/channel policy, detached
attachment input, and resource limit is an explicit immutable verifier input.

Target packages:

- `auths`: supported consumer-facing Rust core facade;
- `auths-sdk`: idiomatic embedded authorization SDK;
- `auths-proof`: bounded proof-protocol component and actionable results;
- `auths-proof-wasm`: prebuildable three-input WebAssembly boundary;
- `auths-model`: validated V1 protocol and context types;
- `auths-codec`: constrained deterministic CBOR and domain-separated IDs;
- `auths-ports`: effect-free principal-method and signature-suite ports;
- `auths-registries`: exact immutable implementations, status handlers, and
  verifier-configuration commitments;
- `auths-signature`: mandatory Ed25519 and low-S P-256 suites;
- `auths-authority`: scoped trust roots and grant attenuation;
- `auths-composition`: proof, all-of, any-of, and K-of-N plans;
- `auths-assurance`: role-indexed evidence assurance;
- `auths-verifier`: the sealed pure pipeline;
- `auths-author`: external-signing requests with no custody;
- `auths-multikey`: the closed canonical Ed25519/P-256 Multikey subset;
- `auths-raw-key`: self-certifying raw-key evidence;
- `auths-identity`: transport- and algorithm-independent identity packets and
  extension ports;
- `auths-identity-raw-key`: optional self-certifying raw-key identity adapter;
- `auths-signature-ed25519`: optional standalone Ed25519 identity-signature
  adapter;
- `auths-iroh`: semantics-free bounded byte exchange over Iroh;
- `auths-did-key`: self-certifying `did:key` evidence;
- `auths-did-keri`: bounded offline KEL replay with threshold and rotation
  commitment verification;
- `auths-did-web`: locally pinned, bundled `did:web` evidence with distinct
  current, historical, and statement-existence claims;
- `auths-webauthn`: challenge-bound WebAuthn assertions with RP, origin,
  presence, verification, counter, and attestation-policy checks;
- `auths-hsm-attested`: verifier-pinned attestation profiles with protection,
  exportability, device-chain, key-handle, and transaction binding;
- `auths-spiffe-x509`: bounded X.509-SVID path, URI SAN, client-EKU,
  trust-domain, key-suite, validity, and local status verification;
- `auths-testkit`: canonical positive and negative corpus construction.

## Identity without authorization

Teams can adopt algorithm-neutral identity packets and Iroh transport without
loading a grant, capability, approval, policy, lifecycle, store, or product
runtime. `auths-identity` has zero workspace and cryptographic dependencies;
callers supply identity-method and signature-suite implementations. The
repository includes raw-key and Ed25519 adapters only as proofs of that port.
`auths-iroh` carries arbitrary bounded bytes under an application-selected
ALPN. Neither component depends on the other or manufactures authorization.

Run the full native backend and browser workbench with:

```sh
cargo run -p auths-identity-iroh-demo
```

Then open `http://localhost:8080`. Architecture CI pins both the neutral
identity port and Iroh transport to zero workspace dependencies, while each
optional identity adapter may depend only on `auths-identity`.

Focused validation:

```sh
cargo xtask arch
cargo xtask wire
cargo xtask conformance
cargo xtask fuzz-smoke
cargo run -p auths-proof-offline-example
```

Canonical `.cbor` files are generated only through:

```sh
cargo xtask wire --update
```

Networking and transports belong to the `auths-proof-exchange` components.
Profiles, live resolvers, runtime state, receipts, execution, custody,
independent implementations, and Auths Lab remain outside the offline proof
kernel in the workspace's product and demo layers.

This repository is prelaunch and pre-audit. Passing corpus, fuzz-smoke, and
WASM equivalence gates is not an independent security review.
