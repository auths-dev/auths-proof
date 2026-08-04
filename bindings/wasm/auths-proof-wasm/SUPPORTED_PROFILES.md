# WASM supported profiles

The prebuilt self-contained distribution exposes:

| Principal method | Configuration source | Signature suites |
|---|---|---|
| `raw-key-v1` | stateless compiled adapter | Ed25519, P-256/SHA-256 |
| `did-key-v1` | stateless compiled adapter | Ed25519, P-256/SHA-256 |
| `did-keri-v1` | compiled default limits, no external checkpoints | Ed25519, P-256/SHA-256 |

`configurationV1()` returns the exact 32-byte commitment that a trusted
context must carry. DID-web, WebAuthn, HSM-attested, and SPIFFE/X.509 require
deployment-specific trust records and are intentionally absent from this
fixed package. Such contexts fail closed with
`verifier-configuration-mismatch` or an unsupported-method requirement; the
package never substitutes another method.

The module also exposes the versioned `auths.wasm-authoring-abi/1` boundary
described by [`authoring-abi-v1.json`](authoring-abi-v1.json). It validates
principal identifiers, plans child grants through `auths-author`, prepares and
completes exact signing envelopes without receiving a private key, and binds
one request to a canonical trusted-context template. Canonical grant, action,
and status decoders use `VerifierLimits::default_deployment`; malformed,
trailing, non-canonical, and widening inputs fail before custody is invoked.

This is a repository-local pre-review ABI. It does not by itself promote the
TypeScript package beyond the Verifier Binding tier.

`cargo xtask wasm` builds `wasm-bindgen` Node artifacts twice, compares every
generated JS/WASM/TypeScript byte, generates authorized verification and
authoring vectors from the checked-in raw-key corpus, and requires Node to
produce identical canonical bytes. Malformed verification arrays return
protocol result bytes; malformed authoring requests return bounded local
errors and never produce a signing request.
