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

`cargo xtask wasm` builds `wasm-bindgen` Node artifacts twice, compares every
generated JS/WASM/TypeScript byte, generates an authorized native result, and
requires Node to produce identical canonical bytes. Malformed arrays must
return protocol result bytes rather than JavaScript exceptions.
