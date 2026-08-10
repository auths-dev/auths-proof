# Modular Rust components

Auths publishes neutral ports and a small number of reference adapters so an
application can adopt only the layer it needs. The port is the product; an
adapter proves the port without becoming mandatory.

## Package map

| Package | Role | Required Auths dependencies | Optional meaning added |
| --- | --- | --- | --- |
| `auths-identity` | Neutral identity and signed-message port | none | decoded, validated, and authenticated identity states |
| `auths-identity-raw-key` | Reference identity-method adapter | identity port, raw-key canonicalization | self-certifying raw-key identifiers |
| `auths-signature-ed25519` | Reference signature-suite adapter | identity port, shared signature semantics | Ed25519 verification |
| `auths-identity-authority` | Explicit optional bridge | identity port, authority model | authority-shaped input from a validated identity |
| `auths-byte-channel` | Neutral bounded byte transport port | none | bounded opaque frame movement |
| `auths-byte-channel-memory` | Reference test adapter | byte-channel port | in-process frame movement |
| `auths-iroh` | Iroh transport adapter | byte-channel port | bounded Iroh frame movement and opaque peer observation |

There is deliberately no dependency from identity to authority, from transport
to identity, or from any package above to capabilities, approvals, profiles, or
the full SDK. `auths-identity-authority` is the only bridge in the table that
imports authority-shaped types, and applications select it explicitly.

## Compatibility table

| Package release | Identity product protocol | Identity model | Identity wire | Signing domain | Raw-key method | Ed25519 suite | Byte-channel port |
| --- | --- | ---: | ---: | ---: | --- | --- | --- |
| `1.0.0-rc.1` | `auths-identity/v1` | 1 | 2 | 2 | `raw-key-v2` | `ed25519-v1` | 1 |

The identity protocol version describes the interoperable family. Wire and
signing-domain versions are separate dimensions and may evolve independently.
All seven packages currently share the workspace release version so a consumer
can select a coherent release candidate. A port-compatible third-party adapter
does not need to share the Auths package version; it must declare the exact
protocol, method, suite, and port versions it implements.

## Platform policy

- MSRV: Rust 1.91.
- `no_std` with `alloc`: `auths-identity`, `auths-identity-raw-key`, and
  `auths-signature-ed25519`.
- `no_std` with default features disabled: `auths-identity-authority`.
- `std`: the byte-channel port and its asynchronous transport adapters.
- Documentation: each package README states its positive and negative security
  claims and is rendered by docs.rs.

## Release-candidate changelog

### 1.0.0-rc.1

- Published the neutral identity and bounded-byte-channel ports.
- Published raw-key, Ed25519, in-memory, and Iroh reference adapters.
- Published the explicit identity-to-authority bridge as an optional component.
- Froze identity protocol V1 bytes, signing preimages, identifiers, rejections,
  and public binding declarations.
- Added packed-artifact consumer smoke tests and a third-party adapter
  conformance process.

## Release qualification

Release CI packages all public crates first. It then unpacks the exact
`auths-identity`, `auths-byte-channel`, and `auths-iroh` `.crate` archives into
isolated temporary projects, compiles and executes a caller-owned identity
method and an identity-free Iroh configuration, and audits each dependency
graph for unexpected Auths packages. Workspace source paths therefore cannot
make this gate pass accidentally.
