# Customer journey matrix

This matrix records which semantic owner and language surface is responsible
for each end-to-end journey. TypeScript consumes the Rust-owned meaning. Python
consumption is tracked separately and is not implemented by the TypeScript SDK.

| Journey | Rust semantic owner | TypeScript package evidence | Python dependency |
| --- | --- | --- | --- |
| Exchange and authenticate an identity | General and compact identity descriptors, signing preimages | `identity` quickstart and identity integration tests | Consume the same descriptor ABI and fixtures |
| Verify one action without effects | Three-valued verifier | `verify`, `inspection`, and hostile diagnostic tests | Consume the same result corpus |
| Attach, delegate, and authorize | Native authoring, attenuation, approval commitments, proof construction | Packed protected-action quickstart and workflow tests | Consume the same workflow operations |
| Authorize exact plans | Native plan commitments and proof composition | MCP and application profile plan tests | Consume the same plan fixtures |
| Operate trust and lifecycle evidence | Trusted-context and status semantics | Trust evidence ports, offline bundles, lifecycle recipes | Consume the same lifecycle fixtures |
| Execute a sealed command safely | Command minting and runtime state transitions | Closed runtime, durable reference store, gateway tests | Bind the same runtime state machine |
| Diagnose and support | Stable decision/error projections | Diagnostics, telemetry, support bundle tests | Emit the same stable schemas |
| Upgrade safely | ABI identities and compatibility rules | Compatibility manifest, public API and packed-package tests | Negotiate the same ABI window |

The Rust/TypeScript differential corpus is a release gate. Adding Python to
that corpus remains a Python SDK deliverable and is not a reason to duplicate
protocol meaning in TypeScript.
