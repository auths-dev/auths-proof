# Auths identity protocol V1 compatibility map

`auths-identity/v1` is the first supported product-protocol compatibility family for neutral
identity exchange. Its version number names the interoperable product contract; it does not imply
that every nested semantic family is also numbered 1.

| Dimension | Frozen value | Owner | Meaning |
| --- | --- | --- | --- |
| Identity product protocol | `auths-identity/v1` | this specification | The compatibility family consumers negotiate and document |
| Identity model | `1` | `auths-identity` public types | Decoded, method-validated, and authenticated states plus the compact and general descriptor models |
| Canonical compact wire | `2` | `auths-identity::IdentityPacket` | Packet framing and descriptor field encoding; experimental wire 1 was never published |
| Signing domain | `2` | `auths-identity::SignedIdentityMessage` | Exact preimage prefix and length-delimited identity/message fields |
| General descriptor wire | `1` | `auths-identity::IdentityDescriptor` | Credential-shape-neutral method material, relationships, suites, and verification material |
| General descriptor signing domain | `1` | `auths-identity::IdentityDescriptor::signing_preimage` | Exact descriptor, relationship, purpose, and application-message binding |
| Raw-key identity method | `raw-key-v2` | `auths-raw-key-core` | Suite-labelled, variable-length self-certifying key identifiers |
| Ed25519 suite | `ed25519-v1` | `auths-signature-core` | Strict Ed25519 verification shared with the proof stack |
| WASM identity ABI | `auths.identity-wasm-abi/1` | `identity-abi-v1.json` | Language-binding operations and explicit trust-state transitions |
| Iroh demo application protocol | `/auths/identity/1` | identity/Iroh demo composition | One optional transport negotiation label, not a requirement of identity interoperability |
| Rust crate/API release | `1.0.0-rc.1` | workspace release metadata | Packaging and source compatibility; it may change without changing wire bytes |

The current wire and signing revisions are numbered 2 because their revision-1 predecessors were
experimental and unpublished. Renumbering corrected bytes back to 1 would conceal that history and
create ambiguity in repository checkouts. Product protocol V1 therefore deliberately freezes wire
revision 2 and signing-domain revision 2.

The identity method `raw-key-v2` is not the proof protocol's frozen `raw-key-v1`. The V2 method
accepts any bounded suite-labelled public material; the V1 proof adapter accepts only its registered
key shapes and derives a different principal namespace. A validated neutral raw-key identity enters
authority only through the explicit `auths-identity-authority` bridge, which proves the selected
mapping and creates no grant by itself.

The general descriptor wire is a separate, explicitly framed member of the same identity product
family. It can carry embedded material, resolver references, rotating key sets, threshold
relationships, or hybrid classical/post-quantum relationships without teaching the core what any
credential means. A method adapter validates method material and resolution evidence; a suite
adapter authenticates the exact relationship signing preimage. Neither transition grants authority.

## Change rules

- Changing packet bytes, signing preimages, raw-key derivation, or a method/suite identifier requires
  a new semantic identity, migration note, and regenerated vector corpus.
- Adding an identity method, signature suite, or transport adapter does not change the neutral wire
  when the existing fields and bounds are sufficient.
- A transport endpoint identity is never automatically an Auths identity or authority principal.
- Canonical decode establishes structure only. Method validation and message authentication remain
  explicit later transitions.
- The checked vector and rejection corpus is regenerated with:

  ```sh
  cargo run -p auths-identity-raw-key --example generate-identity-vectors -- \
    core/fixtures/identity/v1/vectors.json
  ```

The machine-readable compatibility map is `compatibility.toml`; the normative example bytes and
malformed-input cases are `core/fixtures/identity/v1/vectors.json`.
