# AP-SPEC-049: Model and Identity Type Hardening

**Status:** Proposed
**Intended audience:** model, codec, identity, binding, and fixture maintainers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the direct type cutovers and their conformance
program
**Scope:** retrofit the three existing silently deduplicating model sets onto
AP-SPEC-047 `BoundedSet` with duplicate rejection; replace seven
security-relevant Boolean fields with closed enumerations; and replace
untyped method, suite, and material identifiers in `auths-identity` with local
parsed newtypes
**Depends on:** [AP-SPEC-047](0047-algorithm-agnostic-verification-foundations.md)

## Abstract

`PermissionSet`, `AudienceSet`, and `BodyDigestSet` silently remove duplicate
input. Seven Boolean fields encode security categories, and the
zero-dependency identity layer uses strings for registry identifiers.

This specification replaces those forms directly. The project is prelaunch:
duplicate-containing values that were previously normalized are rejected, and
old constructors, fields, and accessors are deleted. There are no compatibility
decoders, aliases, deprecated APIs, feature flags, or dual representations.

This work is separate from AP-SPEC-047 because duplicate rejection changes
accepted model input and deserves its own fixture audit. It is separate from
AP-SPEC-048 because model and identity hardening must not obscure deliberate
adapter commitment changes.

## 1. Current implementation map

| Defect | Current source |
| --- | --- |
| Silent permission deduplication | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `PermissionSet::new` |
| Silent audience deduplication | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `AudienceSet::new` |
| Silent body-digest deduplication | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `BodyDigestSet::new` |
| Untyped identity identifiers | [`core/crates/auths-identity/src/lib.rs`](../../core/crates/auths-identity/src/lib.rs), `IdentityMethod`, `SignatureVerifier`, `VerificationMaterial` |
| Boolean security categories | SPIFFE status policy, WebAuthn user verification, HSM exportability, and attachment security fields |

`CriticalExtensions`, `ControlBinding`, and adapter-local collections already
have distinct identity or empty-set rules. They are not part of the generic
set retrofit in this specification.

## 2. Conformance claims

A passing implementation may claim only the following:

- the three migrated model sets have one cardinality, ordering, and duplicate
  policy owned by AP-SPEC-047 `BoundedSet`;
- duplicate permissions, audiences, and body digests are rejected rather than
  normalized;
- each migrated Boolean security category has a closed, meaningfully named
  enumeration and cannot be constructed from an arbitrary Boolean inside the
  domain model;
- `auths-identity` exposes parsed identifier types rather than `String` or
  `&str` identifiers;
- codec projections are explicit and exhaustive over the new enumeration
  variants.

A passing implementation MUST NOT claim:

- compatibility with constructors or decoders removed by this specification;
- that duplicate rejection is wire-neutral: a previously accepted
  duplicate-containing input now fails;
- semantic unification of `auths-identity` with `auths-ports` or
  `auths-model` identifier types;
- migration of collections outside the three named model sets.

## 3. Direct-cutover rules

1. **No silent normalization.** Security-relevant duplicates are authoring or
   evidence errors, not values to remove before evaluation.
2. **One owner per set invariant.** The named wrapper translates `BoundError`
   but MUST NOT repeat sorting, duplicate detection, or cardinality checks.
3. **Meaning replaces Boolean position.** Callers construct named variants;
   no public constructor accepts a Boolean for a migrated category.
4. **Identity remains dependency-isolated.** `auths-identity` keeps zero
   workspace dependencies and owns local identifier newtypes with the same
   grammar as the corresponding registry identifiers.
5. **No compatibility layer.** Old fields, constructors, accessors, and decode
   paths are deleted in the same change.

## 4. Model-set migration

The domain types remain named so callers cannot interchange sets with
different meanings:

```rust
pub struct PermissionSet(
    BoundedSet<Permission, HARD_MAX_PERMISSIONS>
);

pub struct AudienceSet(
    BoundedSet<Audience, HARD_MAX_AUDIENCES>
);

pub struct BodyDigestSet(
    BoundedSet<Digest, HARD_MAX_BODY_DIGESTS>
);
```

Each wrapper constructor consumes the values, delegates once to
`BoundedSet::new`, and maps `BoundError` to its domain error. It performs no
prior `sort`, `dedup`, length check, or duplicate scan.

`Permission`, `Audience`, and `Digest` MUST implement canonical `Ord`
consistent with `Eq`. The ordering is the byte ordering already used by the
current constructors:

- permission capability bytes, then resource bytes;
- audience bytes;
- digest bytes.

The equality used for duplicate rejection is exactly the equality used for
membership and attenuation. A display-only field MUST NOT enter these element
types or their ordering.

### 4.1 Error mapping

| `BoundError` | `PermissionSet` | `AudienceSet` | `BodyDigestSet` |
| --- | --- | --- | --- |
| `Empty` | `InvalidPermissionSet` | `InvalidAudienceSet` | `InvalidActionConstraint` |
| `AboveMaximum` | `InvalidPermissionSet` | `InvalidAudienceSet` | `InvalidActionConstraint` |
| `Duplicate` | `DuplicatePermission` | `DuplicateAudience` | `DuplicateBodyDigest` |

The three duplicate variants are added directly to `ModelError` and have
stable codec/error projections. A generic `InvalidInput(String)` or nested
string subcode is forbidden.

Decoders surface the corresponding duplicate error. They MUST NOT decode,
normalize, and re-encode a smaller value.

### 4.2 Valid-value encoding

The canonical encoding of every still-valid value remains the ordered
contents of its named wrapper. The accepted value domain changes; the
encoding algorithm for unique values does not.

This is not a compatibility promise. It avoids an unrelated wire redesign in
the same change and keeps every observed fixture delta attributable to the new
duplicate policy.

## 5. Closed security-category enumerations

The following fields cut over directly:

| Removed field | Replacement |
| --- | --- |
| `SpiffeTrustDomain::require_status: bool` | `StatusRequirement::{Required, NotRequired}` |
| `SpiffeStatusRecord::active: bool` | `LeafStatus::{Active, Revoked}` |
| `WebAuthnCredential::require_user_verification: bool` | `UserVerification::{Required, Discouraged}` |
| `HsmKeyRecord::non_exportable: bool` | `Exportability::{NonExportable, Exportable}` |
| `AttachmentDescriptor::encrypted: bool` | `Confidentiality::{Encrypted, Plain}` |
| `AttachmentDescriptor::required: bool` | `Presence::{Required, Optional}` |
| `AttachmentDescriptor::opaque_allowed: bool` | `Opacity::{OpaqueAllowed, MustBeInspectable}` |

Every enumeration:

- derives the comparison traits required by its containing canonical model;
- has an exhaustive codec projection;
- exposes a meaning-based query only where that improves readability;
- has no `From<bool>` or public Boolean constructor;
- replaces every positional Boolean call site with a named variant.

The canonical formats continue to encode these fields in their registered
CBOR Boolean positions because changing that wire shape adds no semantic
value. The mapping is fixed:

| Variant encoded as `true` | Variant encoded as `false` |
| --- | --- |
| `StatusRequirement::Required` | `NotRequired` |
| `LeafStatus::Active` | `Revoked` |
| `UserVerification::Required` | `Discouraged` |
| `Exportability::NonExportable` | `Exportable` |
| `Confidentiality::Encrypted` | `Plain` |
| `Presence::Required` | `Optional` |
| `Opacity::OpaqueAllowed` | `MustBeInspectable` |

Decoding a Boolean constructs exactly the corresponding variant. The old
Boolean fields and getters are removed.

This cutover is owned entirely by AP-SPEC-049. AP-SPEC-048 changes the three
adapters' cryptographic dependencies but does not change these policy fields.

## 6. Typed identifiers in `auths-identity`

`auths-identity` retains its zero-workspace-dependency rule and therefore
defines local newtypes:

```rust
pub struct IdentitySuiteId(String);
pub struct IdentityMethodId(String);
pub struct MaterialId(String);
```

Each type:

- parses 1 to 128 UTF-8 bytes;
- rejects Unicode control characters and whitespace, matching the model
  registry grammar;
- exposes `as_str()` and `Display`;
- derives equality, ordering, and hashing;
- has no unchecked public constructor.

The direct API cutover is:

```rust
pub trait IdentityMethod {
    fn method_id(&self) -> IdentityMethodId;
}

pub trait SignatureVerifier {
    fn suite_id(&self) -> IdentitySuiteId;
}

pub trait VerificationMaterial {
    fn material_id(&self) -> &MaterialId;
}
```

Every implementer returns the typed identifier. Returning an owned, bounded
value preserves zero-sized stateless adapters without reintroducing a string
boundary. No trait retains a parallel string method.

The product integration layer converts between identity-layer and model-layer
identifiers by checked parsing. It does not use unchecked construction or byte
transmutation. A shared vector file asserts that the local identity grammar
and the corresponding model registry grammar accept and reject the same
boundary cases.

The types remain distinct because they belong to layers with different
dependency rules. Equal parsing grammar does not make them interchangeable
Rust types.

## 7. Fixture and conformance audit

The duplicate-semantics audit MUST search all canonical, adversarial,
cross-language, WASM, and product fixtures for duplicate:

- permissions;
- audiences;
- body digests.

For every occurrence, the case file records the previous normalized value and
the new exact rejection. Because the project is prelaunch, no compatibility
fixture is retained. A duplicate representing an authoring mistake becomes a
negative fixture; a fixture intended to be valid is corrected at its source.

Required property tests cover:

- permutation independence for unique inputs;
- rejection of adjacent and non-adjacent duplicates;
- empty, maximum, and above-maximum sizes;
- encode/decode stability for every still-valid collection;
- all fourteen Boolean/enum projections;
- identifier minimum, maximum, whitespace, control, and over-limit cases;
- equal acceptance decisions for the identity and model identifier vector.

Cross-language fixtures MUST observe the same duplicate rejection and enum
meaning. Language bindings expose meaning-based enum names, not raw Booleans,
at public typed boundaries.

## 8. Dependencies and architecture

The generic bounded types remain in `auths-model`; the three domain wrappers
remain in that crate. This specification introduces no cryptographic
dependency.

`auths-identity` gains no workspace dependency. Its local identifiers are
small parsed value types, not imports from `auths-model`.

All changed crates remain `no_std` where they were `no_std` before the cutover
and compile for `wasm32` where currently required.

## 9. Acceptance criteria

1. `PermissionSet`, `AudienceSet`, and `BodyDigestSet` delegate cardinality,
   ordering, and duplicate rejection to AP-SPEC-047 `BoundedSet` exactly once.
2. None of the three constructors calls `dedup`; every duplicate case returns
   its explicit `ModelError` variant.
3. The duplicate fixture audit is checked in as a case file and every changed
   fixture has an exact reason.
4. All seven Boolean fields and Boolean-taking constructors are removed; the
   closed enumerations are used at every call site.
5. Valid canonical encodings retain their registered Boolean positions and
   collection ordering.
6. `auths-identity` exposes only typed method, suite, and material identifiers
   at the affected trait boundaries.
7. The shared identifier vector passes in `auths-identity` and `auths-model`.
8. Rust, WASM, TypeScript, and Python conformance agree on duplicate rejection
   and the seven category meanings.
9. No compatibility shim, deprecated alias, legacy constructor, or
   feature-gated old representation remains.

## 10. Out of scope

- Algorithm, key-validation, signature-input, and certificate-path ports; see
  AP-SPEC-047.
- SPIFFE, HSM-attested, and WebAuthn cryptographic migrations and commitment
  regeneration; see AP-SPEC-048.
- `CriticalExtensions`, `ControlBinding`, and adapter-local collection
  refactors. Their empty-set and keyed-uniqueness semantics need a different
  generic abstraction or remain correctly owned by their named constructors.
- Merging `auths_identity::SignatureVerifier` with
  `auths_ports::SignatureSuite`.
- Retyping WebAuthn relying-party/origin fields or unrelated HSM provider and
  protection-level strings.
- Preserving acceptance of duplicate-containing prelaunch objects.
