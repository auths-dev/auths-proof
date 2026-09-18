# AP-SPEC-047: Algorithm-Agnostic Verification Foundations

**Status:** Proposed
**Intended audience:** port and model maintainers, principal-adapter authors,
signature-suite authors, and security reviewers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the ports, additive model types, reference path
verifier, and conformance program
**Scope:** the verification foundations required by new algorithm-agnostic
principal adapters: structural key validation on `SignatureSuite`; the exact
statement signature on `PrincipalControlInput`; a corrected JWS/SPKI algorithm
binding vocabulary; a constructible certificate-path-verification port with a
`webpki` implementation; additive bounded collection types; and a typed suite
identifier in `RawKeyDescriptorV2`
**Required by:** [AP-SPEC-045](0045-oidc-workload-principal-adapter.md),
[AP-SPEC-046](0046-sigstore-keyless-evidence-adapter.md),
[AP-SPEC-048](0048-existing-adapter-port-migrations.md), and
[AP-SPEC-049](0049-model-and-identity-type-hardening.md)

## Abstract

The kernel already selects signature suites by identifier, but adapters lack
three supporting capabilities: asking a suite whether it accepts verification
key bytes before runtime; selecting a suite and key projection from an
externally named algorithm; and delegating certificate path construction to a
replaceable implementation. A transparency adapter additionally needs access
to the exact outer Auths signature so that logged signature bytes can be bound
to the proof being verified.

This specification adds those foundations without migrating existing
principal adapters or changing existing model collection semantics. It also
adds `BoundedSet` and `BoundedBytes` as new reusable types and replaces the
untyped suite identifier inside `RawKeyDescriptorV2` directly. The project is
prelaunch: these are direct source cutovers with no compatibility aliases,
default trait methods, feature flags, or deprecated forms.

The existing SPIFFE, HSM-attested, and WebAuthn adapter migrations are
AP-SPEC-048. Retrofitting existing collections, replacing Boolean security
categories, and typing `auths-identity` identifiers are AP-SPEC-049. Keeping
those changes separate makes the foundation independently reviewable and
allows AP-SPEC-045 and AP-SPEC-046 to proceed without unrelated fixture
regeneration.

## 1. Current implementation map

| Boundary | Current source |
| --- | --- |
| Signature-suite port | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `SignatureSuite` |
| Principal-control input | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `PrincipalControlInput` |
| Existing suite implementations | [`core/crates/auths-signature/src/lib.rs`](../../core/crates/auths-signature/src/lib.rs), `Ed25519Suite`, `P256Sha256Suite` |
| Raw-key V2 descriptor | [`core/crates/auths-raw-key-core/src/lib.rs`](../../core/crates/auths-raw-key-core/src/lib.rs), `RawKeyDescriptorV2` |
| Existing path implementation embedded in an adapter | [`core/adapters/auths-spiffe-x509/src/lib.rs`](../../core/adapters/auths-spiffe-x509/src/lib.rs), `verify_chain` |
| Existing bounded model types | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), individual constructors |
| Port conformance policy | [AP-SPEC-002](0002-adversarial-context-and-adapter-conformance.md) |

New sources:

```text
core/crates/auths-ports/src/
├── lib.rs            SignatureSuite::validate_key; PrincipalControlInput::signature
├── binding.rs        AlgorithmBinding, AlgorithmBindingSet, typed selections
└── path.rs           CertificatePathVerifier, PathInput, VerifiedLeaf, PathError
core/crates/auths-model/src/
└── bounded.rs        additive BoundedSet and BoundedBytes
core/crates/auths-path-webpki/
└── src/lib.rs        CertificatePathVerifier implementation `webpki-v1`
core/conformance/v1/ports/
├── signature-suite.json
├── algorithm-binding.json
└── path-verifier.json
```

## 2. Conformance claims

A passing implementation may claim only the following:

- every registered suite exposes a structural key-validation operation, and a
  key accepted by that operation is never later classified as `InvalidKey` by
  the same suite;
- an `AlgorithmBindingSet` selects at most one suite for a JWS algorithm name
  and at most one suite and key form for an SPKI algorithm identifier;
- a `CertificatePathVerifier` returns a `VerifiedLeaf` only after accepting a
  path at the requested instant, under the supplied anchors and purpose;
- third-party path-verifier crates can implement the port without privileged
  constructors or workspace-private APIs;
- `BoundedSet` and `BoundedBytes` are total over their bounded input domains;
- `RawKeyDescriptorV2` carries a typed suite identifier while retaining one
  canonical V2 encoding;
- the exact signature stored in the Auths signature envelope is the signature
  exposed to every principal-control method.

A passing implementation MUST NOT claim:

- correctness or side-channel resistance of a suite or path verifier;
- that structural key validation proves possession, provenance, or safety of
  the corresponding private key;
- that a path verifier implements a policy absent from `PathInput`;
- migration of any existing principal adapter;
- duplicate rejection or other changed semantics for existing model
  collection types.

## 3. Design constraints

1. **Adapters ask; ports answer.** New adapters MUST NOT parse cryptographic
   key formats, verify certificate paths, or map algorithm identifiers to
   suites themselves.
2. **Lookup inputs contain only external facts.** A key-delivery form is a
   result of selecting an SPKI binding. It MUST NOT be part of the lookup key.
3. **Port implementers can construct port outputs.** A public trait whose
   output cannot be constructed outside its defining crate is not an
   implementable extension port.
4. **The exact outer signature is borrowed.** `PrincipalControlInput` exposes
   the existing signature bytes without copying or permitting an adapter to
   replace them.
5. **Bounds are additive in this specification.** Existing model and adapter
   collections are not retrofitted here.
6. **Direct cutover.** No compatibility shim, old field, default trait method,
   deprecated alias, or dual constructor is introduced.

## 4. `SignatureSuite::validate_key`

```rust
pub trait SignatureSuite {
    fn id(&self) -> &SignatureSuiteId;
    fn configuration_id(&self) -> AdapterConfigurationId;

    fn validate_key(
        &self,
        verification_key: &[u8],
    ) -> Result<(), SignatureError>;

    fn verify(&self, input: SignatureInput<'_>) -> Result<(), SignatureError>;
    fn work_units(&self) -> u64;
}
```

`validate_key` is required. It has no default implementation. It performs the
same structural decoding and representation checks that `verify` applies to
`SignatureInput::verification_key`, without requiring a signature or private
key.

The consumer-facing invariant is one-way and testable:

> For a fixed suite and verification-key byte string, if `validate_key`
> returns `Ok(())`, `verify` MUST NOT return `SignatureError::InvalidKey` for
> that byte string. Signature bytes may independently produce
> `InvalidSignature` or `InvalidSignatureEncoding`.

The specification does not state an existential biconditional over all
possible signatures. Conformance tests evaluate the invariant over registered
valid-key fixtures, invalid encodings at every length boundary, malformed
points, and deterministic random byte strings.

The existing suites cut over directly:

- `ed25519-v1` accepts exactly 32-byte encodings accepted by its verification
  implementation;
- `p256-sha256-v1` accepts exactly compressed SEC1 points accepted by its
  verification implementation;
- suites introduced later specify their exact accepted key representation in
  their own specification.

A component that persists or pins a key MUST call `validate_key` at
construction. Rejection is a configuration or authoring failure, not a runtime
verification outcome.

## 5. Exact signature in `PrincipalControlInput`

```rust
pub struct PrincipalControlInput<'a> {
    pub principal: &'a PrincipalId,
    pub verification_method: &'a VerificationMethod,
    pub signature_suite: &'a SignatureSuiteId,
    pub purpose: ControlPurpose,
    pub signing_preimage: &'a [u8],
    pub signature: &'a [u8],
    pub asserted_signing_time: Timestamp,
    pub evidence: &'a [&'a EvidenceObject],
    pub evaluation_time: Timestamp,
}
```

`signature` is the byte-exact `SignatureEnvelope::signature()` associated with
`signing_preimage`. The verifier constructs the input from the decoded signed
object. A caller cannot supply a different signature through a principal
adapter API.

Existing adapters ignore the new field until a method needs it. AP-SPEC-046
uses it to require equality with Rekor
`hashedrekord.spec.signature.content`. Adding the borrowed field does not
change any proof encoding or signature preimage.

## 6. Algorithm binding

An external algorithm name selects a binding. A key form is data returned by
an SPKI binding, never data required to find it.

```rust
pub struct JwsAlgorithmName(String);          // 1..=64; section 6.1
pub struct AlgorithmIdentifierDer(Vec<u8>);   // exact DER; 1..=256 bytes

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyForm {
    BitStringContents,
    SubjectPublicKeyInfoDer,
    Sec1Compressed,
}

pub enum AlgorithmBinding {
    Jws {
        algorithm: JwsAlgorithmName,
        suite: SignatureSuiteId,
    },
    Spki {
        algorithm: AlgorithmIdentifierDer,
        suite: SignatureSuiteId,
        key_form: KeyForm,
    },
}

pub struct JwsSelection<'a> {
    pub suite: &'a SignatureSuiteId,
}

pub struct SpkiSelection<'a> {
    pub suite: &'a SignatureSuiteId,
    pub key_form: KeyForm,
}

pub struct AlgorithmBindingSet(
    BoundedSet<AlgorithmBinding, MAX_ALGORITHM_BINDINGS>
);

impl AlgorithmBindingSet {
    pub fn select_jws(&self, algorithm: &JwsAlgorithmName)
        -> Option<JwsSelection<'_>>;

    pub fn select_spki(&self, algorithm: &AlgorithmIdentifierDer)
        -> Option<SpkiSelection<'_>>;
}
```

`MAX_ALGORITHM_BINDINGS` is 32. Construction takes the bindings and the
registered `&[&dyn SignatureSuite]`. It rejects an empty or oversized set, a
row whose suite is not registered, two `Jws` rows with the same algorithm
name, and two `Spki` rows with the same algorithm DER. Two SPKI rows that
differ only by `key_form` are duplicates, not alternatives.

`configuration_id()` commits to the sorted binding rows and to every selected
suite's `configuration_id()`. Reordering rows preserves the commitment; any
algorithm, suite, key form, or suite commitment change alters it.

### 6.1 JWS algorithm names

`JwsAlgorithmName` contains 1 to 64 ASCII bytes from `[A-Za-z0-9+/_-]`. It
rejects `none` and names beginning with `HS`, case-insensitively, because this
port binds asymmetric verification keys. Every other name is syntactically
valid; a name is supported only when a binding selects it.

## 7. Certificate path verification

```rust
pub struct CertificateDer(BoundedBytes<MAX_CERTIFICATE_BYTES>);           // 8192
pub type TrustAnchorSet = BoundedSet<CertificateDer, MAX_TRUST_ANCHORS>;  // 16
pub struct ExtendedKeyUsage(ObjectIdentifier);
pub struct PathVerifierId(String);

pub struct PathInput<'a> {
    pub leaf: &'a CertificateDer,
    pub intermediates: &'a [CertificateDer],
    pub anchors: &'a TrustAnchorSet,
    pub at: Timestamp,
    pub required_eku: &'a ExtendedKeyUsage,
}

pub struct VerifiedLeaf {
    der: CertificateDer,
    not_before: Timestamp,
    not_after: Timestamp,
    verified_at: Timestamp,
    spki_algorithm: AlgorithmIdentifierDer,
    spki: BoundedBytes<MAX_CERTIFICATE_BYTES>,
}

impl VerifiedLeaf {
    pub fn from_path_input(
        input: &PathInput<'_>,
        not_before: Timestamp,
        not_after: Timestamp,
        spki_algorithm: AlgorithmIdentifierDer,
        spki: Vec<u8>,
    ) -> Result<Self, PathError>;

    pub fn key_bytes(&self, form: KeyForm) -> Result<Vec<u8>, PathError>;
}

pub trait CertificatePathVerifier {
    fn id(&self) -> &PathVerifierId;
    fn configuration_id(&self) -> AdapterConfigurationId;
    fn maximum_work_units(&self, chain_length: usize) -> u64;
    fn verify(&self, input: PathInput<'_>) -> Result<VerifiedLeaf, PathError>;
}
```

`VerifiedLeaf::from_path_input` is public so an external crate can implement
the port. It copies `der` and `verified_at` from `input`; an implementer cannot
provide different values for those fields. It rejects `not_before >
input.at`, `input.at >= not_after`, inverted validity, malformed or oversized
SPKI data, and an SPKI algorithm identifier that is not canonical DER.

The constructor cannot prove that the reported validity and SPKI were parsed
from the supplied certificate. A consuming adapter that structurally parsed
those fields before path verification MUST compare them with the returned
values and treat disagreement as a path-verifier contract failure. The path
verifier is an explicit trust boundary; a private constructor would not make
an untrusted implementation trustworthy.

`key_bytes` derives only the requested representation:

- `BitStringContents`: contents of the SPKI BIT STRING with unused bits
  removed;
- `SubjectPublicKeyInfoDer`: complete DER SPKI;
- `Sec1Compressed`: the canonical compressed SEC1 point derived from an EC
  SPKI, or `UnsupportedKeyForm` when inapplicable.

`PathError` is closed:

```rust
pub enum PathError {
    Malformed,
    UntrustedAnchor,
    InvalidSignature,
    NotYetValid,
    Expired,
    MissingEku,
    NotEndEntity,
    NameConstraint,
    UnsupportedAlgorithm,
    UnsupportedKeyForm,
    LimitExceeded,
}
```

### 7.1 `auths-path-webpki`

`auths-path-webpki` implements the port as `webpki-v1`. It wraps
`rustls-webpki`, supports exactly the algorithms enabled in its pinned backend,
and returns `UnsupportedAlgorithm` rather than `Malformed` for a structurally
valid chain using an unsupported algorithm.

Its `configuration_id()` commits to its implementation identifier, dependency
version, backend, and enabled algorithm list. It has no network, clock, or
ambient trust-store access. All anchors and the verification instant come from
`PathInput`.

## 8. Additive bounded containers

```rust
pub struct BoundedSet<T: Ord, const MAX: usize>(Vec<T>);

impl<T: Ord, const MAX: usize> BoundedSet<T, MAX> {
    pub fn new(items: Vec<T>) -> Result<Self, BoundError>;
    pub fn as_slice(&self) -> &[T];
    pub fn contains(&self, item: &T) -> bool;
    pub fn is_subset_of(&self, other: &Self) -> bool;
}

pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

pub enum BoundError {
    Empty,
    AboveMaximum,
    Duplicate,
}
```

`BoundedSet::new` sorts, rejects duplicate values, and enforces `1..=MAX`.
`BoundedBytes::new` enforces `1..=MAX`. Both types expose read-only borrowed
views and consume their owned input once. Error precedence is fixed: empty,
then above-maximum, then duplicate after canonical sorting. An input exceeding
`MAX` is not normalized into range by duplicate removal.

These are new types. AP-SPEC-047 MUST NOT change `PermissionSet`,
`AudienceSet`, `BodyDigestSet`, `CriticalExtensions`, `BindingEvidence`, or
any existing adapter-local collection. AP-SPEC-049 performs those direct
cutovers and owns their semantic audit.

## 9. Typed `RawKeyDescriptorV2` suite identifier

`RawKeyDescriptorV2::suite_id` changes directly from `String` to
`SignatureSuiteId`; its constructor takes `SignatureSuiteId`, and its accessor
returns `&SignatureSuiteId`. There is no string-taking compatibility
constructor.

The V2 encoding continues to place the identifier's UTF-8 bytes in the suite
identifier field. Decoding parses that field through
`SignatureSuiteId::parse` before constructing the descriptor. The type's
length and character rules are the canonical grammar; they are not restated
inside `auths-raw-key-core`.

The principal identifier and AP-SPEC-045 audience commitment continue to hash
the complete canonical descriptor encoding.

## 10. Conformance program

`core/conformance/v1/ports/` adds:

- `signature-suite.json`: accepted keys, wrong lengths, malformed points,
  deterministic random bytes, and proof that every accepted key avoids
  `InvalidKey` in `verify`;
- `algorithm-binding.json`: duplicate JWS and SPKI selectors rejected;
  changing only an SPKI key form changes the commitment but cannot create a
  second selectable row; case-sensitive JWS lookup; DER-exact SPKI lookup;
  unregistered suites rejected; row reordering stable;
- `path-verifier.json`: every `PathError` class supported by `webpki-v1`;
  public construction of a test path verifier in a separate crate;
  `VerifiedLeaf` copying the input leaf and instant; every key form against
  fixed vectors; unsupported algorithms distinguished from malformed input.

Model unit and property tests cover `BoundedSet` ordering, duplicates, empty
and maximum boundaries, and `BoundedBytes` byte boundaries. Raw-key vectors
cover typed construction, decoding, encoding, and principal derivation.

## 11. Dependencies and architecture

`auths-ports` remains the owner of verification extension contracts.
`auths-path-webpki` owns `rustls-webpki`, `rustls-pki-types`, and its
cryptographic backend. New adapters depending on AP-SPEC-047 MUST NOT depend
directly on those crates or on signature/curve crates.

`auths-raw-key-core` depends on `auths-model` with default features disabled
and imports `SignatureSuiteId` from that owner. It MUST NOT define another
suite-identifier grammar or retain its former string field behind an alias.

This specification does not yet claim that every existing adapter is free of
cryptographic and path dependencies. AP-SPEC-048 migrates the known existing
violations and then enables the workspace-wide architecture prohibition.

All changed crates MUST compile for `wasm32` where their dependencies support
that target. A path implementation that cannot support `wasm32` must be
registered as unavailable there; the port types and deterministic test
implementation MUST still compile.

## 12. Acceptance criteria

1. Every registered `SignatureSuite` implements `validate_key` without a
   default method and passes `signature-suite.json`.
2. The verifier passes the exact decoded outer signature into
   `PrincipalControlInput::signature`; all existing call sites compile without
   synthesizing or copying different bytes.
3. `AlgorithmBindingSet` exposes separate `select_jws` and `select_spki`
   operations, and `KeyForm` is absent from the SPKI lookup key.
4. A test crate outside `auths-ports` implements `CertificatePathVerifier` and
   constructs `VerifiedLeaf` solely through public APIs.
5. `auths-path-webpki` passes `path-verifier.json` with no ambient network,
   clock, or root-store access.
6. `BoundedSet` and `BoundedBytes` land as additive types; no existing model or
   adapter collection changes in this specification.
7. `RawKeyDescriptorV2` exposes `SignatureSuiteId` directly and has no legacy
   string constructor or accessor.
8. AP-SPEC-002 and `docs/adapter-conformance.md` register the three port
   conformance suites.

## 13. Out of scope

- Migration of SPIFFE, HSM-attested, or WebAuthn; see AP-SPEC-048.
- Retrofitting existing collections, changing duplicate behavior, replacing
  Boolean categories, or typing `auths-identity`; see AP-SPEC-049.
- New signature suites. The RSA suite needed by AP-SPEC-045 is specified
  there.
- Certificate transparency, OCSP, CRLs, or network trust discovery.
- A COSE algorithm-binding variant. WebAuthn registration remains responsible
  for mapping COSE algorithms outside the kernel until an in-kernel consumer
  requires one.
