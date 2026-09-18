# AP-SPEC-046: Sigstore Keyless Evidence Adapter

**Status:** Proposed
**Intended audience:** principal-adapter authors, verifier implementers,
supply-chain and release engineers, and security reviewers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the adapter, the new path-verification port,
and the conformance program
**Scope:** one new `PrincipalMethod` adapter, `sigstore-keyless-v1`, that
establishes principal control from a Fulcio-issued short-lived certificate
whose exact Auths signature is proven included in a Rekor v1 transparency log
and whose integrated time is authenticated by a Rekor Signed Entry Timestamp;
the adapter-local Fulcio workload-identity projection and policy join; and the
out-of-kernel bundle import tool
**Depends on:** [AP-SPEC-045](0045-oidc-workload-principal-adapter.md) for
the workload-identity claim vocabulary and equivalence oracle, but not shared
production source; [AP-SPEC-047](0047-algorithm-agnostic-verification-foundations.md)
for `CertificatePathVerifier`, `AlgorithmBindingSet`,
`SignatureSuite::validate_key`, `PrincipalControlInput::signature`, and
`BoundedSet`

## Abstract

Sigstore keyless signing binds an OIDC workload identity to an ephemeral key
by issuing an X.509 certificate from Fulcio, then records the signing event
in the Rekor transparency log. The certificate is valid for minutes; the log
entry proves that the signature existed while the certificate was valid.

This specification consumes that evidence offline. The verifier pins Fulcio
trust anchors and Rekor log keys. The workload supplies the certificate
chain and a bounded, deterministic re-encoding of the Rekor entry with its
exact detached signature, inclusion proof, signed checkpoint, and Signed Entry
Timestamp. The adapter proves the log entry commits to this exact statement's
signing preimage, this exact Auths proof signature, and this exact leaf
certificate; verifies the Signed Entry Timestamp over the log ID, index, body,
and integrated time; proves inclusion under a checkpoint signed by a pinned
log key; takes the authenticated integrated time as the signing instant; and
verifies the certificate path at that instant through a replaceable path verifier,
extracts the workload identity from Fulcio extensions, and admits it under an
adapter-local policy whose decisions are differentially checked against the
AP-SPEC-045 policy oracle.

The adapter performs no cryptography of its own beyond the RFC 6962 Merkle
hash, which is a protocol constant of the log kind it consumes. Checkpoint
signatures are verified by registered signature suites. Certificate paths
are verified by the AP-SPEC-047 `CertificatePathVerifier` port; a
post-quantum certificate chain requires a different path-verifier
implementation and a different suite for the leaf key, not an adapter
change. The leaf key is handed to the workload's suite in whichever form
the verifier's `AlgorithmBindingSet` configures for that key algorithm.

The adapter does not depend on `sigstore-rs`: that crate performs network
resolution, reads the clock, and carries protobuf dependencies.

Version 1 consumes Sigstore bundle v0.3 evidence for Rekor v1
`hashedrekord` v0.0.1. Rekor v2 is a separately versioned adapter input, not a
silent extension of this parser. Version 1 verifies Rekor inclusion and a
Signed Entry Timestamp. It does not verify log consistency, witness
cosignatures, or Fulcio certificate-transparency SCTs.

## 1. Current implementation map

| Boundary | Current source |
| --- | --- |
| Principal adapter contract | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `PrincipalMethod` |
| Signature-suite port | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `SignatureSuite` |
| Path verification port | AP-SPEC-047 section 7, `CertificatePathVerifier`, `VerifiedLeaf`, `auths-path-webpki` |
| Algorithm binding | AP-SPEC-047 section 6, `AlgorithmBindingSet`, `KeyForm` |
| Key validation at construction | AP-SPEC-047 section 4, `SignatureSuite::validate_key` |
| Workload identity claim vocabulary and equivalence oracle | [AP-SPEC-045](0045-oidc-workload-principal-adapter.md) sections 4 and 8; no shared production source in this change |
| Adapter conformance program | [AP-SPEC-002](0002-adversarial-context-and-adapter-conformance.md) |
| Predecessor Merkle and checkpoint logic | `auths-transparency` in the archived `auths` repository; design only |

New sources:

```text
core/adapters/auths-sigstore-keyless/
├── Cargo.toml
├── src/
│   ├── lib.rs          adapter, configuration sets, SigstoreError
│   ├── chain.rs        CertificateChain, LeafCertificate
│   ├── fulcio.rs       FulcioIdentity extraction from a VerifiedLeaf
│   ├── identity.rs     Fulcio-local identity normalization and policy
│   ├── entry.rs        RekorEntry, HashedRekordBody, InclusionProof
│   ├── checkpoint.rs   Checkpoint signed-note parser
│   ├── merkle.rs       RFC 6962 hashing; depends on sha2 only
│   └── typestate.rs    BoundEntry → TimestampedEntry → IncludedEntry → AttestedEntry
└── tests/
    └── adversarial_conformance.rs
core/conformance/v1/adapters/sigstore-keyless.json
core/fixtures/v1/valid/sigstore-keyless-*.proof.cbor
tools/sigstore-bundle-import/               out-of-kernel conversion tool
demos/sigstore-keyless/                     public-API producer and verifier journey
```

## 2. Conformance claims

A passing implementation may claim only the following:

- a Rekor entry under a pinned log, whose body commits to this statement's
  preimage digest, the exact Auths proof signature, and this leaf certificate;
  whose Signed Entry Timestamp authenticates the log ID, index, body, and
  integrated time; whose inclusion proof reaches a checkpoint root; and whose
  checkpoint is signed by the pinned log key under its bound suite,
  establishes the authenticated integrated time as the signing instant;
- a certificate chain that the configured path verifier accepts at that
  instant, under the pinned anchors and the code-signing purpose, whose
  leaf carries the registered Fulcio identity extensions, establishes
  control of the leaf key for the exact principal;
- the leaf key is delivered to the statement's suite in the form the
  verifier bound to the leaf's key algorithm;
- every identity fact that influenced the decision is emitted as an exact
  assurance claim under the AP-SPEC-045 identifiers after source-specific
  normalization; the implementation is not shared;
- anchor, log, binding, issuer, and policy reordering preserve the
  configuration commitment; any decision-affecting change, including the
  path verifier's and each suite's own commitment, alters it;
- the specified adversarial inputs cannot silently establish control.

A passing implementation MUST NOT claim:

- that the log is append-only or consistent over time;
- that the checkpoint was published, gossiped, or witnessed;
- that Fulcio correctly authenticated the token it certified;
- that the certificate appeared in a certificate-transparency log;
- freshness beyond the supplied `evaluation_time`;
- correctness of the path verifier or any suite, which are claimed
  separately by those implementations;
- correctness of the bundle import tool beyond its own tests.

## 3. Design constraints

The AP-SPEC-045 section 3 constraints apply. In addition:

1. **Path verification is a port.** X.509 chain building, signature
   algorithms, and name constraints live behind the AP-SPEC-047
   `CertificatePathVerifier`. The adapter sees only a `VerifiedLeaf`.
2. **Key extraction is configuration.** The mapping from a leaf's
   `AlgorithmIdentifier` to a suite and a key form is an AP-SPEC-047
   `AlgorithmBindingSet`. The adapter never inspects key bytes.
3. **Log kind is closed and versioned.** The Merkle hash is a property of
   the `LogKind`, of which version 1 registers one. A log with another hash
   is another kind, not a parameter.
4. **Derived identifiers are derived.** `LogId` is computed from the pinned
   key; it is never accepted as input. The C2SP signed-note key hint is a
   separate derived value and MUST NOT be approximated as `LogId[0..4]`.
5. **The entry is parsed once.** Index, tree size, proof length, and body
   shape are invariants of `RekorEntry`; no later step re-checks them.
6. **The exact signature is logged.** Equality of artifact digest and
   certificate is insufficient. The detached signature in the Rekor body MUST
   equal the exact Auths proof signature that the kernel verifies.
7. **Time is authenticated separately from inclusion.** A checkpoint commits
   to the Merkle leaf, not Rekor v1's outer `integratedTime`. Only a valid
   Signed Entry Timestamp can construct `AuthenticatedIntegratedTime`.

## 4. Port usage

The adapter consumes `CertificatePathVerifier` exactly as AP-SPEC-047
section 6 defines it, with `required_eku` fixed to the code-signing
purpose `1.3.6.1.5.5.7.3.3`. It uses no other method of the port and
adds no adapter-local certificate parsing beyond reading the leaf's
validity window and SPKI algorithm identifier for the steps that precede
path verification.

AP-SPEC-047 exposes the exact outer Auths signature as the borrowed
`PrincipalControlInput::signature` byte slice in addition to the signing
preimage. This does not move signature verification into the adapter: the
kernel still verifies the signature through the statement's `SignatureSuite`.
It lets this adapter require byte equality with
`hashedrekord.spec.signature.content`.

## 5. Configuration model

```rust
pub struct SigstoreKeylessMethod<'a> {
    anchors: TrustAnchorSet,                  // AP-SPEC-047 BoundedSet<CertificateDer, MAX_TRUST_ANCHORS>
    path_verifier: &'a dyn CertificatePathVerifier,
    key_bindings: AlgorithmBindingSet,        // AP-SPEC-047; every row MUST be `AlgorithmBinding::Spki`
    logs: LogSet,                             // BoundedSet<RekorLog, MAX_LOGS>, ordered by LogId
    issuers: IssuerPolicySet,                 // BoundedSet<IssuerPolicy, MAX_ISSUERS>, ordered by IssuerUrl
    leaf_validity: LeafValidity,              // 1..=MAX_LEAF_VALIDITY seconds
    suites: &'a [&'a dyn SignatureSuite],
}

pub enum LogKind { Rfc6962Sha256 }

pub struct RekorLog {                         // no public constructor; see below
    id: LogId,                                // derived: SHA-256(spki)
    note_key_name: NoteName,
    note_key_hint: [u8; 4],                   // C2SP signed-note key-hash derivation
    origin: CheckpointOrigin,                 // 1..=128 bytes; no newline; no leading/trailing space
    spki: BoundedBytes<MAX_KEY_MATERIAL_BYTES>, // DER SubjectPublicKeyInfo
    binding: AlgorithmBinding,                // MUST be `AlgorithmBinding::Spki`
    kind: LogKind,
}

pub struct IssuerPolicy { url: IssuerUrl, profile: FulcioIssuerProfile }
```

### 5.1 Adapter-local identity and policy

The Fulcio adapter defines source-local identity and policy types. They use the
same validated leaf newtypes and final assurance parameter grammar as
AP-SPEC-045, but do not import its normalization or admission functions.

```rust
pub struct FulcioGenericIdentity {
    issuer: IssuerUrl,
    subject: Subject,                         // Fulcio .1.24 token subject
    certificate_san: CertificateIdentity,
}

pub struct FulcioGithubIdentity {
    issuer: IssuerUrl,
    subject: Subject,
    certificate_san: CertificateIdentity,
    repository: Repository,
    repository_id: RepositoryId,
    owner: RepositoryOwner,
    owner_id: RepositoryOwnerId,
    workflow: WorkflowIdentity,
    job_workflow: ReusableWorkflow,
    git_ref: GitRef,
    sha: CommitSha,
    environment: Option<Environment>,
    runner: RunnerEnvironment,
    event: EventName,
    run_invocation: RunInvocationUri,
}

pub enum FulcioWorkloadIdentity {
    Generic(FulcioGenericIdentity),
    GithubActions(FulcioGithubIdentity),
}

pub struct FulcioGenericPolicy { subject: Subject }

pub struct FulcioGithubPolicy {
    repository_id: RepositoryId,
    owner_id: RepositoryOwnerId,
    workflow: Option<WorkflowPin>,
    git_ref: Option<GitRef>,
    environment: Option<Environment>,
}

pub enum FulcioIssuerProfile {
    Generic { policies: BoundedSet<FulcioGenericPolicy, MAX_POLICIES> },
    GithubActions { policies: BoundedSet<FulcioGithubPolicy, MAX_POLICIES> },
}
```

The policy join is specified independently with the same equality rules as
AP-SPEC-045 section 4.3. The section 13 differential oracle compares every
normalized field, decision, admitting-policy digest, and assurance parameter.
Shared production code requires a later abstraction case file and direct
source cutover.

`CertificateIdentity` is a closed enum of one bounded URI, email address, or
Fulcio `.1.7` OtherName value. `RunInvocationUri` is an absolute `https` URL
with no userinfo or fragment and a maximum of 1024 bytes. Both preserve the
exact decoded certificate value; they are evidence facts, not authority
selectors unless a future policy explicitly adds them.

Constants:

| Name | Value |
| --- | --- |
| `MAX_LOGS` | 4 |
| `MAX_ISSUERS` | 16 |
| `MAX_POLICIES` | 64 per issuer |
| `MAX_CHAIN_LENGTH` | 4 including the leaf |
| `MAX_CERTIFICATE_BYTES` | 8192 |
| `MAX_LEAF_VALIDITY` | 3600 seconds |
| `MAX_PROOF_HASHES` | 64 |
| `MAX_CHECKPOINT_BYTES` | 2048 |
| `MAX_SET_BYTES` | 2048 |
| `MAX_ENTRY_BODY_BYTES` | 16 384 |
| `MAX_ENTRY_SIGNATURE_BYTES` | 16 384 |
| `SIGNING_TIME_DRIFT` | 300 seconds |
| `MAX_EXTENSION_BYTES` | 1024 per Fulcio extension |

`RekorLog::new(origin, note_key_name, spki, binding, kind, suites)` derives
`id` and `note_key_hint`, requires the note key name and public-key encoding to
round-trip through the C2SP signed-note verifier-key grammar, requires the
binding to be `AlgorithmBinding::Spki` whose `algorithm` equals the SPKI's
algorithm identifier, requires its suite to be present in `suites`, derives
the key bytes in the binding's `KeyForm`, and
passes them to that suite's `validate_key`. Each failure is a distinct
`ConfigurationError` variant. `SigstoreKeylessMethod::new` MUST reject a
binding set containing any `Jws` descriptor, duplicate log identifiers or
issuer URLs (`BoundError::Duplicate`), and a leaf validity above
`MAX_LEAF_VALIDITY`.

`configuration_id()` is `auths_ports::configuration_id` over the domain
`auths-sigstore-keyless-v1` and the canonical CBOR of: the anchor set; the
path verifier's `id` and `configuration_id`; the binding set's
`configuration_id`; the log set, each log contributing its `id`, origin,
note key name and derived hint, SPKI bytes, binding, kind, and bound suite `configuration_id`; the issuer
policy set; and leaf validity.

## 6. Evidence model

Exactly two evidence objects are bound to each statement.

| Media type | Payload | Bound |
| --- | --- | --- |
| `application/vnd.auths.sigstore-certificate-chain.v1` | canonical CBOR array of DER certificates, leaf first, excluding anchors | `MAX_CHAIN_LENGTH`, `MAX_CERTIFICATE_BYTES` each |
| `application/vnd.auths.sigstore-rekor-entry.v1` | canonical CBOR map, section 6.2 | field bounds |

Zero of either is `SigstoreError::MissingChain` or `MissingEntry`; more
than one is `DuplicateChain` or `DuplicateEntry`.

### 6.1 Typed chain

```rust
pub struct LeafCertificate {
    der: CertificateDer,
    not_before: Timestamp,
    not_after: Timestamp,
    spki_algorithm: AlgorithmIdentifierDer,
    spki: SubjectPublicKeyInfoDer,
}

pub struct CertificateChain {
    leaf: LeafCertificate,
    intermediates: Vec<CertificateDer>,        // 0..=MAX_CHAIN_LENGTH-1
}
```

`CertificateChain::parse` reads the leaf's validity and SPKI structurally.
It makes no trust decision. `LeafCertificate::new` requires
`not_before <= not_after` and `not_after - not_before <= leaf_validity`;
a leaf outside those bounds does not exist as a value.

### 6.2 Typed entry

The wire map has exactly these text keys. Its CBOR encoding MUST be canonical;
the table order is explanatory and is not an alternate ordering rule.

| Key | Type | Meaning |
| --- | --- | --- |
| `body` | bytes | canonical JSON of the `hashedrekord` v0.0.1 body, at most `MAX_ENTRY_BODY_BYTES` |
| `checkpoint` | text | signed-note envelope, at most `MAX_CHECKPOINT_BYTES` |
| `hashes` | array of 32-byte strings | inclusion proof, at most `MAX_PROOF_HASHES` |
| `integrated_time` | uint | seconds since the Unix epoch |
| `log_id` | 32 bytes | `LogId` |
| `log_index` | uint | leaf index |
| `signed_entry_timestamp` | bytes | Rekor v1 Signed Entry Timestamp signature, at most `MAX_SET_BYTES` |
| `tree_size` | uint | tree size at the checkpoint |

```rust
pub struct HashedRekordBody {
    raw: Vec<u8>,                              // exact bytes; hashed as the leaf
    artifact_digest: Digest,                   // spec.data.hash.value, sha256 only
    signature: BoundedBytes<MAX_ENTRY_SIGNATURE_BYTES>, // spec.signature.content, base64 decoded
    certificate: CertificateDer,               // spec.signature.publicKey.content, PEM decoded
}

pub struct SignedEntryTimestamp {
    signature: BoundedBytes<MAX_SET_BYTES>,
}

pub struct InclusionProof {                    // no public constructor
    index: u64, tree_size: u64, hashes: Vec<Digest>,
}

pub struct NoteSignature { name: NoteName, hint: [u8; 4], bytes: Vec<u8> }

pub struct Checkpoint {
    origin: CheckpointOrigin,
    tree_size: u64,
    root: Digest,
    body: Vec<u8>,                             // exact signed bytes
    signatures: Vec<NoteSignature>,            // 1..=MAX_NOTE_SIGNATURES
}

pub struct RekorEntry {
    log: LogId,
    body: HashedRekordBody,
    proof: InclusionProof,
    checkpoint: Checkpoint,
    integrated: Timestamp,
    signed_entry_timestamp: SignedEntryTimestamp,
}
```

The Signed Entry Timestamp preimage is re-derived as the RFC 8785 canonical
JSON encoding of the Rekor v1 log-entry object containing exactly `body`
(standard-base64 of `body.raw`), `integratedTime`, lower-case hexadecimal
`logID`, and `logIndex`. The adapter does not accept caller-supplied SET
preimage bytes. This derivation has byte fixtures copied from the corresponding
public Rekor entries.

`RekorEntry::parse` MUST reject: unknown, missing, or non-canonical keys;
wrong types; a body whose JSON is not the exact closed nested object with `apiVersion =
"0.0.1"`, `kind = "hashedrekord"`, `spec.data.hash.algorithm = "sha256"`,
a 64-hex `spec.data.hash.value`, and a `spec.signature.publicKey.content`
that PEM-decodes to exactly one certificate, plus exactly one bounded
base64 `spec.signature.content`; an absent or empty Signed Entry Timestamp;
`log_index >= tree_size`;
`tree_size == 0`; a proof whose length differs from the RFC 6962 path
length for `(index, tree_size)`; and a checkpoint whose `tree_size`
differs from the entry's. The body uses an independent closed JSON parser with
the same bounded scalar rules as AP-SPEC-045 and the exact nesting required by
`hashedrekord` v0.0.1; it accepts no other shape.

`Checkpoint::parse` reads the signed-note format: body lines
`<origin>`, `<tree_size>`, `<base64 root>`, optional extension lines, a
blank line, then one or more lines `— <name> <base64(hint ‖ signature)>`.
It rejects CRLF, a missing blank line, more than `MAX_NOTE_SIGNATURES`
lines, and an origin or name containing a newline.

## 7. Verification procedure

```text
PrincipalControlInput
  → SelectedIssuer                 (principal parse, issuer lookup)
  → (CertificateChain, RekorEntry)
  → SelectedLog                    (entry.log lookup)
  → BoundEntry                     (body binds preimage, exact signature, and leaf DER)
  → TimestampedEntry               (Signed Entry Timestamp authenticates Rekor metadata)
  → IncludedEntry                  (Merkle path reaches checkpoint root)
  → AttestedEntry                  (checkpoint signature under log suite)
  → SigningInstant                 (integrated time admitted against leaf window)
  → VerifiedLeaf                   (path verifier at the signing instant)
  → FulcioIdentity → FulcioWorkloadIdentity
  → AdmittedWorkload               (FulcioIssuerProfile::admit)
  → ControlEvidence
```

1. **Principal.** As AP-SPEC-045 section 7 step 1; `SigstoreError::PrincipalSyntax`
   or `UnknownIssuer`.
2. **Evidence.** Parse the chain (`SigstoreError::Chain(ChainError)`) and
   the entry (`SigstoreError::Entry(EntryError)`).
3. **Log.** Look up `entry.log`; absence is `SigstoreError::UnknownLog`.
   The result is `SelectedLog`, holding a reference to one `RekorLog`.
4. **Binding.** `RekorEntry::bind(preimage, signature, &chain.leaf) -> BoundEntry`
   requires `body.artifact_digest == SHA-256(input.signing_preimage)` and
   `body.signature == input.signature` and `body.certificate ==
   chain.leaf.der`; otherwise `SigstoreError::PreimageMismatch`,
   `EntrySignatureMismatch`, or `LeafMismatch`. Equality is byte-exact after
   the body's base64 decoding. The kernel separately verifies those same
   signature bytes over the same preimage under the leaf key.
5. **Signed Entry Timestamp.** `BoundEntry::authenticate_timestamp(log,
   suites) -> TimestampedEntry` re-derives the section 6.2 SET preimage and
   verifies `signed_entry_timestamp` under the pinned log suite and key.
   Failure is `SigstoreError::SignedEntryTimestamp`. Only
   `TimestampedEntry` exposes `integrated_time` as authenticated metadata.
6. **Inclusion.** `TimestampedEntry::include(kind) -> IncludedEntry` computes
   the leaf hash `SHA-256(0x00 ‖ body.raw)` and folds the proof with
   `SHA-256(0x01 ‖ left ‖ right)` under `LogKind::Rfc6962Sha256`. The
   result MUST equal `checkpoint.root`; otherwise `SigstoreError::Inclusion`.
7. **Attestation.** `IncludedEntry::attest(log, suites) -> AttestedEntry`
   requires `checkpoint.origin == log.origin` and at least one
   `NoteSignature` with `name == log.note_key_name` and `hint ==
   log.note_key_hint` whose `bytes` verify over
   `checkpoint.body` under the suite named by the log's SPKI binding, with the
   key delivered in that binding's `KeyForm`. Signature lines with other
   hints are ignored. Failure is `SigstoreError::Checkpoint(CheckpointError)`.
   `SignatureError::InvalidKey` cannot occur, because `validate_key`
   accepted the key at construction; an implementation MUST treat it as
   `SigstoreError::SuiteContract`.
8. **Signing instant.** `AttestedEntry::instant(&chain.leaf, signing, now)
   -> SigningInstant` requires `leaf.not_before <= integrated <
   leaf.not_after`, `|signing - integrated| <= SIGNING_TIME_DRIFT` using
   checked arithmetic, and `integrated <= now`; otherwise
   `SigstoreError::OutsideWindow(WindowViolation)`. `SigningInstant` wraps
   the integrated `Timestamp` and has no other constructor.
9. **Path.** `path_verifier.verify(PathInput { leaf, intermediates,
   anchors, at: instant, required_eku: codeSigning })`. `PathError` maps to
   `SigstoreError::Path(PathError)`; `UnsupportedAlgorithm` maps to the
   `Indeterminate` row of section 9. `verified_at != at` is
   `SigstoreError::PathVerifierContract`. The returned leaf DER, validity
   window, and SPKI algorithm MUST equal the corresponding structurally parsed
   values from `CertificateChain`; any disagreement is also
   `PathVerifierContract` and prevents parser-differential acceptance.
10. **Identity.** `FulcioIdentity::extract(&VerifiedLeaf, profile)` reads
   the issuer extension `1.3.6.1.4.1.57264.1.8` (V2 form; the V1 `.1.1`
   form is rejected) and exactly one identity SAN: URI, email, or
   `othername` of type `1.3.6.1.4.1.57264.1.7`, plus the token subject from
   `.1.24`. The token subject, not the SAN, is compared with the principal's
   `Subject`; the SAN is retained as a separate certificate-identity fact.
   Under `GithubActions` it additionally reads `.1.9` build signer URI,
   `.1.10` build signer digest, `.1.11` runner environment, `.1.12` source
   repository URI, `.1.13` source repository digest, `.1.14` source repository
   ref, `.1.15` source repository identifier, `.1.16` source repository owner
   URI, `.1.17` source repository owner identifier, `.1.18` build config URI,
   `.1.19` build config digest, `.1.20` build trigger, `.1.21` run invocation
   URI, and optional `.1.23` deployment environment. Each extension is UTF-8, at most
   `MAX_EXTENSION_BYTES`, and present at most once. Absent required
   extensions or duplicates are `SigstoreError::Extension(ExtensionError)`.
   The extension issuer MUST equal the selected issuer
   (`IssuerMismatch`) and the `.1.24` token subject MUST equal the principal's subject
   (`SubjectMismatch`).
11. **Projection.** `FulcioIdentity::into_workload(profile) ->
    FulcioWorkloadIdentity` maps: repository and owner names from `.1.12` and
    `.1.16` after removing the exact `https://github.com/` prefix; immutable
    repository and owner IDs from `.1.15` and `.1.17`; source ref and commit
    from `.1.14` and `.1.13`; the initiating workflow and commit from `.1.18`
    and `.1.19`; and the executing reusable workflow and commit from `.1.9`
    and `.1.10` when they differ from the initiating workflow. It maps runner,
    event, environment, and invocation URI from `.1.11`, `.1.20`, `.1.23`,
    and `.1.21`; actor remains absent. A GitHub digest MAY have the exact
    `sha1:` prefix, which is removed before `CommitSha` parsing. Any value
    that fails its newtype parse is
    `SigstoreError::Extension`.
12. **Verification method.** Compute
    `<principal>#fulcio-<first 16 base64url characters of SHA-256(leaf DER)>`;
    mismatch is `SigstoreError::VerificationMethodMismatch`.
13. **Key form.** `key_bindings.select_spki(verified_leaf.spki_algorithm())`
    returns the unique suite and configured key form; absence is
    `SigstoreError::UnboundKeyAlgorithm`. Its `suite` MUST equal
    `input.signature_suite`; otherwise
    `SigstoreError::WorkloadSuiteMismatch`. Key bytes come from
    `VerifiedLeaf::key_bytes(binding.key_form)`.
14. **Policy.** `profile.admit(&identity) -> AdmittedWorkload`;
    `SigstoreError::PolicyRejected`.
15. **Result.** `ControlEvidence::new(key_bytes,
    admitted.assurance_claims() ++ sigstore_claims, [chain_id, entry_id],
    adapter, 1, work)`. No `signature_message` is set.

`maximum_work_units()` is the path verifier's bound at `MAX_CHAIN_LENGTH`
plus twice the maximum log suite `work_units()` (SET and checkpoint), plus
`MAX_PROOF_HASHES` Merkle steps and a fixed parsing and canonicalization
charge.

## 8. Assurance claims

The adapter-local `AdmittedWorkload::assurance_claims()` emits the `oidc.*`
claim vocabulary from AP-SPEC-045 section 8 with source
`adapter:sigstore-keyless-v1`. A differential conformance oracle compares the
normalized values; the adapters do not share the normalization implementation.
`oidc.environment` is emitted when `.1.23` is present. `oidc.actor` is never
emitted because Fulcio does not provide that fact.

Adapter-specific claims:

| Claim identifier | Parameters |
| --- | --- |
| `sigstore.certificate` | `leaf_digest`, `not_before`, `not_after`, `path_verifier` |
| `sigstore.transparency` | `log_id`, `log_index`, `integrated_time`, `tree_size`, `root_hash`, `log_kind`, `set_digest` |
| `sigstore.trigger` | `build_trigger`, `run_invocation_uri`; emitted when both extensions are present |

## 9. Errors and translation

```rust
pub enum SigstoreError {
    PrincipalSyntax, UnknownIssuer,
    MissingChain, DuplicateChain, MissingEntry, DuplicateEntry,
    Chain(ChainError), Entry(EntryError), UnknownLog,
    PreimageMismatch, EntrySignatureMismatch, LeafMismatch,
    SignedEntryTimestamp, Inclusion, Checkpoint(CheckpointError), SuiteContract,
    OutsideWindow(WindowViolation), Path(PathError), PathVerifierContract,
    Extension(ExtensionError), IssuerMismatch, SubjectMismatch, VerificationMethodMismatch,
    UnboundKeyAlgorithm, WorkloadSuiteMismatch, PolicyRejected(PolicyRejection), LimitExceeded,
}
```

Constructors return `ConfigurationError` directly. A construction-only error
is not a runtime `SigstoreError`, which makes this translation exhaustive.

| `SigstoreError` | `PrincipalControlError` | Verifier outcome |
| --- | --- | --- |
| `PrincipalSyntax`, `IssuerMismatch`, `SubjectMismatch` | `PrincipalMethodMismatch` | `Denied` |
| `VerificationMethodMismatch` | `VerificationMethodMismatch` | `Denied` |
| `MissingChain`, `MissingEntry` | `MissingEvidence` | `Denied` |
| `WorkloadSuiteMismatch` | `SignatureSuiteMismatch` | `Denied` |
| `UnknownIssuer`, `UnknownLog`, `Chain`, `Entry`, `DuplicateChain`, `DuplicateEntry`, `PreimageMismatch`, `EntrySignatureMismatch`, `LeafMismatch`, `SignedEntryTimestamp`, `Inclusion`, `Checkpoint`, `OutsideWindow`, `Path` except `UnsupportedAlgorithm`, `Extension`, `PolicyRejected` | `InvalidEvidence` | `Denied` |
| `SuiteContract`, `Path(UnsupportedAlgorithm)`, `UnboundKeyAlgorithm`, `PathVerifierContract` | `ExternalFactUnavailable` | `Indeterminate` |
| `LimitExceeded` | `ResourceLimitExceeded` | `Indeterminate` |

`Path(UnsupportedAlgorithm)` and `UnboundKeyAlgorithm` are `Indeterminate`
because a verifier without the implementation or binding for an algorithm
cannot decide the evidence either way. Diagnostic codes are
`sigstore.<variant>[.<inner>]` as in AP-SPEC-045 section 9.

## 10. Adversarial matrix

Required cases in `core/conformance/v1/adapters/sigstore-keyless.json`,
each with its exact expected `SigstoreError`:

Chain:

- empty array; above `MAX_CHAIN_LENGTH`; certificate above byte limit;
  anchor included in the chain; leaf not first; intermediate omitted;
- leaf validity above `leaf_validity` rejected at parse; `not_before >
  not_after` rejected at parse;
- untrusted anchor; invalid path signature; missing code-signing EKU;
  client-auth EKU only; CA leaf; name-constraint violation, each as the
  corresponding `PathError`;
- leaf algorithm with no binding (`UnboundKeyAlgorithm`, `Indeterminate`);
  leaf algorithm the path verifier does not support
  (`Path(UnsupportedAlgorithm)`, `Indeterminate`);
- binding suite differing from `input.signature_suite`;
- verification method over a leaf differing by one byte;
- a path verifier returning leaf DER, validity, or SPKI metadata differing from
  the input leaf (`PathVerifierContract`).

Entry:

- unknown, missing, reordered, or wrong-typed key; float where uint
  expected; oversized `body`, `checkpoint`, or `hashes`;
- `log_index >= tree_size`, `tree_size == 0`, proof length inconsistent
  with index and size, checkpoint size differing from entry size: all
  rejected at parse;
- body with wrong `apiVersion` or `kind`; `sha1`; digest for another
  preimage (`PreimageMismatch`); certificate equal to the intermediate
  (`LeafMismatch`); body signature differing by one byte from the exact Auths
  proof signature (`EntrySignatureMismatch`); PEM with two certificates or
  trailing bytes;
- missing, empty, truncated, extended, or bit-flipped Signed Entry Timestamp;
  a valid SET with any one of body, `log_id`, `log_index`, or
  `integrated_time` changed (`SignedEntryTimestamp`);
- one proof hash flipped; hashes reversed (`Inclusion`);
- checkpoint with wrong origin; origin differing by trailing space; root
  differing from the computed root; missing blank line; CRLF; signature
  under an unknown note name or hint only; correct hint with a signature over a body
  differing by one byte; correct hint with a signature under a key bound
  to a different suite; extension lines present and ignored;
- pinned log key rejected by its suite, or bound with a `Jws` descriptor,
  or bound with an `Spki` algorithm differing from its SPKI: each rejected
  at construction with its `ConfigurationError` variant;
- `integrated_time` before `not_before`, at `not_after`, after
  `evaluation_time`, or beyond `SIGNING_TIME_DRIFT` from the asserted
  signing time, and each boundary exactly.

Identity and policy:

- issuer or token-subject extension absent, duplicated, or V1 issuer form only;
  two identity SANs; no identity SAN; token subject differing from the
  principal by case; extension above `MAX_EXTENSION_BYTES`; `.1.12` or `.1.16`
  without the exact GitHub prefix; `.1.18` or `.1.9` without a complete
  repository/workflow/ref; absent or malformed `.1.15` repository ID or `.1.17`
  owner ID; each deprecated or incorrectly shifted OID rejected rather than
  reinterpreted;
- repository-ID, owner-ID, workflow, commit, ref, and environment policy
  mismatches as in AP-SPEC-045;
- configuration: anchor, binding, log, and issuer reordering preserve
  `configuration_id`; any anchor byte, binding, log key, origin, suite
  `configuration_id`, path verifier `configuration_id`, issuer, policy
  field, or validity bound change alters it.

## 11. Bundle import tool

`tools/sigstore-bundle-import` converts a Sigstore bundle (media type
`application/vnd.dev.sigstore.bundle.v0.3+json`) into the two section 6
evidence objects. It is product-layer code. It:

- accepts exactly one bundle with exactly one `tlogEntries` element and
  rejects any other cardinality;
- rejects `messageSignature` digests other than SHA-256;
- canonically base64-decodes `canonicalizedBody` into `body`, copies
  `inclusionProof.checkpoint.envelope` byte-exact into `checkpoint`, and
  canonically base64-decodes `inclusionPromise.signedEntryTimestamp` into the
  `signed_entry_timestamp` byte string; malformed encodings, excess bytes, or
  absence of either verification object are errors;
- emits the chain from `verificationMaterial.certificate` or
  `x509CertificateChain`, leaf first, omitting any certificate equal to a
  supplied anchor;
- writes nothing else and performs no network access.

Its tests MUST round-trip a recorded public Rekor entry to evidence
objects the adapter accepts under the corresponding pinned keys, retaining
the recorded `logIndex`, integrated time, Signed Entry Timestamp, exact entry
signature, and checkpoint as fixtures.

## 12. Dependencies and trusted computing base

`auths-sigstore-keyless` depends on `auths-model`, `auths-ports`,
`x509-parser` for structural extraction only, `sha2`, `base64ct`, and
`minicbor`. It MUST NOT depend on `sigstore-rs`,
`prost`, or any protobuf crate. `cargo xtask arch` MUST reject signature,
curve, and path-building crates as dependencies of
`auths-sigstore-keyless`. The workspace-wide rule for existing adapters lands
in AP-SPEC-048 and is not a prerequisite for this new adapter.

The security review MUST record the Fulcio anchors and Rekor log keys as
verifier-supplied trust inputs whose provenance is outside the kernel's
claims, and MUST record that checkpoint verification proves signature by
the pinned key and nothing about publication. It MUST separately record that
the Signed Entry Timestamp authenticates Rekor v1 entry metadata but does not
prove log consistency or witnessing.

All new crates MUST compile for `wasm32` and appear in the WASM equivalence
gate.

## 13. Acceptance criteria

1. `cargo xtask arch` pins the adapter crate to its section 12 list.
2. AP-SPEC-047 has landed through its `CertificatePathVerifier`,
   `AlgorithmBindingSet`, public `VerifiedLeaf` construction, exact signature
   input, and conforming `webpki-v1` implementation. AP-SPEC-048 is not a
   prerequisite.
3. `cargo xtask wire --update` adds one fixture derived from a recorded
   public Rekor v1 entry containing an Auths-compatible exact signature, SET,
   inclusion proof, and checkpoint, plus one synthetic fixture under a test
   anchor and a test log key bound to `ed25519-v1`.
4. `cargo xtask conformance` executes every section 10 case with its exact
   `SigstoreError` oracle and a minimized recipe.
5. `cargo xtask fuzz-smoke` includes `RekorEntry::parse`,
   `Checkpoint::parse`, `CertificateChain::parse`, and the Merkle fold.
6. Property tests cover Merkle path length and fold against a reference
   tree builder, SET preimage derivation against recorded Rekor bytes,
   `Timestamp` arithmetic at `u64` boundaries, and set-constructor ordering
   independence.
7. Differential conformance cases feed corresponding GitHub OIDC and Fulcio
   evidence through independent normalizers and require identical repository
   IDs, owner IDs, workflow references and commits, source ref and commit,
   environment, policy decision, and assurance parameters. A mismatch blocks
   extraction of shared production code.
8. A maintained producer recipe obtains a Fulcio certificate, signs the exact
   Auths preimage, submits that exact signature to Rekor, imports the returned
   bundle, creates the Auths proof through a public authoring API, and verifies
   it through a public verification API. The recipe uses ephemeral keys and no
   checked-in credential.
9. AP-SPEC-002 section 1.2 and `docs/adapter-conformance.md` list the
   adapter and the port.

## 14. Out of scope

- Log consistency proofs, witness cosignatures, and checkpoint gossip.
- Fulcio SCT verification. A future version MAY add a `CtLogSet` and a
  `sigstore.ct` claim.
- Rekor entry kinds other than `hashedrekord` v0.0.1.
- Rekor v2 and `hashedrekord` v0.0.2. Supporting them requires a versioned
  evidence media type and adapter parser, not permissive v1 parsing.
- Timestamp-authority (RFC 3161) evidence as an alternative signing
  instant.
- A general Fulcio or Rekor client. The maintained producer recipe is required
  for interoperability and adoption; network acquisition remains outside the
  offline adapter.
- Any status method for `oidc-workload:` principals.
- A `LogKind` with a hash other than SHA-256; it is an additive variant.
