# AP-SPEC-045: OIDC Workload Principal Adapter

**Status:** Implemented on `main` in PR #129 (AP-SPEC-057 Epic 3); the live OIDC
workload run is recorded in that PR.
**Intended audience:** principal-adapter authors, verifier implementers,
CI platform integrators, and security reviewers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the adapter, its identity modules, and its
conformance program
**Scope:** one new `PrincipalMethod` adapter, `oidc-workload-v1`, that
establishes principal control from an OpenID Connect workload identity token
whose audience commits to a self-describing workload key, verified offline
against a verifier-pinned issuer key set through registered signature suites;
the adapter-local workload identity and policy vocabulary; and one maintained
GitHub Actions producer journey using only public Auths authoring and
verification APIs
**Depends on:** [AP-SPEC-047](0047-algorithm-agnostic-verification-foundations.md)
for `SignatureSuite::validate_key`, `AlgorithmBinding`, `BoundedSet`, and
the typed `RawKeyDescriptorV2` suite identifier

## Abstract

Continuous-integration platforms issue short-lived OpenID Connect identity
tokens to running workloads. No long-lived signing key is provisioned to the
runner; the platform asserts which repository, workflow, ref, and environment
produced the token.

This specification binds such a token directly to an ephemeral Auths
verification key for live verification. The workload requests a token whose
`aud` claim is a domain-separated commitment to a `raw-key-v2` descriptor: the suite
identifier and public key it will use to sign the Auths preimage. The
verifier pins, per issuer, a set of issuer keys, each bound to a registered
`SignatureSuite`, and a closed claim policy. Verification is pure: no JWKS
fetch, no discovery document, no clock, no revocation lookup.

The token is not a trusted timestamp. The holder can retain the ephemeral key
and choose an `asserted_signing_time` later. This adapter therefore admits
control only while `evaluation_time` is inside the token window. It does not
turn a short-lived OIDC token into durable historical evidence. A verifier
that needs durable signing-time evidence uses AP-SPEC-046.

The adapter performs no cryptography of its own. Both signatures it depends
on, the issuer's signature over the token and the workload's signature over
the Auths preimage, are verified by registered signature suites selected by
identifier. Which JWS algorithm names are accepted, and which suite verifies
each, is verifier configuration. A post-quantum issuer key or workload key
requires a registered suite and a configuration entry, not an adapter change.

The adapter starts from the issuer/repository/workflow-pin join semantics from
the predecessor `auths-verifier` OIDC policy. It does not reuse that code:
the predecessor implementation was asynchronous, read the system clock, and
depended on `auths-keri`.

AP-SPEC-046 initially owns its Fulcio projection and policy evaluation. A
later source cutover MAY extract a shared `auths-workload-identity` crate only
after both adapters pass exact normalization and policy-decision equivalence
cases. Two proposed specifications are not evidence that their source facts
have identical meaning.

Version 1 registers two issuer profiles, `generic` and `github-actions`.

## 1. Current implementation map

| Boundary | Current source |
| --- | --- |
| Principal adapter contract | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `PrincipalMethod`, `PrincipalControlInput`, `ControlEvidence` |
| Signature-suite port | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `SignatureSuite`, `SignatureInput` |
| Configuration commitment helper | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `configuration_id` |
| Suite-agnostic key descriptor | [`core/crates/auths-raw-key-core/src/lib.rs`](../../core/crates/auths-raw-key-core/src/lib.rs), `RawKeyDescriptorV2`, `RAW_KEY_V2_MEDIA_TYPE` |
| Bounded containers | AP-SPEC-047 section 8, `BoundedSet`, `BoundedBytes` |
| Algorithm binding | AP-SPEC-047 section 6, `AlgorithmBinding`, `JwsAlgorithmName` |
| Key validation at construction | AP-SPEC-047 section 4, `SignatureSuite::validate_key` |
| Structural template | [`core/adapters/auths-spiffe-x509/src/lib.rs`](../../core/adapters/auths-spiffe-x509/src/lib.rs) |
| Diagnostic facts | [`core/crates/auths-ports/src/diagnostics.rs`](../../core/crates/auths-ports/src/diagnostics.rs), `ControlEvaluation`, `ControlFact` |
| Adapter conformance program | [AP-SPEC-002](0002-adversarial-context-and-adapter-conformance.md) |
| Predecessor policy semantics | `auths-verifier/src/oidc_policy.rs` in the archived `auths` repository, `OidcSubjectPolicy`; design only |

New sources:

```text
core/adapters/auths-oidc-workload/
├── Cargo.toml
├── src/
│   ├── lib.rs        adapter, configuration sets, OidcError
│   ├── identity.rs   workload identity vocabulary and policy join
│   ├── github.rs     GitHub Actions vocabulary and normalization
│   ├── claims.rs     assurance-claim projection
│   ├── jws.rs        CompactJws parser and ProtectedHeader
│   ├── json.rs       closed flat-object claim parser
│   ├── token.rs      SignedToken → AuthenticatedToken → BoundToken typestates
│   └── window.rs     TokenWindow time arithmetic
└── tests/
    └── adversarial_conformance.rs
core/conformance/v1/adapters/oidc-workload.json
core/fixtures/v1/valid/oidc-workload-*.proof.cbor
demos/github-actions-oidc-workload/          public-API producer and verifier journey
```

## 2. Conformance claims

A passing implementation may claim only the following:

- a well-formed token, verified under a pinned issuer key by the suite that
  key is bound to, whose audience commits to the presented workload key
  descriptor and whose identity satisfies a registered policy, establishes
  live control of that key for the exact principal at `evaluation_time`;
- every identity fact that influenced the decision is emitted as an exact
  assurance claim;
- key-set, policy-set, and issuer-set reordering preserve the configuration
  commitment; any decision-affecting change alters it;
- accepted JWS algorithm names, and the suite verifying each, are
  configuration facts committed by the configuration identifier;
- the specified adversarial inputs cannot silently establish control;
- parsers remain total over the bounded input domain.

A passing implementation MUST NOT claim:

- that the issuer's signing key was uncompromised at signing time;
- that `asserted_signing_time` is a trusted timestamp or that the Auths
  signature was created during the token window;
- principal control before or after the token window admitted at
  `evaluation_time`;
- correctness of the process that produced the pinned issuer key set;
- that the workload that requested the token is the workload that signed the
  Auths preimage, beyond the audience-to-descriptor binding this adapter
  checks;
- revocation; version 1 registers no status method for this principal;
- security of any signature suite, which is claimed separately by that suite;
- absence of parser defects.

## 3. Design constraints

These constraints are normative for the adapter and its identity modules.

1. **No adapter-owned cryptography.** The adapter MUST NOT depend on any
   cryptographic crate other than `sha2` for commitments. Every signature is
   verified through a `&dyn SignatureSuite` supplied at construction.
2. **Algorithm names are data.** `JwsAlgorithmName` (AP-SPEC-047 section
   6.1) is a validated identifier, not an enumeration. The accepted set is
   the pinned key set. The type rejects only names that can never denote
   an asymmetric verification algorithm.
3. **Key material is opaque.** Issuer keys and workload keys are byte
   strings tagged by `SignatureSuiteId`. The adapter never parses a key.
4. **Parse, don't validate.** Every wire input is parsed once into a typed
   structure whose constructor enforces its invariants. No `String`,
   `Vec<u8>`, `bool`, or `Option` field encodes a security-relevant
   category.
5. **Illegal states are unrepresentable.** Profile, policy vocabulary, and
   identity vocabulary are one enumeration family; a policy for one profile
   cannot be attached to another.
6. **Order is typestate.** Each verification step consumes one type and
   produces the next. Policy evaluation is a method on a type that can only
   be constructed from an authenticated, time-admitted, key-bound token.
7. **Typed errors.** The adapter returns a closed `OidcError`; the port
   mapping and diagnostic code are total functions of that enumeration.

## 4. Adapter-local workload identity

These modules depend only on `auths-model` and have no cryptographic
dependency. Every constructor is the only way to obtain its type. They remain
adapter-local until the extraction gate in the abstract is satisfied.

### 4.1 Identifier newtypes

| Type | Parse rule | Bound |
| --- | --- | --- |
| `IssuerUrl` | absolute `https` URL; no userinfo, query, or fragment; the URL parser's serialization MUST equal the input bytes; no adapter-specific case, port, path, or trailing-slash normalization | 512 bytes |
| `Subject` | non-empty; no ASCII control characters | 1024 bytes |
| `Repository` | `owner/name`; each segment `[A-Za-z0-9._-]+`; canonicalized to ASCII lower case because GitHub repository names are case-insensitive | 256 bytes |
| `RepositoryOwner` | `[A-Za-z0-9-]+`; canonicalized to ASCII lower case | 64 bytes |
| `RepositoryId` | non-zero unsigned decimal integer with no leading zero | `u64` |
| `RepositoryOwnerId` | non-zero unsigned decimal integer with no leading zero | `u64` |
| `WorkflowPath` | `.github/workflows/<file>.yml` or `.yaml`; no `..` segment | 256 bytes |
| `GitRef` | `refs/` prefix; no `..`, `//`, control, or space | 256 bytes |
| `CommitSha` | exactly 40 lower-case hexadecimal characters | 40 bytes |
| `Environment` | non-empty; no control characters | 256 bytes |
| `RunnerEnvironment` | closed: `github-hosted` or `self-hosted` | enum |
| `Actor` | `[A-Za-z0-9-]+` or `[A-Za-z0-9-]+\[bot\]` | 64 bytes |
| `EventName` | `[a-z_]+` | 64 bytes |

### 4.2 Workload identity

```rust
pub struct WorkflowRef {
    repository: Repository,
    path: WorkflowPath,
    git_ref: GitRef,
}

pub struct WorkflowIdentity {
    reference: WorkflowRef,
    commit: CommitSha,
}

pub enum ReusableWorkflow {
    Absent,
    Present(WorkflowIdentity),
}

pub struct GenericIdentity { issuer: IssuerUrl, subject: Subject }

pub struct GithubIdentity {
    issuer: IssuerUrl,
    subject: Subject,
    repository: Repository,
    repository_id: RepositoryId,
    owner: RepositoryOwner,
    owner_id: RepositoryOwnerId,
    workflow: WorkflowIdentity,
    job_workflow: ReusableWorkflow,
    git_ref: GitRef,
    sha: CommitSha,
    environment: Option<Environment>,
    runner: Option<RunnerEnvironment>,
    actor: Option<Actor>,
    event: Option<EventName>,
}

pub enum WorkloadIdentity {
    Generic(GenericIdentity),
    GithubActions(GithubIdentity),
}
```

`Option` here records a fact the issuer did not assert. It never selects a
behaviour. `GithubIdentity::new` requires `owner` to equal the first
segment of `repository`; `workflow.reference.repository` to equal
`repository`; and a reusable workflow reference and its immutable
`job_workflow_sha` to appear together through `ReusableWorkflow`. Repository
and owner names are display and diagnostic facts. Their numeric identifiers
are the stable policy identities.

### 4.3 Policy

```rust
pub enum WorkflowPin {
    Exact { path: WorkflowPath, git_ref: GitRef, commit: CommitSha },
    AnyRef { path: WorkflowPath },
}

pub struct GenericPolicy { subject: Subject }

pub struct GithubPolicy {
    repository_id: RepositoryId,
    owner_id: RepositoryOwnerId,
    workflow: Option<WorkflowPin>,
    git_ref: Option<GitRef>,
    environment: Option<Environment>,
}

pub type GenericPolicySet = BoundedSet<GenericPolicy, MAX_POLICIES>;
pub type GithubPolicySet  = BoundedSet<GithubPolicy, MAX_POLICIES>;

pub enum IssuerProfile {
    Generic { policies: GenericPolicySet },
    GithubActions { policies: GithubPolicySet },
}
```

`GithubPolicy` always constrains immutable repository and owner identifiers;
a policy that constrains only mutable names is unrepresentable. `Option` on
the remaining fields means "not constrained". A deployment MAY additionally
render the current names for review, but renaming a repository or owner does
not change policy identity.

Admission is total and exact:

```rust
impl GenericPolicy  { pub fn admits(&self, identity: &GenericIdentity) -> bool }
impl GithubPolicy   { pub fn admits(&self, identity: &GithubIdentity) -> bool }
impl IssuerProfile  { pub fn admit(&self, identity: &WorkloadIdentity) -> Result<AdmittedWorkload, PolicyRejection> }
```

`GithubPolicy::admits` requires equality on `repository_id` and `owner_id`;
on `workflow`, `Exact` requires path, ref, and commit equality and `AnyRef`
requires path equality; on `git_ref` and `environment`, equality when
constrained. The workflow's repository name is deliberately absent from
`WorkflowPin`: `GithubIdentity::new` has already tied the workflow to the
repository, and the policy authorizes that repository by immutable ID.
A constrained `environment` against an identity whose `environment` is
`None` is `false`: the fact is absent, the policy is not malformed.

`IssuerProfile::admit` rejects with `PolicyRejection::ProfileMismatch` when
the identity variant does not match the profile variant, and
`PolicyRejection::NoPolicyAdmits` otherwise. `AdmittedWorkload` has no
public constructor and carries the identity and the canonical digest of the
admitting policy.

### 4.4 Assurance projection

`AdmittedWorkload::assurance_claims() -> Vec<AssuranceClaim>` is a total
projection producing the section 8 claim set. AP-SPEC-046 implements an
independent projection and compares its output through the differential
conformance oracle; it does not call this implementation.

## 5. Configuration model

```rust
pub struct OidcWorkloadMethod<'a> {
    issuers: IssuerSet,                       // BoundedSet<Issuer, MAX_ISSUERS>, ordered by IssuerUrl
    suites: &'a [&'a dyn SignatureSuite],     // evidence-internal verification
}

pub struct Issuer {
    url: IssuerUrl,
    keys: IssuerKeySet,                       // BoundedSet<PinnedIssuerKey, MAX_KEYS>, ordered by KeyId
    profile: IssuerProfile,
    lifetime: TokenLifetime,                  // 1..=MAX_TOKEN_LIFETIME seconds
}

pub struct PinnedIssuerKey {                  // no public constructor; see below
    kid: KeyId,                               // 1..=256 printable ASCII bytes
    binding: AlgorithmBinding,                // MUST be `AlgorithmBinding::Jws`
    material: BoundedBytes<MAX_KEY_MATERIAL_BYTES>,
}
```

Constants:

| Name | Value |
| --- | --- |
| `MAX_ISSUERS` | 16 |
| `MAX_KEYS` | 32 per issuer |
| `MAX_POLICIES` | 64 per issuer |
| `MAX_KEY_MATERIAL_BYTES` | 131 072 |
| `MAX_TOKEN_BYTES` | 16 384 |
| `MAX_CLAIM_BYTES` | 1024 per string claim |
| `MAX_TOKEN_LIFETIME` | 86 400 seconds |
| `CLOCK_SKEW` | 300 seconds |

`PinnedIssuerKey::new(kid, binding, material, suites)` is the only
constructor. It MUST reject, with a distinct `ConfigurationError` variant
each: a binding that is not `AlgorithmBinding::Jws`; its suite being absent
from `suites`; and material rejected by that suite's `validate_key`. The
last check is what makes an unusable pinned key a construction-time fault
rather than a verification-time outcome. `OidcWorkloadMethod::new` MUST
additionally reject two pinned keys in one issuer with the same `kid` and
two issuers with the same `url`; both are `BoundError::Duplicate` from the
`BoundedSet` constructors.

`configuration_id()` is `auths_ports::configuration_id` over the domain
`auths-oidc-workload-v1` and the canonical CBOR encoding of the sorted
issuer set. Each pinned key contributes `kid`, its binding, the bound
suite's own `configuration_id()`, and its material bytes, so replacing a
suite implementation changes the adapter commitment.

Each GitHub Actions policy contributes one component: the prefix
`github-policy-v2`, then its repository id, owner id, workflow pin (absent,
`any-ref` with a path, or `exact` with path, ref, and commit), ref, and
environment. Every field is tagged and length-prefixed, and an absent
optional field is encoded explicitly. Two distinct policies therefore never
share a commitment.

*Amended 2026-09-22.* The earlier encoding had two defects. It
concatenated ref and environment with no separators, so `ref=refs/heads/ab,
environment=c` and `ref=refs/heads/a, environment=bc` produced the same
bytes. It also left the workflow pin out of the commitment, although the
pin was enforced. A verifier's trusted context could therefore name one
policy while running another. The regression test
`distinct_github_policies_never_share_a_configuration_encoding` covers both
defects. Under the prelaunch rule, earlier trust is regenerated rather than
read.

### 5.1 `JwsAlgorithmName`

Defined in AP-SPEC-047 section 6.1: 1 to 64 bytes from `[A-Za-z0-9+/_-]`,
rejecting `none` and any `HS`-prefixed name case-insensitively. Every other
name is accepted by the type; whether it is accepted by the adapter is
decided by the presence of a pinned key carrying that name. Two keys under
one issuer MAY bind the same name to different suites; selection is by
`kid`.

## 6. Evidence model

Exactly two evidence objects are bound to each statement.

| Media type | Payload | Bound |
| --- | --- | --- |
| `application/vnd.auths.oidc-workload-token.v1` | compact-serialization JWS bytes, ASCII | `MAX_TOKEN_BYTES` |
| `application/vnd.auths.raw-key.v2` | `RawKeyDescriptorV2` encoding: suite identifier and opaque public key | `MAX_RAW_KEY_BYTES` |

The adapter selects exactly one object of each media type; zero of either
is `OidcError::MissingToken` or `MissingKeyDescriptor`; more than one is
`DuplicateToken` or `DuplicateKeyDescriptor`. The key descriptor is
required because the token carries no key; the audience commitment of
section 7.3 binds the two. Reusing `raw-key-v2` means the workload key's
suite and size are whatever a registered suite accepts.

### 6.1 Typed evidence

```rust
pub struct ProtectedHeader {
    alg: JwsAlgorithmName,
    kid: KeyId,
    x5t: Option<BoundedBase64Url<64>>,
    x5t_s256: Option<BoundedBase64Url<64>>,
}

pub struct CompactJws {
    header: ProtectedHeader,
    signing_input: Vec<u8>,     // ASCII(BASE64URL(header) '.' BASE64URL(payload))
    payload: Vec<u8>,           // decoded
    signature: Vec<u8>,         // decoded
}
```

`CompactJws::parse` MUST reject: a byte count above `MAX_TOKEN_BYTES`; any
byte outside the base64url alphabet and `.`; a segment count other than
three; an empty segment; padding characters; a header that is not a flat
JSON object; a header lacking `alg` or `kid`; a header containing `crit`,
`jku`, `jwk`, `x5u`, or `x5c`; a `typ` present and not
equal to `JWT`; and a `cty`. Unknown header members are rejected: the
header vocabulary is closed. `x5t` and `x5t#S256` are accepted only as
bounded base64url values because GitHub-issued tokens can carry them. They do
not participate in key selection or establish a claim; `kid` and the pinned
key binding remain authoritative.

The payload is not interpreted by `CompactJws`. It is bytes until section
7 step 4.

### 6.2 Closed claim parser

`json.rs` parses one flat JSON object into a `ClaimSet` for the selected
profile. It accepts only: an object at depth one; member names from the
profile's registered vocabulary or its closed ignored-claim vocabulary; string values
of at most `MAX_CLAIM_BYTES`; unsigned integers that fit `u64`; and `aud`
as either one string or an array of exactly one string. It MUST reject
duplicate member names, nested objects or arrays other than the `aud`
case, `null`, booleans, floats, negative numbers, and unpaired surrogates.
Members it skips are still fully tokenized and bounded. The output is a
typed struct, never a map.

```rust
pub struct CommonClaims { iss: IssuerUrl, sub: Subject, aud: AudienceClaim, window: TokenWindow, jti: Option<TokenId> }
pub struct GithubClaims { common: CommonClaims, repository: Repository, repository_id: RepositoryId,
                          repository_owner: RepositoryOwner, repository_owner_id: RepositoryOwnerId,
                          workflow_ref: WorkflowRef, workflow_sha: CommitSha,
                          job_workflow_ref: Option<WorkflowRef>, job_workflow_sha: Option<CommitSha>,
                          git_ref: GitRef, sha: CommitSha, environment: Option<Environment>,
                          runner_environment: Option<RunnerEnvironment>, actor: Option<Actor>, event_name: Option<EventName> }
pub enum ClaimSet { Generic(CommonClaims), GithubActions(GithubClaims) }
```

For `github-actions`, `workflow_ref` and `job_workflow_ref` parse the complete
GitHub value `<owner>/<repository>/.github/workflows/<file>@<ref>`; the
repository prefix is retained and validated. `workflow_sha` is required.
`job_workflow_ref` and `job_workflow_sha` MUST either both be absent or both be
present. They describe the called reusable workflow and MUST NOT be projected
as though they belonged to the caller repository.

GitHub emits repository and owner identifiers as decimal JSON strings. The
profile parser MUST parse those strings through `RepositoryId` and
`RepositoryOwnerId`; accepting a JSON integer for either claim would create a
second wire representation and is rejected.

The security-relevant GitHub vocabulary is: `iss`, `sub`, `aud`, `iat`, `exp`,
`nbf`, `jti`, `repository`, `repository_id`, `repository_owner`,
`repository_owner_id`, `workflow_ref`, `workflow_sha`, `job_workflow_ref`,
`job_workflow_sha`, `ref`, `sha`, `environment`, `runner_environment`, `actor`,
and `event_name`. The closed ignored vocabulary is: `actor_id`, `base_ref`,
`check_run_id`, `enterprise`, `enterprise_id`, `head_ref`, `ref_protected`,
`ref_type`, `repository_visibility`, `run_attempt`, `run_id`, `run_number`, and
`workflow`. Adding another ignored claim is a reviewed adapter-version change;
the parser does not accept an arbitrary prefix such as `repo_property_*`.

`TokenWindow::new(iat, exp, nbf: Option)` requires `iat <= exp`,
`nbf <= exp` when present, and `exp - iat <= lifetime`; construction with
inverted values fails, so no later step handles them. All arithmetic on
`Timestamp` is checked; a subtraction that would underflow is treated as
zero and an addition that would overflow fails construction.

## 7. Verification procedure

The procedure is a chain of typestates. Each arrow is the only public path
to the next type; the port method `verify_control` is the composition.

```text
PrincipalControlInput
  → SelectedIssuer            (principal parse, issuer lookup)
  → (CompactJws, RawKeyDescriptorV2)
  → SignedToken               (kid/alg lookup binds one PinnedIssuerKey)
  → AuthenticatedToken        (suite.verify over signing_input)
  → ClaimSet                  (closed parser under the issuer profile)
  → AdmittedLiveTime          (TokenWindow::admits_live)
  → BoundToken                (audience recomputed from descriptor)
  → WorkloadIdentity
  → AdmittedWorkload          (IssuerProfile::admit)
  → ControlEvidence
```

1. **Principal.** Parse `input.principal` as
   `oidc-workload:<pct(issuer)>#<pct(subject)>`. `pct` leaves only RFC 3986
   unreserved bytes literal, uses upper-case hexadecimal escapes, and MUST
   re-encode byte-identically after decoding. Encoding the complete issuer
   makes issuer paths and subject paths unambiguous. The decoded issuer is an
   exact `IssuerUrl`; the decoded subject is a `Subject`. Failure is
   `OidcError::PrincipalSyntax`.
   Look up the issuer; absence is `OidcError::UnknownIssuer`.
2. **Evidence.** Select the two objects of section 6. Parse the token as
   `CompactJws` (`OidcError::Jws(JwsError)`) and the descriptor as
   `RawKeyDescriptorV2` (`OidcError::KeyDescriptor`).
3. **Key selection.** `SelectedIssuer::bind(jws) -> SignedToken` finds the
   pinned key whose `kid` equals the header's and whose binding descriptor
   is `Jws(header.alg)`. A `kid` match with a different algorithm name is
   `OidcError::AlgorithmMismatch`;
   no `kid` match is `OidcError::UnknownKey`. `SignedToken` owns the
   `CompactJws` and a reference to exactly one `PinnedIssuerKey`.
4. **Authentication.** `SignedToken::authenticate(suites) ->
   AuthenticatedToken` locates the suite by the pinned key's `suite` (its
   presence was proven at construction) and calls `verify` with
   `verification_key = material`, `signing_preimage = signing_input`,
   `signature = signature`. `SignatureError::InvalidSignature` and
   `InvalidSignatureEncoding` are `OidcError::TokenSignature`.
   `SignatureError::InvalidKey` cannot occur: the material was accepted by
   `validate_key` at construction; an implementation MUST treat it as
   `OidcError::SuiteContract`. Only `AuthenticatedToken` exposes the
   payload.
5. **Claims.** `AuthenticatedToken::claims(profile) -> ClaimSet` runs the
   section 6.2 parser under the issuer's profile. `iss` MUST equal the
   issuer `url` and `sub` the principal's subject; otherwise
   `OidcError::IssuerMismatch` or `OidcError::SubjectMismatch`.
6. **Verification method.** Compute
   `<principal>#oidc-<first 16 base64url characters of SHA-256(token bytes)>`
   and compare with `input.verification_method`;
   `OidcError::VerificationMethodMismatch`.
7. **Live time.** `TokenWindow::admits_live(now) ->
   Result<AdmittedLiveTime>` with `now = input.evaluation_time` requires
   `iat.saturating_sub(CLOCK_SKEW) <= now`, `now < exp + CLOCK_SKEW`, and
   `nbf <= now + CLOCK_SKEW` when present. `input.asserted_signing_time`
   MUST NOT influence this decision. Failure is
   `OidcError::OutsideWindow(WindowViolation)` with the violated bound named.
8. **Audience binding.** `AudienceCommitment::of(&descriptor)` is
   `"auths-oidc-workload-v1:" ‖ base64url-unpadded(SHA-256(descriptor.encode()))`
   over the exact `RawKeyDescriptorV2` encoding. The token's `aud` MUST
   equal it byte-for-byte; otherwise `OidcError::AudienceMismatch`. The
   descriptor's typed `suite_id` MUST equal `input.signature_suite`;
   otherwise `OidcError::WorkloadSuiteMismatch`. The result is `BoundToken`, which
   owns the descriptor.
9. **Identity.** `BoundToken::identity() -> WorkloadIdentity` is a total
   projection from `ClaimSet`.
10. **Policy.** `profile.admit(&identity) -> AdmittedWorkload`;
    `PolicyRejection` maps to `OidcError::PolicyRejected`.
11. **Result.** `ControlEvidence::new(descriptor.public_key,
    admitted.assurance_claims(), [token_id, descriptor_id], adapter, 1,
    work)`. No `signature_message` is set: the workload signs the Auths
    preimage directly.

`maximum_work_units()` is the maximum over pinned keys of the bound suite's
`work_units()` plus a fixed parsing charge. Charged work MUST NOT depend on
which branch failed.

## 8. Assurance claims

Produced by the adapter-local `AdmittedWorkload::assurance_claims()` with
source `adapter:oidc-workload-v1`. AP-SPEC-046 may emit claims with the same
identifiers only after its source-specific normalization establishes every
parameter from the corresponding Fulcio fact. Equal claim names do not, by
themselves, establish semantic equivalence.

| Claim identifier | Parameters | Emitted when |
| --- | --- | --- |
| `oidc.issuer` | `issuer` | always |
| `oidc.subject` | `subject` | always |
| `oidc.policy` | `policy_digest` | always |
| `oidc.repository` | `repository`, `repository_id`, `owner`, `owner_id` | `GithubActions` |
| `oidc.workflow` | `repository`, `path`, `ref`, `commit`; corresponding `job_*` fields when a reusable workflow is present | `GithubActions` |
| `oidc.ref` | `ref`, `sha` | `GithubActions` |
| `oidc.environment` | `environment` | fact present |
| `oidc.runner` | `runner_environment` | fact present |
| `oidc.actor` | `actor`, `event` | both facts present |

This adapter additionally emits `oidc.token-window` with `issued`,
`expires`, and `lifetime_seconds`.

## 9. Errors and translation

```rust
pub enum OidcError {
    PrincipalSyntax, UnknownIssuer,
    MissingToken, DuplicateToken, MissingKeyDescriptor, DuplicateKeyDescriptor,
    Jws(JwsError), KeyDescriptor,
    UnknownKey, AlgorithmMismatch, TokenSignature, SuiteContract,
    Claims(ClaimError), IssuerMismatch, SubjectMismatch, VerificationMethodMismatch,
    OutsideWindow(WindowViolation), AudienceMismatch, WorkloadSuiteMismatch,
    PolicyRejected(PolicyRejection), LimitExceeded,
}
```

Constructors return `ConfigurationError` directly. A construction-only error
is not a runtime `OidcError`, which keeps the translation below exhaustive.

| `OidcError` | `PrincipalControlError` | Verifier outcome |
| --- | --- | --- |
| `PrincipalSyntax`, `IssuerMismatch`, `SubjectMismatch` | `PrincipalMethodMismatch` | `Denied` |
| `VerificationMethodMismatch` | `VerificationMethodMismatch` | `Denied` |
| `MissingToken`, `MissingKeyDescriptor` | `MissingEvidence` | `Denied` |
| `WorkloadSuiteMismatch` | `SignatureSuiteMismatch` | `Denied` |
| `UnknownIssuer`, `Jws`, `KeyDescriptor`, `DuplicateToken`, `DuplicateKeyDescriptor`, `UnknownKey`, `AlgorithmMismatch`, `TokenSignature`, `Claims`, `OutsideWindow`, `AudienceMismatch`, `PolicyRejected` | `InvalidEvidence` | `Denied` |
| `SuiteContract` | `ExternalFactUnavailable` | `Indeterminate` |
| `LimitExceeded` | `ResourceLimitExceeded` | `Indeterminate` |

`ControlEvaluation` under `DiagnosticMode::Collect` records the `OidcError`
discriminant as a stable diagnostic code of the form `oidc.<variant>`;
nested variants append `.<inner>`. No claim value, key byte, or token byte
appears in a diagnostic.

## 10. Adversarial matrix

Required cases in `core/conformance/v1/adapters/oidc-workload.json`, each
with its exact expected `OidcError`:

- structure: one, two, and four segments; empty segment; padding; non-
  alphabet byte; token above `MAX_TOKEN_BYTES`; header not an object;
  header with unknown member; `typ` of `jwt`; `cty` present;
- header: `alg` of `none`, `NONE`, `HS256`, `hs512` rejected by the type;
  `alg` absent; `kid` absent; `kid` known with a different `alg`
  (`AlgorithmMismatch`); `kid` unknown; `crit`, `jwk`, `jku`, `x5c`,
  `x5u` present; malformed or oversized `x5t` and `x5t#S256`; valid bounded
  thumbprints accepted and ignored for key selection;
- signature: truncated, extended, bit-flipped, under a key not in the set,
  under the right key material bound to a different suite;
- configuration: pinned key naming an unregistered suite, a non-`Jws`
  binding descriptor, or material rejected by `validate_key`, each
  rejected at construction with its `ConfigurationError` variant;
- claims: duplicate member; nested object; `null`; boolean; float;
  negative `exp`; `exp` as string; `aud` array of two; `aud` array of one
  correct string accepted; unpaired surrogate; claim above
  `MAX_CLAIM_BYTES`; `repository_owner` not the first segment of
  `repository`; absent or malformed `repository_id`, `repository_owner_id`,
  or `workflow_sha`; only one of `job_workflow_ref` and `job_workflow_sha`;
  workflow reference without its repository prefix; unknown claim name;
- identity: `iss` differing by scheme, trailing slash, case, or port; `sub`
  differing by case or percent-encoding;
- window: `iat > exp` rejected at parse; evaluation before `nbf`; evaluation
  at or after `exp + CLOCK_SKEW`; `iat` after evaluation beyond skew;
  lifetime above the issuer bound; each boundary exactly at the skew limit;
  `iat` below `CLOCK_SKEW` (saturating subtraction); a retained key signing
  after expiry with a backdated `asserted_signing_time` is denied;
- audience: correct digest under the wrong prefix; digest over a descriptor
  differing in one key byte; digest over the same key under a different
  suite identifier; descriptor `suite_id` differing from
  `input.signature_suite`;
- verification method: token differing by one byte;
- policy: matching repository name with a different repository or owner ID;
  renamed repository with the same IDs accepted; `Exact` pin with a different
  path, ref, or commit; `AnyRef` pin with a different path; constrained
  `environment` against an absent fact; `GithubActions` profile receiving
  a `Generic` identity (`ProfileMismatch`); no policy admitting;
- profile: GitHub vocabulary members under the `Generic` profile are rejected
  unless that profile version explicitly registers the exact name in its
  closed ignored vocabulary; ignored members yield no GitHub assurance claim;
- commitment: key, policy, and issuer reordering preserve
  `configuration_id`; any `kid`, algorithm name, suite identifier, suite
  `configuration_id`, material byte, policy field, issuer, or lifetime
  change alters it.

## 11. Dependencies and trusted computing base

`auths-oidc-workload` depends on `auths-model`, `auths-ports`,
`auths-raw-key-core`, `sha2`, and `base64ct`. `cargo xtask arch` MUST reject
any signature, curve, or path-building crate as a dependency of
`auths-oidc-workload`. The workspace-wide rule for existing adapters lands in
AP-SPEC-048 and is not a prerequisite for this new adapter.

An RS256 suite is required to consume GitHub Actions tokens and does not
exist in the workspace. It is delivered as a separate crate,
`auths-signature-rsa-pkcs1-sha256`, implementing `SignatureSuite` with
identifier `rsa-pkcs1-sha256-v1` over `ring` (`default-features = false`),
accepting only 2048, 3072, and 4096-bit moduli with exponent 65537 encoded
as DER `RSAPublicKey`. It is reviewed as a suite under the existing suite
rules, not as part of this adapter. A deployment that pins only ES256 or
EdDSA issuer keys does not load it.

The adapter and RSA suite MUST compile for `wasm32` and appear in the WASM
equivalence gate.

## 12. Acceptance criteria

1. AP-SPEC-047 sections 4, 6, 8, and 9 have landed. `cargo xtask arch`
   pins `auths-oidc-workload` to the section 11 list.
2. `cargo xtask wire --update` adds one valid GitHub Actions fixture under
   `rsa-pkcs1-sha256-v1`, one under `p256-sha256-v1`, and one generic-
   profile fixture under `ed25519-v1`; at least one fixture uses a workload
   descriptor whose suite differs from the issuer key's suite.
3. `cargo xtask conformance` executes every section 10 case with its exact
   `OidcError` oracle and a minimized recipe.
4. `cargo xtask fuzz-smoke` includes `CompactJws::parse`, the closed claim
   parser, and `TokenWindow::new`.
5. Property tests cover `JwsAlgorithmName::parse` rejection classes,
   `TokenWindow` arithmetic at `u64` boundaries, and set-constructor
   ordering independence.
6. The cross-language corpus verifies the fixtures through the three-input
   WASM boundary with byte-identical results.
7. A maintained GitHub Actions workflow creates an ephemeral workload key,
   derives the exact audience, requests a real GitHub OIDC token, creates an
   Auths proof through a public authoring API, and verifies it through a public
   verification API. The workflow also proves that replay after token expiry
   is denied. No checked-in token or private key is used.
8. The workflow records the real JOSE header and claim-name inventory as
   redacted compatibility evidence. Any new header or claim requires an
   explicit parser decision rather than a permissive unknown-field path.
9. AP-SPEC-002 section 1.2 and `docs/adapter-conformance.md` list the
   adapter.

## 13. Out of scope

- JWKS discovery, caching, or rotation. The key set is a verifier input.
- Issuer profiles other than `generic` and `github-actions`. GitLab,
  Buildkite, and CircleCI profiles are additive variants of
  `IssuerProfile` and `WorkloadIdentity`.
- Token revocation or a status method for `oidc-workload:` principals.
- Certificate-mediated bindings; see AP-SPEC-046.
- A general token-acquisition service. The maintained GitHub Actions producer
  journey is required; other platforms remain platform-specific.
- Digest agility. Commitments use the model's `Digest`; a future digest
  change versions the media types and adapter identifier.
