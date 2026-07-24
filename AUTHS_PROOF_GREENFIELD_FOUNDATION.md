# `auths-proof`: Greenfield Foundation

**Status:** Proposed architecture  
**Date:** 24 July 2026  
**Repository assumption:** A completely new Rust workspace named `auths-proof`  
**Product statement:** **Bring any cryptographic principal. Auths proves whether its action was authorized.**

## Executive decision

`auths-proof` should be a small, embeddable protocol and verification kernel for **proof-carrying authorization**.

Its primitive is:

> Every action carries proof that it was authorized.

Its architectural rule is:

> Auths owns authority. Adapters prove principal control.

That split is non-negotiable.

- An identity adapter answers: **“Did this principal validly approve these exact bytes, using a verification method that was valid for this purpose at the relevant time?”**
- The Auths authority engine answers: **“Did authority flow from one of my trust anchors to that principal, without expansion, and does it cover this exact action?”**
- A proof-exchange transport answers: **“How do I deliver this challenge and proof-bearing action to the intended service, and what peer did the channel authenticate?”**
- The consuming application answers: **“Should I execute the action now, given the Auths verdict and my local operational policy?”**

`did:keri` is therefore an assurance-rich adapter, not the protocol kernel. A raw key, `did:key`, `did:web`, SPIFFE SVID, X.509 identity, SSH key, WebAuthn credential, or future method can occupy the same port without pretending that all methods provide equal security properties.

Networking follows the same discipline, but through a different port.
Iroh, HTTPS, TLS/TCP, a Unix socket, or an in-memory test channel can carry the
same proof-exchange protocol. Transport adapters move proof-bearing actions;
principal adapters prove control of Auths principals. An authenticated
transport peer is never silently promoted into Auths authority.

The first release should optimize for four outcomes:

1. A verifier can validate a complete proof without network, filesystem, database, system clock, or private keys.
2. The same authority chain can contain principals from different identity methods.
3. Verification never hides missing freshness, revocation, or historical evidence behind a generic `valid = true`.
4. The repository remains small enough that its security boundary can be understood, fuzzed, independently audited, and reimplemented in another language.

## Product boundary in one diagram

```text
                 OUTSIDE AUTHS-PROOF

  KMS / passkey / local key / agent / HSM / CI identity
                         |
                         | signs an Auths signing request
                         v
              +-----------------------+
              | auths-proof-author    |
              | builds signed objects |
              +-----------+-----------+
                          |
                          | ProofBundle
                          v
  +-----------------------------------------------------------+
  |                    auths-proof verifier                    |
  |                                                           |
  |  bundled evidence --> principal adapters                  |
  |                          |                                |
  |                          v                                |
  |                   VerifiedPrincipal                       |
  |                          |                                |
  |  trust anchors --> delegation attenuation --> action bind |
  |                          |                                |
  |                          v                                |
  |                     TrustVerdict                           |
  +-----------------------------------------------------------+
                          |
                          v
           MCP server / API / CI gate / admission hook

                 OUTSIDE AUTHS-PROOF

  HTTP resolution, DID discovery, witness networks, databases,
  policy control planes, audit storage, rate limits, budgets,
  key custody, user accounts, dashboards, and execution
```

The important absence is an Auths server. Verification is a library operation over an explicit proof bundle and explicit local context.

## 1. Scope and success criteria

### 1.1 What the protocol proves

Given:

- an action statement;
- the actor's signature;
- a chain of signed grants;
- identity evidence for every signing principal;
- any required grant-status evidence;
- locally configured trust anchors and verification policy;
- locally supplied time, expected audience, challenge, and action body;

the verifier returns a structured answer to:

> Is this exact actor authorized, through this exact chain, to perform this exact action in this verification context?

The verifier proves the chain mechanically. It does not infer organizational intent, discover a root of trust, or decide whether the action is operationally wise.

### 1.2 V1 success criteria

V1 is successful when all of the following work:

- A root identified by one method can delegate to an actor identified by another.
- A proof can be created with a raw Ed25519 or P-256 key and verified offline.
- A KERI principal can be verified through a bundled, historically pinned KEL evidence adapter.
- An action body is cryptographically bound to its proof.
- Delegation can narrow, but never expand, permission, time, audience, or remaining delegation depth.
- The verifier distinguishes `Authorized`, `Denied`, and `Indeterminate`.
- The core verifier builds for `wasm32-unknown-unknown` without networking or native system dependencies.
- Golden proof vectors are stable and can be verified by at least one independent implementation or test harness.
- Malformed and adversarial inputs are bounded, fail closed, and do not panic.

### 1.3 Explicit non-goals for V1

V1 does not provide:

- user accounts, profiles, organizations, groups, or directories;
- a wallet, key generator, keychain, KMS, HSM, or passphrase format;
- a DID resolver service;
- a KERI witness network;
- an authorization server, session service, OAuth replacement, or API gateway;
- a general-purpose policy language;
- global counters, budgets, quotas, or exactly-once execution;
- “instant revocation” without recent, verifiable status evidence;
- identity equivalence across different principal identifiers;
- confidentiality or encrypted transport;
- a hosted registry, database, transparency log, or Git storage layer.
- a mandatory networking stack, network daemon, relay service, or generic
  socket abstraction.

These exclusions are product discipline, not missing architecture.

## 2. Trust model and terminology

The model must use precise nouns. Calling everything a “key” would recreate ambiguity at the center of the protocol.

| Term | Meaning |
|---|---|
| **Principal** | An exact identifier for an entity that can control one or more verification methods. Examples: `did:keri:...`, `did:web:example.com`, `did:key:...`, `spiffe://...`, or an Auths raw-key identifier. |
| **Verification method** | The specific public-key method selected to validate a signature for a purpose. It may be directly encoded by the principal or resolved from evidence. |
| **Principal evidence** | Bundled, method-specific bytes sufficient for an adapter to validate the principal-to-verification-method binding at a stated point. |
| **Principal-control proof** | A signature plus principal evidence demonstrating that the principal approved exact domain-separated bytes. |
| **Trust anchor** | A local, out-of-band decision to trust a principal for a bounded initial authority scope. It is verifier input and is never self-declared by the proof. |
| **Grant** | A signed statement transferring a subset of authority from an issuer to a subject. |
| **Permission** | An exact `(capability, resource)` pair understood by the Auths V1 authority engine. |
| **Action statement** | A canonical statement binding actor, permission, body digest, audience, time, and anti-replay challenge. |
| **Proof bundle** | The action, its signature, grant chain, and all supporting evidence needed for offline verification. |
| **Verification context** | Locally supplied expected audience, challenge, current time, trust anchors, action bytes, and policy. |
| **Trust verdict** | A structured decision with reasons, assurance, evidence times, and limitations. |

### 2.1 A DID is not a key

A DID identifies a controller and can resolve to one or more verification methods with different permitted relationships. DID Core explicitly models verification methods and relationships such as `capabilityInvocation` and `capabilityDelegation`; the DID method supplies the method-specific update and revocation semantics. See [W3C DID Core](https://www.w3.org/TR/did-core/).

Accordingly, the main port should be named `PrincipalControlVerifier`, not `IdentityKeyPort`.

### 2.2 A digest is not a principal-control proof

SHA-256 can safely fingerprint an encoded public key, but the digest cannot sign an action. A raw-key principal must include or resolve to:

- a complete public key;
- an exact key encoding;
- an allowed signature algorithm;
- a signature over Auths signing bytes.

SHA-1 must not be accepted as security-bearing identity material. It may be parsed by a legacy migration tool, but it must never be sufficient for an `Authorized` verdict. NIST has directed users away from SHA-1 because its collision resistance is broken. See [NIST's SHA-1 transition guidance](https://www.nist.gov/news-events/news/2022/12/nist-transitioning-away-sha-1-all-applications).

### 2.3 The verifier's roots are always local

A proof cannot declare its own root and thereby become trusted. The application supplies one or more trust anchors:

```rust
pub struct TrustAnchor {
    pub principal: PrincipalRef,
    pub authority: AuthorityScope,
    pub validity: ValidityWindow,
    pub max_delegation_depth: DelegationDepth,
    pub required_assurance: AssuranceRequirements,
}
```

The same proof can therefore be authorized in one deployment and denied in another without changing its cryptographic validity.

### 2.4 V1 principals use asymmetric control proofs

“Any cryptographic principal” does not mean any cryptographic primitive. V1
accepts principals whose adapters can verify an asymmetric signature or an
equivalent non-forgeable public proof. A shared HMAC key is not a suitable
principal: every verifier holding that secret could forge the principal's
actions. Symmetric transport authentication can still protect the surrounding
channel, but it does not become an Auths principal-control adapter.

## 3. Protocol shape

### 3.1 The V1 permission model is deliberately small

V1 should support only exact permission matching:

```rust
pub struct Permission {
    pub capability: CapabilityId,
    pub resource: ResourceId,
}
```

Examples:

```text
capability = "mcp.tools.call"
resource   = "mcp://github/create_issue"

capability = "ci.release.publish"
resource   = "oci://ghcr.io/acme/payments"

capability = "http.request.post"
resource   = "https://api.example.com/v1/refunds"
```

There is no wildcard syntax in V1. No regex, glob, JSONPath, Rego fragment, or application callback is embedded in the proof kernel. Exact identifiers are less expressive, but their subset relationship is unambiguous:

```text
child permissions ⊆ parent permissions
```

Application-specific policy can map richer local intent onto exact Auths permissions before a grant is issued. Later protocol profiles can add carefully specified constraint types without changing the V1 verifier.

### 3.2 Action statement

```rust
pub struct ActionStatement {
    pub version: ProtocolVersion,
    pub actor: PrincipalRef,
    pub permission: Permission,
    pub body_digest: BodyDigest,
    pub audience: Audience,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub challenge: Challenge,
}

pub struct SignedAction {
    pub payload: ActionStatement,
    pub signature: SignatureEnvelope,
}
```

The action statement does not contain arbitrary action JSON. It commits to the application payload through `body_digest`. The verifier receives the actual body separately and recomputes the digest.

That keeps the protocol format stable while allowing an MCP request, HTTP request, in-toto statement, Git operation, or proprietary command to remain in its native format.

`issued_at` is a signer assertion, not a trusted timestamp. It can support
expiry and request-context checks, but it does not prove that the signature
existed at that time. A proof signed by a now-revoked key cannot become valid
merely by backdating `issued_at`. A policy that accepts a historically valid
but now-revoked verification method must also require evidence that anchors the
specific statement ID before revocation—for example, a witnessed KERI seal, a
trusted timestamp, or a transparency-log inclusion proof.

### 3.3 Grant

```rust
pub struct GrantPayload {
    pub version: ProtocolVersion,
    pub issuer: PrincipalRef,
    pub subject: PrincipalRef,
    pub permissions: PermissionSet,
    pub issued_at: Timestamp,
    pub valid_from: Timestamp,
    pub valid_until: Timestamp,
    pub remaining_delegation_depth: DelegationDepth,
    pub revocation: RevocationRequirement,
    pub parent: Option<GrantId>,
}

pub struct SignedGrant {
    pub payload: GrantPayload,
    pub signature: SignatureEnvelope,
}
```

A child grant must satisfy every attenuation rule:

```text
child.issuer == parent.subject
child.permissions ⊆ parent.permissions
child.issued_at >= parent.issued_at
child.valid_from >= parent.valid_from
child.valid_until <= parent.valid_until
child.remaining_delegation_depth < parent.remaining_delegation_depth
parent.remaining_delegation_depth > 0
```

For the first grant, `parent` is absent and the issuer, permissions, validity, and delegation depth are checked against a locally supplied trust anchor.

### 3.4 Proof bundle

Evidence should be deduplicated and content-addressed inside the bundle:

```rust
pub struct ProofBundle {
    pub version: ProtocolVersion,
    pub action: SignedAction,
    pub grants: Vec<SignedGrant>,
    pub principal_evidence: Vec<PrincipalEvidenceEntry>,
    pub principal_evidence_bindings: Vec<PrincipalEvidenceBinding>,
    pub authority_state_evidence: Vec<AuthorityStateEvidenceEntry>,
}

pub struct PrincipalEvidenceEntry {
    pub id: EvidenceId,
    pub method: AdapterId,
    pub media_type: EvidenceMediaType,
    pub bytes: BoundedBytes,
}

pub struct PrincipalEvidenceBinding {
    pub statement: StatementId,
    pub evidence: EvidenceId,
}
```

Each signature commits to its adapter, verification method, and algorithm. The
proof bundle separately binds the finalized statement ID to an evidence entry:

```rust
pub struct SignatureDescriptor {
    pub adapter: AdapterId,
    pub verification_method: VerificationMethodRef,
    pub algorithm: AlgorithmId,
}

pub struct SignatureEnvelope {
    pub descriptor: SignatureDescriptor,
    pub signature: SignatureBytes,
}
```

`grant_signing_bytes` and `action_signing_bytes` cover both the unsigned payload
and the `SignatureDescriptor`. This prevents an attacker from substituting an
adapter, verification method, or algorithm after signing. Evidence is not part
of the statement ID so that a verifier can use a newer or stronger evidence
bundle without changing the signed grant. The evidence payload remains opaque
to the core; only the selected adapter interprets it.

### 3.5 Revocation requirement

Identity-key status and Auths-grant status are separate:

```rust
pub enum RevocationRequirement {
    /// The grant is intentionally irrevocable until `valid_until`.
    ExpiryOnly,

    /// A proof must contain method-specific status evidence recent enough
    /// for the verifier's local policy.
    StatusProofRequired {
        method: AuthorityStateMethod,
    },
}
```

This is honest about offline verification:

- `ExpiryOnly` means compromise or mistaken issuance cannot be corrected before expiry.
- `StatusProofRequired` means the bundle must carry a signed, policy-fresh status statement or checkpoint.
- Failure to obtain required evidence is `Indeterminate`, not `Authorized`.

Global usage counts, budgets, and rate limits are intentionally absent because they cannot be proven from a standalone offline bundle without a shared, serialized state authority.

### 3.6 Networking is a separate proof-exchange port

`auths-proof` defines portable proof creation and deterministic verification.
It does not define how two processes discover or connect to one another.
Applications that exchange actions over a network should depend on a narrow
proof-exchange port above the kernel:

```text
auths-proof
    pure proof model, codec, authoring, and verification
          ^
auths-proof-exchange
    challenge -> action body + ProofBundle -> application response
          ^
transport port
    Iroh | HTTPS | TLS/TCP | Unix socket | in-memory test channel
```

The port models the Auths operation, not generic sockets. It may expose:

- a versioned challenge request and response;
- bounded submission of an exact action body and `ProofBundle`;
- the transport's observed peer identity, if any;
- transport and framing errors distinct from `TrustVerdict`;
- a response after application verification and execution policy.

It must not expose a lowest-common-denominator `connect/send/receive` API or
pretend all transports authenticate peers equally. An Iroh `EndpointId`, an
mTLS certificate fingerprint, Unix peer credentials, server-authenticated
HTTPS, and an unauthenticated byte stream are different observations.

The application may require a signed channel binding by committing the
observed sender or recipient endpoint identifier into an application action
profile and comparing it with transport metadata. That is an application
check surrounding Auths verification. It does not make the Iroh endpoint key,
TLS certificate, or socket credential an Auths principal automatically.

The normative companion design is `spec/v1/networking.md`; the architectural
decision is recorded in `docs/adr/0006-networking-port.md`.

## 4. Suggested repository structure

```text
auths-proof/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── deny.toml
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE-APACHE
├── LICENSE-MIT
│
├── docs/
│   ├── architecture.md
│   ├── threat-model.md
│   ├── assurance-model.md
│   ├── compatibility.md
│   └── adr/
│       ├── 0001-proof-carrying-authorization.md
│       ├── 0002-deterministic-cbor.md
│       ├── 0003-offline-verifier-boundary.md
│       ├── 0004-exact-permissions-v1.md
│       ├── 0005-adapter-assurance-is-not-uniform.md
│       └── 0006-networking-port.md
│
├── spec/
│   └── v1/
│       ├── protocol.md
│       ├── verification-algorithm.md
│       ├── domain-separation.md
│       ├── error-codes.md
│       ├── auths-proof.cddl
│       ├── registry.md
│       └── networking.md
│
├── fixtures/
│   └── v1/
│       ├── valid/
│       ├── invalid/
│       ├── adapters/
│       │   ├── raw-key/
│       │   └── did-keri/
│       └── manifest.json
│
├── crates/
│   ├── auths-proof-model/
│   ├── auths-proof-codec/
│   ├── auths-proof-adapter-api/
│   ├── auths-proof-verifier/
│   ├── auths-proof-author/
│   ├── auths-proof/
│   └── auths-proof-testkit/
│
├── adapters/
│   ├── auths-proof-raw-key/
│   ├── auths-proof-did-key/
│   ├── auths-proof-did-keri/
│   └── auths-proof-did-web/
│
├── resolvers/
│   └── auths-proof-did-web-http/
│
├── apps/
│   └── auths-proof-cli/
│
├── examples/
│   ├── mixed-principal-chain/
│   ├── offline-verification/
│   └── custom-adapter/
│
├── fuzz/
│   ├── Cargo.toml
│   └── fuzz_targets/
│
├── xtask/
│   ├── Cargo.toml
│   └── src/
│
└── .github/
    └── workflows/
        ├── ci.yml
        ├── fuzz.yml
        ├── interoperability.yml
        └── release.yml
```

This is the target shape, not a demand to publish every crate on day one. The first milestone can omit `did:key`, `did:web`, and the public façade until the raw-key vertical slice is complete.

The proof-exchange port and concrete network transports are intentionally not
workspace members in this repository. They belong in a separately versioned
`auths-proof-exchange` integration repository so that async runtimes, Iroh,
HTTP, TLS, relay configuration, and application state cannot enter the proof
kernel's dependency graph.

## 5. Crate responsibilities and “so what”

### 5.1 `auths-proof-model`

**Owns**

- validated protocol newtypes;
- grant, action, proof, evidence, trust-anchor, policy, and verdict models;
- stable error and reason-code enums;
- bounded collection types;
- no encoding implementation and no cryptography.

**Must not contain**

- `serde_json::Value`;
- HTTP or DID resolution;
- a clock;
- filesystem or environment access;
- signature verification;
- private-key types.

**So what**

This crate makes invalid states difficult to construct without coupling the domain model to JSON, CBOR, a database, or a particular identity method. Every other crate speaks the same vocabulary.

Representative newtypes:

```rust
#![no_std]
extern crate alloc;

use alloc::string::String;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PrincipalRef(String);

impl PrincipalRef {
    pub const MAX_LEN: usize = 512;

    pub fn parse(value: &str) -> Result<Self, ModelError> {
        if value.is_empty() || value.len() > Self::MAX_LEN {
            return Err(ModelError::InvalidPrincipalLength);
        }

        let (scheme, remainder) = value
            .split_once(':')
            .ok_or(ModelError::MissingPrincipalScheme)?;

        let mut scheme_bytes = scheme.bytes();
        if !scheme_bytes.next().is_some_and(|b| b.is_ascii_lowercase())
            || !scheme_bytes.all(|b| b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || matches!(b, b'+' | b'-' | b'.'))
            || remainder.is_empty()
            || remainder.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        {
            return Err(ModelError::InvalidPrincipalSyntax);
        }

        // Deliberately do not normalize or equate identifiers here.
        Ok(Self(value.into()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Digest32([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Timestamp(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct DelegationDepth(u8);
```

Newtype constructors must validate length, character set, ordering, uniqueness, and bounds before a value reaches the verifier.

### 5.2 `auths-proof-codec`

**Owns**

- deterministic V1 wire encoding and strict decoding;
- the CDDL-to-model mapping;
- domain-separated signing bytes;
- content identifiers;
- canonical-order and duplicate-field checks;
- input size, nesting, and collection limits.

**Recommended format**

Use deterministic CBOR with:

- integer map keys fixed in the V1 specification;
- definite-length collections only;
- shortest integer encodings;
- one canonical map ordering;
- no floats;
- no duplicate keys;
- no unregistered tags;
- byte strings for digests, signatures, and evidence;
- rejection of non-canonical encodings after bounded parse.

`minicbor` is a reasonable implementation dependency, but the protocol is the checked-in CDDL and golden bytes—not whatever the library happens to emit.

**So what**

A signature protocol lives or dies on whether every implementation signs the same bytes. Keeping encoding out of model types prevents accidental wire-format changes from routine Rust refactors or `serde` configuration.

Domain separation should be explicit:

```rust
const GRANT_DOMAIN_V1: &[u8] = b"auths-proof/grant/v1\0";
const ACTION_DOMAIN_V1: &[u8] = b"auths-proof/action/v1\0";
const GRANT_ID_DOMAIN_V1: &[u8] = b"auths-proof/grant-id/v1\0";

pub fn grant_signing_bytes(
    grant: &GrantPayload,
    descriptor: &SignatureDescriptor,
) -> Result<BoundedSigningBytes, CodecError> {
    let encoded = encode_grant_signing_input(grant, descriptor)?;
    BoundedSigningBytes::join(GRANT_DOMAIN_V1, &encoded)
}
```

Protocol IDs use one fixed V1 digest, SHA-256:

```rust
pub fn grant_id(grant: &SignedGrant) -> Result<GrantId, CodecError> {
    let encoded = encode_signed_grant(grant)?;
    Ok(GrantId(sha256_framed(GRANT_ID_DOMAIN_V1, &encoded)))
}
```

Do not add generic hash agility to V1. Identity adapters can understand other secure identifiers internally, but Auths object identifiers remain predictable and interoperable.

Initial parser limits should be specified, tested, and configurable only within
hard protocol ceilings:

| Item | Default | Hard V1 ceiling |
|---|---:|---:|
| Complete proof bundle | 2 MiB | 16 MiB |
| One evidence entry | 1 MiB | 8 MiB |
| Grant-chain length | 16 | 32 |
| Permissions in one grant | 256 | 1,024 |
| Evidence entries | 64 | 256 |
| Principal/capability/resource identifier | 512 bytes | 2,048 bytes |
| Signature bytes | 1,024 bytes | 4,096 bytes |
| CBOR nesting depth | 16 | 32 |
| Cryptographic verification operations | 256 | 2,048 |

The exact numbers can change before V1 freezes, but the existence and
enforcement order of these limits cannot. Cheap structural limits run before
expensive signature, KEL, certificate-chain, or witness verification.

### 5.3 `auths-proof-adapter-api`

**Owns**

- the pure principal-control verification port;
- the pure grant-status verification port;
- adapter selection and capability metadata;
- assurance claims emitted by successful verification;
- no concrete DID, certificate, or key implementation.

**So what**

This is the seam that prevents KERI, `did:web`, X.509, or raw-key semantics from leaking into the authority engine. It also prevents the engine from flattening all methods into equal assurance.

Principal control:

```rust
pub struct ControlProofInput<'a> {
    pub principal: &'a PrincipalRef,
    pub purpose: ProofPurpose,
    pub verification_method: &'a VerificationMethodRef,
    pub algorithm: &'a AlgorithmId,
    pub signing_bytes: &'a [u8],
    pub signature: &'a [u8],
    pub evidence: &'a PrincipalEvidenceEntry,
    pub asserted_signing_time: Timestamp,
    pub verification_time: Timestamp,
}

pub trait PrincipalControlVerifier {
    fn adapter_id(&self) -> &AdapterId;

    fn supports(&self, principal: &PrincipalRef) -> bool;

    fn verify_control(
        &self,
        input: ControlProofInput<'_>,
    ) -> Result<VerifiedPrincipal, PrincipalControlError>;
}
```

Grant status:

```rust
pub struct AuthorityStateInput<'a> {
    pub grant_id: GrantId,
    pub issuer: &'a PrincipalRef,
    pub evidence: &'a AuthorityStateEvidenceEntry,
    pub verification_time: Timestamp,
}

pub trait AuthorityStateVerifier {
    fn method(&self) -> &AuthorityStateMethod;

    fn verify_active(
        &self,
        input: AuthorityStateInput<'_>,
    ) -> Result<VerifiedGrantStatus, AuthorityStateError>;
}
```

The registry is explicit and allowlisted:

```rust
pub struct AdapterRegistry<'a> {
    principal: &'a [&'a dyn PrincipalControlVerifier],
    authority_state: &'a [&'a dyn AuthorityStateVerifier],
}
```

There is no dynamic plugin loading in the verifier process. Applications compile or explicitly instantiate the adapters they trust.

### 5.4 `auths-proof-verifier`

**Owns**

- the complete, deterministic authority verification algorithm;
- trust-anchor selection;
- delegation-chain linking and attenuation;
- action-body, audience, challenge, and time binding;
- evidence lookup and adapter invocation;
- assurance aggregation;
- structured `TrustVerdict` production.

**Must not contain**

- concrete adapter implementations;
- network resolution;
- `SystemTime::now()`;
- random number generation;
- signing or private-key handling;
- persistence;
- application execution.

**So what**

This is the product. Everything else exists to create input for or consume output from this small kernel. Its dependency graph and behavior should be auditable in a few sittings.

The verifier receives all ambient facts explicitly:

```rust
pub struct VerificationContext<'a> {
    pub now: Timestamp,
    pub expected_audience: &'a Audience,
    pub expected_challenge: &'a Challenge,
    pub action_body: &'a [u8],
    pub trust_anchors: &'a [TrustAnchor],
    pub policy: &'a VerificationPolicy,
}

pub fn verify(
    encoded_bundle: &[u8],
    context: &VerificationContext<'_>,
    adapters: &AdapterRegistry<'_>,
) -> TrustVerdict;
```

High-level algorithm:

```rust
pub fn verify(/* ... */) -> TrustVerdict {
    let bundle = decode_canonical_bounded(encoded_bundle)?;
    validate_bundle_references(&bundle)?;
    verify_action_context(&bundle.action, context)?;

    let mut authority = authority_from_matching_anchor(
        first_issuer(&bundle),
        context.trust_anchors,
    )?;

    for grant in ordered_chain(&bundle)? {
        require(grant.payload.issuer == authority.current_principal)?;
        require(grant.payload.parent == authority.last_grant_id)?;
        require(grant.payload.permissions.is_subset_of(&authority.permissions))?;
        require(grant.payload.validity.is_within(authority.validity))?;
        require(grant.payload.remaining_delegation_depth
            < authority.remaining_delegation_depth)?;

        verify_principal_signature(
            ProofPurpose::CapabilityDelegation,
            grant,
            adapters,
        )?;

        verify_required_grant_status(grant, &bundle, context, adapters)?;
        authority = authority.attenuate(grant)?;
    }

    require(bundle.action.payload.actor == authority.current_principal)?;
    require(authority.permissions.contains(&bundle.action.payload.permission))?;

    verify_principal_signature(
        ProofPurpose::CapabilityInvocation,
        &bundle.action,
        adapters,
    )?;

    evaluate_assurance_and_build_verdict(authority, context.policy)
}
```

Production code should not use `?` directly into an undifferentiated error. Every exit maps to a stable verdict reason.

### 5.5 `auths-proof-author`

**Owns**

- builders for valid unsigned grant and action payloads;
- deterministic signing requests;
- attachment and structural validation of externally produced signatures;
- proof-bundle assembly and evidence deduplication.

**Does not own**

- private keys;
- key generation;
- passphrases;
- keychain, KMS, HSM, WebAuthn, or SSH agent integrations;
- network resolution.

**So what**

Auths needs a safe authoring experience without becoming a key-management product. This crate hands exact bytes to an external signer and accepts the result back.

```rust
let draft = GrantBuilder::new(root, agent)
    .permission(permission)
    .valid_between(start, end)?
    .delegation_depth(0)?
    .expiry_only()
    .build()?;

let request = draft.signing_request()?;

// Implemented by an application, KMS client, passkey flow, or signing agent.
let external_signature = signer.sign(request.bytes()).await?;

let signed_grant = draft.attach(SignatureEnvelope {
    descriptor: SignatureDescriptor {
        adapter: request.adapter().clone(),
        verification_method: request.verification_method().clone(),
        algorithm: external_signature.algorithm,
    },
    signature: external_signature.bytes,
})?;

let grant_id = signed_grant.id()?;
let bundle = ProofBundleBuilder::new()
    .grant(signed_grant)
    .bind_principal_evidence(StatementId::Grant(grant_id), evidence_id)
    .build()?;
```

An application may define a `Signer` trait in its own integration crate. The core authoring crate should not impose async, transport, or secret-lifetime semantics on all consumers.

### 5.6 `auths-proof`

**Owns**

- a deliberately small public façade;
- re-exports of stable model, authoring, adapter, and verification APIs;
- no default concrete identity adapter.

**So what**

Most Rust users need one dependency, while advanced integrators can depend on the narrow crates. Keeping adapters out of default features prevents a dependency from silently changing the accepted trust model.

Recommended feature policy:

```toml
[features]
default = ["std"]
std = [
  "auths-proof-model/std",
  "auths-proof-codec/std",
  "auths-proof-verifier/std",
]
```

Do not add `all-adapters`, `native`, or `full` convenience features to this crate.

### 5.7 `auths-proof-testkit`

**Owns**

- fixture loading;
- builders for malformed and boundary-case bundles;
- adapter conformance suites;
- invariant/property-test helpers;
- mock time and deterministic test identities;
- no production dependency from the trust kernel.

**So what**

Every adapter must pass the same behavioral contract. A shared testkit makes “adapter” mean more than “implements a trait and compiles.”

```rust
pub fn principal_adapter_conformance(
    adapter: &dyn PrincipalControlVerifier,
    vectors: &AdapterVectors,
) {
    assert_accepts_valid_signature(adapter, vectors);
    assert_rejects_wrong_purpose(adapter, vectors);
    assert_rejects_wrong_principal(adapter, vectors);
    assert_rejects_wrong_method(adapter, vectors);
    assert_rejects_algorithm_confusion(adapter, vectors);
    assert_rejects_modified_signing_bytes(adapter, vectors);
    assert_reports_assurance_exactly(adapter, vectors);
}
```

### 5.8 `auths-proof-raw-key`

**Owns**

- a self-certifying raw-key principal format;
- strict public-key decoding;
- Ed25519 and P-256 signature verification;
- raw-key assurance reporting.

**So what**

This is the smallest useful adapter and the fastest path to a complete vertical slice. It proves that the authority protocol does not require DID resolution or a registry.

Raw-key assurance is intentionally limited:

```text
✓ offline-verifiable
✓ self-certifying key identifier
✗ rotation
✗ revocation
✗ historical controller state
```

Do not implement RSA, secp256k1, arbitrary PEM, JWK auto-detection, or user-selectable hashes in the first release. Add algorithms only through explicit protocol registry entries, fixtures, and policy defaults.

Suggested V1 identifier:

```text
key:sha256:<base64url-no-pad digest of canonical KeyDescriptor>
```

The accompanying evidence contains the descriptor:

```rust
pub struct KeyDescriptor {
    pub version: KeyDescriptorVersion,
    pub key_type: RawKeyType, // Ed25519 or P-256 in V1
    pub encoding: RawKeyEncoding,
    pub public_key: BoundedKeyBytes,
}
```

The adapter deterministically encodes and hashes the complete descriptor,
compares the digest with the principal identifier, checks that the signature
algorithm is permitted for the descriptor, and only then verifies the
signature. A bare `key:sha256:...` string without the matching descriptor and
signature is not a principal-control proof.

### 5.9 `auths-proof-did-key`

**Owns**

- strict parsing of supported `did:key` forms;
- conversion into a supported verification method;
- purpose and algorithm checks;
- no network.

**So what**

This demonstrates that a DID can be an adapter without importing the general DID-resolution ecosystem. Like a raw key, it is portable and self-contained but does not gain rotation or revocation merely by using a DID prefix.

### 5.10 `auths-proof-did-keri`

**Owns**

- bounded parsing of the exact KERI evidence profile accepted by Auths;
- event-chain and signature validation;
- key state at the requested event/time;
- rotation, revocation, delegation, and optional witness assurance;
- verification that the selected key is valid for the Auths proof purpose.

**So what**

KERI becomes the high-assurance adapter for principals that need portable historical key state. It can remain a major differentiator without defining every other crate.

This adapter should be extracted as a clean verifier, not created by depending on the old `auths-sdk`, Git adapter, keychain, CLI, or network stack. Independent KERI fixtures remain mandatory.

### 5.11 `auths-proof-did-web-http`

This crate is intentionally under `resolvers/`, not `adapters/`.

**Owns**

- HTTPS retrieval under explicit allow/deny policy;
- redirect, DNS, response-size, media-type, timeout, and cache controls;
- conversion of a fetched DID document into a bundled evidence entry;
- optional pinning to a document digest or external timestamp/checkpoint.

**Does not own**

- authority verification;
- implicit fetching during `verify`;
- the meaning of an `Authorized` verdict.

**So what**

`did:web` resolution depends on DNS, TLS, hosting, and a mutable current document. Separating retrieval from verification prevents the WASM/offline verifier from inheriting ambient network trust. The method specification describes this HTTPS mapping and its security considerations: [did:web method specification](https://w3c-ccg.github.io/did-method-web/).

A later pure `auths-proof-did-web` adapter can verify the bundled document, document commitment, signature, and purpose. The HTTP resolver is only one way to obtain that evidence.

### 5.12 `auths-proof-cli`

**Owns**

- reading action bodies and proof files;
- loading explicit trust-anchor and policy files;
- composing explicitly selected adapters and resolvers;
- human-readable and JSON verdict output;
- generating signing requests and attaching externally supplied signatures.

**Must not own**

- alternate verification logic;
- hidden online refresh;
- a private-key database;
- policy defaults disguised as protocol truth.

**So what**

The CLI is a reference client and conformance surface, not the product kernel.

Proposed first-success flow:

```text
+------------------------------------------------------------------+
| 1. Verify the published walkthrough fixture                      |
|    auths-proof verify fixtures/walkthrough/proof.ap \            |
|      --body fixtures/walkthrough/action.json \                    |
|      --trust fixtures/walkthrough/trust.cbor                      |
|                                                                  |
| 2. Build a grant signing request for an existing principal       |
|    auths-proof grant draft \                                     |
|      --issuer did:key:z6MkRoot... \                              |
|      --subject did:key:z6MkAgent... \                            |
|      --can mcp.tools.call \                                      |
|      --resource mcp://filesystem/read_file \                     |
|      --expires-in 10m \                                          |
|      --out grant.request                                         |
|                                                                  |
| 3. Sign `grant.request` with an external signer, then attach      |
|    auths-proof grant attach grant.request signature.bin \        |
|      --evidence principal-evidence.cbor --out grant.ap           |
+------------------------------------------------------------------+
```

Checked-in walkthrough keys are public, insecure test fixtures and are never
accepted by a production trust configuration. The CLI does not create or store
private keys. Production authoring delegates to a named external signer or uses
the authoring library from a signer integration.

Example verification output:

```text
AUTHORIZED

action
  actor       did:key:z6Mk...
  permission  mcp.tools.call
  resource    mcp://filesystem/read_file
  body        sha256:4ec1...
  audience    mcp://local/filesystem

authority
  root        did:keri:EN...
  grants      2
  expires     2026-07-24T14:22:00Z

assurance
  root        historical key state verified at KEL event 18
  actor       self-certifying; no rotation or revocation

limitations
  final actor key remains valid until the grant expires
```

JSON output uses the same stable reason codes as the Rust API.

### 5.13 `xtask`

**Owns**

- repository architecture checks;
- fixture generation and byte-for-byte verification;
- cross-target build orchestration;
- release manifest production;
- one local command equivalent to CI.

**So what**

Security invariants that exist only in prose will drift. `xtask` turns dependency direction, wire stability, and portability into executable policy.

## 6. Dependency mapping

### 6.1 Internal dependency graph

Arrows mean “depends on”:

```text
                              +-------------------+
                              | auths-proof-model |
                              +---------+---------+
                                        ^
                    +-------------------+-------------------+
                    |                                       |
          +---------+----------+                +-----------+-----------+
          | auths-proof-codec  |                | auths-proof-adapter-api|
          +---------+----------+                +-----------+-----------+
                    ^                                       ^
                    |                                       |
        +-----------+------------+              +-----------+-----------+
        | auths-proof-author     |              | auths-proof-verifier  |
        +-----------+------------+              +-----------+-----------+
                    ^                                       ^
                    +-------------------+-------------------+
                                        |
                               +--------+--------+
                               |  auths-proof    |
                               +-----------------+

 Concrete adapters depend on model + adapter-api and, only where needed, codec:

   raw-key      did:key      did:keri
       \           |           /
        +----------+----------+
                   |
          adapter-api + model

 CLI composition depends on façade + selected adapters + selected resolvers.
 Core crates never depend on concrete adapters, CLI, resolver, testkit, or runtime.
```

### 6.2 Allowed internal dependencies

| Crate | Allowed workspace dependencies | Forbidden workspace dependencies |
|---|---|---|
| `model` | none | everything else |
| `codec` | `model` | adapters, verifier, author, CLI |
| `adapter-api` | `model` | codec implementations, concrete adapters, resolver |
| `verifier` | `model`, `codec`, `adapter-api` | author, concrete adapters, resolver, CLI |
| `author` | `model`, `codec` | verifier, concrete adapters, resolver, CLI |
| `auths-proof` | model, codec, adapter-api, verifier, author | concrete adapters and resolvers |
| concrete adapters | model, adapter-api; codec only if required | verifier, author, CLI, resolvers |
| resolvers | model and relevant adapter evidence types | verifier business logic |
| CLI | façade, selected adapters/resolvers | no restriction on composition dependencies |
| testkit | any production crate as a dev/test consumer | must never be a production dependency |

### 6.3 Recommended external dependency policy

| Concern | Candidate dependency | Boundary |
|---|---|---|
| Deterministic CBOR | `minicbor` | `codec` only |
| Protocol digest | `sha2` | `codec` only |
| Constant-time comparisons | `subtle` | adapters/crypto-sensitive code only |
| Ed25519 verification | `ed25519-dalek` with minimal features | `raw-key`, selected adapters |
| P-256 verification | `p256` with minimal features | `raw-key`, selected adapters |
| Error derives | `thiserror` if compatible with target profile | crate-local, no error-string protocol |
| CLI parsing | `clap` | CLI only |
| JSON presentation | `serde`/`serde_json` | CLI/API presentation only; not signed wire encoding |
| HTTP | `reqwest` or smaller client | resolver crates only |
| Async runtime | `tokio` | resolver/CLI only |
| Proof exchange | small semantic port | separate integration repository |
| Key-addressed networking | `iroh` | concrete transport adapter only; never a core or principal adapter dependency |
| Property testing | `proptest` | dev dependencies/testkit |
| Fuzzing | `cargo-fuzz`/`libFuzzer` | `fuzz/` only |

Dependency rules:

- Pin the Rust toolchain and commit `Cargo.lock`.
- Minimize default features on cryptographic and parser crates.
- Use `default-features = false` in portable crates unless reviewed otherwise.
- No OpenSSL dependency in the portable verifier path.
- No Git, SQL, Tokio, HTTP, DNS, OS keychain, or process-execution crate below the resolver/CLI layer.
- No unsafe code authored in the model, codec, adapter API, verifier, or author crates.
- An adapter's new cryptographic algorithm requires an ADR, test vectors, algorithm-confusion tests, and an explicit policy decision.

### 6.4 Feature policy

Features describe platform capabilities, not security policy:

```text
Good: std, alloc, wasm
Bad:  accept-legacy, insecure, all-algorithms, skip-revocation
```

Security behavior belongs in an explicit `VerificationPolicy` value so it is visible at the call site and in verdict diagnostics.

## 7. Core APIs and basic logic

### 7.1 Assurance is typed and never silently upgraded

Adapters must describe what they actually established:

```rust
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum AssuranceClaim {
    SelfCertifyingIdentifier,
    OfflineVerifiable,
    ControllerStateCurrentAt(Timestamp),
    ControllerStateHistoricalAt(Timestamp),
    StatementExistenceProvenAt(Timestamp),
    RotationAware,
    RevocationCheckedAt(Timestamp),
    WitnessThresholdMet { receipts: u16 },
    PkiChainValidated,
    HardwareAttested,
}

pub struct VerifiedPrincipal {
    principal: PrincipalRef,
    verification_method: VerificationMethodRef,
    adapter: AdapterId,
    evidence_id: EvidenceId,
    claims: AssuranceClaims,
}
```

The fields of `VerifiedPrincipal` are private. Only the adapter API crate can construct it through a checked constructor.

The local policy names requirements:

```rust
pub struct AssuranceRequirements {
    pub required_claims: AssuranceClaims,
    pub max_controller_status_age: Option<DurationSeconds>,
    pub allow_irrevocable_principals: bool,
    pub require_statement_time_for_historical_keys: bool,
}
```

An adapter may report more assurance than required, but neither the engine nor another adapter may synthesize claims it did not verify.

`ControllerStateHistoricalAt(t)` and `StatementExistenceProvenAt(t)` are
different claims. The first says a key was authorized at `t`; the second says
the exact signed Auths object existed by `t`. Both are necessary to accept a
statement from a key that has since been revoked.

`VerificationPolicy` should have no `Default` implementation. Provide named,
reviewable constructors instead:

```rust
let policy = VerificationPolicy::live_action()
    .max_principal_evidence_age(DurationSeconds::minutes(5))
    .require_status_for_revocable_grants()
    .deny_unknown_adapters();

let archival = VerificationPolicy::offline_audit()
    .require_statement_time_for_historical_keys()
    .allow_expiry_only_grants();
```

The CLI requires `--profile live-action|offline-audit` or an explicit policy
file; it never silently chooses an offline-friendly policy for a live action.

### 7.2 Three-way decision

```rust
pub enum Decision {
    Authorized,
    Denied,
    Indeterminate,
}

pub enum VerdictReason {
    AuthorizedByGrantChain,

    // Denied: the presented proof contradicts the required authorization.
    InvalidSignature,
    ActionBodyMismatch,
    AudienceMismatch,
    ChallengeMismatch,
    PermissionNotGranted,
    DelegationExpanded,
    GrantExpired,
    GrantRevoked,
    UntrustedRoot,

    // Indeterminate: required trustworthy evidence is absent or unavailable.
    UnsupportedAdapter,
    MissingPrincipalEvidence,
    MissingAuthorityStateEvidence,
    StaleAuthorityStateEvidence,
    HistoricalStateUnavailable,
}
```

Use:

- `Denied` when the verifier has enough information to establish that the proof is invalid or unauthorized.
- `Indeterminate` when local policy requires an assurance fact that the bundle cannot establish.
- `Authorized` only when cryptography, delegation, action binding, freshness, and local assurance policy all pass.

Never expose a top-level `is_valid()` helper that ignores policy or limitations.

### 7.3 Adapter selection

Adapter selection is exact:

```rust
fn select_adapter<'a>(
    envelope: &SignatureEnvelope,
    principal: &PrincipalRef,
    registry: &'a AdapterRegistry<'a>,
) -> Result<&'a dyn PrincipalControlVerifier, VerdictReason> {
    let adapter = registry
        .principal()
        .iter()
        .find(|candidate| {
            candidate.adapter_id() == &envelope.descriptor.adapter
        })
        .ok_or(VerdictReason::UnsupportedAdapter)?;

    if !adapter.supports(principal) {
        return Err(VerdictReason::PrincipalAdapterMismatch);
    }

    Ok(*adapter)
}
```

There is:

- no “try every adapter until one verifies” behavior;
- no fallback from `did:keri` to raw key;
- no auto-detection from signature length;
- no equivalence because two identifiers contain the same public key.

### 7.4 Verification context must bind the live request

```rust
fn verify_action_context(
    action: &ActionStatement,
    context: &VerificationContext<'_>,
) -> Result<(), VerdictReason> {
    require(action.audience == *context.expected_audience)
        .or(VerdictReason::AudienceMismatch)?;

    require(action.challenge == *context.expected_challenge)
        .or(VerdictReason::ChallengeMismatch)?;

    require(action.issued_at <= context.now && context.now <= action.expires_at)
        .or(VerdictReason::ActionOutsideValidity)?;

    require(action.body_digest == sha256_body(context.action_body))
        .or(VerdictReason::ActionBodyMismatch)?;

    Ok(())
}
```

The challenge should normally be generated by the verifier or execution service and consumed once by that service. The proof format carries it; Auths does not operate the replay cache.

### 7.5 Authority is monotonically attenuated

```rust
struct EffectiveAuthority {
    current_principal: PrincipalRef,
    permissions: PermissionSet,
    validity: ValidityWindow,
    remaining_delegation_depth: DelegationDepth,
    assurance: AssuranceSummary,
    last_statement_time: Timestamp,
    last_grant_id: Option<GrantId>,
}

impl EffectiveAuthority {
    fn attenuate(self, grant: &SignedGrant) -> Result<Self, VerdictReason> {
        let child = &grant.payload;

        if !child.permissions.is_subset_of(&self.permissions) {
            return Err(VerdictReason::DelegationExpanded);
        }
        if !child.validity().is_within(self.validity) {
            return Err(VerdictReason::DelegationExpanded);
        }
        if child.issued_at < self.last_statement_time {
            return Err(VerdictReason::DelegationExpanded);
        }
        if child.remaining_delegation_depth >= self.remaining_delegation_depth {
            return Err(VerdictReason::DelegationExpanded);
        }

        Ok(Self {
            current_principal: child.subject.clone(),
            permissions: child.permissions.clone(),
            validity: child.validity(),
            remaining_delegation_depth: child.remaining_delegation_depth,
            assurance: self.assurance,
            last_statement_time: child.issued_at,
            last_grant_id: Some(grant.id()?),
        })
    }
}
```

The implementation should calculate effective authority from the anchor downward. It must never “collect permissions” across the chain.

## 8. Protocol and implementation invariants

### 8.1 Signed-byte invariants

1. Every signature has a unique domain string containing object kind and protocol major version.
2. The signed payload contains the exact principal identifier, purpose-relevant statement, audience, validity, and body or grant commitment.
3. Signed bytes use one deterministic encoding; parsing and re-encoding must reproduce the exact accepted bytes.
4. Duplicate CBOR keys, unknown critical fields, non-minimal integers, indefinite lengths, and non-canonical ordering are rejected.
5. A `GrantId` or `ActionId` is derived only through the named domain-separated function.
6. Rust field order, `Debug`, JSON, and display strings never define signed bytes.
7. Evidence payloads are content-addressed and bounded, but method-specific evidence semantics remain adapter-owned.

### 8.2 Authority invariants

1. The first issuer must match a local trust anchor exactly.
2. Every next issuer must equal the previous grant's subject exactly.
3. Child permissions are a mathematical subset of parent permissions.
4. A child's issue time cannot precede its parent, and its validity is contained within parent validity.
5. A root grant's issue time and validity are contained within the trust anchor's validity.
6. Delegation depth strictly decreases.
7. The action actor equals the terminal authorized subject.
8. The action issue time and validity are contained within terminal grant validity.
9. The action permission is in the terminal effective permission set.
10. The action audience, challenge, validity, and body digest match local context.
11. A grant requiring status evidence cannot authorize without acceptable evidence.
12. No proof can add, select, or broaden its own trust anchor.

### 8.3 Adapter invariants

1. An adapter verifies both signature correctness and principal-to-key binding.
2. The selected verification method is permitted for the requested proof purpose.
3. The signature algorithm is explicit and compatible with the key type.
4. The adapter rejects identifiers outside its exact supported method.
5. Adapter output assurance is limited to facts actually established by evidence.
6. Adapter errors cannot be converted to success by another adapter fallback.
7. The same key bytes under two `PrincipalRef` values do not imply principal equivalence.
8. Historical validity is reported only when evidence establishes state at the requested point.
9. Historical key state alone never proves when an Auths signature was created.
10. SHA-1 is never accepted for a security-bearing key or evidence commitment.
11. Evidence parsing is bounded before expensive cryptographic or recursive work.

### 8.4 Runtime invariants

1. Verification performs no network, filesystem, environment, clock, random, or process access.
2. Verification is deterministic for identical bundle, context, adapter set, and policy.
3. No private-key material enters the verifier.
4. The verifier does not mutate proof, context, adapter, cache, or global state.
5. Unsupported methods fail explicitly.
6. A panic is never a valid response to untrusted bytes.
7. Resource limits are configurable but have secure bounded defaults.

### 8.5 Verdict invariants

1. `Authorized` means every required check and assurance requirement passed.
2. Missing required evidence is `Indeterminate`, not a warning attached to success.
3. Cryptographic validity is subordinate diagnostic information, not authorization.
4. Every non-authorized result has stable machine-readable reason codes.
5. Verdicts report the evidence time or state point used for each principal and grant status.
6. Limitations survive through Rust, WASM, CLI JSON, and future language bindings.

## 9. CI and `xtask` enforcement

### 9.1 Required `xtask` commands

```text
cargo xtask ci             # exact local equivalent of required CI
cargo xtask arch           # validate crate layers and forbidden dependencies
cargo xtask wire           # regenerate and byte-compare protocol vectors
cargo xtask conformance    # run every adapter against the shared suite
cargo xtask wasm           # build and test the portable verifier target
cargo xtask fuzz-smoke     # bounded fuzz run for pull requests
cargo xtask release-check  # compatibility, provenance, SBOM, clean-tree checks
```

### 9.2 Architecture checks

`cargo xtask arch` should read `cargo metadata`; it must not rely primarily on grep.

It should reject:

- an edge that violates the internal dependency table;
- `tokio`, `reqwest`, `hyper`, `git2`, `sqlx`, `rusqlite`, keychain crates, or process-execution dependencies below resolver/CLI layers;
- concrete adapters in the verifier dependency graph;
- the testkit as a non-dev dependency;
- default features that introduce native dependencies into portable crates;
- multiple incompatible versions of security-sensitive dependencies without an allowlisted reason.

Source-level checks should additionally reject in verifier and codec paths:

- direct `SystemTime::now()`;
- direct randomness;
- `std::fs`, `std::process`, socket, and environment calls;
- `unsafe`;
- `unwrap`, `expect`, `panic!`, and unchecked indexing in untrusted parse/verify paths.

### 9.3 Pull-request CI

Every pull request runs:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --all-features
cargo test -p auths-proof-verifier --no-default-features
cargo check -p auths-proof-verifier \
  --target wasm32-unknown-unknown \
  --no-default-features
cargo deny check
cargo xtask arch
cargo xtask wire
cargo xtask conformance
cargo xtask fuzz-smoke
```

Also run:

- property tests for every attenuation rule;
- all checked-in valid and invalid proof fixtures;
- malicious size/depth/duplicate-field corpus tests;
- Rust stable and pinned MSRV builds;
- documentation tests for public examples;
- a clean-room build with no uncommitted generated files.

### 9.4 Nightly or scheduled CI

Run:

- long-duration parser and verifier fuzzing;
- Miri over portable crates;
- dependency vulnerability and license review;
- supply-chain review with `cargo-vet` or equivalent;
- KERI differential/interoperability fixtures against an independent implementation;
- WASM execution tests in current Chrome, Firefox, Safari/WebKit, and Node runtimes;
- deterministic vector generation on Linux and macOS;
- mutation testing on the verifier's critical branches;
- semver compatibility checks for public APIs and wire fixtures.

### 9.5 Property tests that matter

Examples:

```text
For every valid chain:
  removing a permission from a child cannot add authority
  shortening any validity window cannot add authority
  decreasing delegation depth cannot add authority

For every authorized action:
  changing one action-body bit denies
  changing audience denies
  changing challenge denies
  changing actor denies
  changing any grant order denies
  replacing an adapter ID denies
  removing required status evidence becomes indeterminate

For every accepted wire object:
  decode(encode(model)) == model
  encode(decode(bytes)) == bytes
```

### 9.6 Release invariants

Each release publishes:

- source commit;
- protocol and fixture-set version;
- Rust crate versions;
- WASM digest, if published;
- supported algorithms and adapters;
- minimum supported Rust version;
- SBOM;
- signed build provenance;
- exact golden-vector manifest;
- known assurance limitations.

Wire-format changes require:

- a protocol version decision;
- updated CDDL;
- new golden vectors;
- backwards-compatibility tests;
- a migration note;
- no silent reinterpretation of existing bytes.

## 10. Threat model and required defenses

| Threat | Required defense |
|---|---|
| Attacker substitutes a weaker identity method | Principal and adapter selection are exact; policy requires assurance; no fallback |
| Same key is presented under a different identifier | Principal references are never equated by key bytes |
| Signature algorithm confusion | Explicit algorithm, strict key compatibility, adapter allowlist |
| Proof is replayed | Audience, short validity, verifier-issued challenge, application replay cache |
| Action parameters are modified | Digest of exact application bytes is in the signed action statement |
| Grant chain expands authority | Mechanical subset, interval, and depth attenuation |
| Old identity state is presented | Policy requires sufficiently fresh or historical evidence; otherwise indeterminate |
| Revoked grant is presented offline | Required signed status/checkpoint evidence; expiry-only grants disclose limitation |
| `did:web` resolver is abused for SSRF | Resolver is outside verifier and enforces host, redirect, size, timeout, and address policy |
| Large evidence exhausts memory/CPU | Hard byte, item, chain-depth, nesting, and cryptographic-work limits |
| Unknown fields change semantics | Closed V1 schema; unknown critical fields fail |
| Root is self-declared | Trust anchors exist only in local verification context |
| Adapter lies about assurance | Small allowlisted adapter set, conformance suite, audit, and application policy |
| Proof reveals sensitive action data | Proof contains a digest, not the body; applications still control metadata exposure |
| Valid proof is used in the wrong protocol | Domain separation plus explicit audience and capability/resource identifiers |
| Authenticated transport peer is mistaken for authorized actor | Transport peer observations and Auths principal authority remain separate; any channel binding is explicit and signed |
| Proof-exchange challenge is replayed | Server-generated unpredictable challenge, short expiry, atomic single-use consumption outside the verifier |
| Transport adapter weakens authorization semantics | Identical proof/context inputs produce the same Auths verdict across transports; transport policy can only reject additionally |
| Unauthenticated TCP is presented as equivalent to Iroh or mTLS | Transport adapters report typed peer observations, including an explicit unauthenticated state |

The protocol cannot protect against:

- a trusted root intentionally granting dangerous authority;
- a currently valid private key being used by its legitimate controller;
- malicious application semantics hidden behind a misleading capability name;
- execution that differs from the exact body the application asked Auths to verify;
- a compromised adapter implementation loaded by the application;
- denial of service beyond configured resource limits.

These limitations belong prominently in `docs/threat-model.md`.

## 11. The strict boundary: where to stop building

This section should be copied into the repository's architecture guide and treated as a scope gate.

### 11.1 `auths-proof` owns

- canonical proof, grant, action, evidence-envelope, and verdict formats;
- exact V1 authorization semantics;
- deterministic offline verification;
- safe construction of signing requests;
- adapter interfaces and conformance requirements;
- a small set of reference verification adapters;
- test vectors and interoperability tooling;
- a reference CLI for authoring and verification.

### 11.2 `auths-proof` does not own

| Tempting feature | Why it must stay out | Where it belongs |
|---|---|---|
| Private-key storage and generation | Expands secret-handling and platform attack surface | KMS, HSM, passkey, SSH agent, OS keychain, or dedicated signer integration |
| DID discovery and live resolution in verification | Introduces ambient network trust and breaks offline/WASM determinism | Resolver crate or host application |
| KERI witness network | Turns a verifier into distributed infrastructure | Separate KERI network/service project |
| User/organization directory | Conflates identity administration with authority proof | Existing IdP/IAM or separate product |
| OAuth/OIDC server | Solves session and transport authorization, not proof-carrying delegation | Existing authorization server |
| General policy language | Recreates OPA/Cedar and makes the kernel impossible to bound | External policy engine |
| API/MCP gateway | Couples proof semantics to forwarding, retries, and availability | Integration/application repo |
| Networking stack or proof-exchange server | Requires async I/O, discovery, replay state, availability, and transport security | Separate `auths-proof-exchange` integration repo |
| Budgets, quotas, rate limits | Require serialized shared state and reconciliation | Treasury/control-plane service |
| Proof database or Git registry | Storage is a deployment choice, not verification truth | Application adapter |
| Hosted dashboard | Creates an operational SaaS product around the primitive | Separate product repo |
| Global identity equivalence | Unsafe and politically/semantically ambiguous | Explicit application mapping |
| Automatic adapter installation | Makes accepted trust code ambient and mutable | Application build/configuration |
| Arbitrary application constraints | Cannot be safely attenuated without defined semantics | Versioned profile crate or external policy |
| “Instant revocation” claim | Impossible for disconnected verifiers | Freshness-qualified status service/integration |

### 11.3 The test for accepting a feature

A feature belongs in the kernel only if all are true:

1. Every conforming verifier must implement it to agree on authorization.
2. It can be evaluated deterministically from the proof and explicit context.
3. It does not require private state, network access, persistence, or execution.
4. Its delegation and attenuation semantics can be specified precisely.
5. It can be bounded and represented in cross-language fixtures.

If any answer is “no,” build it above the kernel.

### 11.4 Avoid “helpful” core abstractions

Do not add:

- generic repositories;
- service locators;
- global registries;
- application event buses;
- generic network, socket, stream, or RPC traits in the proof kernel;
- feature-gated database traits;
- async in the verification API;
- dynamic libraries for identity adapters;
- a general `serde_json::Value` claims bag;
- a policy callback that can redefine what a grant means.

Those abstractions make the core appear flexible while hiding divergent security semantics.

## 12. Ecosystem and integration opportunities

The protocol should complement established identity, transport, policy, and attestation systems rather than position itself as their replacement.

### 12.1 MCP and autonomous tool calls — recommended wedge

**Integration**

- Encode the MCP method and tool as an exact permission/resource pair.
- Hash the canonical MCP request payload into the action statement.
- Use the MCP server or gateway as the audience.
- Have the server issue a short-lived challenge.
- Verify the Auths proof before executing `tools/call`.
- Return the proof digest and verdict reason in the audit record.

```text
OAuth / transport auth
          |
          v
    MCP request + Auths ProofBundle
          |
          v
  verify principal control + delegated authority
          |
          v
   execute exact body or refuse
```

MCP's current authorization specification defines authorization at the
transport layer using OAuth-family mechanisms. Auths should be positioned as
complementary per-action delegated evidence, not as a replacement for transport
authentication or token acquisition. See the
[MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

**Application to build separately**

`auths-proof-mcp`: middleware for an MCP SDK plus one inspectable demo in which a human or organization root delegates exactly one tool call to an agent.

This is the best first application because agent tool calls have:

- an identifiable actor;
- a discrete action body;
- a clear audience;
- high confused-deputy risk;
- a natural need for narrow, short-lived delegation;
- an audit consumer who wants more than “the API token was valid.”

### 12.2 Software supply chain: Sigstore, in-toto, OCI, and CI

Sigstore proves who signed an artifact using short-lived identity-bound certificates and transparency evidence. in-toto defines attestations about software-supply-chain steps. Auths can add a different claim:

> The signer was not only identifiable; this release action was within an explicit delegated authority chain.

Sigstore's bundle already packages signature, certificate, and transparency evidence, making it a plausible principal-evidence adapter or companion artifact. See [Sigstore's keyless signing overview](https://docs.sigstore.dev/cosign/signing/overview/) and [blob bundle documentation](https://docs.sigstore.dev/cosign/signing/signing_with_blobs/). The in-toto project publishes stable specifications for supply-chain attestations: [in-toto specifications](https://in-toto.io/docs/specs/).

**Applications to build separately**

- `auths-proof-ci`: GitHub Actions/GitLab/Buildkite step that proves a workflow had authority to release a named OCI repository.
- An in-toto predicate profile containing an Auths proof digest and verdict inputs.
- A Cosign/OCI attachment convention for storing `ProofBundle` beside an artifact.
- A deployment gate that accepts only a release proof rooted in a locally trusted release authority.

Do not rebuild Fulcio, Rekor, Cosign, or in-toto.

### 12.3 SPIFFE/SPIRE and service workloads

SPIFFE gives workloads cryptographic identities through X.509, JWT, and increasingly other SVID profiles; the Workload API distributes identities and trust bundles. Auths can treat a valid SVID as principal-control evidence and add operation-level delegation above it. See the [SPIFFE Workload API specification](https://spiffe.io/docs/latest/spiffe-specs/spiffe_workload_api/) and [SPIFFE concepts](https://spiffe.io/docs/latest/spiffe/concepts/).

**Applications to build separately**

- A SPIFFE principal adapter that validates a bundled SVID and trust bundle.
- Envoy `ext_authz` integration that turns an Auths verdict into allow/deny metadata.
- A cross-service job-delegation proof: service A authorizes a short-lived worker identity to perform one exact operation against service B.

Do not compete with SPIRE's workload attestation, node agents, identity issuance, or rotation.

### 12.4 OPA and Cedar policy engines

Auths should produce verified facts; OPA or Cedar can combine those facts with application state.

```text
ProofBundle
    |
    v
Auths verifier
    |
    | verified principal, root, permission, evidence times,
    | assurance claims, proof digest
    v
OPA / Cedar + local resource and business context
    |
    v
operational allow / deny
```

OPA evaluates structured input against policy and data across APIs, Kubernetes, and CI/CD. Cedar evaluates authorization requests against permit/forbid policies and entity data. See [OPA documentation](https://www.openpolicyagent.org/docs) and [Cedar authorization semantics](https://docs.cedarpolicy.com/auth/authorization.html).

**Applications to build separately**

- An OPA input schema and Rego helper library.
- A Cedar entity/action mapping.
- Audit correlation between an Auths proof digest and a policy-engine decision ID.

Do not embed Rego, Cedar, or another policy interpreter into the proof verifier.

### 12.5 HTTP APIs and RFC 9421

HTTP Message Signatures standardize signing selected HTTP components and carrying signature metadata. Auths can either:

- hash an RFC 9421 signature base as its action body; or
- carry a proof in an HTTP field while RFC 9421 binds the HTTP message itself.

RFC 9421 explicitly requires applications to decide appropriate key material, algorithms, time boundaries, nonces, and covered components. Auths contributes the missing delegated-authority chain. See [RFC 9421](https://www.rfc-editor.org/info/rfc9421).

**Application to build separately**

`auths-proof-http`: middleware with an explicit canonical request profile, challenge handling, and mapping to exact permissions.

Do not invent another general HTTP canonicalization scheme inside the Auths protocol.

### 12.6 WebAuthn and passkeys for human approvals

WebAuthn credentials provide scoped public-key authentication with user-mediated authenticator operations and optional attestation. A WebAuthn adapter can make a human approval the root or an intermediate Auths grant without Auths storing the credential. See [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/).

**Applications to build separately**

- A browser approval ceremony that signs an Auths grant signing request.
- A “human approved this one agent action” proof.
- An enterprise profile requiring hardware-backed or user-verifying authenticators.

The WebAuthn relying party, challenge store, credential registration, and origin policy stay outside the verifier.

### 12.7 Kubernetes admission and infrastructure changes

Possible profiles:

- deployment action: exact manifest digest, cluster audience, namespace resource;
- Terraform apply: exact plan digest and environment resource;
- emergency production command: exact command document plus short expiry;
- database migration: exact migration bundle digest.

An admission webhook or CI gate can require a valid Auths proof before allowing the native system to proceed. Kubernetes service accounts, cloud workload identities, SPIFFE SVIDs, or CI OIDC-bound certificates can be principal adapters.

Auths proves delegated authority over the exact change. Kubernetes, Terraform, and the cloud provider remain responsible for execution and native access control.

### 12.8 Git and repository operations

Useful profiles:

- approve a commit or tree digest for release;
- authorize a bot to merge one reviewed commit;
- authorize a CI identity to create a tag;
- bind a deployment proof to a Git tree and build artifact.

Store the proof as a CI artifact, release attachment, OCI referrer, or Git note according to the host workflow. Do not make Git storage part of protocol truth.

### 12.9 Event systems and durable audit

Kafka, NATS, CloudEvents, workflow engines, and job queues can carry a proof digest or complete bundle beside a command.

The consumer verifies:

- the exact serialized command body;
- the intended queue/service audience;
- the delegated permission;
- freshness and replay policy.

The audit store records the immutable proof and verdict. Auths itself should not operate that store.

### 12.10 Payments and high-value actions

Payment intent is attractive but must be a profile above V1:

- exact payment instruction digest;
- exact processor or merchant audience;
- exact payment capability/resource;
- short expiry and unique challenge;
- application policy for amount, currency, merchant, and risk.

Budgets and aggregate spend cannot live in an offline proof kernel. A treasury service must serialize reservations and settlements, then optionally issue Auths status evidence.

### 12.11 Proof exchange over Iroh and other transports

Networking is an integration opportunity, not a new responsibility for the
proof kernel. The recommended companion abstraction is a proof-exchange port
whose operation is:

```text
receive fresh challenge
        |
author exact action + ProofBundle
        |
submit bounded body + bundle
        |
application verifies, consumes challenge, and decides whether to execute
```

The first concrete network adapter should use Iroh because its stable
`EndpointId`, encrypted QUIC connections, NAT traversal, discovery, and relay
fallback are a strong fit for agents and edge services that cannot rely on
stable inbound IP addresses. The product story is:

> Iroh gets the action to the right key. Auths proves that the action was authorized.

Or, more compactly:

> Dial by key. Act by proof.

The Iroh integration should use a versioned ALPN such as
`/auths-proof/action/1`, obtain the authenticated remote `EndpointId` from the
established connection, and run the same bounded exchange state machine used
by every other transport. Authorization-bearing requests must not use 0-RTT.
Development may use public relays; production deployments must choose managed
or self-hosted relays according to their availability and metadata threat
model.

Iroh endpoint keys and Auths signing keys should be separate by default. They
have different purposes, compromise boundaries, and rotation lifecycles, and
Iroh's Ed25519 endpoint model must not constrain Auths' multi-principal design.
An application that needs channel binding includes the relevant endpoint ID
in the exact signed action profile and compares it with the connection's
observed peer.

The initial exchange repository should contain only:

- a transport-independent challenge/submission state machine;
- an in-memory transport for deterministic conformance tests;
- an Iroh adapter;
- bounded framing and typed transport peer observations;
- an MCP example that executes only after an Auths `Authorized` verdict and
  application transport policy both pass.

HTTPS, TLS/TCP, Unix-socket, or message-bus adapters may be added when a real
consumer requires them. Raw unauthenticated TCP must never be the recommended
production adapter.

## 13. Recommended build sequence

### Milestone 0: specification before implementation

- Write the threat model and V1 CDDL.
- Freeze domain strings, size limits, and verdict reason taxonomy.
- Create hand-reviewed valid and invalid vectors.
- Decide exact Ed25519 and P-256 encodings.
- Define the raw-key principal format.

**Exit criterion:** A reviewer can calculate the signing bytes and expected decision without reading Rust code.

### Milestone 1: smallest complete vertical slice

Build:

- model;
- codec;
- adapter API;
- verifier;
- author;
- raw-key adapter;
- CLI;
- testkit and fuzz targets.

Demonstrate:

```text
raw root -> raw agent -> exact action -> offline AUTHORIZED
```

**Exit criterion:** A valid proof succeeds, every one-bit mutation fixture fails, WASM builds, and no network/native dependency enters the verifier graph.

### Milestone 2: prove adapter generality

Add the pure KERI adapter and demonstrate:

```text
did:keri root -> raw-key agent -> exact action
raw-key root -> did:keri agent -> exact action
```

Run independent KERI conformance fixtures.

**Exit criterion:** The authority engine has no KERI-specific branches or types.

**Implementation status:** Complete in the greenfield repository. The
`did-keri-v1` adapter is pure, bounded, and WASM-checkable; mixed chains pass in
both directions; independent keripy 1.3.4 multisignature rotation bytes are
pinned as an oracle; and `cargo xtask arch` keeps KERI out of the authority
engine. The adapter intentionally stops at embedded-KEL principal control and
does not claim globally current KERI state.

### Milestone 3: prove resolver separation

Add:

- `did:key`;
- pure `did:web` evidence verification;
- separate `did:web` HTTP evidence resolver;
- explicit current-only versus historically pinned assurance behavior.

**Exit criterion:** The same bundled `did:web` proof verifies in native Rust and WASM without a fetch.

**Implementation status:** Complete in the greenfield repository. `did:key`
and the closed-profile `did:web` adapter are pure and WASM-checkable. Native
HTTP retrieval is isolated under `resolvers/`, produces explicit local trust
records, and is absent from the verifier and adapter dependency graphs. One
byte-identical bundled `did:web` proof verifies under both a fresh current
resolution and a historical document-plus-statement pin; a document-only
historical pin is indeterminate.

### Milestone 4: one application, not an ecosystem

Build the MCP integration and proof-exchange port in a separate repository or
separately versioned workspace. Implement an in-memory conformance transport
and Iroh as the first network adapter:

```text
human/KERI root -> agent key -> exact MCP tool call
                                      |
                            Iroh proof exchange
```

Measure:

- time to first authorized call;
- proof size;
- native and browser verification time;
- clarity of denial reasons;
- replay behavior;
- direct versus relayed connection behavior;
- separation of Iroh endpoint identity from Auths actor identity;
- transport-independent verdict consistency;
- operator ability to inspect the authority chain.

Do not add generic TCP, HTTP, message-bus, or other application integrations
until this flow has real users. Iroh remains optional: its types and
dependencies must not enter the proof wire format or verifier graph.

### Milestone 5: external review

Before calling the protocol production-ready:

- commission an independent protocol and cryptography review;
- commission an implementation review of parser, adapter, WASM, and FFI boundaries;
- publish vectors and invite a second implementation;
- resolve or document all findings against a release commit.

## 14. Initial acceptance checklist

The foundation is ready for application work only when:

- [ ] The core dependency graph matches the documented layers.
- [ ] `cargo xtask ci` passes from a clean checkout.
- [ ] `auths-proof-verifier` builds with `no_std + alloc` or the documented minimal WASM profile.
- [ ] Verification has no ambient clock, network, filesystem, randomness, or global registry.
- [ ] No proof-exchange or concrete transport dependency enters the core verifier graph.
- [ ] Trust anchors and expected audience/challenge are explicit call inputs.
- [ ] Exact permission attenuation is property-tested.
- [ ] Raw-key Ed25519 and P-256 vectors pass.
- [ ] KERI adapter vectors include independent interoperability coverage.
- [ ] All parser inputs have byte, collection, and depth limits.
- [ ] No untrusted-input path panics.
- [ ] Non-canonical wire encodings are rejected.
- [ ] `Authorized`, `Denied`, and `Indeterminate` survive CLI JSON and WASM bindings unchanged.
- [ ] Missing freshness or status evidence cannot produce `Authorized`.
- [ ] No adapter is enabled or tried implicitly.
- [ ] The CLI can complete one useful flow in under five minutes.
- [ ] The README describes Auths as delegated-action proof, not decentralized identity infrastructure.
- [ ] The threat model states what Auths does not prove.
- [ ] A transport failure cannot be represented as an Auths `Denied`,
      `Indeterminate`, or `Authorized` verdict.

## 15. Final recommendation

The greenfield repository should be judged by how little it needs to know.

It should not know:

- where a key lives;
- how a DID document was fetched;
- how KERI witnesses communicate;
- which database stores grants;
- which user belongs to which company;
- whether an MCP tool is sensible;
- how an API request is routed;
- which transport, relay, address, or network path delivered an action;
- how a budget is reconciled.

It should know, exactly and defensibly:

1. which local principal was trusted for which initial authority;
2. which principals proved control of each signed statement;
3. whether each delegation only narrowed that authority;
4. whether the terminal authority covers the exact action and context;
5. what assurance the bundled evidence actually supports.

That is a coherent protocol primitive:

> **Bring any cryptographic principal. Auths proves whether its action was authorized.**

And it gives the project a reliable stopping rule:

> If a feature does not improve portable proof creation, deterministic verification, or adapter conformance, it belongs above `auths-proof`, not inside it.
