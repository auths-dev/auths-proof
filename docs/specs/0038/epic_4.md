# Epic 4 — Harden External Custody

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** Epic 1 and AP-SPEC-029

**Can run alongside:** Epic 2

**Blocks:** Epics 7–9

## Outcome

Make external signing a closed, transaction-bound, cryptographically checked
boundary. Ship one open AWS KMS reference adapter using P-256 and one open
PKCS#11 reference adapter using P-256, plus an adapter conformance kit that
allows other custody implementations without moving provider behavior or
private keys into Auths.

These adapters prove agility; Auths does not promise to own every cloud KMS,
HSM, signature suite, or organizational key ceremony.

## Zero-context starting point

Read:

- `core/crates/auths-author/src/lib.rs`, especially
  `ExternalSigningRequest<T>`;
- `core/crates/auths-model` signature/principal types;
- `core/crates/auths-ports` and `core/crates/auths-registries`;
- `core/adapters/auths-raw-key` and P-256 signature support;
- `product/integrations/auths-custody/src/lib.rs`;
- `bindings/typescript/src/workflow/contracts.ts` and
  `bindings/typescript/src/workflow/custody.ts`;
- `bindings/python/python/auths/_custody.py` and signer types in
  `_workflow.py`;
- `docs/specs/0029-human-approval-and-custody.md`; and
- `docs/plans/simplify/12_ADAPTER_CONFORMANCE_KIT.md`.

Current facts:

- Auths authoring already produces exact signing preimages, object IDs,
  descriptors, request IDs, and transaction digests.
- `auths-custody` exposes `ExternalSigner` and rejects a mismatched returned
  transaction digest.
- `ProviderSigningResponse` can bind request ID, principal, descriptor, and
  transaction, but the trait does not force every adapter through that parser.
- Current `CustodyError` does not distinguish cancellation, throttling,
  revocation, policy mismatch, malformed response, or provider-unknown.
- No maintained cloud KMS or PKCS#11 product adapter is present.

## Product constraint

The default developer flow must remain simple:

```text
production.auths.toml:
  custody.adapter = "aws-kms-p256-v1"
  custody.key = { env = "AUTHS_KMS_KEY_ARN" }
```

The runtime uses workload credentials from the platform. Application code does
not call `sign(bytes)`, handle DER, choose hash functions, parse provider
responses, or see private key material.

Advanced users may supply a custom adapter through the conformance port. The
same transaction-bound request and stable result types apply in Rust,
TypeScript, and Python.

## Architecture

```text
unsigned Auths object
        |
        v
auths-author::ExternalSigningRequest<T>
        | exact preimage + descriptor + transaction digest
        v
auths-custody::SigningIntent
        |
        +-------------------+
        v                   v
AWS KMS P-256        PKCS#11 P-256
        |                   |
        +---------+---------+
                  v
       untrusted provider response
                  |
                  v
 central binding + signature verification
                  |
                  v
          SignedArtifact<T>
```

The provider adapter performs I/O. The central `auths-custody` package owns
response parsing, request/descriptor/principal/transaction equality, signature
normalization contract, verification, and completion of the Auths object.

## Rust API cutover

Replace the current trusted-return trait directly. Do not retain a deprecated
trait or compatibility adapter.

```rust
pub struct CustodyDescriptor {
    kind: CustodyKind,
    adapter_id: CustodyAdapterId,
    principal: PrincipalId,
    signature: SignatureDescriptor,
    key_version: KeyVersionId,
    lifecycle: KeyLifecycleState,
}

pub struct UntrustedSigningResponse {
    request_id: String,
    principal: PrincipalId,
    descriptor: SignatureDescriptor,
    signature: Vec<u8>,
    provider_key_version: KeyVersionId,
    evidence: Vec<EvidenceObject>,
    transaction_digest: [u8; 32],
}

pub trait ExternalSigner: Send + Sync {
    fn descriptor(&self) -> &CustodyDescriptor;
    fn sign(
        &self,
        request: &SigningIntent<'_>,
    ) -> Result<UntrustedSigningResponse, CustodyProviderError>;
}

pub trait CustodySignatureVerifier: Send + Sync {
    fn verify(
        &self,
        descriptor: &CustodyDescriptor,
        preimage: &[u8],
        signature: &SignatureBytes,
        evidence: &[EvidenceObject],
    ) -> Result<(), CustodyError>;
}
```

`sign_grant`, `sign_action`, `sign_principal_status`, and
`sign_grant_status` must:

1. reject a request descriptor different from the configured descriptor;
2. call the adapter with a sealed intent;
3. parse the response into bounded types;
4. compare request ID, principal, descriptor, key version, and transaction
   digest;
5. normalize the provider signature into the suite's canonical encoding;
6. cryptographically verify the signature over the exact Auths preimage;
7. validate bounded attestation/evidence through the registered adapter; and
8. only then consume the unsigned request into `SignedArtifact<T>`.

`CustodyDescriptor` and signing response constructors remain private or
parse-token protected where necessary. Provider-returned bytes are untrusted.

## Stable outcomes

Separate provider failures from Auths validation failures.

Provider outcomes:

- `denied`;
- `cancelled`;
- `throttled`;
- `unavailable`;
- `revoked-key`;
- `disabled-key`;
- `provider-unknown`; and
- `invalid-provider-response`.

Auths validation failures:

- request mismatch;
- principal mismatch;
- descriptor/suite mismatch;
- key-version mismatch;
- transaction mismatch;
- malformed signature;
- non-canonical signature;
- signature verification failed;
- evidence/attestation mismatch; and
- lifecycle state not permitted.

Each maps to `auths-errors` with explicit retry class, effect state, and
recommended action. Signing is not an external application effect, but an
ambiguous custody response must not be silently repeated when provider policy
or operator approval could make repeated signing meaningful.

## AWS KMS reference adapter

Add `product/integrations/auths-custody-aws-kms/`.

V1 supports exactly:

- asymmetric `ECC_NIST_P256` signing keys;
- `SIGN_VERIFY` usage;
- `ECDSA_SHA_256`;
- Auths suite `p256-sha256-v1`;
- a configured full key ARN and expected AWS account/region commitment;
- workload credentials supplied by the standard AWS credential chain; and
- `GetPublicKey`, `DescribeKey`, and `Sign` only.

Startup:

1. resolve credentials without logging them;
2. call `DescribeKey` and `GetPublicKey`;
3. parse DER SPKI into a P-256 verification key;
4. derive the Auths principal/verification method through the registered
   public-key identity adapter;
5. verify key usage, enabled state, algorithm, account, region, and configured
   key-version identity; and
6. freeze a `CustodyDescriptor` and readiness evidence.

Signing sends the exact Auths preimage using the KMS mode appropriate to the
suite contract. If KMS hashes internally, the suite and request explicitly bind
that mode; no adapter may accidentally hash twice. Convert returned ASN.1 DER
ECDSA into canonical fixed-width `r || s`, enforce low-S if required by the
registered suite, and verify locally before completion.

The adapter never accepts an arbitrary KMS algorithm, message type, grant
token, encryption context, or key ID per request.

## PKCS#11 reference adapter

Add `product/integrations/auths-custody-pkcs11/`.

V1 supports exactly:

- one configured module path and slot/token identity;
- one P-256 private-key object selected by immutable object ID;
- corresponding public-key material read and verified at startup;
- one closed ECDSA/SHA-256 mechanism matching `p256-sha256-v1`;
- bounded session pool and operation timeout; and
- PIN supplied through a secret provider, never config or environment dump.

Use a maintained safe PKCS#11 crate. No repository `unsafe` code is permitted.
The adapter serializes or pools sessions according to token capability, clears
PIN/session material, handles token removal and session invalidation, and
locally verifies every returned signature.

SoftHSM provides deterministic CI integration. Real hardware qualification is
recorded separately and does not make SoftHSM a hardware claim.

## Key lifecycle

Add closed types and operations for:

- enrolled and ready;
- rotation pending;
- active current version;
- retiring previous version;
- revoked;
- disabled; and
- unavailable/indeterminate status.

Rotation is an explicit new `CustodyDescriptor` and trusted-status update.
There is no “try old key if new key fails” path. Old signed objects remain
verifiable only according to their exact historical trust/status evidence.

Emergency disablement stops new signing but does not prevent verification,
receipt access, or recovery observation.

## UX and diagnostics

`auths doctor` reports only bounded public facts:

```text
custody adapter:   aws-kms-p256-v1
suite:             p256-sha256-v1
key version:       sha256:<public-version-commitment>
state:             ready
workload identity: available
self-test:         passed
```

It never prints key ARN, account ID, module path, slot, object ID, PIN,
credentials, signing preimage, signature, principal, or provider error text.

## Conformance kit

Add shared fixtures under `product/fixtures/v1/custody/` and expose the
mechanism contract through the existing framework/testkit surfaces only after
the two independent adapters pass.

Required cases:

- exact valid response;
- changed request ID, object, principal, descriptor, suite, key version,
  transaction digest, preimage, signature, and evidence;
- high-S and malformed DER signatures;
- replayed response for another Auths object;
- concurrent signing and response reordering;
- timeout before send, disconnect after possible send, throttle, denial,
  cancellation, disabled/revoked key, and provider outage;
- rotation during an in-flight request;
- KMS policy widening or key replacement;
- PKCS#11 token removal, session loss, wrong object, and wrong PIN; and
- secret/error/telemetry redaction.

The testkit records adapter calls and stable outcomes, never key material.

## Files and policy updates

- direct-cutover `auths-custody` trait and validation path;
- new AWS KMS and PKCS#11 product packages;
- root workspace dependencies and members;
- `architecture.toml`, `compliance.toml`, dependency snapshots;
- Rust/TypeScript/Python conformance fixtures and public type projections;
- semantic-freeze identities and release subjects;
- deployment secret-slot configuration; and
- operator key lifecycle and emergency runbooks.

## Validation commands

```text
cargo test -p auths-custody
cargo test -p auths-custody-aws-kms
cargo test -p auths-custody-pkcs11
cargo xtask arch
cargo xtask compliance
cargo xtask semantic-freeze
cargo deny check
```

Run SoftHSM integration in CI. Run AWS KMS tests only in the dedicated sandbox
account with a short-lived workload identity, a test key, hard cost limits,
cleanup, and redacted evidence.

## Exit gate

This epic is complete when both adapters pass the same adversarial conformance
corpus, every returned signature is centrally bound and locally verified,
private keys never enter Auths memory, failure classes are identical across
SDKs, rotation/revocation/outage runbooks are exercised, and the candidate
manifest binds exact adapter, suite, key-policy, and conformance identities.
