# AP-SPEC-002: Adversarial Context and Adapter Conformance

**Status:** Proposed
**Intended audience:** principal-adapter authors, verifier implementers,
security reviewers, and interoperability laboratories
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the conformance system described here
**Scope:** construction of `VerifierContext`, the `PrincipalMethod` boundary,
all seven target V1 principal adapters, and the mapping of adapter failures into
portable verifier outcomes

## Abstract

Auths-Proof evaluates immutable inputs, but immutability alone does not make
those inputs correct. A malformed trust anchor, ambiguous status snapshot,
wrong adapter configuration, or evidence object consumed under the wrong
principal can produce a deterministic but unsafe deployment.

This specification defines a reproducible adversarial conformance program for:

1. verifier-trusted context construction and canonical round trips;
2. the common `PrincipalMethod` contract;
3. raw-key, `did:key`, bounded `did:keri`, bundled `did:web`, WebAuthn,
   HSM-attested, and SPIFFE X.509-SVID adapters; and
4. verifier translation from adapter failures to `Denied` or `Indeterminate`.

The suite uses deterministic mutation recipes, boundary-value generation,
metamorphic properties, and minimized fixtures. It performs no live resolution
or network access. Every accepted case and every rejection is reproducible from
a named seed, mutation identifier, and immutable configuration digest.

## 1. Current implementation map

### 1.1 Shared boundaries

| Boundary | Current source |
| --- | --- |
| `VerifierContext` fields and constructor invariants | [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs), `VerifierContext` |
| SDK context template | [`product/sdk/auths-sdk/src/lib.rs`](../../product/sdk/auths-sdk/src/lib.rs), `TrustedContextBuilder` |
| Context canonical codec and digest | [`core/crates/auths-codec/src/lib.rs`](../../core/crates/auths-codec/src/lib.rs) |
| Principal adapter contract | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `PrincipalMethod` |
| Adapter output | [`core/crates/auths-ports/src/lib.rs`](../../core/crates/auths-ports/src/lib.rs), `ControlEvidence` |
| Immutable executable registries | [`core/crates/auths-registries/src/lib.rs`](../../core/crates/auths-registries/src/lib.rs), `ImmutableRegistries` |
| Adapter-error translation | [`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs), `control_failure` |
| Existing corpus construction | [`core/testkit/auths-testkit/src/lib.rs`](../../core/testkit/auths-testkit/src/lib.rs) |
| Canonical corpus | [`core/fixtures/v1/manifest.json`](../../core/fixtures/v1/manifest.json) |
| Existing fuzz targets | [`core/fuzz/fuzz_targets`](../../core/fuzz/fuzz_targets) |
| Corpus generation and checks | [`xtask/src/main.rs`](../../xtask/src/main.rs), `wire`, `conformance`, and `cross-language` commands |

### 1.2 Principal adapters

| Method | Implementation | Verifier-local configuration |
| --- | --- | --- |
| Raw key | [`core/adapters/auths-raw-key/src/lib.rs`](../../core/adapters/auths-raw-key/src/lib.rs) | none |
| `did:key` | [`core/adapters/auths-did-key/src/lib.rs`](../../core/adapters/auths-did-key/src/lib.rs) | none |
| `did:keri` | [`core/adapters/auths-did-keri/src/lib.rs`](../../core/adapters/auths-did-keri/src/lib.rs) | limits and optional checkpoints |
| Bundled `did:web` | [`core/adapters/auths-did-web/src/lib.rs`](../../core/adapters/auths-did-web/src/lib.rs) | current/historical trust records and optional statement pins |
| WebAuthn | [`core/adapters/auths-webauthn/src/lib.rs`](../../core/adapters/auths-webauthn/src/lib.rs) | credential registrations, origins, RP IDs, counters, validity, attestation policy |
| HSM-attested | [`core/adapters/auths-hsm-attested/src/lib.rs`](../../core/adapters/auths-hsm-attested/src/lib.rs) | reviewed key and device records |
| SPIFFE X.509 | [`core/adapters/auths-spiffe-x509/src/lib.rs`](../../core/adapters/auths-spiffe-x509/src/lib.rs) | trust-domain roots and optional leaf status |

## 2. Conformance claims

A passing implementation may claim only the following:

- well-formed accepted inputs produce the expected bounded control evidence;
- specified adversarial inputs cannot silently establish control;
- equivalent collection orderings produce the same configuration commitment;
- configuration changes that affect decisions change the configuration
  commitment;
- every consumed evidence identifier is exact and provenance-complete;
- the verifier maps typed adapter failures to the expected stable outcome;
- parsers remain total over the tested bounded input domain.

A passing implementation MUST NOT claim:

- absence of parser or cryptographic defects;
- correctness of external evidence acquisition;
- freshness beyond the timestamps supplied by the test;
- security of live WebAuthn, KERI, HSM, DID, PKI, or SPIFFE infrastructure;
- whole-program memory safety or side-channel resistance.

## 3. Architecture and repository layout

The suite adds:

```text
core/conformance/v1/
├── manifest.json
├── mutations.json
├── context-cases.json
└── adapters/
    ├── raw-key.json
    ├── did-key.json
    ├── did-keri.json
    ├── did-web.json
    ├── webauthn.json
    ├── hsm-attested.json
    └── spiffe-x509.json

core/testkit/auths-testkit/src/
├── adversarial/
│   ├── mod.rs
│   ├── context.rs
│   ├── mutation.rs
│   ├── oracle.rs
│   └── shrink.rs
└── conformance.rs

core/adapters/<adapter>/tests/
└── adversarial_conformance.rs
```

`core/conformance/v1` contains mutation recipes and expected semantic results,
not an alternative canonical wire corpus. Exact portable CBOR fixtures that
define target V1 interoperability remain exclusively in
[`core/fixtures/v1`](../../core/fixtures/v1).

The execution architecture is:

```text
+------------------+     +------------------+     +-------------------+
| Valid seed       | --> | Typed mutation   | --> | Boundary harness  |
| proof/context/   |     | deterministic ID |     | model / parser /  |
| adapter config   |     | + recorded seed  |     | adapter / verifier|
+------------------+     +------------------+     +---------+---------+
                                                             |
                              +------------------------------+|
                              |                               ||
                              v                               vv
                    +------------------+            +------------------+
                    | Exact oracle     |            | Failure shrinker |
                    | value/error/code |            | minimal recipe   |
                    +--------+---------+            +--------+---------+
                             |                               |
                             +---------------+---------------+
                                             v
                                  +-----------------------+
                                  | Reproducible manifest |
                                  | coverage + digests    |
                                  +-----------------------+
```

## 4. Test-case model and APIs

### 4.1 Case identity

Each case is uniquely identified by:

```text
<surface>/<seed>/<mutation>/<boundary>
```

For example:

```text
webauthn/p256-user-verified/client-challenge-bitflip/verify-control
context/raw-key-chain/duplicate-trust-anchor/context-constructor
did-web/historical-valid/remove-statement-pin/verifier-outcome
```

Names MUST use lowercase ASCII, digits, `/`, and `-`. Renaming a case is a
reviewable conformance change.

### 4.2 Manifest schema

The manifest is canonical JSON with lexicographically ordered object keys:

```json
{
  "schema": "auths-proof-adversarial-conformance/v1",
  "protocol": 1,
  "seed": "raw-key/ed25519-valid",
  "mutation": {
    "id": "signature-suite-substitution",
    "target": "principal_control_input.signature_suite",
    "operation": "replace",
    "value": "p256-sha256-v1"
  },
  "oracle": {
    "boundary": "verify-control",
    "class": "error",
    "code": "signature-suite-mismatch"
  }
}
```

Recipes MUST describe a typed field operation. Unstructured “flip a random
byte” recipes are permitted only for parser-totality campaigns and MUST record
the deterministic byte offset.

### 4.3 Oracles

The suite distinguishes four boundaries:

| Boundary | Oracle |
| --- | --- |
| Model construction | `Ok` or exact `ModelError` class |
| Evidence/trust-record parsing | `Ok` or adapter-specific error class |
| `PrincipalMethod::verify_control` | `ControlEvidence` projection or exact `PrincipalControlError` |
| Full verifier | decision, stage, and stable `VerificationCode` |

Adapter-specific error enums are useful for unit diagnosis but are not portable
protocol outputs. Full-verifier cases MUST assert the stable mapping implemented
by `control_failure` in
[`core/crates/auths-verifier/src/lib.rs`](../../core/crates/auths-verifier/src/lib.rs).

For example:

```rust
let outcome = method.verify_control(input);
assert_eq!(
    outcome,
    Err(PrincipalControlError::HistoricalStateUnavailable)
);

let portable = verify_portable(proof, action, &context, &registries);
assert_eq!(portable.decision(), VerificationDecision::Indeterminate);
assert_eq!(
    portable.code(),
    VerificationCode::Indeterminate(Requirement::HistoricalStateUnavailable)
);
```

## 5. Common `PrincipalMethod` contract

Every adapter MUST run the following common suite before method-specific cases.

### 5.1 Exact descriptor binding

The suite substitutes, independently:

- principal identifier;
- verification-method identifier;
- signature-suite identifier;
- control purpose;
- signing preimage;
- asserted signing time;
- verifier evaluation time.

Principal, verification method, and signature suite are always exact. The
remaining fields have method-declared relevance:

- `purpose` selects a verification relationship for methods that distinguish
  delegation, invocation, or assertion keys;
- `signing_preimage` is consumed by ceremony- or transaction-bound methods such
  as WebAuthn and HSM attestation;
- `asserted_signing_time` is consumed by historical controller-state methods;
- `evaluation_time` is consumed by methods with freshness or local-record
  validity.

Each adapter manifest MUST declare which of these fields affects its control
decision. Mutating a relevant field must produce the declared error; mutating
an irrelevant field must preserve the projected `ControlEvidence`. This avoids
pretending, for example, that a self-certifying raw-key descriptor independently
interprets participant purpose when the signed Auths object already binds that
purpose through its domain-separated preimage.

```json
{
  "method": "raw-key-v1",
  "relevance": {
    "principal": true,
    "verification_method": true,
    "signature_suite": true,
    "purpose": false,
    "signing_preimage": false,
    "asserted_signing_time": false,
    "evaluation_time": false
  }
}
```

### 5.2 Evidence-set discipline

For an accepted seed:

- remove the required evidence object;
- duplicate its identifier;
- change its media type;
- change its evidence type;
- change its source;
- replace its payload with another valid principal’s payload;
- append unbound critical evidence;
- bind evidence the adapter does not consume;
- present two candidate objects of the accepted type;
- reorder evidence objects.

Expected properties:

1. missing evidence is `MissingEvidence`;
2. ambiguity or malformed content is `InvalidEvidence`;
3. excessive input is `ResourceLimitExceeded`;
4. successful output lists every and only consumed evidence ID;
5. reordering an otherwise equivalent bound set does not change output.

### 5.3 Output invariants

Successful `ControlEvidence` MUST satisfy:

- non-empty verification key;
- canonical suite-compatible key form;
- sorted, unique, non-empty consumed-evidence IDs;
- exact adapter identifier and semantic version;
- work units not greater than `maximum_work_units()`;
- claims valid under registered assurance-claim rules;
- replacement signature message absent unless the method signs a
  method-specific ceremony message.

The shared harness is:

```rust
pub fn assert_method_contract(
    method: &dyn PrincipalMethod,
    case: &MethodCase,
) -> Result<(), ConformanceFailure> {
    let reserved = method.maximum_work_units();
    let result = method.verify_control(case.input());

    match (&case.oracle, result) {
        (Oracle::Control(expected), Ok(actual)) => {
            assert_eq!(actual.adapter(), method_adapter_id(method.id())?);
            assert!(actual.work_units() <= reserved);
            assert_sorted_unique(actual.consumed_evidence())?;
            assert_eq!(project_control(&actual), *expected);
            Ok(())
        }
        (Oracle::Error(expected), Err(actual)) if *expected == actual => Ok(()),
        (_, actual) => Err(ConformanceFailure::Mismatch { actual }),
    }
}
```

Production code remains free of test callbacks or fault-injection switches.

### 5.4 Configuration commitment

For every configured adapter:

- permuting canonical input records MUST preserve `configuration_id()`;
- duplicate configuration records MUST be rejected;
- modifying any decision-affecting record field MUST change
  `configuration_id()`;
- modifying presentation-only test metadata MUST NOT change it;
- two independently constructed equivalent adapters MUST return identical IDs.

## 6. Trusted-context construction suite

### 6.1 Surfaces

Both construction paths are tested:

1. direct `VerifierContext::new` in
   [`core/crates/auths-model/src/lib.rs`](../../core/crates/auths-model/src/lib.rs);
2. `TrustedContextBuilder::build` in
   [`product/sdk/auths-sdk/src/lib.rs`](../../product/sdk/auths-sdk/src/lib.rs).

The SDK builder MUST NOT accept a context the model constructor would reject.

### 6.2 Field mutation matrix

Each field receives at least the following cases:

| Context field | Required adversarial cases |
| --- | --- |
| Configuration ID | zero, wrong executable ID, one-bit drift |
| Composition | zero minima, diversity above branch minimum, branch minimum above plan limit, wrong exact plan |
| Trust anchors | empty, duplicate ID, same principal/different ID, unaccepted method, unaccepted profile, invalid depth |
| Accepted registries | missing required method/suite/profile/status/claim/matcher/policy; unknown accepted identifier; manifest mismatch |
| Audience | empty/invalid syntax, confusable bytes, wrong exact audience |
| Challenge | all-zero allowed only as explicit template; one-bit request mismatch |
| Evaluation time | before validity, at boundary, after validity, arithmetic edge values |
| Assurance policy | unsupported claim, duplicate requirement, unsatisfied role, stale observed time |
| Principal status | duplicate statement, untrusted issuer, rollback sequence, conflict at greatest sequence, stale/missing |
| Grant status | the same selection and freshness cases as principal status |
| Resource matcher | accepted-but-uninstalled, installed-but-unaccepted, configuration drift |
| Profile policy | accepted-but-uninstalled, denial, invalid result |
| Channel policy | exact match and each mismatch class |
| Limits | zero where invalid, exact boundary, boundary plus one, context collection already above replacement |

### 6.3 Canonical round-trip property

For every accepted context:

```rust
proptest! {
    #[test]
    fn accepted_context_has_one_encoding(case in context_strategy()) {
        let encoded = encode_verifier_context(&case)?;
        let decoded = decode_verifier_context(&encoded)?;
        prop_assert_eq!(decoded, case);
        prop_assert_eq!(encode_verifier_context(&decoded)?, encoded);
    }
}
```

For every byte mutation that remains decodable, re-encoding MUST either equal
the mutated bytes or decoding MUST return `NonCanonical`. Semantically
equivalent alternate encodings MUST NOT be accepted.

### 6.4 Context metamorphic properties

The suite MUST verify:

- trust-anchor input ordering does not change canonical context bytes;
- accepted-registry input ordering does not change bytes;
- adding a well-formed trust anchor whose principal cannot match any proof
  branch does not change decision, code, or authorized branches, although it
  necessarily changes the context digest;
- tightening limits cannot change `Denied` into `Authorized`;
- advancing evaluation time may cause expiry or stale status but cannot make an
  expired grant valid;
- replacing a status snapshot with an older sequence cannot improve a result;
- changing any public context field changes `context_digest`, except when the
  constructor canonicalizes semantically duplicate ordering.

## 7. Method-specific adversarial matrices

### 7.1 Raw key

Required cases:

- Ed25519 key length 31, 32, and 33 bytes;
- compressed P-256 key length 32, 33, and 34 bytes;
- invalid SEC1 prefix and off-curve point;
- principal digest mismatch;
- wrong verification-method fragment;
- descriptor key type inconsistent with suite;
- trailing bytes and alternate descriptor encodings;
- self-certifying and offline-verifiable claim provenance.

### 7.2 `did:key`

Required cases:

- every accepted Multikey prefix and suite pairing;
- non-minimal or unsupported multicodec;
- invalid base58 alphabet and leading-zero aliases;
- DID payload different from evidence Multikey;
- verification method outside the exact DID key;
- valid key under wrong suite;
- trailing bytes and duplicate evidence;
- equivalence with the raw-key public key without equivalence of principal ID.

### 7.3 Bounded `did:keri`

Required cases:

- empty KEL, multiple inception events, and inception not first;
- broken prior-event link and wrong sequence number;
- invalid SAID and changed canonical JSON;
- unsupported event kind or field set;
- key rotation without matching prior next-key commitment;
- signature index duplication, omission, out-of-range index, and wrong key;
- unsatisfied threshold and unsupported weighted threshold;
- witness fields outside the supported zero-witness profile;
- non-transferable identifier used with rotation;
- KEL event, attachment, count, and aggregate byte boundaries;
- checkpoint principal, sequence, SAID, freshness, and witness-result mismatch;
- KERI Ed25519/P-256 algorithm substitution.

### 7.4 Bundled `did:web`

Required cases:

- invalid DID authority, port, path, percent encoding, and case;
- document ID mismatch;
- duplicate verification method;
- unsupported relationship or document feature;
- non-canonical JSON and unknown critical field;
- current record outside its observation interval;
- historical record that does not cover asserted signing time;
- historical record without exact statement-existence pin;
- statement pin for a different Auths signing preimage;
- overlapping or duplicate local trust records;
- document digest drift;
- method key and suite mismatch;
- changed local trust interval changes configuration ID.

### 7.5 WebAuthn

Required cases:

- client-data type other than `webauthn.get`;
- challenge not equal to the digest of the exact Auths preimage;
- RP-ID hash mismatch;
- unaccepted origin, Unicode origin alias, or insecure scheme;
- missing user-presence flag;
- missing user-verification flag when required;
- credential ID, principal, method, or public-key mismatch;
- invalid authenticator-data length;
- malformed or non-canonical client-data JSON;
- signature counter rollback, zero-counter policy, and exact boundary;
- credential before `observed_at` or after `valid_until`;
- attestation level below policy;
- proof signature checked against the Auths preimage instead of the
  method-derived ceremony message.

### 7.6 HSM-attested

Required cases:

- unreviewed or absent local key record;
- provider/profile mismatch;
- principal, verification method, suite, or public-key mismatch;
- transaction digest not equal to the exact Auths signing preimage digest;
- key-handle or device-chain digest mismatch;
- insufficient protection level or exportable key where prohibited;
- stale or future-dated review record;
- altered attestation envelope type, length, or trailing bytes;
- equivalent reordered records preserve configuration ID;
- any reviewed record change affects configuration ID.

### 7.7 SPIFFE X.509-SVID

Required cases:

- empty chain, chain above maximum length, and certificate above byte limit;
- leaf not first;
- untrusted or wrong trust-domain root;
- URI SAN absent, duplicated, malformed, or different from principal;
- unexpected DNS SAN accepted as identity;
- missing client-auth EKU;
- invalid basic constraints or CA path length;
- expired, not-yet-valid, or validity boundary certificate;
- leaf public-key algorithm inconsistent with suite;
- invalid chain signature;
- required local leaf status missing, stale, inactive, or for another digest;
- trust-root reordering preserves configuration ID;
- root or status record mutation changes configuration ID.

## 8. Mutation engine

### 8.1 Typed mutation API

Mutations operate on builders before canonical encoding whenever possible:

```rust
pub trait Mutation<T> {
    fn id(&self) -> MutationId;
    fn apply(&self, seed: &T) -> Result<T, MutationError>;
}

pub enum EvidenceMutation {
    RemoveRequired,
    Duplicate,
    SubstitutePrincipal(PrincipalId),
    SubstituteSuite(SignatureSuiteId),
    ChangeMediaType(MediaType),
    Truncate { bytes: usize },
    Extend { bytes: usize },
    Flip { offset: usize, mask: u8 },
}
```

Illegal states that cannot be built through public model APIs are exercised at
the codec/parser boundary with deterministic byte mutations.

### 8.2 Pairwise and higher-order cases

Single-field mutation is mandatory but insufficient. Each adapter MUST include
pairwise cases for security-relevant interactions, including:

- valid evidence plus wrong local trust record;
- valid signature plus wrong principal;
- stale record plus newer conflicting record;
- correct key plus wrong suite;
- correct evidence payload bound under the wrong evidence ID;
- proof-carried historical state plus missing local existence fact.

Three-or-more-field mutations are generated only from declared interaction
sets to avoid a meaningless full Cartesian explosion.

### 8.3 Shrinking

Every property-test or fuzz failure MUST be reduced to:

- the smallest evidence collection;
- the shortest failing byte string;
- the smallest plan or chain;
- the earliest differing byte offset;
- one stable expected and actual code.

The minimized case is promoted to a named deterministic recipe before the issue
is considered fixed.

## 9. Operator and developer UX

The test runner exposes:

```text
cargo xtask adversarial-conformance
cargo xtask adversarial-conformance --surface context
cargo xtask adversarial-conformance --adapter webauthn
cargo xtask adversarial-conformance --case <case-id>
cargo xtask adversarial-conformance --update
```

Normal runs are read-only. `--update` may rewrite generated summaries only
after all cases pass and MUST print added, removed, and changed case IDs.

The runner emits:

```json
{
  "schema": "auths-proof-conformance-result/v1",
  "revision": "<git-commit>",
  "manifest_sha256": "<digest>",
  "cases": 842,
  "passed": 842,
  "failed": 0,
  "coverage": {
    "context_fields": "14/14",
    "principal_methods": "7/7",
    "common_contract": "7/7"
  }
}
```

Counts above are illustrative; published output records observed values.

## 10. Coverage and traceability

Each case declares one or more requirements:

```json
{
  "case": "spiffe-x509/valid/missing-client-auth-eku/verify-control",
  "requirements": [
    "ADAPTER.COMMON.EXACT_DESCRIPTOR",
    "ADAPTER.SPIFFE.EKU.CLIENT_AUTH"
  ]
}
```

`docs/TRACEABILITY.md` is extended with aggregate requirement families, while
the machine-readable case-level matrix remains in
`core/conformance/v1/manifest.json`.

Coverage is measured over semantic obligations, not Rust source lines. A method
cannot report complete coverage unless it has:

- every common-contract category;
- every declared parser bound at `limit - 1`, `limit`, and `limit + 1`;
- every local-trust field mutation;
- every stable `PrincipalControlError` it can produce;
- at least one full-verifier mapping case for each such error.

## 11. Security and privacy requirements

- Test artifacts MUST contain synthetic principals, credentials, certificates,
  trust roots, origins, and device records.
- No production key, credential ID, DID document, certificate, HSM handle, or
  domain allowlist may enter the repository.
- Random generation MUST use recorded deterministic seeds.
- The suite MUST perform no DNS, HTTP, witness, authenticator, HSM, or workload
  API calls.
- Failure output MUST cap byte dumps and redact private key material.
- Mutation recipes MUST never introduce private signing keys into shipping
  types.
- A panic, out-of-memory condition, unbounded loop, or nondeterministic result
  is a conformance failure regardless of expected semantic code.

## 12. Acceptance criteria

The suite is publishable when:

1. all 14 trusted-context field families are covered;
2. all seven principal methods pass the common contract;
3. every method-specific matrix in Section 7 is implemented;
4. every adapter parser has exact boundary cases and a fuzz target;
5. every adapter error is mapped through the full verifier at least once;
6. configuration commitments pass permutation and sensitivity tests;
7. repeated runs produce byte-identical result manifests;
8. all minimized regression cases have stable IDs;
9. the canonical V1 CBOR corpus remains the single wire source of truth;
10. an external implementer can run one command and reproduce the published
    manifest without network access.

## 13. Publication artifact

Each conformance release publishes:

```text
auths-proof-adversarial-conformance-v1/
├── CONFORMANCE-CLAIMS.md
├── manifest.json
├── result.json
├── requirement-coverage.json
├── minimized-regressions/
├── toolchain.json
└── SHA256SUMS
```

The claims document MUST state the exact adapter versions and immutable
configuration IDs tested. “Adapter V1 passed” is insufficient when two
configured instances commit to different trust records.
