# AP-SPEC-048: Existing Adapter Port Migrations

**Status:** Proposed
**Intended audience:** adapter maintainers, verifier implementers, fixture
owners, and security reviewers
**Normative language:** the terms **MUST**, **MUST NOT**, **SHOULD**, and
**MAY** are requirements on the three adapter migrations, their configuration
commitments, and architecture enforcement
**Scope:** direct migration of the SPIFFE X.509-SVID, HSM-attested, and
WebAuthn principal adapters onto the AP-SPEC-047 verification foundations;
regeneration of their affected trusted-context commitments; and activation of
the workspace-wide rule forbidding cryptographic and path-building
dependencies inside principal adapters
**Depends on:** [AP-SPEC-047](0047-algorithm-agnostic-verification-foundations.md)

## Abstract

AP-SPEC-047 adds algorithm-agnostic key-validation, algorithm-binding, and
certificate-path ports. This specification moves the three existing adapters
that currently duplicate those responsibilities onto the new foundations.

The project is prelaunch. Each adapter cuts over directly: old constructors,
algorithm matches, and embedded cryptographic implementations are deleted in
the same change that introduces the port-backed form. There are no feature
flags, compatibility constructors, deprecated aliases, or dual configuration
commitments.

The migrations intentionally change adapter configuration commitments where
new decision-affecting dependencies become explicit. Those changes are not
mixed with AP-SPEC-047 because new adapters do not depend on them. Each
adapter migration and its derived commitment fixtures form one independently
reviewable and bisectable unit.

## 1. Current implementation map

| Adapter | Current defect |
| --- | --- |
| SPIFFE X.509-SVID | Builds paths with `rustls-webpki`, maps SPKI OIDs to suites, and derives key forms inside the adapter |
| HSM-attested | Parses Ed25519 and P-256 keys locally to validate configured records |
| WebAuthn | Stores a fixed 33-byte P-256 key and rejects any suite except `p256-sha256-v1` |

Affected sources:

```text
core/adapters/auths-spiffe-x509/
core/adapters/auths-hsm-attested/
core/adapters/auths-webauthn/
core/conformance/v1/adapters/
core/fixtures/
architecture.toml
xtask/src/
```

## 2. Conformance claims

A passing implementation may claim only the following:

- the three migrated adapters perform no signature verification, key parsing,
  algorithm mapping, or certificate path construction outside AP-SPEC-047
  ports;
- each adapter's configuration commitment includes every suite, binding, and
  path-verifier commitment capable of changing its decision;
- existing valid and invalid conformance cases retain their external verifier
  outcomes except for deliberately renamed internal error variants;
- every trusted-context commitment change is attributable to exactly one
  adapter migration;
- after all three migrations, architecture enforcement prevents any principal
  adapter from depending on a signature, curve, or path-building crate.

A passing implementation MUST NOT claim:

- byte stability of the old adapter configuration identifiers;
- compatibility with the removed constructors or Boolean forms owned by
  AP-SPEC-049;
- correctness of a suite or path verifier beyond its own conformance claims.

## 3. Migration rules

1. **Direct replacement.** The old implementation and constructor are deleted
   when the new port-backed form lands.
2. **One migration unit per adapter.** Code, tests, conformance expectations,
   commitment manifest entries, and trusted-context fixtures for one adapter
   land together. A later undifferentiated fixture-regeneration change is
   forbidden.
3. **No evidence-wire change.** These migrations alter verifier
   configuration, not evidence media types or signed object encodings.
4. **No adapter-owned cryptography.** Structural parsing may remain where the
   adapter must project protocol facts, but cryptographic acceptance belongs
   to a suite or path-verifier port.
5. **Construction rejects bad configuration.** Unregistered suites,
   unsupported binding rows, and keys rejected by `validate_key` fail before
   runtime verification.

## 4. SPIFFE X.509-SVID migration

```rust
pub struct SpiffeX509Method<'a> {
    trust_domains: SpiffeTrustDomainSet,
    status: SpiffeStatusSet,
    path_verifier: &'a dyn CertificatePathVerifier,
    key_bindings: AlgorithmBindingSet,
    suites: &'a [&'a dyn SignatureSuite],
}
```

The direct cutover is:

- delete adapter-local `verify_chain`;
- delete the SPKI OID-to-suite match and adapter-local cryptographic key
  parsing;
- call `path_verifier.verify` with `input.evaluation_time`, the configured
  trust anchors, supplied intermediates, and the client-auth EKU;
- compare the returned leaf DER, validity, SPKI algorithm, and SPKI bytes with
  the structurally parsed input leaf; disagreement is
  `SpiffeError::PathVerifierContract` and maps to `Indeterminate`;
- call `key_bindings.select_spki(verified_leaf.spki_algorithm())` and obtain
  the suite and `KeyForm` from the result;
- require the selected suite to equal `input.signature_suite`;
- derive verification bytes only through
  `verified_leaf.key_bytes(selection.key_form)`;
- remove `p256`, `rustls-webpki`, `rustls-pki-types`, and any path backend from
  the adapter's dependencies.

The binding set used by the existing fixtures contains:

| SPKI algorithm | Key form | Suite |
| --- | --- | --- |
| Ed25519 `1.3.101.112` | `BitStringContents` | `ed25519-v1` |
| EC public key with P-256 parameters | `Sec1Compressed` | `p256-sha256-v1` |

The exact DER `AlgorithmIdentifier`, including required parameters, is the
selector. Matching an OID while ignoring parameters is forbidden.

`configuration_id()` now commits to the path verifier's `id` and
`configuration_id`, the complete algorithm-binding-set commitment, and every
selected suite commitment in addition to the existing trust-domain and status
configuration.

## 5. HSM-attested migration

`HsmKeyRecord::new` takes the registered suites required to validate its
verification material. It locates the record's typed suite identifier and
calls that suite's `validate_key`.

The direct cutover is:

- delete adapter-local `validate_key` and all Ed25519/P-256 parsing;
- delete `HsmError::UnsupportedSuite` where it represents local algorithm
  knowledge;
- reject an absent suite as `HsmConfigurationError::UnregisteredSuite`;
- reject key material refused by the suite as
  `HsmConfigurationError::InvalidVerificationKey`;
- remove `ed25519-dalek`, `p256`, and other signature or curve crates from the
  adapter's dependencies.

`HsmAttestedMethod::configuration_id()` commits to each suite capable of
validating a configured record. Runtime verification continues to require the
record suite to equal `input.signature_suite`.

The migration does not broaden the HSM evidence claims. `validate_key`
establishes structural suitability for verification only; attestation policy
continues to establish the record's custody and non-exportability claims.

## 6. WebAuthn migration

```rust
pub struct WebAuthnCredential {
    credential_id: CredentialId,
    suite: SignatureSuiteId,
    public_key: BoundedBytes<MAX_WEBAUTHN_PUBLIC_KEY_BYTES>,
    // existing relying-party, origin, counter, and policy fields
}
```

The direct cutover is:

- replace the fixed `[u8; 33]` public key with bounded opaque verification
  bytes plus a typed suite identifier;
- make the credential constructor locate the suite and call `validate_key`;
- delete the `P256_SUITE` comparison and require
  `credential.suite == input.signature_suite`;
- keep assertion-message derivation and `ControlEvidence::signature_message`
  unchanged;
- remove `p256` and every other signature/curve crate from the adapter.

The registrar remains outside the kernel and maps the COSE algorithm and key
to a registered Auths suite plus that suite's accepted key representation.
Adding a COSE selector to `AlgorithmBinding` is not part of this migration.

`WebAuthnMethod::configuration_id()` commits to every suite used by a
configured credential. The credential encoding cuts over directly to the
typed suite plus bounded bytes; no legacy credential decoder remains.

## 7. Errors and outcome preservation

Each adapter keeps a closed error translation. The following failures are
configuration-time errors:

- a binding or record naming an unregistered suite;
- key material rejected by `validate_key`;
- duplicate SPKI selectors;
- an unusable path-verifier configuration.

At runtime:

- no SPKI binding is `UnboundKeyAlgorithm` and maps to `Indeterminate`;
- path `UnsupportedAlgorithm` maps to `Indeterminate`;
- selected suite differing from `input.signature_suite` maps to `Denied` as
  `SignatureSuiteMismatch`;
- invalid signatures continue to be decided by the kernel suite;
- a port result inconsistent with structurally parsed input is a contract
  failure and maps to `Indeterminate`.

Internal error renames are acceptable because the project is prelaunch, but
every conformance case MUST retain an explicit expected verifier outcome.

## 8. Commitment regeneration

The new dependencies are decision-affecting, so the affected adapter
configuration identifiers intentionally change. There is no requirement to
preserve their previous values.

For each adapter, its migration unit MUST:

1. enumerate every newly committed field;
2. update only trusted contexts and manifests referencing that adapter's old
   commitment;
3. record old and new identifiers in the migration case file;
4. demonstrate that changing any newly committed suite, binding, or path
   verifier changes the identifier;
5. demonstrate that configuration reordering does not change it;
6. run the existing positive and negative adapter corpus before accepting the
   regenerated values.

The three units land in this order because it exercises the broadest port
first:

1. SPIFFE plus its fixtures;
2. HSM-attested plus its fixtures;
3. WebAuthn plus its fixtures.

## 9. Architecture enforcement

After the third migration, `cargo xtask arch` MUST reject direct or transitive
dependencies from every `core/adapters/*` crate on:

- signature and curve implementations including `p256`, `rsa`, and
  `ed25519-dalek`;
- path-building implementations including `rustls-webpki`, `webpki`, and
  `ring` when used as a path backend;
- future crates classified in either architecture category.

`sha2` remains permitted for commitments and protocol-defined hashes.
`x509-parser` remains permitted for bounded structural extraction only. The
architecture policy records those two categories explicitly rather than
allowing dependencies by unreviewed crate-name exceptions.

`auths-path-webpki` and signature-suite crates are port implementations, not
principal adapters, and are therefore permitted to own their cryptographic
dependencies.

## 10. Conformance and acceptance criteria

1. SPIFFE passes its existing conformance corpus through
   `CertificatePathVerifier` and `AlgorithmBindingSet`, with no adapter-local
   path or algorithm implementation remaining.
2. HSM-attested constructs every configured record through the selected
   suite's `validate_key`, with no adapter-local key parser remaining.
3. WebAuthn accepts bounded keys for registered suites and uses the credential
   suite rather than a hard-coded P-256 constant.
4. Existing valid cases produce the same `ControlEvidence` facts and verifier
   outcomes. Changed configuration identifiers are accepted only through the
   section 8 case files.
5. Each adapter migration and its fixture delta is independently reviewable;
   no combined snapshot-update commit is used.
6. `cargo xtask arch` enforces section 9 across every principal adapter.
7. All changed crates compile for `wasm32` and remain in the WASM equivalence
   gate where supported.
8. `docs/adapter-conformance.md` records the migrated implementation and its
   AP-SPEC-047 port dependencies.

## 11. Out of scope

- The AP-SPEC-045 OIDC and AP-SPEC-046 Sigstore adapters. They consume
  AP-SPEC-047 directly and do not wait for these migrations.
- Existing model collection semantics, Boolean categories, and
  `auths-identity` identifiers; see AP-SPEC-049.
- Compatibility constructors, feature-gated old implementations, or stable
  prelaunch configuration identifiers.
- New signature suites or path-verifier implementations.
- Retyping other WebAuthn and HSM string fields.
