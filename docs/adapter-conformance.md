# Third-party adapter conformance

Product-facing terms are defined in the [Auths product glossary](product/GLOSSARY.md).
This document uses exact framework and protocol terminology.

Auths does not need to own an adapter for every identity method, cryptographic
suite, or transport. A third party can implement a neutral port in its own
repository and make an accurate compatibility claim by following this process.

## Identity-method adapters

1. Implement `auths_identity::IdentityMethod` or
   `auths_identity::IdentityDescriptorMethod` without importing authority,
   capability, approval, policy, profile, or runtime packages.
2. Select a stable, non-conflicting method identifier and document its exact
   canonical identifier derivation, accepted material shape, limits, and error
   behavior.
3. Reject wrong method labels, malformed relationships, duplicate identifiers,
   non-canonical representations, empty required material, and every
   boundary-plus-one input.
4. Test that decoded data cannot become `ValidatedIdentity` without the method
   check and that a failed method check returns a typed error.
5. Publish deterministic positive and negative vectors. If the adapter claims
   `auths-identity/v1` packet compatibility, run those vectors through the
   canonical packet encoder and decoder in `auths-identity`.

## Signature-suite adapters

1. Implement `auths_ports::SignatureSuite` under one stable suite identifier.
2. Implement `validate_key` as the exact structural gate used by `verify`; a
   key accepted by it must not later produce `SignatureError::InvalidKey`.
3. Verify the exact signing preimage supplied by the caller; do not reconstruct
   or reinterpret application messages inside the adapter.
4. Reject wrong key shapes, wrong signature shapes, changed message bytes,
   unknown suite labels, and non-canonical encodings.
5. Run `core/conformance/v1/ports/signature-suite.json`, use a reviewed
   cryptographic implementation, and cross-check vectors independently.

## Algorithm-binding adapters

1. Construct `auths_ports::AlgorithmBindingSet` only from registered suites.
2. Keep JWS names and complete DER SPKI `AlgorithmIdentifier` values as
   separate exact selectors; never select only by an X.509 OID.
3. Reject duplicate selectors and commit to every selected suite
   configuration.
4. Run `core/conformance/v1/ports/algorithm-binding.json`.

## Certificate-path adapters

1. Implement `auths_ports::CertificatePathVerifier` without ambient clock,
   network, or operating-system trust-store access.
2. Use only the caller-supplied verification instant, anchors, intermediates,
   and required EKU.
3. Construct `VerifiedLeaf` through its public checked constructor and map
   unsupported algorithms separately from malformed certificates.
4. Commit to the implementation, backend, enabled algorithms, and relevant
   dependency version, then run `core/conformance/v1/ports/path-verifier.json`.

## Byte-channel adapters

1. Implement `auths_byte_channel::BoundedByteChannel` without importing
   identity, authority, capability, approval, policy, profile, or SDK packages.
2. Preserve exact non-empty frame bytes and enforce `ChannelLimits` before
   allocation or unbounded work.
3. Enforce the operation deadline and send-side sequence, and return typed
   failures for limit, timeout, sequence, and transport errors.
4. Expose peer information only as a bounded `PeerObservation`. Never promote a
   transport-authenticated identifier into an Auths identity or principal.
5. Run the same request, response, exact-boundary, boundary-plus-one, timeout,
   disconnect, and finish-send cases as the memory and Iroh reference adapters.

## Compatibility statement

A third-party package should publish a table containing:

- package version and MSRV;
- implemented Auths port and protocol versions;
- method, suite, or transport protocol identifiers;
- positive and negative vector digests;
- hard bounds and default features;
- audited cryptographic and network dependencies;
- explicit security claims and non-claims.

Passing conformance means the adapter obeys a port contract. It does not mean
Auths reviewed the package, trusts an identity, grants authority, or approves
an action. Inclusion in the Auths repository is neither required nor implied.
