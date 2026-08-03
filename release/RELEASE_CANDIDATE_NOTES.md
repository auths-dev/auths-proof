# Auths 1.0.0-rc.1 release-candidate notes

Auths 1.0.0-rc.1 is a technical release candidate for the open Auths protocol
and its lean maintained SDK surface. It is not a stable v1 release, a
production-readiness claim, or evidence of an independent security audit.

The candidate includes:

- the `auths` and `auths-sdk` Rust roots and their frozen publishable
  dependency closure;
- the `@auths-dev/sdk` TypeScript package;
- the `auths` Python distribution;
- the bounded WebAssembly module contained by the TypeScript package;
- deterministic source and assurance archives; and
- digest-bound SPDX, provenance, formal, conformance, compatibility, and
  benchmark evidence.

The exact candidate is identified only by the release manifest's full source
commit, semantic-freeze digest, release-subject digests, and signed build
provenance. The tag is a locator and must never be moved.

## Assurance boundary

Auths verifies proof-carrying bounded authority using explicit trusted inputs.
The evidence bundle distinguishes theorem-backed semantics, mechanically
connected Rust refinements, bounded model checking, executable tests, trusted
components, and excluded behavior. A valid proof is not by itself evidence
that a provider accepted an operation or that an externally observed effect
occurred.

This candidate does not claim that:

- Lean proves the network, storage, credentials, providers, or all shipping
  Rust outside the recorded translation and refinement boundary;
- SLSA establishes source correctness, dependency correctness, or artifact
  security;
- GitHub, Sigstore, a registry, or any Auths-hosted service is required to use
  Auths or verify Auths proofs;
- domain providers are atomic, deterministic, available, or exactly-once;
- the software is independently audited, certified, compliant,
  production-ready, or supported by an SLA; or
- prelaunch formats outside the frozen candidate have compatibility or
  migration support.

Offline verification instructions are in `release/RELEASE_CONTROL.md`. Package
publication, tag creation, and the GitHub prerelease require separate approval
of the exact prepared manifest and are not authorized by these notes.
