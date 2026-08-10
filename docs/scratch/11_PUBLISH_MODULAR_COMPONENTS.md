# Publish the modular components as supported products

Status: implemented on `dev-decouple`

## Goal

Turn the internal liquid architecture into something external teams can actually adopt one layer at a time.

## Problem

The key modular packages are currently marked `publish = false`:

- `auths-identity`;
- `auths-identity-raw-key`;
- `auths-signature-ed25519`;
- `auths-iroh`.

They prove the architecture inside the workspace, but outside users must depend on the repository directly or copy patterns. That prevents normal version selection, documentation discovery, compatibility management, and supply-chain review.

## Product boundary

Publishing does not mean Auths must own an adapter catalog. The supported product can be:

1. Neutral ports and canonical formats maintained by Auths.
2. One or two reference adapters proving the port.
3. A conformance kit for caller- and community-owned adapters.

The port is the product. The reference adapters are evidence that it works.

## Release prerequisites

### Neutral identity

- validated/unvalidated type-state boundary;
- frozen wire and signing semantics;
- canonical identifier policy;
- malformed-input and resource-bound tests;
- public documentation and examples.

### Reference adapters

- shared suite semantics with the proof stack;
- explicit support status;
- conformance vectors;
- security and dependency policy.

### Iroh transport

- neutral byte-transport port or clearly documented adapter ownership;
- stable bounds and timeout behavior;
- no Auths semantic claims derived from endpoint identity;
- transport conformance tests.

## Design requirements

1. Published packages have minimal dependency trees and documented MSRV/no-std status.
2. Public packages are included in API and semantic-freeze checks.
3. Each README states which security claim the package does and does not make.
4. Examples use only published APIs.
5. Package versions communicate compatibility across wire, ports, and adapters.
6. Third-party adapters have a documented conformance process without requiring inclusion in this repository.
7. The full SDK may depend on published lower layers, but lower layers never depend on it.

## Rollout

1. Publish the neutral identity port as a release candidate.
2. Publish the raw-key and Ed25519 reference adapters.
3. Publish the byte transport port and Iroh adapter when its boundary is stable.
4. Add docs.rs, package README, changelog, and compatibility tables.
5. Build one external-consumer smoke project using only registry packages.
6. Add that smoke project to release qualification.

## Acceptance criteria

- A clean external project can install only identity and implement its own method or suite.
- Another project can use Iroh without importing identity or authority packages.
- Published package documentation makes optional layering obvious.
- Release CI installs and executes examples from packed artifacts rather than workspace paths.
- Auths can add or remove reference adapters without changing the neutral port contract.

## Implementation evidence

- Seven independently adoptable packages are public release roots: the neutral
  identity and byte-channel ports, raw-key and Ed25519 reference adapters, the
  optional identity-authority bridge, and memory and Iroh transport adapters.
- Each package README records its positive and negative security claims, MSRV,
  portability, compatibility family, and published-API example.
- `docs/modular-components.md` owns the compatibility table and RC changelog;
  `docs/adapter-conformance.md` defines the external adapter process.
- Release packaging unpacks exact `.crate` archives and executes a caller-owned
  identity method and an identity-free Iroh consumer. Their resolved dependency
  graphs reject unrelated Auths packages.
- Architecture, public naming, semantic freeze, focused package tests, and the
  packed-artifact smoke pass for the implemented surface.
