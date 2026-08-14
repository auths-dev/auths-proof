# Epic 1 — Freeze the Open Production Contract

**Parent:** [AP-SPEC-038](../0038-production-runtime-custody-observability-and-assurance.md)

**Depends on:** AP-SPEC-026, AP-SPEC-032, AP-SPEC-033, `AGENTS.md`,
`architecture.toml`, `compliance.toml`, and
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`

**Blocks:** Epics 2–9

## Outcome

Create one machine-readable contract for the first open production candidate.
It freezes what “production-ready” means before implementation begins: exact
profiles, topology, storage and custody families, supported SDKs, limits,
operational objectives, evidence, exclusions, and release subjects.

This epic does not build infrastructure. It prevents later epics from drifting
into an unbounded platform project or quietly moving essential safety features
behind AP-SPEC-039.

## Zero-context starting point

Read these files completely before editing:

- `AGENTS.md`;
- `docs/specs/0038-production-runtime-custody-observability-and-assurance.md`;
- `docs/specs/0039-enterprise-coordination-and-operations-plane.md`;
- `docs/specs/0026-reservation-and-execution-state-semantics.md`;
- `docs/specs/0032-reproducible-release-candidate-and-exact-assurance-claim.md`;
- `docs/specs/0033-independent-review-and-remediation-gate.md`;
- `docs/plans/simplify/README.md`;
- `product/config/auths-config/src/lib.rs`;
- `release/semantic-freeze.json` and `release/release-subjects.toml`; and
- `xtask/src/main.rs`, `xtask/src/semantic_freeze.rs`, and
  `xtask/src/release_control.rs`.

Current facts:

- `AuthsConfig` already parses strict TOML with `deny_unknown_fields` and
  compiles a configuration commitment.
- Release subjects and semantic-freeze inventory already gate public claims.
- No production-candidate manifest currently binds runtime topology, custody,
  profile verticals, SDK artifacts, fault evidence, and operational objectives
  into one typed document.

## Product constraint

The contract must support a Stripe-quality developer experience:

- one normal product waist: `create`, `delegate`, `execute`, `resume`, `verify`;
- one obvious production composition rather than a bag of ports;
- a useful configuration error naming the invalid field and safe next action;
- safe defaults for every non-secret value;
- secrets referenced by environment/secret-store name, never embedded;
- advanced topology and limits available through progressive disclosure; and
- a generated human summary suitable for an operator and design partner.

The production manifest is not presented in the first quickstart. It is
created by `auths doctor`/deployment tooling when a team moves from the
development composition to production.

## Architecture

```text
operator TOML
     |
     | strict parse, no unknown fields
     v
+---------------------------+
| auths-config              |
| ProductionCandidateInput  |
| -> ProductionCandidate    |
+-------------+-------------+
              |
              | canonical projection + SHA-256 commitment
              v
+---------------------------+       +--------------------------+
| candidate manifest JSON   |------>| xtask production-contract|
| no credentials/secrets    |       | release/evidence checks  |
+-------------+-------------+       +--------------------------+
              |
              v
      bounded operator summary
```

`auths-config` owns parsing and closed types. `xtask` owns repository and
release-subject validation. Do not put deployment I/O into `auths-config`.

## UX

Add a bounded diagnostic projection with these sections:

```text
Auths production candidate
  release:          1.0.0-rc.N / <commit>
  topology:         customer-operated / 3 runtime instances
  lifecycle store:  PostgreSQL / TLS required / schema v1
  custody:          aws-kms-v1, pkcs11-v1
  profiles:         opentofu-apply, postgresql-update, github-publication
  SDKs:             Rust, TypeScript, Python
  evidence:         9 required bundles / 0 complete
  exclusions:       hosted control plane, generic executor, compliance claim
```

The summary contains no database URL, key identifier, tenant identifier,
provider resource, proof, action, receipt bytes, or arbitrary label.

## APIs and types

Extend `auths-config` with closed input and compiled types. Names may change
only if an existing repository naming rule requires it; the semantic shape is
fixed.

```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductionCandidateInput {
    release: ReleaseCandidateInput,
    topology: ProductionTopologyInput,
    lifecycle_store: LifecycleStoreInput,
    custody: Vec<CustodyAdapterInput>,
    profiles: Vec<ProductionProfileInput>,
    sdks: SdkMatrixInput,
    operations: OperationsObjectivesInput,
    evidence: EvidenceRequirementsInput,
    exclusions: Vec<ProductionExclusion>,
}

pub struct ProductionCandidate {
    // All fields closed and validated; no public field mutation.
}

impl ProductionCandidateInput {
    pub fn parse_toml(input: &str) -> Result<Self, ProductionConfigError>;
    pub fn compile(self) -> Result<ProductionCandidate, ProductionConfigError>;
}

impl ProductionCandidate {
    pub fn commitment(&self) -> Digest;
    pub fn canonical_manifest(&self) -> Result<Vec<u8>, ProductionConfigError>;
    pub fn summary(&self) -> ProductionCandidateSummary;
}
```

Required closed values:

- topology class: `customer-operated` only in V1;
- runtime instances: integer `3..=32`;
- lifecycle store family: `postgresql-v1` only;
- TLS: required; plaintext cannot be represented by a compiled production
  candidate;
- custody families: exact adapter semantic IDs, not provider display strings;
- profile entries: profile ID/version, domain package, provider-contract ID,
  receipt schema, and fixture suite;
- SDK entries: Rust crate/version, npm package/version, Python wheel/version,
  native/WASM ABI, and public API snapshot digest;
- objectives: bounded integer latency/availability/recovery targets and load
  envelope, explicitly labelled as qualification objectives rather than an SLA;
- evidence requirements: fixed enum values defined by AP-SPEC-038; and
- exclusions: a closed enum containing at least hosted control plane, generic
  executor, arbitrary provider request, regulatory compliance, and universal
  exactly-once.

Do not place connection strings, environment values, private endpoints, KMS
key identifiers, credentials, customer identifiers, or provider resources in
the canonical manifest. Bind deployment-secret *slots* by stable name and
adapter family; resolve their values only at process startup.

## Files to add or change

- `product/config/auths-config/src/production.rs`: input types, compiled types,
  validation, canonical projection, summary projection, and tests.
- `product/config/auths-config/src/lib.rs`: private module plus deliberate
  re-exports.
- `product/spec/v1/open-production-candidate.schema.json`: generated JSON
  schema for the canonical manifest, not a second hand-maintained source.
- `release/open-production-candidate.toml`: first repository candidate input.
- `release/open-production-candidate.json`: generated canonical projection.
- `xtask/src/production_contract.rs`: manifest generation/check and cross-file
  release validation.
- `xtask/src/main.rs`: `cargo xtask production-contract [--update]`.
- `release/semantic-freeze.json`: add the new semantic subject intentionally.
- `release/release-subjects.toml`: bind the candidate manifest and schema.
- `architecture.toml` and `compliance.toml`: update only if package inventory
  or declared surfaces changed.

Generated files are updated only with the explicit `--update` command. Normal
CI runs check for drift and print the exact reproduction command.

## Implementation steps

- [ ] Add bounded identifiers and collection limits before deserializing
  arbitrary maps or free-form objects.
- [ ] Parse TOML into input types with `deny_unknown_fields` at every object.
- [ ] Compile once into private-field types so invalid topology, plaintext
  PostgreSQL, missing SDK parity, duplicate profiles, and unknown evidence
  requirements are unrepresentable.
- [ ] Produce canonical JSON from the compiled value, not from raw TOML.
- [ ] Domain-separate the commitment with
  `AUTHS-OPEN-PRODUCTION-CANDIDATE\0\1`.
- [ ] Generate the schema from the Rust source or validate a checked-in schema
  against exhaustive Rust fixtures; do not maintain two divergent validators.
- [ ] Add `xtask` checks for release version/commit, SDK versions, ABI files,
  profile packages, fixture directories, receipt schemas, and release subjects.
- [ ] Add the bounded human summary and prove prohibited strings cannot appear.
- [ ] Register the semantic identity and update freeze data once, after review.
- [ ] Update AP-SPEC-038 checklist state only when CI checks the artifacts.

## Adversarial tests

Tests must reject:

- unknown fields at every nesting level;
- duplicate profile, SDK, custody, evidence, and exclusion entries;
- fewer than three or more than 32 instances;
- plaintext or optional TLS;
- missing TypeScript/Python parity;
- empty or oversized identifiers and collections;
- an unregistered profile or provider-contract identity;
- a manifest naming files or release subjects that do not exist;
- embedded URI credentials, PEM, secret-like values, or raw key material;
- stale generated JSON/schema/release digest; and
- a later commit inheriting an earlier immutable candidate claim.

Add property tests asserting parse/compile/canonicalize determinism and that two
semantically different candidates never share the same canonical bytes in the
generated corpus.

## Validation commands

Run the narrow checks while iterating:

```text
cargo test -p auths-config
cargo test -p xtask production_contract
cargo xtask production-contract
cargo xtask semantic-freeze
```

Before completion run:

```text
cargo xtask arch
cargo xtask compliance
cargo xtask package
cargo xtask release-contract
```

Use `--update` only for intentional reviewed changes, then rerun the check
without `--update`.

## Exit gate

This epic is complete when a clean checkout can regenerate and verify one
canonical candidate manifest, its digest appears in release subjects, all
referenced packages and evidence requirements resolve, secret scanning passes,
and the generated summary lets an unfamiliar operator state exactly what is
and is not being claimed.
