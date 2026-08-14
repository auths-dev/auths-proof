# Epic 1 — Freeze the Documentation Surface Contract

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Depends on:** AP-SPEC-034, AP-SPEC-038, `AGENTS.md`,
`architecture.toml`, `compliance.toml`, and
`docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`

**Blocks:** Epics 2–11

## Outcome

Create one versioned, machine-readable contract that identifies every public
Auths operation and its projections into Rust, TypeScript, Python, runtime
endpoints, profiles, errors, examples, and assurance evidence.

This epic freezes identities and schemas. It does not build the website,
rewrite public prose, or generate reference pages. Its purpose is to prevent
the documentation system from joining surfaces by fragile function names,
URLs, source paths, or display labels.

## Zero-context starting point

Read these files completely before editing:

- `AGENTS.md`;
- `docs/specs/0040-stripe-quality-documentation-platform.md`;
- `docs/specs/0034-auths-public-naming-consolidation.md`;
- `docs/target-state/PROFILE_AND_DOMAIN_ABSTRACTION_BOUNDARY_PLAN.md`;
- `bindings/public-topology-v1.json`;
- `bindings/typescript/api/public-api.txt`;
- `bindings/python/api/public-api.txt`;
- `release/semantic-freeze.json`;
- `release/release-subjects.toml`;
- `release/public-naming.toml`;
- `xtask/src/semantic_freeze.rs`;
- `xtask/src/sdk_experience.rs`;
- `xtask/src/sdk_vocabulary.rs`; and
- `xtask/src/main.rs`.

Current facts:

- Semantic freeze identifies the public Rust roots, their publishable closure,
  and immutable release subjects.
- TypeScript and Python have installed-artifact public-name snapshots.
- `bindings/public-topology-v1.json` defines the supported product, vertical,
  mechanism, extension, and test entry points.
- No stable identity currently joins one product operation to its SDK symbols,
  runtime routes, guide dependencies, examples, errors, and evidence.
- The documentation repository must remain separate and must consume immutable
  artifacts rather than a mutable sibling checkout.

## Product constraint

The contract must preserve one product vocabulary across all languages while
allowing idiomatic spelling in each language. A reader should see “create
authority” once and switch between `create_authority`, `createAuthority`, and
the Rust item without landing on three unrelated reference pages.

The contract contains product facts, not marketing prose. It must be small,
deterministic, reviewable, and safe to publish. It must not contain secrets,
receipt bodies, arbitrary user data, credentials, tenant identifiers, or
mutable deployment state.

## Architecture

```text
semantic freeze + public topology + checked projection manifests
                              |
                              v
                     DocsContractInputV1
                              |
                       strict parse/compile
                              |
                              v
                      DocsContractV1
                   /          |          \
                  v           v           v
         canonical JSON   SHA-256 ID   bounded summary
```

Rust owns parsing, closed identities, canonical ordering, and validation.
`xtask` owns repository discovery, artifact existence checks, generation, and
drift detection. Website tooling must not become a dependency of a shipping
crate.

## Identities and types

Add bounded types equivalent to:

```rust
pub struct DocsContractVersion(u16);
pub struct OperationId(BoundedSemanticId);
pub struct PageId(BoundedSemanticId);
pub struct ScenarioId(BoundedSemanticId);
pub struct SymbolPath(BoundedString);

pub struct OperationDefinitionV1 {
    id: OperationId,
    status: DocumentationStatus,
    product_verb: Option<ProductVerb>,
    profiles: BoundedVec<ProfileId>,
    errors: BoundedVec<StableErrorCode>,
    scenarios: BoundedVec<ScenarioId>,
}

pub struct SdkProjectionV1 {
    operation: OperationId,
    language: SdkLanguage,
    package: PackageCoordinate,
    entrypoint: PublicEntrypoint,
    symbol: SymbolPath,
    support: ProjectionSupport,
}
```

Required identity forms:

```text
auths.operation.authority.create/1
auths.page.start.rest-api/1
auths.scenario.rest-authorize/1
```

Identities are lowercase ASCII, dot-separated, explicitly versioned, and
bounded in length. Display names and URL slugs are separate fields. A renamed
symbol or page URL does not change the semantic identity. A changed operation
meaning requires a new identity version.

`ProjectionSupport` is a closed enum:

- `supported` with one exact public symbol;
- `not-supported` with one stable reason code; or
- `not-applicable` with one stable reason code.

Absence is not a support state.

## Contract files

Add:

- `release/docs/operations.toml`: semantic operation inventory;
- `release/docs/pages.toml`: stable generated and authored page identities;
- `release/docs/scenarios.toml`: scenario identities and required language
  coverage;
- `release/docs/projections/rust.toml`;
- `release/docs/projections/typescript.toml`;
- `release/docs/projections/python.toml`;
- `product/spec/v1/auths-docs-contract.schema.json`;
- `release/auths-docs-contract-v1.json`: canonical generated snapshot;
- `xtask/src/docs_contract.rs`; and
- contract parsing types in the narrowest existing product/configuration crate
  that can own them without introducing an inward dependency. Open an
  architecture case file before creating a new crate.

The TOML inputs are small mapping authorities. They do not duplicate function
signatures, arguments, return types, docstrings, endpoint paths, or error
descriptions. Later epics extract those facts from installed artifacts and
Rust-owned registries.

## Command contract

Add:

```text
cargo xtask docs-contract
cargo xtask docs-contract --update
cargo xtask docs-contract --artifact-dir <verified-release-directory>
```

The check command validates the checked-in snapshot and prints the exact update
command on drift. `--update` is the only write path. `--artifact-dir` may add
extracted surfaces in Epic 4 but must already be reserved in the command
parser.

The canonical artifact includes:

- schema and contract versions;
- source commit slot and semantic-freeze digest;
- stable operations, pages, scenarios, and projections;
- public package and entrypoint inventory;
- empty, typed slots for routes, profiles, errors, limits, evidence, symbols,
  and provenance that later epics populate; and
- a digest over the canonical payload excluding its digest field.

## Implementation steps

- [ ] Define bounded identifiers and closed enums before parsing TOML.
- [ ] Reject unknown fields at every object and unknown enum values.
- [ ] Enforce global uniqueness for operation, page, and scenario identities.
- [ ] Enforce uniqueness of `(operation, language, package, entrypoint)`.
- [ ] Require one explicit projection state for every maintained language and
  every operation in the launch surface.
- [ ] Resolve package and entrypoint names against
  `bindings/public-topology-v1.json`.
- [ ] Resolve public Rust packages against semantic freeze.
- [ ] Verify that supported TypeScript and Python symbols appear in their
  current public API snapshots, while treating those name snapshots as
  temporary evidence rather than signature sources.
- [ ] Canonicalize maps and sets by semantic identity before encoding.
- [ ] Domain-separate the artifact digest with
  `AUTHS-DOCS-CONTRACT\0\1`.
- [ ] Generate or exhaustively validate the JSON schema from the Rust types;
  do not maintain two independent validators.
- [ ] Add the contract and schema to release subjects and semantic freeze.
- [ ] Add `docs-contract` to `cargo xtask ci` after the artifact is stable.

## Adversarial tests

Reject:

- duplicate or differently cased identities;
- unversioned, empty, oversized, or non-ASCII identities;
- a display name or URL used as an identity;
- unknown packages or entrypoints;
- a supported projection without a symbol;
- a `not-supported` projection with a symbol;
- one symbol mapped to incompatible operation meanings;
- an operation with silent TypeScript or Python absence;
- malformed canonical ordering or a stale digest;
- unknown schema versions and fields;
- path traversal or absolute paths in provenance slots; and
- contracts that embed secret-like strings, URLs with credentials, receipt
  bytes, or arbitrary examples.

Property tests must prove deterministic parse/compile/encode behavior across
input ordering and that semantically different contracts produce different
canonical bytes in the generated corpus.

## Validation commands

```text
cargo test -p xtask docs_contract
cargo xtask docs-contract
cargo xtask semantic-freeze
cargo xtask arch
cargo xtask compliance
cargo xtask release-contract
```

Run the repository pre-commit configuration before committing.

## Exit gate

This epic is complete when a clean checkout produces one deterministic,
checksummed contract with stable operation/page/scenario identities, explicit
Rust/TypeScript/Python support states, release-subject coverage, and no copied
signatures or prose. An unfamiliar consumer can use only the schema and
artifact to understand how future extracted facts will join without knowing
the repository layout.
