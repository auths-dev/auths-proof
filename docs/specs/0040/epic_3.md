# Epic 3 — Export Runtime, Profile, Error, and Assurance Facts

**Parent:** [AP-SPEC-040](../0040-stripe-quality-documentation-platform.md)

**Depends on:** Epic 1 and AP-SPEC-038

**Blocks:** Epics 4, 8, 9, and 11

## Outcome

Make the non-SDK product surface machine-readable from Rust-owned sources:
runtime routes, wire contracts, profiles, stable outcomes and errors, limits,
configuration, lifecycle states, receipt disclosure modes, and assurance
evidence.

The result must eliminate manually maintained endpoint inventories and profile
tables without creating a generic router, generic provider executor, or second
authorization semantics layer.

## Zero-context starting point

Read:

- `AGENTS.md`;
- `docs/specs/0040-stripe-quality-documentation-platform.md`;
- `docs/specs/0040/epic_1.md`;
- `docs/specs/0038/epic_1.md`, `epic_3.md`, `epic_4.md`, and `epic_5.md`;
- `product/runtime/auths-node/src/api.rs`, `config.rs`, and `profiles.rs`;
- `product/runtime/auths-production-client/src/lib.rs`;
- `product/runtime/auths-lifecycle/src/`;
- `product/errors/auths-errors/src/lib.rs`;
- `xtask/src/error_registry.rs`;
- `bindings/public-topology-v1.json`;
- `bounded-domains.toml`;
- `release/open-production-candidate.json`;
- `release/release-subjects.toml`; and
- `release/assurance/open-production-candidate-1/`.

Current facts:

- `auths-node` explicitly registers health, version, metrics, authority,
  profile execution, workflow, and receipt routes in Axum.
- Public production requests use a bounded CBOR content type and one Rust-owned
  product contract rather than arbitrary JSON APIs.
- Stable error, profile, lifecycle, production candidate, fixture, and
  assurance inventories already exist, but they do not expose one joined docs
  projection.
- Scraping Rust source text or maintaining a parallel website endpoint list
  would drift.

## Product constraint

The reference must explain an endpoint as a product operation, not merely an
HTTP path. Each endpoint page must show:

- what exact effect or inspection it represents;
- request and response content type and size limits;
- authorization, authentication, and transport boundaries;
- closed success, denial, indeterminate, recoverable, and unavailable
  outcomes;
- stable errors and recommended actions;
- replay/idempotency/recovery behavior;
- profile and evidence identities; and
- an executable scenario when the endpoint can cause or resume an effect.

Health and metrics endpoints are documented as operational surfaces and never
misrepresented as authorization operations.

## Architecture

Declare every public route once through a narrow registration macro or typed
builder that emits both the concrete Axum route and its metadata:

```text
documented route declaration
      |                         \
      v                          v
concrete Axum registration    RuntimeEndpointSpecV1
      |                          |
      v                          v
runtime behavior             docs contract exporter
```

The mechanism may reduce registration duplication but must not abstract
profile handlers into `execute(profile, json)`. Each OpenTofu, PostgreSQL, and
GitHub handler remains a concrete function with concrete profile semantics.

## APIs and types

Add closed metadata types in `auths-node` or the nearest existing non-circular
contract crate:

```rust
pub struct RuntimeEndpointSpecV1 {
    id: EndpointId,
    operation: OperationId,
    page: PageId,
    class: EndpointClass,
    method: HttpMethod,
    path: StaticEndpointPath,
    content: EndpointContentContract,
    outcomes: BoundedVec<OutcomeKind>,
    errors: BoundedVec<StableErrorCode>,
    profile: Option<QualifiedProfile>,
    limits: EndpointLimits,
    trust: EndpointTrustBoundary,
    scenario: Option<ScenarioId>,
}
```

Closed endpoint classes:

- `health`;
- `version`;
- `metrics`;
- `authority`;
- `profile-execution`;
- `workflow-recovery`;
- `workflow-inspection`;
- `receipt-summary`; and
- `receipt-disclosure`.

The trust boundary records facts such as “TLS required by production client,”
“body remains untrusted until native parsing,” “transport success is not
authorization,” and “full receipt requires disclosure authorization.” It does
not contain free-form claims.

Add a read-only exporter interface:

```rust
pub trait DocumentationFacts {
    fn docs_facts(&self) -> BoundedDocsFactsV1;
}
```

Prefer pure projections from existing typed registries. The trait cannot
mutate state, execute an operation, resolve secrets, call a provider, or mint
authority.

## Sources and provenance

Export:

- route facts from the route declarations used to build `Router`;
- wire/content facts from `auths-production-client` constants and types;
- limits from compiled `AuthsConfig` and bounded protocol constants;
- profiles from the qualified profile registry and public topology;
- errors and recommended actions from `auths-errors` and its generated
  registry;
- lifecycle states from the Rust lifecycle model;
- receipt disclosure modes from the Rust receipt inspection contract;
- release/runtime versions from release subjects;
- evidence identities and limitations from the assurance manifest; and
- exact source links from the release commit plus repository-relative owner
  paths.

Every exported fact includes a provenance kind and semantic subject. Do not
copy descriptive prose from README files into the facts artifact.

## Files to add or change

- `product/runtime/auths-node/src/api.rs`: single-source documented route
  declarations.
- `product/runtime/auths-node/src/docs.rs`: endpoint metadata types and bounded
  exporter.
- `product/runtime/auths-production-client`: wire/content contract projection.
- `product/runtime/auths-lifecycle`: lifecycle documentation projection only
  if existing closed enums cannot be inspected without widening mutation.
- `product/errors/auths-errors`: stable read-only error projection.
- maintained profile registries: stable read-only profile projections.
- `xtask/src/docs_contract.rs`: join the exported facts into the Epic 1
  artifact.
- `product/spec/v1/auths-docs-contract.schema.json` and generated contract.
- semantic freeze and release subjects for intentional new facts.

No website package or JavaScript runtime enters the Rust dependency graph.

## Implementation steps

- [ ] Define bounded paths, methods, classes, content types, limit fields, and
  trust-boundary flags.
- [ ] Convert the existing route registration to one single-source declaration
  mechanism without changing handlers, middleware order, paths, or responses.
- [ ] Add a compile-time or test-time uniqueness check for method/path,
  endpoint identity, operation identity, and page identity.
- [ ] Require effectful and recovery endpoints to name a real scenario.
- [ ] Require every declared error to resolve in the stable error registry.
- [ ] Require every profile to resolve in public topology, production
  candidate, and its fixture/evidence inventory.
- [ ] Export configuration defaults and limits only from compiled types.
- [ ] Export assurance claims and limitations only from the checked release
  assurance manifest.
- [ ] Join all facts into the documentation contract with source provenance.
- [ ] Add an endpoint table to the bounded human contract summary.
- [ ] Prove generation has no network, provider, credential, or state-store
  access.

## Adversarial tests

Reject or fail on:

- a public route registered without metadata;
- metadata with no registered route;
- duplicate method/path with different meanings;
- an effectful endpoint classified as health or inspection;
- a route that names an unknown operation, page, profile, error, or scenario;
- request limits that disagree with runtime middleware;
- a receipt disclosure endpoint described as publicly readable;
- a provider-unknown outcome described as retryable success or failure;
- a route inventory obtained by scraping `api.rs` text;
- mutable state, credential access, or provider calls during export;
- arbitrary labels, secrets, database URLs, key IDs, or receipt bytes in the
  artifact; and
- stale profile, error, evidence, or release-subject digests.

Snapshot tests must prove the exporter remains deterministic across hash-map
ordering. Runtime integration tests must prove the route refactor produces the
same status codes, headers, body limits, timeouts, and handler outcomes.

## Validation commands

```text
cargo test -p auths-node
cargo test -p auths-production-client
cargo test -p auths-errors
cargo xtask error-registry
cargo xtask docs-contract
cargo xtask production-contract
cargo xtask semantic-freeze
cargo xtask arch
cargo xtask compliance
```

Run the repository pre-commit configuration before committing.

## Exit gate

This epic is complete when adding a public runtime route without its exact
contract is impossible, every route/profile/error/limit/evidence fact has one
Rust-owned source and provenance identity, the docs contract regenerates
deterministically, and the refactor leaves runtime behavior byte- and
outcome-equivalent.
