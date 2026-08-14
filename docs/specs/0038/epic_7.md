# Epic 7 — Deliver Identical TypeScript and Python Production Workflows

Status: implementation specification

Parent: [0038](../0038-production-runtime-custody-observability-and-assurance.md)

Depends on: [Epic 1](epic_1.md), [Epic 3](epic_3.md), [Epic 5](epic_5.md), and [Epic 6](epic_6.md)

## 1. Outcome

TypeScript and Python users can run the same open production workflow with the
same five verbs, the same result states, and the same security guarantees.
Neither binding implements Auths lifecycle, commitment, authorization,
reconciliation, disclosure, or receipt meaning.

This epic is complete when both installed packages can perform the three
qualified verticals against the Rust reference runtime without a Rust toolchain,
and the shared differential suite proves that they accept and reject the same
fixtures.

## 2. Current issue

The bindings have strong native-backed verification and product facades, but
they still contain language-owned runtime and observability concepts. That
creates three risks:

- TypeScript, Python, and Rust can assign different meaning to the same state;
- a binding may accidentally turn a diagnostic or transport result into
  authority; and
- users encounter different concepts depending on which language they choose.

Production parity does not mean copying the Rust crate graph into two package
trees. It means exposing one product contract backed by Rust-owned semantics.

## 3. Product constraint

The first successful example in each language must fit on one screen and use
only `create`, `delegate`, `execute`, `resume`, and `verify`. A user must not
need to understand native handles, CBOR, WASM, PyO3, lifecycle transitions,
receipt codecs, or provider reconciliation to complete it.

Advanced users may import profiles, custody integrations, framework adapters,
and inert inspection tools from the progressive package surfaces already frozen
by the SDK product specifications. Do not create an `advanced` namespace or
publish the internal runtime graph.

## 4. UX

The same workflow should read naturally in both languages:

```text
configure Auths -> create authority -> delegate -> execute -> inspect Receipt
                                           |
                                           +-> Recoverable -> resume -> Receipt
```

TypeScript target:

```ts
import { createAuths } from "@auths-dev/sdk";
import { githubIssueAddress } from "@auths-dev/sdk/profiles";

const auths = createAuths({ endpoint, identity, profile: githubIssueAddress() });
const authority = await auths.create(request);
const delegated = await auths.delegate(authority, agent);
const result = await auths.execute(delegated, action);
```

Python target:

```python
from auths import create_auths
from auths.profiles import github_issue_address

auths = create_auths(endpoint=endpoint, identity=identity,
                     profile=github_issue_address())
authority = await auths.create(request)
delegated = await auths.delegate(authority, agent)
result = await auths.execute(delegated, action)
```

Both examples must return the same finite result variants. Errors must name the
failed product step, give a stable machine code, say whether retry is safe, and
identify the recovery reference when one exists. Raw provider errors and secret
material must not cross the SDK boundary.

## 5. Architecture

```text
TypeScript SDK --\
                  >-- versioned client contract --> Rust runtime --> profile gateway
Python SDK -----/             |                         |
                              +-- inert projections ----+-- signed receipts
```

The production path is a versioned client contract to the Rust runtime. The
native TypeScript/WASM and Python/PyO3 modules remain responsible for local,
effect-free parsing and verification where that improves latency and offline
use. They must not independently implement the effect-capable state machine.

The boundary has four layers:

1. Rust defines canonical requests, result variants, errors, projections, and
   wire encoding.
2. WASM and PyO3 expose generated or mechanically mirrored native bindings for
   local inert operations.
3. A small language-native transport client sends bounded bytes to the Rust
   runtime and parses its versioned envelope.
4. The public SDK facade converts those parsed types into idiomatic names
   without changing their meaning.

## 6. Public APIs

Keep the public package topology frozen by the simplification plan:

| Capability | TypeScript | Python |
| --- | --- | --- |
| Product facade | `@auths-dev/sdk` | `auths` |
| Identity | `@auths-dev/sdk/identity` | `auths.identity` |
| Verification | `@auths-dev/sdk/verify` | `auths.verify` |
| Closed profiles | `@auths-dev/sdk/profiles` | `auths.profiles` |
| Maintained integrations | `@auths-dev/sdk/integrations` | `auths.integrations` |
| Framework ports | `@auths-dev/sdk/framework` | `auths.framework` |
| Deterministic fixtures | `@auths-dev/sdk/testkit` | `auths.testkit` |

The root facade owns these operations:

```text
create(input) -> Authority | Denied | Indeterminate
delegate(authority, subject, attenuation) -> Authority | Denied
execute(authority, action) -> Completed | Denied | Indeterminate | Recoverable
resume(recovery_reference) -> Completed | Denied | Indeterminate | Recoverable
verify(receipt_or_authority) -> Verified | Rejected | Indeterminate
```

The exact discriminant values, retry classification, recovery behavior, and
receipt projections are Rust-owned. TypeScript uses discriminated unions;
Python uses frozen dataclasses or enums plus exhaustive type narrowing. Do not
represent a result as an untyped dictionary or free-form exception string.

## 7. Versioned client contract

Add one bounded protocol owned by Rust:

- request and response envelopes carry `contractVersion`;
- request bodies are canonical binary values, not arbitrary JSON policy;
- endpoint paths are explicit per product verb and qualified profile;
- every response has a finite outcome kind and stable error code;
- recovery references are opaque bounded strings;
- response size is capped before allocation;
- identity and receipt disclosure use the Rust-owned views from the receipt and
  inspection crates; and
- content type, timeout, redirect, and TLS behavior fail closed.

The public endpoints are:

```text
POST /v1/authority/create
POST /v1/authority/delegate
POST /v1/profiles/opentofu/saved-plan-apply/execute
POST /v1/profiles/postgresql/bounded-update/execute
POST /v1/profiles/github/issue-address/execute
POST /v1/workflows/resume
GET  /v1/workflows/{opaque-reference}
```

There is deliberately no `POST /execute/{profile}` endpoint accepting an
arbitrary operation name and JSON payload.

## 8. Implementation steps

### 8.1 Rust contract

1. Define the versioned client envelopes beside the coordinator from Epic 3.
2. Use domain newtypes for endpoints, references, profile identifiers, request
   bytes, and result variants.
3. Parse the complete envelope once at the boundary; pass typed values inward.
4. Generate canonical positive and negative vectors from Rust.
5. Bind inert parsing, verification, and projection operations through WASM and
   PyO3.
6. Add the contract version and generated vector digests to release-control and
   semantic-freeze inputs.

### 8.2 TypeScript

1. Add the production client beneath the existing root facade.
2. Use `fetch` through a narrow injectable transport port with enforced size,
   timeout, redirect, and content-type rules.
3. Replace language-owned lifecycle and operational schemas in
   `bindings/typescript/src/runtime.ts` and
   `bindings/typescript/src/observability.ts` with native/client projections.
4. Delete superseded state-machine code; do not retain compatibility exports.
5. Add the three qualified profiles to the closed `profiles` surface.
6. Regenerate package exports and the public API snapshot.
7. Test the packed tarball on the supported Node versions and Chromium without
   Cargo, rustup, or workspace-relative imports.

### 8.3 Python

1. Add the production client beneath the existing root facade.
2. Use one narrow async HTTP transport port with the same enforced bounds.
3. Replace language-owned lifecycle and operational schemas in
   `bindings/python/python/auths/_runtime.py` and `_observability.py` with
   native/client projections.
4. Delete superseded state-machine code; do not retain shims or deprecations.
5. Add the three qualified profiles to `auths.profiles`.
6. Regenerate native stubs and the public API snapshot.
7. Test installed wheels for every supported CPython/OS pair without Cargo,
   rustup, or access to the repository.

### 8.4 Documentation and recipes

1. Publish one matched quickstart per language using the same scenario.
2. Publish matched denial, expiry, replay, provider-unknown, and resume recipes.
3. Add an explicit “what runs locally” and “what contacts the runtime” section.
4. Show safe summary receipts by default; put authorized full disclosure behind
   an explicit operation.
5. Keep each quickstart within the fifteen-minute protected-effect target.

## 9. Differential and adversarial fixtures

Generate a shared fixture corpus containing:

- accepted create, delegate, execute, resume, and verify cases;
- malformed and oversized envelopes;
- unknown contract versions, fields, profiles, suites, and result kinds;
- body mutation and commitment substitution;
- attenuation widening;
- expired, replayed, exhausted, and revoked authority;
- approval substitution;
- transport success with authorization denial;
- provider timeout before and after durable reservation;
- unknown provider outcome followed by reconciliation; and
- opaque, summary, authorized-full, and unauthorized disclosure views.

For every vector, Rust, TypeScript, and Python must produce the same semantic
result and stable error code. Byte equality is required where the contract says
encoding is canonical. Language-specific exception text is not compared.

## 10. Files to change

- `product/runtime/auths-runtime/` or the coordinator crate selected in Epic 3
- `bindings/wasm/auths-proof-wasm/`
- `bindings/python/`
- `bindings/typescript/`
- `bindings/customer-journey-matrix-v1.json`
- `bindings/public-topology-v1.json`
- `product/spec/v1/`
- `xtask/src/`
- generated binding fixtures under the existing binding-vector target
- relevant SDK guides and installed-artifact recipes

Do not introduce a second hand-maintained schema for either binding.

## 11. Validation

Run at minimum:

```text
cargo xtask bindings
cargo xtask package
cargo xtask wire
cargo xtask semantic-freeze
cargo xtask product-conformance
```

The package jobs must explicitly prove the absence of a Rust toolchain in the
consumer environment. Add a parity job that consumes only the packed npm
artifact, the built wheels, and the public reference-runtime image.

## 12. Exit gate

- Both languages expose the same five semantic operations and finite outcomes.
- Both run all three qualified verticals against the Rust runtime.
- No effect-capable lifecycle or observability meaning remains implemented in a
  binding.
- Every shared positive and adversarial fixture agrees across all three
  languages.
- Installed packages require no Rust toolchain or repository checkout.
- A first-time user completes the matched quickstart in fifteen minutes.
- Public API snapshots contain no internal handles, codecs, or legacy surface.
