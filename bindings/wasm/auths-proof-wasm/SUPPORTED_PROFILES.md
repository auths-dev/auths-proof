# WASM supported profiles

## Action profiles

This package is a **consumer** transport. It ships no generic domain parser,
no generic canonicalizer, and no reference action profile.

`bindings/public-topology-v1.json` declares the qualified profiles:

| Qualified profile | Exposed here | How |
|---|---|---|
| `auths.mcp/1` | yes | `prepareMcpActionV1`, `canonicalizeMcpPlanMemberV1`, `beginMcpExecutionV1`, `resumeMcpExecutionV1` |
| `auths.github.issue-address/1` | routed only | `encodeProductionRequestV1` / `decodeProductionResponseV1` |
| `auths.opentofu.saved-plan-apply/1` | routed only | as above |
| `auths.postgresql.bounded-update/1` | routed only | as above |

"Routed only" means this module encodes and decodes the bounded production
request and response for that profile. It does not canonicalize the profile's
action; the service that owns the vertical does.

### Removed in v1.0

The five **unqualified** reference domain profiles — `auths.http`, `auths.git`,
`auths.deploy`, `auths.supply-chain`, `auths.edge` — are no longer projected to
JavaScript. Eleven exports were deleted outright with no shim, alias, or
deprecation window: `parseHttpActionV1`, `parseGitActionV1`,
`parseDeploymentActionV1`, `parseSupplyChainActionV1`, `parseEdgeActionV1`,
their five `parseCanonical…ActionV1` counterparts, and the
`DomainActionFieldsV1` result class. See
`docs/target-state/PRELAUNCH_CODEBASE_CONSOLIDATION_SPEC.md`, phase 2 item 6.
`product-abi-v1.json` records the removal and `tests/node-smoke.cjs` fails if
any of them reappears.

### Known disagreements

1. `bindings/public-topology-v1.json` lists **four** `qualifiedProfiles`, but
   `auths_production_client::QualifiedProfile`
   (`product/runtime/auths-production-client/src/lib.rs:194-206`) has **three**
   members: `auths.mcp/1` has no production-client route. The topology list is
   a union of "profiles the product ships" and "profiles the service routes",
   and nothing reconciles the two.
2. `prepareProfileActionV1`, `canonicalizeProfilePlanMemberV1`, and
   `commitProfilePlanV1` accept an arbitrary `profileId` string from
   JavaScript. `canonical_profile_action_native`
   (`src/lib.rs:4189`) consults no Rust profile: it parses the identifier and
   accepts the supplied body as already canonical. A JavaScript caller can
   therefore name a vertical this package does not implement — the same
   structural hole the v1 contract §6.3 records for the Python
   `define_profile` surface. Closing it belongs with the TypeScript
   `defineProfile` / profile-kit deletion, because those are its only callers.

## Principal methods and signature suites

The WASM module also exposes the neutral identity Level 1/2 operations used by
`@auths-dev/sdk/identity`: structural V2 packet encode/decode, explicit raw-key
validation, external-custody signing preimages, signed-message encoding, and an
explicit Ed25519 authentication adapter. Those operations create no grant,
capability, approval, policy, or execution authority.

The prebuilt self-contained distribution exposes:

| Principal method | Configuration source | Signature suites |
|---|---|---|
| `raw-key-v1` | stateless compiled adapter | Ed25519, P-256/SHA-256 |
| `did-key-v1` | stateless compiled adapter | Ed25519, P-256/SHA-256 |
| `did-keri-v1` | compiled default limits, no external checkpoints | Ed25519, P-256/SHA-256 |

`configurationV1()` returns the exact 32-byte commitment that a trusted
context must carry. DID-web, WebAuthn, HSM-attested, and SPIFFE/X.509 require
deployment-specific trust records and are intentionally absent from this
fixed package. Such contexts fail closed with
`verifier-configuration-mismatch` or an unsupported-method requirement; the
package never substitutes another method.

## The declared ABI

Every symbol this module publishes to JavaScript is declared by exactly one
manifest, and every declaration is published. `tests/node-smoke.cjs` asserts
set equality in both directions.

| Manifest | Schema | Exports | Result types |
|---|---|---|---|
| [`identity-abi-v1.json`](identity-abi-v1.json) | `auths.identity-wasm-abi/1` | 12 | 3 |
| [`authoring-abi-v1.json`](authoring-abi-v1.json) | `auths.wasm-authoring-abi/1` | 36 | 12 |
| [`product-abi-v1.json`](product-abi-v1.json) | `auths.wasm-product-abi/1` | 20 | 2 |

The authoring boundary validates principal identifiers, plans child grants
through `auths-author`, prepares and completes exact signing envelopes without
receiving a private key, and binds one request to a canonical trusted-context
template. Canonical grant, action, and status decoders use
`VerifierLimits::default_deployment`; malformed, trailing, non-canonical, and
widening inputs fail before custody is invoked.

This is a repository-local pre-review ABI. It does not by itself promote the
TypeScript package beyond the Verifier Binding tier.

## Errors

Every failure crossing this boundary is a structured JavaScript `Error` named
`AuthsError` whose own properties are the `auths.error/1` envelope owned by
`auths_errors::ErrorEnvelope`: `schema`, `family`, `code`, `operation`,
`stage`, `summary`, `correlationId`, `retry`, `effect`, `entered`,
`recommendedAction`, and `causes`. No error is flattened to a string.

This module decides none of that meaning. It names each failure with a stable
code from `product/errors/v1/registry.json` and
`auths_errors::classify` supplies the effect state, the retry class, and the
recommended action. The three codes this boundary can name —
`core.malformed-input`, `core.invalid-configuration`,
`core.native-runtime-unavailable` — all carry effect `not-applied`, because the
module opens no connection, invokes no provider, and holds no durable state.

`classifyErrorCodeV1(code)` projects the registry's classification for any
code, including one minted by a newer Auths build: an unrecognized code is
reported with `known: false` and `effect: "possible"`, never swallowed and
never downgraded to `not-applied`.

## Reproducibility

`cargo xtask wasm` builds `wasm-bindgen` Node artifacts twice, compares every
generated JS/WASM/TypeScript byte, generates authorized verification and
authoring vectors from the checked-in raw-key corpus, and requires Node to
produce identical canonical bytes. Malformed verification arrays return
protocol result bytes; malformed authoring requests return bounded structured
errors and never produce a signing request.
