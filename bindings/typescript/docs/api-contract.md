# TypeScript public API contract

## Product boundary

`@auths-dev/sdk` is one package with seven purpose-labelled entry points. The
root is the closed product workflow; the other paths are imported only when an
application needs their purpose.

```text
@auths-dev/sdk               protected workflow
@auths-dev/sdk/identity      standalone identity and authentication
@auths-dev/sdk/verify        deterministic effect-free verification
@auths-dev/sdk/profiles      qualified effect domains
@auths-dev/sdk/integrations  maintained compositions and adapters
@auths-dev/sdk/framework     proven mechanism contracts
@auths-dev/sdk/testkit       fixtures and conformance
```

There is no `advanced` path and no public path for authority construction,
trust compilation, lifecycle transitions, raw workflow coordination,
diagnostics, inspection, custody, runtime kernels or approval sessions.

## Root workflow

The root owns five verbs:

```text
create -> delegate -> execute -> resume -> verify
```

`createAuths` accepts a parsed configuration and returns an `Auths` resource.
`Auths.execute` accepts a qualified profile action/provider pair and returns an
exhaustive completed, denied or indeterminate result. Only an indeterminate
result can carry an `ExecutionReference`, and only `resume` consumes it.

Root exports are intentionally exact. They contain the factory, approval
policy builder, product resource/results, receipts and stable product error.
They contain no native command, profile step, signer, store, gateway, trust
compiler or canonical projection.

## Identity

The identity path decodes and authenticates method- and suite-labelled public
identity data. Its dependency closure excludes effect profiles and workflow
coordination. Identity transport proves delivery only; it never grants
authority.

## Verify

The verify path owns local proof, decision and receipt verification and safe
inspection. Every operation is deterministic and effect-free. It exposes no
opaque execution command and cannot invoke a provider.

## Profiles

Profiles are concrete effect-domain contracts. MCP version 1 is the only
initially qualified public profile. Each profile owns its actions, authority
projection, provider session, outcome classification, recovery and receipt
meaning. Generic HTTP, Git, deployment, supply-chain and edge categories are
not public profiles.

## Integrations

Integrations compose maintained mechanisms. `development` supplies ephemeral
local custody, local trust, no approval and in-memory state. Its diagnostics
explicitly say that it is not production durable. `production` rejects
development capabilities.

## Framework

Framework contracts are evidence-gated. The initial framework contains only
signer/custody and atomic reservation contracts proven across independent
consumers. It does not define a generic effect provider, result,
reconciliation or transition model.

## Testkit

The testkit owns deterministic fixtures, differential verification and
Auths-owned conformance suites. Passing a mechanism suite proves the named
contract only; it does not qualify an effect-domain profile or production
composition.

## Resources and failures

Every resource-owning object supports explicit `close()` and
`Symbol.asyncDispose`. Close is idempotent. Cancellation and ambiguous remote
outcomes fail closed and return a bounded recovery reference when recovery is
possible. Stable `AuthsError` values carry stage, retry, effect and remediation
classification without secrets or raw protocol bytes.

## Artifact contract

The npm export map is the public topology. Declarations, packaged WASM,
runtime-contract metadata and semantic identities ship together. Packed
consumer tests import all supported paths, reject every removed prelaunch
path, compile maintained recipes, and prove that identity/verify do not load
effect workflow code.
