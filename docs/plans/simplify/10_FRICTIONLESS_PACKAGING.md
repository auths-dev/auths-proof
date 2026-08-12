# 10 — Frictionless packaging cutover

**Status:** implemented
**Milestone:** D — Atomic public cutover
**Design dependencies:** final facade/topology design from [04](04_PRELAUNCH_API_PRUNING.md), [05](05_PRIMARY_PRODUCT_WAIST.md), and [06](06_PROGRESSIVE_PACKAGE_LAYOUT.md)

## Current issue

Auths already has substantial installed-artifact coverage. The remaining risk
is not “build packaging from scratch”; it is that the clean-break public
topology, native/WASM artifacts, declarations/stubs, runtime support, resource
disposal, and removed-path behavior can drift during the simplification
cutover.

A greenfield packaging plan would duplicate evidence and obscure the much
smaller set of real gaps.

## Existing evidence to preserve

Before implementation, verify these paths against the current revision and
record any changed names in the pull request evidence:

### Python

- `bindings/python/pyproject.toml` declares an `abi3-py39` extension and the
  supported CPython 3.9–3.14 range.
- `.github/workflows/python-sdk.yml` builds wheels for macOS, Linux, and Windows.
- Installed-wheel consumers cover CPython 3.9–3.14 and run without repository
  source.
- Wheel/API, ABI/capability, performance, and source-free consumer checks
  already exist.

### TypeScript

- `.github/workflows/typescript-sdk.yml` tests packed artifacts on Node
  20.19.6 and 22.23.1 across supported operating systems.
- Packed Chromium, public API, runtime capability, performance, and installed
  package checks already exist.
- `bindings/typescript/tsconfig.json` includes `ESNext.Disposable`, and current
  code uses `Symbol.asyncDispose`.

This spec extends those sources. It must not create a parallel support matrix
or duplicate API manifest.

## Cutover contract

There remains one npm package and one wheel. Their six required public entry
points plus evidence-gated framework entry point are the topology from Spec 06:

| Purpose | TypeScript | Python |
| --- | --- | --- |
| Root workflow | `@auths-dev/sdk` | `auths` |
| Identity | `@auths-dev/sdk/identity` | `auths.identity` |
| Verification | `@auths-dev/sdk/verify` | `auths.verify` |
| Qualified profiles | `@auths-dev/sdk/profiles` | `auths.profiles` |
| Integrations/compositions | `@auths-dev/sdk/integrations` | `auths.integrations` |
| Framework, only when extraction evidence passes | `@auths-dev/sdk/framework` | `auths.framework` |
| Testkit | `@auths-dev/sdk/testkit` | `auths.testkit` |

The root never re-exports the other six surfaces. At cutover, `profiles`
contains MCP and only any additional concrete vertical that independently
passes Spec 04 qualification.

## TypeScript deltas

### Export and artifact cutover

- replace the current export map with the exact supported subpaths;
- emit ESM JavaScript and declarations for each public entry point;
- keep private/lower contract modules unreachable through package exports;
- include the exact package-owned WASM/runtime artifacts required by each path;
- reject every removed subpath in a clean packed consumer;
- prove identity/verify imports do not initialize the root/profile runtime;
- update package-content and size snapshots rather than adding a second list.

### Runtime and disposal

Explicit resource management is ergonomic syntax, not the only correctness
path. Every resource-owning public object must support both:

```ts
await using auths = await createAuths(config);
```

and:

```ts
const auths = await createAuths(config);
try {
  await auths.execute(input);
} finally {
  await auths.close();
}
```

Tests must cover `Symbol.asyncDispose`, explicit `close`, double-close,
partial-construction failure, cancellation, worker/browser disposal, and leaked
resource detection where the runtime permits it. Do not mandate a polyfill
unless a supported target demonstrably lacks required syntax/runtime behavior;
document the exact fallback instead.

### Environment coverage gaps

- add a maintained worker/edge bundle/import smoke test if that runtime remains
  in the declared support policy;
- ensure browser/worker paths do not depend on Node globals or filesystem APIs;
- compile/type-check all recipes against only the packed tarball;
- measure WASM boundary serialization separately from business operation time.

## Python deltas

### Module and typing cutover

- make all required public roots, and framework when evidence-gated, real
  modules/packages with explicit `__all__`;
- ship `py.typed` and complete public annotations;
- run mypy and pyright against the installed wheel;
- reject all removed modules in clean consumers, including forwarders and
  `sys.modules` aliases;
- prove identity/verify imports do not initialize workflow/profile resources;
- update the existing wheel/API inventory and size budgets.

### Native and resource behavior

- preserve the declared `abi3`/CPython support only where current build and
  runtime evidence passes;
- run async-context-manager, explicit `aclose`, double-close,
  partial-construction, cancellation, and interpreter-shutdown tests;
- isolate source-free consumers by restricting `PATH`; never uninstall the
  hosted runner's Rust toolchain;
- measure PyO3 boundary serialization separately from Python-level workflow
  time.

## Bounded doctor experience

The doctor reports installed/runtime facts, not secrets or arbitrary
environment contents:

```text
$ npx --package @auths-dev/sdk auths doctor
Auths SDK        1.0.0-rc.1
Runtime          Node 22 / macOS arm64
Portable ABI     compatible
Semantic subject compatible
Profiles         mcp/1
Mode             development
State            in-memory (not production durable)
Status           ready with 1 production warning
```

Python exposes the equivalent through `python -m auths doctor`; both languages
also expose the bounded report from the root facade. It never prints keys,
credentials, signatures, proof/action bytes, command bytes, raw provider
responses, or unbounded environment variables.

## External-consumer matrix

Extend the current workflows so every supported representative platform:

- installs only the produced tarball/wheel in a fresh directory;
- restricts source and build-tool access after artifact acquisition;
- imports every public entry point and rejects every removed path;
- runs identity-only and verification-only flows;
- runs one MCP development effect, failure, resume/reconciliation, and receipt
  verification flow;
- compiles/type-checks the first four maintained recipes;
- verifies exact ABI/capability/semantic-subject agreement;
- records import/init/artifact size and boundary-performance data; and
- proves deterministic cleanup on success, failure, and cancellation.

The matrix should add jobs only for uncovered risk. Existing jobs are updated
or extended instead of copied under new names.

## Implementation steps

- [x] Capture the current passing packaging matrix and identify exact missing
  rows rather than reimplementing it.
- [x] Apply the six-required-plus-evidence-gated-framework TypeScript/Python
  cutover in the same PR as Specs 04–06.
- [x] Add removed-path rejection for every old TypeScript subpath and Python
  module.
- [x] Add import-isolation checks for root, identity, verify, profiles,
  integrations, testkit, and framework when published; otherwise assert the
  framework path is unavailable.
- [x] Add/finish bounded doctor reports derived from existing ABI/capability
  metadata.
- [x] Add explicit-close/context-manager parity and failure-path cleanup tests.
- [x] Close declared worker/edge coverage gaps or remove the unsupported target
  from the support policy.
- [x] Add WASM/PyO3 boundary metrics to the existing performance evidence.
- [x] Update public API, package/wheel contents, semantic identities, docs, and
  recipes atomically.

## Acceptance criteria

- Every supported consumer journey runs from packed artifacts with no
  repository source and no consumer Rust toolchain requirement.
- Public paths exactly match Spec 06; removed paths fail rather than warn or
  forward, and framework is absent unless its extraction evidence passes.
- Python's published surfaces are statically typed real modules.
- TypeScript resources work with both `await using` and explicit `close` on all
  declared runtimes.
- Doctor output reports MCP only at initial cutover and diagnoses ABI/semantic
  mismatch with stable bounded errors.
- Artifact, import, cleanup, size, and boundary-performance regressions fail the
  existing authoritative gates.
- The spec introduces no redundant workflow, support matrix, or API snapshot.

## Non-goals

- Supporting historical prelaunch entry points or runtimes.
- Uninstalling build tools from hosted CI machines to simulate consumers.
- Runtime download of native code from an Auths service.
- Claiming production readiness from package installation alone.
