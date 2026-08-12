# 04 — Prelaunch API pruning

**Status:** implemented
**Milestones:** B — disposition inventory; D — atomic public cutover
**Design dependencies:** Milestone B contract design and Milestone C vertical proof

## Current issue

The SDKs have accumulated complete but competing ways to approach the product.
TypeScript publishes root workflow symbols plus separate entry points for MCP,
profile construction, verification, inspection, diagnostics, observability,
identity, authority, approvals, profiles, lifecycle, trust, runtime, and
custody. Python exposes dozens of workflow types from `auths` and also
publishes modules for the same subsystems.

This is expressive but product-hostile. A new user cannot tell which APIs are
the supported product path, independently adoptable components, extension
contracts, diagnostic tools, or historical construction blocks.

## Components of the problem

- broad root exports make every type appear equally important;
- one concept is reachable through multiple import paths;
- application and framework responsibilities are interleaved;
- low-level authorization and gateway APIs invite manual choreography;
- broad action families obscure domain-owned effect semantics;
- TypeScript and Python expose different navigation;
- prelaunch history is preserved even though no compatibility is required.

## Product decision

Classify every current public symbol during Milestone B, but do not delete the
old surface until Milestone C proves the replacement vertical. Then land the
root facade, package topology, removed exports, installed-artifact tests, and
first four recipes as one Milestone D public cutover.

Every public symbol has exactly one owner layer and supported import path:

- `product`: normal application workflow;
- `component`: independently usable identity or verification;
- `profile`: a qualified effect-domain vertical;
- `integration`: cross-domain mechanism adapters and compositions;
- `framework`: mechanisms and builders for custom verticals;
- `testkit`: Auths-owned fixtures and conformance;
- `internal`: not exported.

Anything without a clear maintained journey becomes internal or is deleted.
Six entry points are required at Milestone D. `framework` is a seventh,
evidence-gated entry point and is omitted until at least one contract satisfies
Spec 12's two-independent-vertical extraction rule. Entry-point count is not a
target to preserve.

## Target public topology

| Purpose | TypeScript | Python |
| --- | --- | --- |
| Product workflow | `@auths-dev/sdk` | `auths` |
| Identity/authentication | `@auths-dev/sdk/identity` | `auths.identity` |
| Inert verification/receipts | `@auths-dev/sdk/verify` | `auths.verify` |
| Qualified effect verticals | `@auths-dev/sdk/profiles` | `auths.profiles` |
| Mechanism adapters/compositions | `@auths-dev/sdk/integrations` | `auths.integrations` |
| Custom vertical construction | `@auths-dev/sdk/framework` when evidence-gated | `auths.framework` when evidence-gated |
| Fixtures/conformance | `@auths-dev/sdk/testkit` | `auths.testkit` |

There is no `advanced` surface. Inspection and diagnostics are verification,
product diagnostics, or testkit functions according to purpose.

## Profile and domain disposition inventory

Milestone D cannot begin until every current TypeScript profile, Python profile,
and Rust domain package appears in a reviewed table with its owning crate/module,
semantic owner, TypeScript status, Python status, conformance evidence, and one
of these decisions:

- `qualified-public`;
- `domain-package-pending-binding`;
- `demo-owned`; or
- `delete`.

The expected initial disposition is:

| Current family/domain | Milestone D disposition | Reason |
| --- | --- | --- |
| MCP | `qualified-public` under `/profiles` | Existing maintained reference integration and shortest supported product vertical |
| generic HTTP | delete as maintained profile | Transport/request shape is not one effect domain |
| generic Git | delete as maintained profile | GitHub and Radicle own different commands, transitions, and reconciliation |
| generic deployment | delete as maintained profile | Kubernetes and other deployment systems do not share one effect state machine |
| generic supply chain | delete as maintained profile | Broad action family erases domain evidence and receipt meaning |
| generic edge | move to demo ownership or delete | Cross-company edge behavior is a showcase, not a base SDK domain contract |
| GitHub | retain domain package pending independent binding/qualification | Concrete vertical |
| Radicle | retain domain package pending independent binding/qualification | Concrete vertical |
| Stripe | retain domain package pending independent binding/qualification | Concrete vertical |
| Kubernetes | retain domain package pending independent binding/qualification | Concrete vertical |
| OpenTofu | retain domain package pending independent binding/qualification | Concrete vertical |
| PostgreSQL | retain domain package pending independent binding/qualification | Concrete vertical |
| Records | retain domain package pending independent binding/qualification | Concrete vertical |

Repository inspection may add rows, but none may be silently omitted. A
concrete domain joins `/profiles` only after its own Rust session, bindings,
recovery behavior, receipts, TypeScript/Python parity fixtures, and profile
conformance suite pass.

## Authoritative TypeScript ownership map

`@auths-dev/sdk` remains one installed package. Subpaths are not separately
installed packages and are not eagerly re-exported from the root.

| Current import or symbol | Final owner | Decision |
| --- | --- | --- |
| broad `@auths-dev/sdk` barrel | root product facade | Replace with `createAuths`, `Auths`, approval policy, result variants, receipt, and base error |
| `loadAuths` | root `createAuths` | Name the product operation rather than WASM loading |
| `AuthsClient`, `AttachedAgent` | root `Auths` | A delegated child is the same facade with narrower authority |
| `/identity` | `/identity` | Independently adoptable; must not load effect workflow code |
| `/verify`, `/inspection` | `/verify` | Effect-free proof, decision, and receipt verification/inspection |
| `/diagnostics` | root bounded diagnostics or `/testkit` differential tools | Delete purpose-overlapping subpath |
| `/mcp` | named `mcp` from `/profiles` | Initial qualified vertical |
| broad `/profiles` families | disposition inventory | Delete/move broad families; expose only qualified verticals |
| `/profile-kit` | `/framework` only after extraction evidence; otherwise private/profile-owned | Custom vertical construction is not automatically cross-domain |
| `/authority` | root inputs/results; construction projections private or evidence-gated in `/framework` | Delete separate product navigation |
| `/approvals` | root policy; mechanics in `/framework` or `/integrations` only after extraction evidence | Approval never becomes a generic effect provider |
| `/custody`, `/trust`, `/observability` | evidence-gated framework contracts; maintained mechanisms in `/integrations` | Existing names do not prove cross-domain meaning |
| `/runtime`, `/lifecycle` | private coordination plus vertical-owned sessions; only proven store/clock mechanics may enter `/framework` | Do not expose a universal effect state machine |
| `/testkit` | `/testkit` | Deterministic fixtures, mechanism conformance, and profile-owned suite entry points |

The exact TypeScript root allowlist is:

```text
runtime values:
  createAuths
  approval
  AuthsError
  ExecutionReference

type exports:
  Actor
  Auths
  AuthsConfiguration
  Authority
  ApprovalPolicy
  Completed
  Denied
  ExecutionReference
  ExecutionResult
  Indeterminate
  Receipt
  RecoveryResult
  AuthsErrorCode
  RecommendedAction
```

Profile actions and provider/handler types remain under their qualified
profile. Native commands, profile step handles, generic provider ports,
canonical projections, and lifecycle kernels are never root exports. Changing
this list requires the same prototype evidence and atomic snapshot update as
any other public-surface decision.

## Authoritative Python ownership map

`auths` remains one installed wheel. Its public modules mirror the same
purposes with Python naming and resource management.

| Current import or symbol | Final owner | Decision |
| --- | --- | --- |
| `AuthsClient`, `AttachedAgent` | root `Auths` | One async context manager; delegated children are narrower `Auths` values |
| approvals helpers/module | root `Approval`; mechanism contracts below framework/integrations | Delete `auths.approvals` |
| `auths.identity` | `auths.identity` | Independently adoptable |
| `auths.verify`, `auths.inspection`, receipt verification | `auths.verify` | One effect-free purpose |
| `auths.diagnostics` | root bounded diagnostics or `auths.testkit` | Delete overlapping public module |
| current profiles | `auths.profiles` disposition inventory | Initially expose only qualified MCP |
| `auths.profile_kit` | `auths.framework` only after extraction evidence; otherwise private/profile-owned | Custom vertical construction is not automatically cross-domain |
| authority types | root call types; private or evidence-gated construction projections | Delete separate product module |
| custody, trust, observability | evidence-gated mechanism protocols; maintained integrations | Keep out of root |
| runtime, lifecycle | private coordination and vertical sessions; only proven store/clock mechanisms may enter framework | No universal provider runtime protocol |
| development bootstrap | `auths.integrations.development` | Explicit development-only composition |
| workflow/errors/native helpers | private implementation | Remove from public contract/docs |

The exact Python root allowlist is:

```text
Auths
Approval
AuthsError
Actor
Authority
Completed
Denied
ExecutionReference
ExecutionResult
Indeterminate
Receipt
RecoveryResult
AuthsErrorCode
RecommendedAction
```

Every public Python surface is a real typed module or package with explicit
`__all__`, shipped `py.typed`, mypy/pyright coverage, and installed-wheel tests.
Lazy internal loading is allowed; ambiguous public topology is not.

## Exact final import examples

```ts
import { approval, createAuths } from "@auths-dev/sdk";
import { identity } from "@auths-dev/sdk/identity";
import { inspectDecision, verify, verifyReceipt } from "@auths-dev/sdk/verify";
import { mcp } from "@auths-dev/sdk/profiles";
import { development } from "@auths-dev/sdk/integrations";
import { mcpFixtures } from "@auths-dev/sdk/testkit";
```

```python
from auths import Approval, Auths
from auths.identity import IdentityRegistry, decode_identity
from auths.verify import inspect_decision, verify, verify_receipt
from auths.profiles import mcp
from auths.integrations import development
from auths.testkit import mcp_fixtures
```

After framework passes the extraction gate, its additional imports are:

```ts
import { defineProfile, type AtomicStore } from "@auths-dev/sdk/framework";
import { certifyAtomicStore } from "@auths-dev/sdk/testkit";
```

```python
from auths.framework import AtomicStore, define_profile
from auths.testkit import certify_atomic_store
```

## Dependency direction

`framework` must not import the root product facade. Shared call/result and
bounded projection types live in a lower private contract module consumed by
root, framework, profiles, and bindings. Framework exposes cross-domain
mechanisms and custom-vertical construction only; it does not define a generic
effect provider, credential timing policy, result canonicalizer, reconciler,
or domain transition model.

## Implementation steps

- [x] Generate the symbol classification from Spec 01 and review every export.
- [x] Complete the profile/domain disposition inventory with evidence.
- [x] Prove the replacement MCP vertical and development composition in
  Milestone C before deleting any current public path.
- [x] Land the root facade, six required purpose-labelled surfaces, the lower
  private contract module, and framework only if evidence-gated in one cutover
  PR.
- [x] Generate and verify the exact TypeScript/Python root allowlists above;
  reject undeclared root symbols in installed artifacts.
- [x] Remove broad generic profiles and keep concrete domain packages private
  to their current owners until individually qualified.
- [x] Delete superseded files, exports, tests, docs, and fixtures in that PR.
- [x] Update manifests, `__all__`, declarations/stubs, `py.typed`, API snapshots,
  capability metadata, recipes, and semantic identities atomically.
- [x] Add negative installed-package and installed-wheel tests for every
  removed path.
- [x] Prove identity-only and verify-only imports do not load workflow/profile
  execution code.

## Clean-break rules

- No deprecated exports, alias modules, runtime warnings, forwarding modules,
  `oldName = newName` assignments, or migration docs.
- No tests assert old and new imports both work.
- No dual receipt, command, error, configuration, or provider shapes.
- Git history is the migration record until launch.

## Acceptance criteria

- Every public symbol and current profile/domain has one recorded disposition.
- Root imports contain no framework port or effect-capable handle.
- TypeScript exports and Python modules match the six required roots plus the
  evidence-gated framework root and parity fixtures.
- Root values/types match the exact language allowlists with no broad barrel
  leakage.
- Removed imports fail in clean packed/wheel consumers.
- MCP is the only initially promised `/profiles` vertical unless another
  concrete domain independently passes the full qualification gate.
- Framework dependency direction is mechanically enforced.
- Public API snapshots and the SDK experience summary pass without unexplained
  exceptions.

## Non-goals

- Removing independently useful identity, authentication, verification, or
  transport components.
- Making every Rust crate a language entry point.
- Preserving source compatibility with a prelaunch SDK revision.
