# 09 — Development composition and production references

**Status:** Phase A and recoverable development implemented; production references evidence-gated  
**Milestones:** C — Phase A development composition; F — Phase B production references  
**Design dependencies:** Phase A uses [05](05_PRIMARY_PRODUCT_WAIST.md), [07](07_CLOSED_EXECUTION_ORCHESTRATION.md), and the error registry in [08](08_ERRORS_RECOVERY_AND_DIAGNOSTICS.md); Phase B follows [12](12_ADAPTER_CONFORMANCE_KIT.md)

## Current issue

Safe first use currently requires too many choices, while production users
need explicit durable components. Combining those needs into one generic
configuration creates either a hostile quickstart or a demo stack that looks
production-safe. Requiring a complete OIDC/KMS/database/telemetry suite before
the public API cutover would also delay simplification and distort its design.

## Components of the problem

- development actor, signer, authority, trust, state, approval, receipts, and
  clock can all require setup;
- implicit defaults would hide security and durability limits;
- one generic options bag can create partially valid mode combinations;
- production mechanisms need independent contracts and operational evidence;
- effect-domain behavior belongs to profiles, not a universal reference stack;
- Auths does not intend to own every identity provider, KMS, database,
  telemetry backend, transport, or effect-provider adapter.

## Product decision

Split the work into two independently shippable phases.

Phase A is a required simplification primitive: one explicit development
composition used by the Milestone C vertical proof and first-effect recipes.
Phase B is a later ecosystem program: production-shaped reference mechanisms
and profile-specific provider integrations added only after their conformance
contracts exist.

Phase B does not block Milestone D.

## Phase A — Explicit development composition

Purpose: make one protected local effect possible without asking users to
design infrastructure.

```ts
import { development } from "@auths-dev/sdk/integrations";
import { mcp } from "@auths-dev/sdk/profiles";

await using auths = await development.createAuths({
  authority: mcp.allowTools(["publish_report"]),
});
const result = await auths.execute({ action, provider });
```

```python
from auths.integrations import development
from auths.profiles import mcp

async with development.create_auths(
    authority=mcp.allow_tools(["publish_report"]),
) as auths:
    result = await auths.execute(action=action, provider=provider)
```

The factory supplies:

- deterministic local identity and actor metadata;
- ephemeral local signer;
- local trust configuration;
- atomic in-memory execution state;
- no-approval policy;
- deterministic/bounded clock and receipt sink; and
- bounded diagnostics that identify every development-only component.

The caller supplies a visibly bounded profile authority, profile action, and
matching profile-owned development provider, plus an optional application
request ID outside the introductory recipe. The provider still runs through
the real Rust-owned profile session; it is not a shortcut around authorization,
reservation, transition, or receipt semantics.

Development values carry a native mode identity that production composition
rejects. There is no mutable `isProduction` boolean, generic options bag, or
way to promote the same ephemeral object by changing a flag.

### Phase A steps

- [x] Define separate parsed development composition types in Rust, TypeScript,
  and Python that require profile-owned bounded authority.
- [x] Build explicit development factories with equivalent semantic fixtures.
- [x] Route the development provider through the real MCP profile session.
- [x] Emit bounded diagnostics naming ephemeral signer, memory state,
  development authority/trust, and non-production receipt storage.
- [x] Make production constructors reject development-mode capabilities.
- [x] Add deterministic concurrent reservation/replay tests.
- [x] Use Phase A in the first-effect and delegation recipe prototypes; make
  the first-effect break-it case exceed the declared authority and assert zero
  handler calls.

### Phase A acceptance

- One development effect requires only bounded authority, its action, and its
  matching provider; the application coordinates no security transition.
- Development and explicit composition produce identical authorization,
  transition, error, and receipt semantics for the same Rust fixtures.
- The path performs real reservation before provider entry.
- Diagnostics make every absent production property visible.
- No development object can satisfy a production composition type/capability.
- TypeScript and Python installed artifacts expose equivalent behavior.

## Milestone E — Recoverable development composition

Recipe 5 requires recovery across a real process restart, but production
database references do not arrive until Milestone F. Add a second explicit
development factory rather than weakening the in-memory quickstart or pulling
production integrations earlier:

```ts
await using auths = await development.createRecoverableAuths({
  directory,
  authority,
});
```

```python
async with development.create_recoverable_auths(
    directory=directory,
    authority=authority,
) as auths:
    ...
```

This factory uses a file-backed, single-machine atomic development store. It is
unmistakably non-production and is rejected by production composition. It
must provide:

- an explicit caller-owned directory with no ambient home-directory default;
- bounded versioned records and commitment-authenticated execution references;
- atomic compare-and-swap, process locking, durable flush/rename semantics,
  crash/reopen tests, and deterministic corruption errors on supported local
  filesystems;
- no multi-host, network-filesystem, availability, backup, or disaster-recovery
  claim;
- bounded cleanup tooling that never deletes a directory it did not create;
  and
- equivalent restart/resume/reconcile fixtures in Node and Python.

The Recipe 5 scenario must stop the first process after provider entry, start a
new process with the same explicit directory, resume the opaque reference, and
reconcile without a second provider effect. Cross-language receipt verification
remains required; cross-language mutation of the same development state store
is not required unless separately specified.

### Recoverable development steps

- [x] Define a separate parsed recoverable-development configuration and mode
  identity; do not add a durability boolean to the in-memory factory.
- [x] Implement file-backed atomic adapters with equivalent observable
  semantics and crash points in TypeScript and Python.
- [x] Bind resume to the stored profile/commitment and reject copied, corrupted,
  wrong-directory, or wrong-semantic-subject references.
- [x] Add restart tests that prove zero provider re-entry after an ambiguous
  effect.
- [x] Make diagnostics state every missing production durability guarantee.

### Recoverable development acceptance

- A reference produced before process exit can be resumed after restart.
- Corrupt, partial, stale, or substituted records fail closed with bounded
  stable errors.
- Concurrent processes cannot both reserve or enter the same effect.
- Recipe 5 completes before production references or Spec 12 are required.
- No documentation describes this store as production durable.

## Phase B — Production reference integrations

Purpose: show how a production system supplies durable cross-domain mechanisms
and a qualified profile's provider integration without making those choices
part of Auths core semantics.

Phase B begins after Spec 12 separates mechanism conformance from profile-owned
conformance. Candidate references, selected by user demand and maintainer
capacity, include:

- one OIDC identity/approval integration with local token verification;
- one external custody/KMS integration;
- one durable atomic execution/receipt store;
- one OpenTelemetry-compatible exporter;
- one web-service composition example; and
- one production provider integration owned by an already qualified concrete
  profile.

These are candidates, not a mandatory simultaneous bundle. Each reference has
its own threat model, supported versions, operational assumptions, credential
model, disposal behavior, conformance report, and live tests. A production
provider integration lives with its profile and runs that profile's test suite.

The current reference selection is deliberately empty. Spec 12 has not yet
admitted a production mechanism contract, so publishing one now would label an
unqualified adapter as a safe default. Current recipe demand ranks a durable
atomic store first, custody second, OIDC approval third, and telemetry fourth.
That ranking is input to Milestone F, not permission to bypass its evidence
gate.

### Phase B ownership

Auths owns:

- lower mechanism/profile contracts;
- exact configuration parsing and capability metadata;
- Auths-owned conformance cases and bounded reports;
- Rust/profile commitments and transitions; and
- one documented composition of the selected references.

Auths does not own:

- every provider in a category;
- deployment-specific IAM/network policy;
- upstream service availability or business semantics;
- third-party key recovery/onboarding policy; or
- a universal provider marketplace in the core repository.

### Phase B steps

- [x] Rank candidate integrations using actual recipe/customer demand.
- [ ] Implement a reference only after its mechanism or profile-owned
  conformance contract exists.
- [ ] Keep optional dependencies out of core imports and base install paths.
- [ ] Add deterministic contract tests and separately labelled live tests.
- [ ] Publish exact replacement guidance rather than presenting one stack as
  universally correct.
- [ ] Prove development and production compositions feed the same Rust semantic
  operations without requiring identical external behavior.

### Phase B acceptance

- Every published reference passes its owning conformance suite from packed
  npm and wheel artifacts.
- Optional references do not load or connect on root/identity/verify import.
- Credential acquisition and provider semantics remain profile-owned.
- Diagnostic output states the exact durability, custody, identity, telemetry,
  and provider guarantees supplied or absent.
- Removing a reference integration does not change the product facade or Rust
  semantic meaning.

## Non-goals

- Blocking the public simplification cutover on a full production stack.
- Presenting development defaults as production security controls.
- Owning a universal identity, KMS, database, telemetry, or provider adapter
  marketplace.
- Moving profile-specific provider behavior into cross-domain integrations.
