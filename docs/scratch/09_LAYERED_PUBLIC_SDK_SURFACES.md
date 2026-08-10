# Expose layered public SDK surfaces

Status: scratch design note

## Goal

Make the public adoption path reflect the internal architecture. A team should be able to start with data transport or identity, then add authentication, authority, approvals, and enforcement only when needed.

## Problem

The main Rust and TypeScript SDK experiences remain authority-first. `auths-sdk` depends on runtime, custody, profiles, raw-key, signature, registries, and verifier packages. The TypeScript root exports workflow and approval concepts together and does not expose the new neutral identity surface.

The internal graph is layered, but the customer-facing coordinate still looks like a single stack.

## Target adoption ladder

```text
Level 0  bounded data transport
Level 1  identity descriptors and exchange
Level 2  authenticated messages
Level 3  delegated authority and capabilities
Level 4  review and approvals
Level 5  profile enforcement, receipts, lifecycle, governance
```

Each level may depend on lower levels. Lower levels must never depend on higher levels.

## Public surface direction

Rust may expose small crates directly and a convenience facade with opt-in features. TypeScript and other bindings should expose matching subpath entry points, for example:

- `@auths-dev/sdk/identity`
- `@auths-dev/sdk/authority`
- `@auths-dev/sdk/approvals`
- `@auths-dev/sdk/profiles`

Exact packaging can differ by language, but importing identity must not initialize or expose approval and capability workflows by default.

## Design requirements

1. Every public entry point documents what it does not initialize.
2. Identity entry points contain no grants, capabilities, approvals, policy, or lifecycle APIs.
3. Concrete adapters are opt-in.
4. Convenience bundles compose stable lower-level packages rather than redefine semantics.
5. Package and bundle tests prove unused layers are absent.
6. Examples begin at the smallest level that solves the example's problem.
7. The full authority SDK remains available for teams that want the integrated product.

## Migration

1. Declare the supported adoption ladder in product documentation.
2. Promote identity and byte transport to supported public coordinates.
3. Add language-binding entry points backed by native canonical semantics.
4. Make concrete suites and methods explicit imports or features.
5. Retain the existing SDK as a compatibility bundle.
6. Add installation-size and dependency-surface checks for each level.

## Acceptance criteria

- A new user can install and exchange identity without seeing capability or approval types.
- A user can add authority without changing their identity representation.
- Public Rust, TypeScript, Python, and WASM surfaces describe the same semantic layers.
- API snapshots protect every supported entry point independently.
- Documentation never presents the full stack as the minimum adoption unit.
