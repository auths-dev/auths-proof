# TypeScript SDK architecture

```text
identity ports --------> decoded -> validated -> authenticated
                              |
typed trust + lifecycle ------+----------+
                                         v
application -> workflow + profile -> packaged Rust/WASM semantics
                                         |
                                         v
                              authorized sealed profile command
                                         |
                                         v
                              closed gateway -> optional runtime ports
```

The public root exports the integrated workflow. Identity, trust, authority,
lifecycle, profiles, runtime, custody, verification, inspection, diagnostics,
and observability are separate entry points with no implicit activation
between them. Profile packages export
their own action, command, and gateway vocabulary. The testkit is a separate,
explicitly non-production export.

The Rust/WASM subject owns canonical protocol objects, signing preimages,
attenuation, proof assembly, trusted-context validation, and authorization.
TypeScript owns immutable copying, provider calls, deterministic disposal,
typed failures, and idiomatic composition.

Every public transition narrows its input into a nominal or discriminated type.
Opaque state lives behind closure-owned or `WeakMap` resources, while Rust owns
the canonical bytes and semantic acceptance decision. Runtime ports consume
only a gateway-parsed authorized command and do not become part of the verifier.

Package-private modules may exchange resource handles through closure-owned
or `WeakMap` state. Application code must not be able to use those handles to
construct a command. Only package-owned WASM reached through `loadAuths` may
select the command-minting branch.

Workflow ownership is split by change reason:

- `workflow/contracts.ts` owns public provider and result contracts;
- `workflow/authority-source.ts` and `trusted-context.ts` own sealed sources;
- `workflow/internal/profile-runtime.ts` owns unpublished profile dispatch;
- `workflow/internal/copying.ts` owns bounded immutable projections;
- `workflow/internal/authority.ts` owns authority summaries; and
- `workflow/internal/orchestrator.ts` coordinates client and attached-agent
  lifetimes without being a published package subpath.

The public API is an explicit allowlist. `api/public-api.txt` freezes the
installed declaration closure and runtime export names; package tests install
the tarball into a clean consumer before exercising its WASM.

See [the API contract](api-contract.md) and [threat model](threat-model.md).
