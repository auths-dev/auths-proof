# TypeScript SDK architecture

```text
application
    |
    v
public barrels -> workflow + profile facade -> package-private coordination
                                               |
                                               v
                                      packaged Rust/WASM semantics
                                               |
                                               v
                                  authorized sealed profile command
                                               |
                                               v
                                      closed profile gateway
```

The public root exports workflow types, portable results, typed policy and
commitment builders, bounded plans, and inspection. Profile packages export
their own action, command, and gateway vocabulary. The testkit is a separate,
explicitly non-production export.

The Rust/WASM subject owns canonical protocol objects, signing preimages,
attenuation, proof assembly, trusted-context validation, and authorization.
TypeScript owns immutable copying, provider calls, deterministic disposal,
typed failures, and idiomatic composition.

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
