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

See [the API contract](api-contract.md) and [threat model](threat-model.md).
