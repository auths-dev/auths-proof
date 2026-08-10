# Split the generic kernel from profile-specific runtimes

Status: scratch design note

## Goal

Make the pure verification kernel usable without pulling in MCP, proof-exchange services, receipts, replay stores, or product orchestration. Profile runtimes should compose around the kernel as optional layers.

## Problem

`AuthsKernel` is largely generic, but it lives inside `auths-runtime`, which also owns MCP-specific exchange behavior and imports MCP profile identifiers and commands.

As a result, the package boundary says “runtime” while its dependency surface says “generic kernel plus a particular product runtime.” Applications cannot select only the smaller concept.

## Target packages

```text
auths-kernel-runtime
  - immutable verifier context
  - method and suite registries
  - pure in-process verification
  - no profile implementation
  - no exchange service

auths-execution-runtime
  - replay and budget leases
  - receipt and event ports
  - generic profile hooks

auths-mcp-runtime
  - MCP profile
  - MCP exchange service
  - MCP command decoding
```

Names are provisional; the ownership split is the important part.

## Design requirements

1. The lowest runtime package depends only on protocol model, verifier, registries, and extension ports.
2. Generic runtime code contains no MCP profile IDs or MCP command types.
3. Profile runtimes depend inward on the generic kernel.
4. Replay, budget, receipts, and events are independently selectable effects.
5. No package-level split weakens the verified-action sealing boundary.
6. Existing end-to-end semantics and receipt vectors remain byte-identical unless deliberately versioned.
7. A minimal embedded verifier has a visibly small dependency tree.

## Migration

1. Inventory generic versus MCP-specific symbols in `auths-runtime`.
2. Extract `AuthsKernel` and its immutable registry construction.
3. Move MCP exchange/service code into a profile-specific runtime.
4. Keep compatibility re-exports temporarily through `auths-runtime` or `auths-sdk`.
5. Add architecture rules preventing profile dependencies in the generic kernel.
6. Add dependency-tree snapshots for minimal and full runtime compositions.

## Acceptance criteria

- The generic kernel manifest has no `auths-profile-mcp` dependency.
- An application can verify one canonical action without compiling exchange or receipt packages.
- MCP behavior and security tests remain unchanged.
- Adding another profile runtime does not modify the generic kernel.
- Architecture CI rejects profile-specific imports in the kernel package.
