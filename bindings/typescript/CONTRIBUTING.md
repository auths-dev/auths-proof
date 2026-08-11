# Contributing to the TypeScript SDK

The TypeScript package is an ergonomic wrapper around the canonical Rust/WASM
implementation. TypeScript may coordinate providers, lifetimes, profiles, and
typed results. It must not independently implement protocol encoding,
attenuation, verification, or stable verdict semantics.

## Where changes belong

- `src/verifier/` owns the portable verifier wrapper and result projection.
- `src/workflow/` owns public workflow contracts and lifecycle coordination.
- `src/profiles/` owns vertically bounded profile facades.
- `src/internal/` owns package-private coordination.
- `src/testkit/` owns unmistakably non-production helpers.
- `test/unit/` contains fast JavaScript-only tests.
- `test/contract/` contains TypeScript misuse and non-forgeability tests.
- `test/integration/` contains Rust/WASM and canonical-vector tests.
- `test/package/` contains packed external-consumer checks.

Do not add a generic operation tag, executor, credential provider, or global
receipt union. A new domain begins as a closed profile with its own command,
gateway, credential scope, transition, receipt, and tests.

## Fast feedback

```text
npm run build
npm run test:contract
npm run test:unit
```

`npm run test:integration` also rebuilds WASM and Rust-generated vectors.
`npm run test:package` packs and installs a clean consumer, while
`npm run test:browser` runs that tarball through Chromium. `npm run test:api`
rejects declaration or export drift. The authoritative repository CI remains
the final check.

## Public API

Only documented package exports are public. `src/index.ts`, `src/mcp.ts`, and
`src/profile-kit.ts` are public facade barrels and should contain no runtime
implementation. Advanced inspection must never mint an effect capability.

Every public change needs documentation, a misuse test, an external-consumer
example where applicable, and an explicit statement of the assurance claim it
does or does not affect.

After intentionally changing the supported declarations, review the complete
installed surface produced by `node tools/public-api.mjs --print` and update
`api/public-api.txt` in the same bounded change. Never update the snapshot only
to silence unexplained drift.
