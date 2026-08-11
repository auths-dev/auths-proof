# Support and compatibility matrix

The exact package contract is `sdk-compatibility.json`. CI rejects a package,
WASM, subpath, profile, or ABI mismatch before publication.

| Surface | Supported repository-local target |
| --- | --- |
| Node.js | 20 and 22; ESM; macOS, Linux, Windows |
| Browser | Current Playwright Chromium with native WebAssembly and Web Crypto |
| Workers | Standards-based ESM workers with `fetch`, WebAssembly, Web Crypto, and `AbortSignal` |
| Bundling | Direct ESM package exports; no deep imports or CommonJS contract |
| Identity ABI | 1 |
| Authoring ABI | 1 |
| Profiles | MCP, HTTP, Git, deployment, supply-chain, and edge version 1 |

The package has no mandatory account, cloud call, daemon, vendor adapter, key
store, approval service, resolver, telemetry exporter, database, or transport.
An adapter’s support claim belongs to that adapter and its conformance report.

SemVer applies to installed exports, declarations, behavior, compatibility
metadata, and profile versions. Deprecations require a migration guide and at
least one minor-version window. Identity methods, signature suites, profiles,
and provider contracts have independent versions; the SDK never silently
falls back to a nearby identifier or version.

Stable V1, publication, production, and independently reviewed claims remain
blocked until the exact release artifact passes the repository’s external
evidence gates.
