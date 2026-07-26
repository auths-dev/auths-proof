# General Behavior
- Always run `cargo fmt` (or the equivalent code formatter) after making code changes and before committing.
- Use `cargo xtask ci` frequently to ensure all checks pass.

# Repository Scope and Ecosystem Topology
This file governs the `auths-proof` repository only. It defines the quality bar
for the offline protocol kernel and must not be interpreted as permission to
place downstream transport, runtime, profile, or application code here.

The target ecosystem has exactly three repositories:

| Repository | Responsibility |
| --- | --- |
| `auths-proof` | Offline protocol kernel, canonical model and codec, deterministic evidence verification and ports, canonical core corpus, fuzzing, WASM verification, and pure/keyless authoring |
| `auths-proof-exchange` | Exchange protocol and every transport implementation, including memory and Iroh |
| `auths-proof-apps` | Live evidence acquisition, custody integrations, application profiles, runtime, replay and budget state, receipts, configuration, caches, reference applications, Auths Lab, and independent Go/TypeScript verifiers |

The current prelaunch `auths-proof-mcp` repository is renamed and broadened to
`auths-proof-apps`; MCP remains its first profile and reference application.
There are no users or compatibility commitments, so no migration plan is
required.

The allowed repository dependency direction is:

```text
auths-proof-exchange ---> auths-proof
auths-proof-apps     ---> auths-proof + auths-proof-exchange
auths-proof          -X-> auths-proof-exchange
auths-proof          -X-> auths-proof-apps
```

A security boundary does not imply a repository per release unit. Crates and
packages for profiles, runtime, receipts, reference applications, Auths Lab,
and independent implementations remain separated inside `auths-proof-apps`.
Enforce their boundaries with dependency direction, narrow public APIs,
fixtures, tests, and CI.

For the target-state implementation, all three repositories use the
`dev-implementation-delta` branch.

# Working with `auths-proof`
This repository contains the `auths-proof` protocol kernel, an offline verification engine for proof-carrying authorization. It is built to **stringent, pre-audit security standards**. When working on this codebase, you must adhere strictly to the following guidelines.

## 1. Core Principles & Boundary
- **Zero Networking in the Kernel**: The proof kernel is strictly an offline verification engine. It does not own key custody, live DID resolution, witness networks, or HTTP transport. If a feature cannot be evaluated deterministically from a static proof and explicit context, it belongs above the kernel.
- **Strict Separation from Downstream Repositories**: Do not add dependencies or logic owned by `auths-proof-exchange` or `auths-proof-apps`. The kernel must remain agnostic to how proofs are transmitted, acquired, resolved, stored, approved, executed, or mapped to application semantics.
- **Crate Boundaries Inside the Kernel**: Separation between model, codec, adapter API, verifier, evidence, WASM, and authoring is normally a crate boundary inside this repository, not a reason to create another repository.
- **Deterministic & Bounded**: All parsing (especially CBOR) and verification must be deterministic and bounded to prevent resource exhaustion attacks.

## 2. Dependency Management & Crates
- **Minimal Dependencies**: Do not add dependencies unless absolutely necessary. When adding dependencies in `Cargo.toml`, you must consider security, footprint, and determinism.
- **No Default Features**: When adding dependencies, typically use `default-features = false` and explicitly opt-in to `alloc` or specific features. Avoid pulling in the standard library unless required.
- **Workspace Architecture**: Observe the crate separation (e.g., `model`, `codec`, `adapter-api`, `verifier`, `author`). Code must be placed in the appropriate layer according to the workspace dependency graph (`verifier` depends on `model`, `codec`, and `adapter-api`).

## 3. Fixtures and Wire Formats (`fixtures/v1`)
- **Golden Vectors**: The `.cbor` files in `fixtures/v1` are deterministic golden fixtures. They are checked byte-for-byte to ensure the wire format is never accidentally broken.
- **Canonical Ownership**: `auths-proof` is the source of truth for the core wire corpus and its manifest. Downstream repositories consume a pinned corpus revision and may add repository-specific scenario fixtures, but they must not fork or regenerate the canonical core vectors.
- **Updating Vectors**: If you make an intentional protocol change that affects the wire format, you must regenerate the fixtures by running `cargo xtask wire --update`.
- **Validation**: Never modify `.cbor` files by hand. If a test fails due to fixture mismatch, either your code is non-deterministic/broken, or you explicitly need to update the wire fixtures.

## 4. Fuzzing & Quality Assurance
- **Fuzzing (`fuzz/`)**: We rely on fuzzing to ensure the codec and verifier are robust against malformed or adversarial inputs. Any new parsing logic or state transitions must be fuzzed. When making significant changes, verify they do not introduce panics or unbounded allocations under fuzzing.
- **`xtask` Automation**: Use the `xtask` tooling for development and verification.
  - Run `cargo xtask ci` to run the complete suite of tests, formatting, and lint checks.
  - Run `cargo xtask wire` to verify golden vectors byte-for-byte.
  - Keep core corpus generation and validation in this repository. Downstream
    repositories may wrap these checks, but must not silently produce different
    core `.cbor` bytes.

## 5. Security & Review
- Treat all input as adversarial.
- Code should panic *only* on internal invariant violations, never on malformed external input (return a `Result` instead).
- Be mindful of side-channels and cryptographic best practices (rely on the vetted underlying crypto crates rather than rolling your own).

## Implementation Standards

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK. Example: `DomainError::InvalidSignature`, `StorageError::ConcurrentModification`.
5. **`thiserror`/`anyhow` Translation Boundary**: The ban on `anyhow` in Core/SDK is strict, but the CLI **must** define a clear translation boundary where domain errors are wrapped with operational context. The CLI and server crates continue using `anyhow::Context` to collect system-level information (paths, environment, subprocess output), but always wrap the domain `thiserror` errors cleanly — never discard the typed error:
    ```rust
    // Converts the strict thiserror SigningError into a contextualized anyhow::Error
    let signature = sign_artifact(&config, data)
        .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
    ```
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
7. **`unwrap()` / `expect()` Policy**: The workspace denies `clippy::unwrap_used` and `clippy::expect_used` globally. `clippy.toml` sets `allow-unwrap-in-tests = true`, so test code is exempt. For production code:
   - **Default**: Use `?` (in functions returning `Result`), `.ok_or_else(|| ...)`, `.unwrap_or_default()`, or `match` instead of `.unwrap()` / `.expect()`.
   - **Provably safe unwraps**: When an unwrap is provably infallible (e.g., `try_into()` after a length check, `ProgressStyle::with_template()` on a compile-time constant, `Regex::new()` on a literal), use an inline `#[allow]` with an `INVARIANT:` comment explaining why it cannot fail:
     ```rust
     #[allow(clippy::expect_used)] // INVARIANT: length validated to be 32 bytes on line N
     let arr: [u8; 32] = vec.try_into().expect("validated above");
     ```
   - **FFI boundaries**: `expect()` is acceptable in FFI/WASM `extern "C"` functions where panicking is the only option (no `Result` return). Annotate with `#[allow]`.
   - **Mutex/RwLock poisoning**: `lock().expect()` / `write().expect()` on stdlib mutexes is acceptable — a poisoned mutex means another thread panicked, which is unrecoverable. Annotate with `#[allow]` and an INVARIANT comment.
   - **Never** add blanket `#![allow(clippy::unwrap_used, clippy::expect_used)]` to crate roots. Fix each site individually.
8. **Parse, Don't Validate**: Avoid manual runtime string checks, untyped JSON inspection (`serde_json::Value`), or boolean flag validation. Parse raw untrusted strings and JSON inputs at the boundary directly into strongly-typed domain enums, newtypes, and `serde` deserialization structs so illegal states become unrepresentable in downstream logic.
9. **Audit Before Re-inventing (DRY)**: Always search the codebase for pre-existing domain types (`Audience`, `detect_ci_environment`, `Cents`, `KeriPublicKey`) before creating custom helper types or duplicate abstractions from scratch.
10. **Zeroization of Sensitive Memory**: All private key material, signing seeds, nonces, raw payload buffers, and session tokens **MUST** be wrapped in `zeroize::Zeroizing<T>` or implement `zeroize::ZeroizeOnDrop` to ensure secret bytes are scrubbed from RAM immediately when dropped.
11. **Constant-Time Cryptographic Comparison**: Never use standard `==` or string equality for security-sensitive tokens, nonces, or signature verification status checks. Use `subtle::ConstantTimeEq` to prevent timing side-channel attacks.
12. **Property-Based Testing (`proptest`)**: In addition to standard unit tests, complex financial arithmetic (`Cents`), state sequence boundaries, wire deserializers, and C-FFI / WASM export parsers **MUST** include property-based test suites (`proptest!`) to prove invariant properties and overflow safety across arbitrary inputs.
