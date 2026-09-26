# libcrux as the verified signature and hash implementation

## Status

Feasibility spike for [AP-SPEC-061](../../specs/0061-end-to-end-machine-checked-verifier.md)
§3.2, run on 2026-09-26 against `main` at `8b96f2ca`. It records findings;
nothing here is implemented.

| Role | Candidate | Current implementation |
|---|---|---|
| Ed25519 | `libcrux-ed25519` 0.0.9 | `ed25519-dalek` 2.2.0 |
| P-256 ECDSA | `libcrux-ecdsa` 0.0.8, built on `libcrux-p256` 0.0.8 | `p256` 0.13.2 |
| SHA-256 | `libcrux-sha2` 0.0.8 | `sha2` 0.10.9 |

**Question.** AP-SPEC-061 §3.2 left four things unchecked:
- whether libcrux fits `no_std` and the `auths-signature-core` API;
- whether its P-256 enforces low-S;
- licensing;
- whether its proofs cover the exact code paths the suites would call.

## Answers

1. **`no_std`, WASM and MSRV: fit.**
   - libcrux is pure Rust and `#![no_std]`. The Ed25519 and P-256 crates need
     `alloc`. There is no `build.rs`, no C and no assembly.
   - With `default-features = false`, it builds for all of:
     - `riscv64gc-unknown-none-elf` (no `std` in the sysroot);
     - `wasm32-unknown-unknown`, where it runs in Node with 0 imports;
     - Rust 1.91.0;
     - inside `auths-proof-wasm`.
2. **Low-S: neither exposed nor enforced.** HACL* accepts any s ∈ [1, n−1].
   It accepted a valid high-S signature, including the corpus high-S fixture.
   The suite keeps its own s ≤ ⌊n/2⌋ check: one 32-byte big-endian
   comparison, which agreed with `p256`'s `normalize_s` on 5,000 values. That
   check is small enough to prove in Lean.
3. **License: acceptable. `cargo deny` fails.**
   - All crates are Apache-2.0 and pass `deny.toml`'s licenses, bans and
     sources checks.
   - The advisories check fails on RUSTSEC-2026-0173 (`proc-macro-error2`,
     unmaintained, no fixed version). It is reached through `hax-lib-macros` →
     `hax-lib` → `libcrux-secrets`.
   - Using libcrux needs an owner-reviewed advisory exception, or an upstream
     release that drops the dependency.
4. **Proof coverage** (details below).
   - The verify and hash cores are proved in F* (HACL*).
   - The Rust is produced from them by a translation with no formal
     guarantee, and libcrux has edited it by hand.
   - libcrux's own APIs are unverified, as is the suite's glue.
   - None of these paths has hax proofs.
5. **Differential:** 0 disagreements with the current implementation, once the
   suite's glue checks are applied. This covered 357 unique signature and key
   tuples reached by the test corpus. All 67 tests that reach the suites pass
   with libcrux deciding.
6. **Recommendation: link libcrux, conditionally.** The conditions are:
   - the owner approves the RUSTSEC-2026-0173 exception;
   - the crates are `=`-pinned;
   - the glue checks are proved in Lean;
   - `ed25519-dalek`, `p256` and `sha2` stay as differential test oracles.

   Otherwise, use the specification-axiom fallback. Both claim sentences are
   in AP-SPEC-061 §5.

## Current semantics (at `8b96f2ca`)

- **Ed25519** (`auths-signature-core`):
  - 32-byte `VerifyingKey::from_bytes`, 64-byte signature, `verify_strict`.
  - Cofactorless; requires S < L; rejects small-order A and R.
  - R is compared as bytes, so a non-canonical R fails.
  - Key validation accepts some non-canonical encodings of A: 24 of the 38
    encodings with y ≥ p, and x = 0 with the sign bit set. RFC 8032 §5.1.3
    decoding rejects them.
- **P-256:**
  - Raw 64-byte r‖s, with r, s ∈ [1, n−1]. The suite hashes the message with
    SHA-256 itself.
  - Low-S is enforced in the suite.
  - Keys are decoded with `from_sec1_bytes`. That call also accepts the 65-byte
    uncompressed (`0x04`) and 33-byte `0x05` forms. `core/spec/v1/registry.md`
    allows only the 33-byte compressed form. [PR #176](https://github.com/auths-dev/auths-proof/pull/176)
    corrects this.
- **SHA-256** is used for:
  - identifiers: `SHA-256("AUTHS-ID" ‖ u16 major ‖ u16 type ‖ u64 len ‖ bytes)`;
  - `AUTHS-COMMITMENT` commitments;
  - the adapter `configuration_id`;
  - raw-key binding, body, proof and principal-identifier digests.

  Signature preimages are `AUTHS`-framed and signed directly, without a
  prehash.

## Crates

| Crate | Native code / `build.rs` | `unsafe` | `no_std` | API used |
|---|---|---|---|---|
| `libcrux-ed25519` | none | 0 | `alloc` | `verify(msg, &[u8; 32], &[u8; 64])`; one error kind; no key API |
| `libcrux-ecdsa` | none | forbidden | `default = [rand, std]` | `p256::verify(Sha256, msg, &Signature, &PublicKey)`, `compressed_to_coordinates`, `validate_point` |
| `libcrux-p256` | none | 0 | `alloc` | "SHOULD NOT be used directly"; reached only through `libcrux-ecdsa` |
| `libcrux-sha2` | none | 0 | no heap | one-shot `sha256()` |
| `libcrux-hacl-rs`, `-secrets`, `-traits`, `hax-lib` | `hax-lib`'s `build.rs` only generates code | 0 / 18 / 4 / 0 | yes | support crates |

No MSRV is declared, and the edition is 2021. The `unsafe` code in `secrets`
is off the verify path. Use the individual crates, not the umbrella `libcrux`
crate.

## Proof coverage

The code comes from HACL* (Low*), translated to Rust by KaRaMeL's Rust backend
("Scylla"). It is not produced by Eurydice or hax.
- The `hacl-rs` sources cite hacl-star commit `efbf82f2`. That commit exists
  only on the branch of the unmerged hacl-star PR #918, "A preliminary version
  of HACL* extracted to *safe* Rust", not on `main`.
- The Scylla paper (arXiv 2412.15042) says the translation has no formal
  correctness guarantee.
- libcrux edited the output by hand. SHA-2 streaming was rewritten, and
  `memzero` is a commented-out no-op.

| Path | F*-proved (translation trusted) | Unverified glue |
|---|---|---|
| Ed25519 | `Hacl.Ed25519.verify` = `Spec.Ed25519.verify`: rejects y ≥ p and x = 0 with the sign bit set; requires S < L; SHA-512; cofactorless; **no small-order check** | libcrux's `impl_hacl.rs` (146 lines). Suite glue: lengths, the 8-encoding small-order blocklist, key validation |
| P-256 | `ecdsa_verif_p256_sha2` = `Spec.ECDSA`: point on the curve with x, y < p; 0 < r, s < n (**high-S accepted**); SHA-256. `compressed_to_raw` is verified. | libcrux-ecdsa's `p256.rs` (358 lines). Suite glue: 33-byte length, `02`/`03` prefix, low-S, error classes |
| SHA-256 | `hash_256` = `Spec.Agile.Hash`. `Spec.SHA2` is a trusted transcription of FIPS 180-4. | Wrappers and the hand-edited streaming code. Use the one-shot call. |
| Shared | Generated bignum code | The hand-written `fstar`/`lowstar` integer runtime and the `unroll_for!` macro |

Per libcrux's CI, hax covers ML-KEM, ML-DSA, SHA-3 and KMAC, and none of these
paths. RUSTSEC-2026-0026 and RUSTSEC-2026-0075 affected Ed25519 key generation
only, and were fixed by 0.0.7.

**Three defects in libcrux-ecdsa's own API**, which the suite glue avoids:
- `PublicKey::try_from` ignores trailing bytes;
- it decoded 68 of 19,999 raw keys to a different point;
- `validate_point(&[0; 10])` panics.

The glue therefore checks lengths and prefixes itself. It passes only
fixed-size arrays produced by the verified decoder into `validate_point` and
`verify`.

## Differential results

| Case | Current | libcrux |
|---|---|---|
| Small-order A with R = identity and S = 0 (8 points × 32 messages) | 0 accepted | 89 accepted by plain libcrux (the identity key accepts 32 of 32); 0 with the blocklist |
| All-zero key and signature, and signer-made R = identity | rejected | some accepted by plain libcrux; 0 with the blocklist |
| Mixed-order key aB + T₈ (64 messages) | 3 accepted | the same 3 messages |
| Undecodable non-canonical A (28 cases) | `InvalidKey` | `VerificationFailed` (a class difference; the glue maps it) |
| Valid high-S | rejected | accepted without the low-S check |
| 65-byte key; `0x05` key with a valid signature | accepted | rejected (33-byte glue) |
| S ≥ L, non-canonical R, x ≥ p, off-curve, r or s ∈ {0, n}, DER, wrong lengths | rejected | rejected, same class |
| Random vectors: 7,994 Ed25519, 4,000 P-256 | — | 0 disagreements |
| SHA-256: lengths 0–1100 and 4 KiB–1 MiB, streaming, 1,235 fixture digests | — | 0 disagreements |

**Corpus run.** An instrumented copy of `auths-signature-core` dual-ran every
suite call during `cargo test -p auths-verifier` (the corpus, the portable ABI
and adversarial conformance) and in 13 adapter and testkit crates. That was
1,377 calls, forming 357 unique tuples: 345 Ed25519, 4 P-256 and 8 key
validations. There were 0 disagreements for the glued candidates, and every
test passed with libcrux deciding.

**Gap:** the corpus reaches only 4 P-256 tuples.

## Repository policy fit

- `Cargo.toml`: three `=`-pinned workspace dependencies with
  `default-features = false`.
- `deny.toml`:
  - advisories fail (RUSTSEC-2026-0173) and need an owner-reviewed `ignore`;
  - licenses, sources and bans pass;
  - one new `shlex` duplicate.
- `architecture.toml`:
  - no forbidden-dependency or `no_std` violations;
  - `approved_build_scripts` covers only workspace packages.
- The lockfile gains `crabgrind` (valgrind C code with a `build.rs`),
  `bindgen` and `clang-sys`. They sit under a `cfg(valgrind_ct_test)` that is
  never compiled, but the lock entries still need review.

## Reproduction

In a throwaway crate outside the workspace, depending on the three crates at
the versions above:

```text
cargo +1.97.1 test
cargo +1.97.1 build --lib --target wasm32-unknown-unknown --release
cargo +nightly-2026-06-01 build --lib --target riscv64gc-unknown-none-elf
cargo +1.91.0 build --lib
cargo deny --frozen check
```

The glue and the differential harness are not committed. The tables above list
every case class, so the harness can be rebuilt from them.
