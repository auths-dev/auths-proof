# Aeneas translation feasibility for the end-to-end verifier

## Status

Feasibility spike for [AP-SPEC-061](../../specs/0061-end-to-end-machine-checked-verifier.md),
run on 2026-09-26 against `main` at `8b96f2ca`. It records findings; nothing
here is implemented.

Pinned tools, from `formal/translation-toolchain.lock`: Charon 0.1.225 (commit
`527ea8e`, `nightly-2026-06-01`) and Aeneas `3a8586fa`, with Lean v4.31.0. The
tools were invoked as `fn reproduce` in `xtask/src/formal_qualification.rs`
does, but without `--error-on-warnings` and `-warnings-as-errors`, so that
every problem was collected.

**Question.** Can the pinned toolchain translate the code the plan must prove?
If not, what refactoring would make it translatable?

## Answers

1. **`verify_v1` as written: no.** Charon is not the blocker. It extracts the
   whole `verify_v1` closure in 18–93 s: 2,431 function bodies, 2,145 of them
   from 18.4k lines of in-repo code. Aeneas produces no Lean in any
   configuration. Every run ends in an uncaught crash or a cascade of
   follow-on errors. With seven diagnostic workarounds, 199 errors remain
   across 35 verifier declarations, most of them on the staged path:
   `resolve_proof`, `verify_principal_control`, `verify_authority_measured`,
   `verify_branch*`, and the status and constraint checks.
2. **`&dyn` is one of nine blocker classes** (table below).
3. **The codec, with `minicbor` opaque: partly.** Charon extracts 345 codec and
   748 model functions cleanly. Aeneas still reports:
   - 27 loop-shape errors in 24 codec functions, 13 of them in `decode.rs`;
   - 26 errors for functions used as values, plus name clashes from
     `.map(Self)`;
   - the crate-wide crashes listed below.

   A narrow slice (`decode_signed_grant`) reaches Lean with 49 codec
   definitions behind 63 external axioms, 22 of which are `minicbor`. The
   rewrite needed is a medium, mechanical restyle, not a redesign.
4. **An extractable tokenizer style works.** The spike wrote a canonical-CBOR
   head decoder in the planned style: `&[u8]` plus an explicit index,
   `Result`, and one loop per helper. It covers definite lengths, shortest
   form, reserved values and count limits. It passes Charon and Aeneas with
   the strict flags and builds in Lean (`lake build`, about 1,700 jobs,
   about 54 s). It needs no externals and uses only the three standard
   axioms. The codec already rejects input whose re-encoding differs, so once
   the encoder is also extracted, canonical uniqueness mostly follows from
   that check.

## Blocker inventory

Paths are relative to `core/crates/`.

| Class | Count | Representative sites | Fix | Effort at agent speed |
|---|---|---|---|---|
| Std features that crash Aeneas: `Iterator::try_fold`/`copied`, `str` patterns, a `char` match | 306 iterator call sites; 6 `str` pattern sites; 1 `char` match | `registries/lib.rs:102,941–1128`; `model/lib.rs:164,174,1670` | Index-based `while` loops, `u8` matches, byte identifiers | 1–2 d |
| Mixed recursive group: derived `PartialEq`/`Ord` on `AuthorizationPlan` ↔ `AuthorizationPlanNode` | 1 root, which causes 1,410 follow-on errors | `model/lib.rs:1748,1751` | Free `plan_equal`/`plan_cmp` functions, or one self-recursive plan type (probe passes) | 2–4 h |
| Loop shape: `?` in a nested loop, an early exit in a loop that is not the function's first construct, `break`/`continue` to an outer loop | 41 errors in 38 functions | verifier `lib.rs:1281,1409,1515,1983,2065,2244,2537,2584,2650`; `observation.rs:80,137,218,359`; codec `decode.rs:148,690,802,1145,1484`, `encode.rs:249,515,996,1217` | One loop per helper, placed first in the helper; no `?` in nested loops | 1 d |
| `dyn` types and calls | 30 sites | `registries/lib.rs:606,827,945–1168`; verifier `lib.rs:1876,2387,2488,2740`; `observation.rs:291,411` | A closed enum per port (enum dispatch and generic dispatch both pass); a thin `&dyn` shell, tested equal to it | 1–2 d |
| Function items and constructors used as values | 72 sites | `codec/encode.rs:43–68,218,650,1423`; `composition/lib.rs:104`; `model/lib.rs:540,603,671` | Explicit closures | 2–4 h |
| Iterator and closure pipelines that hold borrows | 35 errors | `registries/lib.rs:430–562,1082–1155`; verifier `lib.rs:1589,2209,2346,2558,2759` | Same rewrite as the first row | in row 1 |
| Std functions with no Aeneas model: `BTreeSet`, `Option`/`Result` combinators, `String` | 15 `BTreeSet` sites; 435 combinator call sites | verifier `lib.rs:1300,1338,1625`; `model/lib.rs:1897` | Sorted `Vec`; reviewed Lean models in the style of `generated/model/FunsExternal.lean` | 1 d |
| P-256 wrapper overflows Charon's stack, even with the crypto crates opaque | 1 | `signature-core/lib.rs` (`verify_p256_sha256`) | Mark the function opaque; it becomes the byte-level axiom of AP-SPEC-061 §3.2. The Ed25519 path extracts cleanly behind 3 crypto axioms. | 1 h |
| Charon type errors in std iterator implementations (`enumerate`, `zip`) | 3–6 per run | `core::iter::adapters` | Disappear with the iterator rewrite | in row 1 |

Two further error kinds appear to be secondary: 54 "no bottoms in value" and
2 "enum expansion". They shrink in narrower slices, but they remain a residual
risk until a slice is extracted cleanly.

**Hashing.** `codec/hash.rs:91` uses nested `&mut` closures. It stays opaque
as the SHA-256 axiom, which is what AP-SPEC-061 §3.2 already prescribes.

## How Aeneas represents loops

Aeneas emits each `loop` as a `@[rust_loop_body]` step inside a
`partial_fixpoint`. There is no fuel, and no termination obligation is created
when the loop is defined. Termination is proved at each use, through the
loop's specification lemma and a well-founded measure. Two consequences follow:
- the decreasing measures in AP-SPEC-061 §3.3 are Lean proofs;
- the declared work bound needs an explicit counter in the Rust code, because
  it cannot come from the translation.

## Feature probes

- **Pass with no externals:**
  - a loop with `?`, when the loop is the helper's first construct;
  - inner loops moved into their own helpers;
  - `enumerate`;
  - enum and generic dispatch;
  - `Vec::push`, a `u8` match, `u128`;
  - generic closures;
  - `&mut` held in a struct;
  - `Box`;
  - a self-recursive derived `PartialEq`;
  - `map_err(fn)`.
- **Pass, but need reviewed models:** `BTreeSet`, `Option`/`Result`
  combinators, `str`/`String`, `format!`, `any`, `map`/`filter`/`count`.
- **Fail:**
  - `dyn` calls and `fn` pointers;
  - a `char` match, `split_once` and `copied().find()` (these three crash
    Aeneas);
  - a loop inside an `if`;
  - `?` in a nested loop;
  - `.map(Wrap)`.

## Effort and risk

At agent speed:

| Phase | Refactor to make it translatable | Lean proofs |
|---|---|---|
| 1 (codec) | 2–4 days | 1–2 weeks |
| 3 (control flow) | 4–7 days: closed enums, loop reshaping, about 300 iterator sites, `BTreeSet` → sorted `Vec`, std models | 3–6 weeks |

**The biggest risk is that Aeneas fails all-or-nothing, and each fixed
blocker exposes the next.** This spike went through six layers: the mixed
recursive group, then `try_fold`, `copied`, `Pattern`, `char`, and finally a
crash in Aeneas's micro-passes.

The mitigation is to extract the verifier per stage, with explicit `--opaque`
boundaries, as `fn reproduce` already does for the authority kernel. Each
slice is gated with the strict flags from its first commit.

Where the root causes sit in Aeneas:
- `FunsAnalysis.ml:305` stops at the first mixed group;
- `SymbolicToPureTypes.ml:1012` raises an uncaught error on trait-method type
  constraints;
- the loop-shape rules are in `PrePasses.ml:520–660`.

## Reproduction

Run from the repository root, with `-- --manifest-path <crate>/Cargo.toml
--locked`:

```text
charon cargo --preset aeneas --start-from auths_verifier::verify_v1 \
  --dest-file out/auths_verifier.llbc --format json
charon cargo --preset aeneas \
  --start-from auths_codec::decode::{decode_verifier_context,decode_canonical_action,decode_bundle} \
  --opaque minicbor --dest-file out/auths_codec.llbc --format json
charon cargo --preset aeneas \
  --start-from auths_signature_core::{verify_ed25519,validate_ed25519_key} \
  --dest-file out/auths_signature_core.llbc --format json
aeneas -backend lean -split-files -emit-json -subdir spike -dest <dir> \
  -max-error-spans -1 <file.llbc>
```

The diagnostic workarounds were:
- opaque: the `AuthorizationPlan` comparison impls, `UriNamespaceMatcher`, and
  `auths_model::_::parse`;
- excluded: `Iterator::try_fold`, `Iterator::copied`, and `core::str::pattern`.

The spike's scratch crates and logs are not committed. The commands above
reproduce the results on `8b96f2ca` with the pinned tools.
