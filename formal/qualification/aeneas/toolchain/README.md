# Reviewed Aeneas translator overlay: runtime region erasure

This source overlay applies to Aeneas commit
`3a8586facab25b31bdb1e1f5f45acd60d1cc5ff0`. It changes only the OCaml
translator. Charon, the shipping Rust source/features and the upstream Lean
runtime remain pinned to their original versions.

## Defect and correction

The interpreter compares runtime argument and signature types with
`Substitute.erase_regions`. Its inherited Charon implementation substitutes
region **variables**, preserving `RStatic` and `RBody`. The interpreter already
represents string literal borrows with `RErased`. A real Serde call such as
`serialize_struct("ValueExpr", ...)` therefore fails on erased `&str` versus
`&'static str` even though both have the same runtime reference and pointee.

The patch shadows just `erase_regions` inside Aeneas' own Substitute module,
using the same complete region visitor as the existing
`TypesUtils.ty_erase_regions`. A direct call to that utility would introduce a
module dependency cycle. Reference mutability, pointee types, all non-region
generic structure, regionful call signatures, loan/borrow tracking, original
region substitution and static global instantiation remain intact. No assertion,
warning, type check, source-body guard or qualification gate is disabled.
This does not implement general nested static-reference support.

An initial construction-only experiment also changed the signature/global
substitution helpers. That broader experiment exposed the interpreter's
intentional static-global inspection and was discarded. The committed patch
preserves those helpers; its regression explicitly checks that distinction.

## Reproduction and identity

From the repository root, build the hosted toolchain with:

```sh
nix build --file formal/qualification/aeneas/toolchain/aeneas.nix --out-link target/formal-tools
```

The derivation uses the exact upstream flake and its locked inputs, applies the
tracked patch, embeds the full upstream commit plus the SHA-256 of the patch,
and runs the small OCaml regression executable in its check phase. It retains
the upstream Charon binary symlink. Both CI and the release builder use this
same derivation. Construction may compile only the translator executable;
that does not run the regression or qualify any generated Lean.

`formal/translation-toolchain.lock` and the qualification manifest record the
patch path and digest. The loader checks the actual patch bytes against both
records before staging or qualification. Binary version checks, every mapped
translation report and normalized report output retain the complete patched
identity. Upstream-only, abbreviated patched, wrong-patch and dirty identities
are refused. The overlay, build expression and tests are mandatory source
closure inputs and invalidate toolchain reuse when changed.

The pristine Lake dependency still supplies the upstream Lean runtime and its
existing warning inventory. It is not locally patched and must still pass its
clean-checkout audit. Full translation, source/ABI/model review, Lean proof
checks, two clean reproductions and hosted/release evidence remain required.

## Regression scope and current evidence

The OCaml regression compares runtime erasure to the existing full-type eraser
for static, body, free, bound, erased and nested regions; checks idempotence;
refuses to identify mutable/shared references or different pointees; and checks
that ordinary/global/signature substitutions still preserve static regions.
Rust control-plane regressions cover exact patched identities and mapped-report
identity retention/refusal. The CI planner regression covers overlay source
invalidation. These tests are authored and have not run.

Construction logs under `target/formal` are diagnostics only. No translated
Auths callback or constant may be made opaque to obtain a successful result.
The overlay remains unqualified until the final verification gates pass.
