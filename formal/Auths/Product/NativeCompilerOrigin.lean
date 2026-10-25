import Auths.Product.NativeCompilerPaths

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open PathCompiler
set_option maxHeartbeats 4000000

/-- Exact origin/parsed-host framing. This check does not independently parse
URLs, validate DNS, establish TLS or approve the original recipe. -/
@[step] theorem native_origin_frame_exact (origin host : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.path_compiler.origin_matches_host origin host ⦃ actual =>
      actual = decide (OriginMatches (schemaSliceBytes origin) (schemaSliceBytes host)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.path_compiler.origin_matches_host
  by_cases empty : host.val = []
  · simp [core.slice.Slice.is_empty, empty, OriginMatches, schemaSliceBytes]
  · have positive : 0 < host.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, empty, List.isEmpty_eq_false,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 253 < host.val.length
    · have nativeLarge : host.len > 253#usize := by scalar_tac
      simp [nativeLarge, OriginMatches, schemaSliceBytes, Nat.not_le.mpr large]
    · have bounded : host.val.length ≤ 253 := by omega
      have nativeBound : ¬host.len > 253#usize := by scalar_tac
      simp only [nativeBound, ↓reduceIte]
      step as ⟨expectedLength, lengthMeaning⟩
      by_cases wrongLength : origin.val.length ≠ 8 + host.val.length
      · have nativeWrong : origin.len ≠ expectedLength := by scalar_tac
        have invalid : ¬OriginMatches (schemaSliceBytes origin) (schemaSliceBytes host) := by
          intro matched
          have lengths := congrArg List.length matched.2.2
          simp only [schemaSliceBytes, httpsPrefix, List.length_map, List.length_append,
            List.length_cons, List.length_nil] at lengths
          omega
        simp [nativeWrong, invalid]
      · have nativeLength : origin.len = expectedLength := by scalar_tac
        simp only [nativeLength, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        step as ⟨prefix, prefixMeaning⟩
        step with native_schema_copy_bytes prefix as ⟨copied, copyMeaning⟩
        have prefixLength : copied.val.length = 8 := by simp [copyMeaning, prefixMeaning]
        step with native_append_bytes_exact copied host (by scalar_tac) as ⟨expected, expectedMeaning⟩
        step with native_schema_byte_equality origin (AuthsNativeRecipe.alloc.vec.Vec.deref expected)
          as ⟨actual, same⟩
        have fullExpected : schemaSliceBytes (AuthsNativeRecipe.alloc.vec.Vec.deref expected) =
            httpsPrefix ++ schemaSliceBytes host := by
          simp [schemaSliceBytes, native_deref_contents, expectedMeaning,
            copyMeaning, prefixMeaning, List.map_append, httpsPrefix]
        simpa only [fullExpected, OriginMatches, schemaSliceBytes, List.length_map,
          positive, bounded, true_and] using same

end Auths.Product.NativeCompiler.Refinement
