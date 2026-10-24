import Auths.Product.NativeCompilerEncoding
import Auths.Product.NativeCompilerRecipeBinding

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

def nativeDigestArrayBytes (digest : Array Std.U8 32#usize) : List Nat := digest.val.map (·.val)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeBinding DerivedTokens

set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

private theorem native_digest_hex_suffix (output : NativeVec Std.U8) (digest : Array Std.U8 32#usize)
    (position : Std.Usize) (bound : position.val ≤ digest.val.length)
    (room : output.val.length + 2 * (digest.val.length - position.val) ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.derived_tokens.append_digest_hex_loop output digest position ⦃ actual =>
      bytes actual = bytes output ++ hexDigest ((digest.val.drop position.val).map (·.val)) ⦄ := by
  generalize remaining : digest.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position output with
  | h count ih =>
      unfold AuthsNativeRecipe.auths_gateway_kernel.derived_tokens.append_digest_hex_loop
      simp only [lift, bind_tc_ok]
      split <;> rename_i within
      · have inside : position.val < digest.val.length := by simpa using within
        step with Array.index_usize_spec digest position inside as ⟨byte, byteAt⟩
        step as ⟨high, highMeaning⟩
        have highSmall : high.val < 16 := by scalar_tac
        step with native_hex_lower_exact high highSmall as ⟨highDigit, highDigitMeaning⟩
        step with native_push_exact output highDigit (by omega) as ⟨afterHigh, afterHighMeaning⟩
        have highSize : afterHigh.val.length = output.val.length + 1 := by
          simp [afterHighMeaning]
        step as ⟨low, lowMeaning⟩
        have lowSmall : low.val < 16 := by scalar_tac
        step with native_hex_lower_exact low lowSmall as ⟨lowDigit, lowDigitMeaning⟩
        step with native_push_exact afterHigh lowDigit (by omega) as ⟨afterLow, afterLowMeaning⟩
        have lowSize : afterLow.val.length = output.val.length + 2 := by
          simp [afterLowMeaning, highSize]
        step as ⟨next, nextMeaning⟩
        have nextBound : next.val ≤ digest.val.length := by omega
        have nextRoom : afterLow.val.length + 2 * (digest.val.length - next.val) ≤ Usize.max := by omega
        have smaller : digest.val.length - next.val < count := by omega
        apply spec_mono (ih _ smaller next afterLow nextBound nextRoom rfl)
        intro actual meaning
        have suffix : digest.val.drop position.val = byte :: digest.val.drop next.val := by
          simpa only [byteAt, nextMeaning] using List.drop_eq_getElem_cons inside
        simpa [bytes, afterLowMeaning, afterHighMeaning, List.map_append, List.append_assoc,
          suffix, hexDigest, hexByte, highMeaning, lowMeaning, highDigitMeaning, lowDigitMeaning] using meaning
      · have ended : digest.val.length ≤ position.val := by simpa using within
        simp [List.drop_eq_nil_of_le ended, hexDigest]

@[step] theorem native_append_digest_hex_exact (output : NativeVec Std.U8)
    (digest : Array Std.U8 32#usize) (room : output.val.length + 64 ≤ Usize.max) :
    AuthsNativeRecipe.auths_gateway_kernel.derived_tokens.append_digest_hex output digest ⦃ actual =>
      bytes actual = bytes output ++ hexDigest (nativeDigestArrayBytes digest) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.derived_tokens.append_digest_hex
  apply spec_mono (native_digest_hex_suffix output digest 0#usize (by simp)
    (by simpa [digest.property] using room))
  intro actual meaning
  simpa only [List.drop_zero, nativeDigestArrayBytes] using meaning

@[step] theorem native_schema_digest_matches_exact (declared : Slice Std.U8)
    (digest : Array Std.U8 32#usize) :
    AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.schema_digest_matches declared digest ⦃ actual =>
      actual = decide (SchemaDigestMatches (schemaSliceBytes declared) (nativeDigestArrayBytes digest)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.recipe_binding.schema_digest_matches
  step with native_append_digest_hex_exact (AuthsNativeRecipe.alloc.vec.Vec.new Std.U8) digest
    (by simp; scalar_tac) as ⟨encoded, encodedMeaning⟩
  apply spec_mono (native_schema_byte_equality declared (AuthsNativeRecipe.alloc.vec.Vec.deref encoded))
  intro actual meaning
  simpa [SchemaDigestMatches, schemaSliceBytes, bytes, native_deref_contents,
    encodedMeaning, native_empty_contents] using meaning

theorem native_digest_array_size (digest : Array Std.U8 32#usize) :
    (nativeDigestArrayBytes digest).length = 32 := by simp [nativeDigestArrayBytes, digest.property]

theorem native_digest_array_byte_bounds (digest : Array Std.U8 32#usize) :
    ∀ byte ∈ nativeDigestArrayBytes digest, byte < 256 := by
  intro byte member
  obtain ⟨native, _, rfl⟩ := List.mem_map.mp member
  scalar_tac

end Auths.Product.NativeCompiler.Refinement
