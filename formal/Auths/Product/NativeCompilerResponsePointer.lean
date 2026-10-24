import Auths.Product.RecipePointerProperties
import Auths.Product.NativeCompilerText
import Auths.Product.NativeCompilerByteSlices

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- The source's local look-ahead expression, with both checked additions
retained at their actual callers. The scan proof must match this transparent
expression in the generated body; it is not a supplied Auths validity result. -/
def nativePointerEdge (bytes : Slice Std.U8) (position : Std.Usize) (first : Std.U8) : Result Bool := do
  if first = 126#u8 then
    let next ← position + 1#usize
    if next < bytes.len then
      let second ← Slice.index_usize bytes next
      if second = 50#u8 then ok false else ok true
    else ok true
  else ok true

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 12000000
set_option maxRecDepth 4096

private theorem native_pointer_edge_exact (bytes : Slice Std.U8) (position : Std.Usize) (first : Std.U8)
    (inside : position.val < bytes.val.length) :
    nativePointerEdge bytes position first ⦃ actual =>
      actual = decide (¬(first.val = 126 ∧
        ((schemaSliceBytes bytes).drop (position.val + 1)).head? = some 50)) ⦄ := by
  unfold nativePointerEdge
  by_cases tilde : first.val = 126
  · have nativeTilde : first = 126#u8 := by scalar_tac
    simp only [nativeTilde, ↓reduceIte]
    step as ⟨next, nextValue⟩
    by_cases following : next.val < bytes.val.length
    · have nativeFollowing : next < bytes.len := by scalar_tac
      simp only [nativeFollowing, ↓reduceIte]
      step with Slice.index_usize_spec bytes next following as ⟨second, secondAt⟩
      have suffix : bytes.val.drop (position.val + 1) = second :: bytes.val.drop (next.val + 1) := by
        simpa [nextValue, secondAt] using List.drop_eq_getElem_cons following
      by_cases two : second.val = 50
      · have nativeTwo : second = 50#u8 := by scalar_tac
        simp [nativeTwo, tilde, schemaSliceBytes, List.drop_map, suffix, two]
      · have nativeOther : second ≠ 50#u8 := by scalar_tac
        simp [nativeOther, tilde, schemaSliceBytes, List.drop_map, suffix, two]
    · have nativeEnded : ¬next < bytes.len := by scalar_tac
      have ended : bytes.val.length ≤ position.val + 1 := by omega
      simp [nativeEnded, schemaSliceBytes, List.drop_map, List.drop_eq_nil_of_le ended]
  · have nativeOther : first ≠ 126#u8 := by scalar_tac
    simp [nativeOther, tilde]

private theorem native_pointer_scan (bytes : Slice Std.U8) (position : Std.Usize)
    (tokens : Std.I32) (valid : Bool) (positionBound : position.val ≤ bytes.val.length)
    (counterRoom : tokens.val + (bytes.val.length - position.val : Nat) ≤ 2147483647) :
    AuthsNativeRecipe.recipe.validate.valid_response_pointer_loop bytes position tokens valid ⦃ actual =>
      actual.2 = (valid && decide (CleanEdges ((schemaSliceBytes bytes).drop position.val))) ∧
      (actual.2 = true → actual.1.val = tokens.val + slashCount ((schemaSliceBytes bytes).drop position.val)) ⦄ := by
  generalize remaining : bytes.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position tokens valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.valid_response_pointer_loop
      by_cases inside : position.val < bytes.val.length
      · have nativeInside : position < bytes.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec bytes position inside as ⟨first, firstAt⟩
            have charge : (if first = 47#u8 then tokens + 1#i32 else ok tokens) ⦃ charged =>
                charged.val = tokens.val + (if first.val = 47 then 1 else 0) ⦄ := by
              by_cases slash : first.val = 47
              · have nativeSlash : first = 47#u8 := by scalar_tac
                simp only [nativeSlash, ↓reduceIte]
                step as ⟨charged, chargedValue⟩
                simpa [slash] using chargedValue
              · have nativeOther : first ≠ 47#u8 := by scalar_tac
                simp [nativeOther, slash]
            step with charge as ⟨charged, chargeMeaning⟩
            change (do
              let edge ← nativePointerEdge bytes position first
              let next ← position + 1#usize
              AuthsNativeRecipe.recipe.validate.valid_response_pointer_loop bytes next charged edge) ⦃ _ ⦄
            step with native_pointer_edge_exact bytes position first inside as ⟨edge, edgeMeaning⟩
            step as ⟨next, nextValue⟩
            have nextBound : next.val ≤ bytes.val.length := by omega
            have smaller : bytes.val.length - next.val < count := by omega
            have nextRoom : charged.val + (bytes.val.length - next.val : Nat) ≤ 2147483647 := by
              by_cases slash : first.val = 47 <;> simp [slash] at chargeMeaning <;> omega
            have suffix : (schemaSliceBytes bytes).drop position.val =
                first.val :: (schemaSliceBytes bytes).drop next.val := by
              simpa [schemaSliceBytes, List.drop_map, firstAt, nextValue] using
                congrArg (List.map (·.val)) (List.drop_eq_getElem_cons inside)
            apply spec_mono (ih _ smaller next charged edge nextBound nextRoom rfl)
            rintro actual ⟨complete, countMeaning⟩
            refine ⟨?_, ?_⟩
            · simpa [suffix, clean_edges_cons, edgeMeaning, nextValue, decide_and] using complete
            · intro accepted
              have exactCount := countMeaning accepted
              rw [suffix, slash_count_cons]
              by_cases slash : first.val = 47 <;> simp [slash] at chargeMeaning ⊢ <;> omega
      · have nativeEnded : ¬position < bytes.len := by scalar_tac
        have ended : bytes.val.length ≤ position.val := by omega
        have empty : (schemaSliceBytes bytes).drop position.val = [] := by
          simp [schemaSliceBytes, List.drop_map, List.drop_eq_nil_of_le ended]
        simp [nativeEnded, empty, CleanEdges, slashCount]

/-- Full native response-pointer acceptance and refusal, including the actual
128-byte precheck, slash count and adjacent ~2 rejection. This is the source's
bounded observation-pointer grammar, not RFC 6901 normalization or decoding. -/
@[step] theorem native_response_pointer_exact (pointer : Str) :
    AuthsNativeRecipe.recipe.validate.valid_response_pointer pointer ⦃ actual =>
      actual = responsePointer (schemaSliceBytes pointer) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.valid_response_pointer
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  by_cases empty : pointer.val = []
  · simp [core.slice.Slice.is_empty, empty, responsePointer, ResponsePointer, schemaSliceBytes]
  · have nonempty : 0 < pointer.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases oversized : 128 < pointer.val.length
    · have nativeLarge : pointer.len > AuthsNativeRecipe.recipe.MAX_POINTER_BYTES := by
        simp only [AuthsNativeRecipe.recipe.MAX_POINTER_BYTES]
        scalar_tac
      simp [nativeLarge, responsePointer, ResponsePointer, schemaSliceBytes, Nat.not_le.mpr oversized]
    · have bounded : pointer.val.length ≤ 128 := by omega
      have nativeBound : ¬pointer.len > AuthsNativeRecipe.recipe.MAX_POINTER_BYTES := by
        simp only [AuthsNativeRecipe.recipe.MAX_POINTER_BYTES]
        scalar_tac
      simp only [nativeBound, ↓reduceIte]
      step with Slice.index_usize_spec pointer 0#usize nonempty as ⟨first, firstAt⟩
      have firstMeaning : (schemaSliceBytes pointer).head? = some first.val := by
        have suffix := List.drop_eq_getElem_cons nonempty
        simpa [schemaSliceBytes, firstAt] using congrArg (fun xs => (xs.map (·.val)).head?) suffix
      by_cases slash : first.val = 47
      · have nativeSlash : first = 47#u8 := by scalar_tac
        simp only [nativeSlash, bne_self_eq_false, Bool.false_eq_true, ↓reduceIte]
        step with native_pointer_scan pointer 0#usize 0#i32 true (by simp)
          (by have size : pointer.val.length ≤ 128 := bounded; scalar_tac)
          as ⟨scanned, clean, tokens⟩
        cases scanned.2 with
        | false =>
            have invalidEdges : ¬CleanEdges (schemaSliceBytes pointer) := by simpa using clean.symm
            simp [responsePointer, response_pointer_components, schemaSliceBytes,
              firstMeaning, slash, bounded, invalidEdges]
        | true =>
            have validEdges : CleanEdges (schemaSliceBytes pointer) := by simpa using clean.symm
            have exactTokens := tokens rfl
            simp only [List.drop_zero] at clean exactTokens
            simp [responsePointer, response_pointer_components, firstMeaning, slash,
              bounded, validEdges, IScalar.le_equiv, exactTokens]
      · have nativeOther : first ≠ 47#u8 := by scalar_tac
        simp [nativeOther, responsePointer, ResponsePointer, firstMeaning, slash]

@[step] theorem native_read_bound_exact (maximum : Std.U64) :
    AuthsNativeRecipe.recipe.validate.read_bound_valid maximum ⦃ actual =>
      actual = decide (ReadBound maximum.val) ⦄ := by
  simp [AuthsNativeRecipe.recipe.validate.read_bound_valid,
    AuthsNativeRecipe.recipe.validate.MAX_READ_RESPONSE_BYTES,
    core.ops.range.RangeInclusive.new, AuthsNativeRecipe.core.ops.range.RangeInclusive.contains,
    ReadBound, UScalar.le_equiv, spec_ok]

end Auths.Product.NativeCompiler.Refinement
