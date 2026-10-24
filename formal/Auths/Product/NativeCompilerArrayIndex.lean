import Auths.Product.NativeCompilerResponsePointer
import Auths.Product.RecipeIndexProperties

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- The exact checked digit expression from both native index loops. Both
overflow branches retain the old value. This is transparent source syntax,
not an opaque parser result. -/
def nativeIndexDigit (value : Std.Usize) (byte : Std.U8) : Result (Std.Usize × Bool) := do
  if byte < 48#u8 then ok (value, false)
  else if byte > 57#u8 then ok (value, false)
  else
    let product ← lift (Usize.checked_mul value 10#usize)
    match product with
    | none => ok (value, false)
    | some product =>
        let digit ← byte - 48#u8
        let digit ← lift (core.convert.num.FromUsizeU8.from digit)
        let next ← lift (Usize.checked_add product digit)
        match next with
        | none => ok (value, false)
        | some next => ok (next, true)

def nativeIndexLoop (first : Bool) (token : Slice Std.U8) (position value : Std.Usize) (valid : Bool) :
    Result (Std.Usize × Bool) :=
  if first then AuthsNativeRecipe.recipe.validate.template_array_index_loop0 token position value valid
  else AuthsNativeRecipe.recipe.validate.template_array_index_loop1 token position value valid

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 14000000
set_option maxRecDepth 4096

@[step] theorem native_index_digit_exact (value : Std.Usize) (byte : Std.U8) :
    nativeIndexDigit value byte ⦃ actual =>
      (actual.1.val, actual.2) = indexDigit Usize.max value.val byte.val ⦄ := by
  unfold nativeIndexDigit
  by_cases small : byte.val < 48
  · have nativeSmall : byte < 48#u8 := by scalar_tac
    simp [nativeSmall, indexDigit, Nat.not_le.mpr small]
  · have nativeLower : ¬byte < 48#u8 := by scalar_tac
    simp only [nativeLower, ↓reduceIte]
    by_cases large : 57 < byte.val
    · have nativeLarge : byte > 57#u8 := by scalar_tac
      simp [nativeLarge, indexDigit, Nat.not_le.mpr large]
    · have nativeUpper : ¬byte > 57#u8 := by scalar_tac
      have digit : 48 ≤ byte.val ∧ byte.val ≤ 57 := by omega
      simp only [nativeUpper, ↓reduceIte, bind_tc_ok]
      have productSpec := Usize.checked_mul_bv_spec value 10#usize
      cases productAt : Usize.checked_mul value 10#usize with
      | none =>
          rw [productAt] at productSpec
          have overflow : ¬10 * value.val ≤ Usize.max := by scalar_tac
          simp [productAt, indexDigit, overflow]
      | some product =>
          rw [productAt] at productSpec
          obtain ⟨productFits, productValue, productBits⟩ := productSpec
          simp only [productAt, bind_tc_ok]
          step as ⟨nativeDigit, digitValue⟩
          step as ⟨wordDigit, wordDigitValue⟩
          have addSpec := Usize.checked_add_bv_spec product wordDigit
          cases addedAt : Usize.checked_add product wordDigit with
          | none =>
              rw [addedAt] at addSpec
              have overflow : ¬10 * value.val + (byte.val - 48) ≤ Usize.max := by scalar_tac
              simp [addedAt, indexDigit, overflow]
          | some next =>
              rw [addedAt] at addSpec
              obtain ⟨sumFits, sumValue, sumBits⟩ := addSpec
              have productRoom : 10 * value.val ≤ Usize.max := by scalar_tac
              have sumRoom : 10 * value.val + (byte.val - 48) ≤ Usize.max := by scalar_tac
              have exactValue : next.val = 10 * value.val + (byte.val - 48) := by scalar_tac
              simp [addedAt, indexDigit, digit, productRoom, sumRoom, exactValue]

private theorem native_index_suffix (first : Bool) (token : Slice Std.U8) (position value : Std.Usize)
    (valid : Bool) (positionBound : position.val ≤ token.val.length) :
    nativeIndexLoop first token position value valid ⦃ actual =>
      (actual.1.val, actual.2) = indexScan Usize.max ((schemaSliceBytes token).drop position.val) value.val valid ⦄ := by
  generalize remaining : token.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position value valid with
  | h count ih =>
      unfold nativeIndexLoop
      cases first <;> simp only [Bool.false_eq_true, Bool.true_eq_true, ↓reduceIte]
      all_goals
        first | unfold AuthsNativeRecipe.recipe.validate.template_array_index_loop0
              | unfold AuthsNativeRecipe.recipe.validate.template_array_index_loop1
        by_cases inside : position.val < token.val.length
        · have nativeInside : position < token.len := by scalar_tac
          simp only [nativeInside, ↓reduceIte]
          cases valid with
          | false => simp [index_scan_stopped]
          | true =>
              simp only [Bool.true_eq_true, ↓reduceIte]
              step with Slice.index_usize_spec token position inside as ⟨byte, byteAt⟩
              change (do
                let next ← nativeIndexDigit value byte
                let position ← position + 1#usize
                nativeIndexLoop _ token position next.1 next.2) ⦃ _ ⦄
              step with native_index_digit_exact value byte as ⟨digit, digitMeaning⟩
              step as ⟨next, nextValue⟩
              have suffix : (schemaSliceBytes token).drop position.val = byte.val :: (schemaSliceBytes token).drop next.val := by
                simpa [schemaSliceBytes, List.drop_map, byteAt, nextValue] using
                  congrArg (List.map (·.val)) (List.drop_eq_getElem_cons inside)
              apply spec_mono (ih _ (by omega) next digit.1 digit.2 (by omega) rfl)
              intro actual meaning
              simpa [suffix, indexScan, ← digitMeaning] using meaning
        · have nativeEnded : ¬position < token.len := by scalar_tac
          have ended : token.val.length ≤ position.val := by omega
          simp [nativeEnded, schemaSliceBytes, List.drop_map, List.drop_eq_nil_of_le ended, indexScan]

/-- Both real loops keep the exact numeric prefix and refusal flag for every
original byte sequence and represented input state. They do not assume valid
decimal syntax, a selected child or successful parsing. -/
@[step] theorem native_array_index_loop0_exact (token : Slice Std.U8) (position value : Std.Usize)
    (valid : Bool) (positionBound : position.val ≤ token.val.length) :
    AuthsNativeRecipe.recipe.validate.template_array_index_loop0 token position value valid ⦃ actual =>
      (actual.1.val, actual.2) = indexScan Usize.max ((schemaSliceBytes token).drop position.val) value.val valid ⦄ := by
  simpa [nativeIndexLoop] using native_index_suffix true token position value valid positionBound

@[step] theorem native_array_index_loop1_exact (token : Slice Std.U8) (position value : Std.Usize)
    (valid : Bool) (positionBound : position.val ≤ token.val.length) :
    AuthsNativeRecipe.recipe.validate.template_array_index_loop1 token position value valid ⦃ actual =>
      (actual.1.val, actual.2) = indexScan Usize.max ((schemaSliceBytes token).drop position.val) value.val valid ⦄ := by
  simpa [nativeIndexLoop] using native_index_suffix false token position value valid positionBound

@[step] theorem native_array_index_exact (token : Slice Std.U8) :
    AuthsNativeRecipe.recipe.validate.template_array_index token ⦃ actual =>
      actual.map (·.val) = arrayIndex Usize.max (schemaSliceBytes token) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.template_array_index
  by_cases empty : token.val = []
  · simp [core.slice.Slice.is_empty, empty, arrayIndex, IndexSyntax, schemaSliceBytes]
  · have positive : 0 < token.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      bind_tc_ok, Bool.false_eq_true, ↓reduceIte]
    by_cases long : 1 < token.val.length
    · have nativeLong : token.len > 1#usize := by scalar_tac
      simp only [nativeLong, ↓reduceIte]
      step with Slice.index_usize_spec token 0#usize positive as ⟨first, firstAt⟩
      have originalFirst : (schemaSliceBytes token).head? = some first.val := by
        simpa [schemaSliceBytes, firstAt] using
          congrArg (fun values => (values.map (·.val)).head?) (List.drop_eq_getElem_cons positive)
      by_cases zero : first.val = 48
      · have nativeZero : first = 48#u8 := by scalar_tac
        simp [nativeZero, arrayIndex, IndexSyntax, schemaSliceBytes, originalFirst, long]
      · have nativeNonzero : first ≠ 48#u8 := by scalar_tac
        simp only [nativeNonzero, ↓reduceIte]
        step with native_array_index_loop0_exact token 0#usize 0#usize true (by simp)
          as ⟨scanned, meaning⟩
        have noLeading : ¬(schemaSliceBytes token = [] ∨
            (1 < (schemaSliceBytes token).length ∧ (schemaSliceBytes token).head? = some 48)) := by
          simp [schemaSliceBytes, empty, originalFirst, zero]
        cases valid : scanned.2 <;>
          simp [valid, array_index_from_scan, noLeading, ← meaning, spec_ok]
    · have nativeShort : ¬token.len > 1#usize := by scalar_tac
      have one : token.val.length = 1 := by omega
      simp only [nativeShort, ↓reduceIte]
      step with native_array_index_loop1_exact token 0#usize 0#usize true (by simp)
        as ⟨scanned, meaning⟩
      have noLeading : ¬(schemaSliceBytes token = [] ∨
          (1 < (schemaSliceBytes token).length ∧ (schemaSliceBytes token).head? = some 48)) := by
        simp [schemaSliceBytes, empty, one]
      cases valid : scanned.2 <;>
        simp [valid, array_index_from_scan, noLeading, ← meaning, spec_ok]

end Auths.Product.NativeCompiler.Refinement
