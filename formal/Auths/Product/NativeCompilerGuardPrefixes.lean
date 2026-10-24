import Auths.Product.RecipeGuardPrefixes
import Auths.Product.NativeCompilerReadPointers
import Auths.Product.NativeCompilerConsumption

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

private theorem native_guard_prefix_bytes (bytes : Slice Std.U8) (position : Std.Usize) (valid : Bool)
    (within : position.val ≤ bytes.val.length) :
    AuthsNativeRecipe.recipe.validate.guard_prefix_valid_loop bytes position valid ⦃ actual =>
      actual = (valid && decide (∀ byte ∈ (schemaSliceBytes bytes).drop position.val, 33 ≤ byte ∧ byte ≤ 126)) ⦄ := by
  generalize remaining : bytes.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.guard_prefix_valid_loop
      by_cases inside : position.val < bytes.val.length
      · have nativeInside : position < bytes.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec bytes position inside as ⟨byte, byteAt⟩
            have check : (if byte >= 33#u8 then ok (byte <= 126#u8) else ok false) ⦃ actual =>
                actual = decide (33 ≤ byte.val ∧ byte.val ≤ 126) ⦄ := by
              by_cases lower : 33 ≤ byte.val
              · have nativeLower : byte >= 33#u8 := by scalar_tac
                simp [nativeLower, UScalar.le_equiv, lower, spec_ok]
              · have nativeLower : ¬byte >= 33#u8 := by scalar_tac
                simp [nativeLower, lower, spec_ok]
            step with check as ⟨allowed, allowance⟩
            step as ⟨next, nextValue⟩
            have suffix : (schemaSliceBytes bytes).drop position.val = byte.val :: (schemaSliceBytes bytes).drop next.val := by
              simpa [schemaSliceBytes, List.drop_map, byteAt, nextValue] using
                congrArg (List.map (·.val)) (List.drop_eq_getElem_cons inside)
            apply spec_mono (ih _ (by omega) next allowed (by omega) rfl)
            intro actual meaning
            simpa [suffix, allowance, decide_and] using meaning
      · have nativeEnded : ¬position < bytes.len := by scalar_tac
        have ended : bytes.val.length ≤ position.val := by omega
        simp [nativeEnded, schemaSliceBytes, List.drop_map, List.drop_eq_nil_of_le ended]

@[step] theorem native_guard_prefix_exact (prefix : Str) :
    AuthsNativeRecipe.recipe.validate.guard_prefix_valid prefix ⦃ actual =>
      actual = decide (Prefix (schemaSliceBytes prefix)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.guard_prefix_valid
    AuthsNativeRecipe.core.str.Str.as_bytes _root_.core.str.Str.as_bytes
  simp only [bind_tc_ok]
  by_cases empty : prefix.val = []
  · simp [core.slice.Slice.is_empty, empty, Prefix, schemaSliceBytes]
  · have positive : 0 < prefix.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 32 < prefix.val.length
    · have nativeLarge : prefix.len > AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIX_BYTES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIX_BYTES]; scalar_tac
      simp [nativeLarge, Prefix, schemaSliceBytes, Nat.not_le.mpr large]
    · have nativeWithin : ¬prefix.len > AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIX_BYTES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIX_BYTES]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      apply spec_mono (native_guard_prefix_bytes prefix 0#usize true (by simp))
      intro actual meaning
      simpa [Prefix, schemaSliceBytes, positive, Nat.le_of_not_gt large] using meaning

private theorem native_guard_prefix_suffix (prefixes : Slice String) (position : Std.Usize) (valid : Bool)
    (within : position.val ≤ prefixes.val.length) (fits : ∀ prefix ∈ prefixes.val, TextFits prefix) :
    AuthsNativeRecipe.recipe.validate.validate_prefixes_loop prefixes position valid ⦃ actual =>
      actual = (valid && decide (GuardPrefixSequence (prefixes.val.take position.val) (prefixes.val.drop position.val))) ⦄ := by
  generalize remaining : prefixes.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.validate_prefixes_loop
      by_cases inside : position.val < prefixes.val.length
      · have nativeInside : position < prefixes.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec prefixes position inside as ⟨prefix, prefixAt⟩
            have prefixFits := fits prefix (by rw [prefixAt]; exact List.getElem_mem inside)
            step with native_deref_view_exact prefix prefixFits as ⟨view, viewMeaning⟩
            subst view
            step with native_guard_prefix_exact (nativeTextView prefix prefixFits) as ⟨validPrefix, prefixMeaning⟩
            have suffix : prefixes.val.drop position.val = prefix :: prefixes.val.drop (position.val + 1) := by
              simpa [prefixAt] using List.drop_eq_getElem_cons inside
            have prefixStep : prefixes.val.take (position.val + 1) = prefixes.val.take position.val ++ [prefix] := by
              simpa [prefixAt] using List.take_succ_eq_append_getElem inside
            have continue (next : Std.Usize) (nextValue : next.val = position.val + 1) (flag : Bool) :
                AuthsNativeRecipe.recipe.validate.validate_prefixes_loop prefixes next flag ⦃ actual =>
                  actual = (flag && decide (GuardPrefixSequence (prefixes.val.take next.val) (prefixes.val.drop next.val))) ⦄ :=
              ih _ (by omega) next flag (by omega) rfl
            cases validPrefix with
            | false =>
                have invalid : ¬Prefix (textBytes prefix) := by simpa [native_text_view_bytes] using prefixMeaning.symm
                simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
                step as ⟨next, nextValue⟩
                apply spec_mono (continue next nextValue false)
                intro actual meaning
                simpa [suffix, guard_prefix_sequence_cons, invalid] using meaning
            | true =>
                have prefixValid : Prefix (textBytes prefix) := by simpa [native_text_view_bytes] using prefixMeaning.symm
                simp only [Bool.true_eq_true, ↓reduceIte]
                step with native_string_seen_before_exact prefixes position as ⟨seen, seenMeaning⟩
                have originalSeen : seen = decide (prefix ∈ prefixes.val.take position.val) := by
                  simpa [seenBefore, List.getElem?_eq_getElem inside, prefixAt] using seenMeaning
                step as ⟨next, nextValue⟩
                apply spec_mono (continue next nextValue (!seen))
                intro actual meaning
                simpa [suffix, guard_prefix_sequence_cons, prefixValid, originalSeen,
                  nextValue, prefixStep, decide_and] using meaning
      · have nativeEnded : ¬position < prefixes.len := by scalar_tac
        have ended : prefixes.val.length ≤ position.val := by omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, GuardPrefixSequence]

@[step] theorem native_guard_prefixes_admission_exact (prefixes : Slice String)
    (fits : ∀ prefix ∈ prefixes.val, TextFits prefix) :
    AuthsNativeRecipe.recipe.validate.validate_prefixes prefixes ⦃ actual =>
      actual = consumptionVerdict (if Prefixes (prefixes.val.map textBytes) then .ok () else .error .invalidCredentialGuard) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.validate_prefixes
  by_cases empty : prefixes.val = []
  · simp [core.slice.Slice.is_empty, empty, Prefixes, consumptionVerdict, consumptionError]
  · have positive : 0 < prefixes.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 4 < prefixes.val.length
    · have nativeLarge : prefixes.len > AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIXES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIXES]; scalar_tac
      simp [nativeLarge, Prefixes, Nat.not_le.mpr large, consumptionVerdict, consumptionError]
    · have nativeWithin : ¬prefixes.len > AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIXES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_GUARD_PREFIXES]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_guard_prefix_suffix prefixes 0#usize true (by simp) fits as ⟨valid, validity⟩
      have originalValidity : valid = decide (Prefixes (prefixes.val.map textBytes)) := by
        simpa [guard_prefix_sequence_original, Prefixes, positive, Nat.le_of_not_gt large, and_assoc] using validity
      cases valid <;> simp [← originalValidity, consumptionVerdict, consumptionError]

end Auths.Product.NativeCompiler.Refinement
