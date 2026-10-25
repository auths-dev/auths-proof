import Auths.Product.RecipeReadProperties
import Auths.Product.NativeCompilerResponsePointer

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 14000000
set_option maxRecDepth 4096

private theorem native_seen_prefix (values : Slice String) (position : Std.Usize) (value : String)
    (previous : Std.Usize) (seen : Bool) (previousBound : previous.val ≤ position.val)
    (positionBound : position.val ≤ values.val.length) :
    AuthsNativeRecipe.recipe.validate.string_seen_before_loop values position value previous seen ⦃ actual =>
      actual = (seen || decide (value ∈ (values.val.take position.val).drop previous.val)) ⦄ := by
  generalize remaining : position.val - previous.val = count
  induction count using Nat.strong_induction_on generalizing previous seen with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.string_seen_before_loop
      by_cases inside : previous.val < position.val
      · have nativeInside : previous < position := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases seen with
        | true => simp
        | false =>
            simp only [Bool.false_eq_true, ↓reduceIte]
            have available : previous.val < values.val.length := by omega
            step with Slice.index_usize_spec values previous available as ⟨current, currentAt⟩
            step as ⟨equal, equality⟩
            step as ⟨next, nextValue⟩
            have prefixInside : previous.val < (values.val.take position.val).length := by
              simp only [List.length_take]; omega
            have prefixValue : (values.val.take position.val)[previous.val] = current := by
              simp [currentAt]
            have suffix : (values.val.take position.val).drop previous.val =
                current :: (values.val.take position.val).drop next.val := by
              simpa [prefixValue, nextValue] using List.drop_eq_getElem_cons prefixInside
            have nextBound : next.val ≤ position.val := by omega
            apply spec_mono (ih _ (by omega) next equal nextBound rfl)
            intro actual meaning
            simpa [suffix, List.mem_cons, equality, eq_comm, decide_or] using meaning
      · have nativeEnded : ¬previous < position := by scalar_tac
        have ended : (values.val.take position.val).length ≤ previous.val := by
          simp only [List.length_take]; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

/-- Out-of-range direct helper calls conservatively return true. In-range
calls inspect the complete earlier original prefix; no lexical/UTF-8 premise
or selected duplicate index is supplied. -/
@[step] theorem native_string_seen_before_exact (values : Slice String) (position : Std.Usize) :
    AuthsNativeRecipe.recipe.validate.string_seen_before values position ⦃ actual =>
      actual = seenBefore values.val position.val ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.string_seen_before
    core.slice.Slice.get core.slice.index.SliceIndexUsizeSlice
  simp only [core.slice.index.Usize.get, Slice.getElem?_Usize_eq, bind_tc_ok]
  by_cases inside : position.val < values.val.length
  · simp only [List.getElem?_eq_getElem inside]
    apply spec_mono (native_seen_prefix values position values.val[position.val] 0#usize false
      (by simp) (by omega))
    intro actual meaning
    simpa [seenBefore, List.getElem?_eq_getElem inside, List.drop_zero] using meaning
  · have ended : values.val.length ≤ position.val := by omega
    simp [seenBefore, List.getElem?_eq_none_iff.mpr ended]

private theorem native_pre_entry_pointer_suffix (pointers : Slice String) (position : Std.Usize)
    (valid : Bool) (positionBound : position.val ≤ pointers.val.length)
    (fits : ∀ pointer ∈ pointers.val, TextFits pointer) :
    AuthsNativeRecipe.recipe.validate.pre_entry_pointers_valid_loop pointers position valid ⦃ actual =>
      actual = (valid && decide (PointerSequence (pointers.val.take position.val)
        (pointers.val.drop position.val))) ⦄ := by
  generalize remaining : pointers.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.pre_entry_pointers_valid_loop
      by_cases inside : position.val < pointers.val.length
      · have nativeInside : position < pointers.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with Slice.index_usize_spec pointers position inside as ⟨pointer, pointerAt⟩
            have pointerFits : TextFits pointer := fits pointer (by rw [pointerAt]; exact List.getElem_mem inside)
            step with native_deref_view_exact pointer pointerFits as ⟨view, viewMeaning⟩
            subst view
            step with native_response_pointer_exact (nativeTextView pointer pointerFits) as ⟨admitted, admission⟩
            have suffix : pointers.val.drop position.val = pointer :: pointers.val.drop (position.val + 1) := by
              simpa [pointerAt] using List.drop_eq_getElem_cons inside
            have prefix : pointers.val.take (position.val + 1) = pointers.val.take position.val ++ [pointer] := by
              simpa [pointerAt] using List.take_succ_eq_append_getElem inside
            have recurse (next : Std.Usize) (nextValue : next.val = position.val + 1) (flag : Bool) :
                AuthsNativeRecipe.recipe.validate.pre_entry_pointers_valid_loop pointers next flag ⦃ actual =>
                  actual = (flag && decide (PointerSequence (pointers.val.take next.val)
                    (pointers.val.drop next.val))) ⦄ :=
              ih _ (by omega) next flag (by omega) rfl
            cases admitted with
            | false =>
                have invalid : ¬ResponsePointer (textBytes pointer) := by
                  simpa [responsePointer, native_text_view_bytes] using admission.symm
                simp only [Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
                step as ⟨next, nextValue⟩
                apply spec_mono (recurse next nextValue false)
                intro actual meaning
                simpa [suffix, pointer_sequence_cons, invalid] using meaning
            | true =>
                have accepted : ResponsePointer (textBytes pointer) := by
                  simpa [responsePointer, native_text_view_bytes] using admission.symm
                simp only [Bool.true_eq_true, ↓reduceIte]
                step with native_string_seen_before_exact pointers position as ⟨seen, seenMeaning⟩
                have originalSeen : seen = decide (pointer ∈ pointers.val.take position.val) := by
                  simpa [seenBefore, List.getElem?_eq_getElem inside, pointerAt] using seenMeaning
                step as ⟨next, nextValue⟩
                apply spec_mono (recurse next nextValue (!seen))
                intro actual meaning
                simpa [suffix, pointer_sequence_cons, accepted, originalSeen, nextValue,
                  prefix, decide_and] using meaning
      · have nativeEnded : ¬position < pointers.len := by scalar_tac
        have ended : pointers.val.length ≤ position.val := by omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, PointerSequence]

@[step] theorem native_pre_entry_pointers_exact (pointers : Slice String) (maximum : Std.U64)
    (fits : ∀ pointer ∈ pointers.val, TextFits pointer) :
    AuthsNativeRecipe.recipe.validate.pre_entry_pointers_valid pointers maximum ⦃ actual =>
      actual = decide (PreEntryPointers (pointers.val.map textBytes) maximum.val) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.pre_entry_pointers_valid
  by_cases empty : pointers.val = []
  · simp [core.slice.Slice.is_empty, empty, PreEntryPointers]
  · have nonempty : 0 < pointers.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty, bind_tc_ok,
      Bool.false_eq_true, ↓reduceIte]
    by_cases large : 4 < pointers.val.length
    · have nativeLarge : pointers.len > AuthsNativeRecipe.recipe.validate.MAX_PRE_ENTRY_POINTERS := by
        simp only [AuthsNativeRecipe.recipe.validate.MAX_PRE_ENTRY_POINTERS]
        scalar_tac
      simp [nativeLarge, PreEntryPointers, Nat.not_le.mpr large]
    · have within : pointers.val.length ≤ 4 := by omega
      have nativeWithin : ¬pointers.len > AuthsNativeRecipe.recipe.validate.MAX_PRE_ENTRY_POINTERS := by
        simp only [AuthsNativeRecipe.recipe.validate.MAX_PRE_ENTRY_POINTERS]
        scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      step with native_read_bound_exact maximum as ⟨readBound, readMeaning⟩
      cases readBound with
      | false =>
          have invalid : ¬ReadBound maximum.val := by simpa using readMeaning.symm
          simp [invalid, PreEntryPointers]
      | true =>
          have readValid : ReadBound maximum.val := by simpa using readMeaning.symm
          simp only [Bool.true_eq_true, ↓reduceIte]
          apply spec_mono (native_pre_entry_pointer_suffix pointers 0#usize true (by simp) fits)
          intro actual meaning
          simpa [List.drop_zero, pointer_sequence_original, PreEntryPointers,
            readValid, within, nonempty, and_assoc] using meaning

end Auths.Product.NativeCompiler.Refinement
