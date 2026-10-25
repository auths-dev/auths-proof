import Auths.Product.RecipeGuardStatuses
import Auths.Product.NativeCompilerReadPointers

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel RecipeAdmissionAtoms
set_option maxHeartbeats 18000000
set_option maxRecDepth 4096

private theorem native_status_previous_suffix (statuses : Slice Std.U64) (position : Std.Usize)
    (status : Std.U64) (previous : Std.Usize) (unique : Bool)
    (previousBound : previous.val ≤ position.val) (positionBound : position.val ≤ statuses.val.length) :
    AuthsNativeRecipe.recipe.validate.refused_status_valid_at_loop statuses position status previous unique ⦃ actual =>
      actual = (unique && decide (status.val ∉ ((statuses.val.map (·.val)).take position.val).drop previous.val)) ⦄ := by
  generalize remaining : position.val - previous.val = count
  induction count using Nat.strong_induction_on generalizing previous unique with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.refused_status_valid_at_loop
      by_cases inside : previous.val < position.val
      · have nativeInside : previous < position := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases unique with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            have available : previous.val < statuses.val.length := by omega
            step with Slice.index_usize_spec statuses previous available as ⟨current, currentAt⟩
            step as ⟨next, nextValue⟩
            have prefixInside : previous.val < ((statuses.val.map (·.val)).take position.val).length := by simp; omega
            have prefixValue : ((statuses.val.map (·.val)).take position.val)[previous.val] = current.val := by
              simp [currentAt]
            have suffix : ((statuses.val.map (·.val)).take position.val).drop previous.val =
                current.val :: ((statuses.val.map (·.val)).take position.val).drop next.val := by
              simpa [prefixValue, nextValue] using List.drop_eq_getElem_cons prefixInside
            apply spec_mono (ih _ (by omega) next (current != status) (by omega) rfl)
            intro actual meaning
            simpa [suffix, List.mem_cons, not_or, UScalar.eq_equiv, eq_comm, decide_and] using meaning
      · have nativeEnded : ¬previous < position := by scalar_tac
        have ended : ((statuses.val.map (·.val)).take position.val).length ≤ previous.val := by simp; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended]

/-- Direct out-of-range calls return false. In-range calls check the exact
400..499 catalog, exclude 408/429, then scan every earlier original status. -/
@[step] theorem native_guard_refused_status_at_exact (statuses : Slice Std.U64) (position : Std.Usize) :
    AuthsNativeRecipe.recipe.validate.refused_status_valid_at statuses position ⦃ actual =>
      actual = refusedStatusAt (statuses.val.map (·.val)) position.val ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.refused_status_valid_at
    core.slice.Slice.get core.slice.index.SliceIndexUsizeSlice
  simp only [core.slice.index.Usize.get, Slice.getElem?_Usize_eq, bind_tc_ok]
  by_cases inside : position.val < statuses.val.length
  · simp only [List.getElem?_eq_getElem inside]
    simp only [core.ops.range.RangeInclusive.new,
      AuthsNativeRecipe.core.ops.range.RangeInclusive.contains, bind_tc_ok]
    let status := statuses.val[position.val]
    by_cases interval : 400 ≤ status.val ∧ status.val ≤ 499
    · have nativeInterval : (400#u64 <= status) && (status <= 499#u64) = true := by
        simp [UScalar.le_equiv, interval.1, interval.2]
      simp only [nativeInterval, Bool.true_eq_true, ↓reduceIte]
      by_cases retryable : status.val = 408 ∨ status.val = 429
      · rcases retryable with equal | equal
        · have nativeEqual : status = 408#u64 := by scalar_tac
          simp [status, nativeEqual, refusedStatusAt, List.getElem?_map,
            List.getElem?_eq_getElem inside, RefusedStatus]
        · have nativeEqual : status = 429#u64 := by scalar_tac
          simp [status, nativeEqual, refusedStatusAt, List.getElem?_map,
            List.getElem?_eq_getElem inside, RefusedStatus]
      · have not408 : status ≠ 408#u64 := by scalar_tac
        have not429 : status ≠ 429#u64 := by scalar_tac
        simp only [not408, not429, ↓reduceIte, bind_tc_ok]
        apply spec_mono (native_status_previous_suffix statuses position status 0#usize true (by simp) (by omega))
        intro actual meaning
        simpa [refusedStatusAt, List.getElem?_map, List.getElem?_eq_getElem inside,
          RefusedStatus, interval.1, interval.2, status, retryable, not_or] using meaning
    · have nativeOutside : (400#u64 <= status) && (status <= 499#u64) = false := by
        simp [UScalar.le_equiv, ← decide_and, interval]
      have refused : ¬RefusedStatus status.val := by intro admitted; exact interval ⟨admitted.1, admitted.2.1⟩
      simp [nativeOutside, refusedStatusAt, List.getElem?_map,
        List.getElem?_eq_getElem inside, refused, status]
  · have ended : statuses.val.length ≤ position.val := by omega
    simp [List.getElem?_eq_none_iff.mpr ended, refusedStatusAt, List.getElem?_map]

private theorem native_statuses_suffix (statuses : Slice Std.U64) (position : Std.Usize)
    (valid : Bool) (within : position.val ≤ statuses.val.length) :
    AuthsNativeRecipe.recipe.validate.refused_statuses_valid_loop statuses position valid ⦃ actual =>
      actual = (valid && decide (StatusSequence ((statuses.val.map (·.val)).take position.val)
        ((statuses.val.map (·.val)).drop position.val))) ⦄ := by
  generalize remaining : statuses.val.length - position.val = count
  induction count using Nat.strong_induction_on generalizing position valid with
  | h count ih =>
      unfold AuthsNativeRecipe.recipe.validate.refused_statuses_valid_loop
      by_cases inside : position.val < statuses.val.length
      · have nativeInside : position < statuses.len := by scalar_tac
        simp only [nativeInside, ↓reduceIte]
        cases valid with
        | false => simp
        | true =>
            simp only [Bool.true_eq_true, ↓reduceIte]
            step with native_guard_refused_status_at_exact statuses position as ⟨allowed, allowance⟩
            step as ⟨next, nextValue⟩
            have originalInside : position.val < (statuses.val.map (·.val)).length := by simpa using inside
            have suffix := List.drop_eq_getElem_cons originalInside
            have prefix := List.take_succ_eq_append_getElem originalInside
            apply spec_mono (ih _ (by omega) next allowed (by omega) rfl)
            intro actual meaning
            simpa [nextValue, suffix, status_sequence_cons, prefix, allowance,
              refusedStatusAt, List.getElem?_eq_getElem originalInside, decide_and, and_assoc] using meaning
      · have nativeEnded : ¬position < statuses.len := by scalar_tac
        have ended : (statuses.val.map (·.val)).length ≤ position.val := by simp; omega
        simp [nativeEnded, List.drop_eq_nil_of_le ended, StatusSequence]

@[step] theorem native_guard_refused_statuses_exact (statuses : Slice Std.U64) :
    AuthsNativeRecipe.recipe.validate.refused_statuses_valid statuses ⦃ actual =>
      actual = decide (RefusedStatuses (statuses.val.map (·.val))) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.refused_statuses_valid
  by_cases empty : statuses.val = []
  · simp [core.slice.Slice.is_empty, empty, RefusedStatuses]
  · have positive : 0 < statuses.val.length := List.length_pos.mpr empty
    simp only [core.slice.Slice.is_empty, List.isEmpty_eq_false.mpr empty,
      Bool.false_eq_true, ↓reduceIte, bind_tc_ok]
    by_cases large : 3 < statuses.val.length
    · have nativeLarge : statuses.len > AuthsNativeRecipe.recipe.validate.MAX_REFUSED_STATUSES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_REFUSED_STATUSES]; scalar_tac
      simp [nativeLarge, RefusedStatuses, Nat.not_le.mpr large]
    · have nativeWithin : ¬statuses.len > AuthsNativeRecipe.recipe.validate.MAX_REFUSED_STATUSES := by
        simp [AuthsNativeRecipe.recipe.validate.MAX_REFUSED_STATUSES]; scalar_tac
      simp only [nativeWithin, ↓reduceIte]
      apply spec_mono (native_statuses_suffix statuses 0#usize true (by simp))
      intro actual meaning
      simpa [status_sequence_original, RefusedStatuses, positive, Nat.le_of_not_gt large, and_assoc] using meaning

theorem native_guard_refused_statuses_success (statuses : Slice Std.U64) :
    AuthsNativeRecipe.recipe.validate.refused_statuses_valid statuses ⦃ actual =>
      actual = true → RefusedStatuses (statuses.val.map (·.val)) ∧
        408 ∉ statuses.val.map (·.val) ∧ 429 ∉ statuses.val.map (·.val) ⦄ := by
  apply spec_mono (native_guard_refused_statuses_exact statuses)
  intro actual meaning accepted
  have admitted : RefusedStatuses (statuses.val.map (·.val)) := by simpa [accepted] using meaning.symm
  obtain ⟨not408, not429, _, _⟩ := refused_statuses_exclude_retryable _ admitted
  exact ⟨admitted, not408, not429⟩

end Auths.Product.NativeCompiler.Refinement
