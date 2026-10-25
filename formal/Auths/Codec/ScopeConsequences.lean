import Auths.Codec.ScopeConstructor
import Auths.Verifier.StatusAnchorExamples
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
namespace Auths.ScopeConstructor

/-- Independent domain equivalence for the expected complete typed result. -/
theorem expected_success_iff (values : alloc.vec.Vec String) :
    (∃ output, expectedConstructor values = .Ok output) ↔ Model.admitted values.val := by
  unfold expectedConstructor
  split_ifs with refused
  · simp only [exists_false, false_iff]
    intro admitted
    rcases admitted with ⟨nonempty, bounded, unique⟩
    simp [List.isEmpty_iff, nonempty, Nat.not_lt.mpr bounded, unique] at refused
  · have admitted : Model.admitted values.val := by
      simpa [Model.admitted, Bool.or_eq_true, List.isEmpty_iff, not_or, not_not] using refused
    exact ⟨fun _ => admitted, fun _ => ⟨sortedVector values, rfl⟩⟩

/-- Every successful constructed scope earns the ordering invariant consumed
    by the native status selectors and preserves exactly the input set. -/
theorem constructor_validity (values : alloc.vec.Vec String) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values ⦃ result =>
      match result with
      | .Ok output => Model.admitted values.val ∧
          Auths.StatusSelection.Search.Ordered output.val ∧ output.val.Perm values.val ∧
          output.val.length ≤ Model.maximum
      | .Err error => error = .InvalidStatusSnapshot ∧ ¬Model.admitted values.val ⦄ := by
  rw [constructor_refines]
  simp only [spec_ok]
  unfold expectedConstructor
  split_ifs with refused
  · simp only [true_and]
    intro admitted
    rcases admitted with ⟨nonempty, bounded, unique⟩
    simp [List.isEmpty_iff, nonempty, Nat.not_lt.mpr bounded, unique] at refused
  · have admitted : Model.admitted values.val := by
      simpa [Model.admitted, Bool.or_eq_true, List.isEmpty_iff, not_or, not_not] using refused
    refine ⟨admitted, ?_, Model.sorted_perm values.val, ?_⟩
    · exact Auths.StatusSelection.ordered_of_pairwise _ (Model.sorted_pairwise values.val)
    · simpa only [sortedVector, Model.sorted_length] using admitted.2.1

/-- Actual constructor success feeds the actual binary-search wrapper, with
    membership in the original input list; the ordering condition is earned. -/
theorem constructed_lookup (values : alloc.vec.Vec String) (target : String) :
    AuthsScopeCodec.auths_model.StatusScopeAnchors.new values ⦃ result =>
      match result with
      | .Ok output => AuthsStatusSelection.auths_model.StatusScopeAnchors.contains output target =
          ok (values.val.contains target)
      | .Err error => error = .InvalidStatusSnapshot ⦄ := by
  rw [constructor_refines]
  simp only [spec_ok]
  unfold expectedConstructor
  split_ifs
  · rfl
  · change AuthsStatusSelection.auths_model.StatusScopeAnchors.contains (sortedVector values) target =
        ok (values.val.contains target)
    have ordered : Auths.StatusSelection.Search.Ordered (sortedVector values).val :=
      Auths.StatusSelection.ordered_of_pairwise _ (Model.sorted_pairwise values.val)
    rw [Auths.StatusSelection.Search.scope_contains _ target ordered]
    apply congrArg Result.ok
    apply Bool.eq_iff_iff.mpr
    simp only [List.contains_iff_mem, sortedVector]
    exact (Model.sorted_perm values.val).mem_iff

end Auths.ScopeConstructor
