import Auths.Product.EntryDeadline
import qualification.aeneas.generated.gateway.Funs

open Aeneas Aeneas.Std Result
open Auths.Product.EntryDeadline

namespace Auths.Product.Refinement.EntryDeadline

def boundView (bound : auths_gateway_kernel.deadline.EntryBound) : Bound :=
  ⟨bound.not_after.val, bound.inclusive⟩

theorem translated_entry_time_refines_model (evaluatedAt now : Std.U64)
    (bound : auths_gateway_kernel.deadline.EntryBound) :
    auths_gateway_kernel.deadline.entry_time_allows evaluatedAt now bound =
      ok (decide (admits evaluatedAt.val (boundView bound) now.val)) := by
  simp only [auths_gateway_kernel.deadline.entry_time_allows]
  split <;> rename_i ordered
  · split <;> rename_i before
    · simp [admits, permits, boundView, UScalar.le_equiv, UScalar.lt_equiv] at *
      omega
    · split <;> rename_i equal
      · subst now
        cases inclusive : bound.inclusive <;>
          simp_all [admits, permits, boundView, UScalar.le_equiv]
      · simp [admits, permits, boundView, UScalar.le_equiv, UScalar.lt_equiv] at *
        omega
  · simp [admits, permits, boundView, UScalar.le_equiv] at *
    omega

theorem translated_intersection_refines_model
    (left right : auths_gateway_kernel.deadline.EntryBound) :
    auths_gateway_kernel.deadline.intersect_entry_bounds left right
      ⦃ result => boundView result = meet (boundView left) (boundView right) ⦄ := by
  unfold auths_gateway_kernel.deadline.intersect_entry_bounds
  split <;> rename_i first
  · simp [boundView, meet, UScalar.lt_equiv] at *
    simp_all
  · split <;> rename_i second
    · simp [boundView, meet, UScalar.lt_equiv] at *
      simp_all
    · split <;> rename_i inclusive
      · have notFirst : ¬ left.not_after.val < right.not_after.val := by simpa using first
        have notSecond : ¬ right.not_after.val < left.not_after.val := by simpa using second
        simp [boundView, meet, notFirst, notSecond, inclusive]
      · have notFirst : ¬ left.not_after.val < right.not_after.val := by simpa using first
        have notSecond : ¬ right.not_after.val < left.not_after.val := by simpa using second
        simp [boundView, meet, notFirst, notSecond, inclusive]

theorem translated_clock_rollback_refuses (evaluatedAt now : Std.U64)
    (bound : auths_gateway_kernel.deadline.EntryBound)
    (rollback : now.val < evaluatedAt.val) :
    auths_gateway_kernel.deadline.entry_time_allows evaluatedAt now bound = ok false := by
  rw [translated_entry_time_refines_model]
  have refused : ¬ admits evaluatedAt.val (boundView bound) now.val := by
    intro accepted
    have ordered := accepted.1
    omega
  simp [refused]


end Auths.Product.Refinement.EntryDeadline
