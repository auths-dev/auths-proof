import Auths.Composition.ValidationLeaves
open Aeneas Aeneas.Std Result
namespace Auths.Composition.IteratorFacts

theorem next_nil {T : Type} (iterator : core.slice.iter.Iter T)
    (empty : iterator.slice.val.drop iterator.i = []) :
    core.slice.iter.IteratorSliceIter.next iterator = ok (none, iterator) := by
  have finished : iterator.slice.val.length ≤ iterator.i := by
    have size := congrArg List.length empty
    simp only [List.length_drop, List.length_nil] at size
    omega
  have stop : ¬ iterator.i < iterator.slice.len := by
    simpa only [Slice.len_val] using Nat.not_lt.mpr finished
  unfold core.slice.iter.IteratorSliceIter.next
  rw [dif_neg stop]

theorem next_cons {T : Type} (iterator : core.slice.iter.Iter T) (head : T) (tail : List T)
    (remaining : iterator.slice.val.drop iterator.i = head :: tail) :
    ∃ next, core.slice.iter.IteratorSliceIter.next iterator = ok (some head, next) ∧
      next.slice.val.drop next.i = tail := by
  have within : iterator.i < iterator.slice.val.length := by
    have size := congrArg List.length remaining
    simp only [List.length_drop, List.length_cons] at size
    omega
  have atHead : iterator.slice.val[iterator.i] = head := by
    have split := List.drop_eq_getElem_cons within
    rw [remaining] at split
    exact (List.cons.inj split).1.symm
  have guard : iterator.i < iterator.slice.len := by
    simpa only [Slice.len_val] using within
  refine ⟨{ iterator with i := iterator.i + 1 }, ?_, ?_⟩
  · unfold core.slice.iter.IteratorSliceIter.next
    rw [dif_pos guard]
    exact congrArg (fun value : T => ok (some value, { iterator with i := iterator.i + 1 })) atHead
  · have drop := congrArg (List.drop 1) remaining
    simpa [List.drop_drop, Nat.add_comm] using drop

end Auths.Composition.IteratorFacts
