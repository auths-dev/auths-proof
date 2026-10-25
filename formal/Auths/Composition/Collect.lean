import Auths.Composition.SetModel
open Aeneas Aeneas.Std Result Aeneas.Std.WP
open auths_composition
namespace Auths.Composition.Collect

@[step] theorem push_exact (state : auths_composition.alloc.vec.Vec auths_model.ProofRef) (value : auths_model.ProofRef)
    (room : state.size < Usize.max) :
    auths_composition.alloc.vec.Vec.push state value ⦃ updated =>
      updated.elements.toList = state.elements.toList ++ [value] ⦄ := by
  have baseRoom : state.toBase.val.length < Usize.max := by
    simpa only [auths_composition.alloc.vec.Vec.toBase, auths_composition.alloc.vec.SizedList.length] using room
  unfold auths_composition.alloc.vec.Vec.push
  apply spec_bind (Aeneas.Std.alloc.vec.Vec.push_spec state.toBase value baseRoom)
  intro result exactValues
  simpa only [spec_ok, auths_composition.alloc.vec.Vec.ofBase, auths_composition.alloc.vec.SizedList.toList_ofList,
    auths_composition.alloc.vec.Vec.toBase] using exactValues

theorem collect_exact (remaining : List auths_model.ProofRef)
    (iterator : alloc.collections.btree.set.IntoIter auths_model.ProofRef Global)
    (state : auths_composition.alloc.vec.Vec auths_model.ProofRef)
    (same : iterator.values = remaining)
    (room : state.size + remaining.length ≤ Usize.max) :
    auths_model.AuthorizationPlan.validate_loop iterator state ⦃ updated =>
      updated.elements.toList = state.elements.toList ++ remaining ⦄ := by
  cases iterator with
  | mk values bound =>
    dsimp only at same
    subst values
    induction remaining generalizing state with
    | nil =>
      rw [auths_model.AuthorizationPlan.validate_loop.eq_def]
      simp [alloc.collections.btree.set.IntoIter.Insts.CoreIterTraitsIteratorIterator.next]
    | cons head tail ih =>
      have canPush : state.size < Usize.max := by
        simp only [List.length_cons] at room
        omega
      rw [auths_model.AuthorizationPlan.validate_loop.eq_def]
      simp only [alloc.collections.btree.set.IntoIter.Insts.CoreIterTraitsIteratorIterator.next,
        bind_tc_ok]
      step as ⟨updated, updatedValues⟩
      have updatedSize : updated.size = state.size + 1 := by
        have size := congrArg List.length updatedValues
        simpa only [auths_composition.alloc.vec.SizedList.length, List.length_append, List.length_singleton] using size
      apply spec_mono (ih updated
        (by simp only [List.length_cons] at room; omega)
        (by simp only [List.length_cons] at bound; omega))
      intro final exactValues
      simpa only [updatedValues, List.append_assoc, List.singleton_append] using exactValues
end Auths.Composition.Collect
