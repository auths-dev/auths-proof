import Auths.Composition.Order
open Aeneas Aeneas.Std Result
open auths_composition Auths.Composition.Order
namespace Auths.Composition.SetModel
abbrev Reference := auths_model.ProofRef
abbrev referenceOrder := auths_model.ProofRef.Insts.CoreCmpOrd

def Before (left right : Reference) : Prop := referenceKey left < referenceKey right

theorem order_comparison (left right : Reference) :
    referenceOrder.cmp left right = ok (List.compareLex compare (referenceKey left) (referenceKey right)) :=
  reference_comparison left right

theorem insert_values (value : Reference) (values : List Reference)
    (ordered : values.Pairwise Before) :
    ∃ added updated,
      alloc.collections.btree.set.insertValues referenceOrder value values = ok (added, updated) ∧
      updated.Pairwise Before ∧
      (∀ item, item ∈ updated ↔ item = value ∨ item ∈ values) ∧
      (added = true ↔ value ∉ values) ∧
      updated.length = values.length + (if added then 1 else 0) := by
  induction values with
  | nil =>
    refine ⟨true, [value], rfl, ?_, ?_, ?_, ?_⟩ <;> simp [Before]
  | cons head tail ih =>
    obtain ⟨headLess, tailOrdered⟩ := List.pairwise_cons.mp ordered
    have meaning := order_comparison value head
    cases comparison : List.compareLex compare (referenceKey value) (referenceKey head) with
    | lt =>
      have less : Before value head := (nat_lists_lt _ _).mp comparison
      have absent : value ∉ head :: tail := by
        intro member
        rcases List.mem_cons.mp member with same | member
        · subst value; exact (lt_irrefl (referenceKey head)) less
        · exact (lt_asymm less) (headLess value member)
      refine ⟨true, value :: head :: tail, ?_, ?_, ?_, ?_, ?_⟩
      · rw [alloc.collections.btree.set.insertValues, meaning, comparison]
        rfl
      · apply List.pairwise_cons.mpr
        refine ⟨?_, ordered⟩
        intro item member
        rcases List.mem_cons.mp member with same | member
        · subst item; exact less
        · exact lt_trans less (headLess item member)
      · intro item; simp
      · simp [absent]
      · simp
    | eq =>
      have same : value = head := reference_key_injective ((nat_lists_eq _ _).mp comparison)
      subst value
      refine ⟨false, head :: tail, ?_, ordered, ?_, ?_, ?_⟩
      · rw [alloc.collections.btree.set.insertValues, meaning, comparison]
        rfl
      · intro item; simp only [List.mem_cons]; tauto
      · simp
      · simp
    | gt =>
      have more : Before head value := (nat_lists_gt _ _).mp comparison
      have different : value ≠ head := by
        intro same
        subst value
        exact (lt_irrefl (referenceKey head)) more
      obtain ⟨added, updated, executes, sorted, members, fresh, size⟩ := ih tailOrdered
      refine ⟨added, head :: updated, ?_, ?_, ?_, ?_, ?_⟩
      · rw [alloc.collections.btree.set.insertValues, meaning, comparison]
        simp only [bind_tc_ok]
        rw [executes]
        rfl
      · apply List.pairwise_cons.mpr
        refine ⟨?_, sorted⟩
        intro item member
        rcases (members item).mp member with same | member
        · subst item; exact more
        · exact headLess item member
      · intro item
        simp only [List.mem_cons, members]
        tauto
      · simpa [different] using fresh
      · simp only [List.length_cons]
        omega

theorem ordered_nodup (values : List Reference) (ordered : values.Pairwise Before) : values.Nodup := by
  induction values with
  | nil => simp
  | cons head tail ih =>
    obtain ⟨headLess, tailOrdered⟩ := List.pairwise_cons.mp ordered
    apply List.nodup_cons.mpr
    refine ⟨?_, ih tailOrdered⟩
    intro member
    exact (lt_irrefl (referenceKey head)) (headLess head member)

theorem insert_set (allocator : core.clone.Clone Global)
    (value : Reference) (state : alloc.collections.btree.set.BTreeSet Reference Global)
    (ordered : state.values.Pairwise Before) (room : state.values.length < Usize.max) :
    ∃ added updated,
      alloc.collections.btree.set.BTreeSet.insert allocator referenceOrder state value = ok (added, updated) ∧
      updated.values.Pairwise Before ∧
      (∀ item, item ∈ updated.values ↔ item = value ∨ item ∈ state.values) ∧
      (added = true ↔ value ∉ state.values) ∧
      updated.values.length = state.values.length + (if added then 1 else 0) := by
  obtain ⟨added, values, executes, sorted, members, fresh, size⟩ := insert_values value state.values ordered
  have growth : values.length ≤ state.values.length + 1 := by
    rw [size]
    split <;> omega
  have bound : values.length ≤ Usize.max := by omega
  refine ⟨added, ⟨values, bound⟩, ?_, sorted, members, fresh, size⟩
  unfold alloc.collections.btree.set.BTreeSet.insert
  rw [executes]
  simp only [uncurry, Bind.bind, Aeneas.Std.bind]
  rw [dif_pos bound]

end Auths.Composition.SetModel
