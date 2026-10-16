import Mathlib.Tactic
namespace Auths.StatusSelection.Search

def Ordered {α : Type} [Ord α] (values : List α) : Prop :=
  ∀ (i j : Nat) (left right : α), i ≤ j → values[i]? = some left → values[j]? = some right →
    (compare left right).isLE

def Found {α : Type} (values : List α) (target : α) (base size : Nat) : Prop :=
  ∃ index, base ≤ index ∧ index < base + size ∧ values[index]? = some target

theorem found_step {α : Type} [Ord α] [Std.TransOrd α] [Std.LawfulEqOrd α]
    (values : List α) (target value : α) (base size : Nat)
    (ordered : Ordered values) (large : 1 < size)
    (atMid : values[base + size / 2]? = some value) :
    Found values target base size ↔
      Found values target (if compare value target = .gt then base else base + size / 2) (size - size / 2) := by
  cases comparison : compare value target with
  | lt =>
    simp only [reduceCtorEq, ↓reduceIte]
    constructor
    · rintro ⟨index, lower, upper, atTarget⟩
      have after : base + size / 2 < index := by
        by_contra before
        have ordering := ordered index (base + size / 2) target value (by omega) atTarget atMid
        exact Std.OrientedCmp.not_lt_of_isLE ordering comparison
      exact ⟨index, by omega, by omega, atTarget⟩
    · rintro ⟨index, lower, upper, atTarget⟩
      exact ⟨index, by omega, by omega, atTarget⟩
  | eq =>
    have same : value = target := Std.compare_eq_iff_eq.mp comparison
    subst value
    simp only [reduceCtorEq, ↓reduceIte]
    have original : Found values target base size := ⟨base + size / 2, by omega, by omega, atMid⟩
    have next : Found values target (base + size / 2) (size - size / 2) :=
      ⟨base + size / 2, by omega, by omega, atMid⟩
    exact ⟨fun _ => next, fun _ => original⟩
  | gt =>
    simp only [↓reduceIte]
    constructor
    · rintro ⟨index, lower, upper, atTarget⟩
      have before : index < base + size / 2 := by
        by_contra after
        have ordering := ordered (base + size / 2) index value target (by omega) atMid atTarget
        simp [comparison] at ordering
      exact ⟨index, lower, by omega, atTarget⟩
    · rintro ⟨index, lower, upper, atTarget⟩
      exact ⟨index, lower, by omega, atTarget⟩

theorem found_one {α : Type} (values : List α) (target value : α) (base : Nat)
    (atBase : values[base]? = some value) : Found values target base 1 ↔ value = target := by
  constructor
  · rintro ⟨index, lower, upper, atTarget⟩
    have equal : index = base := by omega
    subst index
    exact Option.some.inj (atBase.symm.trans atTarget)
  · intro equal; subst value; exact ⟨base, by omega, by omega, atBase⟩

end Auths.StatusSelection.Search
