import Auths.Codec.ScopeSort
import Mathlib.Data.List.Chain
namespace Auths.ScopeConstructor

def repeated : List String → Bool
  | [] => false
  | first :: rest => match rest with
    | [] => false
    | second :: _ => first == second || repeated rest

theorem repeated_false_chain (values : List String) :
    repeated values = false ↔ values.IsChain (fun left right => left ≠ right) := by
  induction values with
  | nil => simp [repeated]
  | cons first rest ih =>
    cases rest with
    | nil => simp [repeated]
    | cons second tail =>
      simp [repeated, List.isChain_cons_cons, ← ih]

local instance : IsTrans String (fun left right => compare left right = .lt) where
  trans _ _ _ := Std.TransCmp.lt_trans

theorem repeated_false_iff_nodup (values : List String) (ordered : values.Pairwise Model.stringLE) :
    repeated values = false ↔ values.Nodup := by
  rw [repeated_false_chain]
  constructor
  · intro adjacent
    have strict : values.IsChain (fun left right => compare left right = .lt) := by
      rw [List.isChain_iff_getElem] at adjacent ⊢
      intro index within
      have lower := List.pairwise_iff_getElem.mp ordered index (index + 1) (by omega) within (by omega)
      have unequal := adjacent index within
      have notEqual : compare values[index] values[index + 1] ≠ .eq := by
        intro equal
        exact unequal (Std.compare_eq_iff_eq.mp equal)
      cases comparison : compare values[index] values[index + 1] <;>
        simp_all [Model.stringLE]
    have pairwise : values.Pairwise (fun left right => compare left right = .lt) :=
      List.isChain_iff_pairwise.mp strict
    exact pairwise.imp (by
      intro left right comparison equal
      subst right
      simp at comparison)
  · intro nodup
    exact nodup.isChain

end Auths.ScopeConstructor
