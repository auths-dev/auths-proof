import Mathlib.Data.List.Sort
import Mathlib.Tactic
namespace Auths.ScopeConstructor.Model

abbrev stringLE (left right : String) : Prop := (compare left right).isLE = true

local instance : Std.Total stringLE where
  total left right := by
    cases comparison : compare left right with
    | lt => exact Or.inl (by simp [stringLE, comparison])
    | eq => exact Or.inl (by simp [stringLE, comparison])
    | gt => exact Or.inr (by simp [stringLE, Std.OrientedCmp.lt_of_gt comparison])
local instance : IsTrans String stringLE where
  trans _ _ _ left right := Std.TransOrd.isLE_trans left right

def sorted (values : List String) : List String := values.insertionSort stringLE

theorem sorted_pairwise (values : List String) : (sorted values).Pairwise stringLE :=
  List.pairwise_insertionSort stringLE values

theorem sorted_perm (values : List String) : (sorted values).Perm values :=
  List.perm_insertionSort stringLE values

theorem sorted_length (values : List String) : (sorted values).length = values.length :=
  List.length_insertionSort stringLE values

def maximum : Nat := 1024

def admitted (values : List String) : Prop := values ≠ [] ∧ values.length ≤ maximum ∧ values.Nodup

def construct (values : List String) : Option (List String) :=
  if values.isEmpty || maximum < values.length || decide (¬values.Nodup) then none else some (sorted values)

end Auths.ScopeConstructor.Model
