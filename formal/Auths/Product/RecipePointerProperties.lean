import Auths.Product.RecipeAdmissionAtoms

namespace Auths.Product.RecipeAdmissionAtoms

def CleanEdges (bytes : Bytes) : Prop := (126, 50) ∉ bytes.zip (bytes.drop 1)
instance (bytes : Bytes) : Decidable (CleanEdges bytes) := by unfold CleanEdges; infer_instance

def slashCount (bytes : Bytes) : Nat := (bytes.filter (· == 47)).length

theorem clean_edges_cons (first : Nat) (rest : Bytes) :
    CleanEdges (first :: rest) ↔
      ¬(first = 126 ∧ rest.head? = some 50) ∧ CleanEdges rest := by
  cases rest with
  | nil => simp [CleanEdges]
  | cons second tail =>
      simp only [CleanEdges, List.drop_succ_cons, List.drop_zero, List.zip_cons_cons,
        List.mem_cons, Prod.mk.injEq, not_or, List.head?_cons, Option.some.injEq,
        eq_comm (a := 126), eq_comm (a := 50)]
      tauto

theorem slash_count_cons (first : Nat) (rest : Bytes) :
    slashCount (first :: rest) = (if first = 47 then 1 else 0) + slashCount rest := by
  by_cases slash : first = 47 <;> simp [slashCount, slash]

theorem slash_count_bounded (bytes : Bytes) : slashCount bytes ≤ bytes.length :=
  List.length_filter_le _ _

theorem response_pointer_components (bytes : Bytes) :
    ResponsePointer bytes ↔ bytes.head? = some 47 ∧ bytes.length ≤ 128 ∧
      slashCount bytes ≤ 8 ∧ CleanEdges bytes := Iff.rfl

end Auths.Product.RecipeAdmissionAtoms
